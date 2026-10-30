use std::io::Read;
use std::io::Result as IoResult;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};

/// A `Reader` that reads exactly the number of bytes from a sub-reader.
///
/// If the limit is reached, it returns EOF. If the limit is not reached
/// when the destructor is called, the remaining bytes will be read and
/// thrown away.
pub struct EqualReader<R>
where
    R: Read,
{
    reader: R,
    size: usize,
    last_read_signal: Sender<IoResult<()>>,
}

impl<R> EqualReader<R>
where
    R: Read,
{
    pub fn new(reader: R, size: usize) -> (EqualReader<R>, Receiver<IoResult<()>>) {
        let (tx, rx) = channel();

        let r = EqualReader {
            reader,
            size,
            last_read_signal: tx,
        };

        (r, rx)
    }
}

impl<R> Read for EqualReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.size == 0 {
            return Ok(0);
        }

        let buf = if buf.len() < self.size {
            buf
        } else {
            &mut buf[..self.size]
        };

        match self.reader.read(buf) {
            Ok(len) => {
                self.size -= len;
                Ok(len)
            }
            err @ Err(_) => err,
        }
    }
}

impl<R> Drop for EqualReader<R>
where
    R: Read,
{
    // Keysingate patch: the upstream drain allocated a buffer of the whole
    // unread remainder (`vec![0; remaining]`) — a request declaring a huge
    // `Content-Length` aborted the process on allocation failure — and kept
    // draining as long as the peer trickled bytes. Here the drain goes
    // through a fixed buffer and stops after `DRAIN_MAX_BYTES` or
    // `DRAIN_MAX_TIME`; an undrained connection then fails on its next read
    // and is closed.
    fn drop(&mut self) {
        const DRAIN_MAX_BYTES: usize = 64 * 1024;
        const DRAIN_MAX_TIME: std::time::Duration = std::time::Duration::from_secs(2);
        let started = std::time::Instant::now();
        let mut drained = 0usize;
        let mut buf = [0u8; 8192];

        while self.size > 0 {
            if drained >= DRAIN_MAX_BYTES || started.elapsed() >= DRAIN_MAX_TIME {
                let e = std::io::Error::new(std::io::ErrorKind::Other, "body not drained");
                self.last_read_signal.send(Err(e)).ok();
                return;
            }
            let n = buf.len().min(self.size);
            match self.reader.read(&mut buf[..n]) {
                Err(e) => {
                    self.last_read_signal.send(Err(e)).ok();
                    return;
                }
                Ok(0) => {
                    self.last_read_signal.send(Ok(())).ok();
                    return;
                }
                Ok(other) => {
                    self.size -= other;
                    drained += other;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EqualReader;
    use std::io::Read;

    #[test]
    fn test_limit() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);

            let mut string = String::new();
            equal_reader.read_to_string(&mut string).unwrap();
            assert_eq!(string, "hello");
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }

    #[test]
    fn test_not_enough() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);

            let mut vec = [0];
            equal_reader.read_exact(&mut vec).unwrap();
            assert_eq!(vec[0], b'h');
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }
}
