# tiny_http 0.12.0 — local patch

Copy of the crates.io release `tiny_http 0.12.0` (MIT OR Apache-2.0, see the
license files), wired in through `[patch.crates-io]` in `core-v2/Cargo.toml`.
`benches/`, `examples/` and `tests/` are left out.

One change, `src/util/equal_reader.rs`, `Drop for EqualReader`: the upstream
drain of an unread request body allocated `vec![0; remaining]`, so a single
request with a huge `Content-Length` aborted the whole process, and it kept a
thread as long as the client trickled bytes. The drain now uses a fixed 8 KiB
buffer and stops after 64 KiB or 2 s; the connection is then closed.

Drop this copy once an upstream release carries an equivalent fix.
