//! The anchoring queue (CT-04): nothing lost on a failing network, and a
//! memo never sent a second time while the first may still land — two memos
//! after one head would read as a fork.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use ksg_core_v2::crypto::hash::Hash;
use ksg_service_v2::anchoring::{
    retry_delay_ms, ChainSender, Kind, Landing, Outbox, QueueError, SendError, Sent, MAX_RETRY_MS,
};
use ksg_verify_v2::solana::{AnchorProof, SealMemo, SealScanKey, StatusMemo, STATUS_KIND};

/// A network the test steers.
#[derive(Default)]
struct Net {
    /// Refuse every send with this.
    down: Option<SendError>,
    /// Every memo that went out, in order, with its signature.
    sent: Vec<(String, String)>,
    /// What `landing` answers per signature; landed by default.
    fate: BTreeMap<String, Landing>,
}

impl ChainSender for Net {
    fn cluster(&self) -> &str {
        "devnet"
    }
    fn send_memo(&mut self, memo: &str) -> Result<Sent, SendError> {
        if let Some(e) = &self.down {
            return Err(e.clone());
        }
        let sig = format!("{}{}", "5".repeat(86), self.sent.len() + 10);
        self.sent.push((memo.to_owned(), sig.clone()));
        Ok(Sent {
            signature: sig,
            blockhash: "bh".into(),
        })
    }
    fn landing(&mut self, sent: &Sent) -> Result<Landing, SendError> {
        Ok(self
            .fate
            .get(&sent.signature)
            .cloned()
            .unwrap_or(Landing::Landed {
                slot: 7,
                block_time: Some(1_790_000_000),
            }))
    }
}

fn status_job(q: &mut Outbox) -> (Hash, u64) {
    let record = Hash::sha256(b"record 1");
    let memo = StatusMemo::of(&Hash::sha256(b"record 0"), &record).to_string();
    let id = q
        .push(Hash::sha256(b"container"), Kind::Status, record, memo, 0)
        .unwrap();
    (record, id)
}

#[test]
fn a_memo_lands_and_comes_back_as_an_attestation_of_its_subject() {
    let mut q = Outbox::default();
    let mut net = Net::default();
    let (record, id) = status_job(&mut q);
    let t = q.tick(&mut net, 0);
    assert_eq!(
        (t.sent, t.anchored.len()),
        (1, 0),
        "sent, asked about later"
    );
    let t = q.tick(&mut net, 1_000);
    assert_eq!(t.anchored.len(), 1);
    let a = &t.anchored[0];
    assert_eq!(a.id, id);
    assert_eq!(a.attestation.subject, record);
    assert_eq!(a.attestation.kind.as_str(), STATUS_KIND);
    assert_eq!(
        a.attestation.anchored_at.as_str(),
        "2026-09-21T14:13:20.000Z"
    );
    let proof = AnchorProof::from_bytes(&a.attestation.proof).unwrap();
    assert_eq!(
        (proof.signature.as_str(), proof.slot),
        (net.sent[0].1.as_str(), 7)
    );
    assert_eq!(a.anchor.signature, net.sent[0].1);
    assert!(q.jobs().is_empty());
}

#[test]
fn a_network_that_is_down_delays_and_loses_nothing() {
    let mut q = Outbox::default();
    let mut net = Net {
        down: Some(SendError::Refused("insufficient funds for fee".into())),
        ..Net::default()
    };
    status_job(&mut q);
    let mut now = 0;
    for _ in 0..5 {
        let t = q.tick(&mut net, now);
        assert_eq!(t.failed, 1);
        now = q.jobs()[0].next_try_ms;
    }
    assert_eq!(q.jobs()[0].attempts, 5);
    assert!(q.jobs()[0]
        .last_error
        .as_deref()
        .unwrap()
        .contains("insufficient funds"));
    // Survives a restart of the host, then the payer is funded.
    let mut q = Outbox::from_json(&q.to_json().unwrap()).unwrap();
    net.down = None;
    q.tick(&mut net, now);
    let t = q.tick(&mut net, now + 1_000);
    assert_eq!(t.anchored.len(), 1);
    assert_eq!(net.sent.len(), 1, "one memo in the network");
}

#[test]
fn a_memo_not_yet_final_is_asked_about_never_sent_again() {
    let mut q = Outbox::default();
    let mut net = Net::default();
    status_job(&mut q);
    q.tick(&mut net, 0);
    let sig = net.sent[0].1.clone();
    net.fate.insert(sig.clone(), Landing::Pending);
    let mut now = 1_000;
    for _ in 0..6 {
        let t = q.tick(&mut net, now);
        assert_eq!((t.sent, t.anchored.len()), (0, 0));
        now = q.jobs()[0].next_try_ms;
    }
    net.fate.remove(&sig);
    assert_eq!(q.tick(&mut net, now).anchored.len(), 1);
    assert_eq!(
        net.sent.len(),
        1,
        "never a second memo while the first might land"
    );
}

#[test]
fn a_dropped_or_failed_transaction_is_sent_again() {
    for fate in [Landing::Dropped, Landing::Failed("InstructionError".into())] {
        let mut q = Outbox::default();
        let mut net = Net::default();
        status_job(&mut q);
        q.tick(&mut net, 0);
        net.fate.insert(net.sent[0].1.clone(), fate.clone());
        let t = q.tick(&mut net, 1_000);
        assert_eq!(t.sent, 1, "{fate:?}: sent again");
        let t = q.tick(&mut net, 2_000);
        assert_eq!(t.anchored.len(), 1);
        assert_eq!(
            t.anchored[0].anchor.signature, net.sent[1].1,
            "the second one counts"
        );
    }
}

#[test]
fn a_memo_of_another_kind_or_record_is_refused() {
    let mut q = Outbox::default();
    let record = Hash::sha256(b"record 1");
    let other = StatusMemo::of(&Hash::sha256(b"record 0"), &Hash::sha256(b"another")).to_string();
    assert_eq!(
        q.push(Hash::sha256(b"c"), Kind::Status, record, other, 0),
        Err(QueueError::Memo("status"))
    );
    let scan = SealScanKey::new([1; 32]);
    let seal = SealMemo::of(&scan, &Hash::sha256(b"a"), &Hash::sha256(b"b")).to_string();
    assert_eq!(
        q.push(Hash::sha256(b"c"), Kind::Status, record, seal.clone(), 0),
        Err(QueueError::Memo("status"))
    );
    q.push(Hash::sha256(b"c"), Kind::Seal, Hash::sha256(b"b"), seal, 0)
        .expect("a seal memo is checked for its form only");
    assert_eq!(
        q.push(Hash::sha256(b"c"), Kind::Seal, record, "hello".into(), 0),
        Err(QueueError::Memo("seal"))
    );
}

#[test]
fn the_delay_doubles_up_to_an_hour() {
    assert_eq!(retry_delay_ms(0), 1_000);
    assert_eq!(retry_delay_ms(3), 8_000);
    assert_eq!(retry_delay_ms(30), MAX_RETRY_MS);
    assert_eq!(retry_delay_ms(200), MAX_RETRY_MS);
}

/// KS-8 C-10: the service takes an agent's ID publication only as the open
/// `ksg:id:v1` memo of the very subject it is asked to anchor.
#[test]
fn an_agent_id_memo_is_taken_only_for_its_subject() {
    use ksg_verify_v2::solana::AgentIdMemo;
    let mut q = Outbox::default();
    let subject = Hash::sha256(b"publication");
    let memo = |s: Hash| {
        AgentIdMemo {
            subject: s,
            open_id: "did:web:agent.example.com".into(),
        }
        .to_string()
    };
    assert_eq!(
        q.push(
            Hash::sha256(b"c"),
            Kind::AgentId,
            subject,
            memo(Hash::sha256(b"other")),
            0
        ),
        Err(QueueError::Memo("agent-id"))
    );
    let status = StatusMemo::of(&Hash::sha256(b"a"), &subject).to_string();
    assert_eq!(
        q.push(Hash::sha256(b"c"), Kind::AgentId, subject, status, 0),
        Err(QueueError::Memo("agent-id"))
    );
    q.push(Hash::sha256(b"c"), Kind::AgentId, subject, memo(subject), 0)
        .expect("its own memo");
    // The memo reads back as what was written; whitespace in an ID does not.
    assert_eq!(
        AgentIdMemo::parse(&memo(subject)).map(|m| m.subject),
        Some(subject)
    );
    assert_eq!(
        AgentIdMemo::parse(&format!("ksg:id:v1 {} two words", subject.to_multihash())),
        None
    );
    assert_eq!(
        AgentIdMemo::parse(&format!(
            "ksg:id:v1 {} {}",
            subject.to_multihash(),
            "x".repeat(201)
        )),
        None
    );
}
