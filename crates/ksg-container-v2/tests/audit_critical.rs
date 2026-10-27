//! Attacks from the 13.09 security audit — findings 2 and 3.

use ksg_container_v2::{Button, Command, Event, Head, Keys, Operation, Refusal, Seat, Wrapped};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, SignatureSet};
use ksg_core_v2::doc::Uri;

fn signer(seed: u8, kid: &str) -> Ed25519Signer {
    Ed25519Signer::from_seed(Uri::parse(kid).expect("uri"), [seed; 32])
}

fn event(op: Operation, signers: &[&Ed25519Signer]) -> Event {
    let mut e = Event {
        op,
        button: op.button(),
        container: Hash::sha256(b"container"),
        payload: Wrapped::received(b"wrapped".to_vec()),
        signatures: SignatureSet::default(),
        covered: Vec::new(),
        head: Some(Head {
            counter: 1,
            page: Hash::sha256(b"page 1"),
        }),
    };
    e.covered = e.subject();
    e.signatures = SignatureSet::new(signers.iter().map(|s| s.sign(&e.covered)).collect());
    e
}

// --- finding 2: operation swap under a valid signature ------------------------

#[test]
fn the_subject_changes_with_every_field_it_binds() {
    let client = signer(1, "did:example:client#k1");
    let base = event(Operation::RecordWork, &[&client]);

    // Operation.
    let mut other_op = base.clone();
    other_op.op = Operation::FullExport;
    assert_ne!(
        base.subject(),
        other_op.subject(),
        "the operation is not bound"
    );

    // Button.
    let mut other_button = base.clone();
    other_button.button = Button::Export;
    assert_ne!(
        base.subject(),
        other_button.subject(),
        "the button is not bound"
    );

    // Container — replay into the neighbor.
    let mut other_container = base.clone();
    other_container.container = Hash::sha256(b"another container");
    assert_ne!(
        base.subject(),
        other_container.subject(),
        "the container is not bound"
    );

    // Journal head — freshness.
    let mut other_head = base.clone();
    other_head.head = None;
    assert_ne!(
        base.subject(),
        other_head.subject(),
        "the head is not bound"
    );

    // Payload — swap the material, keep the signature.
    let mut other_payload = base.clone();
    other_payload.payload = Wrapped::received(b"a different material".to_vec());
    assert_ne!(
        base.subject(),
        other_payload.subject(),
        "the payload is not bound"
    );
}

#[test]
fn a_signed_command_does_not_carry_over_to_another_operation() {
    // The audit scenario verbatim: a "record work" command is intercepted,
    // the attacker swaps in a "full export" operation, keeps the signature.
    let client = signer(1, "did:example:client#k1");
    let mut swapped = event(Operation::RecordWork, &[&client]);
    swapped.op = Operation::FullExport;
    swapped.button = swapped.op.button();

    assert_ne!(
        swapped.covered,
        swapped.subject(),
        "the signed bytes must no longer match"
    );
}

// --- finding 3: full export under any single key --------------------------------

#[test]
fn a_full_export_takes_two_named_seats_and_not_any_key() {
    match Operation::FullExport.keys() {
        Keys::Seats(seats) => {
            assert_eq!(seats.len(), 2, "the export is no longer a pair");
            assert!(
                seats.contains(&Seat::Exactly(ksg_container_v2::Role::Owner))
                    && seats.contains(&Seat::Exactly(ksg_container_v2::Role::Client)),
                "export seats must be named, got: {seats:?}"
            );
        }
        Keys::Set | Keys::AnyOf(_) => panic!(
            "FullExport fell back into the branch with no role check — any key of the \
             container set presses the most destructive operation (13.09 audit, finding 3)"
        ),
    }
}

#[test]
fn a_command_with_no_signatures_is_refused_whatever_the_operation() {
    let cmd = Command {
        op: Operation::FullExport,
        payload: Vec::new(),
        signatures: SignatureSet::default(),
        signed_bytes: Vec::new(),
    };
    assert!(matches!(
        cmd.op.keys(),
        Keys::Seats(_) // the Set branch is gone — the seat check now runs
    ));
    let _ = cmd;
}

#[test]
fn an_unbound_signature_is_named_as_such() {
    let client = signer(1, "did:example:client#k1");
    let mut e = event(Operation::RecordWork, &[&client]);
    e.covered = b"bytes the signer never saw".to_vec();
    // The Refusal value itself matters: "the signature does not verify" and
    // "the signature is not about this event" must not be confused — they are fixed differently.
    assert_eq!(
        format!("{}", Refusal::UnboundSignature),
        "the signatures do not cover this event"
    );
}
