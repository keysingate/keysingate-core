//! Rules that hold by the shape of the code — an absence, a signature, a
//! type — kept from drifting by reading the source and the operation table
//! (gap 15.10, list 1 of `[doc:RULES-IN-CODE]`).

use ksg_container_v2::{Keys, Operation, Role, Seat};

const CORE_SECTION: &str = include_str!("../../ksg-core-v2/src/section.rs");
const CORE_JOURNAL: &str = include_str!("../../ksg-core-v2/src/journal/mod.rs");
const CORE_CHAIN: &str = include_str!("../../ksg-core-v2/src/journal/chain.rs");
const CORE_STATUS: &str = include_str!("../../ksg-core-v2/src/status.rs");
const CONTAINER: &str = include_str!("../src/container.rs");
const OPERATION: &str = include_str!("../src/operation.rs");
const TIMECHECK: &str = include_str!("../src/timecheck.rs");
const STORE: &str = include_str!("../src/store.rs");

fn code(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// I-1 (KS-8): the rules are deterministic — no system clock in the core or
/// the container; time comes in as an argument.
#[test]
fn no_rule_reads_the_system_clock() {
    for (name, src) in [
        ("section.rs", CORE_SECTION),
        ("journal/mod.rs", CORE_JOURNAL),
        ("journal/chain.rs", CORE_CHAIN),
        ("status.rs", CORE_STATUS),
        ("container.rs", CONTAINER),
        ("operation.rs", OPERATION),
        ("timecheck.rs", TIMECHECK),
    ] {
        for clock in ["SystemTime", "Instant::now", "Utc::now", "now_ms("] {
            assert!(
                !code(src).contains(clock),
                "{name} reads the clock: {clock}"
            );
        }
    }
}

/// §11.1 (KS-7): the journal and the status section are append-only — no
/// method takes a record out, cuts the tail or rewrites one.
#[test]
fn the_journal_and_the_section_only_grow() {
    for (name, src) in [
        ("section.rs", CORE_SECTION),
        ("journal/mod.rs", CORE_JOURNAL),
        ("journal/chain.rs", CORE_CHAIN),
    ] {
        for verb in [
            "remove", "truncate", "pop", "clear", "delete", "rewrite", "replace",
        ] {
            assert!(
                !code(src).contains(&format!("pub fn {verb}")),
                "{name} has pub fn {verb}"
            );
        }
    }
}

/// §3.2 (KS-7): one writer, events one at a time — pressing takes the
/// container exclusively.
#[test]
fn pressing_takes_the_container_exclusively() {
    let at = CONTAINER.find("pub fn press(").expect("press");
    let head: String = CONTAINER[at..].chars().take(80).collect();
    assert!(head.contains("&mut self"), "{head}");
}

/// H-4 (KS-8): the container is not read as a file — there is no operation
/// that reads, and the file on disk is encrypted (`store.rs`).
#[test]
fn no_operation_reads_the_container() {
    for op in Operation::all() {
        let name = format!("{op:?}");
        for word in ["Read", "Dump", "Show", "Get"] {
            assert!(!name.contains(word), "{name}");
        }
    }
    assert!(
        STORE.contains("a file here is encrypted and signed"),
        "the stored file is encrypted"
    );
}

/// I-5 (KS-8): nothing is read through the issuer's buttons, the counter
/// included — every operation the issuer presses alone moves the status.
#[test]
fn the_issuers_buttons_read_nothing() {
    let mut issuers = 0;
    for &op in Operation::all() {
        if let Keys::Seats(seats) = op.keys() {
            if seats == [Seat::Exactly(Role::Issuer)] {
                issuers += 1;
                assert!(
                    op.event().is_some(),
                    "{op:?} is the issuer's and moves nothing"
                );
            }
        }
    }
    assert!(issuers >= 4, "E-1, E-2, E-13, E-14 at least: {issuers}");
}

/// `Bare_v2_spec` §5: the `bare` check key never goes into the container —
/// the issuance anchor is written and read by the issuer's program.
#[test]
fn the_bare_check_key_is_not_in_the_container() {
    for (name, src) in [("container.rs", CONTAINER), ("operation.rs", OPERATION)] {
        for word in ["issue_anchor", "check_key", "ksg:ia"] {
            assert!(!code(src).contains(word), "{name} holds {word}");
        }
    }
}
