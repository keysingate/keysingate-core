//! The holder's consent on the mobile half (`ksg-mobile-v2`): a share is made
//! only for a round the holder approved, and the holder is shown what the
//! round signs.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use ksg_cli_v2::mobile::Mobile;
use ksg_cli_v2::{init, InitOptions, Reader};
use ksg_container_v2::client_key::{Commitment, MobileHalf, MobileShare, SigningRound};
use ksg_core_v2::doc::{Class, Uri};
use ksg_mobile_v2::{handle_line, ApproveAll, Consent, Session, Signing};
use rand_core::OsRng;

struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("ksg-mobile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Approves or refuses, and remembers what it was shown.
#[derive(Clone)]
struct Holder {
    yes: bool,
    shown: Rc<RefCell<Vec<Signing>>>,
}
impl Consent for Holder {
    fn approve(&mut self, what: &Signing) -> bool {
        self.shown.borrow_mut().push(what.clone());
        self.yes
    }
}

struct Phone(Session<Holder>);
impl Mobile for Phone {
    fn commit(&mut self) -> Result<Commitment, String> {
        Ok(self.0.commit(&mut OsRng))
    }
    fn respond(&mut self, round: &SigningRound) -> Result<MobileShare, String> {
        self.0.respond(round).map_err(|e| e.to_string())
    }
}

fn printed(d: &Dir) -> (PathBuf, MobileHalf) {
    let home = d.0.join("home");
    let half = d.0.join("m.half");
    init(
        &home,
        &InitOptions {
            class: Class::Heavy,
            emission: "ksg:em:test:000001".into(),
            serial: 1,
            artifact: Uri::parse("urn:example:artefact").unwrap(),
            anchor: None,
            channel: None,
            base: None,
        },
    )
    .unwrap();
    let mut r = Reader::open(&home, Box::new(ksg_cli_v2::mobile::NoMobile)).unwrap();
    r.packet().unwrap();
    r.buyer_key().unwrap();
    // E-4: the client's key is born, its mobile half to the file (CH-5b).
    r.initiate(&half).unwrap();
    drop(r);
    let m = MobileHalf::from_bytes(&std::fs::read(&half).unwrap()).unwrap();
    (home, m)
}

#[test]
fn a_round_the_holder_refuses_signs_nothing_and_writes_nothing() {
    let d = Dir::new("refuse");
    let (home, half) = printed(&d);
    let before = std::fs::read(home.join("container.ksg")).unwrap();
    let holder = Holder {
        yes: false,
        shown: Rc::default(),
    };
    let mut r = Reader::open(&home, Box::new(Phone(Session::new(half, holder.clone())))).unwrap();
    let err = r.open_journal().unwrap_err();
    assert!(err.contains("the holder refused to sign"), "{err}");
    drop(r);
    assert_eq!(std::fs::read(home.join("container.ksg")).unwrap(), before);
    assert_eq!(
        holder.shown.borrow().len(),
        1,
        "asked once, before any share"
    );
}

#[test]
fn the_holder_is_shown_what_each_round_signs() {
    let d = Dir::new("approve");
    let (home, half) = printed(&d);
    let holder = Holder {
        yes: true,
        shown: Rc::default(),
    };
    let mut r = Reader::open(&home, Box::new(Phone(Session::new(half, holder.clone())))).unwrap();
    r.open_journal().unwrap();
    let shown = holder.shown.borrow();
    assert!(!shown.is_empty());
    for s in shown.iter() {
        assert!(s.len > 0);
        assert!(s.to_string().contains(&s.digest), "{s}");
    }
}

#[test]
fn the_wire_refuses_what_it_cannot_do() {
    let d = Dir::new("wire");
    let (_, half) = printed(&d);
    let mut s = Session::new(half, ApproveAll);
    let round = "{\"op\":\"respond\",\"round\":\"AAAA\"}";
    assert!(handle_line(&mut s, "not json", &mut OsRng).starts_with("{\"err\":\"request:"));
    assert!(handle_line(&mut s, round, &mut OsRng).contains("err"));
    assert!(handle_line(&mut s, "{\"op\":\"commit\"}", &mut OsRng).starts_with("{\"ok\":"));
}

#[test]
fn a_json_message_is_described_by_its_type() {
    let s = Signing::of(br#"{"type":"Seal","v":3}"#);
    assert_eq!(s.doc_type.as_deref(), Some("Seal"));
    assert_eq!(Signing::of(b"\x00\x01").doc_type, None);
}
