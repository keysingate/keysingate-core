//! The layers written zone by zone (owner's decision 18.10 "A"): a zone's
//! fields sealed under its level's key and padded with noise to a constant
//! width; a zone never written is noise of the same width; a lower level's
//! key does not open a higher level's zone.

mod stand;

use ksg_container_v2::container::Evidence;
use ksg_container_v2::layers::LayerKey;
use ksg_container_v2::layers::Level;
use ksg_container_v2::layout::{
    open_zone, seal_zone, zone_position, ZoneError, CHAIN_POSITIONS, ZONE_BYTES, ZONE_POSITIONS,
    ZONE_ROOM,
};
use ksg_container_v2::{Operation as Op, Zone};
use ksg_core_v2::doc::Class;
use stand::{Page, Stand, Who};

fn noise(byte: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ byte).collect()
}

#[test]
fn a_sealed_zone_is_one_width_whatever_it_holds_and_opens_with_its_key_alone() {
    let key = LayerKey::from_bytes([1; 32]);
    let lower = LayerKey::from_bytes([0; 32]);
    let short = seal_zone(&key, b"template", 1, b"p", &noise(7, ZONE_BYTES)).unwrap();
    let long = seal_zone(
        &key,
        b"template",
        1,
        &[9u8; ZONE_ROOM],
        &noise(8, ZONE_BYTES),
    )
    .unwrap();
    assert_eq!(short.len(), ZONE_BYTES);
    assert_eq!(
        long.len(),
        ZONE_BYTES,
        "the width says nothing of the length"
    );
    assert_eq!(open_zone(&key, b"template", 1, &short).unwrap(), b"p");
    assert_eq!(
        open_zone(&key, b"template", 1, &long).unwrap(),
        vec![9u8; ZONE_ROOM]
    );
    assert_eq!(
        open_zone(&lower, b"template", 1, &short),
        Err(ZoneError::Sealed),
        "a lower level's key does not open it"
    );
    assert_eq!(
        open_zone(&key, b"template", 2, &short),
        Err(ZoneError::Sealed),
        "nor does it open as another position"
    );
    assert_eq!(
        open_zone(&key, b"template", 1, &noise(3, ZONE_BYTES)),
        Err(ZoneError::Sealed),
        "noise is not a zone"
    );
    assert_eq!(
        seal_zone(
            &key,
            b"template",
            1,
            &[0u8; ZONE_ROOM + 1],
            &noise(1, ZONE_BYTES)
        ),
        Err(ZoneError::TooLarge(ZONE_ROOM + 1))
    );
}

#[test]
fn the_container_takes_sealed_zones_in_order_once_each_and_only_when_open() {
    let mut s = Stand::new(Class::Light, 9100);
    let key = LayerKey::from_bytes([1; 32]);
    let zone = |p: usize| seal_zone(&key, b"t", p, b"fields", &noise(p as u8, ZONE_BYTES)).unwrap();
    assert!(
        s.c.write_zone(Zone::Release, zone(0)).is_err(),
        "no noise laid, nothing written"
    );
    s.c.lay_zone_noise(&noise(5, ZONE_POSITIONS * ZONE_BYTES))
        .unwrap();
    assert!(s
        .c
        .lay_zone_noise(&noise(6, ZONE_POSITIONS * ZONE_BYTES))
        .is_err());
    let before: Vec<Vec<u8>> = (0..ZONE_POSITIONS)
        .map(|p| s.c.sealed_zone(p).unwrap().to_vec())
        .collect();
    assert!(
        before.iter().all(|z| z.len() == ZONE_BYTES),
        "noise of the zone's width"
    );

    assert!(
        s.c.write_zone(Zone::Release, vec![0; 10]).is_err(),
        "another width"
    );
    assert!(
        s.c.write_zone(Zone::Packet, zone(1)).is_err(),
        "the packet zone is not open at printing"
    );
    assert_eq!(s.c.write_zone(Zone::Release, zone(0)).unwrap(), 0);
    assert!(
        s.c.write_zone(Zone::Release, zone(0)).is_err(),
        "written once"
    );
    assert_eq!(s.c.sealed_zone(0).unwrap(), zone(0).as_slice());
    assert_eq!(
        s.c.sealed_zone(1).unwrap(),
        before[1].as_slice(),
        "the rest is still noise"
    );
    assert_eq!(
        zone_position(Zone::Chain, CHAIN_POSITIONS - 1),
        Ok(ZONE_POSITIONS - 1)
    );
    assert!(
        zone_position(Zone::Chain, CHAIN_POSITIONS).is_err(),
        "a hundred and four chain positions"
    );
}

/// A hundred and four chain positions (owner's decision 18.10, after CH-15's
/// hundred transfers between owners, and four more): past the six C-3 gave,
/// every one takes its write once, and the hundred and fifth has no room.
#[test]
fn the_chain_takes_a_hundred_and_four_positions_and_no_more() {
    let mut s = Stand::new(Class::Light, 9101);
    s.press(Op::ApplyPacket, &[Who::Issuer], Evidence::None, Page::None)
        .expect("packet");
    let buyer = s.parties.buyer.public();
    s.press(
        Op::ApplyBuyerKey,
        &[Who::Buyer, Who::Owner],
        Evidence::KeyLaid {
            to: buyer,
            up_to: Level(2),
        },
        Page::None,
    )
    .expect("buyer's key: the chain opens");
    s.c.lay_zone_noise(&noise(4, ZONE_POSITIONS * ZONE_BYTES))
        .unwrap();
    let key = LayerKey::from_bytes([2; 32]);
    for nth in 0..CHAIN_POSITIONS {
        let p = zone_position(Zone::Chain, nth).unwrap();
        let sealed = seal_zone(&key, b"t", p, b"owner", &noise(nth as u8, ZONE_BYTES)).unwrap();
        assert_eq!(s.c.write_zone(Zone::Chain, sealed).unwrap(), p);
        assert!(s.c.sealed_zone_written(p));
    }
    let extra = seal_zone(&key, b"t", 0, b"owner", &noise(1, ZONE_BYTES)).unwrap();
    assert!(
        s.c.write_zone(Zone::Chain, extra).is_err(),
        "the hundred and fifth has no position"
    );
    assert_eq!(
        open_zone(
            &key,
            b"t",
            ZONE_POSITIONS - 1,
            s.c.sealed_zone(ZONE_POSITIONS - 1).unwrap()
        )
        .unwrap(),
        b"owner"
    );
}
