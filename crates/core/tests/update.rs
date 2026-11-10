use bgp_hijack_core::{model::AddressFamily, update::*};
fn bytes(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
}
#[test]
fn independent_ipv4_fixture_and_required_attributes() {
    // RFC 4271 UPDATE body: origin IGP, AS_SEQUENCE 65536, next hop 192.0.2.1.
    let b = bytes(
        "00 00 00 14 40 01 01 00 40 02 06 02 01 00 01 00 00 40 03 04 c0 00 02 01 18 cb 00 71",
    );
    let u = decode_update(&b, &DecodeContext::default()).unwrap();
    assert_eq!(u.attributes.origin_asn(), Some(65536));
    assert_eq!(u.announcements[0].prefix.to_string(), "203.0.113.0/24");
    for n in 0..b.len() - 4 {
        assert!(
            decode_update(&b[..n], &DecodeContext::default()).is_err(),
            "{n}"
        );
    }
    let mut bad = b.clone();
    bad[4] = 0x80;
    assert!(decode_update(&bad, &DecodeContext::default()).is_err());
}
#[test]
fn ipv6_mp_and_withdraw() {
    let b = bytes(
        "00 00 00 2a 40 01 01 00 40 02 06 02 01 00 01 00 00 80 0e 1a 00 02 01 10 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 00 20 20 01 0d b8",
    );
    let u = decode_update(&b, &DecodeContext::default()).unwrap();
    assert_eq!(u.announcements[0].prefix.to_string(), "2001:db8::/32");
    let w = bytes("00 00 00 0b 80 0f 08 00 02 01 20 20 01 0d b8");
    assert_eq!(
        decode_update(&w, &DecodeContext::default())
            .unwrap()
            .withdrawals
            .len(),
        1
    );
}
#[test]
fn as4_reconstruction_sets_and_addpath() {
    let a = bytes("40 02 06 02 02 fb f0 5b a0 c0 11 06 02 01 00 01 00 00");
    let u = decode_attributes(
        &a,
        &DecodeContext {
            asn_width: 2,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(u.attributes.path[0].asns, vec![64496]);
    assert_eq!(u.attributes.origin_asn(), Some(65536));
    let set = decode_attributes(
        &bytes("40 02 06 01 01 00 01 00 00"),
        &DecodeContext::default(),
        None,
    )
    .unwrap();
    assert_eq!(set.attributes.origin_asn(), None);
    let n = nlri(&bytes("00 00 00 2a 18 cb 00 71"), AddressFamily::Ipv4, true).unwrap();
    assert_eq!(n[0].path_id, Some(42));
    assert!(nlri(&[33, 0, 0, 0, 0, 0], AddressFamily::Ipv4, false).is_err());
}
