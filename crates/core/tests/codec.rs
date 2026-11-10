use bgp_hijack_core::{
    codec::*,
    model::{AddressFamily, Asn},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    source: String,
    hex: String,
    outcome: String,
}

fn fixtures() -> Vec<Case> {
    serde_json::from_str(include_str!("fixtures/control-messages.json")).unwrap()
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture(name: &str) -> Vec<u8> {
    unhex(
        &fixtures()
            .into_iter()
            .find(|case| case.name == name)
            .unwrap()
            .hex,
    )
}
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![255; 16];
    output.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    output.push(kind);
    output.extend_from_slice(body);
    output
}
fn decode(bytes: &[u8]) -> Result<ControlMessage, CodecError> {
    decode_control(&Frame::from_bytes(bytes)?)
}
fn open(bytes: &[u8]) -> OpenMessage {
    let ControlMessage::Open(open) = decode(bytes).unwrap() else {
        panic!("expected OPEN")
    };
    open
}

#[test]
fn independent_corpus_is_replayed_in_normal_tests() {
    for case in fixtures() {
        assert!(!case.source.is_empty());
        let bytes = unhex(&case.hex);
        let result = Frame::from_bytes(&bytes);
        match case.outcome.as_str() {
            "keepalive" => assert_eq!(decode(&bytes).unwrap(), ControlMessage::Keepalive),
            "open" => {
                open(&bytes);
            }
            "notification" => assert_eq!(
                decode(&bytes).unwrap(),
                ControlMessage::Notification(NotificationMessage {
                    code: 6,
                    subcode: 2,
                    data: vec![0xde, 0xad, 0xbe, 0xef]
                })
            ),
            "update" => {
                let raw = result.unwrap();
                assert_eq!(raw.body(), &[0; 4]);
                assert_eq!(decode_control(&raw), Err(CodecError::UpdateNotImplemented));
            }
            "invalid_marker" => assert_eq!(result, Err(CodecError::InvalidMarker)),
            "invalid_length" => assert!(matches!(result, Err(CodecError::InvalidLength(18)))),
            "invalid_type" => assert_eq!(result, Err(CodecError::InvalidMessageType(255))),
            "truncated" => assert!(matches!(result, Err(CodecError::Truncated { .. }))),
            "invalid_open" => assert_eq!(decode(&bytes), Err(CodecError::UnsupportedVersion(3))),
            other => panic!("unhandled fixture {}: {other}", case.name),
        }
    }
}

#[test]
fn every_split_and_coalesced_messages_preserve_frames() {
    for name in [
        "keepalive",
        "open-dual-as4",
        "open-extended",
        "notification",
        "empty-update",
    ] {
        let bytes = fixture(name);
        let expected = Frame::from_bytes(&bytes).unwrap();
        for split in 0..=bytes.len() {
            let mut decoder = FrameDecoder::default();
            let (n1, first) = decoder.consume(&bytes[..split]).unwrap();
            let (n2, second) = decoder.consume(&bytes[split..]).unwrap();
            assert_eq!(n1 + n2, bytes.len());
            assert_eq!(first.or(second).unwrap(), expected);
            decoder.finish().unwrap();
        }
    }
    let messages = [
        fixture("keepalive"),
        fixture("open-dual-as4"),
        fixture("notification"),
    ];
    let combined = messages.concat();
    let mut decoder = FrameDecoder::default();
    let mut offset = 0;
    for message in &messages {
        let (used, got) = decoder.consume(&combined[offset..]).unwrap();
        assert_eq!(used, message.len());
        assert_eq!(got.unwrap(), Frame::from_bytes(message).unwrap());
        offset += used;
    }
    assert_eq!(offset, combined.len());
    decoder.finish().unwrap();
}

#[test]
fn limits_are_checked_at_header_and_failure_is_terminal() {
    for (kind, length) in [(1, 28), (2, 22), (3, 20), (4, 20), (3, 4097), (3, 18)] {
        let mut bytes = vec![255; 16];
        bytes.extend_from_slice(&(length as u16).to_be_bytes());
        bytes.push(kind);
        let mut decoder = FrameDecoder::default();
        let error = decoder.consume(&bytes).unwrap_err();
        assert_eq!(
            error.notification().unwrap(),
            NotificationMessage {
                code: 1,
                subcode: 2,
                data: (length as u16).to_be_bytes().to_vec()
            }
        );
        assert_eq!(
            decoder.consume(&fixture("keepalive")),
            Err(CodecError::DecoderFailed)
        );
        assert_eq!(decoder.finish(), Err(CodecError::DecoderFailed));
    }
    let maximum = frame(3, &vec![0; MAX_MESSAGE_LEN - HEADER_LEN]);
    assert_eq!(maximum.len(), 4096);
    let parsed = Frame::from_bytes(&maximum).unwrap();
    assert_eq!(
        encode_control(&decode_control(&parsed).unwrap()).unwrap(),
        maximum
    );
    let too_big = ControlMessage::Notification(NotificationMessage {
        code: 1,
        subcode: 0,
        data: vec![0; 4076],
    });
    assert_eq!(encode_control(&too_big), Err(CodecError::EncodingLimit));
    let mut decoder = FrameDecoder::default();
    let mut huge = fixture("keepalive");
    huge.resize(1024 * 1024, 0);
    assert_eq!(decoder.consume(&huge).unwrap().0, 19);
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn eof_distinguishes_clean_header_and_body_truncation() {
    let bytes = fixture("open-dual-as4");
    for cut in 1..bytes.len() {
        let mut decoder = FrameDecoder::default();
        assert!(decoder.consume(&bytes[..cut]).unwrap().1.is_none());
        let error = decoder.finish().unwrap_err();
        assert!(matches!(error, CodecError::Truncated { received, .. } if received == cut));
        assert!(error.notification().is_none());
    }
    let mut decoder = FrameDecoder::default();
    decoder.finish().unwrap();
    assert_eq!(decoder.consume(&[]), Err(CodecError::DecoderFinished));
}

#[test]
fn encoder_matches_independent_wire_bytes_and_asn_semantics() {
    let local = OpenMessage::new(
        Asn(4_200_000_001),
        90,
        0xcb007101,
        &[AddressFamily::Ipv4, AddressFamily::Ipv6],
    );
    assert_eq!(
        encode_control(&ControlMessage::Open(local.clone())).unwrap(),
        fixture("open-dual-as4")
    );
    assert_eq!(open(&fixture("open-extended")), local);
    assert_eq!(
        encode_control(&ControlMessage::Keepalive).unwrap(),
        fixture("keepalive")
    );
    let mut remote = local.clone();
    remote.my_as = 65000;
    assert_eq!(remote.effective_asn().unwrap(), Asn(4_200_000_001));
    assert_eq!(
        encode_control(&ControlMessage::Open(remote)).unwrap()[20..22],
        AS_TRANS.to_be_bytes()
    );
    let small = OpenMessage::new(Asn(64512), 0, 1, &[AddressFamily::Ipv4]);
    assert_eq!(
        encode_control(&ControlMessage::Open(small)).unwrap()[20..22],
        64512_u16.to_be_bytes()
    );
}

#[test]
fn capability_order_duplicates_unknowns_and_compatibility_are_distinct() {
    let local = open(&fixture("open-dual-as4"));
    let mut peer = local.clone();
    peer.hold_time = 30;
    peer.capabilities.reverse();
    peer.capabilities
        .push(Capability::FourOctetAsn(Asn(4_200_000_001)));
    peer.capabilities.push(Capability::Unknown {
        code: 200,
        value: vec![1, 2, 3],
    });
    let decoded = open(&encode_control(&ControlMessage::Open(peer.clone())).unwrap());
    assert_eq!(decoded.capabilities, peer.capabilities);
    let negotiated = validate_open(
        &local,
        &peer,
        Asn(4_200_000_001),
        &[AddressFamily::Ipv4, AddressFamily::Ipv6],
    )
    .unwrap();
    assert_eq!(negotiated.hold_time, 30);
    peer.hold_time = 0;
    assert_eq!(
        validate_open(&local, &peer, Asn(4_200_000_001), &[AddressFamily::Ipv4])
            .unwrap()
            .hold_time,
        0
    );
    assert!(matches!(
        validate_open(&local, &peer, Asn(42), &[AddressFamily::Ipv4]),
        Err(OpenCompatibilityError::AsnMismatch { .. })
    ));
    peer.capabilities
        .retain(|cap| *cap != Capability::unicast(AddressFamily::Ipv6));
    assert_eq!(
        validate_open(&local, &peer, Asn(4_200_000_001), &[AddressFamily::Ipv6]),
        Err(OpenCompatibilityError::MissingFamily(AddressFamily::Ipv6))
    );
    peer.capabilities
        .push(Capability::FourOctetAsn(Asn(4200000002)));
    assert_eq!(
        peer.effective_asn(),
        Err(OpenCompatibilityError::ConflictingAsns)
    );
    let legacy = open(&fixture("open-legacy"));
    assert_eq!(
        validate_open(&local, &legacy, Asn(65000), &[AddressFamily::Ipv4]),
        Err(OpenCompatibilityError::MissingFourOctetAsn)
    );
    for families in [&[][..], &[AddressFamily::Ipv4, AddressFamily::Ipv4][..]] {
        assert!(matches!(
            validate_open(&local, &local, Asn(4200000001), families),
            Err(OpenCompatibilityError::LocalRequirements(_))
        ));
    }
}

#[test]
fn open_fields_and_nested_boundaries_fail_with_protocol_context() {
    let good = fixture("open-dual-as4");
    for hold in [1_u16, 2] {
        let mut bytes = good.clone();
        bytes[22..24].copy_from_slice(&hold.to_be_bytes());
        assert_eq!(
            decode(&bytes).unwrap_err().notification().unwrap().subcode,
            6
        );
    }
    let mut bytes = good.clone();
    bytes[24..28].fill(0);
    assert_eq!(decode(&bytes), Err(CodecError::InvalidRouterId));
    for (offset, value) in [(28, 19), (30, 19), (32, 5), (32, 3)] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        let error = decode(&bytes).unwrap_err();
        assert_eq!(error.notification().unwrap().code, 2);
    }
    let mut bytes = good.clone();
    bytes[29] = 99;
    assert!(matches!(
        decode(&bytes),
        Err(CodecError::UnsupportedParameter { kind: 99, .. })
    ));
    let mut bytes = good;
    bytes[41] = 123; // RFC 4760 reserved octet is ignored.
    assert!(decode(&bytes).is_ok());
    for body in [
        vec![4, 0, 1, 0, 0, 0, 0, 0, 1, 1, 255],
        vec![4, 0, 1, 0, 0, 0, 0, 0, 1, 1, 255, 0],
    ] {
        assert!(matches!(
            decode(&frame(1, &body)),
            Err(CodecError::MalformedOpen(_))
        ));
    }
}

#[test]
fn extended_open_boundaries_and_encoding_limits() {
    let mut message = open(&fixture("open-dual-as4"));
    message.capabilities.push(Capability::Unknown {
        code: 200,
        value: vec![7; 255],
    });
    let encoded = encode_control(&ControlMessage::Open(message.clone())).unwrap();
    assert_eq!(&encoded[28..30], &[255, 255]);
    assert_eq!(open(&encoded), message);
    let mut bytes = fixture("open-extended");
    bytes[28] = 1;
    assert!(decode(&bytes).is_ok()); // non-extended length ignored after marker detection.
    for offset in [31, 34] {
        let mut broken = bytes.clone();
        broken[offset] += 1;
        assert!(matches!(decode(&broken), Err(CodecError::MalformedOpen(_))));
    }
    message.capabilities.extend(std::iter::repeat_n(
        Capability::Unknown {
            code: 200,
            value: vec![0; 255],
        },
        16,
    ));
    assert_eq!(
        encode_control(&ControlMessage::Open(message)),
        Err(CodecError::EncodingLimit)
    );
}

#[test]
fn compatibility_notifications_preserve_missing_capabilities_and_local_errors() {
    let local = open(&fixture("open-dual-as4"));
    let missing = OpenCompatibilityError::MissingFamily(AddressFamily::Ipv6)
        .notification(&local)
        .unwrap();
    assert_eq!(
        missing,
        NotificationMessage {
            code: 2,
            subcode: 7,
            data: vec![1, 4, 0, 2, 0, 1]
        }
    );
    let missing = OpenCompatibilityError::MissingFourOctetAsn
        .notification(&local)
        .unwrap();
    assert_eq!(missing.data, vec![65, 4, 0xfa, 0x56, 0xea, 1]);
    assert_eq!(
        OpenCompatibilityError::ConflictingAsns
            .notification(&local)
            .unwrap()
            .subcode,
        2
    );
    let mut broken_local = local.clone();
    broken_local.router_id = 0;
    let error = validate_open(
        &broken_local,
        &local,
        Asn(4200000001),
        &[AddressFamily::Ipv4],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        OpenCompatibilityError::LocalRequirements(_)
    ));
    assert!(error.notification(&broken_local).is_none());
}
