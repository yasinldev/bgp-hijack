#![no_main]
use bgp_hijack_core::codec::{Frame, FrameDecoder, decode_control, encode_control};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let mut decoder = FrameDecoder::default();
    let Ok((_, Some(frame))) = decoder.consume(data) else {
        return;
    };
    let Ok(message) = decode_control(&frame) else {
        return;
    };
    // Decoding may preserve conflicting ASN capabilities or less compact OPEN
    // layouts that the outbound encoder intentionally rejects/normalizes.
    if let Ok(bytes) = encode_control(&message) {
        let decoded = decode_control(&Frame::from_bytes(&bytes).unwrap()).unwrap();
        let canonical = encode_control(&decoded).unwrap();
        assert_eq!(bytes, canonical);
    }
});
