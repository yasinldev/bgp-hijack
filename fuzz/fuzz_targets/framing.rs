#![no_main]
use bgp_hijack_core::codec::{FrameDecoder, MAX_MESSAGE_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    // Compare arbitrary chunk boundaries with the same complete byte stream.
    fn frames(data: &[u8], chunk: usize) -> Vec<bgp_hijack_core::codec::Frame> {
        let mut decoder = FrameDecoder::default();
        let mut output = Vec::new();
        for part in data.chunks(chunk) {
            let mut offset = 0;
            while offset < part.len() {
                match decoder.consume(&part[offset..]) {
                    Ok((consumed, frame)) => {
                        assert!(consumed > 0);
                        offset += consumed;
                        assert!(decoder.buffered_len() <= MAX_MESSAGE_LEN);
                        if let Some(frame) = frame {
                            output.push(frame);
                        }
                    }
                    Err(_) => {
                        assert!(decoder.consume(&[]).is_err());
                        return output;
                    }
                }
            }
        }
        let _ = decoder.finish();
        output
    }
    assert_eq!(
        frames(data, data.first().copied().unwrap_or(0) as usize + 1),
        frames(data, 8192)
    );
});
