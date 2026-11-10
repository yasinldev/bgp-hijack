#![no_main]
use libfuzzer_sys::fuzz_target;
use bgp_hijack_analysis::mrt::MrtDecoder;
fuzz_target!(|data:&[u8]|{if data.len()<4||data.len()>8192{return;}let mut d=MrtDecoder::new("fuzz".into());let _=d.decode(u16::from_be_bytes([data[0],data[1]]),u16::from_be_bytes([data[2],data[3]]),1.0,&data[4..]);});
