#![no_main]
use libfuzzer_sys::fuzz_target;
use bgp_hijack_analysis::tcp::TcpStream;
fuzz_target!(|data:&[u8]|{if data.len()>8192{return;}let mut t=TcpStream::new(Some(u32::MAX-128),4096);for chunk in data.chunks(64){if chunk.len()<4{break;}let seq=u32::from_be_bytes([chunk[0],chunk[1],chunk[2],chunk[3]]);let _=t.push(seq,&chunk[4..]);}let _=t.finish();});
