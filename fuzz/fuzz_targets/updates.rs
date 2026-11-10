#![no_main]
use libfuzzer_sys::fuzz_target;
use bgp_hijack_core::{update::{decode_update,DecodeContext},model::AddressFamily};
fuzz_target!(|data:&[u8]|{if data.len()>4096{return;}for width in [2,4]{for add in [false,true]{let mut ctx=DecodeContext{asn_width:width,..Default::default()};if add{ctx.add_path.extend([AddressFamily::Ipv4,AddressFamily::Ipv6]);}let _=decode_update(data,&ctx);}}});
