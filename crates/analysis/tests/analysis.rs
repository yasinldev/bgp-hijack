use bgp_hijack_analysis::{
    bundle::{BundleWriter, report},
    lookup::{LookupClient, Query},
    model::*,
    mrt::MrtDecoder,
    ris,
    state::Analyzer,
    tcp::TcpStream,
};
use bgp_hijack_core::update::{Attributes, PathSegment};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};
fn source(peer: &str) -> Source {
    Source {
        source: "fixture".into(),
        collector: Some("rrc00".into()),
        peer: peer.into(),
        epoch: 1,
    }
}
fn event(seq: u64, peer: &str, prefix: &str, asn: u32) -> AnalysisEvent {
    AnalysisEvent {
        schema_version: 1,
        run_id: "test".into(),
        sequence: seq,
        received_at: "2026-11-10T00:00:00Z".into(),
        elapsed_ms: seq,
        evidence_refs: vec!["fixture".into()],
        observation: Observation::Route(RouteObservation {
            source: source(peer),
            source_time: Some(seq as f64),
            prefix: prefix.parse().unwrap(),
            address_family: prefix
                .parse::<bgp_hijack_core::model::CanonicalPrefix>()
                .unwrap()
                .family(),
            path_id: None,
            action: RouteAction::Announce,
            attributes: Attributes {
                path: vec![PathSegment {
                    kind: 2,
                    asns: vec![64496, asn],
                }],
                ..Default::default()
            },
        }),
    }
}
#[test]
fn source_local_changes_gaps_and_ambiguous_origin() {
    let mut a = Analyzer::new(AnalysisLimits::default());
    a.apply(&event(1, "a", "203.0.113.0/24", 65536)).unwrap();
    assert!(a.findings.is_empty());
    a.apply(&event(2, "a", "203.0.113.0/24", 65536)).unwrap();
    assert!(a.findings.is_empty());
    a.apply(&event(3, "b", "203.0.113.0/24", 65537)).unwrap();
    assert_eq!(a.snapshot().len(), 2);
    assert!(
        a.findings
            .iter()
            .any(|f| f.kind == FindingKind::MultipleOriginsObserved)
    );
    a.apply(&event(4, "a", "203.0.113.0/24", 65538)).unwrap();
    assert!(
        a.findings
            .iter()
            .any(|f| f.kind == FindingKind::OriginChanged)
    );
    let n = a.findings.len();
    let mut gap = event(5, "a", "203.0.113.0/24", 1);
    gap.observation = Observation::Gap {
        source: None,
        reason: "disconnect".into(),
    };
    a.apply(&gap).unwrap();
    a.apply(&event(6, "a", "203.0.113.0/24", 65539)).unwrap();
    assert_eq!(a.findings.len(), n);
    a.apply(&event(7, "a", "203.0.113.0/25", 65539)).unwrap();
    assert!(
        a.findings
            .iter()
            .any(|f| f.kind == FindingKind::MoreSpecificObserved)
    );
    let mut ambiguous = event(8, "a", "203.0.113.0/24", 65539);
    if let Observation::Route(r) = &mut ambiguous.observation {
        r.attributes.path[0].kind = 1;
    }
    let n = a
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::OriginChanged)
        .count();
    a.apply(&ambiguous).unwrap();
    assert_eq!(
        n,
        a.findings
            .iter()
            .filter(|f| f.kind == FindingKind::OriginChanged)
            .count()
    );
}
#[test]
fn bundle_roundtrip_integrity_truncation_and_existing_dir() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("run");
    let mut w =
        BundleWriter::create(&dir, "fixture".into(), json!({}), AnalysisLimits::default()).unwrap();
    let reference = w.evidence(b"independent evidence").unwrap();
    for e in [
        event(1, "a", "203.0.113.0/24", 65536),
        event(2, "a", "203.0.113.0/24", 65537),
    ] {
        w.record(e.observation, vec![reference.clone()]).unwrap();
    }
    let live = w.finish(true).unwrap();
    let offline = report(&dir).unwrap();
    assert_eq!(live.findings, offline.findings);
    assert_eq!(offline.coverage, "selected_input");
    assert!(
        BundleWriter::create(&dir, "fixture".into(), json!({}), AnalysisLimits::default()).is_err()
    );
    std::fs::write(dir.join(reference), b"tampered").unwrap();
    let invalid = report(&dir).unwrap();
    assert_eq!(invalid.coverage, "partial");
    assert!(invalid.findings.is_empty());
    let events = dir.join("events.jsonl");
    let mut b = std::fs::read(&events).unwrap();
    b.pop();
    std::fs::write(events, b).unwrap();
    assert!(
        report(&dir)
            .unwrap()
            .gaps
            .iter()
            .any(|s| s.contains("truncated"))
    );
}
#[test]
fn tcp_wrap_reordering_retransmission_conflict_and_gap() {
    let mut t = TcpStream::new(Some(u32::MAX - 1), 64);
    assert!(t.push(1, b"de").unwrap().is_empty());
    assert_eq!(t.push(u32::MAX - 1, b"abc").unwrap(), b"abcde");
    assert!(t.push(u32::MAX - 1, b"abcde").unwrap().is_empty());
    assert!(t.finish().is_ok());
    assert!(t.push(1, b"X").is_err());
    assert!(t.push(3, b"f").is_err());
    let mut t = TcpStream::new(Some(0), 64);
    t.push(1, b"b").unwrap();
    assert!(t.finish().is_err());
    assert!(t.push(100, b"x").is_err());
}
#[test]
fn ris_normalization_preserves_set_and_family() {
    let v = json!({"type":"ris_message","data":{"host":"rrc00","peer":"192.0.2.1","peer_asn":"65536","timestamp":1.0,"type":"UPDATE","path":[64496,[65536,65537]],"announcements":[{"next_hop":"2001:db8::1","prefixes":["2001:db8::/32"]}],"withdrawals":["203.0.113.0/24"]}});
    let events = ris::normalize(&v, 3).unwrap();
    assert_eq!(events.len(), 2);
    let Observation::Route(r) = &events[1] else {
        panic!()
    };
    assert_eq!(r.attributes.origin_asn(), None);
    assert_eq!(r.source.epoch, 3);
    let mut excessive = v.clone();
    excessive["data"]["host"] = json!("x".repeat(10000));
    assert!(ris::normalize(&excessive, 3).is_err());
    let mut amplified = v.clone();
    amplified["data"]["announcements"][0]["prefixes"] = json!(vec!["2001:db8::/32"; 4097]);
    assert!(ris::normalize(&amplified, 3).is_err());
    let mut bad = v;
    bad["data"]["path"] = json!([4294967296u64]);
    assert!(ris::normalize(&bad, 3).is_err());
}
#[test]
fn mrt_peer_index_and_rib_independent_bytes() {
    let mut d = MrtDecoder::new("fixture".into());
    let peer = hex("c0000201 0000 0001 02 c0000202 c0000202 00010000");
    assert!(d.decode(13, 1, 1.0, &peer).unwrap().is_empty());
    let rib = hex("00000001 18 cb0071 0001 0000 00000001 000d 40010100 400206020100010000");
    let e = d.decode(13, 2, 1.0, &rib).unwrap();
    let Observation::Route(r) = &e[0] else {
        panic!()
    };
    assert_eq!(r.attributes.origin_asn(), Some(65536));
    assert_eq!(r.prefix.to_string(), "203.0.113.0/24");
    let rib6 = hex(
        "00000001 20 20010db8 0001 0000 00000001 0021 40010100 400206020100010000 800e11 10 20010db8000000000000000000000001",
    );
    let ipv6 = d.decode(13, 4, 1.0, &rib6).unwrap();
    let Observation::Route(r6) = &ipv6[0] else {
        panic!()
    };
    assert_eq!(r6.prefix.to_string(), "2001:db8::/32");
    assert_eq!(r6.attributes.next_hops, vec!["2001:db8::1"]);
    let add =
        hex("00000001 18 cb0071 0001 0000 00000001 0000002a 000d 40010100 400206020100010000");
    let additional = d.decode(13, 8, 1.0, &add).unwrap();
    let Observation::Route(extra) = &additional[0] else {
        panic!()
    };
    assert_eq!(extra.path_id, Some(42));
    for n in 0..rib.len() {
        assert!(d.decode(13, 2, 1.0, &rib[..n]).is_err());
    }
    assert!(matches!(
        d.decode(12, 1, 1.0, &[]).unwrap()[0],
        Observation::Gap { .. }
    ));
}
fn hex(s: &str) -> Vec<u8> {
    let s = s.replace(' ', "");
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).unwrap())
        .collect()
}
fn server(
    replies: Vec<(u16, &'static str, &'static str)>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        for (status, headers, body) in replies {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = [0; 8192];
            assert!(s.read(&mut request).unwrap() > 0);
            write!(s,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",body.len()).unwrap();
        }
    });
    (url, h)
}
#[tokio::test]
async fn lookup_retry_metadata_empty_and_bad_json() {
    let (url, h) = server(vec![
        (429, "Retry-After: 0\r\n", ""),
        (
            200,
            "",
            r#"{"status":"ok","data":{"prefix":"2001:db8::/32","asns":[65536,65537]},"data_call_status":"supported","time":"old"}"#,
        ),
    ]);
    let client = LookupClient::with_base(&url).unwrap();
    let r = client
        .lookup(Query::Ip("2001:db8::1".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(r.status, "observed");
    assert_eq!(r.responses["network_info"]["time"], "old");
    h.join().unwrap();
    let (url, h) = server(vec![(
        200,
        "",
        r#"{"status":"ok","data":{"announced":false}}"#,
    )]);
    assert_eq!(
        LookupClient::with_base(&url)
            .unwrap()
            .lookup(Query::Prefix("203.0.113.0/24".parse().unwrap()))
            .await
            .unwrap()
            .status,
        "no_data"
    );
    h.join().unwrap();
    let (url, h) = server(vec![(200, "", "broken")]);
    assert!(
        LookupClient::with_base(&url)
            .unwrap()
            .lookup(Query::Ip("192.0.2.1".parse().unwrap()))
            .await
            .is_err()
    );
    h.join().unwrap();
}
#[test]
fn limits_and_incomplete_manifest() {
    let t = tempfile::tempdir().unwrap();
    let l = AnalysisLimits {
        record_bytes: 64,
        ..Default::default()
    };
    let d = t.path().join("r");
    let mut w = BundleWriter::create(&d, "test".into(), json!({}), l).unwrap();
    assert!(w.evidence(&[0; 65]).is_err());
    drop(w);
    assert_eq!(report(&d).unwrap().coverage, "partial");
    let _ = BTreeMap::<String, String>::new();
    let _ = Duration::from_secs(1);
}
#[test]
fn pcap_and_pcapng_full_session_and_explicit_context() {
    use bgp_hijack_analysis::pcap::{self, ContextFile};
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in [
        "session.pcap",
        "session.pcapng",
        "raw-ipv4.pcap",
        "raw-ipv6.pcap",
        "vlan.pcap",
        "sll.pcap",
        "sll2.pcap",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("run");
        let mut w =
            BundleWriter::create(&dir, name.into(), json!({}), AnalysisLimits::default()).unwrap();
        pcap::inspect(&fixtures.join(name), ContextFile::default(), &mut w).unwrap();
        let s = w.finish(true).unwrap();
        assert_eq!(s.coverage, "selected_input", "{:?}", s.gaps);
        assert!(
            s.findings
                .iter()
                .any(|f| f.kind == FindingKind::OriginChanged)
        );
        assert_eq!(s.findings, report(&dir).unwrap().findings);
    }
    for context in [None, Some("session-context.json")] {
        let temp = tempfile::tempdir().unwrap();
        let mut w = BundleWriter::create(
            &temp.path().join("r"),
            "midstream".into(),
            json!({}),
            AnalysisLimits::default(),
        )
        .unwrap();
        let c = context
            .map(|p| pcap::load_context(&fixtures.join(p)).unwrap())
            .unwrap_or_default();
        pcap::inspect(&fixtures.join("midstream.pcap"), c, &mut w).unwrap();
        let s = w.finish(true).unwrap();
        assert_eq!(
            s.coverage,
            if context.is_some() {
                "selected_input"
            } else {
                "partial"
            }
        );
    }
}
#[test]
fn compressed_mrt_and_input_limits() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let bytes = std::fs::read(fixtures.join("routes.mrt")).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&bytes).unwrap();
    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(&bytes).unwrap();
    for data in [bytes, gzip.finish().unwrap(), bz.finish().unwrap()] {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        std::fs::write(&input, data).unwrap();
        let mut w = BundleWriter::create(
            &temp.path().join("run"),
            "input".into(),
            json!({}),
            AnalysisLimits::default(),
        )
        .unwrap();
        bgp_hijack_analysis::mrt::inspect(&input, &mut w).unwrap();
        assert_eq!(w.finish(true).unwrap().routes, 1);
    }
}
#[tokio::test]
async fn websocket_mock_records_ack_and_routes() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let sub = ws.next().await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(sub.to_text().unwrap()).unwrap();
        let mut subscription = v["data"].clone();
        subscription
            .as_object_mut()
            .unwrap()
            .remove("socketOptions");
        ws.send(Message::Text(
            json!({"type":"ris_subscribe_ok","data":{"subscription":subscription}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        for (n, origin) in [(1, 65536), (2, 65537)] {
            ws.send(Message::Text(json!({"type":"ris_message","data":{"id":format!("id-{n}"),"host":"rrc00","peer":"192.0.2.1","peer_asn":"64496","timestamp":n,"type":"UPDATE","path":[64496,origin],"announcements":[{"next_hop":"192.0.2.1","prefixes":["203.0.113.0/24"]}]}}).to_string().into())).await.unwrap();
        }
        while let Some(Ok(message)) = ws.next().await {
            if message.is_text() {
                let _ = ws
                    .send(Message::Text(json!({"type":"pong"}).to_string().into()))
                    .await;
            }
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let opts = ris::WatchOptions {
        prefixes: vec!["203.0.113.0/24".parse().unwrap()],
        collectors: vec!["rrc00".into()],
        more_specific: false,
        duration: Duration::from_secs(1),
        output: temp.path().join("run"),
        limits: AnalysisLimits::default(),
    };
    let (s, code) = ris::watch_url(opts.clone(), &url).await.unwrap();
    assert_eq!(code, 0);
    assert!(
        s.findings
            .iter()
            .any(|f| f.kind == FindingKind::OriginChanged)
    );
    assert_eq!(s.findings, report(&opts.output).unwrap().findings);
    server.abort();
}
#[test]
fn stale_epoch_cannot_replace_newer_state() {
    let mut a = Analyzer::new(AnalysisLimits::default());
    let mut new = event(1, "a", "203.0.113.0/24", 65536);
    if let Observation::Route(r) = &mut new.observation {
        r.source.epoch = 3;
    }
    a.apply(&new).unwrap();
    a.apply(&event(2, "a", "203.0.113.0/24", 65537)).unwrap();
    assert_eq!(a.snapshot()[0].source.epoch, 3);
    assert!(a.findings.is_empty());
}
#[test]
fn origin_replacement_is_not_concurrent_moas() {
    let mut a = Analyzer::new(AnalysisLimits::default());
    a.apply(&event(1, "peer", "203.0.113.0/24", 65536)).unwrap();
    a.apply(&event(2, "peer", "203.0.113.0/24", 65537)).unwrap();
    assert_eq!(a.findings.len(), 2);
    assert!(
        !a.findings
            .iter()
            .any(|f| f.kind == FindingKind::MultipleOriginsObserved)
    );
}
#[test]
fn cancelled_reader_and_corrupt_middle_line_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("run");
    let mut w =
        BundleWriter::create(&dir, "fixture".into(), json!({}), AnalysisLimits::default()).unwrap();
    w.cancellation()
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        bgp_hijack_analysis::mrt::read_records(&b""[..], &mut w, "test".into()),
        Err(bgp_hijack_analysis::Error::Interrupted)
    ));
    drop(w);
    std::fs::write(dir.join("events.jsonl"), b"broken\n").unwrap();
    assert!(report(&dir).is_err());
}
#[test]
fn event_matches_independent_json_contract() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/event.json")).unwrap();
    assert_eq!(
        serde_json::to_value(event(1, "a", "203.0.113.0/24", 65536)).unwrap(),
        expected
    );
}
#[tokio::test]
async fn websocket_missing_ack_rejection_and_queue_overflow_are_partial() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    for mode in ["no_ack", "reject", "overflow"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let sub = ws.next().await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_str(sub.to_text().unwrap()).unwrap();
            if mode == "reject" {
                ws.send(Message::Text(
                    json!({"type":"ris_error","data":"bad filter"})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            }
            if mode == "overflow" {
                ws.send(Message::Text(json!({"type":"ris_subscribe_ok","data":{"subscription":{"host":"rrc00","prefix":v["data"]["prefix"]}}}).to_string().into())).await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let temp = tempfile::tempdir().unwrap();
        let limits = AnalysisLimits {
            queue_bytes: if mode == "overflow" {
                1
            } else {
                16 * 1024 * 1024
            },
            ..Default::default()
        };
        let opts = ris::WatchOptions {
            prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            collectors: vec!["rrc00".into()],
            more_specific: false,
            duration: Duration::from_secs(1),
            output: temp.path().join("run"),
            limits,
        };
        let (s, code) = ris::watch_url(opts, &url).await.unwrap();
        assert_ne!(code, 0);
        assert_eq!(s.coverage, "partial");
        assert!(!s.gaps.is_empty());
        task.abort();
    }
}
#[test]
fn evidence_io_failure_poisoning_and_missing_journal() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("r");
    let mut w =
        BundleWriter::create(&dir, "x".into(), json!({}), AnalysisLimits::default()).unwrap();
    std::fs::remove_dir(dir.join("evidence")).unwrap();
    assert!(w.evidence(b"x").is_err());
    assert!(w.gap("should not append after I/O failure").is_err());
    assert!(w.finish(true).is_err());
    std::fs::remove_file(dir.join("events.jsonl")).unwrap();
    assert_eq!(report(&dir).unwrap().coverage, "partial");
}
#[test]
fn independent_passive_fuzz_catalog_replays_in_standard_tests() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/fuzz-seeds.json")).unwrap();
    for case in cases {
        let b = hex(case["hex"].as_str().unwrap());
        match case["target"].as_str().unwrap() {
            "updates" => {
                bgp_hijack_core::update::decode_update(&b, &Default::default()).unwrap();
            }
            "mrt" => {
                MrtDecoder::new("seed".into())
                    .decode(
                        u16::from_be_bytes([b[0], b[1]]),
                        u16::from_be_bytes([b[2], b[3]]),
                        1.0,
                        &b[4..],
                    )
                    .unwrap();
            }
            "tcp" => {
                let mut t = TcpStream::new(Some(u32::MAX - 128), 4096);
                t.push(u32::from_be_bytes(b[..4].try_into().unwrap()), &b[4..])
                    .unwrap();
            }
            _ => panic!("unknown seed target"),
        }
    }
}
#[tokio::test]
async fn reconnect_starts_new_comparison_period() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for n in 1..=2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let sub = ws.next().await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_str(sub.to_text().unwrap()).unwrap();
            ws.send(Message::Text(json!({"type":"ris_subscribe_ok","data":{"subscription":{"host":"rrc00","prefix":v["data"]["prefix"]}}}).to_string().into())).await.unwrap();
            ws.send(Message::Text(json!({"type":"ris_message","data":{"id":format!("id-{n}"),"host":"rrc00","peer":"192.0.2.1","peer_asn":"64496","timestamp":n,"type":"UPDATE","path":[64496,65536+n],"announcements":[{"next_hop":"192.0.2.1","prefixes":["203.0.113.0/24"]}]}}).to_string().into())).await.unwrap();
            if n == 1 {
                ws.send(Message::Close(None)).await.unwrap();
            } else {
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_text() {
                        let _ = ws
                            .send(Message::Text(json!({"type":"pong"}).to_string().into()))
                            .await;
                    }
                }
            }
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let opts = ris::WatchOptions {
        prefixes: vec!["203.0.113.0/24".parse().unwrap()],
        collectors: vec!["rrc00".into()],
        more_specific: false,
        duration: Duration::from_secs(3),
        output: temp.path().join("run"),
        limits: AnalysisLimits::default(),
    };
    let (s, code) = ris::watch_url(opts.clone(), &url).await.unwrap();
    assert_eq!(code, 4);
    assert_eq!(s.routes, 1);
    assert!(s.findings.is_empty());
    assert!(s.gaps.iter().any(|g| g.contains("connection lost")));
    assert_eq!(s.findings, report(&opts.output).unwrap().findings);
    task.abort();
}
