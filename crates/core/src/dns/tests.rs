use super::*;
use hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA, CNAME},
    },
};
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    sync::{Arc, atomic::Ordering},
    thread,
    time::Instant,
};

fn plan() -> QueryPlan {
    QueryPlan {
        name: "example.test.".into(),
        recordType: RecordType::A,
    }
}

fn reply(request: &[u8], code: ResponseCode, answers: Vec<Record>) -> Vec<u8> {
    let query = Message::from_vec(request).unwrap();
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = code;
    response.metadata.recursion_available = true;
    response.add_queries(query.queries);
    response.add_answers(answers);
    response.to_vec().unwrap()
}

fn address(owner: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(owner).unwrap(),
        60,
        RData::A(A("192.0.2.1".parse().unwrap())),
    )
}

fn alias(owner: &str, target: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(owner).unwrap(),
        30,
        RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
    )
}

fn decode(bytes: &[u8], plan: &QueryPlan) -> AppResult<DnsOutcome> {
    let mut result = DnsOutcome::empty(plan.clone());
    wire::apply(bytes, plan, 42, &mut result)?;
    Ok(result)
}

#[test]
fn canonicalNamesAndResolversAreBounded() {
    let normalized = QueryPlan {
        name: "EXAMPLE.Test".into(),
        recordType: RecordType::A,
    }
    .normalized()
    .unwrap();
    assert_eq!(normalized, plan());
    for name in [
        "",
        ".",
        "a..test",
        "-a.test",
        "a-.test",
        "*.test",
        "a test",
        "a\ntest",
        "café.test",
    ] {
        assert!(
            QueryPlan {
                name: name.into(),
                recordType: RecordType::A
            }
            .normalized()
            .is_err()
        );
    }
    assert!(
        QueryPlan {
            name: "a".repeat(64),
            recordType: RecordType::A
        }
        .normalized()
        .is_err()
    );
    for value in [
        "resolver.test:53",
        "0.0.0.0:53",
        "224.0.0.1:53",
        "255.255.255.255:53",
        "1.1.1.1:0",
        "[fe80::1]:53",
        "[::ffff:127.0.0.1]:53",
    ] {
        assert!(parseResolver(value).is_err(), "{value}");
    }
    assert_eq!(
        parseResolver("[fe80::1%12]:53").unwrap().to_string(),
        "[fe80::1%12]:53"
    );
}

#[test]
fn codecFollowsOnlyTheRequestedAnswerChainAndFamily() {
    let request = wire::request(&plan(), 42).unwrap();
    let bytes = reply(
        &request,
        ResponseCode::NoError,
        vec![
            address("unrelated.test."),
            alias("EXAMPLE.test.", "alias.test."),
            address("alias.test."),
        ],
    );
    let parsed = decode(&bytes, &plan()).unwrap();
    assert_eq!(parsed.status, DnsStatus::Resolved);
    assert_eq!(parsed.aliases.len(), 1);
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(parsed.answers[0].owner, "alias.test.");
    assert_eq!(parsed.answers[0].ttlSeconds, 60);
    let noData = reply(
        &request,
        ResponseCode::NoError,
        vec![address("unrelated.test.")],
    );
    assert_eq!(decode(&noData, &plan()).unwrap().status, DnsStatus::NoData);
    let aaaa = QueryPlan {
        recordType: RecordType::Aaaa,
        ..plan()
    };
    let request = wire::request(&aaaa, 42).unwrap();
    let bytes = reply(
        &request,
        ResponseCode::NoError,
        vec![Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            20,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        )],
    );
    assert!(decode(&bytes, &aaaa).unwrap().answers[0].address.is_ipv6());
}

#[test]
fn invalidEnvelopesCompressionAndConflictingAliasesAreRejected() {
    let request = wire::request(&plan(), 42).unwrap();
    let valid = reply(
        &request,
        ResponseCode::NoError,
        vec![address("example.test.")],
    );
    for (position, value) in [(0, 99), (2, 0), (3, 0x40), (5, 2), (6, 2)] {
        let mut bytes = valid.clone();
        bytes[position] = value;
        assert!(decode(&bytes, &plan()).is_err(), "position {position}");
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(decode(&trailing, &plan()).is_err());
    let differentQuestion = QueryPlan {
        name: "other.test.".into(),
        ..plan()
    };
    assert!(decode(&valid, &differentQuestion).is_err());
    let differentType = QueryPlan {
        recordType: RecordType::Aaaa,
        ..plan()
    };
    assert!(decode(&valid, &differentType).is_err());
    let oversized = reply(
        &request,
        ResponseCode::NoError,
        (0..33).map(|_| address("example.test.")).collect(),
    );
    assert!(decode(&oversized, &plan()).is_err());
    assert!(decode(&valid[..valid.len() - 1], &plan()).is_err());
    let mut cyclic = vec![
        0, 42, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1,
    ];
    assert!(decode(&cyclic, &plan()).is_err());
    cyclic[13] = 255;
    assert!(decode(&cyclic, &plan()).is_err());
    for answers in [
        vec![alias("example.test.", "example.test.")],
        vec![
            alias("example.test.", "a.test."),
            alias("example.test.", "b.test."),
        ],
        vec![alias("example.test.", "a.test."), address("example.test.")],
    ] {
        assert!(decode(&reply(&request, ResponseCode::NoError, answers), &plan()).is_err());
    }
}

#[test]
fn negativeAnswersNeverBecomeSuccessfulLookupTimes() {
    let request = wire::request(&plan(), 42).unwrap();
    for (code, status) in [
        (ResponseCode::NXDomain, DnsStatus::NxDomain),
        (ResponseCode::ServFail, DnsStatus::DnsError),
        (ResponseCode::NoError, DnsStatus::NoData),
    ] {
        let result = decode(&reply(&request, code, vec![]), &plan()).unwrap();
        assert_eq!(result.status, status);
        assert!(result.lookupMs.is_none());
        assert!(result.answers.is_empty());
    }
}

#[test]
fn realUdpRejectsWrongIdThenMeasuresOnlyValidatedAnswers() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let resolver = socket.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut buffer = [0; 512];
        let (count, peer) = socket.recv_from(&mut buffer).unwrap();
        let response = reply(
            &buffer[..count],
            ResponseCode::NoError,
            vec![address("example.test.")],
        );
        let mut wrong = response.clone();
        wrong[0] ^= 1;
        socket.send_to(&wrong, peer).unwrap();
        socket.send_to(&response, peer).unwrap();
    });
    let result = measure(
        resolver,
        &plan(),
        Duration::from_secs(1),
        &AtomicBool::new(false),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(result.status, DnsStatus::Resolved);
    assert_eq!(result.transport, Transport::Udp);
    assert_eq!(result.rejectedResponses, 1);
    assert!(result.lookupMs.unwrap() >= result.responseMs.unwrap());
    assert_eq!(result.cacheMode, CacheMode::DirectResolverCacheUnknown);
    assert!(result.requestBytes > 12 && result.responseBytes > result.requestBytes);
}

#[test]
fn truncatedUdpFallsBackToFramedTcpOnTheSameResolver() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let resolver = listener.local_addr().unwrap();
    let socket = UdpSocket::bind(resolver).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let server = thread::spawn(move || {
        let mut buffer = [0; 512];
        let (count, peer) = socket.recv_from(&mut buffer).unwrap();
        let mut response = reply(&buffer[..count], ResponseCode::NoError, vec![]);
        response[2] |= 2;
        socket.send_to(&response, peer).unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).unwrap();
        let mut request = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut request).unwrap();
        let response = reply(
            &request,
            ResponseCode::NoError,
            vec![address("example.test.")],
        );
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .unwrap();
        for chunk in response.chunks(3) {
            stream.write_all(chunk).unwrap();
        }
    });
    let result = measure(
        resolver,
        &plan(),
        Duration::from_secs(2),
        &AtomicBool::new(false),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(result.status, DnsStatus::Resolved);
    assert_eq!(result.transport, Transport::TcpFallback);
    assert!(result.lookupMs.is_some());
}

#[test]
fn deadlinesAndCancellationDoNotInventDnsResults() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let resolver = socket.local_addr().unwrap();
    let result = measure(
        resolver,
        &plan(),
        Duration::from_millis(100),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.status, DnsStatus::TimedOut);
    assert!(result.lookupMs.is_none() && result.responseMs.is_none());
    let cancelled = Arc::new(AtomicBool::new(false));
    let other = cancelled.clone();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(80));
        other.store(true, Ordering::SeqCst);
    });
    let start = Instant::now();
    let result = measure(resolver, &plan(), Duration::from_secs(5), &cancelled).unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, DnsStatus::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(1));
    let result = measure(resolver, &plan(), Duration::from_secs(1), &cancelled).unwrap();
    assert_eq!(result.requestBytes, 0);
    assert_eq!(result.responseBytes, 0);
}

#[test]
fn dnsCohortRetainsRawNegativeResultsAndPersistsProtocolSemantics() {
    use crate::{
        benchmark::{Endpoint, ProbeProtocol, runBenchmark, validateEndpoints},
        config::Config,
        storage,
    };
    let mut endpoints = Vec::new();
    let mut servers = Vec::new();
    for (index, code) in [ResponseCode::NoError, ResponseCode::NXDomain]
        .into_iter()
        .enumerate()
    {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        endpoints.push(Endpoint {
            id: index.to_string(),
            address: socket.local_addr().unwrap().to_string(),
            protocol: ProbeProtocol::DnsLookup,
            dnsQuery: Some(plan()),
        });
        servers.push(thread::spawn(move || {
            for iteration in 0..3 {
                let mut buffer = [0; 512];
                let (count, peer) = socket.recv_from(&mut buffer).unwrap();
                let answers = if code == ResponseCode::NoError {
                    vec![if iteration == 1 {
                        Record::from_rdata(
                            Name::from_ascii("example.test.").unwrap(),
                            10,
                            RData::A(A("192.0.2.2".parse().unwrap())),
                        )
                    } else {
                        address("example.test.")
                    }]
                } else {
                    vec![]
                };
                socket
                    .send_to(&reply(&buffer[..count], code, answers), peer)
                    .unwrap();
            }
        }));
    }
    let config = Config {
        sampleCount: 3,
        intervalMs: 250,
        timeoutMs: 500,
        ..Config::default()
    };
    let mut invalid = endpoints.clone();
    invalid[1].dnsQuery.as_mut().unwrap().recordType = RecordType::Aaaa;
    assert!(validateEndpoints(&invalid).is_err());
    invalid[1].dnsQuery = None;
    assert!(validateEndpoints(&invalid).is_err());
    let mut run = runBenchmark(config, endpoints, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    for server in servers {
        server.join().unwrap();
    }
    assert_eq!(run.protocol, "dnsLookup");
    assert_eq!(run.samples.len(), 6);
    assert!(
        run.samples
            .iter()
            .all(|sample| sample.connectMs.is_none() && sample.echo.is_none())
    );
    let resolved = &run.results[0];
    assert_eq!(resolved.summary.successful, 3);
    assert_eq!(resolved.summary.dnsFailurePercent, Some(0.0));
    assert_eq!(resolved.dnsCounts.as_ref().unwrap().addressSetChanges, 2);
    let negative = &run.results[1];
    assert_eq!(negative.summary.successful, 0);
    assert_eq!(negative.summary.dnsFailurePercent, Some(100.0));
    assert_eq!(negative.dnsCounts.as_ref().unwrap().nxDomain, 3);
    assert!(negative.summary.medianMs.is_none());
    assert!(
        negative.summary.connectionFailurePercent.is_none()
            && negative.summary.echoTimeoutPercent.is_none()
    );
    for sample in run.samples.iter().filter(|sample| sample.endpointId == "1") {
        let dns = sample.dns.as_ref().unwrap();
        assert!(dns.responseMs.is_some() && dns.lookupMs.is_none());
        assert_eq!(dns.responseCode, Some(3));
    }
    let mut database = storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    storage::saveRun(&mut database, &mut run).unwrap();
    let saved = storage::history(&database, 1).unwrap().remove(0);
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        serde_json::to_value(run).unwrap()
    );
}
