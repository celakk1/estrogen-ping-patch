use super::{Alias, Answer, DnsOutcome, DnsStatus, QueryPlan, RecordType};
use crate::AppResult;
use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType as WireType},
    serialize::binary::{BinDecodable, BinDecoder},
};

const MAX_RECORDS: u32 = 256;
const MAX_ANSWERS: usize = 32;
const MAX_ALIASES: usize = 8;

fn question(plan: &QueryPlan) -> AppResult<Query> {
    Ok(Query::query(
        Name::from_ascii(&plan.name)?,
        match plan.recordType {
            RecordType::A => WireType::A,
            RecordType::Aaaa => WireType::AAAA,
        },
    ))
}

pub(super) fn request(plan: &QueryPlan, id: u16) -> AppResult<Vec<u8>> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.authentic_data = true;
    message.add_query(question(plan)?);
    Ok(message.to_vec()?)
}

pub(super) fn isTruncated(bytes: &[u8], plan: &QueryPlan, id: u16) -> AppResult<bool> {
    if !(12..=65_535).contains(&bytes.len()) {
        return Err("DNS response length is invalid".into());
    }
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder)?;
    let records = u32::from(u16::from_be_bytes([bytes[6], bytes[7]]))
        + u32::from(u16::from_be_bytes([bytes[8], bytes[9]]))
        + u32::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    if header.metadata.id != id
        || header.metadata.message_type != MessageType::Response
        || header.metadata.op_code != OpCode::Query
        || bytes[3] & 0x40 != 0
        || u16::from_be_bytes([bytes[4], bytes[5]]) != 1
        || records > MAX_RECORDS
    {
        return Err("DNS response ID, flags, question count, or record count is invalid".into());
    }
    let received = Query::read(&mut decoder)?;
    let expected = question(plan)?;
    if received.name().to_lowercase() != expected.name().to_lowercase()
        || received.query_type() != expected.query_type()
        || received.query_class() != DNSClass::IN
    {
        return Err("DNS response question does not match the request".into());
    }
    Ok(header.metadata.truncation)
}

pub(super) fn apply(
    bytes: &[u8],
    plan: &QueryPlan,
    id: u16,
    result: &mut DnsOutcome,
) -> AppResult<()> {
    if isTruncated(bytes, plan, id)? {
        return Err("DNS response remains truncated".into());
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder)?;
    if !decoder.is_empty() {
        return Err("DNS response contains trailing data".into());
    }
    result.responseCode = Some(u16::from(message.metadata.response_code));
    result.authenticatedDataReported = Some(message.metadata.authentic_data);
    result.recursionAvailable = Some(message.metadata.recursion_available);
    result.status = match message.metadata.response_code {
        ResponseCode::NXDomain => DnsStatus::NxDomain,
        ResponseCode::NoError => DnsStatus::NoData,
        _ => DnsStatus::DnsError,
    };
    if message.metadata.response_code != ResponseCode::NoError {
        return Ok(());
    }
    let mut current = Name::from_ascii(&plan.name)?.to_lowercase();
    let mut seen = vec![current.clone()];
    loop {
        let records: Vec<_> = message
            .answers
            .iter()
            .filter(|record| {
                record.dns_class == DNSClass::IN && record.name.to_lowercase() == current
            })
            .collect();
        let aliases: Vec<_> = records
            .iter()
            .filter_map(|record| {
                if let RData::CNAME(name) = &record.data {
                    Some((name.0.to_lowercase(), record.ttl))
                } else {
                    None
                }
            })
            .collect();
        if !aliases.is_empty() && records.iter().any(|record| record.data.ip_addr().is_some()) {
            return Err("DNS answer mixes address data and a CNAME for the same owner".into());
        }
        let addresses: Vec<_> = records
            .iter()
            .filter_map(|record| {
                let address = record.data.ip_addr()?;
                let correctFamily = matches!(
                    (plan.recordType, address),
                    (RecordType::A, std::net::IpAddr::V4(_))
                        | (RecordType::Aaaa, std::net::IpAddr::V6(_))
                );
                correctFamily.then(|| Answer {
                    owner: current.to_ascii(),
                    address,
                    ttlSeconds: record.ttl,
                })
            })
            .collect();
        if addresses.len() > MAX_ANSWERS {
            return Err("DNS answer exceeds the supported address count".into());
        }
        if !addresses.is_empty() {
            result.answers = addresses;
            result.status = DnsStatus::Resolved;
            return Ok(());
        }
        let Some((target, _)) = aliases.first() else {
            return Ok(());
        };
        if aliases.iter().any(|(name, _)| name != target)
            || seen.contains(target)
            || result.aliases.len() >= MAX_ALIASES
        {
            return Err("DNS CNAME chain is ambiguous, cyclic, or too long".into());
        }
        result.aliases.push(Alias {
            name: current.to_ascii(),
            target: target.to_ascii(),
            ttlSeconds: aliases.iter().map(|(_, ttl)| *ttl).min().unwrap(),
        });
        current = target.clone();
        seen.push(current.clone());
    }
}
