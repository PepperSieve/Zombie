use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use der_parser::ber::{parse_ber_sequence, BerObjectContent};
use snmp_parser::{parse_snmp_v1, parse_snmp_v2c, PduType};

pub struct SNMPv1Builder {}
impl RBuilder for SNMPv1Builder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(SNMPParser::new(b"SNMPv1", 1))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(snmpv1_probe)
    }
}

pub struct SNMPv2cBuilder {}
impl RBuilder for SNMPv2cBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(SNMPParser::new(b"SNMPv2c", 2))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(snmpv2c_probe)
    }
}

pub struct SNMPParser<'a> {
    _name: Option<&'a [u8]>,
    version: u8,
    community: Option<String>,
    req_type: Option<PduType>,
}

impl<'a> From<PduType> for Variant<'a> {
    fn from(input: PduType) -> Self {
        input.0.into()
    }
}

impl<'a> SNMPParser<'a> {
    pub fn new(name: &'a [u8], version: u8) -> SNMPParser<'a> {
        SNMPParser {
            _name: Some(name),
            version,
            community: None,
            req_type: None,
        }
    }
}

impl<'a> RParser for SNMPParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        let parser = match self.version {
            1 => parse_snmp_v1,
            2 => parse_snmp_v2c,
            _ => return ParseResult::Error,
        };
        match parser(data) {
            Ok((_rem, r)) => {
                debug!("parse_snmp({}): {:?}", self.version, r);
                self.community = Some(r.community);
                if direction == Direction::ToServer {
                    self.req_type = Some(r.pdu.pdu_type());
                }
                ParseResult::Ok
            }
            e => {
                warn!("parse_snmp({}) failed: {:?}", self.version, e);
                ParseResult::Error
            }
        }
    }

    gen_get_variants! {SNMPParser, "snmp.",
        version   => into,
        community => map_as_ref,
        req_type  => map,
    }
}

// Read PDU sequence and extract version, if similar to SNMP definition
pub fn parse_pdu_enveloppe_version(i: &[u8]) -> Option<u32> {
    match parse_ber_sequence(i) {
        Ok((_, x)) => {
            match x.content {
                BerObjectContent::Sequence(ref v) => {
                    if v.len() == 3 {
                        match v[0].as_u32() {
                            Ok(0) => Some(1), // possibly SNMPv1
                            Ok(1) => Some(2), // possibly SNMPv2c
                            _ => None,
                        }
                    } else if v.len() == 4 && v[0].as_u32() == Ok(3) {
                        Some(3) // possibly SNMPv3
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn snmp_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 {
        return ProbeResult::NotForUs;
    }
    match parse_pdu_enveloppe_version(i) {
        Some(1) | Some(2) => ProbeResult::Certain,
        _ => ProbeResult::NotForUs,
    }
}

pub fn snmpv1_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 {
        return ProbeResult::NotForUs;
    }
    (parse_pdu_enveloppe_version(i) == Some(1)).into()
}

pub fn snmpv2c_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 {
        return ProbeResult::NotForUs;
    }
    (parse_pdu_enveloppe_version(i) == Some(2)).into()
}
