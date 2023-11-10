use crate::rparser::*;
use nom::{Err, HexDisplay};
use ssh_parser::{parse_ssh_identification, parse_ssh_packet, SshPacket};

pub struct SSHBuilder {}
impl RBuilder for SSHBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(SSHParser::new(b"SSH"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(ssh_probe)
    }
}

#[derive(Debug, PartialEq)]
enum SSHConnectionState {
    Start,
    CIdent,
    SIdent,
    CKexInit,
    SKexInit,
    CKexDH,
    SKexDH,

    Established,

    Error,
}

pub struct SSHParser<'a> {
    _name: Option<&'a [u8]>,

    state: SSHConnectionState,
    buffer_clt: Vec<u8>,
    buffer_srv: Vec<u8>,
}

fn pretty_print_ssh_packet(pkt: &(SshPacket, &[u8])) {
    #[allow(clippy::single_match)]
    match pkt.0 {
        SshPacket::KeyExchange(ref kex) => {
            debug!("kex algs: {:?}", kex.get_kex_algs());
            debug!("server_host_key_algs: {:?}", kex.get_server_host_key_algs());
            debug!(
                "encr_algs_client_to_server: {:?}",
                kex.get_encr_algs_client_to_server()
            );
            debug!(
                "encr_algs_server_to_client: {:?}",
                kex.get_encr_algs_server_to_client()
            );
            debug!(
                "mac_algs_client_to_server: {:?}",
                kex.get_mac_algs_client_to_server()
            );
            debug!(
                "mac_algs_server_to_client: {:?}",
                kex.get_mac_algs_server_to_client()
            );
            debug!(
                "comp_algs_client_to_server: {:?}",
                kex.get_comp_algs_client_to_server()
            );
            debug!(
                "comp_algs_server_to_client: {:?}",
                kex.get_comp_algs_server_to_client()
            );
            debug!(
                "langs_algs_client_to_server: {:?}",
                kex.get_langs_client_to_server()
            );
            debug!(
                "langs_algs_client_to_server: {:?}",
                kex.langs_client_to_server
            );
            debug!(
                "langs_algs_server_to_client: {:?}",
                kex.get_langs_server_to_client()
            );
            debug!(
                "langs_algs_server_to_client: {:?}",
                kex.langs_server_to_client
            );
            // XXX etc.
        }
        _ => (),
    }
}

impl<'a> SSHParser<'a> {
    pub fn new(name: &'a [u8]) -> SSHParser<'a> {
        SSHParser {
            _name: Some(name),
            state: SSHConnectionState::Start,
            buffer_clt: Vec::new(),
            buffer_srv: Vec::new(),
        }
    }

    fn parse_ident(&mut self, i: &[u8]) -> ParseResult {
        match parse_ssh_identification(i) {
            Ok((rem, (ref crap, ref res))) => {
                // In version 2.0, the SSH server is allowed to send an arbitrary number of
                // UTF-8 lines before the final identification line containing the server
                // version.
                if !crap.is_empty() {
                    info!("Extra lines before SSH version:");
                    for line in crap.iter() {
                        info!("{}", line.to_hex(16));
                    }
                }
                if !rem.is_empty() {
                    warn!("Extra bytes after SSH ident data");
                }
                debug!("parse_ssh_identification: {:?}", res);
                self.state = match self.state {
                    SSHConnectionState::Start => SSHConnectionState::CIdent,
                    SSHConnectionState::CIdent => SSHConnectionState::SIdent,
                    _ => {
                        return ParseResult::Error;
                    }
                };
                info!("protocol\n{}", res.proto.to_hex(16));
                info!("software\n{}", res.software.to_hex(16));
            }
            e => {
                warn!("parse_ssh_identification: {:?}", e);
                self.state = SSHConnectionState::Error;
            }
        };
        ParseResult::Ok
    }

    fn parse_packet(&mut self, i: &[u8], direction: Direction) -> ParseResult {
        debug!("parse_ssh_packet direction: {:?}", direction);
        debug!("\tbuffer_clt size: {}", self.buffer_clt.len());
        debug!("\tbuffer_srv size: {}", self.buffer_srv.len());
        if self.state == SSHConnectionState::Established {
            // stop following session when encrypted
            return ParseResult::Ok;
        }
        let mut v: Vec<u8>;
        // Check if a record is being defragmented
        let self_buffer = if direction == Direction::ToServer {
            &mut self.buffer_srv
        } else {
            &mut self.buffer_clt
        };
        let buf = match self_buffer.len() {
            0 => i,
            _ => {
                v = self_buffer.split_off(0);
                v.extend_from_slice(i);
                v.as_slice()
            }
        };
        // info!("parsing:\n{}", buf.to_hex(16));
        match parse_ssh_packet(buf) {
            Ok((rem, ref res)) => {
                // put back remaining data
                self_buffer.extend_from_slice(rem);
                debug!("parse_ssh_packet: {:?}", res);
                pretty_print_ssh_packet(res);
                self.state = match self.state {
                    SSHConnectionState::SIdent => SSHConnectionState::CKexInit,
                    SSHConnectionState::CKexInit => SSHConnectionState::SKexInit,
                    SSHConnectionState::SKexInit => SSHConnectionState::CKexDH,
                    SSHConnectionState::CKexDH => SSHConnectionState::SKexDH,
                    SSHConnectionState::SKexDH => SSHConnectionState::Established,
                    _ => {
                        return ParseResult::Error;
                    }
                };
            }
            Err(Err::Incomplete(_e)) => {
                debug!("Defragmentation required (SSH packet): {:?}", _e);
                self_buffer.extend_from_slice(buf);
            }
            e => {
                warn!("parse_ssh_packet: {:?}", e);
                self.state = SSHConnectionState::Error;
            }
        };
        // info!("after parsing:\n{}", self_buffer.to_hex(16));
        ParseResult::Ok
    }
}

impl<'a> RParser for SSHParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        debug!("SSH current state: {:?}", self.state);
        match self.state {
            SSHConnectionState::Start | SSHConnectionState::CIdent => self.parse_ident(data),
            SSHConnectionState::SIdent
            | SSHConnectionState::CKexInit
            | SSHConnectionState::SKexInit
            | SSHConnectionState::CKexDH
            | SSHConnectionState::SKexDH
            | SSHConnectionState::Established => self.parse_packet(data, direction),
            SSHConnectionState::Error => ParseResult::Error,
            // _            => R_STATUS_FAIL,
        }
    }
}

pub fn ssh_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 4 {
        return ProbeResult::Unsure;
    }
    if &i[..4] == b"SSH-" {
        return ProbeResult::Certain;
    }
    ProbeResult::NotForUs
}
