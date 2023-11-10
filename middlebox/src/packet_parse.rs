// Borrowed from https://github.com/chifflier/nfqueue-rs/blob/master/examples/nfq-parse.rs

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use std::vec;
use nfq::{Message, Verdict, Queue};
use pnet::packet::tcp::TcpFlags::*;
use tls_parser::{parse_tls_raw_record, TlsRecordType, parse_tls_record_with_header};
use tls_parser::nom::{Err, IResult};
use rusticata::Direction;

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum SuspiciousEvent {
    DNS(Vec<u8>),
    // payload, SN, seq_num
    TLSClientRequest(Vec<u8>, usize),
    TLSServerResponse,
    // ClientHello, ServerHello, ServerHashshakeEncrypted
    DoTHandshake(Vec<u8>, Vec<u8>, Vec<u8>),
    // seq_num
    Retransmission(u32),
    // retransmission or out of order
    Misorder
}

const TLS_HEADER_SIZE: u32 = 5;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct SuspiciousTraffic {
    pub source: IpAddr, 
    pub destination: IpAddr,
    pub event: SuspiciousEvent,
}

pub enum FilterState {
    Wait(VerifyMaterial),
    Reject(IpAddr),
    Accept,
}

pub struct VerifyMaterial {
    pub sn: usize,
    pub start: Instant,
    pub source: IpAddr,
    pub payload: Vec<u8>,
    pub msg: Option<Message>,
}

fn print_bytes(array: &[u8]) {
    for byte in array {
        print!("{:02X} ", &byte);
    }
    for _ in array.len()..16 {
        print!("   ");
    }
    print!("  |");
    for byte in array {
        print_ascii(byte);
    }
    for _ in array.len()..16 {
        print!(" ");
    }
    println!("|");
}

fn print_ascii(byte: &u8) {
    if *byte > 32 && *byte < 127 {
        let letter = *byte as char;
        print!("{}", letter);
    } else {
        print!(".");
    }
}

fn print_hexdump(data: &[u8]) {
    for line in data.chunks(16) {
        print_bytes(line);
    }
}

fn print_flags(flags: u16) {
    print!("| ");
    let flags_arr = vec![("NS", NS), ("CWR", CWR), ("ECE", ECE), ("URG", URG), ("ACK", ACK), ("PSH", PSH), ("RST", RST), ("SYN", SYN), ("FIN", FIN)];
    for (name, num) in flags_arr {
        if flags & num != 0 {
            print!("{} | ", name);
        }
    }
    print!("\n");
}

type TcpConnection = (IpAddr, u16, IpAddr, u16);
type ClientServerTuple = (IpAddr, u16, IpAddr, u16); 

pub struct PacketHandler {
    sequence_map: HashMap<TcpConnection, HashMap<u32, Vec<u8>>>,
    next_seq_num_map: HashMap<TcpConnection, u32>,
    // TLSParser expects client -> server and server -> client to share the same parser
    parser_map: HashMap<ClientServerTuple, TLS13Parser>
}

impl PacketHandler {
    pub fn new() -> Self {
        PacketHandler { sequence_map: HashMap::new() , next_seq_num_map: HashMap::new(), parser_map: HashMap::new() }
    }

    fn handle_icmp_packet(&self, id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Vec<SuspiciousTraffic> {
        let icmp_packet = IcmpPacket::new(packet);
        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    println!(
                        "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        id,
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    println!(
                        "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        id,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                }
                _ => println!(
                    "[{}]: ICMP packet {} -> {} (type={:?})",
                    id,
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                ),
            }
            println!("icmp payload:");
            print_hexdump(icmp_packet.payload());
        } else {
            println!("[{}]: Malformed ICMP Packet", id);
        }
        Vec::new()
    }
    
    fn handle_udp_packet(&self, id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Vec<SuspiciousTraffic> {
        let udp = UdpPacket::new(packet);
    
        if let Some(udp) = udp {
            println!(
                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                id,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            );
            println!("udp payload:");
            print_hexdump(udp.payload());
            if let IpAddr::V4(addr) = destination && addr.octets() == [8, 8, 8, 8] {
                return vec![SuspiciousTraffic { source, destination, event: SuspiciousEvent::DNS(udp.payload().to_vec()) }]
            }
        } else {
            println!("[{}]: Malformed UDP Packet", id);
        }
        Vec::new()
    }

    // change name
    fn consume_tcp_packet(&mut self, tcp: TcpPacket, source: IpAddr, destination: IpAddr) -> Vec<Vec<u8>> {
        let connection = (source, tcp.get_source(), destination, tcp.get_destination());
        if !self.sequence_map.contains_key(&connection) {
            self.sequence_map.insert(connection, HashMap::new());
            self.next_seq_num_map.insert(connection, tcp.get_sequence());
        }
        let mut opt_len = 0;
        if tcp.get_options().len() == 5 {
            opt_len = 1;
        }
        if self.sequence_map.entry(connection).or_default().contains_key(&tcp.get_sequence()) {
            return vec![];
        }
        self.sequence_map.entry(connection).or_default().insert(tcp.get_sequence(), tcp.payload().to_vec());
        let mut payloads = Vec::new();
        while self.sequence_map[&connection].contains_key(&self.next_seq_num_map[&connection]) {
            // println!("Enter while loop!!!!! {} {}", tcp.get_sequence(), &self.next_seq_num_map[&connection]);
            let payload = self.sequence_map[&connection][&self.next_seq_num_map[&connection]].clone();
            if payload.len() + opt_len == 0 {
                break;
            }
            *self.next_seq_num_map.entry(connection).or_default() += payload.len() as u32 + opt_len as u32;
            payloads.push(payload);
        }
        payloads
    }

    // TODO: assume packet come from order, defragmented, but may exist retransmission
    fn handle_tcp_packet(&mut self, id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Vec<SuspiciousTraffic> {
        // log::info!("check 1");
        let mut traffics = Vec::new();
        let tcp = TcpPacket::new(packet);
        if let Some(tcp) = tcp {
            // println!(
            //     "[{}]: TCP Packet: {}:{} > {}:{}; length: {}; seq num {}; payload len {}; data offset {}",
            //     id,
            //     source,
            //     tcp.get_source(),
            //     destination,
            //     tcp.get_destination(),
            //     packet.len(),
            //     tcp.get_sequence(),
            //     tcp.payload().len(),
            //     tcp.get_options().len()
            // );
            // print_flags(tcp.get_flags());
            // println!("tcp sequence {}", tcp.get_sequence());
            // keep alive, skip to avoid interfere retransmission detection
            // TODO: why packet size of 32 here?
            if packet.len() == 20 || packet.len() == 32 {
                return traffics;
            }
            let tcp_dest = tcp.get_destination();
            let tcp_src = tcp.get_source();
            // log::info!("check 2");
            let payloads = self.consume_tcp_packet(tcp, source, destination);
            // log::info!("check 3");
            if payloads.len() == 0 {
                traffics.push(SuspiciousTraffic { source: source, destination: destination, event: SuspiciousEvent::Misorder });
                return traffics;
            }
            for payload in payloads {
                // assume clients have ip from 192.168.0.5 to 192.168.0.255
                if let IpAddr::V4(addr) = destination && addr.octets()[0] == 192 && addr.octets()[1] == 168 && addr.octets()[2] == 0 && addr.octets()[3] >= 5 {
                    // println!("packet to client");
                    let tuple = (destination, tcp_dest, source, tcp_src);
                    let parser = self.parser_map.entry(tuple).or_insert(TLS13Parser::new());
                    let events = parser.parse_tcp_level(&payload, Direction::ToServer);
                    for event in events {
                        match event {
                            TLS13State::ServerHandshakeEncrypted => {
                                traffics.push(SuspiciousTraffic {
                                    source, 
                                    destination, 
                                    event: SuspiciousEvent::DoTHandshake(parser.client_hello_payload.clone().unwrap(), parser.server_hello_payload.clone().unwrap(), parser.server_hs_encrypted_payload.clone().unwrap()),
                                } );
                            },
                            TLS13State::ActualApplicationData(_, _) => {
                                traffics.push(SuspiciousTraffic {source, destination, event: SuspiciousEvent::TLSServerResponse})
                            }
                            _ => ()
                        }
                    }
                } 
                // assume clients have ip from 192.168.0.5 to 192.168.0.255
                else if let IpAddr::V4(addr) = source && addr.octets()[0] == 192 && addr.octets()[1] == 168 && addr.octets()[2] == 0 && addr.octets()[3] >= 5 {
                    // println!("packet to server");
                    let tuple = (source, tcp_src, destination, tcp_dest);
                    let parser = self.parser_map.entry(tuple).or_insert(TLS13Parser::new());
                    let timer = Instant::now();
                    let events = parser.parse_tcp_level(&payload, Direction::ToClient);
                    // log::info!("parse tcp level takes {}", timer.elapsed().as_millis());
                    for event in events {
                        match event {
                            TLS13State::ActualApplicationData(payload, sn) => {
                                traffics.push(SuspiciousTraffic {source, destination, event: SuspiciousEvent::TLSClientRequest(payload, sn)} );
                            },
                            _ => ()
                        }
                    }
                }
            }
            // log::info!("check 4");
            // let parser = {
            //     if let IpAddr::V4(addr) = source && addr.octets() == [8, 8, 8, 8] {
            //         // this is different from connection
            //         let two_direction_connection = (destination, tcp.get_destination(), source, tcp.get_source());
            //         let parser = self.parser_map.entry(two_direction_connection).or_insert(TLS13Parser::new());
            //         Some(parser)
            //     } else if let IpAddr::V4(addr) = destination && addr.octets() == [8, 8, 8, 8] {
            //         println!("packet to server");
            //         // this is different from connection
            //         let two_direction_connection = (source, tcp.get_source(), destination, tcp.get_destination());
            //         let parser = self.parser_map.entry(two_direction_connection).or_insert(TLS13Parser::new());
            //         Some(parser)
            //     } else {
            //         None
            //     }
            // }.unwrap();
            // while self.sequence_map[&connection].contains_key(&self.next_seq_num_map[&connection]) {
            //     println!("Enter while loop!!!!! {} {}", tcp.get_sequence(), &self.next_seq_num_map[&connection]);
            //     let payload = self.sequence_map[&connection][&self.next_seq_num_map[&connection]].clone();
            //     if payload.len() + opt_len == 0 {
            //         break;
            //     }
            //     *self.next_seq_num_map.entry(connection).or_default() += payload.len() as u32 + opt_len as u32;
            //     let events = parser.parse_tcp_level(&payload, Direction::ToClient);
            //     println!("events {:?}", &events);
            //     for event in events {
            //         match event {
            //             TLS13State::ActualApplicationData(payload, sn) => {
            //                 traffics.push(SuspiciousTraffic {source, destination, event: SuspiciousEvent::DoTApplicationData(payload, sn, tcp.get_sequence())} );
            //             },
            //             _ => ()
            //         }
            //     }
            // }
        } else {
            println!("[{}]: Malformed TCP Packet", id);
        }
        traffics
    }

    fn handle_transport_protocol(
        &mut self,
        id: u32,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) -> Vec<SuspiciousTraffic> {
        // log::info!("check 0.3");
        match protocol {
            IpNextHeaderProtocols::Icmp => self.handle_icmp_packet(id, source, destination, packet),
            IpNextHeaderProtocols::Udp => self.handle_udp_packet(id, source, destination, packet),
            IpNextHeaderProtocols::Tcp => self.handle_tcp_packet(id, source, destination, packet),
            _ => {
                println!(
                    "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                    id,
                    match source {
                        IpAddr::V4(..) => "IPv4",
                        _ => "IPv6",
                    },
                    source,
                    destination,
                    protocol,
                    packet.len()
                );
                Vec::new()
            }
        }
    }
    
    pub fn handle_message(&mut self, msg: &Message) -> Vec<SuspiciousTraffic> {
        // log::info!("check 0");
        // println!("\n---");
        // println!("Packet received [id: 0x{:x}]\n", msg.get_queue_num());
        // println!("{:?}", msg.get_payload());
    
        // assume IPv4
        // log::info!("check 0.1");
        let header = Ipv4Packet::new(msg.get_payload());
        // log::info!("check 0.2");
        match header {
            Some(h) => self.handle_transport_protocol(
                msg.get_queue_num() as u32,
                IpAddr::V4(h.get_source()),
                IpAddr::V4(h.get_destination()),
                h.get_next_level_protocol(),
                h.payload(),
            ),
            None => {
                println!("Malformed IPv4 packet");
                Vec::new()
            },
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
// Expects TLS 1.3
pub enum TLS13State {
    None,
    ClientHello,
    ServerHello,
    // this state is ignored at this point
    ChangeCipher,
    ServerHandshakeEncrypted,
    ClientHandshakeEncrypted,
    ActualApplicationData(Vec<u8>, usize)
}

pub struct TLS13Parser {
    state: TLS13State,
    client_hello_payload: Option<Vec<u8>>,
    server_hello_payload: Option<Vec<u8>>,
    client_hs_encrypted_payload: Option<Vec<u8>>,
    server_hs_encrypted_payload: Option<Vec<u8>>,
    buffer: Vec<u8>,
    server_sn: usize,
    client_sn: usize
}

impl TLS13Parser {
    fn new() -> Self {
        TLS13Parser { 
            state: TLS13State::None, 
            client_hello_payload: None, 
            server_hello_payload: None, 
            client_hs_encrypted_payload: None, 
            server_hs_encrypted_payload: None, 
            buffer: Vec::new(), 
            server_sn: 0, 
            client_sn: 0 
        }
    }

    fn parse_tcp_level(&mut self, i: &[u8], direction: Direction) -> Vec<TLS13State> {
        let mut events = Vec::<TLS13State>::new();
        let mut v: Vec<u8>;
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.buffer.len() {
            0 => i,
            _ => {
                // sanity check vector length to avoid memory exhaustion
                // maximum length may be 2^24 (handshake message)
                if self.buffer.len() + i.len() > 16_777_216 {
                    return events;
                };
                v = self.buffer.split_off(0);
                v.extend_from_slice(i);
                v.as_slice()
            }
        };
        // trace!("tcp_buffer ({})",tcp_buffer.len());
        let mut cur_i = tcp_buffer;
        while !cur_i.is_empty() {
            // println!("cur_i len {}", cur_i.len());
            match parse_tls_raw_record(cur_i) {
                Ok((rem, ref r)) => {
                    // println!("rem len {}, r len {}", rem.len(), r.data.len());
                    // trace!("rem: {:?}",rem);
                    cur_i = rem;
                    // println!("hdr {:?}", &r.hdr);
                    // NOTE: parse_tls_record_with_header doesn't parse ApplicationData correctly, this is a workaround
                    if r.hdr.record_type == TlsRecordType::ApplicationData {
                        match self.state {
                            TLS13State::ClientHello => println!("Received Application Data before handshake finish"),
                            TLS13State::ServerHello => {
                                println!("ServerHandshakeEncrypted");
                                self.state = TLS13State::ServerHandshakeEncrypted;
                                self.server_hs_encrypted_payload = Some(r.data.to_vec());
                                events.push(self.state.clone());
                            },
                            TLS13State::ServerHandshakeEncrypted => {
                                self.state = TLS13State::ClientHandshakeEncrypted;
                                self.server_hs_encrypted_payload = Some(r.data.to_vec()); 
                                events.push(self.state.clone())
                            },
                            TLS13State::ClientHandshakeEncrypted | TLS13State::ActualApplicationData(_, _) => {
                                match direction {
                                    Direction::ToServer => {
                                        self.state = TLS13State::ActualApplicationData(r.data.to_vec(), self.client_sn);
                                        self.client_sn += 1;
                                        events.push(self.state.clone());
                                        // // self.state = TLS13State::ActualApplicationData(r.data.to_vec(), self.client_sn);
                                        // // self.client_sn += 1;
                                        // // events.push(self.state.clone());
                                        // // self.tls_next_seq_num = seq_num + r.hdr.len as u32 + 5; 
                                        // // log::info!("AAAAAAA:: seq num {}, predicted {}", seq_num, self.tls_next_seq_num);
                                        // self.seq_payload_dict.insert(seq_num, r.data.to_vec());
                                        // while self.seq_payload_dict.contains_key(&self.tls_next_seq_num) {
                                        //     self.tls_next_seq_num = self.tls_next_seq_num + r.hdr.len as u32 + TLS_HEADER_SIZE;
                                        //     self.state = TLS13State::ActualApplicationData(self.seq_payload_dict.get(&seq_num).unwrap().clone(), self.client_sn);
                                        //     self.client_sn += 1;
                                        //     events.push(self.state.clone());
                                        // }
                                    },
                                    Direction::ToClient => {
                                        self.state = TLS13State::ActualApplicationData(r.data.to_vec(), self.server_sn);
                                        self.server_sn += 1;
                                        events.push(self.state.clone());
                                    },
                                }
                            },
                            TLS13State::ChangeCipher => {
                                self.state = TLS13State::ClientHandshakeEncrypted;
                                print!("This is the message after ChangeCipher")
                            },
                            _ => ()
                        }
                    } else {
                        match parse_tls_record_with_header(r.data, &r.hdr) {
                            Ok((rem2, ref msg_list)) => {
                                // TODO: when will msg_list have more than one msg?
                                for msg in msg_list {
                                    match msg {
                                        tls_parser::TlsMessage::Handshake(hs) => {
                                            match hs {
                                                tls_parser::TlsMessageHandshake::ClientHello(_) => {
                                                    println!("ClientHello");
                                                    self.state = TLS13State::ClientHello;
                                                    self.client_hello_payload = Some(r.data.to_vec());
                                                    events.push(self.state.clone());
                                                },
                                                tls_parser::TlsMessageHandshake::ServerHello(_) => {
                                                    println!("ServerHello");
                                                    self.state = TLS13State::ServerHello;
                                                    self.server_hello_payload = Some(r.data.to_vec());
                                                    events.push(self.state.clone());
                                                },
                                                _ => ()
                                            }
                                        },
                                        // if use my own tlsserver, we need this, otherwise it seems we doesn't?
                                        tls_parser::TlsMessage::ChangeCipherSpec => {
                                            // WARNING: This is very hacky find time to change this!!!
                                            self.state = TLS13State::ChangeCipher
                                        },
                                        tls_parser::TlsMessage::Alert(_) => (),
                                        tls_parser::TlsMessage::ApplicationData(_) => (),
                                        tls_parser::TlsMessage::Heartbeat(_) => (),
                                    }
                                }
                                if !rem2.is_empty() {
                                    println!("extra bytes in TLS record: {:?}", rem2);
                                };
                            }
                            Err(e) => {
                                println!("Parse record Error {}", e);
                                return events;
                            }
                        };
                    }
                }
                Err(Err::Incomplete(needed)) => {
                    self.buffer.extend_from_slice(cur_i);
                    break;
                }
                Err(e) => {
                    break;
                }
            }
        }
        events
    }
}