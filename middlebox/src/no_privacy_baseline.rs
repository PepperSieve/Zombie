use crate::blocklist_checker::BlocklistChecker;
use nfq::{Queue, Verdict, Message};
use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration};
use crate::packet_parse::{self, FilterState, VerifyMaterial};
use std::net::IpAddr;
use dns_parser::Packet;

pub fn netfilter() -> std::io::Result<()> {
    // TODO: the nfq library can only process the next when last msg has been processed, so we have to block on current msg
    let mut queue = Queue::open()?;
    queue.bind(1)?;
    let mut sn_dict = HashMap::<IpAddr, usize>::new();
    let mut packet_handler = packet_parse::PacketHandler::new();
    let checker = BlocklistChecker::new("/mydata/blocklist.txt".to_string());
    loop {
        let mut msg = queue.recv()?;
        let mut verdict = Verdict::Accept;
        for traffic in packet_handler.handle_message(&msg) {
            if let packet_parse::SuspiciousEvent::DNS(query) = traffic.event {
                if let Ok(packet) = Packet::parse(&query) {
                    let questions = packet.questions;
                    for q in questions {
                        let name = q.qname.to_string();
                        println!("dns name {}", name);
                        let timer = Instant::now();
                        if checker.contains(name) {
                            verdict = Verdict::Drop;
                        }
                        println!("blocklist check time {}", timer.elapsed().as_micros());
                    }
                }
            }
        }
        println!("will set verdict {:?}", verdict);
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    };
    Ok(())
}
