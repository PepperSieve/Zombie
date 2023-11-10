#![feature(let_chains)]

use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::thread::JoinHandle;
use std::{thread, fs};
#[macro_use] extern crate nickel;
use std::sync::{Arc, Mutex, Condvar, mpsc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, Duration};
use std::net::IpAddr;
use std::env;
use chrono::Local;
use log::{debug, info};
use nfq::Queue;
use rusticata::tls_parser::parse_tls_extension_signature_algorithms_content;
use std::io::prelude::*;

use crate::blocklist_checker::BlocklistChecker;
use crate::middlebox::{PretendVerifyMode, get_syncthetic_proof, get_syncthetic_regex_proof};
use crate::packet_parse::FilterState;

mod packet_parse;
mod middlebox;
mod blocklist_checker;
mod no_policy_baseline;
mod no_privacy_baseline;
mod test_tcp_congestion_control;

pub struct MyPrinter {
    file: String
}

impl MyPrinter {
    fn new(file: String) -> Self {
        File::create(file.clone());
        MyPrinter {
            file
        }
    }

    fn print(&self, msg: &str) {
        let mut file = OpenOptions::new().write(true)
        .append(true)
        .open(&self.file)
        .unwrap();
        let now = Local::now();
        let msg = format!("{}:: {}", now.format("%H:%M:%S%.3f"), msg);
        writeln!(file, "{}", msg);
    }
}

fn main() -> Result<(), std::io::Error> {
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();
    let args: Vec<String> = env::args().collect();
    debug!("test debug ok");
    println!("below debug");
    println!("{}", args[1]);
    if args[1] == "no_privacy" {
        println!("no privacy middlebox");
        let mut queue = Queue::open()?;
        queue.bind(0)?;
        queue.set_nonblocking(true);
        let queue_lock = Arc::new(Mutex::new(queue));
        let handshake_dict_pair = Arc::new((Mutex::new(HashMap::<IpAddr, (Vec<u8>, Vec<u8>)>::new()), Condvar::new()));
        middlebox::netfilter(middlebox::NetfilterMode::NoPolicy(BlocklistChecker::new("/mydata/blocklist.txt".to_string())), handshake_dict_pair, queue_lock);
        Ok(())
    } else if args[1] == "test_congestion" {
        let batch_size = args[2].parse().unwrap();
        test_tcp_congestion_control::netfilter(batch_size)
    } else if args[1] == "no_policy" {
        println!("no policy middlebox");
        no_policy_baseline::netfilter()
    } else if args[1] == "no_policy_privacy" {
        println!("no policy middlebox");
        no_policy_baseline::netfilter() 
    } else if args[1] == "benchmark_async" {
        let mut packet_handler = packet_parse::PacketHandler::new();
        let mut queue = Queue::open()?;
        queue.bind(0)?;
        queue.set_nonblocking(true);
        let queue_lock = Arc::new(Mutex::new(queue));
        println!("async middlebox");
        let packet_state_dict_pair = Arc::new((Mutex::new(HashMap::<IpAddr, HashMap<usize, FilterState>>::new()), Condvar::new()));
        let packet_state_dict_pair2 = packet_state_dict_pair.clone();
        let packet_state_dict_pair3 = packet_state_dict_pair.clone();
        let blocklist_pair = Arc::new((Mutex::new(HashSet::<IpAddr>::new()), Condvar::new()));
        let blocklist_pair2 = blocklist_pair.clone();
        let blocklist_pair3 = blocklist_pair.clone();
        let handshake_dict_pair = Arc::new((Mutex::new(HashMap::<IpAddr, (Vec<u8>, Vec<u8>)>::new()), Condvar::new()));
        let handshake_dict_pair2 = handshake_dict_pair.clone();
        let (tx, rx) = mpsc::channel();
        let netfilter_handle = thread::spawn(move || {
            middlebox::netfilter(middlebox::NetfilterMode::Async(tx, blocklist_pair), handshake_dict_pair, queue_lock)
        });
        let drop_handle = thread::spawn(move || {
            middlebox::drop_thread(packet_state_dict_pair2, blocklist_pair2, Duration::from_secs(100000))
        });
        let collector_handle = thread::spawn(move || {
            middlebox::filter_state_collector(packet_state_dict_pair, rx)
        });
        let http_handle = thread::spawn(move || {
            let should_verify_co = if args[5] == "true" { true } else { false };
            match args[2].as_str() {
                "Dot" => {
                    let pretend_size: usize = args[6].parse().unwrap(); 
                    let pretend_mode = if pretend_size > 0 {
                        let (proof, witnesses) = get_syncthetic_proof(pretend_size);
                        PretendVerifyMode::DnsPretend(proof, witnesses)
                    } else {
                        PretendVerifyMode::NotPretend
                    };
                    info!("Pretend size is {}", pretend_size);
                    middlebox::start_http_server::<255>(Arc::new(middlebox::HttpServerMode::Async(packet_state_dict_pair3, blocklist_pair3)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::DnsBlocklist, pretend_mode)
                },
                "Doh" => {
                    middlebox::start_http_server::<500>(Arc::new(middlebox::HttpServerMode::Async(packet_state_dict_pair3, blocklist_pair3)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::DnsBlocklist, middlebox::PretendVerifyMode::NotPretend)
                },
                "Regex" => {
                    let pretend_size: usize = args[6].parse().unwrap(); 
                    let pretend_mode = if pretend_size > 0 {
                        let (proof, witnesses) = get_syncthetic_regex_proof(pretend_size);
                        PretendVerifyMode::RegexPretend(proof, witnesses)
                    } else {
                        PretendVerifyMode::NotPretend
                    };
                    middlebox::start_http_server::<500>(Arc::new(middlebox::HttpServerMode::Async(packet_state_dict_pair3, blocklist_pair3)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::Regex, pretend_mode)
                },
                _ => unimplemented!()
            }
            
        });
        http_handle.join().unwrap();
        drop_handle.join().unwrap();
        netfilter_handle.join().unwrap()
    } else if args[1] == "sync_precomp" {
        Ok(())
    } else if args[1] == "test_nfq" {
        // middlebox::test_nfq();
        Ok(())
    } else if args[1] == "batch_benchmark" {
        middlebox::batch_benchmark(args[2].parse().unwrap(), args[3].parse().unwrap());
        Ok(())
    } else if args[1] == "benchmark_sync" {
        let mut packet_handler = packet_parse::PacketHandler::new();
        let mut queue = Queue::open()?;
        queue.bind(0)?;
        queue.set_nonblocking(true);
        let queue_lock = Arc::new(Mutex::new(queue));
        let queue_lock2 = queue_lock.clone();
        println!("sync middlebox");
        let mut should_cache_response = true;
        if args[1] == "benchmark_sync" {
            should_cache_response = false;
        }
        let handshake_dict_pair = Arc::new((Mutex::new(HashMap::<IpAddr, (Vec<u8>, Vec<u8>)>::new()), Condvar::new()));
        let handshake_dict_pair2 = handshake_dict_pair.clone();
        let mut max_verified_seq_nums = Vec::new();
        let packet_state_dict_pair = Arc::new((Mutex::new(HashMap::<IpAddr, HashMap<usize, FilterState>>::new()), Condvar::new()));
        let packet_state_dict_pair2 = packet_state_dict_pair.clone();
        let (tx, rx) = mpsc::channel();
        let netfilter_block_handle = thread::spawn(move || {
            middlebox::netfilter(middlebox::NetfilterMode::Sync(tx, max_verified_seq_nums, should_cache_response), handshake_dict_pair, queue_lock)
        });
        let collector_handle = thread::spawn(move || {
            middlebox::filter_state_collector(packet_state_dict_pair, rx)
        });
        let block_http_handle = thread::spawn(move || {
            let should_verify_co = if args[5] == "true" { true } else { false };
            match args[2].as_str() {
                "Dot" => {
                    middlebox::start_http_server::<255>(Arc::new(middlebox::HttpServerMode::Sync(packet_state_dict_pair2, queue_lock2, should_cache_response)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::DnsBlocklist, PretendVerifyMode::NotPretend)
                },
                "Doh" => {
                    middlebox::start_http_server::<500>(Arc::new(middlebox::HttpServerMode::Sync(packet_state_dict_pair2, queue_lock2, should_cache_response)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::DnsBlocklist, PretendVerifyMode::NotPretend)
                },
                "Regex" => {
                    middlebox::start_http_server::<500>(Arc::new(middlebox::HttpServerMode::Sync(packet_state_dict_pair2, queue_lock2, should_cache_response)), handshake_dict_pair2, args[2].clone(), args[3].clone(), should_verify_co, middlebox::PolicyMode::Regex, PretendVerifyMode::NotPretend)
                }
                _ => unimplemented!()
            }
        });
        
        block_http_handle.join().unwrap();
        netfilter_block_handle.join().unwrap();
        collector_handle.join().unwrap();
        Ok(())
    } else {
        Ok(())
    }
}