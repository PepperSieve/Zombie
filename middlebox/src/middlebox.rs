use crate::blocklist_checker::BlocklistChecker;
use crate::packet_parse::{self, FilterState, VerifyMaterial};
use crate::MyPrinter;
use bincode::Error;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use chrono::Local;
use circ_zkmb::witnesses::amortized_unpack::AmortizedUnpackVerifierWitness;
use circ_zkmb::witnesses::amortized_witness::AmortizedProverWitness;
use circ_zkmb::witnesses::precomp_witness::PrecompDotChaChaVerifierWitness;
use circ_zkmb::witnesses::regex_witness::{
    RegexAmortizedProverWitness, RegexAmortizedVerifierWitness, RegexAmortizedUnpackVerifierWitness,
};
use circ_zkmb::witnesses::Witness;
use circ_zkmb::{
    decode_hex, witnesses::amortized_witness::AmortizedVerifierWitness,
    witnesses::channel_open_witness::ChannelOpenVerifierWitness, SpartanProof, SpartanVerifier,
};
use circ_zkmb::{zkmb_get_prover, SpartanProver, SpartanProcessesVerifier};
use core::time;
use dns_parser::Packet;
use env_logger::filter::{self, Filter};
use log::{info, warn};
use nfq::{Message, Queue, Verdict};
use nickel::{HttpRouter, JsonBody, Nickel};
use rand::rngs::OsRng;
use rand_distr::{Distribution, Exp};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryInto;
use std::ffi::CString;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{fs, panic, thread};

type CondPair<T> = Arc<(Mutex<T>, Condvar)>;
type HashMapLock<K, V> = Arc<Mutex<HashMap<K, V>>>;

#[derive(Clone)]
pub enum NetfilterMode {
    Sync(
        Sender<(IpAddr, FilterState, usize)>,
        // max_verified_seq_num
        Vec<Arc<Mutex<u32>>>,
        bool,
    ),
    // addr, state, sn
    Async(
        Sender<(IpAddr, FilterState, usize)>,
        CondPair<HashSet<IpAddr>>,
    ),
    NoPolicy(BlocklistChecker),
}

#[derive(Clone)]
pub enum HttpServerMode {
    Sync(
        CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
        Arc<Mutex<Queue>>,
        bool,
    ),
    Async(
        CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
        CondPair<HashSet<IpAddr>>,
    ),
}

fn myprint(msg: &str, thread: &str) {
    let thread_map = HashMap::from([
        ("nfq", 0),
        ("http_server", 1),
        ("async_verifier", 2),
        ("drop_thread", 3),
    ]);
    let mut words = vec![" "; thread_map.len()];
    words[thread_map[thread]] = msg;
    let sentence = words.join(";;;;;;");
    log::info!("{}", sentence);
}

fn recv_from_nfq(queue_lock: Arc<Mutex<Queue>>) -> Message {
    loop {
        // myprint("before recv_from_nfq queue lock", "message.log");
        let mut queue = queue_lock.lock().unwrap();
        // myprint("after recv_from_nfq queue lock", "message.log");
        if let Ok(msg) = queue.recv() {
            return msg;
        }
        // should call drop to release the lock here!
        drop(queue);
        sleep(time::Duration::from_micros(10));
    }
}

// pub fn test_nfq() {
//     let mut queue = Queue::open().unwrap();
//     queue.bind(0);
//     queue.set_nonblocking(true);
//     let queue_lock = Arc::new(Mutex::new(queue));
//     let queue_lock2 = queue_lock.clone();
//     let mut packet_handler = packet_parse::PacketHandler::new();
//     let (tx, rx): (Sender<(Message, bool)>, Receiver<(Message, bool)>) = mpsc::channel();
//     let handler1 = thread::spawn(move || {
//         loop {
//             myprint("before received message", "nfq");
//             let msg = recv_from_nfq(queue_lock.clone());
//             let msg2 = msg.clone();
//             myprint("after received message", "nfq");
//             let payload = format!("{:?}", msg.get_payload());
//             myprint(&payload, "nfq");
//             let mut is_dot = false;
//             for traffic in packet_handler.handle_message(&msg2) {
//                 match traffic.event {
//                     packet_parse::SuspiciousEvent::DoTApplicationData(client_ciphertext, sn) => {
//                         myprint("received dot message", "nfq");
//                         is_dot = true;
//                     }
//                     _ => ()
//                 }
//             }
//             tx.send((msg2.clone(), is_dot));
//         }
//     });
//     let handler2 = thread::spawn(move || {
//         loop {
//             let (mut msg, is_dot) = rx.recv().unwrap();
//             msg.set_verdict(Verdict::Accept);
//             if is_dot {
//                 // sleep only when dot
//                 sleep(Duration::from_millis(1000));
//             }
//             let mut queue = queue_lock2.lock().unwrap();
//             queue.verdict(msg);
//             drop(queue);
//         }
//     });
//     handler1.join();
//     handler2.join();
// }
pub fn netfilter(
    mode: NetfilterMode,
    handshake_dict_pair: CondPair<HashMap<IpAddr, (Vec<u8>, Vec<u8>)>>,
    queue_lock: Arc<Mutex<Queue>>,
) -> std::io::Result<()> {
    let mut packet_handler = packet_parse::PacketHandler::new();
    loop {
        // myprint("before received message", "message.log");
        // info!("before receive message");
        let msg = recv_from_nfq(queue_lock.clone());
        // info!("after receive message");
        // myprint("after received message", "message.log");
        let mut verdict = Some(Verdict::Accept);
        let t1 = Instant::now();
        let traffic_vec = packet_handler.handle_message(&msg);
        // info!("Handle message takes {}", t1.elapsed().as_millis());
        // TODO: msg can be used once at most, so we wrap it in a vec...
        // is this the best practice?
        let mut addr = None;
        let mut payload_sn_tuples = Vec::new();

        // cipher for no_privacy test
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);

        for traffic in traffic_vec {
            match traffic.event {
                packet_parse::SuspiciousEvent::DNS(query) => {
                    // if let Ok(packet) = Packet::parse(&query) {
                    //     let questions = packet.questions;
                    //     for q in questions {
                    //         let name = q.qname.to_string();
                    //         println!("dns name {}", name);
                    //         let timer = Instant::now();
                    //         if checker.contains(name) {
                    //             verdict = Some(Verdict::Drop);
                    //         }
                    //         println!("blocklist check time {}", timer.elapsed().as_micros());
                    //     }
                    // }
                }
                packet_parse::SuspiciousEvent::TLSClientRequest(client_ciphertext, sn) => {
                    // myprint(
                    //     &format!("{} received dot message sn: {}", traffic.source, sn),
                    //     "nfq",
                    // );
                    payload_sn_tuples.push((client_ciphertext, sn));
                    addr = Some(traffic.source);
                }
                packet_parse::SuspiciousEvent::TLSServerResponse => match &mode {
                    NetfilterMode::Sync(_, _, _) => {
                        // TODO: cache response mode
                        // if should_cache_response {
                        //     let (lock, cvar) = &*filter_states_pair[queue_num as usize];
                        //     let mut filter_state = lock.lock().unwrap();
                        //     while matches!(*filter_state, Some(FilterState::Wait(_))) {
                        //         filter_state = cvar.wait(filter_state).unwrap();
                        //     }
                        //     println!("wait finish");
                        //     match *filter_state {
                        //         Some(FilterState::Wait(_)) => {
                        //             panic!("state shouldn't be Wait here!")
                        //         }
                        //         Some(FilterState::Reject(_)) => verdict = Some(Verdict::Drop),
                        //         Some(FilterState::Accept) => (),
                        //         None => panic!("state shouldn't be None here!"),
                        //     }
                        // }
                    }
                    _ => (),
                },
                packet_parse::SuspiciousEvent::DoTHandshake(
                    client_hello,
                    server_hello,
                    server_hs_encrypted,
                ) => {
                    // println!("{:?}, {:?}, {:?}", client_hello, server_hello, server_hs_encrypted);
                    // println!("client hello");
                    // print_hexdump(&client_hello);
                    // println!("server hello");
                    // print_hexdump(&server_hello);
                    // println!("server hs encrypted");
                    // print_hexdump(&server_hs_encrypted);
                    let (lock, cvar) = &*handshake_dict_pair;
                    let mut handshake_dict = lock.lock().unwrap();
                    info!("insert source {}", traffic.destination);
                    handshake_dict.insert(
                        traffic.destination,
                        (
                            [client_hello, server_hello].concat(),
                            server_hs_encrypted[0..server_hs_encrypted.len() - 17].to_vec(),
                        ),
                    );
                }
                packet_parse::SuspiciousEvent::Retransmission(seq_num) => {
                    // myprint(
                    //     &format!("{}: Retransmission received {}", traffic.source, seq_num),
                    //     "nfq",
                    // );
                    verdict = Some(Verdict::Drop);
                    // TODO: this only works if messages are verified in order
                    // match mode.clone() {
                    //     NetfilterMode::Sync(_, _, max_verified_seq_num, _) => {
                    //         let lock = &*max_verified_seq_num[queue_num as usize].clone();
                    //         let max_queue_num = lock.lock().unwrap();
                    //         if *max_queue_num >= seq_num {
                    //             verdict = Some(Verdict::Accept);
                    //         }
                    //     }
                    //     NetfilterMode::Async(_, _) => (),
                    // }
                }
                packet_parse::SuspiciousEvent::Misorder => {
                    verdict = Some(Verdict::Drop);
                }
            }
        }
        let mut msg = Some(msg);
        if payload_sn_tuples.len() > 0 {
            match &mode {
                NetfilterMode::Sync(tx, _, _) => {
                    let last_idx = payload_sn_tuples.len() - 1;
                    for (idx, (payload, sn)) in payload_sn_tuples.iter().enumerate() {
                        // give message to the last state, such that we accept the message after verifying all of them
                        // TODO: this actually worsen latency, can we avoid it?
                        let msg = if idx == last_idx { msg.take() } else { None };
                        let state = FilterState::Wait(VerifyMaterial {
                            sn: sn.clone(),
                            start: Instant::now(),
                            source: addr.unwrap(),
                            payload: payload.clone(),
                            msg,
                        });
                        tx.send((addr.unwrap(), state, sn.clone()));
                        // info!("tx send data {} {}", addr.unwrap(), sn);
                    }
                    verdict = None;
                }
                NetfilterMode::Async(tx, blocklist_pair) => {
                    // println!("netfilter before blocklist");
                    let (lock, cvar) = &**blocklist_pair;
                    let blocklist = lock.lock().unwrap();
                    // println!("netfilter get blocklist");
                    if blocklist.contains(&addr.unwrap()) {
                        // println!("will drop traffic");
                        verdict = Some(Verdict::Drop);
                    } else {
                        for (payload, sn) in payload_sn_tuples {
                            let new_packet_state = FilterState::Wait(VerifyMaterial {
                                sn,
                                start: Instant::now(),
                                source: addr.unwrap(),
                                payload,
                                msg: None,
                            });
                            tx.send((addr.unwrap(), new_packet_state, sn));
                        }
                    }
                }
                NetfilterMode::NoPolicy(checker) => {
                    for (payload, sn) in payload_sn_tuples {
                        let plaintext = cipher.decrypt(&nonce, payload.as_ref());
                        if !checker.contains("amazon.com".to_string()) {
                            verdict = Some(Verdict::Accept);
                        } else {
                            verdict = Some(Verdict::Drop)
                        }
                        // info!("Set verdict");
                    }
                }
            }
        }
        if let Some(verdict) = verdict {
            let mut msg = msg.take().unwrap();
            msg.set_verdict(verdict);
            let mut queue = queue_lock.lock().unwrap();
            queue.verdict(msg)?;
        }
    }
    Ok(())
}

fn print_hexdump(data: &[u8]) {
    for byte in data {
        print!("{:02x}", &byte);
    }
    println!("");
}

// collects filter states from the receiver
// TODO: is this the best practice? anyway to improve this?
pub fn filter_state_collector(
    packet_state_dict_pair: CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
    rx: Receiver<(IpAddr, FilterState, usize)>,
) {
    loop {
        let (addr, state, sn) = rx.recv().unwrap();
        info!("rx collect data {} {}", addr, sn);
        let (lock, cvar) = &*packet_state_dict_pair;
        let mut packet_state_dict = lock.lock().unwrap();
        let packet_state_stack = packet_state_dict
            .entry(addr)
            .or_insert(HashMap::<usize, FilterState>::new());
        packet_state_stack.insert(sn, state);
        cvar.notify_all();
    }
}

pub fn drop_thread(
    packet_state_dict_pair: CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
    blocklist_pair: CondPair<HashSet<IpAddr>>,
    wait_maximum: Duration,
) {
    loop {
        // check every one second
        thread::sleep(Duration::from_millis(1000));
        // println!("drop thread wake up");
        let (lock, cvar) = &*packet_state_dict_pair;
        let mut packet_state_dict = lock.lock().unwrap();
        let mut ip_to_block = HashSet::<IpAddr>::new();
        let (blocklist_lock, blocklist_cvar) = &*blocklist_pair;
        let mut blocklist = blocklist_lock.lock().unwrap();
        for (source, state_list) in packet_state_dict.iter() {
            for (_, state) in state_list {
                if blocklist.contains(source) {
                    continue;
                }
                match state.clone() {
                    FilterState::Wait(material) => {
                        // myprint(
                        //    &format!("{}: {} elapsed {}",
                        //     material.source,
                        //     material.sn,
                        //     material.start.elapsed().as_millis()),
                        //     "drop_thread"
                        // );
                        if material.start.elapsed() > wait_maximum {
                            println!("Ban {}", material.source);
                            blocklist.insert(material.source.clone());
                            ip_to_block.insert(material.source.clone());
                        }
                    }
                    FilterState::Reject(ip) => {
                        blocklist.insert(ip.clone());
                        ip_to_block.insert(ip.clone());
                    }
                    FilterState::Accept => (),
                }
            }
        }
        // // only keep traffic waiting for proof
        // packet_state_dict.retain(|key, value| {
        //     match value {
        //         FilterState::Wait(material) => {
        //             !ip_to_block.contains(&material.traffic.source)
        //         },
        //         FilterState::Reject(_) => false,
        //     }
        // });
        // println!("blocklist {:?}", blocklist);
    }
}

fn get_tail_minus_18_bytes(arr: Vec<u8>) -> Vec<u8> {
    let num_whole_blocks = (arr.len() - 36) / 64;
    let tail_len = arr.len() - num_whole_blocks * 64;
    arr.as_slice()[arr.len() - tail_len..].to_vec()
}

fn middlebox_verify_co(
    ch_sh: Vec<u8>,
    ct_3: Vec<u8>,
    comm: String,
    proof: &Vec<u8>,
    verifier: &SpartanVerifier,
) -> bool {
    let t1 = Instant::now();
    let mut m = Sha256::new();
    m.update(&ch_sh);
    let ServExt_ct_tail = get_tail_minus_18_bytes([ch_sh.clone(), ct_3.clone()].concat());
    if let Ok(proof) = bincode::deserialize(&proof) {
        let witness = ChannelOpenVerifierWitness {
            H2: m.finalize().to_vec().iter().map(|b| b.clone()).collect(),
            CH_SH_len: ch_sh.len() as u16,
            ServExt_len: ct_3.len() as u16,
            ServExt_ct_tail: ServExt_ct_tail.iter().map(|b| b.clone()).collect(),
            ServExt_tail_len: ServExt_ct_tail.len() as u8,
            comm,
        };
        info!(
            "H2 {:?} CH_SH_len {} ServExt_len {} ServExt_ct_tail {:?} ServExt_tail_len {} comm {}",
            witness.H2,
            witness.CH_SH_len,
            witness.ServExt_len,
            witness.ServExt_ct_tail,
            witness.ServExt_tail_len,
            witness.comm
        );
        let t2 = Instant::now();
        let result = verifier.verify(&proof, &vec![witness]);
        let t3 = Instant::now();
        println!(
            "verify {} {}",
            t3.duration_since(t2).as_millis(),
            t2.duration_since(t1).as_millis()
        );
        return result;
    }
    false
}

pub enum PretendVerifyMode {
    DnsPretend(SpartanProof, Vec<AmortizedVerifierWitness<255>>),
    RegexPretend(SpartanProof, Vec<RegexAmortizedVerifierWitness<1000>>),
    NotPretend,
}

fn verify_async_amortized_witnesses<const DnsCtLen: usize>(
    verifier: &SpartanProcessesVerifier,
    proof: &Option<SpartanProof>,
    batch_tuple: (usize, usize),
    packet_state_dict_pair: CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
    source: &IpAddr,
    comm: &String,
    pretend_mode: Arc<PretendVerifyMode>,
    policy_mode: &PolicyMode,
    pid: usize
) -> bool {
    match policy_mode {
        PolicyMode::DnsBlocklist => {
            let mut witnesses = Vec::new();
            let (lock, cvar) = &*packet_state_dict_pair;
            info!("before packet_state_dict lock");
            let mut packet_state_dict = lock.lock().unwrap();
            info!("after packet_state_dict lock");
            for sn in batch_tuple.0..batch_tuple.1 + 1 {
                info!("Check sn {} start", sn);
                while !packet_state_dict.get(&source).unwrap().contains_key(&sn) {
                    info!("packet_state_dict will wait");
                    packet_state_dict = cvar.wait(packet_state_dict).unwrap();
                    info!("packet_state_dict end wait");
                }
                if let Some(FilterState::Wait(material)) =
                    packet_state_dict.get_mut(source).unwrap().remove(&sn)
                {
                    myprint(
                        &format!(
                            "Async sn {} get proof elapsed {}",
                            material.sn,
                            material.start.elapsed().as_millis()
                        ),
                        "http_server",
                    );
                    // TODO: change255 to DnsCtLen
                    let witness = AmortizedVerifierWitness::<255> {
                SN: material.sn as u32,
                comm: comm.to_string(),
                dns_ct: material.payload.clone(),
                root:
                    "5972733345965465510373436926431083918242531555386867859948086370295902707692"
                        .to_string(),
            };
                    info!(
                        "{} amortized witness SN {} comm {} dns_ct {:?}",
                        source, witness.SN, witness.comm, witness.dns_ct
                    );
                    info!("{} sn is {}", source, material.sn);
                    witnesses.push(witness);
                } else {
                    panic!("FilterState has to be Wait here");
                }
                info!("Check sn {} end", sn);
            }
            info!("Check 5");
            drop(packet_state_dict);
            info!(
                "batch size is {}, witnesses len is {}",
                batch_tuple.1 - batch_tuple.0 + 1,
                witnesses.len()
            );
            let res = match &*pretend_mode {
                PretendVerifyMode::DnsPretend(proof, witnesses) => {
                    verifier.verify(&proof, &witnesses, pid)
                }
                PretendVerifyMode::RegexPretend(proof, witnesses) => {
                    // verifier.verify(&proof, &witnesses, pid)
                    todo!()
                }
                PretendVerifyMode::NotPretend => {
                    verifier.verify(proof.as_ref().unwrap(), &witnesses, pid)
                }
            };
            res
        }
        PolicyMode::Regex => {
            let mut witnesses = Vec::new();
            let (lock, cvar) = &*packet_state_dict_pair;
            info!("before packet_state_dict lock");
            let mut packet_state_dict = lock.lock().unwrap();
            info!("after packet_state_dict lock");
            for sn in batch_tuple.0..batch_tuple.1 + 1 {
                info!("Check sn {} start", sn);
                while !packet_state_dict.get(&source).unwrap().contains_key(&sn) {
                    info!("packet_state_dict will wait");
                    packet_state_dict = cvar.wait(packet_state_dict).unwrap();
                    info!("packet_state_dict end wait");
                }
                if let Some(FilterState::Wait(material)) =
                    packet_state_dict.get_mut(source).unwrap().remove(&sn)
                {
                    myprint(
                        &format!(
                            "Async sn {} get proof elapsed {}",
                            material.sn,
                            material.start.elapsed().as_millis()
                        ),
                        "http_server",
                    );
                    let witness = RegexAmortizedVerifierWitness::<1000> {
                        SN: material.sn as u32,
                        comm: comm.to_string(),
                        ciphertext: material.payload.clone(),
                    };
                    info!(
                        "{} amortized witness SN {} comm {} ciphertext {:?}",
                        source, witness.SN, witness.comm, witness.ciphertext
                    );
                    info!("{} sn is {}", source, material.sn);
                    witnesses.push(witness);
                } else {
                    panic!("FilterState has to be Wait here");
                }
                info!("Check sn {} end", sn);
            }
            info!("Check 5");
            drop(packet_state_dict);
            info!(
                "batch size is {}, witnesses len is {}",
                batch_tuple.1 - batch_tuple.0 + 1,
                witnesses.len()
            );
            let res = match &*pretend_mode {
                PretendVerifyMode::DnsPretend(proof, witnesses) => {
                    verifier.verify(&proof, &witnesses, pid)
                }
                PretendVerifyMode::NotPretend => {
                    // verifier.verify(proof.as_ref().unwrap(), &witnesses)
                    todo!()
                }
                PretendVerifyMode::RegexPretend(proof, witnesses) => {
                    // verifier.verify(&proof, &witnesses)
                    todo!()
                }
            };
            res
        }
    }
}

fn middlebox_verify_amortized_async(
    packet_state_dict_pair: CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
    comm_dict: Arc<Mutex<HashMap<IpAddr, String>>>,
    blocklist_pair: CondPair<HashSet<IpAddr>>,
    source: IpAddr,
    proof: &Vec<u8>,
    policy_mode: &PolicyMode,
    verifier: Arc<SpartanProcessesVerifier>,
    batch_tuple: (usize, usize),
    protocol: &str,
    pretend_mode: Arc<PretendVerifyMode>,
    pid: usize
) {
    let comm_dict = comm_dict.lock().unwrap();
    if let Some(comm) = comm_dict.get(&source) {
        let comm = comm.clone();
        drop(comm_dict);
        let proof: Option<SpartanProof> = match &*pretend_mode {
            PretendVerifyMode::NotPretend => Some(bincode::deserialize(&proof).unwrap()),
            _ => None,
        };
        let batch_size = batch_tuple.1 - batch_tuple.0 + 1;
        let t1 = Instant::now();
        // TODO: if 3rd proof get processed before 2nd proof, there will be problem
        info!(
            "{} wait for packets for {}",
            source,
            t1.elapsed().as_millis()
        );
        let result = match protocol {
            "Doh" => verify_async_amortized_witnesses::<500>(
                &verifier,
                &proof,
                batch_tuple,
                packet_state_dict_pair,
                &source,
                &comm,
                pretend_mode,
                policy_mode,
                pid
            ),
            "Dot" => verify_async_amortized_witnesses::<255>(
                &verifier,
                &proof,
                batch_tuple,
                packet_state_dict_pair,
                &source,
                &comm,
                pretend_mode,
                policy_mode,
                pid
            ),
            "Regex" => verify_async_amortized_witnesses::<255>(
                &verifier,
                &proof,
                batch_tuple,
                packet_state_dict_pair,
                &source,
                &comm,
                pretend_mode,
                policy_mode,
                pid
            ),
            _ => unimplemented!(),
        };
        info!(
            "{} verify result is {}, batch size is {}",
            source, result, batch_size
        );
        if !result {
            let (blocklist_lock, blocklist_cvar) = &*blocklist_pair;
            let mut blocklist = blocklist_lock.lock().unwrap();
            blocklist.insert(source);
        }
    } else {
        println!("commitment not found!");
    }
}

fn verify_sync_amortized_witnesses<const DnsCtLen: usize>(
    policy_mode: &PolicyMode,
    verifier: &SpartanVerifier,
    proof: &Vec<u8>,
    sn_comm_dns_tuples: Vec<(usize, String, Vec<u8>)>,
) -> bool {
    match policy_mode {
        PolicyMode::DnsBlocklist => {
            let witnesses = sn_comm_dns_tuples
                .iter()
                .map({
                    |(sn, comm, dns_ct)| {
                        AmortizedVerifierWitness::<DnsCtLen> {
                SN: sn.clone() as u32,
                comm: comm.to_string(),
                dns_ct: dns_ct.clone(),
                root:
                    "5972733345965465510373436926431083918242531555386867859948086370295902707692"
                        .to_string(),
            }
                    }
                })
                .collect();
            let proof: SpartanProof = bincode::deserialize(&proof).unwrap();
            let timer = Instant::now();
            let res = verifier.verify(&proof, &witnesses);
            info!("Just verify takes {}", timer.elapsed().as_millis());
            res
        }
        PolicyMode::Regex => {
            let witnesses = sn_comm_dns_tuples
                .iter()
                .map({
                    |(sn, comm, dns_ct)| RegexAmortizedVerifierWitness::<1000> {
                        SN: sn.clone() as u32,
                        comm: comm.to_string(),
                        ciphertext: dns_ct.clone(),
                    }
                })
                .collect();
            info!("Regex witness is {:?}", witnesses);
            let proof: SpartanProof = bincode::deserialize(&proof).unwrap();
            verifier.verify(&proof, &witnesses)
        }
    }
}

fn verify_sync_precomputed_amortized_witnesses<const DnsCtLen: usize>(
    policy_mode: &PolicyMode,
    verifier: &SpartanVerifier,
    proof: &Vec<u8>,
    comm_ciphertext_tuples: &Vec<(String, Vec<u8>)>,
) -> bool {
    match policy_mode {
        PolicyMode::DnsBlocklist => {
            println!("precomputed witness {:?}", comm_ciphertext_tuples);
            // we don't need sn here since is has been verified in precomp
            let witnesses: Vec<AmortizedUnpackVerifierWitness<DnsCtLen>> = comm_ciphertext_tuples
                .iter()
                .map(|tuple| AmortizedUnpackVerifierWitness::<DnsCtLen> {
                    comm_pad: tuple.0.clone(),
                    dns_ct: tuple.1.clone(),
                    root: "5972733345965465510373436926431083918242531555386867859948086370295902707692"
                        .to_string(),
                    ret: "1".to_string(),
                })
                .collect();
            let proof: SpartanProof = bincode::deserialize(&proof).unwrap();
            // println!("witness is {:?}", witness);
            verifier.verify(&proof, &witnesses)
        }
        PolicyMode::Regex => {
            println!("precomputed witness {:?}", comm_ciphertext_tuples);
            // we don't need sn here since is has been verified in precomp
            let witnesses: Vec<RegexAmortizedUnpackVerifierWitness<1000>> = comm_ciphertext_tuples
                .iter()
                .map(|tuple| RegexAmortizedUnpackVerifierWitness::<1000> {
                    comm_pad: tuple.0.clone(),
                    ciphertext: tuple.1.clone(),
                })
                .collect();
            let proof: SpartanProof = bincode::deserialize(&proof).unwrap();
            // println!("witness is {:?}", witness);
            verifier.verify(&proof, &witnesses)
        }
    }
}

enum AmortizedMode {
    PrecompMode(
        HashMapLock<IpAddr, HashMapLock<u32, String>>,
        PolicyMode,
        Arc<SpartanVerifier>,
    ),
    DefaultMode(
        Arc<Mutex<HashMap<IpAddr, String>>>,
        PolicyMode,
        Arc<SpartanVerifier>,
    ),
}

#[derive(Clone, Debug)]
pub enum PolicyMode {
    DnsBlocklist,
    Regex,
}

fn middlebox_verify_amortized_sync<const DnsCtLen: usize>(
    // batch start, filter_states
    packet_state_dict_pair: CondPair<HashMap<IpAddr, HashMap<usize, FilterState>>>,
    mode: AmortizedMode,
    client: IpAddr,
    proof: &Vec<u8>,
    // start, end
    batch_tuple: (usize, usize),
    queue_lock: Arc<Mutex<Queue>>,
) {
    info!("Start amortized sync {} {:?}", client, batch_tuple);
    let mut materials = Vec::new();
    let mut messages = Vec::new();
    // let batch_size = batch_tuple.1 - batch_tuple.0 + 1;
    let (lock, cvar) = &*packet_state_dict_pair;
    myprint("Before filter_states lock", "http_server");
    let mut filter_states = lock.lock().unwrap();
    myprint("After filter_states lock", "http_server");
    for idx in batch_tuple.0..batch_tuple.1 + 1 {
        while !filter_states[&client].contains_key(&idx) {
            info!("Start filter_states wait {} {:?}", client, batch_tuple);
            filter_states = cvar.wait(filter_states).unwrap();
            info!("End filter_states wait {} {:?}", client, batch_tuple);
        }
        let filter_state = filter_states
            .get_mut(&client)
            .unwrap()
            .remove(&idx)
            .unwrap();
        match filter_state {
            FilterState::Wait(material) => {
                materials.push(material);
            }
            _ => {
                println!("Expected Wait here");
                return;
            }
        }
    }
    drop(filter_states);
    println!("materials are {:?}", materials.len());
    info!("Check3 {} {:?}", client, batch_tuple);
    let result = match mode {
        AmortizedMode::PrecompMode(pad_comm_dict_lock, policy_mode, verifier) => {
            myprint("Before pad_comm_dict lock", "http_server");
            let pad_comm_dict = pad_comm_dict_lock.lock().unwrap();
            myprint("After pad_comm_dict lock", "http_server");
            let mut comm_dns_tuples = Vec::new();
            for material in materials {
                if let Some(m) = pad_comm_dict.get(&material.source) {
                    // TODO: is pad_comm_dict dropped here?
                    myprint("Before m lock", "http_server");
                    info!("Check m before {} {:?}", client, batch_tuple);
                    let m = m.lock().unwrap();
                    info!("Check m after {} {:?}", client, batch_tuple);
                    myprint("After m lock", "http_server");
                    if let Some(pad_comm) = m.get(&(material.sn as u32)) {
                        let dns_ct = material.payload;
                        comm_dns_tuples.push((pad_comm.clone(), dns_ct));
                    } else {
                        println!("pad commitment not found!");
                        // TODO: return or reject here?
                        return;
                    };
                } else {
                    println!("ip address not found!");
                    return;
                }
                messages.push((material.msg, vec![0; 8]));
            }
            drop(pad_comm_dict);
            verify_sync_precomputed_amortized_witnesses::<DnsCtLen>(
                &policy_mode,
                &verifier,
                proof,
                &comm_dns_tuples,
            )
        }
        AmortizedMode::DefaultMode(comm_dict, policy_mode, verifier) => {
            let comm_dict = comm_dict.lock().unwrap();
            let mut sn_comm_dns_tuples = Vec::new();
            for material in materials {
                let sn = material.sn;
                info!("material source is {}", &material.source);
                info!("comm_dict {:?}", comm_dict);
                let comm = comm_dict.get(&material.source).unwrap();
                let dns_ct = material.payload;
                sn_comm_dns_tuples.push((sn, comm.clone(), dns_ct.clone()));
                messages.push((material.msg, dns_ct));
            }
            drop(comm_dict);
            verify_sync_amortized_witnesses::<DnsCtLen>(
                &policy_mode,
                &verifier,
                proof,
                sn_comm_dns_tuples,
            )
        }
    };
    info!("Check4 {} {:?}", client, batch_tuple);
    for msg in messages {
        myprint("Before queue lock", "http_server");
        let mut queue = queue_lock.lock().unwrap();
        myprint("After queue lock", "http_server");
        // if the payload belongs to first several requests in the message, we shouldn't accept the message yet
        if let (Some(mut msg), payload) = msg {
            // sleep(Duration::from_millis(50));
            if result {
                msg.set_verdict(Verdict::Accept);
            } else {
                // msg.set_verdict(Verdict::Drop);
                msg.set_verdict(Verdict::Accept);
            }
            let r = queue.verdict(msg);
            info!("before verdict resul");
            myprint(
                &format!(
                    "{}: verdict result {} {}-{} {:?}",
                    client,
                    result,
                    batch_tuple.0,
                    batch_tuple.1,
                    &payload[0..8]
                ),
                "http_server",
            );
        } else {
            myprint(
                &format!(
                    "{}: verdict result {} {}-{}",
                    client, result, batch_tuple.0, batch_tuple.1
                ),
                "http_server",
            );
        }
    }
    info!("Check5 {} {:?}", client, batch_tuple);
    info!("End amortized sync {} {:?}", client, batch_tuple);
}

fn read_from_path<T: DeserializeOwned>(path: &str) -> T {
    println!("path {}", path);
    let data = fs::read(path).expect("Unable to read data");
    let result = bincode::deserialize(&data).unwrap();
    result
}

#[derive(Deserialize, Clone)]
pub struct AmortizedRequest {
    pub is_precomputed: bool,
    pub batch_start: usize,
    pub batch_end: usize,
    pub r1cs_proof: String,
}

#[derive(Deserialize)]
struct ChannelOpenRequest {
    comm: String,
    r1cs_proof: String,
}

#[derive(Deserialize)]
struct PrecompRequest {
    r1cs_proof: String,
    // comm, pad_comm, seq_num
    comm_list: Vec<String>,
    pad_comm_list: Vec<String>,
    seq_num_list: Vec<u32>,
}

pub fn get_normal_amortized_processes_verifier(protocol: &String, cipher: &String) -> Arc<SpartanProcessesVerifier> {
    let inst = read_from_path(&format!("/mydata/{}{}Amortized_inst", protocol, cipher));
    let gens = read_from_path(&format!("/mydata/{}{}Amortized_gens", protocol, cipher));
    let input_names = read_from_path(&format!(
        "/mydata/{}{}Amortized_input_names",
        protocol, cipher
    ));
    let verifier = Arc::new(SpartanProcessesVerifier::new(inst, gens, input_names, 16));
    verifier
}

pub fn get_normal_amortized_verifier(protocol: &String, cipher: &String) -> Arc<SpartanVerifier> {
    let inst = read_from_path(&format!("/mydata/{}{}Amortized_inst", protocol, cipher));
    let gens = read_from_path(&format!("/mydata/{}{}Amortized_gens", protocol, cipher));
    let input_names = read_from_path(&format!(
        "/mydata/{}{}Amortized_input_names",
        protocol, cipher
    ));
    let verifier = Arc::new(SpartanVerifier::new(inst, gens, input_names));
    verifier
}

pub fn get_regex_verifier() -> Option<Arc<SpartanVerifier>> {
    let result = panic::catch_unwind(|| {
        let inst = read_from_path(&format!("/mydata/RegexChaChaAmortized_inst"));
        let gens = read_from_path(&format!("/mydata/RegexChaChaAmortized_gens"));
        let input_names = read_from_path(&format!("/mydata/RegexChaChaAmortized_input_names"));
        let verifier = Arc::new(SpartanVerifier::new(inst, gens, input_names));
        verifier
    });
    match result {
        Ok(verifier) => Some(verifier),
        Err(_) => None,
    }
}

pub fn get_precomp_verifier(protocol: &String, cipher: &String) -> Arc<SpartanVerifier> {
    let inst = read_from_path(&format!("/mydata/PrecompDot{}_inst", cipher));
    let gens = read_from_path(&format!("/mydata/PrecompDot{}_gens", cipher));
    let input_names = read_from_path(&format!("/mydata/PrecompDot{}_input_names", cipher));
    Arc::new(SpartanVerifier::new(inst, gens, input_names))
}

pub fn get_unpack_verifier(protocol: &String, cipher: &String) -> Option<Arc<SpartanVerifier>> {
    let result = panic::catch_unwind(|| {
        let inst = read_from_path(&format!(
            "/mydata/{}{}AmortizedUnpack_inst",
            protocol, cipher
        ));
        let gens = read_from_path(&format!(
            "/mydata/{}{}AmortizedUnpack_gens",
            protocol, cipher
        ));
        let input_names = read_from_path(&format!(
            "/mydata/{}{}AmortizedUnpack_input_names",
            protocol, cipher
        ));
        Arc::new(SpartanVerifier::new(inst, gens, input_names))
    });
    match result {
        Ok(verifier) => Some(verifier),
        Err(_) => None,
    }
}

#[deny(unreachable_code)]
pub fn start_http_server<const DnsCtLen: usize>(
    mode: Arc<HttpServerMode>,
    handshake_dict_pair: CondPair<HashMap<IpAddr, (Vec<u8>, Vec<u8>)>>,
    protocol: String,
    cipher: String,
    should_verify_co: bool,
    policy_mode: PolicyMode,
    pretend_mode: PretendVerifyMode,
) {
    let policy_mode_clone = policy_mode.clone();
    let mut server = Nickel::new();
    let comm_dict_lock = Arc::new(Mutex::new(HashMap::<IpAddr, String>::new()));
    let comm_dict_lock2 = comm_dict_lock.clone();
    let protocol_copy = protocol.clone();
    let pad_comm_dict_lock = Arc::new(Mutex::new(
        HashMap::<IpAddr, HashMapLock<u32, String>>::new(),
    ));
    let pad_comm_dict_lock2 = pad_comm_dict_lock.clone();

    let normal_processes_verifier = get_normal_amortized_processes_verifier(&protocol, &cipher);
    let normal_verifier = get_normal_amortized_verifier(&protocol, &cipher);
    let unpack_verifier = get_unpack_verifier(&protocol, &cipher);

    let regex_normal_verifier = get_regex_verifier();

    let co_verifier = {
        if should_verify_co {
            let inst = read_from_path(&format!("/mydata/{}ChannelOpen_inst", cipher));
            let gens = read_from_path(&format!("/mydata/{}ChannelOpen_gens", cipher));
            let input_names = read_from_path(&format!("/mydata/{}ChannelOpen_input_names", cipher));
            let co_verifier = SpartanVerifier::new(inst, gens, input_names);
            Some(co_verifier)
        } else {
            None
        }
    };

    let pretend_mode = Arc::new(pretend_mode);

    server.post(
        "/channel_open_proof",
        middleware! { |request|
            info!("received co dot");
            let r = request.json_as::<ChannelOpenRequest>().unwrap();
            let ip = request.origin.remote_addr.ip();
            let mut comm_dict = comm_dict_lock.lock().unwrap();
            if should_verify_co {
                let (lock, cvar) = &*handshake_dict_pair;
                let handshake_dict = lock.lock().unwrap();
                info!("get ip {}", ip);
                let (ch_sh, ct_3) = handshake_dict[&ip].clone();
                let proof = decode_hex(&r.r1cs_proof).unwrap();
                if middlebox_verify_co(ch_sh, ct_3, r.comm.clone(), &proof, &co_verifier.clone().unwrap()) {
                    comm_dict.insert(ip, r.comm.clone());
                } else {
                    // hack, workaround for regex case
                    comm_dict.insert(ip, r.comm.clone());
                }
            } else {
                comm_dict.insert(ip, r.comm.clone());
            }
            info!("comm_dict {:?}", comm_dict);
            "ok"
        },
    );

    let filter_states_pair = Arc::new((
        Mutex::new(Vec::<(AmortizedRequest, IpAddr, Instant)>::new()),
        Condvar::new(),
    ));
    let filter_states_pair2 = filter_states_pair.clone();

    let NUM_THREAD = 16;
    let mut filter_states_tx_list = Vec::new();
    let mut filter_states_rx_list = Vec::new();
    for _ in 0..NUM_THREAD {
        let (tx, rx): (
            Sender<(AmortizedRequest, IpAddr, Instant)>,
            Receiver<(AmortizedRequest, IpAddr, Instant)>,
        ) = mpsc::channel();
        filter_states_tx_list.push(tx);
        filter_states_rx_list.push(rx);
    }
    let filter_states_tx_list_lock = Arc::new(Mutex::new(filter_states_tx_list));

    for pid in 0..NUM_THREAD {
        let filter_states_rx = filter_states_rx_list.pop().unwrap();
        let pad_comm_dict_lock = pad_comm_dict_lock.clone();
        let comm_dict_lock2 = comm_dict_lock2.clone();
        let protocol_copy = protocol_copy.clone();
        let mode = mode.clone();
        let unpack_verifier = unpack_verifier.clone();
        let normal_processes_verifier = normal_processes_verifier.clone();
        let normal_verifier = normal_verifier.clone();
        let regex_normal_verifier = regex_normal_verifier.clone();
        let policy_mode = policy_mode.clone();
        let pretend_mode = pretend_mode.clone();
        thread::spawn(move || {
            // if sn not seen, add back to the queue
            let mut states_to_verify = Vec::new();
            let mut prepare_time_timer = Instant::now();
            loop {
                prepare_time_timer = Instant::now();
                // info!("Start of Loop");
                let mut my_states = Vec::new();
                for state in states_to_verify {
                    my_states.push(state);
                }
                loop {
                    match filter_states_rx.try_recv() {
                        Ok(state) => {
                            my_states.push(state);
                        }
                        Err(_) => break,
                    }
                }

                // make sure has seen the message
                let pair = match &*mode {
                    HttpServerMode::Sync(packet_state_dict_pair, _, _) => {
                        packet_state_dict_pair.clone()
                    }
                    HttpServerMode::Async(packet_state_dict_pair, _) => {
                        packet_state_dict_pair.clone()
                    }
                };

                let (lock, cvar) = &*pair;
                let packet_state_dict = lock.lock().unwrap();
                let mut ok_states = Vec::new();
                let mut not_ok_states = Vec::new();
                for state in my_states {
                    let mut ok = true;
                    for sn in state.0.batch_start..state.0.batch_end + 1 {
                        if !packet_state_dict.contains_key(&state.1) {
                            // info!("packet_state_dict not prepared!");
                            ok = false;
                            break;
                        }
                        if !packet_state_dict[&state.1.clone()].contains_key(&sn) {
                            // info!("packet_state_dict not prepared!");
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        ok_states.push(state);
                    } else {
                        not_ok_states.push(state);
                    }
                }
                drop(packet_state_dict);

                // don't have to check for precomp
                match *mode {
                    HttpServerMode::Sync(_, _, _) => {
                        let mut ok_ok_states = Vec::new();
                        let pad_comm_dict = pad_comm_dict_lock.lock().unwrap();
                        for state in ok_states {
                            let r = &state.0;
                            if r.is_precomputed {
                                let ip = &state.1;
                                let mut ok = true;
                                for sn in r.batch_start..r.batch_end + 1 {
                                    if !pad_comm_dict.contains_key(ip) {
                                        ok = false;
                                        break;
                                    }
                                    if !pad_comm_dict[&ip]
                                        .lock()
                                        .unwrap()
                                        .contains_key(&(sn as u32))
                                    {
                                        ok = false;
                                        break;
                                    }
                                }
                                if ok {
                                    ok_ok_states.push(state);
                                } else {
                                    not_ok_states.push(state);
                                }
                            } else {
                                ok_ok_states.push(state);
                            }
                        }
                        ok_states = ok_ok_states;
                    }
                    HttpServerMode::Async(_, _) => (),
                }

                states_to_verify = Vec::new();
                for state in not_ok_states {
                    states_to_verify.push(state);
                }

                if ok_states.len() == 0 {
                    continue;
                }

                // let chunk_size = 16 / (ok_states[0].0.batch_end - ok_states[0].0.batch_start + 1) + 1;
                let chunk_size = 16;
                info!("Chunk size is {}", chunk_size);
                info!(
                    "Prepare time timer elapsed {}, ok states len {}",
                    prepare_time_timer.elapsed().as_millis(),
                    ok_states.len()
                );
                for chunk in ok_states.chunks(chunk_size) {
                    info!("Start of chunk");
                    let t2 = Instant::now();
                    for state in chunk {
                        let (r, ip, t1) = state;
                        info!(
                            "Batch prepare {} proofs takes {} ms, {}-{}",
                            r.batch_end - r.batch_start + 1,
                            t1.elapsed().as_millis(),
                            r.batch_start,
                            r.batch_end
                        );
                        let proof = decode_hex(&r.r1cs_proof).unwrap();
                        match &*mode.clone() {
                            HttpServerMode::Sync(packet_state_dict_pair, queue_lock, nums) => {
                                match ip {
                                    IpAddr::V4(addr) => {
                                        let timer = Instant::now();
                                        if r.is_precomputed {
                                            // there might be more than one filter_state in the queue
                                            println!("before amortized unpack verify");
                                            info!("policy mode is {:?}", policy_mode);
                                            middlebox_verify_amortized_sync::<DnsCtLen>(
                                                packet_state_dict_pair.clone(),
                                                AmortizedMode::PrecompMode(
                                                    pad_comm_dict_lock.clone(),
                                                    policy_mode.clone(),
                                                    match policy_mode {
                                                        PolicyMode::DnsBlocklist => {
                                                            unpack_verifier.clone().unwrap()
                                                        }
                                                        PolicyMode::Regex => {
                                                            unpack_verifier.clone().unwrap()
                                                        }
                                                    },
                                                ),
                                                *ip,
                                                &proof,
                                                (r.batch_start, r.batch_end),
                                                queue_lock.clone(),
                                            );
                                        } else {
                                            middlebox_verify_amortized_sync::<DnsCtLen>(
                                                packet_state_dict_pair.clone(),
                                                AmortizedMode::DefaultMode(
                                                    comm_dict_lock2.clone(),
                                                    policy_mode.clone(),
                                                    match policy_mode {
                                                        PolicyMode::DnsBlocklist => {
                                                            normal_verifier.clone()
                                                        }
                                                        PolicyMode::Regex => {
                                                            regex_normal_verifier.clone().unwrap()
                                                        }
                                                    },
                                                ),
                                                *ip,
                                                &proof,
                                                (r.batch_start, r.batch_end),
                                                queue_lock.clone(),
                                            );
                                        }
                                        println!(
                                            "sync verify takes {} in total",
                                            timer.elapsed().as_millis()
                                        );
                                    }
                                    IpAddr::V6(_) => todo!(),
                                }
                            }
                            HttpServerMode::Async(packet_state_dict_pair, blocklist_pair) => {
                                middlebox_verify_amortized_async(
                                    packet_state_dict_pair.clone(),
                                    comm_dict_lock2.clone(),
                                    blocklist_pair.clone(),
                                    *ip,
                                    &proof,
                                    &policy_mode,
                                    match policy_mode {
                                        PolicyMode::DnsBlocklist => normal_processes_verifier.clone(),
                                        PolicyMode::Regex => todo!()
                                    },
                                    (r.batch_start, r.batch_end),
                                    &protocol_copy,
                                    pretend_mode.clone(),
                                    pid
                                );
                            }
                        }
                        warn!(
                            "Batch verify {} proofs takes {} ms, {}-{}",
                            r.batch_end - r.batch_start + 1,
                            t1.elapsed().as_millis(),
                            r.batch_start,
                            r.batch_end
                        );
                    }
                    info!("End of chunk takes {} ms", t2.elapsed().as_millis());
                }
                // info!("End of loop");
            }
        });
    }

    let idx_lock: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

    server.post("/amortized_proof", middleware! { |request|
        warn!("Received amortized proof");
        let t1 = Instant::now();
        let r = request.json_as::<AmortizedRequest>().unwrap();
        warn!("Enter amortized_proof {} {}-{}", r.batch_end - r.batch_start + 1, r.batch_start, r.batch_end);
        let lock = &*filter_states_tx_list_lock;
        let filter_states_tx_list = lock.lock().unwrap();
        let lock = &*idx_lock;
        let mut idx = lock.lock().unwrap();
        let my_idx = *idx;
        filter_states_tx_list[my_idx % filter_states_tx_list.len()].send((r, request.origin.remote_addr.ip(), t1));
        *idx += 1;
        "ok"
    });

    let precomp_verifier = get_precomp_verifier(&protocol, &cipher);
    let (tx, rx): (
        Sender<(PrecompRequest, IpAddr)>,
        Receiver<(PrecompRequest, IpAddr)>,
    ) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));

    thread::spawn(move || loop {
        let (r, ip): (PrecompRequest, IpAddr) = rx.recv().unwrap();
        let t = Instant::now();
        let mut witnesses = Vec::new();
        for idx in 0..r.comm_list.len() {
            witnesses.push(PrecompDotChaChaVerifierWitness {
                comm: r.comm_list[idx].clone(),
                SN: r.seq_num_list[idx],
                ret: r.pad_comm_list[idx].clone(),
            })
        }
        let proof = decode_hex(&r.r1cs_proof).unwrap();
        let proof: SpartanProof = bincode::deserialize(&proof).unwrap();

        println!("before precomp verify");
        if precomp_verifier.verify(&proof, &witnesses) {
            let mut pad_comm_dict = pad_comm_dict_lock2.lock().unwrap();
            let mut m = pad_comm_dict
                .entry(ip)
                .or_insert(Arc::new(Mutex::new(HashMap::new())))
                .lock()
                .unwrap();
            for w in witnesses {
                m.insert(w.SN, w.ret);
            }
            info!(
                "Verify Precomp takes {} ms, batch size {}",
                t.elapsed().as_millis(),
                r.comm_list.len()
            )
        } else {
            println!("precomp pad proof is incorrect!");
        }
    });

    server.post(
        "/precompute_proof",
        middleware! { |request|
            let r = request.json_as::<PrecompRequest>().unwrap();
            let ip = request.origin.remote_addr.ip();
            tx.lock().unwrap().send((r, ip)).expect("Rx should be good here");
            "ok"
        },
    );

    server.listen("0.0.0.0:8080").unwrap();
}

pub fn get_syncthetic_proof(
    batch_size: usize,
) -> (SpartanProof, Vec<AmortizedVerifierWitness<255>>) {
    let t1 = Instant::now();
    let dot_chacha_amortized_prover_witness = AmortizedProverWitness::<255> {
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134"
            .to_string(),
        SN: 1,
        dns_ct: vec![
            209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97,
            168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164,
            244, 86, 56, 4, 1, 92, 218, 104, 185,
        ],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692"
            .to_string(),
        key: vec![
            25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187,
            173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158,
        ],
        nonce: vec![222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161],
        left_domain_name: "moc.elpoepyxes.".chars().map(|c| c as u8).collect(),
        right_domain_name: "moc.elppacitoxe.".chars().map(|c| c as u8).collect(),
        left_index: 7,
        right_index: 9,
        left_path_array: vec![
            "1752129289157004846513364561035016959483567890799881965360261832269306118159",
            "5213947047904663182855168970299786258303520625485597599616726408396954592357",
            "4678654874247556106212070218407996724004768492975815783984666471771925610899",
            "6336962835497945360065827906694881015522159855505317143357147839892804953700",
            "3523222539937572237100155550629646599408540366300808242286182584478492907317",
            "854341270139830926623584190118162891363166235422882513305577057329067067730",
            "1155071630969204158629655404356963894097277727349596471673303080128212611008",
            "1101034354473216551382867399671639371742948873992440223181044851915028528187",
            "3671015490920580048837962862614506805436352270750717168705471947641608581763",
            "2916439049174176672988459502690028312502890869375463170061042136368105278383",
            "4902657669876404755160600927691245732335010579181492567064072369970254951943",
            "1291982324028367648857921827583320951626262620909453384576679149185114442171",
            "5590835449981926938360572745376509795530579163827580797571516465934968148185",
            "891545073237170511742591588133687396077072403024370654505408573352481184802",
            "458109328395050672473423391643539330979992982208543352845130781744812522502",
            "655884264879651899644983860630469243345443908940594634672283090102063236425",
            "2839092813370586975090752156408730624247809158862672281446335443807891333395",
            "5425169782538910714092423632218831094890099464960756551344981699594055460447",
            "2326252787767864222978752870209848689412849751880836738068297509804573644232",
            "2926199112255787778707184107940826811888856500774718781576137388347946365290",
            "5862428253581911978164236873998992598944144594277149928428395602902613123842",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        right_path_array: vec![
            "4029907311593792750484498435368156719160829193890227244100835352776679360047",
            "1047467952388836899138722578366330326649405090875887618128479192405646602243",
            "6895007323553775386387855880832878063946281581456959574788271261206193783665",
            "6336962835497945360065827906694881015522159855505317143357147839892804953700",
            "3523222539937572237100155550629646599408540366300808242286182584478492907317",
            "854341270139830926623584190118162891363166235422882513305577057329067067730",
            "1155071630969204158629655404356963894097277727349596471673303080128212611008",
            "1101034354473216551382867399671639371742948873992440223181044851915028528187",
            "3671015490920580048837962862614506805436352270750717168705471947641608581763",
            "2916439049174176672988459502690028312502890869375463170061042136368105278383",
            "4902657669876404755160600927691245732335010579181492567064072369970254951943",
            "1291982324028367648857921827583320951626262620909453384576679149185114442171",
            "5590835449981926938360572745376509795530579163827580797571516465934968148185",
            "891545073237170511742591588133687396077072403024370654505408573352481184802",
            "458109328395050672473423391643539330979992982208543352845130781744812522502",
            "655884264879651899644983860630469243345443908940594634672283090102063236425",
            "2839092813370586975090752156408730624247809158862672281446335443807891333395",
            "5425169782538910714092423632218831094890099464960756551344981699594055460447",
            "2326252787767864222978752870209848689412849751880836738068297509804573644232",
            "2926199112255787778707184107940826811888856500774718781576137388347946365290",
            "5862428253581911978164236873998992598944144594277149928428395602902613123842",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        left_dir: 797851,
        right_dir: 797852,
    };
    let prover_witnesses = vec![dot_chacha_amortized_prover_witness; batch_size];
    let dot_chacha_amortized_verifier_witness = AmortizedVerifierWitness::<255> {
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134"
            .to_string(),
        SN: 1,
        dns_ct: vec![
            209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97,
            168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164,
            244, 86, 56, 4, 1, 92, 218, 104, 185,
        ],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692"
            .to_string(),
    };
    let verifier_witnesses = vec![dot_chacha_amortized_verifier_witness; batch_size];

    let circuit = "DotChaChaAmortized";
    let inst_path = CString::new(format!("/mydata/{}_inst", circuit))
        .expect("failed")
        .into_raw();
    let gens_path = CString::new(format!("/mydata/{}_gens", circuit))
        .expect("failed")
        .into_raw();
    let term_arr_path = CString::new(format!("/mydata/{}_term_arr", circuit))
        .expect("failed")
        .into_raw();
    let input_idxes_path = CString::new(format!("/mydata/{}_input_idxes", circuit))
        .expect("failed")
        .into_raw();
    let var_idxes_path = CString::new(format!("/mydata/{}_var_idxes", circuit))
        .expect("failed")
        .into_raw();
    let prover = zkmb_get_prover(
        inst_path,
        gens_path,
        term_arr_path,
        input_idxes_path,
        var_idxes_path,
    );
    let prover = unsafe { &mut *prover };
    // let proof = prover.prove(prover_witnesses);
    let proof = read_from_path(&format!("batch_{}_proof", batch_size));
    info!("Get synthetic proof takes {}", t1.elapsed().as_millis());
    (proof, verifier_witnesses)
}

pub fn get_syncthetic_regex_proof(
    batch_size: usize,
) -> (SpartanProof, Vec<RegexAmortizedVerifierWitness<1000>>) {
    let t1 = Instant::now();
    let prover_witnesses = vec![RegexAmortizedProverWitness::<1000>::default(); batch_size];
    let verifier_witnesses = vec![RegexAmortizedVerifierWitness::<1000>::default(); batch_size];

    let circuit = "RegexChaChaAmortized";
    let inst_path = CString::new(format!("/mydata/{}_inst", circuit))
        .expect("failed")
        .into_raw();
    let gens_path = CString::new(format!("/mydata/{}_gens", circuit))
        .expect("failed")
        .into_raw();
    let term_arr_path = CString::new(format!("/mydata/{}_term_arr", circuit))
        .expect("failed")
        .into_raw();
    let input_idxes_path = CString::new(format!("/mydata/{}_input_idxes", circuit))
        .expect("failed")
        .into_raw();
    let var_idxes_path = CString::new(format!("/mydata/{}_var_idxes", circuit))
        .expect("failed")
        .into_raw();
    let prover = zkmb_get_prover(
        inst_path,
        gens_path,
        term_arr_path,
        input_idxes_path,
        var_idxes_path,
    );
    let prover = unsafe { &mut *prover };
    // let proof = prover.prove(prover_witnesses);
    // let data = bincode::serialize(&proof).unwrap();
    // fs::write(&format!("batch_{}_regex_proof", batch_size), data).expect(&format!("Unable to write data"));
    let proof = read_from_path(&format!("batch_{}_regex_proof", batch_size));
    info!("Get synthetic proof takes {}", t1.elapsed().as_millis());
    (proof, verifier_witnesses)
}

pub fn batch_benchmark(batch_size: usize, num_clients: usize) {
    let (proof, verifier_witnesses) = get_syncthetic_proof(batch_size);
    let proof = Arc::new(proof);
    let normal_verifier = get_normal_amortized_processes_verifier(&"Dot".to_string(), &"ChaCha".to_string());
    let verifier_witnesses = Arc::new(verifier_witnesses);

    let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel();
    let tx_lock = Arc::new(Mutex::new(tx));

    let handle = thread::spawn(move || {
        loop {
            let mut cnt = 0;
            // let chunk_size = (16 / batch_size) + 1;
            loop {
                match rx.try_recv() {
                    Ok(_) => cnt += 1,
                    Err(_) => break,
                }
            }
            let arr = vec![0; cnt];
            for chunk in arr.chunks(16) {
                let mut verify_handles = Vec::new();
                let t0 = Instant::now();
                for _ in chunk {
                    let proof = proof.clone();
                    let verifier_witnesses = verifier_witnesses.clone();
                    let normal_verifier = normal_verifier.clone();
                    let t1 = Instant::now();
                    let verify_handle = thread::spawn(move || {
                        // normal_verifier.verify(&proof, &verifier_witnesses);
                        info!("Normal verifier takes {}", t1.elapsed().as_millis());
                        warn!("Batch verify finish {}", batch_size);
                    });
                    verify_handles.push(verify_handle);
                }
                for verify_handle in verify_handles {
                    verify_handle.join();
                }
                info!("Chunk verifier takes {}", t0.elapsed().as_millis());
            }
        }
    });

    let mut handles = Vec::new();
    for idx in 0..num_clients {
        let tx_lock = tx_lock.clone();
        let handle2 = thread::spawn(move || {
            let avg_interval = (batch_size as f64) / 32.0;
            let mut rng = rand::thread_rng();
            let exp_dist = Exp::new(1.0 / avg_interval).unwrap();
            loop {
                let interval = exp_dist.sample(&mut rng);
                info!("Will sleep {} secs", interval);
                sleep(Duration::from_secs_f64(interval));
                let tx = tx_lock.lock().unwrap();
                tx.send(0);
                info!("{idx} Batch prove send {batch_size}");
            }
        });
        handles.push(handle2);
    }

    handle.join();
    for handle in handles {
        handle.join();
    }
}