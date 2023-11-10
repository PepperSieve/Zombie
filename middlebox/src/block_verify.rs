use crate::nickel;
use crate::packet_parse;
use crate::packet_parse::{FilterState, SuspiciousTraffic, VerifyMaterial};
use circ_zkmb::{decode_hex, DotChaChaAmortizedPublicWitness, SpartanProof, SpartanVerifier};
use dns_parser::Packet;
use nfq::{Message, Queue, Verdict};
use nickel::{HttpRouter, JsonBody, Nickel};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

type CondPair<T> = Arc<(Mutex<T>, Condvar)>;

pub fn netfilter_block(
    packet_state_dict_pair: CondPair<HashMap<IpAddr, FilterState>>,
    should_forward_async: bool
) -> std::io::Result<()> {
    // TODO: the nfq library can only process the next when last msg has been processed, so we have to block on current msg
    let mut queue = Queue::open()?;
    queue.bind(1)?;
    let mut sn_dict = HashMap::<IpAddr, usize>::new();
    let mut packet_handler = packet_parse::PacketHandler::new();
    loop {
        let mut msg = queue.recv()?;
        let mut verdict = Verdict::Accept;
        for traffic in packet_handler.handle_message(&msg) {
            println!("get event");
            match traffic.event {
                packet_parse::SuspiciousEvent::DNS(query) => {
                    // if let Ok(packet) = Packet::parse(&query) {
                    //     let questions = packet.questions;
                    //     for q in questions {
                    //         let name = q.qname.to_string();
                    //         println!("dns name {}", name);
                    //         let timer = Instant::now();
                    //         println!("blocklist check time {}", timer.elapsed().as_micros());
                    //     }
                    // }
                }
                packet_parse::SuspiciousEvent::DoTApplicationData(client_ciphertext, sn) => {
                    let (lock, cvar) = &*packet_state_dict_pair;
                    let mut packet_state_dict = lock.lock().unwrap();
                    packet_state_dict.insert(
                        traffic.source,
                        FilterState::Wait(VerifyMaterial {
                            sn,
                            start: Instant::now(),
                            source: traffic.source,
                            payload: client_ciphertext,
                        }),
                    );

                    if !should_forward_async {
                        while matches!(
                            packet_state_dict[&traffic.source],
                            FilterState::Wait(_)
                        ) {
                            packet_state_dict = cvar.wait(packet_state_dict).unwrap();
                        }
                        println!("wait finish");
                        match packet_state_dict[&traffic.source] {
                            FilterState::Wait(_) => panic!("state shouldn't be Wait here!"),
                            FilterState::Reject(_) => verdict = Verdict::Drop,
                            FilterState::Accept => (),
                        }
                    }
                }
                packet_parse::SuspiciousEvent::DoTServerResponse => {
                    if should_forward_async {
                        let (lock, cvar) = &*packet_state_dict_pair;
                        let mut packet_state_dict = lock.lock().unwrap();
                        while matches!(
                            packet_state_dict[&traffic.destination],
                            FilterState::Wait(_)
                        ) {
                            packet_state_dict = cvar.wait(packet_state_dict).unwrap();
                        }
                        println!("wait finish");
                        match packet_state_dict[&traffic.destination] {
                            FilterState::Wait(_) => panic!("state shouldn't be Wait here!"),
                            FilterState::Reject(_) => verdict = Verdict::Drop,
                            FilterState::Accept => (),
                        }
                    }
                }
                packet_parse::SuspiciousEvent::DoTHandshake(
                    client_hello,
                    server_hello,
                    server_hs_encrypted,
                ) => {
                    // // println!("{:?}, {:?}, {:?}", client_hello, server_hello, server_hs_encrypted);
                    // // println!("client hello");
                    // // print_hexdump(&client_hello);
                    // // println!("server hello");
                    // // print_hexdump(&server_hello);
                    // // println!("server hs encrypted");
                    // // print_hexdump(&server_hs_encrypted);
                    // let (lock, cvar) = &*handshake_dict_pair;
                    // let mut handshake_dict = lock.lock().unwrap();
                    // println!("insert source {}", traffic.destination);
                    // handshake_dict.insert(traffic.destination, ([client_hello, server_hello].concat(), server_hs_encrypted[0..server_hs_encrypted.len()-17].to_vec()));
                }
            }
        }
        println!("will set verdict {:?}", verdict);
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
    Ok(())
}

fn middlebox_verify_dot_chacha(
    packet_state_dict_pair: CondPair<HashMap<IpAddr, FilterState>>,
    comm_dict: Arc<Mutex<HashMap<IpAddr, String>>>,
    client: IpAddr,
    proof: &Vec<u8>,
    verifier: &SpartanVerifier,
) {
    let (lock, cvar) = &*packet_state_dict_pair;
    let mut packet_state_dict = lock.lock().unwrap();
    if let Some(FilterState::Wait(material)) = packet_state_dict.get(&client) {
        let material = material.clone();
        let comm_dict = comm_dict.lock().unwrap();
        if let Some(comm) = comm_dict.get(&material.source) {
            let payload = &material.payload;
            let dns_ct = payload.iter().map(|n| n.to_string()).collect();

            let witness = DotChaChaAmortizedPublicWitness {
                SN: material.sn.to_string(),
                comm: comm.to_string(),
                dns_ct,
                root:
                    "5972733345965465510373436926431083918242531555386867859948086370295902707692"
                        .to_string(),
            };
            let proof: SpartanProof = bincode::deserialize(&proof).unwrap();
            println!("witness is {:?}", witness);
            let result = verifier.verify(&proof, vec![witness]);
            if result {
                // if accept, remove it from packet state list
                println!("packet accepted");
                packet_state_dict.insert(client.clone(), FilterState::Accept);
            } else {
                // if reject, mark it to be dropped in the next round
                // TODO: change it to be blocked at once
                println!("packet dropped");
                packet_state_dict.insert(client.clone(), FilterState::Reject(material.source));
            }
            cvar.notify_all();
        } else {
            println!("commitment not found!");
        }
    } else {
        println!("packet_id not found!");
    }
}

fn read_from_path<T: DeserializeOwned>(path: &str) -> T {
    let data = fs::read(path).expect("Unable to read data");
    let result = bincode::deserialize(&data).unwrap();
    result
}

#[derive(Deserialize)]
struct DotChaChaAmortizedRequest {
    packet_id: String,
    r1cs_proof: String,
}

#[derive(Deserialize)]
struct DotChaChaCORequest {
    comm: String,
}

pub fn start_block_http_server(packet_state_dict_pair: CondPair<HashMap<IpAddr, FilterState>>) {
    let mut server = Nickel::new();
    let comm_dict_lock = Arc::new(Mutex::new(HashMap::<IpAddr, String>::new()));
    let comm_dict_lock2 = comm_dict_lock.clone();
    let inst = read_from_path("../circ/keys/chacha_amortized_inst");
    let gens = read_from_path("../circ/keys/chacha_amortized_gens");
    let input_names = read_from_path("../circ/keys/chacha_amortized_input_names");
    let verifier = SpartanVerifier::new(inst, gens, input_names);

    server.post(
        "/co_dot_chacha_proof",
        middleware! { |request|
            let r = request.json_as::<DotChaChaCORequest>().unwrap();
            let ip = request.origin.remote_addr.ip();
            let mut comm_dict = comm_dict_lock.lock().unwrap();
            comm_dict.insert(ip, r.comm);
            "ok"
        },
    );

    server.post("/dot_chacha_proof", middleware! { |request|
        let r = request.json_as::<DotChaChaAmortizedRequest>().unwrap();
        let proof = decode_hex(&r.r1cs_proof).unwrap();
        // Is the proof system still sound if we allow client to give the packet id?
        let packet_id = decode_hex(&r.packet_id).unwrap();
        middlebox_verify_dot_chacha(packet_state_dict_pair.clone(), comm_dict_lock2.clone(), request.origin.remote_addr.ip(), &proof, &verifier);
        "ok"
    });

    server.listen("0.0.0.0:8080").unwrap();
}
