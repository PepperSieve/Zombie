// #![deny(warnings)]
// #![allow(non_snake_case)]

#[macro_use]
pub mod ir;
pub mod circify;
pub mod front;
pub mod target;
pub mod util;
pub mod witnesses;

#[macro_use]
extern crate nickel;

use ark_curve25519::Fr;
use ark_ff::fields::PrimeField;
use circ_fields::{int_to_bigint, FieldT, FieldV};
use curve25519_dalek::scalar::Scalar;
use fxhash::FxHashMap;
use ir::{
    opt::{opt, Opt},
    term::{precomp::PreComp, BitVector, Computation, NumTerm, Value},
};
use itertools::Itertools;
use libspartan::{InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK, BatchedNIZK, transcript::TranscriptWrapper};
use log::info;
use merlin::Transcript;
use nickel::{HttpRouter, Nickel, JsonBody};
use rayon::prelude::*;
use rug::Integer;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Write, fs, num::ParseIntError, panic, path::{PathBuf, Path}, sync::{Arc, Mutex}, time::Instant, env, collections::HashMap};
use target::r1cs::{
    spartan::{self, get_spartan_public_assignment},
    ProverData, R1cs,
};
use util::field::DFL_T;
use witnesses::{Witness, channel_open_witness::*, amortized_witness::*, sha_round_witness::*, non_membership::*, amortized_witness::*, precomp_witness::PrecompDotChaChaProverWitness, amortized_unpack::AmortizedUnpackProverWitness, regex_witness::{RegexAmortizedProverWitness, RegexAmortizedVerifierWitness, RegexAmortizedUnpackProverWitness, RegexAmortizedUnpackVerifierWitness}, WitnessMapper, aes_witness::AESProverWitness};

#[cfg(feature = "smt")]
use crate::{
    front::{
        zsharp::{Inputs, ZSharpFE},
        FrontEnd, Mode,
    },
    ir::opt::precomp_opt,
    target::r1cs::{trans::to_r1cs, opt::reduce_linearities},
};

pub type SpartanProof = BatchedNIZK;
pub type char_pointer = *mut libc::c_char;


pub struct SpartanProver {
    pub inst: Instance,
    gens: NIZKGens,
    term_arr: Vec<NumTerm>,
    input_idxes: Vec<usize>,
    var_idxes: Vec<usize>,
    val_arr: Vec<Option<Value>>,
}

impl SpartanProver {
    fn new(
        inst: Instance,
        gens: NIZKGens,
        term_arr: Vec<NumTerm>,
        input_idxes: Vec<usize>,
        var_idxes: Vec<usize>,
    ) -> Self {
        let val_arr = vec![Option::None; term_arr.len()];
        SpartanProver {
            inst,
            gens,
            term_arr,
            input_idxes,
            var_idxes,
            val_arr,
        }
    }

    pub fn prove<T: Witness + Send + Sync>(&mut self, witness_list: Vec<T>) -> BatchedNIZK {
        let t0 = Instant::now();
        let result: Vec<(VarsAssignment, InputsAssignment)> = witness_list
            .par_iter()
            .map(|witness| {
                // let t1 = Instant::now();
                let mapper = witness.to_map();
                // let t2 = Instant::now();
                let mut val_arr = vec![Option::None; self.term_arr.len()];
                PreComp::real_eval(&mut val_arr, &self.term_arr, &mapper.input_map);
                // let t3 = Instant::now();
                let (var_assignment, input_assignment) =
                    spartan::get_spartan_assignment(&self.input_idxes, &self.var_idxes, &val_arr);
                // let t4 = Instant::now();
                // let result = self
                //     .inst
                //     .is_sat(&var_assignment, &input_assignment)
                //     .unwrap();
                // println!("is proof satisfiable? {}", result);
                // println!("map {}", t2.duration_since(t1).as_millis());
                // println!("eval {}", t3.duration_since(t2).as_millis());
                // println!("transform {}", t4.duration_since(t3).as_millis());
                (var_assignment, input_assignment)
            })
            .collect();
        // let t5 = Instant::now();
        let vars_list = result.iter().map(|tuple| tuple.0.clone()).collect_vec();
        let inputs_list = result.iter().map(|tuple| tuple.1.clone()).collect_vec();
        let mut prover_transcript = Transcript::new(b"zkmb_proof");
        let proof = BatchedNIZK::batched_prove(
            &self.inst,
            vars_list,
            inputs_list,
            &self.gens,
            TranscriptWrapper { trans: prover_transcript },
        );
        // let t6 = Instant::now();
        // println!("prepare {}", t5.duration_since(t0).as_millis());
        // println!("prove {}", t6.duration_since(t5).as_millis());

        // let result = panic::catch_unwind(|| {
        //     let mut transcript = Transcript::new(b"zkmb_proof");
        //     proof
        //         .verify(&self.inst, &inputs_list, &mut transcript, &self.gens)
        //         .unwrap();
        // });
        // println!("is ok {}", result.is_ok());
        proof
    }

    pub fn solve<T: Witness + Send + Sync>(&mut self, witness_list: Vec<T>, input_names: Vec<String>) {
        let _: Vec<(VarsAssignment, InputsAssignment)> = witness_list
            .par_iter()
            .map(|witness| {
                let mapper = witness.to_map();
                let mut val_arr = vec![Option::None; self.term_arr.len()];
                PreComp::real_eval(&mut val_arr, &self.term_arr, &mapper.input_map);
                let (var_assignment, input_assignment) =
                    spartan::get_spartan_assignment(&self.input_idxes, &self.var_idxes, &val_arr);
                for idx in 0..input_names.len() {
                    println!("{}: {:?}", input_names[idx], input_assignment.assignment[idx]);
                }
                (var_assignment, input_assignment)
            })
            .collect();
    }
}

#[derive(Clone)]
pub struct SpartanProcessesVerifier {
    inst: Instance,
    gens: NIZKGens,
    input_names: Vec<String>,
    socket_idx: Arc<Mutex<usize>>,
    num_processes: usize
}

pub unsafe fn fork<F: FnOnce()>(child_func: F) -> libc::pid_t {
    match libc::fork() {
        -1 => panic!("Fork failed"),
        0 => {
            // child process will terminate after child_func
            child_func();
            libc::exit(0);
        },
        pid => pid,
    }
}

#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    proof: BatchedNIZK,
    witnesses: Vec<AmortizedVerifierWitness<255>>
}

#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    res: bool
}

impl SpartanProcessesVerifier {
    pub fn new(inst: Instance, gens: NIZKGens, input_names: Vec<String>, num_processes: usize) -> Self {
        let mut core_ids = core_affinity::get_core_ids().unwrap();
        for idx in 0..num_processes {
            let core_id = core_ids.pop().unwrap();
            let child_pid = unsafe {
                let inst = inst.clone();
                let gens = gens.clone();
                let input_names = input_names.clone();
                fork(|| {
                    // core_affinity::set_for_current(core_id);
                    let mut server = Nickel::new();
                    // let mut interval_timer = Arc::new(Mutex::new(Instant::now()));
    
                    server.post(
                        "/verify",
                        middleware! { |request|
                            // let mut lock = interval_timer.lock().unwrap();
                            // let t = &*lock;
                            // info!("interval takes {} ms", t.elapsed().as_millis());
                            let timer = Instant::now();
                            let r = request.json_as::<VerifyRequest>().unwrap();
                            // println!("received request");
                            let mut inputs_list = Vec::new();
                            for witness in r.witnesses {
                                let input_assignment =
                                    get_spartan_public_assignment(&input_names, &witness.to_map().input_map);
                                inputs_list.push(input_assignment);
                            }
                            let transcript = Transcript::new(b"zkmb_proof");
                            // println!("will verify");
                            let res = r.proof.batched_verify(&inst, inputs_list, TranscriptWrapper { trans: transcript } , &gens);
                            let json = serde_json::to_string(&VerifyResponse {res}).unwrap();
                            // info!("process {} verified result takes {} ms", idx, timer.elapsed().as_millis());
                            // *lock = Instant::now();
                            json
                        },
                    );
                
                    server.listen(format!("localhost:{}", 10000 + idx)).unwrap();
                })
            };
        }

        let socket_idx = Arc::new(Mutex::new(0));

        SpartanProcessesVerifier {
            inst,
            gens,
            input_names,
            socket_idx,
            num_processes
        }
    }

    pub fn verify(&self, proof: &BatchedNIZK, witness_list: &Vec<AmortizedVerifierWitness<255>>, idx: usize) -> bool {
        // let mut lock = self.socket_idx.lock().unwrap();
        // let socket_idx = *lock;
        // *lock = (*lock + 1) % self.num_processes;
        // drop(lock);
        let request = VerifyRequest {
            proof: proof.clone(),
            witnesses: witness_list.clone(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let response = ureq::post(&format!("http://localhost:{}/verify", 10000 + idx))
            .send_string(&json).unwrap()
            .into_string().unwrap();
        let response: VerifyResponse = serde_json::from_str(&response).unwrap();
        response.res
    }
}

#[derive(Clone)]
pub struct SpartanVerifier {
    inst: Instance,
    gens: NIZKGens,
    input_names: Vec<String>,
}

impl SpartanVerifier {
    pub fn new(inst: Instance, gens: NIZKGens, input_names: Vec<String>) -> Self {
        SpartanVerifier {
            inst,
            gens,
            input_names,
        }
    }

    pub fn verify<T: Witness>(&self, proof: &BatchedNIZK, witness_list: &Vec<T>) -> bool {
        let mut inputs_list = Vec::new();
        for witness in witness_list {
            let input_assignment =
                get_spartan_public_assignment(&self.input_names, &witness.to_map().input_map);
            inputs_list.push(input_assignment);
        }
        let transcript = Transcript::new(b"zkmb_proof");
        // let timer = Instant::now();
        let res = proof.batched_verify(&self.inst, inputs_list, TranscriptWrapper { trans: transcript } , &self.gens);
        // println!("Timer takes {}", timer.elapsed().as_millis());
        res
    }

    pub fn verify_test<T: Witness>(&self, proof: &BatchedNIZK, witness_list: &Vec<T>) {
        let timer = Instant::now();
        let mut inputs_list = Vec::new();
        for witness in witness_list {
            let input_assignment =
                get_spartan_public_assignment(&self.input_names, &witness.to_map().input_map);
            inputs_list.push(input_assignment);
        }
        // println!("Get inputs list take {}", timer.elapsed().as_micros());
        let transcript = Transcript::new(b"zkmb_proof");
        proof.batched_verify_test(&self.inst, inputs_list, TranscriptWrapper { trans: transcript } , &self.gens);

        // let timer = Instant::now();
        // // for idx in 0..16 {
        // //     let zero = Scalar::zero();
        // //     let mut evals: Vec<Scalar> = vec![zero; 131072];
        // //     println!("{} takes {} microseconds", idx, timer.elapsed().as_micros());
        // // }
        // let zero = Scalar::zero();
        // let mut evals: Vec<Scalar> = vec![zero; 131072];
        // println!("it takes {} microseconds", timer.elapsed().as_micros());
    }
}

fn default_opt(cs: Computation) -> Computation {
    return opt(
        cs,
        vec![
            Opt::ScalarizeVars,
            Opt::Flatten,
            // Opt::Sha,
            Opt::ConstantFold(Box::new([])),
            Opt::Flatten,
            Opt::Inline,
            // Tuples must be eliminated before oblivious array elim
            Opt::Tuple,
            Opt::ConstantFold(Box::new([])),
            Opt::Obliv,
            // The obliv elim pass produces more tuples, that must be eliminated
            Opt::Tuple,
            Opt::LinearScan,
            // The linear scan pass produces more tuples, that must be eliminated
            Opt::Tuple,
            Opt::Flatten,
            Opt::ConstantFold(Box::new([])),
            Opt::Inline,
        ],
    );
}

fn write_to_path<T: Serialize>(path: *mut libc::c_char, v: T) {
    let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
    let path: &str = path.to_str().unwrap();
    let data = bincode::serialize(&v).unwrap();
    fs::write(path, data).expect(&format!("Unable to write data {}", path));
}

fn read_from_path<T: DeserializeOwned>(path: *mut libc::c_char) -> T {
    let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
    let path: &str = path.to_str().unwrap();
    let data = fs::read(path).expect(&format!("Unable to read data {}", path));
    let result = bincode::deserialize(&data).unwrap();
    result
}

fn parse_c_str(cstr: *mut libc::c_char) -> String {
    let result: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(cstr) };
    let result: &str = result.to_str().unwrap();
    result.to_string()
}

#[cfg(feature = "smt")]
fn generate_keys(
    inputs: Inputs,
    inst_path: char_pointer,
    gens_path: char_pointer,
    input_names_path: char_pointer,
    term_arr_path: char_pointer,
    input_idxes_path: char_pointer,
    var_idxes_path: char_pointer,
) {
    println!("start generate");
    let timer = Instant::now();
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let (r1cs, prover_data, _) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    println!("r1cs cons before reduce linearity {}", r1cs.constraints().len());
    let r1cs = reduce_linearities(r1cs, Some(50));
    let precomp = precomp_opt(
        prover_data.precompute,
        vec![Opt::ConstantFold(Box::new([])), Opt::Obliv, Opt::Tuple],
    );
    println!("r1cs cons after reduce linearity {}", r1cs.constraints().len());
    let (term_arr, input_idxes, var_idxes) = precomp.eval_preprocess(&r1cs);
    let inst = spartan::get_spartan_instance(&r1cs);
    let input_num = r1cs.public_idxs.len();
    let var_num = r1cs.idxs_signals.len() - input_num;
    println!("Num Variables {}", r1cs.idxs_signals.len());
    println!("inst {}", inst.inst.get_num_cons());
    let gens = NIZKGens::new(r1cs.constraints().len(), var_num, input_num);
    write_to_path(inst_path, inst);
    write_to_path(gens_path, gens);
    let mut input_names = Vec::new();
    for (cid, name) in r1cs.idxs_signals.iter().sorted() {
        if r1cs.public_idxs.contains(&cid) {
            // TODO: very hacky way
            // var name is like dns_ct.214_n152
            // but if dns_nt.214_n152, it won't work
            let v = name.match_indices("_n").collect::<Vec<_>>().len();
            if v != 1 {
                panic!("this function assumes there's exactly one _n in variable name, but there's {} _n in the name", v);
            }
            let splits = name.split("_n");
            let splits: Vec<&str> = splits.collect();
            let name = splits[0].to_string();
            input_names.push(name);
        }
    }
    // tmp code
    // println!("input names {:?}", input_names);
    write_to_path(input_names_path, input_names);
    write_to_path(term_arr_path, term_arr);
    write_to_path(input_idxes_path, input_idxes);
    write_to_path(var_idxes_path, var_idxes);
}

fn get_prover(
    inst_path: char_pointer,
    gens_path: char_pointer,
    term_arr_path: char_pointer,
    input_idxes_path: char_pointer,
    var_idxes_path: char_pointer,
) -> *mut SpartanProver {
    let timer = Instant::now();
    let inst = read_from_path(inst_path);
    let gens = read_from_path(gens_path);
    let term_arr = read_from_path(term_arr_path);
    let input_idxes = read_from_path(input_idxes_path);
    let var_idxes = read_from_path(var_idxes_path);
    println!("get prover time {}", timer.elapsed().as_micros());
    Box::into_raw(Box::new(SpartanProver::new(
        inst,
        gens,
        term_arr,
        input_idxes,
        var_idxes,
    )))
}

fn get_verifier(
    inst_path: *mut libc::c_char,
    gens_path: *mut libc::c_char,
    input_names_path: *mut libc::c_char,
) -> *const SpartanVerifier {
    let inst = read_from_path(inst_path);
    let gens = read_from_path(gens_path);
    let input_names = read_from_path(input_names_path);
    Box::into_raw(Box::new(SpartanVerifier::new(inst, gens, input_names)))
}

fn get_verifier_normal(
    inst_path: *mut libc::c_char,
    gens_path: *mut libc::c_char,
    input_names_path: *mut libc::c_char,
) -> SpartanVerifier {
    let inst = read_from_path(inst_path);
    let gens = read_from_path(gens_path);
    let input_names = read_from_path(input_names_path);
    SpartanVerifier::new(inst, gens, input_names)
}

fn verify_proof<T>(
    verifier: *const SpartanVerifier,
    witness_list: *mut libc::c_char,
    proof: *mut libc::c_char,
) -> bool
where
    T: Witness + 'static,
    T: DeserializeOwned,
{
    let verifier = unsafe { &*verifier };
    let witness_list = parse_c_str(witness_list);
    let proof = parse_c_str(proof);
    let proof: BatchedNIZK = bincode::deserialize_from(decode_hex(&proof).unwrap().as_slice()).unwrap();
    let witness_list: Vec<T> = serde_json::from_str(&witness_list).unwrap();
    verifier.verify(&proof, &witness_list)
}

fn generate_proof<T>(
    prover: *mut SpartanProver,
    witness_list: *mut libc::c_char,
    proof_path: *mut libc::c_char,
) where
    T: Witness + 'static + Send + Sync,
    T: DeserializeOwned,
{
    let prover = unsafe { &mut *prover };
    let my_witness_list = parse_c_str(witness_list);
    let witness_list: Vec<T> = serde_json::from_str(&my_witness_list).unwrap();
    let proof = prover.prove(witness_list);
    write_to_path(proof_path, proof);
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(feature = "smt")]
#[no_mangle]
pub extern "C" fn zkmb_generate_keys(
    file_path: char_pointer, 
    inst_path: char_pointer,
    gens_path: char_pointer,
    input_names_path: char_pointer,
    term_arr_path: char_pointer,
    input_idxes_path: char_pointer,
    var_idxes_path: char_pointer,) {
        let file_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(file_path) };
        let file_path: &str = file_path.to_str().unwrap();
        let inputs = Inputs {
            file: PathBuf::from(file_path),
            mode: Mode::Proof,
            isolate_asserts: true,
        };
        generate_keys(
            inputs,
            inst_path,
            gens_path,
            input_names_path,
            term_arr_path,
            input_idxes_path,
            var_idxes_path,
        );
}

#[cfg(not(feature = "smt"))]
#[no_mangle]
pub extern "C" fn zkmb_generate_keys(
    file_path: char_pointer, 
    inst_path: char_pointer,
    gens_path: char_pointer,
    input_names_path: char_pointer,
    term_arr_path: char_pointer,
    input_idxes_path: char_pointer,
    var_idxes_path: char_pointer,) {
        println!("smt is not enabled, so zkmb_generate_keys does nothing");
}

#[no_mangle]
pub extern "C" fn zkmb_get_prover(
    inst_path: char_pointer,
    gens_path: char_pointer,
    term_arr_path: char_pointer,
    input_idxes_path: char_pointer,
    var_idxes_path: char_pointer) -> *mut SpartanProver {
        get_prover(
            inst_path,
            gens_path,
            term_arr_path,
            input_idxes_path,
            var_idxes_path,
        )
}

#[no_mangle]
pub extern "C" fn zkmb_prove(
    circuit: *mut libc::c_char,
    prover: *mut SpartanProver,
    witness_list: *mut libc::c_char,
    proof_path: *mut libc::c_char,
) {
    let circuit: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(circuit) };
    let circuit: &str = circuit.to_str().unwrap();
    match circuit {
        "DotChaChaAmortized" => {
            generate_proof::<AmortizedProverWitness::<255>>(prover, witness_list, proof_path)
        },
        "DohChaChaAmortized" => {
            generate_proof::<AmortizedProverWitness::<500>>(prover, witness_list, proof_path)
        },
        "DohAESAmortized" => {
            generate_proof::<AmortizedProverWitness::<500>>(prover, witness_list, proof_path)
        },
        "ChaChaChannelOpen" => {
            generate_proof::<ChannelOpenProverWitness>(prover, witness_list, proof_path)
        },
        "AESChannelOpen" => {
            generate_proof::<ChannelOpenProverWitness>(prover, witness_list, proof_path)
        },
        "ShaRound" => {
            generate_proof::<ShaRoundProverWitness>(prover, witness_list, proof_path)
        },
        "PrecompDotChaCha" => {
            generate_proof::<PrecompDotChaChaProverWitness>(prover, witness_list, proof_path)
        },
        "DotChaChaAmortizedUnpack" => {
            generate_proof::<AmortizedUnpackProverWitness::<255>>(prover, witness_list, proof_path)
        },
        "RegexChaChaAmortized" => {
            generate_proof::<RegexAmortizedProverWitness::<1000>>(prover, witness_list, proof_path)
        },
        "RegexChaChaAmortizedUnpack" => {
            generate_proof::<RegexAmortizedUnpackProverWitness::<1000>>(prover, witness_list, proof_path)
        },
        _ => unimplemented!()
    }
}

#[no_mangle]
pub extern "C" fn zkmb_get_verifier(
    inst_path: *mut libc::c_char,
    gens_path: *mut libc::c_char,
    input_names_path: *mut libc::c_char,
) -> *const SpartanVerifier {
    get_verifier(inst_path, gens_path, input_names_path)
}

#[no_mangle]
pub extern "C" fn zkmb_verify(
    circuit: *mut libc::c_char,
    verifier: *const SpartanVerifier,
    witness_list: *mut libc::c_char,
    proof: *mut libc::c_char,
) -> bool {
    let circuit: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(circuit) };
    let circuit: &str = circuit.to_str().unwrap();
    match circuit {
        "DotChaChaAmortized" => {
            verify_proof::<AmortizedVerifierWitness<255>>(verifier, witness_list, proof)
        },
        "DohChaChaAmortized" => {
            verify_proof::<AmortizedVerifierWitness<500>>(verifier, witness_list, proof)
        },
        "DohAESAmortized" => {
            verify_proof::<AmortizedVerifierWitness<500>>(verifier, witness_list, proof)
        },
        "ChaChaChannelOpen" => {
            verify_proof::<ChannelOpenVerifierWitness>(verifier, witness_list, proof)
        },
        "AESChannelOpen" => {
            verify_proof::<ChannelOpenVerifierWitness>(verifier, witness_list, proof)
        },
        "ShaRound" => {
            verify_proof::<ShaRoundProverWitness>(verifier, witness_list, proof)
        },
        "RegexChaChaAmortized" => {
            verify_proof::<RegexAmortizedVerifierWitness::<1000>>(verifier, witness_list, proof)
        },
        "RegexChaChaAmortizedUnpack" => {
            verify_proof::<RegexAmortizedUnpackVerifierWitness::<1000>>(verifier, witness_list, proof)
        },
        _ => unimplemented!()
    }
}

use std::{ffi::CString, thread};

fn spartan_benchmark<T: Witness + Send + Sync + Clone, T2: Witness + Send + Sync + Clone + 'static>(circuit: &str, prover_witness: T, verifier_witness: T2) {
    let inst_path = CString::new(format!("./keys/{}_inst", circuit)).expect("failed").into_raw();
    let gens_path = CString::new(format!("./keys/{}_gens", circuit)).expect("failed").into_raw(); 
    let input_names_path = CString::new(format!("./keys/{}_input_names", circuit)).expect("failed").into_raw();
    let term_arr_path = CString::new(format!("./keys/{}_term_arr", circuit)).expect("failed").into_raw();
    let input_idxes_path = CString::new(format!("./keys/{}_input_idxes", circuit)).expect("failed").into_raw();
    let var_idxes_path = CString::new(format!("./keys/{}_var_idxes", circuit)).expect("failed").into_raw();
    let file_path = CString::new(format!("./zkmb/{}.zok", circuit)).expect("failed").into_raw();
    // let witness_list = fs::read_to_string("./tmp/witness.json").expect("read string fail");
    // let witness_list = CString::new(witness_list).expect("failed").into_raw();
    // let proof_path = CString::new("./tmp/proof").expect("fail").into_raw();
    // let circuit_cstr = CString::new("DotChaChaAmortized").expect("fail").into_raw();
    // zkmb_generate_keys(file_path, inst_path, gens_path, input_names_path, term_arr_path, input_idxes_path, var_idxes_path);
    for batch_size in [1] {
        let timer = Instant::now();
        let proof_name = format!("test_{}.proof", batch_size);
        let file_path = Path::new(&proof_name);
        if !file_path.exists() {
            let prover = zkmb_get_prover(inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path);
            let prover = unsafe { &mut *prover };
            println!("\n{} circuit constraints cons {} inputs {} vars {}", circuit, prover.inst.inst.get_num_cons(), prover.inst.inst.get_num_inputs(), prover.inst.inst.get_num_vars());
            let proof = prover.prove(vec![prover_witness.clone(); batch_size]);
            write_to_path(CString::new(proof_name.clone()).expect("failed").into_raw(), proof);
        }
        // let proof = read_from_path(CString::new(proof_name).expect("failed").into_raw());
        // let proof = Arc::new(proof);
        println!("batch prove {} takes {}", batch_size, timer.elapsed().as_millis());
        let verifier = get_verifier_normal(inst_path, gens_path, input_names_path);
        // let verifier = Arc::new(verifier);

        if false {
            // let timer = Instant::now();
            // verifier.verify(&proof, &vec![verifier_witness.clone(); batch_size]);
            // println!("batch verify {} takes {}", batch_size, timer.elapsed().as_millis());
        } else {
            let args: Vec<String> = env::args().collect();
            let chunk_size = args[1].parse().unwrap();
            let repeat_times = args[2].parse().unwrap();
            let timer = Instant::now();
            let mut handles = Vec::new();
            for idx in 0..chunk_size {
                // let proof = proof.clone();
                let proof: BatchedNIZK = read_from_path(CString::new(proof_name.clone()).expect("failed").into_raw());
                let verifier_witness = verifier_witness.clone();
                let verifier = verifier.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..repeat_times {
                        verifier.verify(&proof, &vec![verifier_witness.clone(); batch_size]);
                    }
                });
                handles.push(handle);
            }
            for handle in handles {
                handle.join();
            }
            println!("batch verify {} takes {}", batch_size, timer.elapsed().as_millis());
        }
    }   
}


use rayon::prelude::{IntoParallelIterator, ParallelIterator, IntoParallelRefMutIterator};

use crate::{
    witnesses::{sha_round_witness::{ShaRoundProverWitness, ShaRoundVerifierWitness}, non_membership::{NonMembershipProverWitness, NonMembershipVerifierWitness}, aes_witness::{AESVerifierWitness}, channel_open_witness::{ChannelOpenProverWitness, ChannelOpenVerifierWitness}, amortized_witness::{AmortizedProverWitness, AmortizedVerifierWitness}, precomp_witness::{PrecompDotChaChaVerifierWitness}, amortized_unpack::{AmortizedUnpackVerifierWitness}, policy_witness::{RegexProverWitness, RegexVerifierWitness}}
};

// use this function to display the assignments of a circuit
fn solve_one_circuit<T: Witness + Send + Sync>(circuit: &str, prover_witness: Vec<T>, should_generate: bool) {
    let inst_path = CString::new(format!("./keys/{}_inst", circuit)).expect("failed").into_raw();
    let gens_path = CString::new(format!("./keys/{}_gens", circuit)).expect("failed").into_raw(); 
    let input_names_path = CString::new(format!("./keys/{}_input_names", circuit)).expect("failed").into_raw();
    let term_arr_path = CString::new(format!("./keys/{}_term_arr", circuit)).expect("failed").into_raw();
    let input_idxes_path = CString::new(format!("./keys/{}_input_idxes", circuit)).expect("failed").into_raw();
    let var_idxes_path = CString::new(format!("./keys/{}_var_idxes", circuit)).expect("failed").into_raw();
    let file_path = CString::new(format!("./zkmb/{}.zok", circuit)).expect("failed").into_raw();
    if should_generate {
        zkmb_generate_keys(file_path, inst_path, gens_path, input_names_path, term_arr_path, input_idxes_path, var_idxes_path);
    }
    let prover = zkmb_get_prover(inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path);
    let prover = unsafe { &mut *prover };
    prover.solve(prover_witness, read_from_path(input_names_path));
}

fn compile_one_circuit(circuit: &str) {
    let inst_path = CString::new(format!("./keys/{}_inst", circuit)).expect("failed").into_raw();
    let gens_path = CString::new(format!("./keys/{}_gens", circuit)).expect("failed").into_raw(); 
    let input_names_path = CString::new(format!("./keys/{}_input_names", circuit)).expect("failed").into_raw();
    let term_arr_path = CString::new(format!("./keys/{}_term_arr", circuit)).expect("failed").into_raw();
    let input_idxes_path = CString::new(format!("./keys/{}_input_idxes", circuit)).expect("failed").into_raw();
    let var_idxes_path = CString::new(format!("./keys/{}_var_idxes", circuit)).expect("failed").into_raw();
    let file_path = CString::new(format!("./zkmb/{}.zok", circuit)).expect("failed").into_raw();
    zkmb_generate_keys(file_path, inst_path, gens_path, input_names_path, term_arr_path, input_idxes_path, var_idxes_path);
}

enum BenchmarkMethod {
    Prover,
    Verifier,
    ProverAndVerifier
}

fn benchmark_one_circuit<T: Witness + Send + Sync, T2: Witness + Send + Sync>(circuit: &str, prover_witness: Vec<T>, verifier_witness: Vec<T2>, should_generate: bool, method: BenchmarkMethod) {
    println!("benchmark {}", circuit);
    let inst_path = CString::new(format!("./keys/{}_inst", circuit)).expect("failed").into_raw();
    let gens_path = CString::new(format!("./keys/{}_gens", circuit)).expect("failed").into_raw(); 
    let input_names_path = CString::new(format!("./keys/{}_input_names", circuit)).expect("failed").into_raw();
    let term_arr_path = CString::new(format!("./keys/{}_term_arr", circuit)).expect("failed").into_raw();
    let input_idxes_path = CString::new(format!("./keys/{}_input_idxes", circuit)).expect("failed").into_raw();
    let var_idxes_path = CString::new(format!("./keys/{}_var_idxes", circuit)).expect("failed").into_raw();
    let file_path = CString::new(format!("./zkmb/{}.zok", circuit)).expect("failed").into_raw();
    // let witness_list = fs::read_to_string("./tmp/witness.json").expect("read string fail");
    // let witness_list = CString::new(witness_list).expect("failed").into_raw();
    // let proof_path = CString::new("./tmp/proof").expect("fail").into_raw();
    // let circuit_cstr = CString::new("DotChaChaAmortized").expect("fail").into_raw();
    if should_generate {
        zkmb_generate_keys(file_path, inst_path, gens_path, input_names_path, term_arr_path, input_idxes_path, var_idxes_path);
    }
    match method {
        BenchmarkMethod::Prover => {
            let mut prover_parameter_size = 0;
            for path in [inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path] {
                let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
                let path: &str = path.to_str().unwrap();
                prover_parameter_size += fs::metadata(path).unwrap().len();
            }
            println!("prover parameter size {} mb", prover_parameter_size as f64 / 1000000.0);
            let prover = zkmb_get_prover(inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path);
            let prover = unsafe { &mut *prover };
            println!("{} circuit constraints cons {} inputs {} vars {}", circuit, prover.inst.inst.get_num_cons(), prover.inst.inst.get_num_inputs(), prover.inst.inst.get_num_vars());
            let timer = Instant::now();
            let proof = prover.prove(prover_witness);
            println!("prove takes {}", timer.elapsed().as_millis());
            let data = bincode::serialize(&proof).unwrap();
            println!("proof size is {} bytes", data.len());
            let path = format!("{}_proof", circuit);
            fs::write(&path, data).expect(&format!("Unable to write data {}", path));
        },
        BenchmarkMethod::Verifier => {
            let mut verifier_parameter_size = 0;
            for path in [inst_path, gens_path, input_names_path] {
                let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
                let path: &str = path.to_str().unwrap();
                verifier_parameter_size += fs::metadata(path).unwrap().len();
            }
            println!("verifier parameter size {} mb", verifier_parameter_size as f64 / 1000000.0);
            let verifier = zkmb_get_verifier(inst_path, gens_path, input_names_path);
            let verifier = unsafe { & *verifier };
            let timer = Instant::now();
            let path = format!("{}_proof", circuit);
            let data = fs::read(&path).expect(&format!("Unable to read data {}", path));
            let proof = bincode::deserialize(&data).unwrap();
            verifier.verify(&proof, &verifier_witness);
            println!("verify takes {}", timer.elapsed().as_millis());
            println!("");
        },
        BenchmarkMethod::ProverAndVerifier => {
            let mut prover_parameter_size = 0;
            for path in [inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path] {
                let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
                let path: &str = path.to_str().unwrap();
                prover_parameter_size += fs::metadata(path).unwrap().len();
            }
            println!("prover parameter size {} mb", prover_parameter_size as f64 / 1000000.0);
        
            let mut verifier_parameter_size = 0;
            for path in [inst_path, gens_path, input_names_path] {
                let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
                let path: &str = path.to_str().unwrap();
                verifier_parameter_size += fs::metadata(path).unwrap().len();
            }
            println!("verifier parameter size {} mb", verifier_parameter_size as f64 / 1000000.0);
        
            let prover = zkmb_get_prover(inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path);
            let prover = unsafe { &mut *prover };
            println!("{} circuit constraints cons {} inputs {} vars {}", circuit, prover.inst.inst.get_num_cons(), prover.inst.inst.get_num_inputs(), prover.inst.inst.get_num_vars());
            let timer = Instant::now();
            let proof = prover.prove(prover_witness);
            println!("prove takes {}", timer.elapsed().as_millis());
            let data = bincode::serialize(&proof).unwrap();
            println!("proof size is {} bytes", data.len());
        
            let verifier = zkmb_get_verifier(inst_path, gens_path, input_names_path);
            let verifier = unsafe { & *verifier };
            let timer = Instant::now();
            verifier.verify(&proof, &verifier_witness);
            println!("verify takes {}", timer.elapsed().as_millis());
            println!("");
        },
    }
}

fn zk_test() {
    let aes_prover_witness = AESProverWitness {
        key: vec![0; 16],
        iv: vec![0; 12],
        ct: vec![0; 160],
    };
    let aes_verifier_witness = AESVerifierWitness {
        key: vec![0; 16],
        iv: vec![0; 12],
        ct: vec![0; 160],
        ret: vec![3, 136, 218, 206, 96, 182, 163, 146, 243, 40, 194, 185, 113, 178, 254, 120, 247, 149, 170, 171, 73, 75, 89, 35, 247, 253, 137, 255, 148, 139, 193, 224, 32, 2, 17, 33, 78, 115, 148, 218, 32, 137, 182, 172, 208, 147, 171, 224, 201, 77, 162, 25, 17, 142, 41, 125, 123, 126, 188, 188, 201, 195, 136, 242, 138, 222, 125, 133, 168, 238, 53, 97, 111, 113, 36, 169, 213, 39, 2, 145, 149, 184, 77, 27, 150, 198, 144, 255, 47, 45, 227, 11, 242, 236, 137, 224, 2, 83, 120, 110, 18, 101, 4, 240, 218, 185, 12, 72, 163, 3, 33, 222, 51, 69, 230, 176, 70, 30, 124, 158, 108, 107, 122, 254, 221, 232, 63, 64, 222, 179, 250, 103, 148, 248, 253, 143, 85, 168, 141, 203, 218, 157, 104, 242, 19, 124, 201, 200, 52, 32, 7, 126, 124, 242, 138, 178, 105, 107, 13, 240],
    };
    let aes_prover_witness_2 = AESProverWitness {
        key: vec![0; 16],
        iv: vec![0; 12],
        ct: vec![1; 160],
    };
    let aes_verifier_witness_2 = AESVerifierWitness {
        key: vec![0; 16],
        iv: vec![0; 12],
        ct: vec![1; 160],
        ret: vec![2, 137, 219, 207, 97, 183, 162, 147, 242, 41, 195, 184, 112, 179, 255, 121, 246, 148, 171, 170, 72, 74, 88, 34, 246, 252, 136, 254, 149, 138, 192, 225, 33, 3, 16, 32, 79, 114, 149, 219, 33, 136, 183, 173, 209, 146, 170, 225, 200, 76, 163, 24, 16, 143, 40, 124, 122, 127, 189, 189, 200, 194, 137, 243, 139, 223, 124, 132, 169, 239, 52, 96, 110, 112, 37, 168, 212, 38, 3, 144, 148, 185, 76, 26, 151, 199, 145, 254, 46, 44, 226, 10, 243, 237, 136, 225, 3, 82, 121, 111, 19, 100, 5, 241, 219, 184, 13, 73, 162, 2, 32, 223, 50, 68, 231, 177, 71, 31, 125, 159, 109, 106, 123, 255, 220, 233, 62, 65, 223, 178, 251, 102, 149, 249, 252, 142, 84, 169, 140, 202, 219, 156, 105, 243, 18, 125, 200, 201, 53, 33, 6, 127, 125, 243, 139, 179, 104, 106, 12, 241],
    };
    let non_membership_prover_witness = NonMembershipProverWitness {
        input_domain_wildcard: "moc.nozama.".chars().map(|c| (c as u8)).collect(),
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        left_domain_name: "moc.nozalleb.".chars().map(|c| (c as u8)).collect(),
        right_domain_name: "moc.nozamaainat.".chars().map(|c| (c as u8)).collect(),
        left_index: 8,
        right_index: 10,
        left_path_array: vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].into_iter().map(|s| s.to_string()).collect(),
        right_path_array: vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].into_iter().map(|s| s.to_string()).collect(),
        left_dir: 852258,
        right_dir: 852259
    };
    let non_membership_verifier_witness = NonMembershipVerifierWitness {
        input_domain_wildcard: "moc.nozama.".chars().map(|c| (c as u8).to_string()).collect(),
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        ret: "1".to_string()
    };
    let chacha_co_prover_witness = ChannelOpenProverWitness {
        HS: vec![156, 100, 164, 70, 175, 125, 251, 187, 195, 252, 218, 163, 247, 162, 104, 223, 141, 31, 157, 80, 201, 75, 109, 100, 103, 126, 160, 83, 35, 62, 110, 151],
        H2: vec![199, 19, 121, 24, 40, 28, 157, 126, 161, 31, 209, 97, 176, 243, 199, 25, 167, 27, 254, 231, 67, 165, 171, 4, 6, 254, 217, 126, 251, 196, 209, 246],
        CH_SH_len: 446,
        ServExt_len: 4655,
        ServExt_ct_tail: vec![55, 20, 119, 239, 196, 227, 25, 25, 66, 85, 86, 48, 177, 19, 204, 221, 60, 227, 215, 249, 250, 136, 147, 200, 179, 140, 65, 197, 170, 13, 131, 223, 141, 241, 30, 29, 93, 46, 240, 185, 88, 233, 68, 62, 98],
        ServExt_tail_len: 45,
        SHA_H_Checkpoint: vec![1995366002, 482694727, 3830622027, 387007927, 117988151, 1972788801, 1813956131, 3208532732],
        comm: "5658669201696800707554988141608320636732262216527181082290336347131007410316".to_string(),
    };
    let chacha_co_verifier_witness = ChannelOpenVerifierWitness {
        H2: vec![199, 19, 121, 24, 40, 28, 157, 126, 161, 31, 209, 97, 176, 243, 199, 25, 167, 27, 254, 231, 67, 165, 171, 4, 6, 254, 217, 126, 251, 196, 209, 246],
        CH_SH_len: 446,
        ServExt_len: 4655,
        ServExt_ct_tail: vec![55, 20, 119, 239, 196, 227, 25, 25, 66, 85, 86, 48, 177, 19, 204, 221, 60, 227, 215, 249, 250, 136, 147, 200, 179, 140, 65, 197, 170, 13, 131, 223, 141, 241, 30, 29, 93, 46, 240, 185, 88, 233, 68, 62, 98],
        ServExt_tail_len: 45,
        comm: "5658669201696800707554988141608320636732262216527181082290336347131007410316".to_string(),
    };
    let aes_co_prover_witness = ChannelOpenProverWitness {
        HS: vec![64, 0, 102, 176, 166, 165, 130, 119, 153, 99, 121, 9, 24, 23, 134, 194, 127, 113, 95, 105, 226, 44, 39, 151, 40, 78, 176, 49, 75, 1, 35, 238],
        H2: vec![203, 145, 85, 183, 177, 149, 25, 122, 197, 17, 137, 95, 81, 85, 182, 148, 104, 96, 19, 0, 197, 152, 165, 103, 213, 152, 137, 139, 19, 68, 216, 218],
        CH_SH_len: 448,
        ServExt_len: 4655,
        ServExt_ct_tail: vec![95, 119, 78, 150, 167, 89, 161, 15, 55, 92, 119, 7, 101, 58, 160, 57, 33, 142, 88, 183, 145, 144, 187, 32, 3, 254, 240, 13, 254, 13, 11, 118, 64, 65, 115, 53, 195, 109, 185, 142, 62, 239, 143, 51, 101, 186, 21],
        ServExt_tail_len: 47,
        SHA_H_Checkpoint: vec![108061636, 2955690276, 501099418, 480367027, 198558409, 2237606510, 898773191, 1157260509],
        comm: "6780552697568315653593609634023854386185172693090417235926717932034419422727".to_string(),
    };
    let aes_co_verifier_witness = ChannelOpenVerifierWitness {
        H2: vec![203, 145, 85, 183, 177, 149, 25, 122, 197, 17, 137, 95, 81, 85, 182, 148, 104, 96, 19, 0, 197, 152, 165, 103, 213, 152, 137, 139, 19, 68, 216, 218],
        CH_SH_len: 448,
        ServExt_len: 4655,
        ServExt_ct_tail: vec![95, 119, 78, 150, 167, 89, 161, 15, 55, 92, 119, 7, 101, 58, 160, 57, 33, 142, 88, 183, 145, 144, 187, 32, 3, 254, 240, 13, 254, 13, 11, 118, 64, 65, 115, 53, 195, 109, 185, 142, 62, 239, 143, 51, 101, 186, 21],
        ServExt_tail_len: 47,
        comm: "6780552697568315653593609634023854386185172693090417235926717932034419422727".to_string(),
    };
    let dot_chacha_amortized_prover_witness = AmortizedProverWitness::<255> {
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
        SN: 1,
        dns_ct: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        key: vec![25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187, 173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158],
        nonce: vec![222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161],
        left_domain_name: "moc.elpoepyxes.".chars().map(|c| c as u8).collect(),
        right_domain_name: "moc.elppacitoxe.".chars().map(|c| c as u8).collect(),
        left_index: 7,
        right_index: 9,
        left_path_array: vec!["1752129289157004846513364561035016959483567890799881965360261832269306118159", "5213947047904663182855168970299786258303520625485597599616726408396954592357", "4678654874247556106212070218407996724004768492975815783984666471771925610899", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        right_path_array: vec!["4029907311593792750484498435368156719160829193890227244100835352776679360047", "1047467952388836899138722578366330326649405090875887618128479192405646602243", "6895007323553775386387855880832878063946281581456959574788271261206193783665", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        left_dir: 797851,
        right_dir: 797852,
    };
    let dot_chacha_amortized_verifier_witness: AmortizedVerifierWitness<255> = AmortizedVerifierWitness::<255> {
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
        SN: 1,
        dns_ct: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
    };
    let doh_aes_amortized_prover_witness = AmortizedProverWitness::<500> {
        comm: "2509824152775235412653340525192363587469511895841505132552578921224376026197".to_string(),
        SN: 0,
        dns_ct: vec![250, 24, 128, 55, 181, 211, 176, 162, 24, 236, 223, 20, 3, 62, 113, 152, 45, 251, 223, 231, 47, 229, 4, 219, 151, 136, 223, 166, 223, 135, 199, 153, 185, 83, 192, 189, 96, 165, 9, 236, 151, 58, 192, 141, 209, 163, 44, 109, 143, 81, 213, 172, 255, 167, 250, 127, 137, 68, 167, 61, 203, 151, 124, 235, 30, 100, 6, 118, 124, 184, 240, 24, 155, 216, 0, 130, 12, 81, 30, 95, 49, 71, 172, 175, 110, 71, 142, 25, 201, 82, 142, 177, 29, 105, 32, 199, 54, 144, 108, 100, 248, 182, 89, 219, 2, 174, 148, 31, 55, 223, 157, 140, 34, 174, 78, 60, 78, 180, 195, 219, 200, 179, 216, 118, 57, 92, 204, 73, 238, 184, 49, 126, 89, 59, 191, 69, 78, 222, 164, 6, 115, 26, 250, 78, 172, 127, 214, 44, 188, 126, 2, 223, 3, 94, 102, 184, 12, 22, 168, 122],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        key: vec![236, 179, 229, 229, 248, 50, 233, 225, 46, 201, 207, 169, 67, 156, 30, 58],
        nonce: vec![231, 129, 118, 40, 220, 173, 36, 201, 252, 28, 250, 94],
        left_domain_name: "moc.nozalleb.".chars().map(|c| c as u8).collect(),
        right_domain_name: "moc.nozamaainat.".chars().map(|c| c as u8).collect(),
        left_index: 8,
        right_index: 10,
        left_path_array: vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        right_path_array: vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        left_dir: 852258,
        right_dir: 852259,
    };
    let doh_aes_amortized_verifier_witness = AmortizedVerifierWitness::<500> {
        comm: "2509824152775235412653340525192363587469511895841505132552578921224376026197".to_string(),
        SN: 0,
        dns_ct: vec![250, 24, 128, 55, 181, 211, 176, 162, 24, 236, 223, 20, 3, 62, 113, 152, 45, 251, 223, 231, 47, 229, 4, 219, 151, 136, 223, 166, 223, 135, 199, 153, 185, 83, 192, 189, 96, 165, 9, 236, 151, 58, 192, 141, 209, 163, 44, 109, 143, 81, 213, 172, 255, 167, 250, 127, 137, 68, 167, 61, 203, 151, 124, 235, 30, 100, 6, 118, 124, 184, 240, 24, 155, 216, 0, 130, 12, 81, 30, 95, 49, 71, 172, 175, 110, 71, 142, 25, 201, 82, 142, 177, 29, 105, 32, 199, 54, 144, 108, 100, 248, 182, 89, 219, 2, 174, 148, 31, 55, 223, 157, 140, 34, 174, 78, 60, 78, 180, 195, 219, 200, 179, 216, 118, 57, 92, 204, 73, 238, 184, 49, 126, 89, 59, 191, 69, 78, 222, 164, 6, 115, 26, 250, 78, 172, 127, 214, 44, 188, 126, 2, 223, 3, 94, 102, 184, 12, 22, 168, 122],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
    };
    let sha_round_prover_witness = ShaRoundProverWitness {
        a: vec![0; 16],
    };
    let sha_round_verifier_witness = ShaRoundVerifierWitness {
        a: vec![0; 16],
        ret: vec![3663108286, 398046313, 1647531929, 2006957770, 2363872401, 3235013187, 3137272298, 406301144],
    };
    let sha_round_prover_witness_2 = ShaRoundProverWitness {
        a: vec![1; 16],
    };
    let sha_round_verifier_witness_2 = ShaRoundVerifierWitness {
        a: vec![1; 16],
        ret: vec![3097815191, 947444931, 2420862107, 3754189083, 3136032896, 4150764797, 313045342, 3782171449],
    };
    let precomp_dot_chacha_prover_witness = PrecompDotChaChaProverWitness {
        key: vec![25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187, 173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158],
        nonce: vec![222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161],
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
        SN: 1
    };
    let precomp_dot_chacha_verifier_witness = PrecompDotChaChaVerifierWitness {
        comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
        SN: 1,
        ret: "1281332324447114668914509763277493145125755630037994190890567650764234607898".to_string(),
    };

    let dot_chacha_amortized_unpack_prover_witness = AmortizedUnpackProverWitness::<255> {
        comm_pad: "1281332324447114668914509763277493145125755630037994190890567650764234607898".to_string(),
        dns_ct: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        pad: vec![209, 160, 191, 226, 149, 157, 113, 238, 109, 52, 142, 83, 209, 222, 40, 15, 228, 17, 196, 215, 31, 232, 113, 232, 135, 47, 234, 17, 12, 196, 10, 205, 108, 109, 58, 204, 226, 166, 130, 234, 247, 121, 236, 79, 108, 12, 15, 165, 194, 185, 147, 125, 71, 124, 147, 80, 177, 102, 156, 165, 177, 77, 5, 151, 237, 113, 191, 40, 192, 110, 25, 81, 149, 105, 203, 224, 87, 76, 181, 45, 193, 4, 168, 231, 89, 181, 158, 175, 225, 48, 91, 251, 126, 115, 199, 29, 137, 80, 44, 37, 125, 28, 99, 132, 50, 183, 230, 183, 51, 24, 92, 112, 5, 129, 190, 79, 181, 10, 146, 222, 227, 254, 168, 189, 214, 52, 96, 208, 33, 182, 144, 127, 214, 20, 188, 247, 79, 76, 150, 67, 254, 236, 241, 167, 225, 1, 51, 26, 184, 179, 100, 28, 232, 131, 2, 146, 63, 88, 84, 15, 52, 194, 67, 81, 79, 205, 50, 82, 175, 84, 50, 73, 60, 45, 154, 73, 140, 37, 124, 208, 199, 191, 80, 52, 194, 246, 38, 110, 137, 66, 90, 123, 225, 253, 44, 8, 201, 126, 141, 160, 160, 110, 21, 17, 65, 84, 239, 236, 102, 1, 156, 76, 214, 175, 9, 214, 159, 85, 99, 113, 95, 189, 229, 171, 40, 51, 76, 254, 178, 220, 120, 54, 79, 45, 151, 122, 28, 20, 81, 48, 192, 208, 26, 2, 183, 122, 77, 252, 9, 228, 50, 119, 12, 62, 220],
        left_domain_name: "moc.elpoepyxes.".chars().map(|c| c as u8).collect(),
        right_domain_name: "moc.elppacitoxe.".chars().map(|c| c as u8).collect(),
        left_index: 7,
        right_index: 9,
        left_path_array: vec!["1752129289157004846513364561035016959483567890799881965360261832269306118159", "5213947047904663182855168970299786258303520625485597599616726408396954592357", "4678654874247556106212070218407996724004768492975815783984666471771925610899", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        right_path_array: vec!["4029907311593792750484498435368156719160829193890227244100835352776679360047", "1047467952388836899138722578366330326649405090875887618128479192405646602243", "6895007323553775386387855880832878063946281581456959574788271261206193783665", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].iter().map(|s| s.to_string()).collect(),
        left_dir: 797851,
        right_dir: 797852,
    };
    let dot_chacha_amortized_unpack_verifier_witness = AmortizedUnpackVerifierWitness::<255> {
        comm_pad: "1281332324447114668914509763277493145125755630037994190890567650764234607898".to_string(),
        dns_ct: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
        ret: "1".to_string(),
    };

    let args: Vec<String> = env::args().collect();
    println!("{}", args[1]);
    let should_generate = match args[2].as_str() {
        "true" => true,
        _ => false
    };
    let benchmark_method = match args[3].as_str() {
        "prover" => BenchmarkMethod::Prover,
        "verifier" => BenchmarkMethod::Verifier,
        "prover_verifier" => BenchmarkMethod::ProverAndVerifier,
        _ => panic!()
    };
    match args[1].as_str() {
        "DotChaChaAmortized_Isolated_255" => benchmark_one_circuit("DotChaChaAmortized_Isolated", vec![dot_chacha_amortized_prover_witness.clone()], vec![dot_chacha_amortized_verifier_witness.clone()], should_generate, benchmark_method),
        "DotChaChaAmortized_255" => benchmark_one_circuit("DotChaChaAmortized", vec![dot_chacha_amortized_prover_witness], vec![dot_chacha_amortized_verifier_witness], should_generate, benchmark_method),
        "PrecompDotChaCha_255" => benchmark_one_circuit("PrecompDotChaCha", vec![precomp_dot_chacha_prover_witness.clone(); 1], vec![precomp_dot_chacha_verifier_witness.clone(); 1], should_generate, benchmark_method),
        "DotChaChaAmortizedUnpack_255" => benchmark_one_circuit("DotChaChaAmortizedUnpack", vec![dot_chacha_amortized_unpack_prover_witness.clone()], vec![dot_chacha_amortized_unpack_verifier_witness.clone()], should_generate, benchmark_method), 
        "2_date_100" => benchmark_one_circuit("2_date_100", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "2_date_1000" => benchmark_one_circuit("2_date_1000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "2_date_2000" => benchmark_one_circuit("2_date_2000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "1_email_100" => benchmark_one_circuit("1_email_100", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method) ,
        "1_email_1000" => benchmark_one_circuit("1_email_1000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "1_email_2000" => benchmark_one_circuit("1_email_2000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "0_URI_100" => benchmark_one_circuit("0_URI_100", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "0_URI_1000" => benchmark_one_circuit("0_URI_1000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "0_URI_2000" => benchmark_one_circuit("0_URI_2000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "3_URIemail_100" => benchmark_one_circuit("3_URIemail_100", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "3_URIemail_1000" => benchmark_one_circuit("3_URIemail_1000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "3_URIemail_2000" => benchmark_one_circuit("3_URIemail_2000", vec![RegexProverWitness::<2048>::default()], vec![RegexVerifierWitness::<2048>::default()], should_generate, benchmark_method),
        "policy_100" => benchmark_one_circuit("policy100", vec![RegexProverWitness::<100>::default()], vec![RegexVerifierWitness::<100>::default()], should_generate, benchmark_method),
        "RegexChaChaAmortized_100" => benchmark_one_circuit("RegexChaChaAmortized100", vec![RegexAmortizedProverWitness::<1000>::default()], vec![RegexAmortizedVerifierWitness::<1000>::default()], should_generate, benchmark_method),
        "RegexChaChaAmortized_2000" => benchmark_one_circuit("RegexChaChaAmortized2000", vec![RegexAmortizedProverWitness::<2000>::default()], vec![RegexAmortizedVerifierWitness::<2000>::default()], should_generate, benchmark_method),
        "policy_2000" => benchmark_one_circuit("policy2000", vec![RegexProverWitness::<2000>::default()], vec![RegexVerifierWitness::<2000>::default()], should_generate, benchmark_method),
        _ => ()
    }
}

// TODO: don't commit this, update temporary for testing
fn main() {
    zk_test()
}