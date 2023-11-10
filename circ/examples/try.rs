use core::prelude::v1;
use std::mem::size_of_val;
use std::path::PathBuf;
use std::sync::Arc;
use circ::front::{FrontEnd, Mode};
use circ::front::zsharp::{ZSharpFE, Inputs};
use circ::target::r1cs::{ProverData, R1cs};
use circ::target::r1cs::trans::to_r1cs;
use circ::util::field::DFL_T;
use circ_fields::{FieldT, FieldV};
use std::env;
use circ::ir::opt::{opt, Opt};
use circ::ir::term::{Value, BitVector};
use fxhash::FxHashMap as HashMap;
use rug::Integer;
use circ::target::r1cs::{spartan};
use curve25519_dalek::scalar::Scalar;
use gmp_mpfr_sys::gmp::limb_t;
use libspartan::{Instance, Assignment, NIZK, NIZKGens};
use circ_fields::FieldV::IntField;
use merlin::Transcript;
use std::time::{Duration, Instant};
use std::fs;
use log::debug;


// let cs = ZSharpFE::gen(inputs);

fn main() {
    env_logger::init();
    let inputs = Inputs {
        // file: PathBuf::from("./third_party/ZoKrates/zokrates_stdlib/stdlib/hashes/poseidon/poseidon.zok"),
        file: PathBuf::from("./zkmb/tls_key_schedules/HKDF.zok"),
        // file: PathBuf::from("./examples/ZoKrates/pf/3_plus.zok"), 
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let cs = opt(
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

    println!("opt finish");
    let tt1 = Instant::now();
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs.clone(), FieldT::from(FieldT::from(DFL_T.modulus())));
    println!("to r1cs time {}", tt1.elapsed().as_millis());
    let tt2 = Instant::now();
    println!("num of constraints {}", r1cs.constraints().len());
    // let proof_encoded: Vec<u8> = bincode::serialize(&r1cs).unwrap();
    // println!("serialization time {}", tt2.elapsed().as_millis());
    // println!("size of r1cs is {} bytes", &proof_encoded.len());
    // fs::write("r1cs_tmp", proof_encoded).expect("fail to write file");

    for (name, sort) in prover_data.precompute_inputs {
        println!("name is {}", name);
    }

    let inst = spartan::get_spartan_instance(&r1cs);

    // evaluation and transform
    let mut input_map = HashMap::<String, Value>::default();
    let v1: FieldV = FieldV::new(Integer::from(200 as u32), Arc::new(DFL_T.modulus().clone()));
    let v2: FieldV = FieldV::new(Integer::from(100 as u32), Arc::new(DFL_T.modulus().clone()));
    let comm = Integer::from_str_radix("3371477359450881573900358540781813942536054075356934037141634247916804112110", 10).unwrap();
    let comm: FieldV = FieldV::new(comm, Arc::new(DFL_T.modulus().clone()));
    // input_map.insert("inputs.0".to_string(), Value::Field(v1));
    // input_map.insert("inputs.1".to_string(), Value::Field(v2));
    // input_map.insert("comm".to_string(), Value::Field(comm));
    input_map.insert("key.0".to_string(), Value::BitVector(BitVector::new(Integer::from(0 as u8), 8)));
    input_map.insert("key.1".to_string(), Value::BitVector(BitVector::new(Integer::from(5 as u8), 8)));
    input_map.insert("info.0".to_string(), Value::BitVector(BitVector::new(Integer::from(0 as u8), 8)));
    input_map.insert("info.1".to_string(), Value::BitVector(BitVector::new(Integer::from(5 as u8), 8)));
    let t1 = Instant::now();
    let assignment = prover_data.precompute.eval(&input_map);
    let t2 = Instant::now();
    println!("circuit evaluation took {}", t2.duration_since(t1).as_micros());
    let (var_assignment, input_assignment) = spartan::get_spartan_assignment(&r1cs, &assignment);
    let t3 = Instant::now();
    println!("assignment transformation took {}", t3.duration_since(t2).as_millis());

    // test and generate gens
    let result = inst.is_sat(&var_assignment, &input_assignment).unwrap();
    let input_num = r1cs.public_idxs.len();
    let var_num = r1cs.idxs_signals.len() - input_num;
    let gens = NIZKGens::new(r1cs.constraints().len(), var_num, input_num);
    println!("result is {}", result);

    // actuall proof start
    let mut prover_transcript = Transcript::new(b"zkmb_proof");
    let t4 = Instant::now();
    let proof = NIZK::prove(
      &inst,
      var_assignment,
      &input_assignment,
      &gens,
      &mut prover_transcript,
    );
    let t5 = Instant::now();
    println!("NIZK proof took {}", t5.duration_since(t4).as_millis());

    let timer = Instant::now();
    let mut verifier_transcript = Transcript::new(b"zkmb_proof");
    let ok = proof.verify(&inst, &input_assignment, &mut verifier_transcript, &gens).is_ok();
    println!("NIZK verify took {} {}", timer.elapsed().as_millis(), ok);
}