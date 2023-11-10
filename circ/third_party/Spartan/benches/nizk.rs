/*

The function zkmb() handles all reading of matrices and creating/verifying proofs.

This file requires "custom_r1cs_input.txt" to be present where cargo bench is run.

I named this file "nizk.rs" 
and replaced the original nizk.rs in the benches/ directory. 
and ran it using "cargo bench nizk".

----------------------------------

The verification step is around line 220. 
It calls and measures proof.verify().

VERIFIER TIME:
- the r1cs instance has 190,420 constraints and 185,525 variables
- num non-zero entries are (192724, 152888, 193020)
- the prover takes ~ 0.9 seconds
- the verifier takes ~ 160 ms

But according to the Spartan benchmarks,
a circuit of 2^18 R1CS constaints (~ 260,000)
should verify in ~ 88 ms. 

I am seeing an almost 2x blowup in verification time
in nearly all of my custom r1cs instances.

*/

use std::mem;


extern crate byteorder;
extern crate core;
extern crate criterion;
extern crate digest;
extern crate libspartan;
extern crate merlin;
extern crate rand;
extern crate sha3;
use curve25519_dalek::scalar::Scalar;
use libspartan::{Instance, NIZKGens, NIZK};
use libspartan::{SNARKGens, SNARK};
use libspartan::{InputsAssignment, VarsAssignment};
use merlin::Transcript;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::time::{Duration, Instant};

use criterion::*;
extern crate num;
use num::bigint::BigInt;

use num::bigint::ToBigInt;

use flate2::{write::ZlibEncoder, Compression};

fn print(msg: &str) {
  let star = "* ";
  println!("{:indent$}{}{}", "", star, msg.to_string(), indent = 2);
}


fn pad_32_little_endian(big_int_vec: Vec<u8>) -> ([u8;32]) {
  let mut byte_array: [u8; 32] = [0; 32];
  for i in 0..32 {
    if i < big_int_vec.len() {
      byte_array[i] = big_int_vec[i];
    } else {
      byte_array[i] = 0;
    }
  }

  byte_array
}

fn zkmb() {
  // The r1cs matrices are stored in custom_r1cs_input.txt
  let file = File::open("custom_r1cs_input.txt").unwrap();
  let mut reader = BufReader::new(file);

  // Variables to store matrices
  let mut matrix_A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut matrix_B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut matrix_C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  // ********************************** START OF CODE TO READ MATRICES, INPUT VECTOR *****************

  let mut currently_reading = -1; 
  let mut num_constraints = 0;
  let mut num_variables = 0;
  let mut num_inputs = 0;

  let mut num_non_zero_entries_a = 0;
  let mut num_non_zero_entries_b = 0;
  let mut num_non_zero_entries_c = 0;
  let mut num_non_zero_entries = 0;

  let skip_lines = 8;
  for _ in reader.by_ref().lines().take(skip_lines) {}  


  let mut count_lines = 1;
  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    if count_lines == 1 {
      println!("{}", next_line_stupid_rust);
      num_constraints = next_line_stupid_rust.parse::<usize>().unwrap();
      count_lines += 1;
    } else if count_lines == 2 {
      println!("{}", next_line_stupid_rust);
      num_variables = next_line_stupid_rust.parse::<usize>().unwrap();
      count_lines += 1;
    } else if count_lines == 3 {
      num_inputs = next_line_stupid_rust.parse::<usize>().unwrap();
      println!("Num Inputs: {}", &num_inputs);
      break;
    }
  }


  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    let vec = next_line_stupid_rust.split_whitespace().collect::<Vec<&str>>();

    if vec[0].eq("New") {
      println!("Reading Next Matrix/Vector {}", vec[2]);
      currently_reading = currently_reading+1;
      if currently_reading > 2 { break; }
      else { continue; }
    }

    let mut byte_array: [u8; 32] = [0; 32];

    let mut big_int = vec[2].parse::<BigInt>().unwrap();

    let big_int_vec = big_int.to_bytes_le().1;

    byte_array = pad_32_little_endian(big_int_vec);


    let entry: (usize, usize, [u8; 32]) = (vec[0].parse::<usize>().unwrap(), vec[1].parse::<usize>().unwrap(), byte_array);
    if currently_reading == 0 {
      if big_int != 0_i32.to_bigint().unwrap() {
        num_non_zero_entries_a += 1;
      }
      matrix_A.push(entry);
    } else if currently_reading == 1 {
      if big_int != 0_i32.to_bigint().unwrap() {
        num_non_zero_entries_b += 1;
      }
      matrix_B.push(entry); 
    } else if currently_reading == 2 {
      if big_int != 0_i32.to_bigint().unwrap() {
        num_non_zero_entries_c += 1;
      }
      matrix_C.push(entry);
    }
  }

  println!("Number of non-zero entries: {}, {}, {}", num_non_zero_entries_a, num_non_zero_entries_b, num_non_zero_entries_c,);


  let num_non_zero_entries = num_non_zero_entries_a + num_non_zero_entries_b + num_non_zero_entries_c;

  println!("Done with reading all matrices!");

  num_variables = num_variables - (num_inputs);
  let mut vars = vec![Scalar::zero().to_bytes(); num_variables];
  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];

  let mut counter = 0;
  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    let vec = next_line_stupid_rust.split_whitespace().collect::<Vec<&str>>();

    let mut byte_array: [u8; 32] = [0; 32];
    let big_int = vec[0].parse::<BigInt>().unwrap();
    let big_int_vec = big_int.to_bytes_le().1;

    byte_array = pad_32_little_endian(big_int_vec);

    if counter < num_inputs {
      inputs[counter] = byte_array;
    } else {
      vars[counter - num_inputs] = byte_array;
    }
    counter += 1;

    if counter == (num_variables + num_inputs) { break; }
  }

  println!("Done with reading input vector!");

  // ********************************** END OF CODE TO READ MATRICES, INPUT VECTOR *****************


  // Create gens, inst variables 

  let gens = NIZKGens::new(num_constraints, num_variables, num_inputs);
  let inst = Instance::new(num_constraints, num_variables, num_inputs, &matrix_A, &matrix_B, &matrix_C).unwrap();

  println!("Done with creating gens, inst!");

  // let mut gens_encoder = ZlibEncoder::new(Vec::new(), Compression::default());
  // bincode::serialize_into(&mut gens_encoder, &gens).unwrap();
  // let gens_encoded = gens_encoder.finish().unwrap();
  // let msg_gens_len = format!("NIZK::gens_commpressed_len is {:?}", gens_encoded.len());
  // print(&msg_gens_len);

  let assignment_vars = VarsAssignment::new(&vars).unwrap();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  println!("Done with assignment of vars, inputs! Now testing...");

  // Check is R1CS instance is satisfiable

  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);

  println!("Looks like the assignment satisfies!");

  

  // // Create proof
  let mut prover_transcript = Transcript::new(b"zkmb_proof");

  let proof_time = Instant::now(); // start time of proof 
  
  let proof = NIZK::prove(
    black_box(&inst), 
    black_box(assignment_vars), 
    black_box(&assignment_inputs), 
    black_box(&gens), 
    black_box(&mut prover_transcript));
  
  println!("Done with NIZK proof generation!");
  println!("NIZK proof took {}", proof_time.elapsed().as_millis()); // end time

  // amortized size: 30528
  let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap(); 
  println!("len_r1cs_sat_proof {:?}", proof_encoded.len());

  

  // Verify proof
  let mut verifier_transcript = Transcript::new(b"zkmb_proof");
  let verif_time = Instant::now();
  assert!(proof
    .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  println!("NIZK proof verification successful!"); 
  println!("NIZK verif took {}", verif_time.elapsed().as_millis()); 
  


  // // try SNARK prove (not NIZK)

  // let gens2 = SNARKGens::new(num_constraints, num_variables, num_inputs, num_non_zero_entries_b);
  // // create a commitment to the R1CS instance
  // let (comm, decomm) = SNARK::encode(&inst, &gens2);

  // let mut prover_transcript2 = Transcript::new(b"snark_example");
  // let proof_time_2 = Instant::now(); // start time of proof 
  // let proof2 = SNARK::prove(&inst, &decomm, assignment_vars, &assignment_inputs, &gens2, &mut prover_transcript2);
  // println!("SNARK proof took {}", proof_time_2.elapsed().as_millis()); // end time

  // let mut verifier_transcript2 = Transcript::new(b"snark_example");
  // let verif_time_2 = Instant::now(); // start time of proof 
  // assert!(proof2
  //     .verify(&comm, &assignment_inputs, &mut verifier_transcript2, &gens2)
  //     .is_ok());
  // println!("SNARK verif took {}", verif_time_2.elapsed().as_millis()); // end time
  // println!("proof verification successful!");
}


fn nizk_prove_benchmark(c: &mut Criterion) {
   rayon::ThreadPoolBuilder::new().num_threads(8).build_global().unwrap();
  zkmb();
}

fn nizk_verify_benchmark(c: &mut Criterion) {
  for &s in [21].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("NIZK_verify_benchmark");
    group.plot_config(plot_config);

    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    let num_inputs = 200;
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    //let gens = NIZKGens::new(num_cons, num_vars, num_inputs);
    let gens = NIZKGens::new(1298318, 1280116, 164);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    let name = format!("NIZK_verify_{}", num_cons);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut verifier_transcript = Transcript::new(b"example");
        assert!(proof
          .verify( black_box(&inst),
            black_box(&inputs),
            black_box(&mut verifier_transcript),
            black_box(&gens)
          )
          .is_ok());
      });
    });
    group.finish();
  }
}


fn set_duration() -> Criterion {
  Criterion::default().sample_size(10)
}

criterion_group! {
name = benches_nizk;
config = set_duration();
targets = nizk_prove_benchmark, nizk_verify_benchmark
}

criterion_main!(benches_nizk);