use std::env;
use std::fs;
use std::mem;

extern crate byteorder;
extern crate core;
extern crate digest;
extern crate libspartan;
extern crate merlin;
extern crate rand;
extern crate sha3;
use curve25519_dalek::scalar::Scalar;
use libspartan::{InputsAssignment, VarsAssignment};
use libspartan::{Instance, NIZKGens, NIZK};
use libspartan::{SNARKGens, SNARK};
use merlin::Transcript;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::time::{Duration, Instant};
extern crate num;
use num::bigint::BigInt;
use num::bigint::ToBigInt;
use serde::{Deserialize, Serialize};
use serde_json::Result;

fn pad_32_little_endian(big_int_vec: Vec<u8>) -> ([u8; 32]) {
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

fn zkmb_generate(r1cs_path: &str) -> (usize, usize) {
  // The r1cs matrices are stored in custom_r1cs_input.txt
  let file = File::open(r1cs_path).unwrap();
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
    let vec = next_line_stupid_rust
      .split_whitespace()
      .collect::<Vec<&str>>();

    if vec[0].eq("New") {
      println!("Reading Next Matrix/Vector {}", vec[2]);
      currently_reading = currently_reading + 1;
      if currently_reading > 2 {
        break;
      } else {
        continue;
      }
    }

    let mut byte_array: [u8; 32] = [0; 32];

    let mut big_int = vec[2].parse::<BigInt>().unwrap();

    let big_int_vec = big_int.to_bytes_le().1;

    byte_array = pad_32_little_endian(big_int_vec);

    let entry: (usize, usize, [u8; 32]) = (
      vec[0].parse::<usize>().unwrap(),
      vec[1].parse::<usize>().unwrap(),
      byte_array,
    );
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

  println!(
    "Number of non-zero entries: {}, {}, {}",
    num_non_zero_entries_a, num_non_zero_entries_b, num_non_zero_entries_c,
  );

  let num_non_zero_entries =
    num_non_zero_entries_a + num_non_zero_entries_b + num_non_zero_entries_c;

  println!("Done with reading all matrices!");

  num_variables = num_variables - (num_inputs);
  let mut vars = vec![Scalar::zero().to_bytes(); num_variables];
  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];

  let mut counter = 0;
  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    let vec = next_line_stupid_rust
      .split_whitespace()
      .collect::<Vec<&str>>();

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

    if counter == (num_variables + num_inputs) {
      break;
    }
  }

  println!("Done with reading input vector!");

  // ********************************** END OF CODE TO READ MATRICES, INPUT VECTOR *****************

  // Create gens, inst variables

  let gens = NIZKGens::new(num_constraints, num_variables, num_inputs);
  let inst = Instance::new(
    num_constraints,
    num_variables,
    num_inputs,
    &matrix_A,
    &matrix_B,
    &matrix_C,
  )
  .unwrap();

  let gens_encoded = bincode::serialize(&gens).unwrap();
  fs::write("nizk_gens", gens_encoded).expect("Unable to write file");
  let inst_encoded = bincode::serialize(&inst).unwrap();
  fs::write("nizk_inst", inst_encoded).expect("Unable to write file");
  (num_variables, num_inputs)
}

fn zkmb_prove(
  gens: &NIZKGens,
  inst: &Instance,
  num_variables: usize,
  num_inputs: usize,
  full_assignment_file: &str,
) {
  let mut vars = vec![Scalar::zero().to_bytes(); num_variables];
  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
  let file = File::open(full_assignment_file).unwrap();
  let mut reader = BufReader::new(file);

  let mut counter = 0;
  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    let vec = next_line_stupid_rust
      .split_whitespace()
      .collect::<Vec<&str>>();

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

    if counter == (num_variables + num_inputs) {
      break;
    }
  }
  let assignment_vars = VarsAssignment::new(&vars).unwrap();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);
  let mut prover_transcript = Transcript::new(b"zkmb_proof");
  let proof = NIZK::prove(
    &inst,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );

  let proof_encoded = bincode::serialize(&proof).unwrap();
  fs::write("r1cs_proof", proof_encoded).expect("Unable to write file");
}

fn zkmb_verify(
  gens: &NIZKGens,
  inst: &Instance,
  proof: NIZK,
  assignment_inputs: InputsAssignment,
) -> bool {
  let mut verifier_transcript = Transcript::new(b"zkmb_proof");
  let result = proof
    .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok();
  println!("{}", result);
  result
}

pub fn main() {
  let args: Vec<String> = env::args().collect();
  let (num_variables, num_inputs) = zkmb_generate(&args[1]);
  let gens_data = fs::read("nizk_gens").expect("Unable to read gens data");
  let gens: NIZKGens = bincode::deserialize(&gens_data).unwrap();
  let inst_data = fs::read("nizk_inst").expect("Unable to read inst data");
  let inst: Instance = bincode::deserialize(&inst_data).unwrap();
  zkmb_prove(
    &gens,
    &inst,
    num_variables,
    num_inputs,
    "full_assignment.txt",
  );
  let data = fs::read("r1cs_proof").expect("Unable to read file");
  let proof: NIZK = bincode::deserialize(&data).unwrap();
  let file = File::open("primary_assignment.txt").unwrap();
  let mut reader = BufReader::new(file);
  let mut counter = 0;
  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
  for next_line in reader.by_ref().lines() {
    let next_line_stupid_rust = next_line.unwrap();
    let vec = next_line_stupid_rust
      .split_whitespace()
      .collect::<Vec<&str>>();
    let big_int = vec[0].parse::<BigInt>().unwrap();
    let big_int_vec = big_int.to_bytes_le().1;
    let byte_array = pad_32_little_endian(big_int_vec);
    inputs[counter] = byte_array;
    counter += 1;
    if counter == (num_variables + num_inputs) {
      break;
    }
  }
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
  zkmb_verify(&gens, &inst, proof, assignment_inputs);
}
