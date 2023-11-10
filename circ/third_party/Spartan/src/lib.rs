#![allow(non_snake_case)]
#![feature(test)]

extern crate byteorder;
extern crate core;
extern crate curve25519_dalek;
extern crate digest;
extern crate merlin;
extern crate rand;
extern crate rayon;
extern crate sha3;
extern crate test;

mod commitments;
mod dense_mlpoly;
mod errors;
mod group;
mod math;
mod nizk;
mod product_tree;
mod r1csinstance;
mod r1csproof;
mod random;
pub mod scalar;
mod sparse_mlpoly;
mod sumcheck;
mod timer;
pub mod transcript;
mod unipoly;

use core::cmp::max;
use errors::{ProofVerifyError, R1CSError};
use libc;
use merlin::Transcript;
use num::bigint::BigInt;
use num::bigint::ToBigInt;
use r1csinstance::{
  R1CSCommitment, R1CSCommitmentGens, R1CSDecommitment, R1CSEvalProof, R1CSInstance,
};
use r1csproof::{R1CSGens, R1CSProof};
use random::RandomTape;
use scalar::Scalar;
use serde::{Deserialize, Serialize};
use std;
use std::fs;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use timer::Timer;
use transcript::TranscriptWrapper;
use transcript::{AppendToTranscript, ProofTranscript};

/// `ComputationCommitment` holds a public preprocessed NP statement (e.g., R1CS)
#[derive(Serialize, Deserialize, Debug)]
pub struct ComputationCommitment {
  comm: R1CSCommitment,
}

/// `ComputationDecommitment` holds information to decommit `ComputationCommitment`
#[derive(Serialize, Deserialize, Debug)]
pub struct ComputationDecommitment {
  decomm: R1CSDecommitment,
}

/// `Assignment` holds an assignment of values to either the inputs or variables in an `Instance`
#[derive(Clone)]
pub struct Assignment {
  pub assignment: Vec<Scalar>,
}

impl Assignment {
  /// Constructs a new `Assignment` from a vector
  pub fn new(assignment: &Vec<[u8; 32]>) -> Result<Assignment, R1CSError> {
    let bytes_to_scalar = |vec: &Vec<[u8; 32]>| -> Result<Vec<Scalar>, R1CSError> {
      let mut vec_scalar: Vec<Scalar> = Vec::new();
      for i in 0..vec.len() {
        let val = Scalar::from_bytes(&vec[i]);
        if val.is_some().unwrap_u8() == 1 {
          vec_scalar.push(val.unwrap());
        } else {
          return Err(R1CSError::InvalidScalar);
        }
      }
      Ok(vec_scalar)
    };

    let assignment_scalar = bytes_to_scalar(assignment);

    // check for any parsing errors
    if assignment_scalar.is_err() {
      return Err(R1CSError::InvalidScalar);
    }

    Ok(Assignment {
      assignment: assignment_scalar.unwrap(),
    })
  }

  /// pads Assignment to the specified length
  fn pad(&self, len: usize) -> VarsAssignment {
    // check that the new length is higher than current length
    assert!(len > self.assignment.len());

    let padded_assignment = {
      let mut padded_assignment = self.assignment.clone();
      padded_assignment.extend(vec![Scalar::zero(); len - self.assignment.len()]);
      padded_assignment
    };

    VarsAssignment {
      assignment: padded_assignment,
    }
  }
}

/// `VarsAssignment` holds an assignment of values to variables in an `Instance`
pub type VarsAssignment = Assignment;

/// `VarsAssignment` holds an assignment of values to variables in an `Instance`
pub type InputsAssignment = Assignment;

/// `Instance` holds the description of R1CS matrices
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Instance {
  pub inst: R1CSInstance,
}

impl Instance {
  /// Constructs a new `Instance` and an associated satisfying assignment
  pub fn new(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: &Vec<(usize, usize, [u8; 32])>,
    B: &Vec<(usize, usize, [u8; 32])>,
    C: &Vec<(usize, usize, [u8; 32])>,
  ) -> Result<Instance, R1CSError> {
    let (num_vars_padded, num_cons_padded) = {
      let num_vars_padded = {
        let mut num_vars_padded = num_vars;

        // ensure that num_inputs + 1 <= num_vars
        num_vars_padded = max(num_vars_padded, num_inputs + 1);

        // ensure that num_vars_padded a power of two
        if num_vars_padded.next_power_of_two() != num_vars_padded {
          num_vars_padded = num_vars_padded.next_power_of_two();
        }
        num_vars_padded
      };

      let num_cons_padded = {
        let mut num_cons_padded = num_cons;

        // ensure that num_cons_padded is at least 2
        if num_cons_padded == 0 || num_cons_padded == 1 {
          num_cons_padded = 2;
        }

        // ensure that num_cons_padded is power of 2
        if num_cons.next_power_of_two() != num_cons {
          num_cons_padded = num_cons.next_power_of_two();
        }
        num_cons_padded
      };

      (num_vars_padded, num_cons_padded)
    };

    let bytes_to_scalar =
      |tups: &Vec<(usize, usize, [u8; 32])>| -> Result<Vec<(usize, usize, Scalar)>, R1CSError> {
        let mut mat: Vec<(usize, usize, Scalar)> = Vec::new();
        for i in 0..tups.len() {
          let (row, col, val_bytes) = tups[i];

          // row must be smaller than num_cons
          if row >= num_cons {
            return Err(R1CSError::InvalidIndex);
          }

          // col must be smaller than num_vars + 1 + num_inputs
          if col >= num_vars + 1 + num_inputs {
            return Err(R1CSError::InvalidIndex);
          }

          let val = Scalar::from_bytes(&val_bytes);
          if val.is_some().unwrap_u8() == 1 {
            // if col >= num_vars, it means that it is referencing a 1 or input in the satisfying
            // assignment
            if col >= num_vars {
              mat.push((row, col + num_vars_padded - num_vars, val.unwrap()));
            } else {
              mat.push((row, col, val.unwrap()));
            }
          } else {
            return Err(R1CSError::InvalidScalar);
          }
        }

        // pad with additional constraints up until num_cons_padded if the original constraints were 0 or 1
        // we do not need to pad otherwise because the dummy constraints are implicit in the sum-check protocol
        if num_cons == 0 || num_cons == 1 {
          for i in tups.len()..num_cons_padded {
            mat.push((i, num_vars, Scalar::zero()));
          }
        }

        Ok(mat)
      };

    let A_scalar = bytes_to_scalar(A);
    if A_scalar.is_err() {
      return Err(A_scalar.err().unwrap());
    }

    let B_scalar = bytes_to_scalar(B);
    if B_scalar.is_err() {
      return Err(B_scalar.err().unwrap());
    }

    let C_scalar = bytes_to_scalar(C);
    if C_scalar.is_err() {
      return Err(C_scalar.err().unwrap());
    }

    let inst = R1CSInstance::new(
      num_cons_padded,
      num_vars_padded,
      num_inputs,
      &A_scalar.unwrap(),
      &B_scalar.unwrap(),
      &C_scalar.unwrap(),
    );

    Ok(Instance { inst })
  }

  /// Checks if a given R1CSInstance is satisfiable with a given variables and inputs assignments
  pub fn is_sat(
    &self,
    vars: &VarsAssignment,
    inputs: &InputsAssignment,
  ) -> Result<bool, R1CSError> {
    if vars.assignment.len() > self.inst.get_num_vars() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    if inputs.assignment.len() != self.inst.get_num_inputs() {
      return Err(R1CSError::InvalidNumberOfInputs);
    }

    // we might need to pad variables
    let padded_vars = {
      let num_padded_vars = self.inst.get_num_vars();
      let num_vars = vars.assignment.len();
      let padded_vars = if num_padded_vars > num_vars {
        vars.pad(num_padded_vars)
      } else {
        vars.clone()
      };
      padded_vars
    };

    Ok(
      self
        .inst
        .is_sat(&padded_vars.assignment, &inputs.assignment),
    )
  }

  /// Constructs a new synthetic R1CS `Instance` and an associated satisfying assignment
  pub fn produce_synthetic_r1cs(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (Instance, VarsAssignment, InputsAssignment) {
    let (inst, vars, inputs) = R1CSInstance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    (
      Instance { inst },
      VarsAssignment { assignment: vars },
      InputsAssignment { assignment: inputs },
    )
  }
}

/// `SNARKGens` holds public parameters for producing and verifying proofs with the Spartan SNARK
#[derive(Serialize, Deserialize, Debug)]
pub struct SNARKGens {
  gens_r1cs_sat: R1CSGens,
  gens_r1cs_eval: R1CSCommitmentGens,
}

impl SNARKGens {
  /// Constructs a new `SNARKGens` given the size of the R1CS statement
  /// `num_nz_entries` specifies the maximum number of non-zero entries in any of the three R1CS matrices
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize, num_nz_entries: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    let gens_r1cs_eval = R1CSCommitmentGens::new(
      b"gens_r1cs_eval",
      num_cons,
      num_vars_padded,
      num_inputs,
      num_nz_entries,
    );
    SNARKGens {
      gens_r1cs_sat,
      gens_r1cs_eval,
    }
  }
}

/// `SNARK` holds a proof produced by Spartan SNARK
#[derive(Serialize, Deserialize, Debug)]
pub struct SNARK {
  r1cs_sat_proof: R1CSProof,
  inst_evals: (Scalar, Scalar, Scalar),
  r1cs_eval_proof: R1CSEvalProof,
}

impl SNARK {
  fn protocol_name() -> &'static [u8] {
    b"Spartan SNARK proof"
  }

  /// A public computation to create a commitment to an R1CS instance
  pub fn encode(
    inst: &Instance,
    gens: &SNARKGens,
  ) -> (ComputationCommitment, ComputationDecommitment) {
    let timer_encode = Timer::new("SNARK::encode");
    let (comm, decomm) = inst.inst.commit(&gens.gens_r1cs_eval);
    timer_encode.stop();
    (
      ComputationCommitment { comm },
      ComputationDecommitment { decomm },
    )
  }

  /// A method to produce a SNARK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance,
    decomm: &ComputationDecommitment,
    vars: VarsAssignment,
    inputs: &InputsAssignment,
    gens: &SNARKGens,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("SNARK::prove");

    // we create a Transcript object seeded with a random Scalar
    // to aid the prover produce its randomness
    let mut random_tape = RandomTape::new(b"proof");
    transcript.append_protocol_name(SNARK::protocol_name());
    let (r1cs_sat_proof, rx, ry) = {
      let (proof, rx, ry) = {
        // we might need to pad variables
        let padded_vars = {
          let num_padded_vars = inst.inst.get_num_vars();
          let num_vars = vars.assignment.len();
          let padded_vars = if num_padded_vars > num_vars {
            vars.pad(num_padded_vars)
          } else {
            vars
          };
          padded_vars
        };

        R1CSProof::prove(
          &inst.inst,
          padded_vars.assignment,
          &inputs.assignment,
          &gens.gens_r1cs_sat,
          transcript,
          &mut random_tape,
        )
      };

      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));

      (proof, rx, ry)
    };

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    let inst_evals = {
      let (Ar, Br, Cr) = inst.inst.evaluate(&rx, &ry);
      Ar.append_to_transcript(b"Ar_claim", transcript);
      Br.append_to_transcript(b"Br_claim", transcript);
      Cr.append_to_transcript(b"Cr_claim", transcript);
      (Ar, Br, Cr)
    };
    timer_eval.stop();

    let r1cs_eval_proof = {
      let proof = R1CSEvalProof::prove(
        &decomm.decomm,
        &rx,
        &ry,
        &inst_evals,
        &gens.gens_r1cs_eval,
        transcript,
        &mut random_tape,
      );

      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_eval_proof {:?}", proof_encoded.len()));
      proof
    };

    timer_prove.stop();
    SNARK {
      r1cs_sat_proof,
      inst_evals,
      r1cs_eval_proof,
    }
  }

  /// A method to verify the SNARK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    comm: &ComputationCommitment,
    input: &InputsAssignment,
    transcript: &mut Transcript,
    gens: &SNARKGens,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("SNARK::verify");
    transcript.append_protocol_name(SNARK::protocol_name());

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), comm.comm.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      comm.comm.get_num_vars(),
      comm.comm.get_num_cons(),
      &input.assignment,
      &self.inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;
    timer_sat_proof.stop();

    let timer_eval_proof = Timer::new("verify_eval_proof");
    let (Ar, Br, Cr) = &self.inst_evals;
    Ar.append_to_transcript(b"Ar_claim", transcript);
    Br.append_to_transcript(b"Br_claim", transcript);
    Cr.append_to_transcript(b"Cr_claim", transcript);
    assert!(self
      .r1cs_eval_proof
      .verify(
        &comm.comm,
        &rx,
        &ry,
        &self.inst_evals,
        &gens.gens_r1cs_eval,
        transcript
      )
      .is_ok());
    timer_eval_proof.stop();
    timer_verify.stop();
    Ok(())
  }
}

/// `NIZKGens` holds public parameters for producing and verifying proofs with the Spartan NIZK
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NIZKGens {
  gens_r1cs_sat: R1CSGens,
}

impl NIZKGens {
  /// Constructs a new `NIZKGens` given the size of the R1CS statement
  pub fn new(num_cons: usize, num_vars: usize, num_inputs: usize) -> Self {
    let num_vars_padded = {
      let mut num_vars_padded = max(num_vars, num_inputs + 1);
      if num_vars_padded != num_vars_padded.next_power_of_two() {
        num_vars_padded = num_vars_padded.next_power_of_two();
      }
      num_vars_padded
    };

    let gens_r1cs_sat = R1CSGens::new(b"gens_r1cs_sat", num_cons, num_vars_padded);
    NIZKGens { gens_r1cs_sat }
  }
}

/// `NIZK` holds a proof produced by Spartan NIZK
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchedNIZK {
  pub r1cs_sat_proof: Vec<R1CSProof>,
  r: (Vec<Scalar>, Vec<Scalar>),
}

impl BatchedNIZK {
  fn protocol_name() -> &'static [u8] {
    b"Spartan NIZK proof"
  }

  pub fn batched_prove(
    inst: &Instance,
    vars_list: Vec<VarsAssignment>,
    input_list: Vec<InputsAssignment>,
    gens: &NIZKGens,
    transcript: TranscriptWrapper,
  ) -> Self {
    assert!(vars_list.len() > 0);
    assert!(vars_list.len() == input_list.len());
    // top function that starts the batching
    let timer_prove = Timer::new("NIZK::prove");
    // we create a Transcript object seeded with a random Scalar
    // to aid the prover produce its randomness
    let barrier = Arc::new(Barrier::new(vars_list.len()));
    let current_transcripts = Arc::new(Mutex::new(vec![Transcript::new(b"null"); vars_list.len()]));
    let mut handles = Vec::new();
    for idx in 0..vars_list.len() {
      let vars = vars_list[idx].clone();
      let input = input_list[idx].clone();
      let current_transcripts = current_transcripts.clone();
      let barrier = barrier.clone();
      let mut transcript = transcript.clone();
      let inst = inst.clone();
      let gens = gens.clone();
      let handle = thread::spawn(move || {
        // let mut transcript = transcript.clone();
        let mut random_tape = RandomTape::new(b"proof");
        transcript.trans.append_protocol_name(NIZK::protocol_name());
        let (r1cs_sat_proof, rx, ry) = {
          // we might need to pad variables
          let padded_vars = {
            let num_padded_vars = inst.inst.get_num_vars();
            let num_vars = vars.assignment.len();
            let padded_vars = if num_padded_vars > num_vars {
              vars.pad(num_padded_vars)
            } else {
              vars
            };
            padded_vars
          };

          let (proof, rx, ry) = R1CSProof::batch_prove(
            &inst.inst,
            padded_vars.assignment,
            input.assignment,
            &gens.gens_r1cs_sat,
            &mut transcript.clone(),
            &mut random_tape,
            barrier,
            current_transcripts,
            idx.clone(),
          );
          let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
          Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
          // println!("rx {:?}", rx);
          // println!("ry {:?}", ry);
          (proof, rx, ry)
        };
        // proofs.push(NIZK {
        //   r1cs_sat_proof,
        //   r: (rx, ry),
        // })

        // // make it wrong for sanity check
        // let mut rx_wrong = rx.clone();
        // rx_wrong[0] = rx[1].clone();
        // println!("rx {:?}", rx);
        // println!("rx_wrong {:?}", rx_wrong);

        (r1cs_sat_proof, rx, ry)
      });
      handles.push(handle);
    }

    let mut results = Vec::<(R1CSProof, Vec<Scalar>, Vec<Scalar>)>::new();
    for handle in handles {
      let result = handle.join().unwrap();
      results.push(result);
    }

    // rx and ry should be all equal
    let ok = results
        .iter()
        .all(|x| x.1 == results[0].1 && x.2 == results[0].2 );
    assert!(ok);


    timer_prove.stop();
    BatchedNIZK { r1cs_sat_proof: results.iter().map(|x| x.0.clone()).collect(), r: ((results[0].1.clone(), results[0].2.clone())) }
  }

  pub fn batched_verify(
    &self,
    inst: &Instance,
    input_list: Vec<InputsAssignment>,
    transcript: TranscriptWrapper,
    gens: &NIZKGens,
  ) -> bool {

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    // let eval_timer = Instant::now();
    let (claimed_rx, claimed_ry) = &self.r;
    let inst_evals = inst.inst.evaluate(claimed_rx, claimed_ry);
    // let inst_evals = (Scalar::zero(), Scalar::zero(), Scalar::zero());
    // println!("eval takes {}", eval_timer.elapsed().as_millis());

    // let sat_timer = Instant::now();
    let barrier = Arc::new(Barrier::new(self.r1cs_sat_proof.len()));
    let current_transcripts = Arc::new(Mutex::new(vec![Transcript::new(b"null"); self.r1cs_sat_proof.len()]));
    let mut handles = Vec::new();
    let num_vars = inst.inst.get_num_vars();
    let num_cons = inst.inst.get_num_cons();
    for idx in 0..self.r1cs_sat_proof.len() {
      let current_transcripts = current_transcripts.clone();
      let barrier = barrier.clone();
      let mut transcript = transcript.clone();
      let gens = gens.clone();
      let input = input_list[idx].clone();
      let proof = self.r1cs_sat_proof[idx].clone();
      let claimed_rx = claimed_rx.clone();
      let claimed_ry = claimed_ry.clone();
      assert_eq!(input.assignment.len(), inst.inst.get_num_inputs());
      let handle = thread::spawn(move || {
        transcript.trans.append_protocol_name(NIZK::protocol_name());
        let (rx, ry) = proof.batch_verify(
          num_vars,
          num_cons,
          &input.assignment,
          &inst_evals,
          &mut transcript,
          &gens.gens_r1cs_sat,
          barrier.clone(),
          current_transcripts.clone(),
          idx
        ).unwrap();
        // verify if claimed rx and ry are correct
        assert_eq!(rx, claimed_rx);
        assert_eq!(ry, claimed_ry);
        // println!("is it equal?");
      });
      handles.push(handle);
    }

    let mut res = Ok(());

    for handle in handles {
      res = res.and(handle.join());
    }
    
    // println!("sat verify takes {}", sat_timer.elapsed().as_millis());

    res.is_ok()
  }


  pub fn batched_verify_test(
    &self,
    inst: &Instance,
    input_list: Vec<InputsAssignment>,
    transcript: TranscriptWrapper,
    gens: &NIZKGens,
  ) -> bool {
    let (claimed_rx, claimed_ry) = &self.r;
    let inst_evals = inst.inst.evaluate_test(claimed_rx, claimed_ry);

    let barrier = Arc::new(Barrier::new(self.r1cs_sat_proof.len()));
    let current_transcripts = Arc::new(Mutex::new(vec![Transcript::new(b"null"); self.r1cs_sat_proof.len()]));
    let mut handles = Vec::new();
    let num_vars = inst.inst.get_num_vars();
    let num_cons = inst.inst.get_num_cons();
    for idx in 0..self.r1cs_sat_proof.len() {
      let current_transcripts = current_transcripts.clone();
      let barrier = barrier.clone();
      let mut transcript = transcript.clone();
      let gens = gens.clone();
      let input = input_list[idx].clone();
      let proof = self.r1cs_sat_proof[idx].clone();
      let claimed_rx = claimed_rx.clone();
      let claimed_ry = claimed_ry.clone();
      assert_eq!(input.assignment.len(), inst.inst.get_num_inputs());
      let handle = thread::spawn(move || {
        transcript.trans.append_protocol_name(NIZK::protocol_name());
        let (rx, ry) = proof.batch_verify(
          num_vars,
          num_cons,
          &input.assignment,
          &inst_evals,
          &mut transcript,
          &gens.gens_r1cs_sat,
          barrier.clone(),
          current_transcripts.clone(),
          idx
        ).unwrap();
        // verify if claimed rx and ry are correct
        assert_eq!(rx, claimed_rx);
        assert_eq!(ry, claimed_ry);
        // println!("is it equal?");
      });
      handles.push(handle);
    }

    let mut res = Ok(());

    for handle in handles {
      res = res.and(handle.join());
    }
    
    // println!("sat verify takes {}", sat_timer.elapsed().as_millis());

    res.is_ok()
  }

}

/// `NIZK` holds a proof produced by Spartan NIZK
#[derive(Serialize, Deserialize, Debug)]
pub struct NIZK {
  r1cs_sat_proof: R1CSProof,
  r: (Vec<Scalar>, Vec<Scalar>),
}

impl NIZK {
  fn protocol_name() -> &'static [u8] {
    b"Spartan NIZK proof"
  }

  /// A method to produce a NIZK proof of the satisfiability of an R1CS instance
  pub fn prove(
    inst: &Instance,
    vars: VarsAssignment,
    input: &InputsAssignment,
    gens: &NIZKGens,
    transcript: &mut Transcript,
  ) -> Self {
    let timer_prove = Timer::new("NIZK::prove");
    // we create a Transcript object seeded with a random Scalar
    // to aid the prover produce its randomness
    let mut random_tape = RandomTape::new(b"proof");
    transcript.append_protocol_name(NIZK::protocol_name());
    let (r1cs_sat_proof, rx, ry) = {
      // we might need to pad variables
      let padded_vars = {
        let num_padded_vars = inst.inst.get_num_vars();
        let num_vars = vars.assignment.len();
        let padded_vars = if num_padded_vars > num_vars {
          vars.pad(num_padded_vars)
        } else {
          vars
        };
        padded_vars
      };

      let (proof, rx, ry) = R1CSProof::prove(
        &inst.inst,
        padded_vars.assignment,
        &input.assignment,
        &gens.gens_r1cs_sat,
        transcript,
        &mut random_tape,
      );
      let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();
      Timer::print(&format!("len_r1cs_sat_proof {:?}", proof_encoded.len()));
      (proof, rx, ry)
    };

    timer_prove.stop();
    NIZK {
      r1cs_sat_proof,
      r: (rx, ry),
    }
  }

  /// A method to verify a NIZK proof of the satisfiability of an R1CS instance
  pub fn verify(
    &self,
    inst: &Instance,
    input: &InputsAssignment,
    transcript: &mut Transcript,
    gens: &NIZKGens,
  ) -> Result<(), ProofVerifyError> {
    let timer_verify = Timer::new("NIZK::verify");

    transcript.append_protocol_name(NIZK::protocol_name());

    // We send evaluations of A, B, C at r = (rx, ry) as claims
    // to enable the verifier complete the first sum-check
    let timer_eval = Timer::new("eval_sparse_polys");
    let (claimed_rx, claimed_ry) = &self.r;
    let inst_evals = inst.inst.evaluate(claimed_rx, claimed_ry);
    timer_eval.stop();

    let timer_sat_proof = Timer::new("verify_sat_proof");
    assert_eq!(input.assignment.len(), inst.inst.get_num_inputs());
    let (rx, ry) = self.r1cs_sat_proof.verify(
      inst.inst.get_num_vars(),
      inst.inst.get_num_cons(),
      &input.assignment,
      &inst_evals,
      transcript,
      &gens.gens_r1cs_sat,
    )?;

    // verify if claimed rx and ry are correct
    assert_eq!(rx, *claimed_rx);
    assert_eq!(ry, *claimed_ry);
    timer_sat_proof.stop();
    timer_verify.stop();

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  pub fn check_snark() {
    let num_vars = 256;
    let num_cons = num_vars;
    let num_inputs = 10;

    // produce public generators
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_cons);

    // produce a synthetic R1CSInstance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // create a commitment to R1CSInstance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof
    let mut prover_transcript = Transcript::new(b"example");
    let proof = SNARK::prove(&inst, &decomm, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof
    let mut verifier_transcript = Transcript::new(b"example");
    assert!(proof
      .verify(&comm, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }

  #[test]
  pub fn check_r1cs_invalid_index() {
    let num_cons = 4;
    let num_vars = 8;
    let num_inputs = 1;

    let zero: [u8; 32] = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,
    ];

    let A = vec![(0, 0, zero)];
    let B = vec![(100, 1, zero)];
    let C = vec![(1, 1, zero)];

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    assert_eq!(inst.is_err(), true);
    assert_eq!(inst.err(), Some(R1CSError::InvalidIndex));
  }

  #[test]
  pub fn check_r1cs_invalid_scalar() {
    let num_cons = 4;
    let num_vars = 8;
    let num_inputs = 1;

    let zero: [u8; 32] = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,
    ];

    let larger_than_mod = [
      3, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8, 216,
      57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
    ];

    let A = vec![(0, 0, zero)];
    let B = vec![(1, 1, larger_than_mod)];
    let C = vec![(1, 1, zero)];

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    assert_eq!(inst.is_err(), true);
    assert_eq!(inst.err(), Some(R1CSError::InvalidScalar));
  }

  #[test]
  fn test_padded_constraints() {
    // parameters of the R1CS instance
    let num_cons = 1;
    let num_vars = 0;
    let num_inputs = 3;
    let num_non_zero_entries = 3;

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    // Create a^2 + b + 13
    A.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
    B.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
    C.push((0, num_vars + 1, Scalar::one().to_bytes())); // 1*z
    C.push((0, num_vars, (-Scalar::from(13u64)).to_bytes())); // -13*1
    C.push((0, num_vars + 3, (-Scalar::one()).to_bytes())); // -1*b

    // Var Assignments (Z_0 = 16 is the only output)
    let vars = vec![Scalar::zero().to_bytes(); num_vars];

    // create an InputsAssignment (a = 1, b = 2)
    let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
    inputs[0] = Scalar::from(16u64).to_bytes();
    inputs[1] = Scalar::from(1u64).to_bytes();
    inputs[2] = Scalar::from(2u64).to_bytes();

    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // Check if instance is satisfiable
    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert_eq!(res.unwrap(), true, "should be satisfied");

    // SNARK public params
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a SNARK
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
      &inst,
      &decomm,
      assignment_vars.clone(),
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the SNARK
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());

    // NIZK public params
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // produce a NIZK
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(
      &inst,
      assignment_vars,
      &assignment_inputs,
      &gens,
      &mut prover_transcript,
    );

    // verify the NIZK
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());
  }
}

#[test]
fn test_batched_prove() {
  // parameters of the R1CS instance
  let num_cons = 1024 * 32;
  let num_vars = 0;
  let num_inputs = 3;
  let num_non_zero_entries = 3;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  // Create a^2 + b + 13
  A.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
  B.push((0, num_vars + 2, Scalar::one().to_bytes())); // 1*a
  C.push((0, num_vars + 1, Scalar::one().to_bytes())); // 1*z
  C.push((0, num_vars, (-Scalar::from(13u64)).to_bytes())); // -13*1
  C.push((0, num_vars + 3, (-Scalar::one()).to_bytes())); // -1*b

  // Var Assignments (Z_0 = 16 is the only output)
  let vars = vec![Scalar::zero().to_bytes(); num_vars];

  // create an InputsAssignment (a = 1, b = 2)
  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
  inputs[0] = Scalar::from(16u64).to_bytes();
  inputs[1] = Scalar::from(1u64).to_bytes();
  inputs[2] = Scalar::from(2u64).to_bytes();

  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // Check if instance is satisfiable
  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true, "should be satisfied");

  let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

  // produce a NIZK
  let batch_size = 8;
  let mut prover_transcript = Transcript::new(b"nizk_example");
  let timer = Instant::now();
  let proof = BatchedNIZK::batched_prove(
    &inst,
    vec![assignment_vars; batch_size],
    vec![assignment_inputs.clone(); batch_size],
    &gens,
    TranscriptWrapper {
      trans: prover_transcript,
    },
  );
  println!("prove takes {}", timer.elapsed().as_millis());
  let mut verifier_transcript = Transcript::new(b"nizk_example");
  let timer = Instant::now();
  let verify_ok = proof
    .batched_verify(&inst, vec![assignment_inputs; batch_size], TranscriptWrapper { trans: verifier_transcript }, &gens);
  println!("verify_ok {}", verify_ok);
  println!("verify takes {}", timer.elapsed().as_millis());
  assert!(verify_ok);

  // let proof = NIZK::prove(
  //   &inst,
  //   assignment_vars,
  //   &assignment_inputs,
  //   &gens,
  //   &mut prover_transcript,
  // );
  // verify the NIZK
  // let mut verifier_transcript = Transcript::new(b"nizk_example");
  // assert!(proof
  //   .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
  //   .is_ok());
}

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

#[no_mangle]
pub extern "C" fn nizk_test(
  matrixs: SpartanR1CSMatrixs,
  var_assignment: SpartanAssignment,
  input_assignment: SpartanAssignment,
  num_constraints: usize,
) {
  let my_vars = &var_assignment;
  let my_inputs = &input_assignment;

  let my_matrix_A = matrixs.A.to_vec();
  let my_matrix_B = matrixs.B.to_vec();
  let my_matrix_C = matrixs.C.to_vec();

  let gens = NIZKGens::new(num_constraints, var_assignment.size, input_assignment.size);
  let inst = Instance::new(
    num_constraints,
    var_assignment.size,
    input_assignment.size,
    &my_matrix_A,
    &my_matrix_B,
    &my_matrix_C,
  )
  .unwrap();
  let assignment_vars = VarsAssignment::new(&my_vars.to_vec()).unwrap();
  let assignment_inputs = InputsAssignment::new(&my_inputs.to_vec()).unwrap();
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);
  println!("Looks like the assignment satisfies!");
  // Create proof
  let mut prover_transcript = Transcript::new(b"zkmb_proof");
  let proof_time = Instant::now(); // start time of proof
  let proof = NIZK::prove(
    &inst,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );
  println!("Done with NIZK proof generation!");
  println!("NIZK proof took {}", proof_time.elapsed().as_millis()); // end time

  // Verify proof
  let mut verifier_transcript = Transcript::new(b"zkmb_proof");
  let verif_time = Instant::now();
  assert!(proof
    .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  println!("NIZK proof verification successful!");
  println!("NIZK verif took {}", verif_time.elapsed().as_millis());

  // // try SNARK prove (not NIZK)

  // let gens2 = SNARKGens::new(num_constraints, var_assignment.size, input_assignment.size, num_non_zero_entries_b);
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

fn write_to_path(path: *mut libc::c_char, contents: Vec<u8>) {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  fs::write(path, contents).expect("Unable to write file");
}

// Bridge SNARK
#[no_mangle]
pub extern "C" fn snark_generate(
  matrixs: SpartanR1CSMatrixs,
  var_assignment: SpartanAssignment,
  input_assignment: SpartanAssignment,
  num_constraints: usize,
  gens_path: *mut libc::c_char,
  inst_path: *mut libc::c_char,
  comm_path: *mut libc::c_char,
  decomm_path: *mut libc::c_char,
) {
  let gens = SNARKGens::new(
    num_constraints,
    var_assignment.size,
    input_assignment.size,
    matrixs.num_non_zero_entries,
  );
  let matrix_A = matrixs.A.to_vec();
  let matrix_B = matrixs.B.to_vec();
  let matrix_C = matrixs.C.to_vec();
  let inst = Instance::new(
    num_constraints,
    var_assignment.size,
    input_assignment.size,
    &matrix_A,
    &matrix_B,
    &matrix_C,
  )
  .unwrap();
  let (comm, decomm) = SNARK::encode(&inst, &gens);
  let gens_encoded = bincode::serialize(&gens).unwrap();
  write_to_path(gens_path, gens_encoded);
  println!("snark check 1");
  let inst_encoded = bincode::serialize(&inst).unwrap();
  write_to_path(inst_path, inst_encoded);
  println!("snark check 2");
  let comm_encoded = bincode::serialize(&comm).unwrap();
  write_to_path(comm_path, comm_encoded);
  println!("snark check 3");
  let decomm_encoded = bincode::serialize(&decomm).unwrap();
  write_to_path(decomm_path, decomm_encoded);
  println!("snark check 4");
}

#[no_mangle]
pub extern "C" fn snark_read_gens(path: *mut libc::c_char) -> *mut SNARKGens {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read(path).expect("Unable to read gens");
  let result: SNARKGens = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub extern "C" fn snark_read_inst(path: *mut libc::c_char) -> *mut Instance {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read(path).expect("Unable to read inst");
  let result: Instance = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub extern "C" fn snark_read_comm(path: *mut libc::c_char) -> *mut ComputationCommitment {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read(path).expect("Unable to read comm");
  let result: ComputationCommitment = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub extern "C" fn snark_read_decomm(path: *mut libc::c_char) -> *mut ComputationDecommitment {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read(path).expect("Unable to read decomm");
  let result: ComputationDecommitment = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub extern "C" fn snark_read_proof(path: *mut libc::c_char) -> *mut SNARK {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read("r1cs_proof").expect("Unable to read proof");
  let result: SNARK = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(result))
}

#[no_mangle]
pub extern "C" fn snark_prove(
  gens: *mut SNARKGens,
  inst: *mut Instance,
  decomm: *mut ComputationDecommitment,
  var_assignment: SpartanAssignment,
  input_assignment: SpartanAssignment,
  proof_path: *mut libc::c_char,
) {
  let assignment_vars = VarsAssignment::new(&var_assignment.to_vec()).unwrap();
  let assignment_inputs = InputsAssignment::new(&input_assignment.to_vec()).unwrap();
  // Box::from_raw will free the memory
  let gens = unsafe { &*gens };
  let inst = unsafe { &*inst };
  let decomm = unsafe { &*decomm };
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);
  let mut prover_transcript = Transcript::new(b"zkmb_proof");
  let time = Instant::now();
  let proof = SNARK::prove(
    inst,
    decomm,
    assignment_vars,
    &assignment_inputs,
    gens,
    &mut prover_transcript,
  );
  println!("SNARK proof took {}", time.elapsed().as_millis());
  let proof_encoded = bincode::serialize(&proof).unwrap();
  let proof_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(proof_path) };
  let proof_path: &str = proof_path.to_str().unwrap();
  fs::write(proof_path, proof_encoded).expect("Unable to write file");
}

#[no_mangle]
pub extern "C" fn snark_verify(
  gens: *mut SNARKGens,
  comm: *mut ComputationCommitment,
  proof: *mut SNARK,
  input_assignment: SpartanAssignment,
) -> bool {
  let assignment_inputs = InputsAssignment::new(&input_assignment.to_vec()).unwrap();
  let gens = unsafe { &*gens };
  let comm = unsafe { &*comm };
  let proof = unsafe { &*proof };
  let mut verifier_transcript = Transcript::new(b"zkmb_proof");
  let verify_time = Instant::now();
  let result = proof
    .verify(comm, &assignment_inputs, &mut verifier_transcript, gens)
    .is_ok();
  println!("NIZK verify took {}", verify_time.elapsed().as_millis());
  println!("{}", result);
  result
}

// Bridge NIZK
#[no_mangle]
pub extern "C" fn nizk_generate(
  matrixs: SpartanR1CSMatrixs,
  var_assignment: SpartanAssignment,
  input_assignment: SpartanAssignment,
  num_constraints: usize,
  gens_path: *mut libc::c_char,
  inst_path: *mut libc::c_char,
) {
  let gens = NIZKGens::new(num_constraints, var_assignment.size, input_assignment.size);
  let matrix_A = matrixs.A.to_vec();
  let matrix_B = matrixs.B.to_vec();
  let matrix_C = matrixs.C.to_vec();
  let inst = Instance::new(
    num_constraints,
    var_assignment.size,
    input_assignment.size,
    &matrix_A,
    &matrix_B,
    &matrix_C,
  )
  .unwrap();
  let gens_encoded = bincode::serialize(&gens).unwrap();
  let gens_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(gens_path) };
  let gens_path: &str = gens_path.to_str().unwrap();
  fs::write(gens_path, gens_encoded).expect("Unable to write file");
  let inst_encoded = bincode::serialize(&inst).unwrap();
  let inst_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(inst_path) };
  let inst_path: &str = inst_path.to_str().unwrap();
  fs::write(inst_path, inst_encoded).expect("Unable to write file");
}

#[no_mangle]
pub extern "C" fn nizk_read_gens(gens_path: *mut libc::c_char) -> *mut NIZKGens {
  let gens_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(gens_path) };
  let gens_path: &str = gens_path.to_str().unwrap();
  let data = fs::read(gens_path).expect("Unable to read gens");
  let gens: NIZKGens = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(gens))
}

#[no_mangle]
pub extern "C" fn nizk_read_inst(inst_path: *mut libc::c_char) -> *mut Instance {
  let inst_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(inst_path) };
  let inst_path: &str = inst_path.to_str().unwrap();
  let data = fs::read(inst_path).expect("Unable to read inst");
  let inst: Instance = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(inst))
}

#[no_mangle]
pub extern "C" fn nizk_read_proof(path: *mut libc::c_char) -> *mut NIZK {
  let path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(path) };
  let path: &str = path.to_str().unwrap();
  let data = fs::read(path).expect("Unable to read proof");
  let proof: NIZK = bincode::deserialize(&data).unwrap();
  Box::into_raw(Box::new(proof))
}

#[no_mangle]
pub extern "C" fn nizk_prove(
  gens: *mut NIZKGens,
  inst: *mut Instance,
  var_assignment: SpartanAssignment,
  input_assignment: SpartanAssignment,
  proof_path: *mut libc::c_char,
) {
  let assignment_vars = VarsAssignment::new(&var_assignment.to_vec()).unwrap();
  let assignment_inputs = InputsAssignment::new(&input_assignment.to_vec()).unwrap();
  println!("assignment_vars len {}", assignment_vars.assignment.len());
  println!(
    "assignment_inputs len {}",
    assignment_inputs.assignment.len()
  );
  // Box::from_raw will free the memory
  let gens = unsafe { &*gens };
  let inst = unsafe { &*inst };
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);
  let mut prover_transcript = Transcript::new(b"zkmb_proof");
  let proof_time = Instant::now();
  let proof = NIZK::prove(
    inst,
    assignment_vars,
    &assignment_inputs,
    gens,
    &mut prover_transcript,
  );
  println!("NIZK proof took {}", proof_time.elapsed().as_millis());
  let proof_encoded = bincode::serialize(&proof).unwrap();
  let proof_path: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(proof_path) };
  let proof_path: &str = proof_path.to_str().unwrap();
  fs::write(proof_path, proof_encoded).expect("Unable to write file");
}

#[no_mangle]
pub extern "C" fn nizk_verify(
  gens: *mut NIZKGens,
  inst: *mut Instance,
  proof: *mut NIZK,
  input_assignment: SpartanAssignment,
) -> bool {
  println!("will read assign");
  let assignment_inputs = InputsAssignment::new(&input_assignment.to_vec()).unwrap();
  println!("will read gens");
  let gens = unsafe { &*gens };
  println!("will read inst");
  let inst = unsafe { &*inst };
  println!("will read proof");
  let proof = unsafe { &*proof };
  println!("read all done");
  let mut verifier_transcript = Transcript::new(b"zkmb_proof");
  let verify_time = Instant::now();
  let result = proof
    .verify(inst, &assignment_inputs, &mut verifier_transcript, gens)
    .is_ok();
  println!("NIZK verify took {}", verify_time.elapsed().as_millis());
  println!("{}", result);
  result
}

// Bridge Struct
#[repr(C)]
pub struct Entry {
  row: usize,
  col: usize,
  element: SpartanFieldElement,
}

#[repr(C)]
pub struct SpartanFieldElement {
  val: [u8; 32],
}

#[repr(C)]
pub struct SpartanAssignment {
  val: *mut SpartanFieldElement,
  size: usize,
}

impl SpartanAssignment {
  fn to_vec(&self) -> Vec<[u8; 32]> {
    let arr = unsafe { std::slice::from_raw_parts(self.val, self.size) };
    let mut result: Vec<[u8; 32]> = Vec::new();
    for element in arr {
      result.push(element.val);
    }
    result
  }
}

#[repr(C)]
pub struct SpartanMatrix {
  val: *const Entry,
  size: usize,
}

impl SpartanMatrix {
  fn to_vec(&self) -> Vec<(usize, usize, [u8; 32])> {
    let arr = unsafe { std::slice::from_raw_parts(self.val, self.size) };
    let mut result: Vec<(usize, usize, [u8; 32])> = Vec::new();
    for entry in arr {
      result.push((entry.row, entry.col, entry.element.val));
    }
    result
  }
}

#[repr(C)]
pub struct SpartanR1CSMatrixs {
  A: SpartanMatrix,
  B: SpartanMatrix,
  C: SpartanMatrix,
  num_non_zero_entries: usize,
}
