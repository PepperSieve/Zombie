use super::dense_mlpoly::DensePolynomial;
use super::errors::ProofVerifyError;
use super::math::Math;
use super::random::RandomTape;
use super::scalar::Scalar;
use super::sparse_mlpoly::{
  MultiSparseMatPolynomialAsDense, SparseMatEntry, SparseMatPolyCommitment,
  SparseMatPolyCommitmentGens, SparseMatPolyEvalProof, SparseMatPolynomial,
};
use super::timer::Timer;
use merlin::Transcript;
use rand::thread_rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct R1CSInstance {
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
  A: SparseMatPolynomial,
  B: SparseMatPolynomial,
  C: SparseMatPolynomial,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct R1CSCommitmentGens {
  gens: SparseMatPolyCommitmentGens,
}

impl R1CSCommitmentGens {
  pub fn new(
    label: &'static [u8],
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    num_nz_entries: usize,
  ) -> R1CSCommitmentGens {
    assert!(num_inputs < num_vars);
    let num_poly_vars_x = num_cons.log2();
    let num_poly_vars_y = (2 * num_vars).log2();
    let gens =
      SparseMatPolyCommitmentGens::new(label, num_poly_vars_x, num_poly_vars_y, num_nz_entries, 3);
    R1CSCommitmentGens { gens }
  }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct R1CSCommitment {
  num_cons: usize,
  num_vars: usize,
  num_inputs: usize,
  comm: SparseMatPolyCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct R1CSDecommitment {
  dense: MultiSparseMatPolynomialAsDense,
}

impl R1CSCommitment {
  pub fn get_num_cons(&self) -> usize {
    self.num_cons
  }

  pub fn get_num_vars(&self) -> usize {
    self.num_vars
  }

  pub fn get_num_inputs(&self) -> usize {
    self.num_inputs
  }
}

impl R1CSInstance {
  pub fn new(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: &Vec<(usize, usize, Scalar)>,
    B: &Vec<(usize, usize, Scalar)>,
    C: &Vec<(usize, usize, Scalar)>,
  ) -> R1CSInstance {
    Timer::print(&format!("number_of_constraints {}", num_cons));
    Timer::print(&format!("number_of_variables {}", num_vars));
    Timer::print(&format!("number_of_inputs {}", num_inputs));
    Timer::print(&format!("number_non-zero_entries_A {}", A.len()));
    Timer::print(&format!("number_non-zero_entries_B {}", B.len()));
    Timer::print(&format!("number_non-zero_entries_C {}", C.len()));

    // check that num_cons is a power of 2
    assert_eq!(num_cons.next_power_of_two(), num_cons);

    // check that num_vars is a power of 2
    assert_eq!(num_vars.next_power_of_two(), num_vars);

    // check that number_inputs + 1 <= num_vars
    assert!(num_inputs < num_vars);

    // no errors, so create polynomials
    let num_poly_vars_x = num_cons.log2();
    let num_poly_vars_y = (2 * num_vars).log2();

    let mat_A = (0..A.len())
      .map(|i| SparseMatEntry::new(A[i].0, A[i].1, A[i].2))
      .collect::<Vec<SparseMatEntry>>();
    let mat_B = (0..B.len())
      .map(|i| SparseMatEntry::new(B[i].0, B[i].1, B[i].2))
      .collect::<Vec<SparseMatEntry>>();
    let mat_C = (0..C.len())
      .map(|i| SparseMatEntry::new(C[i].0, C[i].1, C[i].2))
      .collect::<Vec<SparseMatEntry>>();

    let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, mat_A);
    let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, mat_B);
    let poly_C = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, mat_C);

    let inst = R1CSInstance {
      num_cons,
      num_vars,
      num_inputs,
      A: poly_A,
      B: poly_B,
      C: poly_C,
    };

    inst
  }

  pub fn get_num_vars(&self) -> usize {
    self.num_vars
  }

  pub fn get_num_cons(&self) -> usize {
    self.num_cons
  }

  pub fn get_num_inputs(&self) -> usize {
    self.num_inputs
  }

  pub fn produce_synthetic_r1cs(
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
  ) -> (R1CSInstance, Vec<Scalar>, Vec<Scalar>) {
    Timer::print(&format!("number_of_constraints {}", num_cons));
    Timer::print(&format!("number_of_variables {}", num_vars));
    Timer::print(&format!("number_of_inputs {}", num_inputs));

    // assert num_cons and num_vars are power of 2
    assert_eq!(num_cons.log2().pow2(), num_cons);
    assert_eq!(num_vars.log2().pow2(), num_vars);

    // num_inputs + 1 <= num_vars
    assert!(num_inputs < num_vars);

    // z is organized as [vars,1,io]
    let size_z = num_vars + num_inputs + 1;

    // produce a random satisfying assignment
    let Z = {
      let mut Z: Vec<Scalar> = (0..size_z)
        .into_par_iter()
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect();
      Z[num_vars] = Scalar::one(); // set the constant term to 1
      Z
    };

    // three sparse matrices
    let one = Scalar::one();
    let A: Vec<SparseMatEntry> = {
      (0..num_cons)
        .into_par_iter()
        .map(|i| {
          let A_idx = i % size_z;
          SparseMatEntry::new(i, A_idx, one)
        })
        .collect()
    };

    let B: Vec<SparseMatEntry> = {
      (0..num_cons)
        .into_par_iter()
        .map(|i| {
          let B_idx = (i + 2) % size_z;
          SparseMatEntry::new(i, B_idx, one)
        })
        .collect()
    };

    let C: Vec<SparseMatEntry> = {
      (0..num_cons)
        .into_par_iter()
        .map(|i| {
          let A_idx = i % size_z;
          let B_idx = (i + 2) % size_z;
          let AB_val = Z[A_idx] * Z[B_idx];

          let C_idx = (i + 3) % size_z;
          let C_val = Z[C_idx];

          if C_val == Scalar::zero() {
            SparseMatEntry::new(i, num_vars, AB_val)
          } else {
            SparseMatEntry::new(i, C_idx, AB_val * C_val.invert().unwrap())
          }
        })
        .collect()
    };

    Timer::print(&format!("number_non-zero_entries_A {}", A.len()));
    Timer::print(&format!("number_non-zero_entries_B {}", B.len()));
    Timer::print(&format!("number_non-zero_entries_C {}", C.len()));

    let num_poly_vars_x = num_cons.log2();
    let num_poly_vars_y = (2 * num_vars).log2();
    let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, A);
    let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, B);
    let poly_C = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, C);

    let inst = R1CSInstance {
      num_cons,
      num_vars,
      num_inputs,
      A: poly_A,
      B: poly_B,
      C: poly_C,
    };

    assert_eq!(
      inst.is_sat(&Z[..num_vars].to_vec(), &Z[num_vars + 1..].to_vec()),
      true,
    );

    (inst, Z[..num_vars].to_vec(), Z[num_vars + 1..].to_vec())
  }

  pub fn is_sat(&self, vars: &[Scalar], input: &[Scalar]) -> bool {
    assert_eq!(vars.len(), self.num_vars);
    assert_eq!(input.len(), self.num_inputs);

    let z = {
      let mut z = vars.to_vec();
      z.extend(&vec![Scalar::one()]);
      z.extend(input);
      z
    };

    // verify if Az * Bz - Cz = [0...]
    let Az = self
      .A
      .multiply_vec(self.num_cons, self.num_vars + self.num_inputs + 1, &z);
    let Bz = self
      .B
      .multiply_vec(self.num_cons, self.num_vars + self.num_inputs + 1, &z);
    let Cz = self
      .C
      .multiply_vec(self.num_cons, self.num_vars + self.num_inputs + 1, &z);

    assert_eq!(Az.len(), self.num_cons);
    assert_eq!(Bz.len(), self.num_cons);
    assert_eq!(Cz.len(), self.num_cons);
    let res: usize = (0..self.num_cons)
      .map(|i| if Az[i] * Bz[i] == Cz[i] { 0 } else { 1 })
      .sum();

    res == 0
  }

  pub fn multiply_vec(
    &self,
    num_rows: usize,
    num_cols: usize,
    z: &[Scalar],
  ) -> (DensePolynomial, DensePolynomial, DensePolynomial) {
    assert_eq!(num_rows, self.num_cons);
    assert_eq!(z.len(), num_cols);
    assert!(num_cols > self.num_vars);

    let (A, (B, C)) = rayon::join(
      || DensePolynomial::new(self.A.multiply_vec(num_rows, num_cols, z)),
      || {
        rayon::join(
          || DensePolynomial::new(self.B.multiply_vec(num_rows, num_cols, z)),
          || DensePolynomial::new(self.C.multiply_vec(num_rows, num_cols, z)),
        )
      },
    );

    (A, B, C)
  }

  pub fn compute_eval_table_sparse(
    &self,
    num_rows: usize,
    num_cols: usize,
    evals: &[Scalar],
  ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
    assert_eq!(num_rows, self.num_cons);
    assert!(num_cols > self.num_vars);

    let (evals_A, (evals_B, evals_C)) = rayon::join(
      || self.A.compute_eval_table_sparse(evals, num_rows, num_cols),
      || {
        rayon::join(
          || self.B.compute_eval_table_sparse(evals, num_rows, num_cols),
          || self.C.compute_eval_table_sparse(evals, num_rows, num_cols),
        )
      },
    );

    (evals_A, evals_B, evals_C)
  }

  pub fn evaluate(&self, rx: &[Scalar], ry: &[Scalar]) -> (Scalar, Scalar, Scalar) {
    let evals = SparseMatPolynomial::multi_evaluate(&[&self.A, &self.B, &self.C], rx, ry);
    (evals[0], evals[1], evals[2])
  }

  pub fn evaluate_test(&self, rx: &[Scalar], ry: &[Scalar]) -> (Scalar, Scalar, Scalar) {
    let evals = SparseMatPolynomial::multi_evaluate_test(&[&self.A, &self.B, &self.C], rx, ry);
    (evals[0], evals[1], evals[2])
  }

  pub fn commit(&self, gens: &R1CSCommitmentGens) -> (R1CSCommitment, R1CSDecommitment) {
    let (comm, dense) = SparseMatPolynomial::multi_commit(&[&self.A, &self.B, &self.C], &gens.gens);
    let r1cs_comm = R1CSCommitment {
      num_cons: self.num_cons,
      num_vars: self.num_vars,
      num_inputs: self.num_inputs,
      comm,
    };

    let r1cs_decomm = R1CSDecommitment { dense };

    (r1cs_comm, r1cs_decomm)
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct R1CSEvalProof {
  proof: SparseMatPolyEvalProof,
}

impl R1CSEvalProof {
  pub fn prove(
    decomm: &R1CSDecommitment,
    rx: &[Scalar], // point at which the polynomial is evaluated
    ry: &[Scalar],
    evals: &(Scalar, Scalar, Scalar),
    gens: &R1CSCommitmentGens,
    transcript: &mut Transcript,
    random_tape: &mut RandomTape,
  ) -> R1CSEvalProof {
    let timer = Timer::new("R1CSEvalProof::prove");
    let proof = SparseMatPolyEvalProof::prove(
      &decomm.dense,
      rx,
      ry,
      &[evals.0, evals.1, evals.2],
      &gens.gens,
      transcript,
      random_tape,
    );
    timer.stop();

    R1CSEvalProof { proof }
  }

  pub fn verify(
    &self,
    comm: &R1CSCommitment,
    rx: &[Scalar], // point at which the R1CS matrix polynomials are evaluated
    ry: &[Scalar],
    evals: &(Scalar, Scalar, Scalar),
    gens: &R1CSCommitmentGens,
    transcript: &mut Transcript,
  ) -> Result<(), ProofVerifyError> {
    assert!(self
      .proof
      .verify(
        &comm.comm,
        rx,
        ry,
        &[evals.0, evals.1, evals.2],
        &gens.gens,
        transcript
      )
      .is_ok());

    Ok(())
  }
}
