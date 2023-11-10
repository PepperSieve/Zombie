//! Export circ R1cs to Spartan
use circ_fields::bigint_to_int;
use ark_ff::PrimeField;
use fxhash::FxHashMap;
use itertools::Itertools;
use libspartan::*;
use crate::target::r1cs::*;
use curve25519_dalek::scalar::Scalar;
use rug::{Integer};
use core::clone::Clone;
use std::collections::HashMap;
use gmp_mpfr_sys::gmp::limb_t;
// use fxhash::FxHashMap;

struct Variable {
    sid: usize,
    value: [u8; 32],
}

/// transform r1cs to spartan instance
#[allow(non_snake_case)]
pub fn get_spartan_instance(r1cs: &R1cs::<String>) -> Instance {
    let input_num = r1cs.public_idxs.len();
    let var_num = r1cs.idxs_signals.len() - input_num;
    // map from circ id to spartan id
    // Spartan: (vars, constant, inputs)
    let mut cid_sid_map = HashMap::<usize, usize>::default();
    let mut input_count = 0;
    let mut var_count = 0;
    for (cid, _) in r1cs.idxs_signals.iter().sorted() {
        if r1cs.public_idxs.contains(&cid) {
            let sid = var_num + input_count + 1;
            cid_sid_map.insert(cid.clone(), sid);
            input_count += 1;
        } else {
            let sid = var_count;
            cid_sid_map.insert(cid.clone(), sid);
            var_count += 1;
        }
    }

    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let mut i = 0; // constraint #
    for (lc_a, lc_b, lc_c) in r1cs.constraints() {

        // circ Lc (const, monomials <Integer>) -> Vec<Integer> -> Vec<Variable>
        let a = lc_to_v(&lc_a, var_num, &cid_sid_map);
        let b = lc_to_v(&lc_b, var_num, &cid_sid_map);
        let c = lc_to_v(&lc_c, var_num, &cid_sid_map);

        // constraint # x identifier (vars, 1, inp)
        for Variable { sid, value } in a {
            A.push((i, sid, value));
        }
        for Variable { sid, value } in b {
            B.push((i, sid, value));
        }
        for Variable { sid, value } in c {
            C.push((i, sid, value));
        }

        i += 1;
    }

    Instance::new(r1cs.constraints().len(), var_num, input_num, &A, &B, &C).unwrap()
}

/// transform assignment to spartan assignment
pub fn get_spartan_assignment(input_idxes: &Vec<usize>, var_idxes: &Vec<usize>, val_arr: &Vec<Option<Value>>) -> (Assignment, Assignment) {
    let mut input_assignment = Vec::<[u8; 32]>::new();
    let mut var_assignment = Vec::<[u8; 32]>::new();
    for idx in input_idxes {
        if let Some(v) = &val_arr[idx.clone()] {
            input_assignment.push(value_to_scalar(v));
        } else {
            panic!("variable missing!");
        }
    }
    for idx in var_idxes {
        if let Some(v) = &val_arr[idx.clone()] {
            var_assignment.push(value_to_scalar(v));
        } else {
            panic!("variable missing!");
        }
    }
    (Assignment::new(&var_assignment).unwrap(), Assignment::new(&input_assignment).unwrap())
}

/// transform public witness to spartan assignment
pub fn get_spartan_public_assignment(input_names: &Vec<String>, input_map: &FxHashMap<String, Value>) -> Assignment {

    let mut assignment = Vec::new();
    for name in input_names {
        match input_map.get(name) {
            Some(v) => assignment.push(value_to_scalar(v)),
            None => panic!("Name {} not exists", name),
        }
    }
    Assignment::new(&assignment).unwrap()
}

fn int_to_scalar(i: &Integer) -> Scalar {
    let mut accumulator = Scalar::zero();
    let limb_bits = (std::mem::size_of::<limb_t>() as u64) << 3;
    assert_eq!(limb_bits, 64);

    let two: u64 = 2;
    let mut m = Scalar::from(two.pow(63) as u64);
    m = m * Scalar::from(2 as u64);
    //println!("in int2scal i={:#?}", i);

    // as_ref yeilds a least-significant-first array.
    for digit in i.as_ref().iter().rev() {
        // println!("digit: {:#?}", digit);
        accumulator *= m;
        accumulator += Scalar::from(*digit as u64);
    }
    return accumulator;
}

fn fieldv_to_scalar(fieldv: &FieldV) -> [u8; 32] {
    match fieldv {
        FieldV::FCurve25519(value) => {
            let i = value.0.into_bigint();
            let array_map = i.0.iter().map(|limb| limb.to_le_bytes());
            let mut res = [0; 32];
            let mut current = 0;
            for limb in array_map {
                for n in limb {
                    res[current] = n;
                    current += 1;
                }
            }
            res
        },
        FieldV::FBls12381(_) => unimplemented!(),
        FieldV::FBn254(_) => unimplemented!(),
        FieldV::IntField(_) => unimplemented!(),
    }
}

fn value_to_scalar(value: &Value) -> [u8; 32] {
    match value {
        Value::Field(fieldv) => {
            fieldv_to_scalar(fieldv)
        },
        _ => unimplemented!()
    }
}

fn lc_to_v(lc: &Lc, const_id: usize, cid_sid_map: &HashMap::<usize, usize>) -> Vec<Variable> {
    let mut v: Vec<Variable> = Vec::new();

    for (cid,coeff) in &lc.monomials {
        let scalar = fieldv_to_scalar(&coeff);
        // println!("scalar is: {:#?}", scalar.to_bytes());
        let var = Variable {
            sid: cid_sid_map.get(cid).unwrap().clone(),
            value: scalar,
        };
        v.push(var);
    }
    if !lc.constant.is_zero() {
        let scalar = fieldv_to_scalar(&lc.constant);
        let var = Variable {
            sid: const_id,
            value: scalar,
        };
        v.push(var);
    }
    v
}