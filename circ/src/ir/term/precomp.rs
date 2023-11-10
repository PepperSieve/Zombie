//! Non-cryptographic pre-computation.
//!
//! Conceptually, this machinery allows a party with input material for one computation to map it
//! into input material for another computation.

// use std::time::Instant;

use std::{time::Instant};

use fxhash::{FxHashMap, FxHashSet};
use itertools::Itertools;
// use std::time::{Instant};

use crate::{ir::term::*, target::r1cs::R1cs};
use smallvec::SmallVec;

/// A "precomputation".
///
/// Expresses a computation to be run in advance by a single party.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PreComp {
    /// A map from output names to the terms that compute them.
    pub outputs: FxHashMap<String, Term>,
    pub sequence: Vec<String>,
}

impl PreComp {
    /// Create a new precomputation
    pub fn new() -> Self {
        Self::default()
    }
    /// immutable access to the outputs
    pub fn outputs(&self) -> &FxHashMap<String, Term> {
        &self.outputs
    }
    /// Add a new output variable to the precomputation. `value` is the term that computes its value.
    pub fn add_output(&mut self, name: String, value: Term) {
        self.sequence.push(name.clone());
        let old = self.outputs.insert(name, value);
        assert!(old.is_none());
    }
    /// Retain only the parts of this precomputation that can be evaluated from
    /// the `known` inputs.
    pub fn restrict_to_inputs(&mut self, mut known: FxHashSet<String>) {
        let os = &mut self.outputs;
        let seq = &mut self.sequence;
        seq.retain(|o| {
            let term = os.get(o).unwrap();
            let drop = extras::free_variables(term.clone())
                .iter()
                .any(|v| !known.contains(v));
            if drop {
                os.remove(o);
            } else {
                known.insert(o.clone());
            }
            !drop
        });
    }

    /// transform Term to NumTerm
    pub fn transform_terms(
        &self,
        index_cache: &mut TermMap<usize>,
        term_arr: &mut Vec<NumTerm>,
    ) {

        for o_name in &self.sequence {
            let t = self.outputs.get(o_name).unwrap();
            let mut stack = vec![(false, t.clone())];
            while let Some((children_pushed, node)) = stack.pop() {
                if index_cache.contains_key(&node) {
                    continue;
                }
                if children_pushed {
                    let mut cs_arr = SmallVec::<[usize; 3]>::new();
                    for child in &node.cs {
                        cs_arr.push(index_cache.get(child).unwrap().clone());
                    }
                    let new_num_term = NumTerm {
                        op: NumOp::Op(node.op.clone()),
                        cs: cs_arr,
                    };
                    index_cache.insert(node, term_arr.len());
                    term_arr.push(new_num_term);
                } else {
                    stack.push((true, node.clone()));
                    for c in &node.cs {
                        if !index_cache.contains_key(c) {
                            stack.push((false, c.clone()));
                        }
                    }
                }
            }
        }
    }

    /// function
    pub fn eval(&self, env: &FxHashMap<String, Value>) -> FxHashMap<String, Value>{
        env.clone()
    }

    /// eval preprocess
    pub fn eval_preprocess_darpa(
        &self,
        r1cs: &R1cs<String>,
    ) -> (Vec<NumTerm>, Vec<usize>, Vec<usize>, TermMap<usize>) {
        let mut term_arr = Vec::<NumTerm>::new();
        let mut index_cache = TermMap::<usize>::new();
        self.transform_terms(&mut index_cache, &mut term_arr);
        for i in 0..term_arr.len() {
            if let NumOp::Op(op) = &term_arr[i].op {
                match op {
                    Op::Var(o_name, _) => {
                        if let Some(o) = self.outputs.get(o_name) {
                            let term_idx = index_cache.get(&o).unwrap().clone();
                            term_arr[i].op = NumOp::Var(term_idx);
                        }
                    }
                    _ => (),
                }
            } else {
                panic!("Op should not be transformed here!");
            }
        }
        let mut input_idxes = Vec::<usize>::new();
        let mut var_idxes = Vec::<usize>::new();
        for (cid, name) in r1cs.idxs_signals.iter().sorted() {
            let o = self.outputs.get(name).unwrap();
            let term_idx = index_cache.get(o).unwrap().clone();
            if r1cs.public_idxs.contains(&cid) {
                // println!("name {}", name);
                input_idxes.push(term_idx);
            } else {
                var_idxes.push(term_idx);
            }
        }
        (term_arr, input_idxes, var_idxes, index_cache)
    }

    /// eval preprocess
    pub fn eval_preprocess(
        &self,
        r1cs: &R1cs<String>,
    ) -> (Vec<NumTerm>, Vec<usize>, Vec<usize>) {
        let mut term_arr = Vec::<NumTerm>::new();
        let mut index_cache = TermMap::<usize>::new();
        self.transform_terms(&mut index_cache, &mut term_arr);
        for i in 0..term_arr.len() {
            if let NumOp::Op(op) = &term_arr[i].op {
                match op {
                    Op::Var(o_name, _) => {
                        if let Some(o) = self.outputs.get(o_name) {
                            let term_idx = index_cache.get(&o).unwrap().clone();
                            term_arr[i].op = NumOp::Var(term_idx);
                        }
                    }
                    _ => (),
                }
            } else {
                panic!("Op should not be transformed here!");
            }
        }
        let mut input_idxes = Vec::<usize>::new();
        let mut var_idxes = Vec::<usize>::new();
        for (cid, name) in r1cs.idxs_signals.iter().sorted() {
            let o = self.outputs.get(name).unwrap();
            let term_idx = index_cache.get(o).unwrap().clone();
            if r1cs.public_idxs.contains(&cid) {
                // println!("name {}", name);
                input_idxes.push(term_idx);
            } else {
                var_idxes.push(term_idx);
            }
        }
        (term_arr, input_idxes, var_idxes)
    }

    /// real evaluation
    pub fn real_eval(val_arr: &mut Vec<Option<Value>>, term_arr: &Vec<NumTerm>, env: &FxHashMap<String, Value>) {
        let t1 = Instant::now();
        // let mut val_arr = vec![Option::None; term_arr.len()];
        for term_idx in 0..term_arr.len() {
            eval_value_efficient(term_idx, term_arr, val_arr, env);
        }
        // println!("real eval take {}", t1.elapsed().as_millis());
    }

    /// Compute the inputs for this precomputation
    pub fn inputs_to_terms(&self) -> FxHashMap<String, Term> {
        PostOrderIter::new(term(Op::Tuple, self.outputs.values().cloned().collect()))
            .filter_map(|t| match &t.op {
                Op::Var(name, _) => Some((name.clone(), t.clone())),
                _ => None,
            })
            .collect()
    }

    /// Compute the inputs for this precomputation
    pub fn inputs(&self) -> FxHashSet<String> {
        self.inputs_to_terms().into_keys().collect()
    }

    /// Bind the outputs of `self` to the inputs of `other`.
    pub fn sequential_compose(mut self, other: &PreComp) -> PreComp {
        for o_name in &other.sequence {
            let o = other.outputs.get(o_name).unwrap().clone();
            assert!(!self.outputs.contains_key(o_name));
            self.outputs.insert(o_name.clone(), o);
            self.sequence.push(o_name.clone());
        }
        self
    }
}
