//! Optimizations
pub mod binarize;
pub mod cfold;
pub mod flat;
pub mod inline;
pub mod mem;
pub mod scalarize_vars;
pub mod sha;
pub mod tuple;
mod visit;

use super::term::{*, precomp::PreComp};

use log::debug;

#[derive(Clone, Debug)]
/// An optimization pass
pub enum Opt {
    /// Convert non-scalar (tuple, array) inputs to scalar ones
    /// The scalar variable names are suffixed with .N, where N indicates the array/tuple position
    ScalarizeVars,
    /// Fold constants
    ConstantFold(Box<[Op]>),
    /// Flatten n-ary operators
    Flatten,
    /// Binarize n-ary operators
    Binarize,
    /// SHA-2 peephole optimizations
    Sha,
    /// Replace oblivious arrays with tuples
    Obliv,
    /// Replace arrays with linear scans
    LinearScan,
    /// Extract top-level ANDs as distinct outputs
    FlattenAssertions,
    /// Find outputs like `(= variable term)`, and substitute out `variable`
    Inline,
    /// Eliminate tuples
    Tuple,
}

/// Run optimizations on `cs`, in this order, returning the new constraint system.
pub fn opt<I: IntoIterator<Item = Opt>>(mut cs: Computation, optimizations: I) -> Computation {
    for i in optimizations {
        debug!("Applying: {:?}", i);
        match i.clone() {
            Opt::ScalarizeVars => {
                scalarize_vars::scalarize_inputs(&mut cs);
            }
            Opt::ConstantFold(ignore) => {
                // lock the collector because fold_cache locks TERMS
                let _lock = super::term::COLLECT.read().unwrap();
                let mut cache = TermCache::new(TERM_CACHE_LIMIT);
                for a in &mut cs.outputs {
                    // allow unbounded size during a single fold_cache call
                    cache.resize(std::usize::MAX);
                    *a = cfold::fold_cache(a, &mut cache, &*ignore.clone());
                    // then shrink back down to size between calls
                    cache.resize(TERM_CACHE_LIMIT);
                }
            }
            Opt::Sha => {
                for a in &mut cs.outputs {
                    *a = sha::sha_rewrites(a);
                }
            }
            Opt::Obliv => {
                mem::obliv::elim_obliv(&mut cs);
            }
            Opt::LinearScan => {
                mem::lin::linearize(&mut cs);
            }
            Opt::FlattenAssertions => {
                let mut new_outputs = Vec::new();
                for a in std::mem::take(&mut cs.outputs) {
                    assert_eq!(check(&a), Sort::Bool, "Non-bool in {:?}", i);
                    if a.op == Op::BoolNaryOp(BoolNaryOp::And) {
                        new_outputs.extend(a.cs.iter().cloned());
                    } else {
                        new_outputs.push(a)
                    }
                }
                cs.outputs = new_outputs;
            }
            Opt::Flatten => {
                let mut cache = flat::Cache::new();
                for a in &mut cs.outputs {
                    *a = flat::flatten_nary_ops_cached(a.clone(), &mut cache);
                }
            }
            Opt::Binarize => {
                let mut cache = binarize::Cache::new();
                for a in &mut cs.outputs {
                    *a = binarize::binarize_nary_ops_cached(a.clone(), &mut cache);
                }
            }
            Opt::Inline => {
                let public_inputs = cs
                    .metadata
                    .public_input_names()
                    .map(ToOwned::to_owned)
                    .collect();
                inline::inline(&mut cs.outputs, &public_inputs);
            }
            Opt::Tuple => {
                tuple::eliminate_tuples(&mut cs);
            }
        }
        debug!("After {:?}: {} outputs", i, cs.outputs.len());
        //debug!("After {:?}: {}", i, Letified(cs.outputs[0].clone()));
        debug!("After {:?}: {} terms", i, cs.terms());
    }
    garbage_collect();
    cs
}

/// precomp opt
pub fn precomp_opt<I: IntoIterator<Item = Opt>>(mut precomp: PreComp, optimizations: I) -> PreComp {
    for i in optimizations {
        match i.clone() {
            Opt::ConstantFold(ignore) => {
                let mut cache = TermCache::new(TERM_CACHE_LIMIT);
                println!("begin constant fold");
                let mut idx = 0;
                let size = precomp.outputs.len();
                cache.resize(std::usize::MAX);
                for (_, a) in &mut precomp.outputs {
                    // println!("constant fold {}/{}", idx, size);
                    // idx += 1;
                    // allow unbounded size during a single fold_cache call
                    // cache.resize(std::usize::MAX);
                    *a = cfold::fold_cache(a, &mut cache, &*ignore.clone());
                    // then shrink back down to size between calls
                    // cache.resize(TERM_CACHE_LIMIT); 
                }
                println!("finish constant fold");
            },
            Opt::Obliv => {
                println!("begin obliv");
                mem::obliv::elim_obliv_precomp(&mut precomp);
                println!("finish obliv");
            },
            Opt::Tuple => {
                println!("begin tuple");
                tuple::eliminate_tuples_precomp(&mut precomp);
                println!("finish tuple");
            },
            _ => ()
        }
    }
    garbage_collect();
    precomp
}