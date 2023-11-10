//! Field type defaults
//
// NOTE: when we eventually break CirC into separate crates,
//       each crate may want its own field type default

use std::sync::Arc;

#[cfg(not(feature = "ff_dfl"))]
use circ_fields::moduli::*;
use circ_fields::FieldT;
use lazy_static::lazy_static;
use rug::Integer;
// #[cfg(not(feature = "ff_dfl"))]


#[cfg(all(feature = "dalek", feature = "ff_dfl"))]
lazy_static! {
    /// Dalek Field for Spartan
    pub static ref DFL_T: FieldT = FieldT::FCurve25519;
}
#[cfg(all(feature = "bls12381", feature = "ff_dfl"))]
/// Default field
pub const DFL_T: FieldT = FieldT::FBls12381;
#[cfg(all(feature = "bls12381", not(feature = "ff_dfl")))]
lazy_static! {
    /// Default field
    pub static ref DFL_T: FieldT = FieldT::IntField(F_BLS12381_FMOD_ARC.clone());
}

#[cfg(all(not(feature = "bls12381"), feature = "ff_dfl", not(feature = "dalek")))]
/// Default field
pub const DFL_T: FieldT = FieldT::FBn254;
#[cfg(all(not(feature = "bls12381"), not(feature = "ff_dfl")))]
lazy_static! {
    /// Default field
    pub static ref DFL_T: FieldT = FieldT::IntField(F_BN254_FMOD_ARC.clone());
}

// darpa field
// lazy_static! {
//     pub static ref DFL_T: FieldT = FieldT::IntField(Arc::new(Integer::from_str_radix("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10).unwrap()));
// }