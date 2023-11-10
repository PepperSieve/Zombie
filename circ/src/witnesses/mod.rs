use std::sync::Arc;

use circ_fields::FieldV;
use fxhash::FxHashMap;
use rug::Integer;
use serde::{Serialize, Deserialize};

use crate::{ir::term::{Value, BitVector}, util::field::DFL_T};

pub mod sha_round_witness;
pub mod amortized_witness;
pub mod channel_open_witness;
pub mod aes_witness;
pub mod non_membership;
pub mod precomp_witness;
pub mod amortized_unpack;
pub mod tmp;
pub mod regex_witness;
pub mod policy_witness;

pub trait Witness {
    fn to_map(&self) -> WitnessMapper;
}

#[derive(Serialize, Deserialize)]
pub struct WitnessMapper {
    pub input_map: FxHashMap<String, Value>,
}

impl WitnessMapper {
    pub fn new() -> Self {
        WitnessMapper {
            input_map: FxHashMap::<String, Value>::default(),
        }
    }

    pub fn map_field<S: ToString>(&mut self, v: &S, name: &str) {
        self.input_map
            .insert(name.to_string(), str_to_field(v.to_string()));
    }

    pub fn map_u8(&mut self, v: u8, name: &str) {
        self.input_map.insert(name.to_string(), u8_to_value(v));
    }

    pub fn map_u16(&mut self, v: u16, name: &str) {
        self.input_map.insert(name.to_string(), u16_to_value(v));
    }

    pub fn map_u32(&mut self, v: u32, name: &str) {
        self.input_map.insert(name.to_string(), u32_to_value(v));
    }

    pub fn map_u64(&mut self, v: u64, name: &str) {
        self.input_map.insert(name.to_string(), u64_to_value(v));
    }

    // fn map_str(&mut self, v: String, name: &str) {
    //     for (i, c) in v.chars().enumerate() {
    //         self.input_map.insert(format!("{}.{}", name, i), u8_to_value(c as u8));
    //     }
    // }

    pub fn map_u8_arr_padded(&mut self, v: &Vec<u8>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), u8_to_value(c.clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), u8_to_value(0));
        }
    }

    pub fn map_u32_arr_padded(&mut self, v: &Vec<u32>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), u32_to_value(c.clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), u32_to_value(0));
        }
    }

    pub fn map_field_arr_padded<S: ToString>(&mut self, v: &Vec<S>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field(c.to_string().clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field("0".to_string()));
        }
    }

    pub fn map_field_arr<S: ToString>(&mut self, v: &Vec<S>, name: &str) {
        for (i, s) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field(s.to_string().clone()));
        }
    }
}

fn u8_to_value(n: u8) -> Value {
    Value::BitVector(BitVector::new(Integer::from(n), 8))
}

fn u16_to_value(n: u16) -> Value {
    Value::BitVector(BitVector::new(Integer::from(n), 16))
}

fn u32_to_value(num: u32) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 32))
}

fn u64_to_value(num: u64) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 64))
}

fn str_to_field(s: String) -> Value {
    let big_int = Integer::from_str_radix(&s, 10).unwrap();
    Value::Field(FieldV::new(big_int, Arc::new(DFL_T.modulus().clone())))
    // Value::Field(FieldV::FCurve25519(Fr::from_bigint(int_to_bigint(big_int)).unwrap()))
}