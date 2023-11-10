use super::{Witness, WitnessMapper};
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct RegexVerifierWitness<const CiphertextLen: usize> {
    pub t: Vec<String>,
    pub tu: Vec<u8>
}

impl<const CiphertextLen: usize> Witness for RegexVerifierWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field_arr_padded(&self.t, CiphertextLen, "t");
        mapper.map_field_arr_padded(&self.tu, CiphertextLen, "tu");
        mapper.map_field(&"0".to_string(), "return");
        mapper
    }
}

impl<const CiphertextLen: usize> RegexVerifierWitness<CiphertextLen> {
    pub fn default() -> Self {
        Self {
            t: vec!["0".to_string(), "0".to_string(), "0".to_string()],
            tu: vec![0, 0, 0]
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct RegexProverWitness<const CiphertextLen: usize> {
    pub t: Vec<String>,
    pub tu: Vec<u8>
}

impl<const CiphertextLen: usize> Witness for RegexProverWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        let mut mapper = WitnessMapper::new();
        mapper.map_field_arr_padded(&self.t, CiphertextLen, "t");
        mapper.map_u8_arr_padded(&self.tu, CiphertextLen, "tu");
        mapper
    }
}

impl<const CiphertextLen: usize> RegexProverWitness<CiphertextLen> {
    pub fn default() -> Self {
        Self {
            t: vec!["0".to_string(), "0".to_string(), "0".to_string()],
            tu: vec![0, 0, 0]
        }
    }
}