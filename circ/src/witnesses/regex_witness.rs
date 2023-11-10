use super::{Witness, WitnessMapper};
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct RegexAmortizedVerifierWitness<const CiphertextLen: usize> {
    pub comm: String,
    pub SN: u32,
    pub ciphertext: Vec<u8>,
}

impl<const CiphertextLen: usize> Witness for RegexAmortizedVerifierWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.comm, "comm");
        mapper.map_field(&self.SN, "SN");
        mapper.map_field_arr_padded(&self.ciphertext, CiphertextLen, "ciphertext");
        mapper.map_field(&"1".to_string(), "return");
        mapper
    }
}

impl<const CiphertextLen: usize> RegexAmortizedVerifierWitness<CiphertextLen> {
    pub fn default() -> Self {
        Self {
            comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
            SN: 1,
            ciphertext: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
            // ciphertext: vec![0, 1],
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct RegexAmortizedProverWitness<const CiphertextLen: usize> {
    pub comm: String,
    pub SN: u32,
    pub ciphertext: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl<const CiphertextLen: usize> Witness for RegexAmortizedProverWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.comm, "comm");
        mapper.map_u32(self.SN, "SN");
        mapper.map_u8_arr_padded(&self.ciphertext, CiphertextLen, "ciphertext");
        mapper.map_u8_arr_padded(&self.key, 32, "key");
        mapper.map_u8_arr_padded(&self.nonce, 12, "nonce");
        mapper
    }
}

impl<const CiphertextLen: usize> RegexAmortizedProverWitness<CiphertextLen> {
    pub fn default() -> Self {
        Self {
            comm: "5883134975370231444140612170814698975570178598892810303949601208329168084134".to_string(),
            SN: 1,
            ciphertext: vec![209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185],
            // ciphertext: vec![0, 1],
            key: vec![25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187, 173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158],
            nonce: vec![222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161]
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct RegexAmortizedUnpackVerifierWitness<const CiphertextLen: usize> {
    pub comm_pad: String,
    pub ciphertext: Vec<u8>,
}

impl<const CiphertextLen: usize> Witness for RegexAmortizedUnpackVerifierWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.comm_pad, "comm_pad");
        mapper.map_field_arr_padded(&self.ciphertext, CiphertextLen, "ciphertext");
        mapper.map_field(&"1".to_string(), "return");
        mapper
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct RegexAmortizedUnpackProverWitness<const CiphertextLen: usize> {
    pub pad: Vec<u8>,
    pub comm_pad: String,
    pub ciphertext: Vec<u8>,
}

impl<const CiphertextLen: usize> Witness for RegexAmortizedUnpackProverWitness<CiphertextLen> {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_u8_arr_padded(&self.pad, CiphertextLen, "pad");
        mapper.map_field(&self.comm_pad, "comm_pad");
        mapper.map_u8_arr_padded(&self.ciphertext, CiphertextLen, "ciphertext");
        mapper.map_field(&"1".to_string(), "return");
        mapper
    }
}