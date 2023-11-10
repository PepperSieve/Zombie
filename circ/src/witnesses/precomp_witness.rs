use serde::Deserialize;
use super::{Witness, WitnessMapper};

#[derive(Deserialize, Clone)]
pub struct PrecompDotChaChaVerifierWitness {
	pub comm: String,
	pub SN: u32,
	pub ret: String
}

impl Witness for PrecompDotChaChaVerifierWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field(&self.comm, "comm");
		mapper.map_field(&self.SN, "SN");
		mapper.map_field(&self.ret.to_string(), "return");
		mapper
	}
}

#[derive(Deserialize, Clone)]
pub struct PrecompDotChaChaProverWitness {
	pub comm: String,
	pub SN: u32,
	pub key: Vec<u8>,
	pub nonce: Vec<u8>,
}

impl Witness for PrecompDotChaChaProverWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field(&self.comm, "comm");
		mapper.map_u32(self.SN, "SN");
		mapper.map_u8_arr_padded(&self.key, 32, "key");
		mapper.map_u8_arr_padded(&self.nonce, 12, "nonce");
		mapper
	}
}