use serde::Deserialize;
use super::{Witness, WitnessMapper};

#[derive(Deserialize)]
pub struct AESVerifierWitness {
	pub key: Vec<u8>,
	pub iv: Vec<u8>,
	pub ct: Vec<u8>,
	pub ret: Vec<u8>
}

impl Witness for AESVerifierWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field_arr_padded(&self.key, 16, "key");
		mapper.map_field_arr_padded(&self.iv, 12, "iv");
		mapper.map_field_arr_padded(&self.ct, 160, "ct");
		mapper.map_field_arr_padded(&self.ret, 160, "return");
		mapper
	}
}

#[derive(Deserialize)]
pub struct AESProverWitness {
	pub key: Vec<u8>,
	pub iv: Vec<u8>,
	pub ct: Vec<u8>,
}

impl Witness for AESProverWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_u8_arr_padded(&self.key, 16, "key");
		mapper.map_u8_arr_padded(&self.iv, 12, "iv");
		mapper.map_u8_arr_padded(&self.ct, 160, "ct");
		mapper
	}
}

