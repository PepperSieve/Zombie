use serde::Deserialize;
use super::{Witness, WitnessMapper};

#[derive(Deserialize, Clone)]
pub struct ShaRoundVerifierWitness {
	pub a: Vec<u32>,
	pub ret: Vec<u32>
}

impl Witness for ShaRoundVerifierWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field_arr_padded(&self.a, 16, "a");
		mapper.map_field_arr_padded(&self.ret, 8, "return");
		mapper
	}
}

#[derive(Deserialize, Clone)]
pub struct ShaRoundProverWitness {
	pub a: Vec<u32>,
}

impl Witness for ShaRoundProverWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_u32_arr_padded(&self.a, 16, "a");
		mapper
	}
}

