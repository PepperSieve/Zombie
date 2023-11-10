use serde::Deserialize;
use super::{Witness, WitnessMapper};

// #[derive(Deserialize)]
// pub struct NonMembershipVerifierWitness {
//     pub input_domain_wildcard: Vec<String>,
//     pub root: String,
// }

// impl Witness for NonMembershipVerifierWitness {
// 	fn to_map(&self) -> WitnessMapper {
// 		let mut mapper = WitnessMapper::new();
// 		mapper.map_field_arr_padded(&self.input_domain_wildcard, 255, "input_domain_wildcard");
// 		mapper.map_field(&self.root, "root");
// 		mapper.map_field(&"1".to_string(), "return");
// 		mapper
// 	}
// }

// #[derive(Deserialize)]
// pub struct NonMembershipProverWitness {
// 	pub input_domain_wildcard: Vec<u8>,
// 	pub root: String,
//     pub left_domain_name: Vec<u8>,
//     pub right_domain_name: Vec<u8>,
//     pub left_index: u32,
//     pub right_index: u32,
//     pub left_path_array: Vec<String>,
//     pub right_path_array: Vec<String>,
//     pub left_dir: u64,
//     pub right_dir: u64,
// }

// impl Witness for NonMembershipProverWitness {
// 	fn to_map(&self) -> WitnessMapper {
// 		let mut mapper = WitnessMapper::new();
// 		mapper.map_u8_arr_padded(&self.input_domain_wildcard, 255, "input_domain_wildcard");
// 		mapper.map_field(&self.root, "root");
// 		mapper.map_u8_arr_padded(&self.left_domain_name, 255, "left_domain_name");
// 		mapper.map_u8_arr_padded(&self.right_domain_name, 255, "right_domain_name");
// 		mapper.map_u32(self.left_index, "left_index");
// 		mapper.map_u32(self.right_index, "right_index");
// 		mapper.map_field_arr_padded(&self.left_path_array, 21, "left_path_array");
// 		mapper.map_field_arr_padded(&self.right_path_array, 21, "right_path_array");
// 		mapper.map_u64(self.left_dir, "left_dir");
// 		mapper.map_u64(self.right_dir, "right_dir");
// 		mapper
// 	}
// }

#[derive(Deserialize)]
pub struct NonMembershipVerifierWitness {
	pub input_domain_wildcard: Vec<String>,
	pub root: String,
	pub ret: String
}

impl Witness for NonMembershipVerifierWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field_arr_padded(&self.input_domain_wildcard, 255, "input_domain_wildcard");
		mapper.map_field(&self.root, "root");
		mapper.map_field(&self.ret.to_string(), "return");
		mapper
	}
}

#[derive(Deserialize)]
pub struct NonMembershipProverWitness {
	pub input_domain_wildcard: Vec<u8>,
	pub root: String,
	pub left_domain_name: Vec<u8>,
	pub right_domain_name: Vec<u8>,
	pub left_index: u32,
	pub right_index: u32,
	pub left_path_array: Vec<String>,
	pub right_path_array: Vec<String>,
	pub left_dir: u64,
	pub right_dir: u64,
}

impl Witness for NonMembershipProverWitness {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_u8_arr_padded(&self.input_domain_wildcard, 255, "input_domain_wildcard");
		mapper.map_field(&self.root, "root");
		mapper.map_u8_arr_padded(&self.left_domain_name, 255, "left_domain_name");
		mapper.map_u8_arr_padded(&self.right_domain_name, 255, "right_domain_name");
		mapper.map_u32(self.left_index, "left_index");
		mapper.map_u32(self.right_index, "right_index");
		mapper.map_field_arr_padded(&self.left_path_array, 21, "left_path_array");
		mapper.map_field_arr_padded(&self.right_path_array, 21, "right_path_array");
		mapper.map_u64(self.left_dir, "left_dir");
		mapper.map_u64(self.right_dir, "right_dir");
		mapper
	}
}