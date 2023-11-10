use serde::Deserialize;
use super::{Witness, WitnessMapper};

#[derive(Deserialize, Clone)]
pub struct AmortizedUnpackVerifierWitness<const DnsCtLen: usize> {
	pub comm_pad: String,
	pub dns_ct: Vec<u8>,
	pub root: String,
	pub ret: String
}

impl<const DnsCtLen: usize> Witness for AmortizedUnpackVerifierWitness<DnsCtLen> {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field(&self.comm_pad, "comm_pad");
		mapper.map_field_arr_padded(&self.dns_ct, DnsCtLen, "dns_ct");
		mapper.map_field(&self.root, "root");
		mapper.map_field(&self.ret.to_string(), "return");
		mapper
	}
}

#[derive(Deserialize, Clone)]
pub struct AmortizedUnpackProverWitness<const DnsCtLen: usize> {
	pub comm_pad: String,
	pub dns_ct: Vec<u8>,
	pub root: String,
	pub pad: Vec<u8>,
	pub left_domain_name: Vec<u8>,
	pub right_domain_name: Vec<u8>,
	pub left_index: u32,
	pub right_index: u32,
	pub left_path_array: Vec<String>,
	pub right_path_array: Vec<String>,
	pub left_dir: u64,
	pub right_dir: u64,
}

impl<const DnsCtLen: usize> Witness for AmortizedUnpackProverWitness<DnsCtLen> {
	fn to_map(&self) -> WitnessMapper {
		let mut mapper = WitnessMapper::new();
		mapper.map_field(&self.comm_pad, "comm_pad");
		mapper.map_u8_arr_padded(&self.dns_ct, DnsCtLen, "dns_ct");
		mapper.map_field(&self.root, "root");
		mapper.map_u8_arr_padded(&self.pad, 255, "pad");
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

