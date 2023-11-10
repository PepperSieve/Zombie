use serde::Deserialize;
use super::{Witness, WitnessMapper};

#[derive(Deserialize)]
pub struct ChannelOpenProverWitness {
    pub HS: Vec<u8>,
    pub H2: Vec<u8>,
    pub CH_SH_len: u16,
    pub ServExt_len: u16,
    pub ServExt_ct_tail: Vec<u8>,
    pub ServExt_tail_len: u8,
    pub SHA_H_Checkpoint: Vec<u32>,
    pub comm: String,
}

impl Witness for ChannelOpenProverWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_u8_arr_padded(&self.HS, 32, "HS");
        mapper.map_u8_arr_padded(&self.H2, 32, "H2");
        mapper.map_u16(self.CH_SH_len, "CH_SH_len");
        mapper.map_u16(self.ServExt_len, "ServExt_len");
        mapper.map_u8_arr_padded(&self.ServExt_ct_tail, 128, "ServExt_ct_tail");
        mapper.map_u8(self.ServExt_tail_len, "ServExt_tail_len");
        mapper.map_u32_arr_padded(&self.SHA_H_Checkpoint, 8, "SHA_H_Checkpoint");
        mapper.map_field(&self.comm, "comm");
        mapper
    }
}

#[derive(Deserialize)]
pub struct ChannelOpenVerifierWitness {
    pub H2: Vec<u8>,
    pub CH_SH_len: u16,
    pub ServExt_len: u16,
    pub ServExt_ct_tail: Vec<u8>,
    pub ServExt_tail_len: u8,
    pub comm: String,
}

impl Witness for ChannelOpenVerifierWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field_arr_padded(&self.H2, 32, "H2");
        mapper.map_field(&self.CH_SH_len, "CH_SH_len");
        mapper.map_field(&self.ServExt_len, "ServExt_len");
        mapper.map_field_arr_padded(&self.ServExt_ct_tail, 128, "ServExt_ct_tail");
        mapper.map_field(&self.ServExt_tail_len, "ServExt_tail_len");
        mapper.map_field(&self.comm, "comm");
        mapper.map_field(&"1".to_string(), "return");
        mapper
    }
}