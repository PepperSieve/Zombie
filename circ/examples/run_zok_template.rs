use std::convert::TryInto;
use std::fs::{File, self};
use std::io::BufReader;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::sync::Arc;
use circ::front::{FrontEnd, Mode};
use circ::front::zsharp::{ZSharpFE, Inputs};
use circ::ir::term::precomp::PreComp;
use circ::target::r1cs::opt::reduce_linearities;
use circ::target::aby::assignment;
use circ::target::r1cs::trans::to_r1cs;
use circ::util::field::DFL_T;
use circ::ir::opt::{opt, Opt, precomp_opt};
use rsmt2::print;
use serde::Serialize;
use std::time::{Instant, Duration};
use circ::ir::term::{Value, BitVector, Computation};
use fxhash::FxHashMap as HashMap;
use rug::Integer;
use circ_fields::{FieldT, FieldV};
use libspartan::{Instance, Assignment, NIZK, NIZKGens};
use merlin::Transcript;
use circ::target::r1cs::{Lc, R1cs, spartan, zkif};
use std::thread;
use std::env;
use zki_sieve::{producers::from_r1cs::FromR1CSConverter, FilesSink};

fn main() {
    env_logger::init();
    // test_non_membership();
    // test_label_extraction();
    // test_chacha();
    rayon::ThreadPoolBuilder::new().num_threads(8).build_global().unwrap();
    darpa_chacha();
    // // test_hkdf();
    // // test_dot_chacha_co();
    // // test_Util();
    // // test_shaRound();

    // test_sbox();
    // test_aes();
    // count_circuit_size();
    // test_doh_aes();

    // benchmark_circuits();
}

fn benchmark_circuits() {
    // let files = vec!["./zkmb/DotChaChaAmortized.zok", "./zkmb/benchmark/chachaEncrypt.zok", "./zkmb/benchmark/computeMerkleRoot.zok", "./zkmb/benchmark/extractDoTReverse.zok", "./zkmb/benchmark/generatePoseidon.zok", "./zkmb/benchmark/hkdfExpand.zok", "./zkmb/benchmark/nonMembership.zok", "./zkmb/benchmark/sha2_of_tail.zok", "./zkmb/DotChaChaChannelOpen.zok", "./zkmb/benchmark/get1RTT_HS.zok"];
    let files = vec!["./zkmb/benchmark/extractDoTReverse.zok"];
    for file in files {
        benchmark_circuit_size(file);
    };
}

fn benchmark_circuit_size(file_path: &str) {
    let inputs = Inputs {
        file: PathBuf::from(file_path),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    let cs = default_opt(cs);
    let (r1cs, _, _) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    println!("{} r1cs constraints before linear reduction {}", file_path, r1cs.constraints().len());  
    let r1cs = reduce_linearities(r1cs, Some(50));
    println!("{} r1cs constraints {}", file_path, r1cs.constraints().len());  
}

fn test_sbox() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/AES.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    println!("gen start");
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    map_u8_arr(&[101; 10], "index", &mut input_map);
    map_u8_arr(&[1; 1], "kint", &mut input_map);
    // let assignment = evaluate_cs(cs, &input_map);
    // print_u8_arr_result(&assignment);
    new_evaluate_cs(cs, &input_map);
}

fn test_aes() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/AES.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    println!("gen start");
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    // let key: [u8; 16]= [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60];

    let key: [u8; 16] = hex::decode("ecb3e5e5f832e9e12ec9cfa9439c1e3a").unwrap().try_into().unwrap();
    let iv: [u8; 12] = hex::decode("e7817628dcad24c9fc1cfa5e").unwrap().try_into().unwrap();
    let dns_ct: [u8; 160] = hex::decode("fa188037b5d3b0a218ecdf14033e71982dfbdfe72fe504db9788dfa6df87c799b953c0bd60a509ec973ac08dd1a32c6d8f51d5acffa7fa7f8944a73dcb977ceb1e6406767cb8f0189bd800820c511e5f3147acaf6e478e19c9528eb11d6920c736906c64f8b659db02ae941f37df9d8c22ae4e3c4eb4c3dbc8b3d876395ccc49eeb8317e593bbf454edea406731afa4eac7fd62cbc7e02df035e66b80c16a87a").unwrap().try_into().unwrap();

    map_u8_arr(&key, "key", &mut input_map);
    map_u8_arr(&iv, "iv", &mut input_map);
    map_u8_arr(&dns_ct, "ct", &mut input_map);

    // map_u8_arr(&[0;16], "key", &mut input_map);
    // map_u8_arr(&[0;12], "iv", &mut input_map);
    // map_u8_arr(&[0;255], "plaintext", &mut input_map);
    // let assignment = evaluate_cs(cs, &input_map);
    // print_u8_arr_result(&assignment);
    new_evaluate_cs(cs, &input_map);
}


fn test_shaRound() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/test.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    map_u32_arr(&[1; 16], "input", &mut input_map);
    map_u32_arr(&[0; 8], "current", &mut input_map);
    let assignment = evaluate_cs(cs, &input_map);
}

fn count_circuit_size() {
    let args: Vec<String> = env::args().collect();
    let file = format!("./zkmb/{}.zok", args[1]);
    println!("{}", file);
    let inputs = Inputs {
        file: PathBuf::from(file),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    println!("will generate r1cs");
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    println!("r1cs constraints {}", r1cs.constraints().len());
    let r1cs = reduce_linearities(r1cs, Some(50));
    println!("r1cs timerr {}", timer.elapsed().as_millis());
    println!("r1cs constraints {}", r1cs.constraints().len());
}

fn test_Util() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/Util.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    input_map.insert("x".to_string(), Value::Bool(true));
    let label = "amazon.com".as_bytes();
    for idx in 0..255 {
        let mut v = u8_to_value(0);
        if idx < label.len() {
            v = u8_to_value(label[idx]);
        }
        input_map.insert(format!("arr.{}", idx), v);
    }
    input_map.insert("prefix_len".to_string(), u8_to_value(label.len() as u8));
    let assignment = evaluate_cs(cs, &input_map);
    print_u8_arr_result(&assignment);
}

fn test_dot_chacha_co() {
    let (HS, H2, CH_SH_len, ServExt_len, ServExt_ct_tail_padded, ServExt_tail_len, SHA_H_Checkpoint, comm) = read_dot_chacha_co_json("./zkmb/tls.json");
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/DotChaChaChannelOpen.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let timer = Instant::now();
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default(); 
    map_dot_chacha_co(&mut input_map, HS, H2, CH_SH_len, ServExt_len, ServExt_ct_tail_padded, ServExt_tail_len, SHA_H_Checkpoint, comm);
    let assignment = evaluate_cs(cs, &input_map);
    // print_u8_arr_result(&assignment);
}

fn get_tail_minus_36(line: String) -> String {
    let line_len = line.len() / 2;
    let num_whole_blocks = (line_len - 36) / 64;
    let tail_len = line_len - num_whole_blocks * 64;
    return line[line.len() - tail_len * 2..line.len()].to_string();
}

fn hex_to_u8(line: String) -> Result<Vec<u8>, ParseIntError> {
    (0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i+2], 16))
        .collect()
}

fn hex_to_u32(line: String)  -> Result<Vec<u32>, ParseIntError> {
    (0..line.len())
        .step_by(8)
        .map(|i| u32::from_str_radix(&line[i..i+8], 16))
        .collect()
}

fn read_dot_chacha_co_json(path: &str) -> ([u8; 32], [u8; 32], u16, u16, [u8; 128], u8, [u32; 8], String){
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tls_json: serde_json::Value = serde_json::from_reader(reader).unwrap();
    let HS = tls_json.get("HS").unwrap().as_str().unwrap();
    let H_2 = tls_json.get("H_2").unwrap().as_str().unwrap();
    let ServExt_ct = tls_json.get("ch_sh").unwrap().as_str().unwrap().to_owned() + tls_json.get("ct_3").unwrap().as_str().unwrap();
    let ServExt_ct_tail = get_tail_minus_36(ServExt_ct);
    let SHA_H_Checkpoint = tls_json.get("H_state_tr7").unwrap().as_str().unwrap();
    let ServExt_tail_len = ServExt_ct_tail.len() / 2;
    let CH_SH_len = tls_json.get("ch_sh").unwrap().as_str().unwrap().len() / 2;
    let ServExt_ct_len = tls_json.get("ct_3").unwrap().as_str().unwrap().len() / 2;
    let comm = tls_json.get("comm").unwrap().as_str().unwrap().to_string();
    let HS = hex_to_u8(HS.to_owned()).unwrap();
    let mut HS_u8: [u8; 32] = [0; 32];
    for i in 0..32 {
        HS_u8[i] = HS[i];
    }
    let H_2 = hex_to_u8(H_2.to_owned()).unwrap();
    let mut H2_u8: [u8; 32] = [0; 32];
    for i in 0..32 {
        H2_u8[i] = H_2[i];
    }
    let ServExt_ct_tail = hex_to_u8(ServExt_ct_tail.to_owned()).unwrap();
    let mut ServExt_ct_tail_u8: [u8; 128] = [0; 128];
    for i in 0..ServExt_ct_tail.len() {
        ServExt_ct_tail_u8[i] = ServExt_ct_tail[i];
    }
    let SHA_H_Checkpoint = hex_to_u32(SHA_H_Checkpoint.to_owned()).unwrap();
    let mut SHA_H_Checkpoint_u32: [u32; 8] = [0; 8];
    for i in 0..8 {
        SHA_H_Checkpoint_u32[i] = SHA_H_Checkpoint[i];
    }
    return (HS_u8, H2_u8, CH_SH_len as u16, ServExt_ct_len as u16, ServExt_ct_tail_u8, ServExt_tail_len as u8, SHA_H_Checkpoint_u32, comm);
}

fn map_dot_chacha_co(input_map: &mut HashMap::<String, Value>, HS: [u8; 32], H2: [u8; 32], CH_SH_len: u16, ServExt_len: u16, ServExt_ct_tail: [u8; 128], ServExt_tail_len: u8, SHA_H_Checkpoint: [u32; 8], comm: String) {
    map_u8_arr(&HS, "HS", input_map);
    map_u8_arr(&H2, "H2", input_map);
    map_u8_arr(&ServExt_ct_tail, "ServExt_ct_tail", input_map);
    map_u32_arr(&SHA_H_Checkpoint, "SHA_H_Checkpoint", input_map);
    input_map.insert("CH_SH_len".to_string(), u16_to_value(CH_SH_len));
    input_map.insert("ServExt_len".to_string(), u16_to_value(ServExt_len));
    input_map.insert("ServExt_tail_len".to_string(), u8_to_value(ServExt_tail_len));
    let comm = Integer::from_str_radix(&comm, 16).unwrap();
    let comm = Value::Field(FieldV::new(comm, Arc::new(DFL_T.modulus().clone())));
    input_map.insert("comm".to_string(), comm);
}

fn test_hkdf() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/tls_key_schedules/HKDF.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    let key = [0, 5];
    let info = [0, 5];
    map_hkdf(&mut input_map, key, info);
    let assignment = evaluate_cs(cs, &input_map);
    print_u8_arr_result(&assignment);
}

fn map_hkdf(input_map: &mut HashMap::<String, Value>, key: [u8; 2], info: [u8; 2]) {
    input_map.insert("key.0".to_string(), u8_to_value(key[0]));
    input_map.insert("key.1".to_string(), u8_to_value(key[1]));
    input_map.insert("info.0".to_string(), u8_to_value(info[0]));
    input_map.insert("info.1".to_string(), u8_to_value(info[1]));
}

fn test_doh_aes() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/DohAESAmortized.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    println!("starting gen");
    let cs = ZSharpFE::gen(inputs);
    let timer = Instant::now();
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis()); 
    // key = ecb3e5e5f832e9e12ec9cfa9439c1e3a
    let key: [u8; 16] = hex::decode("ecb3e5e5f832e9e12ec9cfa9439c1e3a").unwrap().try_into().unwrap();
    // iv = e7817628dcad24c9fc1cfa5e
    let iv: [u8; 12] = hex::decode("e7817628dcad24c9fc1cfa5e").unwrap().try_into().unwrap();
    let comm_hex = "58c8297d89f169e197f055c51ab15bd60e480d35d90ba4a78bb5ec586fe0455";
    let SN = 0;

    // let dns_ct: [u8; 46] = [209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185];
    // let binding = hex::decode("96e5ebc2baf91f9d4045fb36a3a7176b8a62f9b35ed833a9c66ea8504d854b8c2d2c7b8e8fe0f6b3af099a2d0b4265c7f089d23c0639d211e046d4f1e51d2aa6c340b22288016a25af49a88c3839d14bad65da8274d1f0dccf5334964447f32e845a6d461e7913f01ff288d45c7c351e62bb9e26d16ffcaa8a8ad1b0dc5503b344c6e445f675cc872325f5228a859ec9ce655d6995de016f9be265f732525905bd7f558a44ca8fd56e6422492788a657").unwrap();
    // let dns_ct: &[u8] = binding.as_slice();

    // dns_ct = fa188037b5d3b0a218ecdf14033e71982dfbdfe72fe504db9788dfa6df87c799b953c0bd60a509ec973ac08dd1a32c6d8f51d5acffa7fa7f8944a73dcb977ceb1e6406767cb8f0189bd800820c511e5f3147acaf6e478e19c9528eb11d6920c736906c64f8b659db02ae941f37df9d8c22ae4e3c4eb4c3dbc8b3d876395ccc49eeb8317e593bbf454edea406731afa4eac7fd62cbc7e02df035e66b80c16a87a
    let dns_ct: &[u8] = &hex::decode("fa188037b5d3b0a218ecdf14033e71982dfbdfe72fe504db9788dfa6df87c799b953c0bd60a509ec973ac08dd1a32c6d8f51d5acffa7fa7f8944a73dcb977ceb1e6406767cb8f0189bd800820c511e5f3147acaf6e478e19c9528eb11d6920c736906c64f8b659db02ae941f37df9d8c22ae4e3c4eb4c3dbc8b3d876395ccc49eeb8317e593bbf454edea406731afa4eac7fd62cbc7e02df035e66b80c16a87a").unwrap();
    
    let input_domain_name_wildcard = "moc.nozama.";
    let left_domain_name = "moc.nozalleb.";
    let right_domain_name = "moc.nozamaainat.";
    let left_index = 8;
    let right_index = 10;
    let left_path_array = vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let right_path_array = vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let left_dir = 852258;
    let right_dir = 852259;
    let root = "5972733345965465510373436926431083918242531555386867859948086370295902707692";
    
    println!("starting map");

    let mut input_map = HashMap::<String, Value>::default();
    map_doh_aes(&mut input_map, key, iv, comm_hex, SN, &dns_ct, input_domain_name_wildcard, root, left_domain_name, right_domain_name, left_index, right_index, left_path_array, right_path_array, left_dir, right_dir);
    
    println!("starting evaluation");
    // let assignment = evaluate_cs(cs, &input_map);
    // print_u8_arr_result(&assignment);
    new_evaluate_cs(cs, &input_map);
    // print_return(&assignment);
    // println!("will generate r1cs");
    // let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    // println!("r1cs timer {}", timer.elapsed().as_millis());
    // println!("r1cs constraints {}", r1cs.constraints().len()); 

    
}

fn test_doh_chacha() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/DohChaChaAmortized.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    println!("starting gen");
    let cs = ZSharpFE::gen(inputs);
    let timer = Instant::now();
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis()); 
    // use "print ('0x', ''.join('{:02x}'.format(x) for x in __array__))" to get hex
    let key = [25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187, 173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158];
    let nonce = [222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161];
    let comm = "5883134975370231444140612170814698975570178598892810303949601208329168084134";
    let SN = 1;

    // let dns_ct: [u8; 46] = [209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185];
    // let binding = hex::decode("96e5ebc2baf91f9d4045fb36a3a7176b8a62f9b35ed833a9c66ea8504d854b8c2d2c7b8e8fe0f6b3af099a2d0b4265c7f089d23c0639d211e046d4f1e51d2aa6c340b22288016a25af49a88c3839d14bad65da8274d1f0dccf5334964447f32e845a6d461e7913f01ff288d45c7c351e62bb9e26d16ffcaa8a8ad1b0dc5503b344c6e445f675cc872325f5228a859ec9ce655d6995de016f9be265f732525905bd7f558a44ca8fd56e6422492788a657").unwrap();
    // let dns_ct: &[u8] = binding.as_slice();

    let dns_ct: &[u8] = &[150, 229, 235, 194, 186, 249, 31, 157, 64, 69, 251, 54, 163, 167, 23, 107, 138, 98, 249, 179, 94, 216, 51, 169, 198, 110, 168, 80, 77, 133, 75, 140, 45, 44, 123, 142, 143, 224, 246, 179, 175, 9, 154, 45, 11, 66, 101, 199, 240, 137, 210, 60, 6, 57, 210, 17, 224, 70, 212, 241, 229, 29, 42, 166, 195, 64, 178, 34, 136, 1, 106, 37, 175, 73, 168, 140, 56, 57, 209, 75, 173, 101, 218, 130, 116, 209, 240, 220, 207, 83, 52, 150, 68, 71, 243, 46, 132, 90, 109, 70, 30, 121, 19, 240, 31, 242, 136, 212, 92, 124, 53, 30, 98, 187, 158, 38, 209, 111, 252, 170, 138, 138, 209, 176, 220, 85, 3, 179, 68, 198, 228, 69, 246, 117, 204, 135, 35, 37, 245, 34, 138, 133, 158, 201, 206, 101, 93, 105, 149, 222, 1, 111, 155, 226, 101, 247, 50, 82, 89, 5, 189, 127, 85, 138, 68, 202, 143, 213, 110, 100, 34, 73, 39, 136, 166, 87];
    
    let input_domain_name_wildcard = "moc.nozama.";
    let left_domain_name = "moc.nozalleb.";
    let right_domain_name = "moc.nozamaainat.";
    let left_index = 8;
    let right_index = 10;
    let left_path_array = vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let right_path_array = vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let left_dir = 852258;
    let right_dir = 852259;
    let root = "5972733345965465510373436926431083918242531555386867859948086370295902707692";
    
    println!("starting map");

    let mut input_map = HashMap::<String, Value>::default();
    map_doh_chacha(&mut input_map, key, nonce, comm, SN, &dns_ct, input_domain_name_wildcard, root, left_domain_name, right_domain_name, left_index, right_index, left_path_array, right_path_array, left_dir, right_dir);
    
    println!("starting evaluation");
    // let assignment = evaluate_cs(cs, &input_map);
    // print_u8_arr_result(&assignment);
    new_evaluate_cs(cs, &input_map);
    // print_return(&assignment);
    // println!("will generate r1cs");
    // let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    // println!("r1cs timer {}", timer.elapsed().as_millis());
    // println!("r1cs constraints {}", r1cs.constraints().len()); 
    
}

fn test_dot_chacha() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/DotChaChaAmortized.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    let timer = Instant::now();
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis()); 
    let key = [25, 43, 90, 61, 240, 252, 25, 141, 247, 212, 112, 88, 50, 146, 160, 190, 63, 59, 187, 173, 7, 68, 255, 235, 33, 185, 241, 30, 195, 68, 51, 158];
    let nonce = [222, 46, 128, 34, 208, 214, 139, 81, 110, 56, 27, 161];
    let comm = "5883134975370231444140612170814698975570178598892810303949601208329168084134";
    let SN = 1;
    let dns_ct: [u8; 46] = [209, 187, 99, 199, 148, 157, 113, 239, 109, 52, 142, 83, 209, 222, 45, 110, 148, 97, 168, 178, 28, 139, 30, 133, 135, 47, 235, 17, 13, 211, 246, 3, 122, 251, 251, 115, 164, 244, 86, 56, 4, 1, 92, 218, 104, 185];

    let input_domain_name_wildcard = "moc.elppa.";
    let left_domain_name = "moc.elpoepyxes.";
    let right_domain_name = "moc.elppacitoxe.";
    let left_index = 7;
    let right_index = 9;
    let left_path_array = vec!["1752129289157004846513364561035016959483567890799881965360261832269306118159", "5213947047904663182855168970299786258303520625485597599616726408396954592357", "4678654874247556106212070218407996724004768492975815783984666471771925610899", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let right_path_array = vec!["4029907311593792750484498435368156719160829193890227244100835352776679360047", "1047467952388836899138722578366330326649405090875887618128479192405646602243", "6895007323553775386387855880832878063946281581456959574788271261206193783665", "6336962835497945360065827906694881015522159855505317143357147839892804953700", "3523222539937572237100155550629646599408540366300808242286182584478492907317", "854341270139830926623584190118162891363166235422882513305577057329067067730", "1155071630969204158629655404356963894097277727349596471673303080128212611008", "1101034354473216551382867399671639371742948873992440223181044851915028528187", "3671015490920580048837962862614506805436352270750717168705471947641608581763", "2916439049174176672988459502690028312502890869375463170061042136368105278383", "4902657669876404755160600927691245732335010579181492567064072369970254951943", "1291982324028367648857921827583320951626262620909453384576679149185114442171", "5590835449981926938360572745376509795530579163827580797571516465934968148185", "891545073237170511742591588133687396077072403024370654505408573352481184802", "458109328395050672473423391643539330979992982208543352845130781744812522502", "655884264879651899644983860630469243345443908940594634672283090102063236425", "2839092813370586975090752156408730624247809158862672281446335443807891333395", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let left_dir = 797851;
    let right_dir = 797852;
    let root = "5972733345965465510373436926431083918242531555386867859948086370295902707692";

    let mut input_map = HashMap::<String, Value>::default();
    map_dot_chacha(&mut input_map, key, nonce, comm, SN, &dns_ct, input_domain_name_wildcard, root, left_domain_name, right_domain_name, left_index, right_index, left_path_array, right_path_array, left_dir, right_dir);
    new_evaluate_cs(cs, &input_map);
    // println!("PRINTING ASSIGNMENT: {:?} ", assignment);
    // print_return(&assignment);
    // println!("will generate r1cs");
    // let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    // println!("r1cs timer {}", timer.elapsed().as_millis());
    // println!("r1cs constraints {}", r1cs.constraints().len()); 
}

fn map_dot_chacha(input_map: &mut HashMap::<String, Value>, key: [u8; 32], nonce: [u8; 12], comm: &str, SN: u32, dns_ct: &[u8], input_domain_name_wildcard: &str, root: &str, left_domain_name: &str, right_domain_name: &str, left_index: u32, right_index: u32, left_path_array: Vec<&str>, right_path_array: Vec<&str>, left_dir: u64, right_dir: u64) {
    map_u8_arr(&key, "key", input_map);
    map_u8_arr(&nonce, "nonce", input_map);
    input_map.insert("comm".to_string(), str_to_field(comm));
    input_map.insert("SN".to_string(), u32_to_value(SN));
    map_u8_arr_padded(dns_ct, 255, "dns_ct", input_map);
    for (i, c) in input_domain_name_wildcard.chars().enumerate() {
        input_map.insert(format!("input_domain_name_wildcard.{}", i), char_to_value(c));
    }
    map_str_padded(input_domain_name_wildcard, 255, "input_domain_name_wildcard", input_map);
    map_str_padded(left_domain_name, 255, "left_domain_name", input_map);
    map_str_padded(right_domain_name, 255, "right_domain_name", input_map);
    input_map.insert("left_index".to_string(), u32_to_value(left_index));
    input_map.insert("right_index".to_string(), u32_to_value(right_index));
    input_map.insert("left_dir".to_string(), u64_to_value(left_dir));
    input_map.insert("right_dir".to_string(), u64_to_value(right_dir));
    input_map.insert("root".to_string(), str_to_field(root));
    for (i, s) in left_path_array.iter().enumerate() {
        input_map.insert(format!("left_path_array.{}", i), str_to_field(s));
    }
    for (i, s) in right_path_array.iter().enumerate() {
        input_map.insert(format!("right_path_array.{}", i), str_to_field(s));
    }
}

fn map_doh_aes(input_map: &mut HashMap::<String, Value>, key: [u8; 16], iv: [u8; 12], comm: &str, SN: u32, dns_ct: &[u8], input_domain_name_wildcard: &str, root: &str, left_domain_name: &str, right_domain_name: &str, left_index: u32, right_index: u32, left_path_array: Vec<&str>, right_path_array: Vec<&str>, left_dir: u64, right_dir: u64) {
    map_u8_arr(&key, "key", input_map);
    map_u8_arr(&iv, "iv", input_map);
    input_map.insert("comm".to_string(), hex_str_to_field(comm));
    input_map.insert("SN".to_string(), u32_to_value(SN));
    map_u8_arr_padded(dns_ct, 500, "dns_ct", input_map);
    for (i, c) in input_domain_name_wildcard.chars().enumerate() {
        input_map.insert(format!("input_domain_name_wildcard.{}", i), char_to_value(c));
    }
    map_str_padded(input_domain_name_wildcard, 255, "input_domain_name_wildcard", input_map);
    map_str_padded(left_domain_name, 255, "left_domain_name", input_map);
    map_str_padded(right_domain_name, 255, "right_domain_name", input_map);
    input_map.insert("left_index".to_string(), u32_to_value(left_index));
    input_map.insert("right_index".to_string(), u32_to_value(right_index));
    input_map.insert("left_dir".to_string(), u64_to_value(left_dir));
    input_map.insert("right_dir".to_string(), u64_to_value(right_dir));
    input_map.insert("root".to_string(), str_to_field(root));
    for (i, s) in left_path_array.iter().enumerate() {
        input_map.insert(format!("left_path_array.{}", i), str_to_field(s));
    }
    for (i, s) in right_path_array.iter().enumerate() {
        input_map.insert(format!("right_path_array.{}", i), str_to_field(s));
    }
}

fn map_doh_chacha(input_map: &mut HashMap::<String, Value>, key: [u8; 32], nonce: [u8; 12], comm: &str, SN: u32, dns_ct: &[u8], input_domain_name_wildcard: &str, root: &str, left_domain_name: &str, right_domain_name: &str, left_index: u32, right_index: u32, left_path_array: Vec<&str>, right_path_array: Vec<&str>, left_dir: u64, right_dir: u64) {
    map_u8_arr(&key, "key", input_map);
    map_u8_arr(&nonce, "nonce", input_map);
    input_map.insert("comm".to_string(), str_to_field(comm));
    input_map.insert("SN".to_string(), u32_to_value(SN));
    map_u8_arr_padded(dns_ct, 500, "dns_ct", input_map);
    for (i, c) in input_domain_name_wildcard.chars().enumerate() {
        input_map.insert(format!("input_domain_name_wildcard.{}", i), char_to_value(c));
    }
    map_str_padded(input_domain_name_wildcard, 255, "input_domain_name_wildcard", input_map);
    map_str_padded(left_domain_name, 255, "left_domain_name", input_map);
    map_str_padded(right_domain_name, 255, "right_domain_name", input_map);
    input_map.insert("left_index".to_string(), u32_to_value(left_index));
    input_map.insert("right_index".to_string(), u32_to_value(right_index));
    input_map.insert("left_dir".to_string(), u64_to_value(left_dir));
    input_map.insert("right_dir".to_string(), u64_to_value(right_dir));
    input_map.insert("root".to_string(), str_to_field(root));
    for (i, s) in left_path_array.iter().enumerate() {
        input_map.insert(format!("left_path_array.{}", i), str_to_field(s));
    }
    for (i, s) in right_path_array.iter().enumerate() {
        input_map.insert(format!("right_path_array.{}", i), str_to_field(s));
    }
}

// fn test_aes() {
//     let inputs = Inputs {
//         file: PathBuf::from("./zkmb/AES.zok"),
//         mode: Mode::Proof,
//         isolate_asserts: true,
//     };
//     let cs = ZSharpFE::gen(inputs);
//     println!("gen finish");
//     let timer = Instant::now();
//     let cs = default_opt(cs);
//     println!("opt finish {}", timer.elapsed().as_millis());
//     let mut input_map = HashMap::<String, Value>::default();
//     let key: [u8; 32] = [61, 186, 53, 153, 12, 58, 4, 1, 80, 128, 185, 140, 182, 118, 216, 154, 42, 242, 52, 3, 69, 207, 178, 74, 71, 109, 123, 30, 99, 61, 234, 187];
//     let iv: [u8; 12] = [216, 247, 232, 104, 34, 33, 214, 207, 234, 2, 5, 190];
//     // let msg: [u8; 255] = [160, 1, 80, 174, 221, 140, 55, 46, 155, 108, 15, 222, 154, 198, 160, 77, 198, 26, 65, 29, 26, 85, 131, 57, 225, 190, 113, 55, 146, 108, 171, 212, 174, 118, 24, 35, 252, 188, 183, 198, 93, 235, 201, 159, 132, 106, 61, 189, 20, 213, 212, 238, 87, 130, 235, 94, 63, 115, 105, 164, 2, 180, 6, 83, 110, 250, 84, 96, 57, 11, 106, 23, 96, 176, 185, 17, 81, 13, 41, 249, 235, 105, 141, 62, 201, 86, 12, 164, 177, 255, 183, 172, 183, 184, 95, 225, 41, 210, 181, 104, 35, 32, 193, 54, 57, 146, 102, 165, 188, 221, 120, 150, 74, 19, 98, 47, 180, 164, 104, 245, 250, 8, 28, 139, 212, 222, 64, 151, 126, 208, 36, 88, 88, 210, 89, 37, 0, 155, 94, 60, 6, 174, 31, 220, 133, 54, 33, 237, 34, 18, 58, 255, 211, 219, 60, 79, 238, 125, 117, 159, 26, 241, 236, 77, 221, 237, 223, 9, 255, 44, 142, 119, 53, 35, 212, 209, 254, 136, 168, 53, 242, 182, 151, 70, 42, 54, 52, 177, 212, 122, 139, 52, 137, 127, 190, 126, 73, 144, 110, 100, 106, 141, 48, 89, 235, 228, 207, 210, 194, 173, 9, 188, 20, 78, 5, 252, 187, 27, 108, 76, 17, 181, 91, 32, 108, 220, 203, 148, 35, 28, 181, 185, 130, 113, 62, 74, 188, 183, 79, 214, 247, 202, 132, 247, 59, 165, 184, 99, 23, 197, 20, 86, 217, 81, 216];
//     let msg: [u8; 60] = [5; 60];
//     map_chacha(&mut input_map, key, iv, &msg);
//     let assignment = evaluate_cs(cs, &input_map);
//     for i in 0..255 {
//         let v = assignment.get(&format!("return.{}", i)).unwrap();
//         match v.clone() {
//             Value::BitVector(bv) => {
//                 print!("{} ", bv.uint().to_u8().unwrap());
//             },
//             _ => todo!()
//         }
//     };
//     println!();
// }

fn test_chacha() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/ChaCha.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    let key: [u8; 32] = [61, 186, 53, 153, 12, 58, 4, 1, 80, 128, 185, 140, 182, 118, 216, 154, 42, 242, 52, 3, 69, 207, 178, 74, 71, 109, 123, 30, 99, 61, 234, 187];
    let iv: [u8; 12] = [216, 247, 232, 104, 34, 33, 214, 207, 234, 2, 5, 190];
    // let msg: [u8; 255] = [160, 1, 80, 174, 221, 140, 55, 46, 155, 108, 15, 222, 154, 198, 160, 77, 198, 26, 65, 29, 26, 85, 131, 57, 225, 190, 113, 55, 146, 108, 171, 212, 174, 118, 24, 35, 252, 188, 183, 198, 93, 235, 201, 159, 132, 106, 61, 189, 20, 213, 212, 238, 87, 130, 235, 94, 63, 115, 105, 164, 2, 180, 6, 83, 110, 250, 84, 96, 57, 11, 106, 23, 96, 176, 185, 17, 81, 13, 41, 249, 235, 105, 141, 62, 201, 86, 12, 164, 177, 255, 183, 172, 183, 184, 95, 225, 41, 210, 181, 104, 35, 32, 193, 54, 57, 146, 102, 165, 188, 221, 120, 150, 74, 19, 98, 47, 180, 164, 104, 245, 250, 8, 28, 139, 212, 222, 64, 151, 126, 208, 36, 88, 88, 210, 89, 37, 0, 155, 94, 60, 6, 174, 31, 220, 133, 54, 33, 237, 34, 18, 58, 255, 211, 219, 60, 79, 238, 125, 117, 159, 26, 241, 236, 77, 221, 237, 223, 9, 255, 44, 142, 119, 53, 35, 212, 209, 254, 136, 168, 53, 242, 182, 151, 70, 42, 54, 52, 177, 212, 122, 139, 52, 137, 127, 190, 126, 73, 144, 110, 100, 106, 141, 48, 89, 235, 228, 207, 210, 194, 173, 9, 188, 20, 78, 5, 252, 187, 27, 108, 76, 17, 181, 91, 32, 108, 220, 203, 148, 35, 28, 181, 185, 130, 113, 62, 74, 188, 183, 79, 214, 247, 202, 132, 247, 59, 165, 184, 99, 23, 197, 20, 86, 217, 81, 216];
    let msg: [u8; 60] = [5; 60];
    map_chacha(&mut input_map, key, iv, &msg);
    let assignment = evaluate_cs(cs, &input_map);
    for i in 0..255 {
        let v = assignment.get(&format!("return.{}", i)).unwrap();
        match v.clone() {
            Value::BitVector(bv) => {
                print!("{} ", bv.uint().to_u8().unwrap());
            },
            _ => todo!()
        }
    };
    println!();
}

fn darpa_chacha() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/ChaCha.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish");
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let mut input_map = HashMap::<String, Value>::default();
    let key: [u8; 32] = [61, 186, 53, 153, 12, 58, 4, 1, 80, 128, 185, 140, 182, 118, 216, 154, 42, 242, 52, 3, 69, 207, 178, 74, 71, 109, 123, 30, 99, 61, 234, 187];
    let iv: [u8; 12] = [216, 247, 232, 104, 34, 33, 214, 207, 234, 2, 5, 190];
    // let msg: [u8; 255] = [160, 1, 80, 174, 221, 140, 55, 46, 155, 108, 15, 222, 154, 198, 160, 77, 198, 26, 65, 29, 26, 85, 131, 57, 225, 190, 113, 55, 146, 108, 171, 212, 174, 118, 24, 35, 252, 188, 183, 198, 93, 235, 201, 159, 132, 106, 61, 189, 20, 213, 212, 238, 87, 130, 235, 94, 63, 115, 105, 164, 2, 180, 6, 83, 110, 250, 84, 96, 57, 11, 106, 23, 96, 176, 185, 17, 81, 13, 41, 249, 235, 105, 141, 62, 201, 86, 12, 164, 177, 255, 183, 172, 183, 184, 95, 225, 41, 210, 181, 104, 35, 32, 193, 54, 57, 146, 102, 165, 188, 221, 120, 150, 74, 19, 98, 47, 180, 164, 104, 245, 250, 8, 28, 139, 212, 222, 64, 151, 126, 208, 36, 88, 88, 210, 89, 37, 0, 155, 94, 60, 6, 174, 31, 220, 133, 54, 33, 237, 34, 18, 58, 255, 211, 219, 60, 79, 238, 125, 117, 159, 26, 241, 236, 77, 221, 237, 223, 9, 255, 44, 142, 119, 53, 35, 212, 209, 254, 136, 168, 53, 242, 182, 151, 70, 42, 54, 52, 177, 212, 122, 139, 52, 137, 127, 190, 126, 73, 144, 110, 100, 106, 141, 48, 89, 235, 228, 207, 210, 194, 173, 9, 188, 20, 78, 5, 252, 187, 27, 108, 76, 17, 181, 91, 32, 108, 220, 203, 148, 35, 28, 181, 185, 130, 113, 62, 74, 188, 183, 79, 214, 247, 202, 132, 247, 59, 165, 184, 99, 23, 197, 20, 86, 217, 81, 216];
    let msg: [u8; _MSG_LEN_] = [5; _MSG_LEN_];
    map_chacha(&mut input_map, key, iv, &msg);
    darpa_transform(cs.clone(), &input_map);
}

fn map_chacha(input_map: &mut HashMap::<String, Value>, key: [u8; 32], iv: [u8; 12], msg: &[u8]) {
    map_u8_arr(&key, "key", input_map);
    map_u8_arr(&iv, "iv", input_map);
    map_u8_arr(&msg, "msg", input_map);
}

fn test_label_extraction() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/LabelExtraction.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let timer = Instant::now();
    let cs = ZSharpFE::gen(inputs);
    println!("gen finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    let cs = default_opt(cs);
    println!("opt finish {}", timer.elapsed().as_millis());
    let timer = Instant::now();
    println!("will generate r1cs");
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    let r1cs = reduce_linearities(r1cs, Some(50));
    println!("r1cs timer {}", timer.elapsed().as_millis());
    println!("r1cs constraints {}", r1cs.constraints().len());
}

fn map_label_extraction(input_map: &mut HashMap::<String, Value>, dns_message: &[u8]) {
    for (i, b) in dns_message.iter().enumerate() {
        input_map.insert(format!("dns_message.{}", i), char_to_value(b.clone() as char));
    }
    for i in dns_message.len()..255 {
        input_map.insert(format!("dns_message.{}", i), char_to_value(0 as char));
    }
}

fn test_non_membership() {
    let inputs = Inputs {
        file: PathBuf::from("./zkmb/membership_merkle/non_membership.zok"),
        mode: Mode::Proof,
        isolate_asserts: true,
    };
    let cs = ZSharpFE::gen(inputs);
    let cs = default_opt(cs);
    let mut input_map = HashMap::<String, Value>::default();
    let input_domain_name_wildcard = "moc.nozama.";
    let left_domain_name = "moc.nozalleb.";
    let right_domain_name = "moc.nozamaainat.";
    let left_index = 8;
    let right_index = 10;
    let left_path_array = vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let right_path_array = vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"];
    let left_dir = 852258;
    let right_dir = 852259;
    let root = "5972733345965465510373436926431083918242531555386867859948086370295902707692";
    map_non_membership(&mut input_map, input_domain_name_wildcard, root, left_domain_name, right_domain_name, left_index, right_index, left_path_array, right_path_array, left_dir, right_dir);
    // benchmark_r1cs(cs, &input_map);
}

fn map_non_membership(input_map: &mut HashMap::<String, Value>, input_domain_name_wildcard: &str, root: &str, left_domain_name: &str, right_domain_name: &str, left_index: u32, right_index: u32, left_path_array: Vec<&str>, right_path_array: Vec<&str>, left_dir: u64, right_dir: u64) {
    for (i, c) in input_domain_name_wildcard.chars().enumerate() {
        input_map.insert(format!("input_domain_name_wildcard.{}", i), char_to_value(c));
    }
    map_str_padded(input_domain_name_wildcard, 255, "input_domain_name_wildcard", input_map);
    map_str_padded(left_domain_name, 255, "left_domain_name", input_map);
    map_str_padded(right_domain_name, 255, "right_domain_name", input_map);
    input_map.insert("left_index".to_string(), u32_to_value(left_index));
    input_map.insert("right_index".to_string(), u32_to_value(right_index));
    input_map.insert("left_dir".to_string(), u64_to_value(left_dir));
    input_map.insert("right_dir".to_string(), u64_to_value(right_dir));
    input_map.insert("root".to_string(), str_to_field(root));
    for (i, s) in left_path_array.iter().enumerate() {
        input_map.insert(format!("left_path_array.{}", i), str_to_field(s));
    }
    for (i, s) in right_path_array.iter().enumerate() {
        input_map.insert(format!("right_path_array.{}", i), str_to_field(s));
    } 
}

fn darpa_transform(cs: Computation, input_map: &HashMap::<String, Value>) {
    let timer = Instant::now();
    println!("will generate r1cs");
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    let r1cs = reduce_linearities(r1cs, Some(50));
    println!("r1cs timer {}", timer.elapsed().as_millis());
    println!("r1cs constraints {}", r1cs.constraints().len());
    let precomp = precomp_opt(
        prover_data.precompute,
        vec![
            Opt::ConstantFold(Box::new([])),
            Opt::Obliv,
        ]
    );
    let (term_arr, input_idxes, var_idxes, index_cache) = precomp.eval_preprocess_darpa(&r1cs); 
    let mut val_arr = vec![Option::None; term_arr.len()];
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    let (zki_header, zki_r1cs, zki_witness) = zkif::r1cs_to_zkif(r1cs, index_cache, val_arr, precomp);
    // convert zkinterface R1CS -> SIEVE IR
    let dir = PathBuf::from("./darpa");
    let sink = FilesSink::new_clean(&dir).unwrap();
    let mut converter = FromR1CSConverter::new(sink, &zki_header);
    match converter.ingest_witness(&zki_witness) {
        Ok(()) => {},
        Err(e) => { panic!("Unable to ingest zkinterface witness: {}", e)}
    };
    match converter.ingest_constraints(&zki_r1cs) {
        Ok(()) => {},
        Err(e) => { panic!("Unable to ingest zkinterface constraints: {}", e)}
    }
    converter.finish();
}

fn new_evaluate_cs(cs: Computation, input_map: &HashMap::<String, Value>) {
    let timer = Instant::now();
    println!("will generate r1cs");
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    let r1cs = reduce_linearities(r1cs, Some(50));
    println!("r1cs timer {}", timer.elapsed().as_millis());
    println!("r1cs constraints {}", r1cs.constraints().len());
    let precomp = precomp_opt(
        prover_data.precompute,
        vec![
            Opt::ConstantFold(Box::new([])),
            Opt::Obliv,
        ]
    ); 
    println!("after precomp opt");
    let (term_arr, input_idxes, var_idxes) = precomp.eval_preprocess(&r1cs);
    let mut val_arr = vec![Option::None; term_arr.len()];
    let timer = Instant::now();
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    thread::sleep(Duration::from_millis(10));
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    // prover_data.precompute.real_eval(&mut val_arr, &term_arr, input_map);
    println!("eval timer {}", timer.elapsed().as_millis());
    // r1cs.check_all(&assignment);
    let timer = Instant::now();
    let (var_assignment, input_assignment) = spartan::get_spartan_assignment(&input_idxes, &var_idxes, &val_arr);
    println!("assignment transform {}", timer.elapsed().as_millis());
    // test and generate gens
    let inst = spartan::get_spartan_instance(&r1cs);
    let result = inst.is_sat(&var_assignment, &input_assignment).unwrap();
    let input_num = r1cs.public_idxs.len();
    let var_num = r1cs.idxs_signals.len() - input_num;
    let gens = NIZKGens::new(r1cs.constraints().len(), var_num, input_num);
    println!("result is {}", result);

    // actuall proof start
    let mut prover_transcript = Transcript::new(b"zkmb_proof");
    let t4 = Instant::now();
    let proof = NIZK::prove(
      &inst,
      &vec![var_assignment],
      &vec![input_assignment.clone()],
      &gens,
      &mut prover_transcript,
    );
    let t5 = Instant::now();
    println!("NIZK proof took {}", t5.duration_since(t4).as_millis());

    let timer = Instant::now();
    let mut verifier_transcript = Transcript::new(b"zkmb_proof");
    let ok = proof.verify(&inst, &vec![input_assignment.clone()], &mut verifier_transcript, &gens).is_ok();
    println!("NIZK verify took {} {}", timer.elapsed().as_millis(), ok); 
}

fn evaluate_cs(cs: Computation, input_map: &HashMap::<String, Value>) -> HashMap::<String, Value> {
    let timer = Instant::now();
    println!("will generate r1cs");
    let (r1cs, prover_data, verifier_data) = to_r1cs(cs, FieldT::from(FieldT::from(DFL_T.modulus())));
    // let r1cs = reduce_linearities(r1cs, Some(50));
    println!("r1cs timerr {}", timer.elapsed().as_millis());
    println!("r1cs constraints {}", r1cs.constraints().len()); 
    let (term_arr, input_idxes, var_idxes) = prover_data.precompute.eval_preprocess(&r1cs);
    let mut val_arr = vec![Option::None; term_arr.len()];
    let timer = Instant::now();
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    PreComp::real_eval(&mut val_arr, &term_arr, input_map);
    println!("eval timer {}", timer.elapsed().as_millis());
    input_map.clone()
    // r1cs.check_all(&assignment);
    // let timer = Instant::now();
    // let (var_assignment, input_assignment) = spartan::get_spartan_assignment(&r1cs, &assignment);
    // println!("assignment transform {}", timer.elapsed().as_millis());
    // // test and generate gens
    // let inst = spartan::get_spartan_instance(&r1cs);
    // let result = inst.is_sat(&var_assignment, &input_assignment).unwrap();
    // let input_num = r1cs.public_idxs.len();
    // let var_num = r1cs.idxs_signals.len() - input_num;
    // let gens = NIZKGens::new(r1cs.constraints().len(), var_num, input_num);
    // println!("result is {}", result);

    // // actuall proof start
    // let mut prover_transcript = Transcript::new(b"zkmb_proof");
    // let t4 = Instant::now();
    // let proof = NIZK::prove(
    //   &inst,
    //   var_assignment,
    //   &input_assignment,
    //   &gens,
    //   &mut prover_transcript,
    // );
    // let t5 = Instant::now();
    // println!("NIZK proof took {}", t5.duration_since(t4).as_millis());

    // let timer = Instant::now();
    // let mut verifier_transcript = Transcript::new(b"zkmb_proof");
    // let ok = proof.verify(&inst, &input_assignment, &mut verifier_transcript, &gens).is_ok();
    // println!("NIZK verify took {} {}", timer.elapsed().as_millis(), ok);
    // assignment
}

fn map_u8_arr_padded(u8_arr: &[u8], size: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, n) in u8_arr.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u8_to_value(n.clone()));
    }
    for i in u8_arr.len()..size {
        input_map.insert(format!("{}.{}", name, i), char_to_value(0 as char)); 
    }
}

fn map_str_padded(s: &str, size: usize, name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, c) in s.chars().enumerate() {
        input_map.insert(format!("{}.{}", name, i), char_to_value(c));
    }
    for i in s.len()..size {
        input_map.insert(format!("{}.{}", name, i), char_to_value(0 as char)); 
    }
}

fn map_u8_arr(u8_arr: &[u8], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, b) in u8_arr.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), char_to_value(b.clone() as char));
    }
}

fn map_u32_arr(u32_arr: &[u32], name: &str, input_map: &mut HashMap::<String, Value>) {
    for (i, b) in u32_arr.iter().enumerate() {
        input_map.insert(format!("{}.{}", name, i), u32_to_value(b.clone() as u32));
    }
}

fn char_to_value(c: char) -> Value {
    Value::BitVector(BitVector::new(Integer::from(c as u8), 8))
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

fn str_to_field(s: &str) -> Value {
    let big_int = Integer::from_str_radix(s, 10).unwrap();
    Value::Field(FieldV::new(big_int, Arc::new(DFL_T.modulus().clone())))
}

fn hex_str_to_field(s: &str) -> Value {
    let big_int = Integer::from_str_radix(s, 16).unwrap();
    Value::Field(FieldV::new(big_int, Arc::new(DFL_T.modulus().clone())))
}

fn default_opt(cs: Computation) -> Computation {
    return opt(
        cs,
        vec![
            Opt::ScalarizeVars,
            Opt::Flatten,
            // Opt::Sha,
            Opt::ConstantFold(Box::new([])),
            Opt::Flatten,
            Opt::Inline,
            // Tuples must be eliminated before oblivious array elim
            Opt::Tuple,
            Opt::ConstantFold(Box::new([])),
            Opt::Obliv,
            // The obliv elim pass produces more tuples, that must be eliminated
            Opt::Tuple,
            Opt::LinearScan,
            // The linear scan pass produces more tuples, that must be eliminated
            Opt::Tuple,
            Opt::Flatten,
            Opt::ConstantFold(Box::new([])),
            Opt::Inline,
        ],
    ); 
}

fn map_labelextraction(input_map: &mut HashMap::<String, Value>) {
    for i in 0..255 {
        input_map.insert(format!("dns_message.{}", i), Value::BitVector(BitVector::new(Integer::from(0 as u8), 8)));
    }
}

fn map_membership(input_map: &mut HashMap::<String, Value>) {
    for i in 0..255 {
        input_map.insert(format!("msg.{}", i), Value::BitVector(BitVector::new(Integer::from(0 as u8), 8)));
    }
}

fn map_merkle(input_map: &mut HashMap::<String, Value>) {
    input_map.insert("x".to_string(), Value::BitVector(BitVector::new(Integer::from(0 as u8), 8)));
}

fn print_membership(assignment: &HashMap::<String, Value>) {
    // for i in 0..8 {
    //     let k = format!("return.{}", i);
    //     match assignment.get(&k).unwrap() {
    //         Value::Field(f) => {
    //             match f.clone() {
    //                 FieldV::IntField(v) => {
    //                     println!("{}", v);
    //                 },
    //                 _ => todo!()
    //             }
    //         }
    //         _ => todo!()
    //     }
    // }
    match assignment.get("return").unwrap() {
        Value::Field(f) => {
            match f.clone() {
                FieldV::IntField(v) => {
                    println!("{}", v);
                },
                _ => todo!()
            }
        }
        _ => todo!()
    }
}

fn print_labelextraction(assignment: &HashMap::<String, Value>) {
    for i in 0..255 {
        let k = format!("return.0.{}", i);
        match assignment.get(&k).unwrap() {
            Value::BitVector(v) => {
                print!("{}", v.uint().to_u8().unwrap() as char);
                // print!("{}", v.uint());
            },
            _ => todo!(),
        }
    }
    println!();
    for i in 0..255 {
        let k = format!("return.1.{}", i);
        match assignment.get(&k).unwrap() {
            Value::BitVector(v) => {
                // print!("{}", v.uint().to_u8().unwrap() as char);
                print!("{}", v.uint());
            },
            _ => todo!(),
        }
    }
    println!();
}

fn print_merkle(assignment: &HashMap::<String, Value>) {
    for i in 0..1000 {
        let k = format!("return.{}", i);
        print!("{} ", assignment.get(&k).unwrap());
        // match assignment.get(&k).unwrap() {
        //     Value::Field(f) => {
        //         match f.clone() {
        //             FieldV::IntField(v) => {
        //                 println!("{}", v);
        //             },
        //             _ => todo!()
        //         }
        //     },
        //     _ => todo!(),
        // }
    }
}

fn print_return(assignment: &HashMap::<String, Value>) {
    println!("{}", assignment.get("return").unwrap())
}

fn print_assignment(assignment: &HashMap::<String, Value>) {
    for key in assignment.keys() {
        println!("{} {}", key, assignment.get(key).unwrap());
    }
}

fn print_u8_arr_result(assignment: &HashMap::<String, Value>) {
    for i in 0..400 {
        let v = assignment.get(&format!("return.{}", i));
        match v {
            Some(vv) => {
                match vv.clone() {
                    Value::BitVector(bv) => {
                        // print!("{}_", bv.uint().to_u8().unwrap() as char);
                        print!("{} ", bv.uint().to_u8().unwrap());
                    },
                    _ => todo!()
                }
            }
            None => break,
        }
    }
    println!("");
}
