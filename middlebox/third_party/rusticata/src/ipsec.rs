use crate::rparser::*;
use crate::{gen_get_variants, Variant};
use ipsec_parser::*;
use itertools::Itertools;
use std::fmt::Write as _;

impl<'a> From<IkeTransformDHType> for Variant<'a> {
    fn from(input: IkeTransformDHType) -> Self {
        Variant::U16(input.0)
    }
}

pub struct IPsecBuilder {}
impl RBuilder for IPsecBuilder {
    fn build(&self) -> Box<dyn RParser> {
        Box::new(IPsecParser::new(b"IKEv2"))
    }
    fn get_l4_probe(&self) -> Option<ProbeL4> {
        Some(ipsec_probe)
    }
}

pub struct IPsecParser<'a> {
    _name: Option<&'a [u8]>,

    /// The transforms proposed by the initiator
    pub client_proposals: Vec<Vec<IkeV2Transform>>,

    /// The transforms selected by the responder
    pub server_proposals: Vec<Vec<IkeV2Transform>>,

    /// The Diffie-Hellman group from the server KE message, if present.
    pub dh_group: IkeTransformDHType,

    /// JA3-like hash
    pub fingerprint: Option<String>,
}

impl<'a> RParser for IPsecParser<'a> {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        match parse_ikev2_header(data) {
            Ok((rem, ref hdr)) => {
                debug!("parse_ikev2_header: {:?}", hdr);
                if rem.is_empty() && hdr.length == 28 {
                    return ParseResult::Ok;
                }
                // Rule 0: check version
                if hdr.maj_ver != 2 || hdr.min_ver != 0 {
                    warn!("Unknown header version: {}.{}", hdr.maj_ver, hdr.min_ver);
                }
                match parse_ikev2_payload_list(rem, hdr.next_payload) {
                    Ok((_, Ok(p))) => {
                        debug!("parse_ikev2_payload_with_type: {:?}", p);
                        let fingerprint = build_ipsec_fingerprint(hdr, &p);
                        let digest = md5::compute(&fingerprint);
                        debug!("Fingerprint: {} --> {:x}", fingerprint, digest);
                        self.fingerprint = Some(format!("{:?}", digest));
                        for payload in p {
                            match payload.content {
                                IkeV2PayloadContent::SA(ref prop) => {
                                    let is_initiator = hdr.flags & IKEV2_FLAG_INITIATOR != 0;
                                    self.add_proposals(prop, is_initiator);
                                }
                                IkeV2PayloadContent::KE(ref kex) => {
                                    debug!("KEX {:?}", kex.dh_group);
                                    if direction == Direction::ToClient {
                                        self.dh_group = kex.dh_group;
                                    }
                                }
                                IkeV2PayloadContent::Nonce(ref n) => {
                                    debug!("Nonce: {:?}", n);
                                }
                                IkeV2PayloadContent::Notify(ref n) => {
                                    debug!("Notify: {:?}", n);
                                }
                                _ => {
                                    debug!("Unknown payload content {:?}", payload.content);
                                }
                            }
                        }
                    }
                    e => warn!("parse_ikev2_payload_with_type: {:?}", e),
                };
            }
            e => warn!("parse_ikev2_header: {:?}", e),
        };
        ParseResult::Ok
    }

    gen_get_variants! {IPsecParser, "ikev2.",
        dh_group    => into,
        enc         => |s| { s.get_server_proposal_enc().map(|x| x.into()) },
        prf         => |s| { s.get_server_proposal_prf().map(|x| x.into()) },
        auth        => |s| { s.get_server_proposal_auth().map(|x| x.into()) },
        dh          => |s| { s.get_server_proposal_dh().map(|x| x.into()) },
        esn         => |s| { s.get_server_proposal_esn().map(|x| x.into()) },
        fingerprint => map_as_ref,
    }
}

macro_rules! get_server_proposal {
    ( $t:tt, $n:ident ) => {
        pub fn $n(&self) -> Option<u16> {
            if let Some(xform) = self.server_proposals.first() {
                xform.iter().find_map(|x| {
                    if let IkeV2Transform::$t(e) = x {
                        Some(e.0)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        }
    };
}

impl<'a> IPsecParser<'a> {
    pub fn new(name: &'a [u8]) -> IPsecParser<'a> {
        IPsecParser {
            _name: Some(name),
            client_proposals: Vec::new(),
            server_proposals: Vec::new(),
            dh_group: IkeTransformDHType::None,
            fingerprint: None,
        }
    }

    get_server_proposal! {Encryption, get_server_proposal_enc}
    get_server_proposal! {PRF, get_server_proposal_prf}
    get_server_proposal! {Auth, get_server_proposal_auth}
    get_server_proposal! {DH, get_server_proposal_dh}
    get_server_proposal! {ESN, get_server_proposal_esn}

    #[allow(clippy::cognitive_complexity)]
    fn add_proposals(&mut self, prop: &[IkeV2Proposal], is_initiator: bool) {
        debug!("num_proposals: {}", prop.len());
        for p in prop {
            debug!("proposal: {:?}", p);
            debug!("num_transforms: {}", p.num_transforms);
            for xform in &p.transforms {
                debug!("transform: {:?}", xform);
                debug!("\ttype: {:?}", xform.transform_type);
                match xform.transform_type {
                    IkeTransformType::EncryptionAlgorithm => {
                        debug!(
                            "\tEncryptionAlgorithm: {:?}",
                            IkeTransformEncType(xform.transform_id)
                        );
                    }
                    IkeTransformType::PseudoRandomFunction => {
                        debug!(
                            "\tPseudoRandomFunction: {:?}",
                            IkeTransformPRFType(xform.transform_id)
                        );
                    }
                    IkeTransformType::IntegrityAlgorithm => {
                        debug!(
                            "\tIntegrityAlgorithm: {:?}",
                            IkeTransformAuthType(xform.transform_id)
                        );
                    }
                    IkeTransformType::DiffieHellmanGroup => {
                        debug!(
                            "\tDiffieHellmanGroup: {:?}",
                            IkeTransformDHType(xform.transform_id)
                        );
                    }
                    IkeTransformType::ExtendedSequenceNumbers => {
                        debug!(
                            "\tExtendedSequenceNumbers: {:?}",
                            IkeTransformESNType(xform.transform_id)
                        );
                    }
                    _ => warn!("\tUnknown transform type {:?}", xform.transform_type),
                }
                if xform.transform_id == 0 {
                    warn!("\tTransform ID == 0 (choice left to responder)");
                };
            }
            let proposals: Vec<IkeV2Transform> = p.transforms.iter().map(|x| x.into()).collect();
            debug!("Proposals\n{:?}", proposals);
            // Rule 1: warn on weak or unknown transforms
            for prop in &proposals {
                match *prop {
                    IkeV2Transform::Encryption(ref enc) => match *enc {
                        IkeTransformEncType::ENCR_DES_IV64
                        | IkeTransformEncType::ENCR_DES
                        | IkeTransformEncType::ENCR_3DES
                        | IkeTransformEncType::ENCR_RC5
                        | IkeTransformEncType::ENCR_IDEA
                        | IkeTransformEncType::ENCR_CAST
                        | IkeTransformEncType::ENCR_BLOWFISH
                        | IkeTransformEncType::ENCR_3IDEA
                        | IkeTransformEncType::ENCR_DES_IV32
                        | IkeTransformEncType::ENCR_NULL => {
                            warn!("Weak Encryption: {:?}", enc);
                        }
                        _ => (),
                    },
                    IkeV2Transform::Auth(ref auth) => {
                        match *auth {
                            IkeTransformAuthType::NONE => {
                                // Note: this could be expected with an AEAD encryption alg.
                                // See rule 4
                            }
                            IkeTransformAuthType::AUTH_HMAC_MD5_96
                            | IkeTransformAuthType::AUTH_HMAC_SHA1_96
                            | IkeTransformAuthType::AUTH_DES_MAC
                            | IkeTransformAuthType::AUTH_KPDK_MD5
                            | IkeTransformAuthType::AUTH_AES_XCBC_96
                            | IkeTransformAuthType::AUTH_HMAC_MD5_128
                            | IkeTransformAuthType::AUTH_HMAC_SHA1_160 => {
                                warn!("Weak auth: {:?}", auth);
                            }
                            _ => (),
                        }
                    }
                    IkeV2Transform::DH(ref dh) => match *dh {
                        IkeTransformDHType::None => {
                            warn!("'None' DH transform proposed");
                        }
                        IkeTransformDHType::Modp768
                        | IkeTransformDHType::Modp1024
                        | IkeTransformDHType::Modp1024s160
                        | IkeTransformDHType::Modp1536 => {
                            warn!("Weak DH: {:?}", dh);
                        }
                        _ => (),
                    },
                    IkeV2Transform::Unknown(tx_type, tx_id) => {
                        warn!("Unknown proposal: type={}, id={}", tx_type.0, tx_id);
                    }
                    _ => (),
                }
            }
            // Rule 2: check if no DH was proposed
            fn has_dh(proposals: &[IkeV2Transform]) -> bool {
                proposals.iter().any(|x| matches!(x, IkeV2Transform::DH(_)))
            }
            if !has_dh(&proposals) {
                warn!("No DH transform found");
            }
            // Rule 3: check if proposing AH ([RFC7296] section 3.3.1)
            if p.protocol_id == ProtocolID::AH {
                warn!("Proposal uses protocol AH - no confidentiality");
            }
            // Rule 4: lack of integrity is accepted only if using an AEAD proposal
            // Look if no auth was proposed, including if proposal is Auth::None
            fn has_auth(proposals: &[IkeV2Transform]) -> bool {
                proposals.iter().any(|x| match *x {
                    IkeV2Transform::Auth(IkeTransformAuthType::NONE) => false,
                    IkeV2Transform::Auth(_) => true,
                    _ => false,
                })
            }
            fn has_gcm(proposals: &[IkeV2Transform]) -> bool {
                proposals.iter().any(|x| {
                    if let IkeV2Transform::Encryption(ref enc) = x {
                        enc.is_aead()
                    } else {
                        false
                    }
                })
            }
            if !has_auth(&proposals) && !has_gcm(&proposals) {
                warn!("No integrity transform found");
            }
            // Rule 5: Check if an integrity and no integrity are part of the same proposal ?
            // XXX
            // Finally
            if is_initiator {
                self.client_proposals.push(proposals);
            } else {
                self.server_proposals.push(proposals);
            }
        }
        // The server must accept one proposal, or reject them all (RFC 5996 2.7)
        if self.server_proposals.len() > 1 {
            warn!("more than one server proposals")
        }
        debug!("client_proposals: {:?}", self.client_proposals);
        debug!("server_proposals: {:?}", self.server_proposals);
    }
}

/// IPsec version,exchnage type,payload types,notify types,transform proposals
pub fn build_ipsec_fingerprint(hdr: &IkeV2Header, payload_list: &[IkeV2Payload]) -> String {
    // version is fix
    let mut fingerprint = String::from("2.0,");
    // exchange type
    let _ = write!(fingerprint, "{}", hdr.exch_type.0);
    // payload types
    let payload_types_str = payload_list
        .iter()
        .fold(vec![hdr.next_payload.0], |mut acc, payload| {
            acc.push(payload.hdr.next_payload_type.0);
            acc
        })
        .iter()
        .join("-");
    fingerprint.push_str(&payload_types_str);
    // notify types
    fingerprint.push(',');
    let notify_types_str = payload_list
        .iter()
        .filter_map(|payload| {
            if let IkeV2PayloadContent::Notify(notify) = &payload.content {
                Some(notify.notify_type.0)
            } else {
                None
            }
        })
        .join("-");
    fingerprint.push_str(&notify_types_str);
    // proposals and transforms
    fingerprint.push(',');
    let mut transforms = Vec::new();
    for payload in payload_list {
        if let IkeV2PayloadContent::SA(sa_list) = &payload.content {
            for sa in sa_list {
                for xform in &sa.transforms {
                    transforms.push(format!("{}:{}", xform.transform_type.0, xform.transform_id));
                }
            }
        }
    }
    let transforms_str = transforms.iter().join("-");
    fingerprint.push_str(&transforms_str);
    // finish
    fingerprint
}

pub fn ipsec_probe(i: &[u8], _l4info: &L4Info) -> ProbeResult {
    if i.len() <= 20 {
        return ProbeResult::Unsure;
    }
    match parse_ikev2_header(i) {
        Ok((_, ref hdr)) => {
            if hdr.maj_ver != 2 || hdr.min_ver != 0 {
                // trace!(
                //     "ipsec_probe: could be ipsec, but with unsupported/invalid version {}.{}",
                //     hdr.maj_ver, hdr.min_ver
                // );
                return ProbeResult::NotForUs;
            }
            if hdr.exch_type.0 < 34 || hdr.exch_type.0 > 37 {
                // trace!(
                //     "ipsec_probe: could be ipsec, but with unsupported/invalid exchange type {}",
                //     hdr.exch_type.0
                // );
                return ProbeResult::NotForUs;
            }
            ProbeResult::Certain
        }
        _ => ProbeResult::NotForUs,
    }
}
