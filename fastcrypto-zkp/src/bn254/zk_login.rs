// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

use super::poseidon::PoseidonWrapper;
use crate::circom::CircomPublicInputs;
use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use ark_ff::ToConstraintField;
use ark_groth16::Proof;
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::{
    error::FastCryptoError,
    rsa::{Base64UrlUnpadded, Encoding},
};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(test)]
#[path = "unit_tests/zk_login_tests.rs"]
mod zk_login_tests;

const MAX_EXTENDED_ISS_LEN: u8 = 99;
const MAX_EXTENDED_ISS_LEN_B64: u8 = 1 + (4 * (MAX_EXTENDED_ISS_LEN / 3));
const MAX_EXTENDED_AUD_LEN: u8 = 99;
const MAX_EXTENDED_AUD_LEN_B64: u8 = 1 + (4 * (MAX_EXTENDED_AUD_LEN / 3));
const MAX_HEADER_LEN: u8 = 150;
const PACK_WIDTH: u8 = 248;

/// Hardcoded mapping from the provider and its supported key claim name to its map-to-field Big Int in string.
/// The field value is computed from the max key claim length and its provider.
static SUPPORTED_KEY_CLAIM_TO_FIELD: Lazy<HashMap<(&str, String), &str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        (
            OAuthProvider::Google.get_config().0,
            SupportedKeyClaim::Sub.to_string(),
        ),
        "18523124550523841778801820019979000409432455608728354507022210389496924497355",
    );
    map.insert(
        (
            OAuthProvider::Google.get_config().0,
            SupportedKeyClaim::Email.to_string(),
        ),
        "",
    );
    map.insert(
        (
            OAuthProvider::Twitch.get_config().0,
            SupportedKeyClaim::Sub.to_string(),
        ),
        "",
    );
    map.insert(
        (
            OAuthProvider::Twitch.get_config().0,
            SupportedKeyClaim::Email.to_string(),
        ),
        "",
    );
    map
});

/// Supported OAuth providers. Must contain "openid" in "scopes_supported"
/// and "public" for "subject_types_supported" instead of "pairwise".
#[derive(Debug)]
pub enum OAuthProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
}

/// Struct that contains all the OAuth provider information. A list of them can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>)
/// and published on the bulletin along with a trusted party's signature.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    ///d
    pub kty: String,
    ///d
    pub e: String,
    ///d
    pub n: String,
    ///d
    pub alg: String,
}

impl OAuthProvider {
    /// Returns a tuple of iss string and JWK endpoint string for the given provider.
    pub fn get_config(&self) -> (&str, &str) {
        match self {
            OAuthProvider::Google => (
                "https://accounts.google.com",
                "https://www.googleapis.com/oauth2/v2/certs",
            ),
            OAuthProvider::Twitch => (
                "https://id.twitch.tv/oauth2",
                "https://id.twitch.tv/oauth2/keys",
            ),
        }
    }

    /// Returns the provider for the given iss string.
    pub fn from_iss(iss: &str) -> Result<Self, FastCryptoError> {
        match iss {
            "https://accounts.google.com" => Ok(Self::Google),
            "https://id.twitch.tv/oauth2" => Ok(Self::Twitch),
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

/// The claims in the body signed by OAuth provider that must
/// be locally unique to the provider and cannot be reassigned.
#[derive(Debug)]
pub enum SupportedKeyClaim {
    /// Subject id representing an unique account.
    Sub,
    /// Email string representing an unique account.
    Email,
}

impl fmt::Display for SupportedKeyClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupportedKeyClaim::Email => write!(f, "email"),
            SupportedKeyClaim::Sub => write!(f, "sub"),
        }
    }
}

/// Necessary value for claim.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct Claim {
    name: String,
    value_base64: String,
    index_mod_4: u8,
}

/// A parsed result of all aux inputs.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub struct AuxInputs {
    claims: Vec<Claim>,
    header_base64: String,
    addr_seed: String,
    eph_public_key: Vec<String>,
    max_epoch: u64,
    key_claim_name: String,
    modulus: String,
    #[serde(skip)]
    parsed_masked_content: ParsedMaskedContent,
}

impl AuxInputs {
    /// Validate and parse masked content bytes into the struct and other json strings into the struct.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let mut inputs: AuxInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidInput)?;
        inputs.parsed_masked_content =
            ParsedMaskedContent::new(&inputs.header_base64, &inputs.claims)?;
        Ok(inputs)
    }

    /// Init ParsedMaskedContent
    pub fn init(&mut self) -> Result<Self, FastCryptoError> {
        self.parsed_masked_content = ParsedMaskedContent::new(&self.header_base64, &self.claims)?;
        Ok(self.to_owned())
    }

    /// Get the max epoch value.
    pub fn get_max_epoch(&self) -> u64 {
        self.max_epoch
    }

    /// Get the address seed in string.
    pub fn get_address_seed(&self) -> &str {
        &self.addr_seed
    }

    /// Get the iss string.
    pub fn get_iss(&self) -> &str {
        self.parsed_masked_content.get_iss()
    }

    /// Get the iss string.
    pub fn get_iss_str(&self) -> &str {
        self.parsed_masked_content.get_iss_str()
    }

    /// Get the iss string.
    pub fn get_aud_str(&self) -> &str {
        self.parsed_masked_content.get_aud_str()
    }

    /// Get the client id string.
    pub fn get_aud(&self) -> &str {
        self.parsed_masked_content.get_aud()
    }

    /// Get the iss index.
    pub fn get_iss_index(&self) -> u8 {
        self.parsed_masked_content.get_iss_index()
    }

    /// Get the aud index.
    pub fn get_aud_index(&self) -> u8 {
        self.parsed_masked_content.get_aud_index()
    }

    /// Get the aud index.
    pub fn get_claim_name(&self) -> &str {
        &self.key_claim_name
    }

    /// Get the header base64 string.
    pub fn get_header(&self) -> &str {
        self.parsed_masked_content.get_header()
    }

    /// Get the kid string.
    pub fn get_kid(&self) -> &str {
        &self.parsed_masked_content.kid
    }

    /// Get the modulus
    pub fn get_mod(&self) -> &str {
        &self.modulus
    }

    /// Calculate the poseidon hash from 10 selected fields in the aux inputs.
    pub fn calculate_all_inputs_hash(&self) -> Result<String, FastCryptoError> {
        // TODO(joyqvq): check each string for bigint is valid.
        let mut poseidon = PoseidonWrapper::new();
        let addr_seed = Bn254Fr::from_str(&self.addr_seed.to_string()).unwrap();
        let eph_public_key_0 = Bn254Fr::from_str(&self.eph_public_key[0]).unwrap();
        let eph_public_key_1 = Bn254Fr::from_str(&self.eph_public_key[1]).unwrap();
        let max_epoch = Bn254Fr::from_str(&self.max_epoch.to_string()).unwrap();
        let key_claim_name_f = Bn254Fr::from_str(
            SUPPORTED_KEY_CLAIM_TO_FIELD
                .get(&(self.get_iss(), self.get_claim_name().to_owned()))
                .unwrap(),
        )
        .unwrap();
        let iss_f = map_to_field(self.get_iss_str(), MAX_EXTENDED_ISS_LEN_B64)?;
        let aud_f = map_to_field(self.get_aud_str(), MAX_EXTENDED_AUD_LEN_B64)?;
        let header_f = map_to_field(self.get_header(), MAX_HEADER_LEN)?;

        let iss_index = Bn254Fr::from_str(&self.get_iss_index().to_string()).unwrap();
        let aud_index = Bn254Fr::from_str(&self.get_aud_index().to_string()).unwrap();

        Ok(poseidon
            .hash(vec![
                addr_seed,
                eph_public_key_0,
                eph_public_key_1,
                max_epoch,
                key_claim_name_f,
                iss_f,
                iss_index,
                aud_f,
                aud_index,
                header_f,
            ])?
            .to_string())
    }
}

fn map_to_field(input: &str, max_size: u8) -> Result<Bn254Fr, FastCryptoError> {
    if input.len() > max_size as usize {
        return Err(FastCryptoError::InvalidInput);
    }

    let num_elements = max_size / (PACK_WIDTH / 8) + 1;
    println!("input: {:?} {:?} {:?}", input, max_size, num_elements);
    let in_arr: Vec<BigUint> = input
        .chars()
        .map(|c| BigUint::from_slice(&([c as u32])))
        .collect();
    println!(
        "in arr {:?}",
        in_arr
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
    );
    let packed = pack2(&in_arr, 8, PACK_WIDTH, num_elements)?;
    println!(
        "packed2: {:?}",
        packed
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
    );
    to_poseidon_hash(packed)
}

fn pack2(
    in_arr: &[BigUint],
    in_width: u8,
    out_width: u8,
    out_count: u8,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let packed = pack(in_arr, in_width as usize, out_width as usize)?;
    println!(
        "packed: {:?}",
        packed
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
    );
    if packed.len() > out_count as usize {
        return Err(FastCryptoError::InvalidInput);
    }

    let mut padded = packed.clone();
    padded.extend(vec![
        Bn254Fr::from_str("0").unwrap();
        out_count as usize - packed.len() as usize
    ]);
    Ok(padded)
}

fn pack(
    in_arr: &[BigUint],
    in_width: usize,
    out_width: usize,
) -> Result<Vec<Bn254Fr>, FastCryptoError> {
    let bits = big_int_array_to_bits(in_arr, in_width);
    println!("bits: {:?}", bits.len());
    let extra_bits = if bits.len() % out_width == 0 {
        0
    } else {
        out_width - (bits.len() % out_width)
    };
    println!("extra_bits: {:?}", extra_bits);

    let mut bits_padded = bits;
    bits_padded.extend(vec![false; extra_bits]);

    if bits_padded.len() % out_width != 0 {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok(bits_padded
        .chunks(out_width)
        .map(|chunk| {
            let f = bitarray_to_bytearray(chunk);
            let st = BigUint::from_radix_be(&f, 2).unwrap().to_string();
            Bn254Fr::from_str(&st).unwrap()
        })
        .collect())
}

fn big_int_array_to_bits(arr: &[BigUint], int_size: usize) -> Vec<bool> {
    let mut bitarray: Vec<bool> = Vec::new();

    for num in arr {
        let mut binary_str = num.to_str_radix(2);
        if binary_str.len() < int_size {
            let padding = "0".repeat(int_size - binary_str.len());
            binary_str = format!("{}{}", padding, binary_str);
        }
        let bits: Vec<bool> = binary_str.chars().map(|c| c == '1').collect();
        bitarray.extend(bits)
    }
    bitarray
}

/// A structed of all parsed and validated values from the masked content bytes.
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ParsedMaskedContent {
    kid: String,
    header: String,
    iss: String,
    aud: String,
    iss_str: String,
    aud_str: String,
    iss_index: u8,
    aud_index: u8,
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Default, Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl JWTHeader {
    /// Parse the header base64 string into a [struct JWTHeader].
    pub fn new(header_base64: &str) -> Result<Self, FastCryptoError> {
        let header_bytes = Base64UrlUnpadded::decode_vec(header_base64)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        let header_str =
            std::str::from_utf8(&header_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        let header: JWTHeader =
            serde_json::from_str(header_str).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(header)
    }
}
impl ParsedMaskedContent {
    /// Read a list of Claims and header string and parse them into fields
    /// header, iss, iss_index, aud, aud_index.
    pub fn new(header_base64: &str, claims: &[Claim]) -> Result<Self, FastCryptoError> {
        let header = JWTHeader::new(header_base64)?;
        if header.alg != "RS256" || header.typ != "JWT" {
            return Err(FastCryptoError::GeneralError("Invalid header".to_string()));
        }

        let mut iss = None;
        let mut aud = None;
        for claim in claims {
            match claim.name.as_str() {
                "iss" => {
                    iss = Some((
                        decode_base64_url(&claim.value_base64, &claim.index_mod_4)?,
                        claim.value_base64.clone(),
                        claim.index_mod_4,
                    ));
                }
                "aud" => {
                    aud = Some((
                        decode_base64_url(&claim.value_base64, &claim.index_mod_4)?,
                        claim.value_base64.clone(),
                        claim.index_mod_4,
                    ));
                }
                _ => {
                    return Err(FastCryptoError::GeneralError(
                        "Invalid claim name".to_string(),
                    ));
                }
            }
        }
        let iss_val = iss.ok_or(FastCryptoError::InvalidInput)?;
        let aud_val = aud.ok_or(FastCryptoError::InvalidInput)?;

        Ok(ParsedMaskedContent {
            kid: header.kid,
            header: header_base64.to_string(),
            iss: verify_extended_claim(&iss_val.0.to_string(), "iss")?,
            aud: verify_extended_claim(&aud_val.0.to_string(), "aud")?,
            iss_str: iss_val.1,
            aud_str: aud_val.1,
            iss_index: iss_val.2,
            aud_index: aud_val.2,
        })
    }

    /// Get the iss string value.
    pub fn get_iss(&self) -> &str {
        &self.iss
    }

    /// Get the aud string value.
    pub fn get_aud(&self) -> &str {
        &self.aud
    }

    /// Get the iss string value.
    pub fn get_iss_str(&self) -> &str {
        &self.iss_str
    }

    /// Get the aud string value.
    pub fn get_aud_str(&self) -> &str {
        &self.aud_str
    }

    /// Get the iss index value.
    pub fn get_iss_index(&self) -> u8 {
        self.iss_index
    }

    /// Get the aud index value.
    pub fn get_aud_index(&self) -> u8 {
        self.aud_index
    }

    /// Get the Base64 header string value.
    pub fn get_header(&self) -> &str {
        &self.header
    }

    /// Get kid string from header.
    pub fn get_kid(&self) -> &str {
        &self.kid
    }
}

fn verify_extended_claim(
    extended_claim: &str,
    expected_key: &str,
) -> Result<String, FastCryptoError> {
    // Last character of each extracted_claim must be '}' or ','
    if !(extended_claim.ends_with('}') || extended_claim.ends_with(',')) {
        return Err(FastCryptoError::InvalidInput);
    }

    let json_str = format!("{{{}}}", &extended_claim[..extended_claim.len() - 1]);
    let json: Value = serde_json::from_str(&json_str).map_err(|_| FastCryptoError::InvalidInput)?;

    if json.as_object().map(|obj| obj.len()) != Some(1) {
        return Err(FastCryptoError::InvalidInput);
    }
    let key = json.as_object().unwrap().keys().next().unwrap();
    if key != expected_key {
        return Err(FastCryptoError::InvalidInput);
    }
    let value = json[key].as_str().unwrap();
    Ok(value.to_string())
}
fn decode_base64_url(s: &str, i: &u8) -> Result<String, FastCryptoError> {
    if s.len() < 2 {
        return Err(FastCryptoError::GeneralError(
            "Length smaller than 2".to_string(),
        ));
    }
    let mut bits = base64_to_bitarray(s);
    let first_char_offset = i % 4;
    match first_char_offset {
        0 => {}
        1 => {
            bits.drain(..2);
        }
        2 => {
            bits.drain(..4);
        }
        _ => {
            return Err(FastCryptoError::GeneralError(
                "Invalid first_char_offset".to_string(),
            ));
        }
    }

    let last_char_offset = (i + s.len() as u8 - 1) % 4;
    match last_char_offset {
        3 => {}
        2 => {
            bits.drain(bits.len() - 2..);
        }
        1 => {
            bits.drain(bits.len() - 4..);
        }
        _ => {
            return Err(FastCryptoError::GeneralError(
                "Invalid last_char_offset".to_string(),
            ));
        }
    }

    if bits.len() % 8 != 0 {
        return Err(FastCryptoError::GeneralError(
            "Invalid bits length".to_string(),
        ));
    }

    Ok(std::str::from_utf8(&bits_to_bytes(&bits))
        .map_err(|_| FastCryptoError::GeneralError("Invalid masked content".to_string()))?
        .to_owned())
}
/// The zk login proof.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: String,
}

impl ZkLoginProof {
    /// Parse the proof from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let proof: ZkLoginProof =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        match proof.protocol == "groth16" {
            true => Ok(proof),
            false => Err(FastCryptoError::InvalidProof),
        }
    }

    /// Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    pub fn as_arkworks(&self) -> Proof<Bn254> {
        let a = g1_affine_from_str_projective(self.pi_a.clone());
        let b = g2_affine_from_str_projective(self.pi_b.clone());
        let c = g1_affine_from_str_projective(self.pi_c.clone());
        Proof { a, b, c }
    }
}

/// The public inputs containing an array of string that is the all inputs hash.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct PublicInputs {
    inputs: Vec<String>, // Represented the public inputs in canonical serialized form.
}

impl PublicInputs {
    /// Parse the public inputs from a json string.
    pub fn from_json(value: &str) -> Result<Self, FastCryptoError> {
        let inputs: CircomPublicInputs =
            serde_json::from_str(value).map_err(|_| FastCryptoError::InvalidProof)?;
        Ok(Self { inputs })
    }

    /// Convert the public inputs into arkworks format.
    pub fn as_arkworks(&self) -> Vec<Bn254Fr> {
        // TODO(joyqvq): check safety for valid bigint string.
        self.inputs
            .iter()
            .map(|x| Bn254Fr::from_str(x).unwrap())
            .collect()
    }

    /// Get the all_inputs_hash as big int string.
    pub fn get_all_inputs_hash(&self) -> &str {
        &self.inputs[0]
    }
}

/// Map a base64 string to a bit array by taking each char's index and covert it to binary form.
fn base64_to_bitarray(input: &str) -> Vec<bool> {
    let base64_url_character_set =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    input
        .chars()
        .flat_map(|c| {
            let index = base64_url_character_set.find(c).unwrap();
            let mut bits = Vec::new();
            for i in 0..6 {
                bits.push((index >> (5 - i)) & 1 == 1);
            }
            bits
        })
        .collect()
}

/// Convert a bitarray to a bytearray.
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bits_remaining: u8 = 8;

    for bit in bits.iter() {
        if *bit {
            current_byte |= 1 << (bits_remaining - 1);
        }
        bits_remaining -= 1;
        if bits_remaining == 0 {
            bytes.push(current_byte);
            current_byte = 0;
            bits_remaining = 8;
        }
    }

    if bits_remaining < 8 {
        bytes.push(current_byte);
    }

    bytes
}

// /// Convert a big int string to a big endian bytearray.
// pub fn big_int_str_to_bytes(value: &str) -> Vec<u8> {
//     BigInt::from_str(value)
//         .expect("Invalid big int string")
//         .to_bytes_be()
//         .1
// }

// /// Calculate the integer value from the bytearray.
// fn calculate_value_from_bytearray(arr: &[u8]) -> usize {
//     let sized: [u8; 8] = arr.try_into().expect("Invalid byte array");
//     ((sized[7] as u16) | (sized[6] as u16) << 8).into()
// }

// /// Given a chunk of bytearray, parse it as an ascii string and decode as a JWTHeader.
// /// Return the JWTHeader if its fields are valid.
// fn parse_and_validate_header(chunk: &[u8]) -> Result<JWTHeader, FastCryptoError> {
//     let header_str = std::str::from_utf8(chunk)
//         .map_err(|_| FastCryptoError::GeneralError("Cannot parse header string".to_string()))?;
//     let decoded_header = Base64UrlUnpadded::decode_vec(header_str)
//         .map_err(|_| FastCryptoError::GeneralError("Invalid jwt header".to_string()))?;
//     let json_header: Value = serde_json::from_slice(&decoded_header)
//         .map_err(|_| FastCryptoError::GeneralError("Invalid json".to_string()))?;
//     let header: JWTHeader = serde_json::from_value(json_header)
//         .map_err(|_| FastCryptoError::GeneralError("Cannot parse jwt header".to_string()))?;
//     if header.alg != "RS256" || header.typ != "JWT" {
//         Err(FastCryptoError::GeneralError("Invalid header".to_string()))
//     } else {
//         Ok(header)
//     }
// }

/// Calculate the merklized hash of the given bytes after 0 paddings.
pub fn calculate_merklized_hash(bytes: &[u8]) -> Result<String, FastCryptoError> {
    let mut bitarray = bytearray_to_bits(bytes);
    pad_bitarray(&mut bitarray, 248);
    let bigints = convert_to_bigints(&bitarray, 248);
    Ok(to_poseidon_hash(bigints)?.to_string())
}

/// Calculate the hash of the inputs.
pub fn to_poseidon_hash(inputs: Vec<Bn254Fr>) -> Result<Bn254Fr, FastCryptoError> {
    if inputs.len() <= 15 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        poseidon1.hash(inputs)
    } else if inputs.len() <= 30 {
        let mut poseidon1: PoseidonWrapper = PoseidonWrapper::new();
        let hash1 = poseidon1.hash(inputs[0..15].to_vec())?;

        let mut poseidon2 = PoseidonWrapper::new();
        let hash2 = poseidon2.hash(inputs[15..].to_vec())?;

        let mut poseidon3 = PoseidonWrapper::new();
        poseidon3.hash([hash1, hash2].to_vec())
    } else {
        Err(FastCryptoError::InvalidInput)
    }
}

/// Convert a bytearray to a bitarray.
fn bytearray_to_bits(bytearray: &[u8]) -> Vec<bool> {
    bytearray
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

/// Convert a bitarray to a bytearray.
fn bitarray_to_bytearray(bitarray: &[bool]) -> Vec<u8> {
    bitarray.iter().map(|&b| u8::from(b)).collect()
}

/// Pad the bitarray some number of 0s so that its length is a multiple of the segment size.
fn pad_bitarray(bitarray: &mut Vec<bool>, segment_size: usize) {
    let remainder = bitarray.len() % segment_size;
    if remainder != 0 {
        bitarray.extend(std::iter::repeat(false).take(segment_size - remainder));
    }
}

/// Convert a bitarray to a vector of field elements, padded using segment size.
fn convert_to_bigints(bitarray: &[bool], segment_size: usize) -> Vec<Bn254Fr> {
    let chunks = bitarray.chunks(segment_size);
    chunks
        .map(|chunk| {
            let mut bytes = vec![0; (segment_size + 7) / 8];
            for (i, &bit) in chunk.iter().enumerate() {
                bytes[i / 8] |= (bit as u8) << (7 - i % 8);
            }
            let f = bitarray_to_bytearray(chunk);
            let st = BigUint::from_radix_be(&f, 2).unwrap().to_string();
            Bn254Fr::from_str(&st).unwrap()
        })
        .collect()
}
