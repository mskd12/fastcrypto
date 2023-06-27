// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
use num_bigint::BigUint;

use crate::bn254::{
    zk_login::{AuxInputs, JWTHeader, OAuthProviderContent, PublicInputs, ZkLoginProof},
    zk_login_api::verify_zk_login,
};

#[test]
fn test_verify_groth16_in_bytes_api() {
    // let i: u32 = 65537;
    let exponent = Base64UrlUnpadded::decode_vec("AQAB").unwrap();
    let f = BigUint::from_bytes_be(&exponent);
    println!("f: {:?}", f);
    let aux_inputs = AuxInputs::from_json("{\"claims\": [{\"name\": \"iss\",\"value_base64\":\"yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC\",\"index_mod_4\": 1},{\"name\": \"aud\",\"value_base64\": \"CJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLC\",\"index_mod_4\": 1}], \"header_base64\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ\",\"addr_seed\": \"15604334753912523265015800787270404628529489918817818174033741053550755333691\",\"eph_public_key\": [\"17932473587154777519561053972421347139\", \"134696963602902907403122104327765350261\"],\"max_epoch\": 10000,\"key_claim_name\": \"sub\",\"modulus\": \"24501106890748714737552440981790137484213218436093327306276573863830528169633224698737117584784274166505493525052788880030500250025091662388617070057693555892212025614452197230081503494967494355047321073341455279175776092624566907541405624967595499832566905567072654796017464431878680118805774542185299632150122052530877100261682728356139724202453050155758294697161107805717430444408191365063957162605112787073991150691398970840390185880092832325216009234084152827135531285878617366639283552856146367480314853517993661640450694829038343380576312039548353544096265483699391507882147093626719041048048921352351403884619\"}").unwrap();
    let public_inputs = PublicInputs::from_json(
        "[\"6049184272607241856912886413680599526372437331989542437266935645748489874658\"]",
    )
    .unwrap();
    assert_eq!(
        aux_inputs.calculate_all_inputs_hash().unwrap(),
        public_inputs.get_all_inputs_hash()
    );

    // assert_eq!(
    //     aux_inputs.get_jwt_hash(),
    //     vec![
    //         187, 81, 38, 253, 76, 198, 157, 166, 214, 87, 161, 53, 77, 141, 223, 15, 85, 99, 17,
    //         247, 75, 248, 40, 150, 239, 21, 140, 190, 12, 123, 242, 175
    //     ]
    // );
    // assert_eq!(
    //     aux_inputs.get_eph_pub_key(),
    //     vec![
    //         13, 125, 171, 53, 140, 141, 173, 170, 78, 250, 0, 73, 167, 91, 7, 67, 101, 85, 177, 10,
    //         54, 130, 25, 187, 104, 15, 112, 87, 19, 73, 215, 117
    //     ]
    // );
    // assert_eq!(aux_inputs.get_max_epoch(), 10000);
    // assert!(aux_inputs.get_jwt_signature().is_ok());
    // assert_eq!(aux_inputs.get_iss(), OAuthProvider::Google.get_config().0);
    // assert_eq!(aux_inputs.get_claim_name(), "sub");
    // assert_eq!(
    //     aux_inputs.get_client_id(),
    //     "575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com"
    // );
    let mut map = HashMap::new();
    map.insert("c9afda3682ebf09eb3055c1c4bd39b751fbf8195", OAuthProviderContent {
        kty: "RSA".to_string(),
        e: "AQAB".to_string(),
        n: "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw".to_string(),
        alg: "RS256".to_string(),
    });
    let proof = ZkLoginProof::from_json("{\"pi_a\":[\"21079899190337156604543197959052999786745784780153100922098887555507822163222\",\"4490261504756339299022091724663793329121338007571218596828748539529998991610\",\"1\"],\"pi_b\":[[\"9379167206161123715528853149920855132656754699464636503784643891913740439869\",\"15902897771112804794883785114808675393618430194414793328415185511364403970347\"],[\"16152736996630746506267683507223054358516992879195296708243566008238438281201\",\"15230917601041350929970534508991793588662911174494137634522926575255163535339\"],[\"1\",\"0\"]],\"pi_c\":[\"8242734018052567627683363270753907648903210541694662698981939667442011573249\",\"1775496841914332445297048246214170486364407018954976081505164205395286250461\",\"1\"],\"protocol\":\"groth16\"}");
    assert!(proof.is_ok());
    let res = verify_zk_login(&proof.unwrap(), &public_inputs, &aux_inputs, 1, map);
    println!("{:?}", res);
    assert!(res.is_ok());
}

// #[test]
// fn test_masked_content_parse() {
//     // bytes after 64 * num_sha2_blocks contains non-zeros fails.
//     let content = ParsedMaskedContent::new(&[1; 65], 0, 0, 1);
//     assert!(content.is_err());

//     // payload index must be >= 1
//     let content = ParsedMaskedContent::new(&[0; 65], 0, 0, 1);
//     assert!(content.is_err());

//     // value at (payload index - 1) must be "."
//     // TODO: cover all parsed masked content logic
// }

#[test]
fn test_() {
    let d = JWTHeader::new("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM5YWZkYTM2ODJlYmYwOWViMzA1NWMxYzRiZDM5Yjc1MWZiZjgxOTUiLCJ0eXAiOiJKV1QifQ").unwrap();
    println!("{:?}", d);
}
