// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::bls12381;
use fastcrypto_tbls::ecies;
use fastcrypto_tbls::nidkg::{Party, PkiNode};
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::types::ShareIndex;
use rand::thread_rng;

type G = bls12381::G1Element;

fn gen_ecies_keys(n: usize) -> Vec<(ShareIndex, ecies::PrivateKey<G>, ecies::PublicKey<G>)> {
    (1..=n)
        .into_iter()
        .map(|id| {
            let sk = ecies::PrivateKey::<G>::new(&mut thread_rng());
            let pk = ecies::PublicKey::<G>::from_private_key(&sk);
            (ShareIndex::new(id as u32).unwrap(), sk, pk)
        })
        .collect()
}

pub fn setup_party(
    id: usize,
    threshold: u32,
    keys: &[(ShareIndex, ecies::PrivateKey<G>, ecies::PublicKey<G>)],
) -> Party<G> {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| PkiNode::<G> {
            id: *id,
            pk: pk.clone(),
        })
        .collect();
    Party::<G>::new(
        keys.get(id - 1).unwrap().1.clone(),
        nodes,
        threshold,
        RandomOracle::new("dkg"),
        &mut thread_rng(),
    )
    .unwrap()
}

mod nidkg_benches {
    use super::*;

    fn nidkg(c: &mut Criterion) {
        const SIZES: [usize; 1] = [512];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("NI-DKG create");
            for n in SIZES {
                let t = (n / 2) as u32;
                let keys = gen_ecies_keys(n);
                let d1 = setup_party(1, t, &keys);
                let d2 = setup_party(2, t, &keys);

                create.bench_function(format!("n={}, t={}", n, t).as_str(), |b| {
                    b.iter(|| d1.create_message(&mut thread_rng()))
                });
            }
        }

        {
            let mut verify: BenchmarkGroup<_> = c.benchmark_group("NI-DKG message verification");
            for n in SIZES {
                let t = (n / 2) as u32;
                let keys = gen_ecies_keys(n);
                let d1 = setup_party(1, t, &keys);
                let d2 = setup_party(2, t, &keys);
                let m = d1.create_message(&mut thread_rng());

                verify.bench_function(format!("n={}, t={}", n, t).as_str(), |b| {
                    b.iter(|| d2.verify_message(&m, &mut thread_rng()))
                });
            }
        }
    }

    criterion_group! {
        name = nidkg_benches;
        config = Criterion::default();
        targets = nidkg,
    }
}

criterion_main!(nidkg_benches::nidkg_benches);
