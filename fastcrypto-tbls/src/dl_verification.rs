use crate::polynomial::PrivatePoly;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{bls12381, GroupElement, MultiScalarMul, Pairing, Scalar};
use fastcrypto::traits::AllowedRng;
use std::num::NonZeroU32;
use std::ops::Mul;

/// Helper functions for checking relations between scalars and group elements.

/// Check that a pair (k, H) satisfies H = k*G using a random combination of the pairs and
/// multi scalar multiplication.
pub fn verify_pairs<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    pairs: &[(G::ScalarType, G)],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    // Denote the inputs by (k1, H1), (k2, H2), ..., (kn, Hn)
    // Generate random r1, r2, ..., rn
    let rs = get_random_scalars::<G, R>(pairs.len() as u32, rng);
    // Compute (r1*k1 + r2*k2 + ... + rn*kn)*G
    let lhs = G::generator()
        * rs.iter()
            .zip(pairs.iter())
            .fold(G::ScalarType::zero(), |acc, (r, (k, _))| acc + *r * *k);
    // Compute r1*H1 + r2*H2 + ... + rn*Hn
    let rhs = G::multi_scalar_mul(
        &rs[..],
        &pairs.iter().map(|(_, g)| g.clone()).collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");

    if lhs == rhs {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

/// Check that a triplet (k, G, H) satisfies H = k*G using a random combination of the
/// triplets and multi scalar multiplication.
pub fn verify_triplets<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    triplets: &[(G::ScalarType, G, G)],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if triplets.is_empty() {
        return Ok(());
    }
    // Denote the inputs by (k1, G1, H1), (k2, G2, H2), ..., (kn, Gn, Hn)
    // Generate random r1, r2, ..., rn
    let rs = get_random_scalars::<G, R>(triplets.len() as u32, rng);
    // Compute r1*k1, r2*k2, ..., rn*kn
    let lhs_coeffs = rs
        .iter()
        .zip(triplets.iter())
        .map(|(r, (k, _, _))| *r * *k)
        .collect::<Vec<_>>();
    // Compute r1*k1*G1 + r2*k2*G2 + ... + rn*kn*Gn
    let lhs = G::multi_scalar_mul(
        &lhs_coeffs[..],
        &triplets
            .iter()
            .map(|(_, b, _)| b.clone())
            .collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");
    // Compute r1*H1 + r2*H2 + ... + rn*Hn
    let rhs = G::multi_scalar_mul(
        &rs[..],
        &triplets
            .iter()
            .map(|(_, _, k_b)| k_b.clone())
            .collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");

    if lhs == rhs {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

/// Check that partial public keys form a polynomial of the right degree using the protocol of
/// https://eprint.iacr.org/2017/216.pdf. deg_f should be n-k-2 if the polynomial is of degree k.
pub fn verify_deg_t_poly<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    deg_f: u32,
    values: &[G],
    precomputed_dual_code_coefficients: &Vec<G::ScalarType>,
    rng: &mut R,
) -> FastCryptoResult<()> {
    let poly_f = PrivatePoly::<G>::rand(deg_f, rng);
    let coefficients = precomputed_dual_code_coefficients
        .iter()
        .enumerate()
        .map(|(i, c)| *c * poly_f.eval(NonZeroU32::new((i + 1) as u32).unwrap()).value)
        .collect::<Vec<_>>();
    let lhs = G::multi_scalar_mul(&coefficients[..], values).expect("sizes match");
    if lhs != G::zero() {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

/// Checks if vectors v1=(a1*G1, ..., an*G1) and v2=(a1'*G2, ..., an'*G2) use ai = ai' for all i, by
/// computing <v1, e> and <v2, e> for a random e and checking if they are equal using pairing.
pub fn verify_equal_exponents<R: AllowedRng>(
    g1: &[bls12381::G1Element],
    g2: &[bls12381::G2Element],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if g1.len() != g2.len() {
        return Err(FastCryptoError::InvalidProof);
    }
    let rs = get_random_scalars::<bls12381::G1Element, R>(g1.len() as u32, rng);
    let lhs = bls12381::G1Element::multi_scalar_mul(&rs[..], g1).expect("sizes match");
    let rhs = bls12381::G2Element::multi_scalar_mul(&rs[..], g2).expect("sizes match");

    if lhs.pairing(&bls12381::G2Element::generator())
        != bls12381::G1Element::generator().pairing(&rhs)
    {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

pub fn get_random_scalars<G: GroupElement, R: AllowedRng>(
    n: u32,
    rng: &mut R,
) -> Vec<<G as GroupElement>::ScalarType> {
    // TODO: can use 40 bits instead of 64 (& 0x000F_FFFF_FFFF_FFFF below)
    (0..n)
        .into_iter()
        .map(|_| G::ScalarType::from(rng.next_u64()))
        .collect::<Vec<_>>()
}
