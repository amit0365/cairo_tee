use starknet::secp256r1::{Secp256r1Point, secp256r1_new_syscall}; 
use starknet::secp256_trait::is_valid_signature;
use core::sha256::compute_sha256_u32_array;
use crate::utils::byte::u8_to_u32_be;

fn verify_p256_signature(data: u256, public_key: (@u256, @u256), r: @u256, s: @u256) -> bool {
    let (x, y) = public_key;
    let public_key_point: Secp256r1Point = secp256r1_new_syscall(x.clone(), y.clone()).unwrap().unwrap();
    is_valid_signature::<Secp256r1Point>(data, r.clone(), s.clone(), public_key_point)
}