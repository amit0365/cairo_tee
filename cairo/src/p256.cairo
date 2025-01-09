use core::ecdsa::check_ecdsa_signature;
use starknet::secp256_trait::Signature;
use alexandria_encoding::base64;
use snforge_std::fs::{FileTrait, read_txt};

fn verify_p256_signature_felt(data: felt252, public_key: felt252, r: felt252, s: felt252) -> bool {
    check_ecdsa_signature(data, public_key, r, s)
}

#[test]
fn test_verify_p256_signature_felt(inputs: Array<ByteArray>) {     
    let path_bytes: ByteArray = "src/signature_inputs.txt";
    let file = FileTrait::new(path_bytes);
    let inputs: Array<felt252> = read_txt(@file);

    // let mut x: Array<ByteArray> = ArrayTrait::new();
    // let x_bytes: ByteArray = "src/signature_inputs.txt";
    // x.append(x_bytes);

    let message_hash = *inputs.at(0);
    let pubkey = *inputs.at(1);
    let r = *inputs.at(2);
    let s = *inputs.at(3);

    let result = verify_p256_signature_felt(message_hash.clone(), pubkey.clone(), r.clone(), s.clone());
    assert(result, 'Signature verification failed');
}

