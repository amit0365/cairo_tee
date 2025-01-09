use cainome_cairo_serde::{self, CairoSerde};
use starknet_types_core::felt::Felt as Felt252;
use dcap_rs::types::{collaterals::IntelCollateral, quotes::version_4::QuoteV4};
use crate::parsed_inputs::{into_wrapper_x509_cert, ToNestedBytes, X509CertificateIndex};

fn prepare_parsed_inputs(
    collaterals: &[u8],
){
  let intel_collaterals = IntelCollateral::from_bytes(collaterals);
//   println!("collaterals sgx_tcb_signing_der signature {:?}", &intel_collaterals.clone().sgx_tcb_signing_der.unwrap()[572..]);
  let sgx_tcb_signing_cert = intel_collaterals.get_sgx_tcb_signing();
//   println!("sgx_tcb_signing_cert.signature_algorithm {:?}", &sgx_tcb_signing_cert.signature_algorithm);
//   println!("sgx_tcb_signing_cert.signature_value {:?}", &sgx_tcb_signing_cert.signature_value);
  let parsed_sgx_tcb_signing_cert = into_wrapper_x509_cert(&sgx_tcb_signing_cert);
  let (parsed_sgx_tcb_signing_cert_indices_raw, parsed_sgx_tcb_signing_cert_bytes) = parsed_sgx_tcb_signing_cert.to_der_bytes(0);
//   println!("parsed_sgx_tcb_signing_cert_indices_raw {:?}", &parsed_sgx_tcb_signing_cert_indices_raw[28..]);
  let parsed_sgx_tcb_signing_cert_indices = X509CertificateIndex::from_indices(parsed_sgx_tcb_signing_cert_indices_raw);
//   println!("parsed_sgx_tcb_signing_cert_bytes len {:?}", &parsed_sgx_tcb_signing_cert_bytes.len());
  let parsed_sgx_tcb_signing_cert_extracted = parsed_sgx_tcb_signing_cert_indices.extract_certificate(&parsed_sgx_tcb_signing_cert_bytes);
  // assert_eq!(parsed_sgx_tcb_signing_cert.as_ref(), parsed_sgx_tcb_signing_cert_extracted.as_ref());
}

// fn serialise_collateral_inputs(
//   collaterals: &IntelCollateral,
// ) { 

//   let collaterals_bytes = collaterals.to_bytes();
//   let felts = Vec::<u8>::cairo_serialize(&collaterals_bytes);
//   let txt_data = format!("{:?}", felts);
//   std::fs::write("src/cairo/src/collateral_inputs.txt", txt_data).unwrap();
// }

// pub fn verify_p256_signature_bytes_inputs(data: &[u8], signature: &[u8], public_key: &[u8]) {
//     let data_felt: Felt252 = Felt252::from_bytes_be(data.try_into().unwrap());
//     let pubkey_felt = Felt252::from_bytes_be(public_key.try_into().unwrap());
//     let signature_r = &signature[..32];
//     let signature_s = &signature[32..];
//     let signature_r_felt = Felt252::from_bytes_be(signature_r.try_into().unwrap());
//     let signature_s_felt = Felt252::from_bytes_be(signature_s.try_into().unwrap());
    
//     let txt_data = format!("{}\n{}\n{}\n{}", 
//         data_felt.to_bigint(),
//         pubkey_felt.to_bigint(),
//         signature_r_felt.to_bigint(),
//         signature_s_felt.to_bigint()
//     );

//     std::fs::write("src/cairo/src/signature_inputs.txt", txt_data).unwrap();
// }

#[test]
fn test_prepare_parsed_inputs() {
    let mut collaterals = IntelCollateral::new();
    collaterals.set_tcbinfo_bytes(include_bytes!("../data/tcbinfov3_00806f050000.json"));
    collaterals.set_qeidentity_bytes(include_bytes!("../data/qeidentityv2_apiv4.json"));
    collaterals.set_intel_root_ca_der(include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer"));
    collaterals.set_sgx_tcb_signing_pem(include_bytes!("../data/signing_cert.pem"));
    collaterals.set_sgx_intel_root_ca_crl_der(include_bytes!("../data/intel_root_ca_crl.der"));
    collaterals.set_sgx_platform_crl_der(include_bytes!("../data/pck_platform_crl.der"));
    collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));
    //println!("sgx_tcb_signing_der {:?}", collaterals.clone().sgx_tcb_signing_der.map(|b| b.len()));

    let collaterals_bytes = collaterals.to_bytes();
    //prepare_parsed_inputs(&collaterals_bytes);
}

#[test]
fn test_serialise_collateral_inputs() {
  let tcb_signing_cert = include_bytes!("../data/signing_cert.pem").to_vec();
  let tcb_signing_cert_felts = Vec::<u8>::cairo_serialize(&tcb_signing_cert);
  let txt_data = format!("{:?}", tcb_signing_cert_felts);
  std::fs::write("src/tcb_signing_cert.txt", txt_data).unwrap();
}

// fn test_verify_p256_signature_bytes_inputs() { 
//     let message_hash = "02d6479c0758efbb5aa07d35ed5454d728637fceab7ba544d3ea95403a5630a8";
//     let message_hash_bytes = hex::decode(message_hash).unwrap();
//     let pubkey = "01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca";
//     let pubkey_bytes = hex::decode(pubkey).unwrap();
//     let r = "06ff7b413a8457ef90f326b5280600a4473fef49b5b1dcdfcd7f42ca7aa59c69";
//     let s = "0023a9747ed71abc5cb956c0df44ee8638b65b3e9407deade65de62247b8fd77";
//     let r_bytes = hex::decode(r).unwrap();
//     let s_bytes = hex::decode(s).unwrap();
//     let signature = [r_bytes, s_bytes].concat();
//     verify_p256_signature_bytes_inputs(&message_hash_bytes, &signature, &pubkey_bytes);
// }