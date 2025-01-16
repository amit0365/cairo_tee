use super::super::utils::byte::ArrayU8ExtTrait;
use crate::verify::crypto::verify_p256_signature;
use crate::types::tcbinfo::{TcbInfoV2, TcbInfoV3};
use crate::types::cert::{X509CertificateData};
use core::sha256::compute_sha256_byte_array;
use crate::utils::x509_decode::X509CertObj;
use crate::utils::byte::{u32s_to_u8s, u32s_typed_to_u256, SpanU8TryIntoU256};
// use crate::utils::crypto::verify_p256_signature_bytes;
// use crate::X509Certificate;

pub fn validate_tcbinfov2(tcbinfov2: @TcbInfoV2, sgx_signing_cert: @X509CertObj, current_time: u64) -> bool {
    // get tcb_info_root time
    // let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.issue_date).unwrap();
    // let next_update_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.next_update).unwrap();

    // // convert the issue_date and next_update_date to seconds since epoch
    // let issue_date_seconds = issue_date.timestamp() as u64;
    // let next_update_seconds = next_update_date.timestamp() as u64;

    // // check that the current time is between the issue_date and next_update_date
    // if current_time < issue_date_seconds || current_time > next_update_seconds {
    //     assert!(false);
    //     return false;
    // }

    // verify that the tcb_info_root is signed by the root cert
    let mut tcbinfov2_signature_data = array![];
    Serde::serialize(tcbinfov2.tcb_info, ref tcbinfov2_signature_data);
    let (public_key_x, public_key_y) = sgx_signing_cert.subject_public_key;
    let public_key_x = SpanU8TryIntoU256::try_into(public_key_x.deref()).unwrap();
    let public_key_y = SpanU8TryIntoU256::try_into(public_key_y.deref()).unwrap();
    let tcbinfov2_signature_data_u8s = u32s_to_u8s(tcbinfov2_signature_data.span()).into_byte_array(); 
    let tcbinfov2_signature_data_hash: u256 = u32s_typed_to_u256(@compute_sha256_byte_array(@tcbinfov2_signature_data_u8s));
    verify_p256_signature(tcbinfov2_signature_data_hash, (@public_key_x, @public_key_y), tcbinfov2.signature.r, tcbinfov2.signature.s)
}

pub fn validate_tcbinfov3(tcbinfov3: @TcbInfoV3, sgx_signing_cert: @X509CertObj, current_time: u64) -> bool {
    // get tcb_info_root time
    // let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.issue_date).unwrap();
    // let next_update_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.next_update).unwrap();

    // // convert the issue_date and next_update_date to seconds since epoch
    // let issue_date_seconds = issue_date.timestamp() as u64;
    // let next_update_seconds = next_update_date.timestamp() as u64;

    // // check that the current time is between the issue_date and next_update_date
    // if current_time < issue_date_seconds || current_time > next_update_seconds {
    //     assert!(false);
    //     return false;
    // }

    // verify that the tcb_info_root is signed by the root cert
    let mut tcbinfov3_signature_data = array![];
    Serde::serialize(tcbinfov3.tcb_info, ref tcbinfov3_signature_data);
    let (public_key_x, public_key_y) = sgx_signing_cert.subject_public_key;
    let public_key_x = SpanU8TryIntoU256::try_into(public_key_x.deref()).unwrap();
    let public_key_y = SpanU8TryIntoU256::try_into(public_key_y.deref()).unwrap();
    let tcbinfov3_signature_data = u32s_to_u8s(tcbinfov3_signature_data.span()).into_byte_array(); 
    let tcbinfov3_signature_data_hash: u256 = u32s_typed_to_u256(@compute_sha256_byte_array(@tcbinfov3_signature_data));
    verify_p256_signature(tcbinfov3_signature_data_hash, (@public_key_x, @public_key_y), tcbinfov3.signature.r, tcbinfov3.signature.s)
}
