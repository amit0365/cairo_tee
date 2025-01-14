use crate::types::{enclave_identity::EnclaveIdentityV2, TcbStatus, quotes::body::EnclaveReport};
use crate::verify::crypto::verify_p256_signature;
use crate::types::cert::X509CertificateData;
use core::sha256::compute_sha256_byte_array;
use crate::types::TcbStatusImpl;
use super::super::utils::byte::ArrayU8ExtTrait;
use crate::utils::byte::{u32s_to_u8s, u32s_typed_to_u256};

pub fn validate_enclave_identityv2(enclave_identityv2: @EnclaveIdentityV2, sgx_signing_cert: @X509CertificateData, current_time: u64) -> bool {
    // get tcb_info_root time
    // let issue_date = chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.issue_date).unwrap();
    // let next_update_date = chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.next_update).unwrap();

    // // convert the issue_date and next_update_date to seconds since epoch
    // let issue_date_seconds = issue_date.timestamp() as u64;
    // let next_update_seconds = next_update_date.timestamp() as u64;

    // // check that the current time is between the issue_date and next_update_date
    // if current_time < issue_date_seconds || current_time > next_update_seconds {
    //     return false;
    // }

    let mut enclave_identityv2_signature_data = array![];
    Serde::serialize(enclave_identityv2.signature, ref enclave_identityv2_signature_data);
    let (public_key_x, public_key_y) = (sgx_signing_cert.tbs_certificate_data.subject_pki.x, sgx_signing_cert.tbs_certificate_data.subject_pki.y);
    let enclave_identityv2_signature_data_u8s = u32s_to_u8s(enclave_identityv2_signature_data.span()).into_byte_array(); 
    let enclave_identityv2_signature_data_hash: u256 = u32s_typed_to_u256(@compute_sha256_byte_array(@enclave_identityv2_signature_data_u8s));
    verify_p256_signature(enclave_identityv2_signature_data_hash, (public_key_x, public_key_y), enclave_identityv2.signature.r, enclave_identityv2.signature.s)
}

pub fn get_qe_tcbstatus(enclave_report: @EnclaveReport, qeidentityv2: @EnclaveIdentityV2) -> TcbStatus {
    let mut tcb_status_found: TcbStatus = TcbStatus::TcbUnrecognized;
    let mut found_tcb_level: bool = false;
    for i in 0..qeidentityv2.enclave_identity.tcb_levels.deref().len() {
        let tcb_level = qeidentityv2.enclave_identity.tcb_levels[i];
        if tcb_level.tcb.isvsvn <= enclave_report.isv_svn {
            let tcb_status = TcbStatusImpl::from_str(tcb_level.tcb_status.clone());
            tcb_status_found = tcb_status;
            found_tcb_level = true;
        }
    };

    if !found_tcb_level {
        return TcbStatus::TcbUnrecognized;
    }
    tcb_status_found
}