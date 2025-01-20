use cairo::types::cert::{CertificateRevocationList, X509CertificateData, TbsCertificateDataListImpl, TbsCertificateDataImpl};
use crate::utils::byte::{felt252s_to_u8s, u32s_typed_to_u256, u8s_typed_to_u256, SpanU8TryIntoU256};
use cairo::verify::crypto::verify_p256_signature;
use super::super::utils::byte::ArrayU8ExtTrait;
use core::sha256::compute_sha256_byte_array;
use cairo::utils::x509_decode::X509CertObj;
use crate::utils::x509crl_decode::X509CRLObj;
use crate::utils::pck_parse::PCKCertTCB;
use crate::types::tcbinfo::TcbInfoV3;
use crate::types::TcbStatus;
use core::array::SpanIntoIterator;

// pub fn check_certificate(
//     cert: @X509CertificateData,
//     issuer: @X509CertificateData,
//     crl: @CertificateRevocationList,
//     subject_name: @str,
//     current_time: u64,
// ) -> bool {
//     let is_cert_valid = validate_certificate(
//         cert,
//         crl,
//         subject_name,
//         issuer.subject().to_string().as_str(),
//         current_time,
//     );
//     let is_cert_verified = verify_certificate(cert, issuer);
//     is_cert_valid && is_cert_verified
// }

pub fn verify_certificate(cert: @X509CertObj, signer_cert: @X509CertObj) -> bool {
    // verifies that the certificate is valid
    let data_hash: u256 = sha256_as_u256(cert.tbs.deref().into_byte_array());

    let (signature_r, signature_s) = cert.signature;
    let signature_r = @SpanU8TryIntoU256::try_into(signature_r.deref()).unwrap();
    let signature_s = @SpanU8TryIntoU256::try_into(signature_s.deref()).unwrap();

    let (public_key_x, public_key_y) = signer_cert.subject_public_key;
    let public_key_x = @SpanU8TryIntoU256::try_into(public_key_x.deref()).unwrap();
    let public_key_y = @SpanU8TryIntoU256::try_into(public_key_y.deref()).unwrap();
    // make sure that the issuer is the signer
    if cert.issuer_common_name != signer_cert.issuer_common_name {
        return false;
    }
    verify_p256_signature(data_hash, (public_key_x, public_key_y), signature_r, signature_s)
}

pub fn verify_crl(crl: @X509CRLObj, signer_cert: @X509CertObj) -> bool {
    // verifies that the crl is valid
    let data = crl.tbs;
    let data_hash: u256 = sha256_as_u256(data.deref().into_byte_array());

    let (signature_r, signature_s) = crl.signature;
    let signature_r = @SpanU8TryIntoU256::try_into(signature_r.deref()).unwrap();
    let signature_s = @SpanU8TryIntoU256::try_into(signature_s.deref()).unwrap();

    let (public_key_x, public_key_y) = signer_cert.subject_public_key;
    let public_key_x = @SpanU8TryIntoU256::try_into(public_key_x.deref()).unwrap();
    let public_key_y = @SpanU8TryIntoU256::try_into(public_key_y.deref()).unwrap();
    // make sure that the issuer is the signer
    if crl.issuer_common_name != signer_cert.subject_common_name {
        return false;
    }
    verify_p256_signature(data_hash, (public_key_x, public_key_y), signature_r, signature_s)
}

// pub fn validate_certificate(
//     _cert: @X509CertificateData,
//     crl: @CertificateRevocationList,
//     subject_name: @str,
//     issuer_name: @str,
//     current_time: u64,
// ) -> bool {
//     // check that the certificate is a valid cert.
//     // i.e., make sure that the cert name is correct, issued by intel,
//     // has not been revoked, etc.
//     // for now, we'll just return true

//     // check if certificate is expired
//     let issue_date = _cert.validity().not_before.timestamp() as u64;
//     let expiry_date = _cert.validity().not_after.timestamp() as u64;

//     if (current_time < issue_date) || (current_time > expiry_date) {
//         return false;
//     }

//     // check that the certificate is issued to the correct subject
//     if _cert.subject().to_string().as_str() != subject_name {
//         return false;
//     }

//     // check if certificate is issued by the correct issuer
//     if _cert.issuer().to_string().as_str() != issuer_name {
//         return false;
//     }

//     // check if certificate has been revoked
//     let is_revoked = crl.iter_revoked_certificates().any(|entry| {
//         (entry.revocation_date.timestamp() as u64) < current_time
//             && entry.user_certificate == _cert.tbs_certificate.serial
//     });

//     !is_revoked
// }

// // we'll just verify that the certchain signature matches, any other checks will be done by the caller
pub fn verify_certchain_signature(
    certs: @Span<X509CertObj>,
    root_cert: @X509CertObj,
) -> bool {
    // verify that the cert chain is valid
    let mut valid = false;
    let mut prev_cert = certs.deref().at(1);
    for i in 0..certs.deref().len() {
        let cert = certs.deref().at(i);
        // verify that the previous cert signed the current cert
        if !verify_certificate(prev_cert, cert) {
            valid = false;
            break;
        }
        prev_cert = cert;
    };
    // verify that the root cert signed the last cert
    if valid {
        valid = verify_certificate(prev_cert, root_cert);
    };
    valid
}

pub fn is_cert_revoked(
    cert: @X509CertificateData,
    crl: @CertificateRevocationList,
) -> bool {
    let mut i = 0;
    let mut revoked = false;
    while i < crl.tbs_cert_list.revoked_certificates.deref().len() {
        if crl.tbs_cert_list.revoked_certificates[i].user_certificate == cert.tbs_certificate_data.serial {
            revoked = true;
            break;
        }
        i += 1;
    };
    revoked
}

// // Slightly modified from https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181
// pub fn get_sgx_tdx_fmspc_tcbstatus_v3(
//     tee_type: u32,
//     sgx_extensions: @PCKCertTCB,
//     tee_tcb_svn: [u8; 16],
//     tcbinfov3: @TcbInfoV3,
// ) -> (TcbStatus, TcbStatus, Option<Span<String>>) {
//     // we'll make sure the tcbinforoot is valid
//     // check that fmspc is valid
//     // check that pceid is valid

//     // convert tcbinfo fmspc and pceid from string to bytes for comparison
//     assert!(sgx_extensions.fmspc_bytes == tcbinfov3.tcb_info.fmspc);
//     assert!(sgx_extensions.pceid_bytes == tcbinfov3.tcb_info.pce_id);

//     let mut sgx_tcb_status = TcbStatus::TcbUnrecognized;
//     let mut tdx_tcb_status = TcbStatus::TcbUnrecognized;

//     let extension_pcesvn = sgx_extensions.pcesvn;
//     let mut advisory_ids = Option::None;

//     for tcb_level in tcbinfov3.tcb_info.tcb_levels.deref().into_iter() {
//         if sgx_tcb_status == TcbStatus::TcbUnrecognized {
//             let sgxtcbcomponents_ok =
//                 match_sgxtcbcomp(sgx_extensions, @tcb_level.tcb.sgxtcbcomponents);
//             let pcesvn_ok = extension_pcesvn >= tcb_level.pcesvn;
//             if sgxtcbcomponents_ok && pcesvn_ok {
//                 sgx_tcb_status = TcbStatus::from_str(tcb_level.tcb_status.as_str());
//                 if tee_type == SGX_TEE_TYPE {
//                     advisory_ids = tcb_level.advisory_ids.clone();
//                 }
//             }
//         }
//         if sgx_tcb_status != TcbStatus::TcbUnrecognized || sgx_tcb_status != TcbStatus::TcbRevoked {
//             if !is_empty(tee_tcb_svn) {
//                 let tdxtcbcomponents_ok = match tcb_level.tcb.tdxtcbcomponents.as_ref() {
//                     Some(tdxtcbcomponents) => tdxtcbcomponents
//                         .iter()
//                         .zip(tee_tcb_svn.iter())
//                         .all(|(tcb, tee)| *tee >= tcb.svn as u8),
//                     None => true,
//                 };
//                 if tdxtcbcomponents_ok {
//                     tdx_tcb_status = TcbStatus::from_str(tcb_level.tcb_status.as_str());
//                     if tee_type == TDX_TEE_TYPE {
//                         advisory_ids = tcb_level.advisory_ids.clone();
//                     }
//                     break;
//                 }
//             }
//         }
//     };
//     (sgx_tcb_status, tdx_tcb_status, advisory_ids)
// }

/// computes the sha256 of the input and returns it as a u256.
pub fn sha256_as_u256(input: ByteArray) -> u256 {
    let hash_result = compute_sha256_byte_array(@input);
    let mut value: u256 = 0;
    for word in hash_result.span() {
        value *= 0x100000000;
        value = value + (*word).into();
    };
    value
}