use cairo::types::cert::{CertificateRevocationList, X509CertificateData, TbsCertificateDataListImpl, TbsCertificateDataImpl};
use crate::utils::byte::{u32s_to_u8s, u32s_typed_to_u256};
use cairo::verify::crypto::verify_p256_signature;
use super::super::utils::byte::ArrayU8ExtTrait;
use core::sha256::compute_sha256_byte_array;

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

pub fn verify_certificate(cert: @X509CertificateData, signer_cert: @X509CertificateData) -> bool {
    // verifies that the certificate is valid
    let data = TbsCertificateDataImpl::as_ref(cert.tbs_certificate_data);
    let data_hash: u256 = u32s_typed_to_u256(@compute_sha256_byte_array(@data.into_byte_array()));

    let signature = cert.signature_value;
    let public_key = signer_cert.tbs_certificate_data.subject_pki;
    // make sure that the issuer is the signer
    if cert.tbs_certificate_data.issuer != signer_cert.tbs_certificate_data.subject {
        return false;
    }
    verify_p256_signature(data_hash, (public_key.x, public_key.y), signature.r, signature.s)
}

pub fn verify_crl(crl: @CertificateRevocationList, signer_cert: @X509CertificateData) -> bool {
    // verifies that the crl is valid
    let data = TbsCertificateDataListImpl::as_ref(crl.tbs_cert_list);
    let data_hash: u256 = u32s_typed_to_u256(@compute_sha256_byte_array(@data.into_byte_array()));

    let signature = crl.signature_value;
    let public_key = signer_cert.tbs_certificate_data.subject_pki;
    // make sure that the issuer is the signer
    if crl.tbs_cert_list.issuer != signer_cert.tbs_certificate_data.subject {
        return false;
    }
    verify_p256_signature(data_hash, (public_key.x, public_key.y), signature.r, signature.s)
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
// pub fn verify_certchain_signature(
//     certs: @Span<X509CertificateData>,
//     root_cert: @X509CertificateData,
// ) -> bool {
//     // verify that the cert chain is valid
//     let mut iter = certs.iter();
//     let mut prev_cert = iter.next().unwrap();
//     for cert in iter {
//         // verify that the previous cert signed the current cert
//         if !verify_certificate(prev_cert, cert) {
//             return false;
//         }
//         prev_cert = cert;
//     }
//     // verify that the root cert signed the last cert
//     verify_certificate(prev_cert, root_cert)
// }

// pub fn is_cert_revoked(
//     cert: @X509CertificateData,
//     crl: @CertificateRevocationList,
// ) -> bool {
//     crl.iter_revoked_certificates()
//         .any(|entry| entry.user_certificate == cert.tbs_certificate.serial)
// }