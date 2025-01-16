use super::tcbinfo::ArrayU8ExtTrait;
use crate::utils::byte::ByteArrayExtTrait;
use starknet::secp256_trait::Signature;
use crate::types::cert::PublicKey;

mod version_4;
use crate::types::collaterals::TcbInfoVersion;
use crate::types::cert::X509CertificateData;
use crate::constants::{ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID};
use cairo::utils::compare::{PartialEqU8Array16, PartialEqU8Array20};
use crate::types::cert::IntelSgxCrlsImpl;
use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::cert::{IntelSgxCrls, SgxExtensions};
use crate::types::collaterals::IntelCollateralData;
use crate::types::quotes::{
    body::{EnclaveReport, QuoteBody},
    header::QuoteHeader,
};
use crate::utils::byte::{SpanU8TryIntoArrayU8Fixed32, u32s_typed_to_u256, u8s_typed_to_u256};
use core::sha256::compute_sha256_byte_array;
use crate::types::quotes::{CertData, CertDataType};
use crate::types::tcbinfo::TcbInfo;
use crate::types::TcbStatus;
use crate::verify::enclave_identity::get_qe_tcbstatus;
use crate::utils::pem_decode::PemParserImpl;
use crate::utils::x509_decode::X509DecodeImpl;
use crate::verify::cert::{
    //extract_sgx_extension, get_x509_issuer_cn, get_x509_subject_cn, parse_certchain, parse_pem,
    verify_certchain_signature, 
    verify_certificate, verify_crl,
};
use crate::verify::crypto::verify_p256_signature;
use crate::verify::enclave_identity::validate_enclave_identityv2;
use crate::verify::tcbinfo::{validate_tcbinfov2, validate_tcbinfov3};
use crate::utils::x509_decode::X509CertObj;
fn check_quote_header(quote_header: @QuoteHeader, quote_version: u16) -> bool {
    let quote_version_is_valid = *quote_header.version == quote_version;
    let att_key_type_is_supported = *quote_header.att_key_type == ECDSA_256_WITH_P256_CURVE;
    let qe_vendor_id_is_valid = *quote_header.qe_vendor_id == INTEL_QE_VENDOR_ID;

    quote_version_is_valid && att_key_type_is_supported && qe_vendor_id_is_valid
}

// verification steps that are required for both SGX and TDX quotes
// Checks:
// - valid qeidentity
// - valid tcbinfo
// - valid pck certificate chain
// - qe report content
// - ecdsa verification on qe report data and quote body data
// Returns:
// - QEIdentity TCB Status
// - SGX Extension
// - TCBInfo (v2 or v3)
fn common_verify_and_fetch_tcb(
    quote_header: Span<u8>,//@QuoteHeader,
    quote_body: Span<u8>,//@QuoteBody,
    ecdsa_attestation_signature: (Span<u8>, Span<u8>),
    ecdsa_attestation_pubkey: (Span<u8>, Span<u8>),
    qe_report: @EnclaveReport,
    qe_report_signature: [u8; 64],
    qe_auth_data: Span<u8>,
    qe_cert_data: @CertData,
    collaterals: @IntelCollateralData,
    current_time: u64,
) -> (TcbStatus, SgxExtensions, TcbInfo) {
    let signing_cert = collaterals.sgx_tcb_signing;
    let intel_sgx_root_cert = collaterals.sgx_intel_root_ca;

    // verify that signing_verifying_key is not revoked and signed by the root cert
    let intel_crls = IntelSgxCrlsImpl::from_collaterals(collaterals);

    // ZL: If collaterals are checked by the caller, then these can be removed
    // check that CRLs are valid
    match intel_crls.sgx_root_ca_crl {
        Option::Some(crl) => {
            assert!(verify_crl(crl, intel_sgx_root_cert));
        },
        Option::None => {
            panic!("No SGX Root CA CRL found");
        }
    }

    //let signing_cert_revoked = intel_crls.is_cert_revoked(&signing_cert);
    // assert!(!signing_cert_revoked, "TCB Signing Cert revoked"); todo check this
    assert!(
        verify_certificate(signing_cert, intel_sgx_root_cert),
        "TCB Signing Cert is not signed by Intel SGX Root CA"
    );

    // validate QEIdentity
    let qeidentityv2 = collaterals.qeidentity;
    assert!(validate_enclave_identityv2(
        qeidentityv2,
        signing_cert,
        current_time
    ));

    // verify QEReport then get TCB Status
    assert!(
        verify_qe_report_data(
            qe_report.report_data.span(),
            ecdsa_attestation_pubkey,
            qe_auth_data
        ),
        "QE Report Data is incorrect"
    );
    assert!(
        validate_qe_report(qe_report, qeidentityv2),
        "QE Report values do not match with the provided QEIdentity"
    );
    let qe_tcb_status = get_qe_tcbstatus(qe_report, qeidentityv2);
    assert!(
        qe_tcb_status != TcbStatus::TcbRevoked,
        "QEIdentity TCB Revoked"
    );

    // get the certchain embedded in the ecda quote signature data
    // this can be one of 5 types
    // we only handle type 5 for now...
    // TODO: Add support for all other types
    assert_eq!(*qe_cert_data.cert_data_type, 5, "QE Cert Type must be 5");
    let certchain_pems = PemParserImpl::parse_pem(*qe_cert_data.cert_data);
    let mut certchain = array![];
    for i in 0..certchain_pems.len() {
        certchain.append(X509DecodeImpl::parse_x509_der(*certchain_pems[i].contents));
    };
    // checks that the certificates used in the certchain are not revoked
    // for i in 0..certchain.len() {
    //     assert!(!intel_crls.is_cert_revoked(certchain[i]));
    // };

    // get the pck certificate, and check whether issuer common name is valid
    let pck_cert = @certchain[0];
    let pck_cert_issuer = @certchain[1];
    // assert!(
    //     check_pck_issuer_and_crl(pck_cert, pck_cert_issuer, @intel_crls),
    //     "Invalid PCK Issuer or CRL"
    // );

    // verify that the cert chain signatures are valid
    assert!(
        verify_certchain_signature(@certchain.span(), intel_sgx_root_cert),
        "Invalid PCK Chain"
    );

    // verify the signature for qe report data
    // let qe_report_bytes = qe_report.to_bytes();

    // let qe_report_public_key = pck_cert.public_key().subject_public_key.as_ref();
    // assert!(
    //     verify_p256_signature_bytes(@qe_report_bytes, qe_report_signature, qe_report_public_key),
    //     "Invalid qe signature"
    // );

    // get the SGX extension
    //let sgx_extensions = extract_sgx_extension(@pck_cert);

    // verify the signature for attestation body
    let mut data = array![];
    assert!(quote_header.len() == 48, "invalid quote header");
    data.append_span(quote_header);
    data.append_span(quote_body);
    let data_hash = u32s_typed_to_u256(@compute_sha256_byte_array(@data.span().into_byte_array()));

    let (ecdsa_attestation_signature_r_u8s, ecdsa_attestation_signature_s_u8s) = ecdsa_attestation_signature;
    let ecdsa_attestation_signature_r = u8s_typed_to_u256(@ecdsa_attestation_signature_r_u8s.try_into().unwrap());
    let ecdsa_attestation_signature_s = u8s_typed_to_u256(@ecdsa_attestation_signature_s_u8s.try_into().unwrap());

    let (ecdsa_attestation_pubkey_x, ecdsa_attestation_pubkey_y) = ecdsa_attestation_pubkey;
    let ecdsa_attestation_pubkey_x = u8s_typed_to_u256(@ecdsa_attestation_pubkey_x.try_into().unwrap());
    let ecdsa_attestation_pubkey_y = u8s_typed_to_u256(@ecdsa_attestation_pubkey_y.try_into().unwrap());

    // todo dont need this if already in bytes
    // match quote_body {
    //     QuoteBody::SGXQuoteBody(body) => data.append_span(@body.to_bytes()),
    //     QuoteBody::TD10QuoteBody(body) => data.append_span(@body.to_bytes()),
    // };

    assert!(
        verify_p256_signature(data_hash, (@ecdsa_attestation_pubkey_x, @ecdsa_attestation_pubkey_y), @ecdsa_attestation_signature_r, @ecdsa_attestation_signature_s),
        "Invalid attestation signature"
    );

    // validate tcbinfo v2 or v3, depending on the quote version
    let tcb_info = match collaterals.tcbinfo {
        TcbInfoVersion::V3(tcb_info_v3) => {
            assert!(
                validate_tcbinfov3(tcb_info_v3, signing_cert, current_time),
                "Invalid TCBInfoV3"
            );
            TcbInfoVersion::V3(tcb_info_v3.deref())
        },
        TcbInfoVersion::V2(tcb_info_v2) => {
            assert!(
                validate_tcbinfov2(tcb_info_v2, signing_cert, current_time),
                "Invalid TCBInfoV2"
            );
            TcbInfoVersion::V2(tcb_info_v2.deref())
        }
    };

    (qe_tcb_status, sgx_extensions, tcb_info)
}

// fn check_pck_issuer_and_crl(
//     pck_cert: @X509CertObj,
//     pck_issuer_cert: @X509CertObj,
//     intel_crls: @IntelSgxCrls,
// ) -> bool {
//     // we'll check what kind of cert is it, and validate the appropriate CRL
//     let pck_cert_subject_cn = get_x509_issuer_cn(pck_cert);
//     let pck_cert_issuer_cn = get_x509_subject_cn(pck_issuer_cert);

//     assert!(
//         pck_cert_issuer_cn == pck_cert_subject_cn,
//         "PCK Issuer CN does not match with PCK Intermediate Subject CN"
//     );

//     match pck_cert_issuer_cn.as_str() {
//         "Intel SGX PCK Platform CA" => verify_crl(
//             intel_crls.sgx_pck_platform_crl.as_ref().unwrap(),
//             pck_issuer_cert,
//         ),
//         "Intel SGX PCK Processor CA" => verify_crl(
//             &intel_crls.sgx_pck_processor_crl.as_ref().unwrap(),
//             pck_issuer_cert,
//         ),
//         _ => {
//             panic!("Unknown PCK Cert Subject CN: {}", pck_cert_subject_cn);
//         }
//     }
// }

fn validate_qe_report(enclave_report: @EnclaveReport, qeidentityv2: @EnclaveIdentityV2) -> bool {
    // make sure that the enclave_identityv2 is a qeidentityv2
    // check that id is "QE", "TD_QE" or "QVE" and version is 2
    if !((qeidentityv2.enclave_identity.id == "QE"
        || qeidentityv2.enclave_identity.id == "TD_QE"
        || qeidentityv2.enclave_identity.id == "QVE")
        && qeidentityv2.enclave_identity.version == 2)
    {
        return false;
    }

    let mrsigner_ok = enclave_report.mrsigner
        == qeidentityv2.enclave_identity.mrsigner.as_slice();
    let isvprodid_ok = enclave_report.isv_prod_id == qeidentityv2.enclave_identity.isvprodid;

    let attributes = qeidentityv2.enclave_identity.attributes;
    let attributes_mask = qeidentityv2.enclave_identity.attributes_mask;
    // let masked_attributes = attributes
    //     .iter()
    //     .zip(attributes_mask.iter())
    //     .map(|(a, m)| a & m)
    //     .collect::<Vec<u8>>();
    // let masked_enclave_attributes = enclave_report
    //     .attributes
    //     .iter()
    //     .zip(attributes_mask.iter())
    //     .map(|(a, m)| a & m)
    //     .collect::<Vec<u8>>();
    let enclave_attributes_ok = masked_enclave_attributes == masked_attributes;

    let miscselect = qeidentityv2.enclave_identity.miscselect;
    let miscselect_mask = qeidentityv2.enclave_identity.miscselect_mask;
    // let masked_miscselect = miscselect
    //     .iter()
    //     .zip(miscselect_mask.iter())
    //     .map(|(a, m)| a & m)
    //     .collect::<Vec<u8>>();
    // let masked_enclave_miscselect = enclave_report
    //     .misc_select
    //     .iter()
    //     .zip(miscselect_mask.iter())
    //     .map(|(a, m)| a & m)
    //     .collect::<Vec<u8>>();
    //let enclave_miscselect_ok = masked_enclave_miscselect == masked_miscselect;

    mrsigner_ok && isvprodid_ok && enclave_attributes_ok && enclave_miscselect_ok
}

fn verify_qe_report_data(
    report_data: Span<u8>,
    ecdsa_attestation_key: (Span<u8>, Span<u8>),
    qe_auth_data: Span<u8>,
) -> bool {
    let mut verification_data = array![];
    let (ecdsa_attestation_key_x, ecdsa_attestation_key_y) = ecdsa_attestation_key;
    verification_data.append_span(ecdsa_attestation_key_x);
    verification_data.append_span(ecdsa_attestation_key_y);
    verification_data.append_span(qe_auth_data);
    //let mut recomputed_data = array![];
    let hash = u32s_typed_to_u256(@compute_sha256_byte_array(@verification_data.span().into_byte_array()));
    let report_data_u256 = u8s_typed_to_u256(@report_data.try_into().unwrap());
    hash == report_data_u256
}

// // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
// fn converge_tcb_status_with_qe_tcb(tcb_status: TcbStatus, qe_tcb_status: TcbStatus) -> TcbStatus {
//     let converged_tcb_status: TcbStatus;
//     match qe_tcb_status {
//         TcbStatus::TcbOutOfDate => {
//             if tcb_status == TcbStatus::OK || tcb_status == TcbStatus::TcbSwHardeningNeeded {
//                 converged_tcb_status = TcbStatus::TcbOutOfDate;
//             } else if tcb_status == TcbStatus::TcbConfigurationNeeded
//                 || tcb_status == TcbStatus::TcbConfigurationAndSwHardeningNeeded
//             {
//                 converged_tcb_status = TcbStatus::TcbOutOfDateConfigurationNeeded;
//             } else {
//                 converged_tcb_status = tcb_status;
//             }
//         },
//         _ => {
//             converged_tcb_status = tcb_status;
//         }
//     }
//     converged_tcb_status
// }
