use crate::constants::SGX_TEE_TYPE;
use starknet::secp256_trait::Signature;
use crate::types::quotes::body::QuoteBody;
use crate::types::quotes::version_4::QuoteV4;
use crate::types::quotes::{CertDataType, QeReportCertData, QeReportCertDataImpl};
use crate::types::{TcbStatus};
use crate::types::{
    cert::PublicKey,
    tcbinfo::{TcbInfo, TcbInfoV3},
    collaterals::IntelCollateral, VerifiedOutput,
};
use crate::utils::byte::{felt252s_to_u8s};
use crate::types::collaterals::IntelCollateralData;
use crate::types::quotes::{QeReportCertDataRaw, CertDataImpl, QeAuthDataImpl};
use crate::verify::quotes::common_verify_and_fetch_tcb;
use crate::utils::byte::{u8s_typed_to_u256, SpanU8TryIntoArrayU8Fixed32, u8s_to_felt252s, felt252s_to_u32, felt252s_to_u16};
// use crate::utils::cert::get_sgx_tdx_fmspc_tcbstatus_v3;
// use crate::utils::tdx_module::{
//     converge_tcb_status_with_tdx_module_tcb, get_tdx_module_identity_and_tcb,
// };

// use super::{check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv4(
    raw_quote: Span<u8>,
    is_sgx: bool,
    collaterals: @IntelCollateralData,
    current_time: u64,
) -> VerifiedOutput {

    let mut offset = 0;
    let quote_header = raw_quote.slice(offset, 48);
    offset += 48;
    let quote_body = if is_sgx {
        offset += 384;
        raw_quote.slice(offset, 384)
    } else {
        offset += 584;
        raw_quote.slice(offset, 584)
    };
    let _quote_signature_len = raw_quote.slice(offset, 4);
    offset += 4;
    let quote_signature_r = raw_quote.slice(offset, 32);
    offset += 32;
    let quote_signature_s = raw_quote.slice(offset, 32);
    offset += 32;
    let quote_pubkey_x = raw_quote.slice(offset, 32);
    offset += 32;
    let quote_pubkey_y = raw_quote.slice(offset, 32);
    offset += 32;

    // assert!(check_quote_header(@quote.header, 4), "invalid quote header");

    // we'll now proceed to verify the qe
    let qe_cert_data_v4_type_u16 = felt252s_to_u16(u8s_to_felt252s(raw_quote.slice(offset, 2)).span());
    offset += 2;
    let qe_cert_data_v4_len = felt252s_to_u32(u8s_to_felt252s(raw_quote.slice(offset, 4)).span());
    offset += 4;
    let qe_cert_data_v4 = u8s_to_felt252s(raw_quote.slice(offset, qe_cert_data_v4_len)).span();

    // right now we just handle type 6, which contains the QEReport, QEReportSignature, QEAuthData and another CertData
    let qe_report_cert_data = if qe_cert_data_v4_type_u16 == 6 {
        QeReportCertDataImpl::from_bytes(qe_cert_data_v4)
    } else {
        panic!("Unsupported CertDataType in QuoteSignatureDataV4")
    };

    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        quote_header,
        quote_body,
        (quote_signature_r, quote_signature_s),
        (quote_pubkey_x, quote_pubkey_y),
        @qe_report_cert_data.qe_report,
        qe_report_cert_data.qe_report_signature,
        qe_report_cert_data.qe_auth_data.data,
        @qe_report_cert_data.qe_cert_data,
        collaterals,
        current_time,
    );

    let tcb_info_v3 = if let TcbInfo::V3(tcb) = tcb_info {
        tcb
    } else {
        panic!("TcbInfo must be V3!")
    };

    let (quote_tdx_body, tee_tcb_svn) = if !is_sgx {
        (Option::Some(quote_body), quote_body.slice(0, 16))
    } else {
        // SGX does not produce tee_tcb_svns
        (Option::None, [0; 16].span())
    };

//     let tee_type = quote.header.tee_type;
//     let (sgx_tcb_status, tdx_tcb_status, advisory_ids) =
//         get_sgx_tdx_fmspc_tcbstatus_v3(tee_type, &sgx_extensions, &tee_tcb_svn, &tcb_info_v3);
    
//     assert!(
//         sgx_tcb_status != TcbStatus::TcbRevoked || tdx_tcb_status != TcbStatus::TcbRevoked,
//         "FMSPC TCB Revoked"
//     );
    
//     let mut tcb_status: TcbStatus;
//     if quote.header.tee_type == SGX_TEE_TYPE {
//         tcb_status = sgx_tcb_status;
//     } else {
//         tcb_status = tdx_tcb_status;

//         // Fetch TDXModule TCB and TDXModule Identity
//         let (tdx_module_tcb_status, tdx_module_mrsigner, tdx_module_attributes) =
//             get_tdx_module_identity_and_tcb(&tee_tcb_svn, &tcb_info_v3);

//         assert!(
//             tdx_module_tcb_status != TcbStatus::TcbRevoked,
//             "TDX Module TCB Revoked"
//         );

//         // check TDX module
//         let (tdx_report_mrsigner, tdx_report_attributes) = if let Some(tdx_body) = quote_tdx_body {
//             (tdx_body.mrsignerseam, tdx_body.seam_attributes)
//         } else {
//             unreachable!();
//         };

//         let mr_signer_matched = tdx_module_mrsigner == tdx_report_mrsigner;
//         let attributes_matched = tdx_module_attributes == tdx_report_attributes;
//         assert!(
//             mr_signer_matched && attributes_matched,
//             "TDX module values mismatch"
//         );

//         tcb_status = converge_tcb_status_with_tdx_module_tcb(tcb_status, tdx_module_tcb_status)
//     }

//     tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

//     VerifiedOutput {
//         quote_version: quote.header.version,
//         tee_type: quote.header.tee_type,
//         tcb_status,
//         fmspc: sgx_extensions.fmspc,
//         quote_body: quote.quote_body,
//         advisory_ids: advisory_ids
//     }
}
