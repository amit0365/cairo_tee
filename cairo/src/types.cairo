pub mod quotes;
pub mod cert;
pub mod tcbinfo;
pub mod collaterals;
pub mod enclave_identity;
use crate::types::tcbinfo::TcbStatus;
use crate::types::quotes::body::QuoteBody;
use crate::constants::{ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE};
// use alloy_sol_types::SolValue;


// // serialization:
// // [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes]
// // 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
// // total: 13 + var bytes
#[derive(Drop)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: Option<TcbStatus>, //remove option
    pub fmspc: [u8; 6],
    pub quote_body: Span<u8>,
    pub advisory_ids: Option<Span<u8>>,
}

//not used todo check
// impl VerifiedOutput {
//     pub fn to_bytes(&self) -> Vec<u8> {
//         let mut output_vec = Vec::new();

//         output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
//         output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
//         output_vec.push(match self.tcb_status {
//             TcbStatus::OK => 0,
//             TcbStatus::TcbSwHardeningNeeded => 1,
//             TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
//             TcbStatus::TcbConfigurationNeeded => 3,
//             TcbStatus::TcbOutOfDate => 4,
//             TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
//             TcbStatus::TcbRevoked => 6,
//             TcbStatus::TcbUnrecognized => 7,
//         });
//         output_vec.extend_from_slice(&self.fmspc);

//         match self.quote_body {
//             QuoteBody::SGXQuoteBody(body) => {
//                 output_vec.extend_from_slice(&body.to_bytes());
//             }
//             QuoteBody::TD10QuoteBody(body) => {
//                 output_vec.extend_from_slice(&body.to_bytes());
//             }
//         }

//         if let Some(advisory_ids) = self.advisory_ids.as_ref() {
//             let encoded = advisory_ids.abi_encode();
//             output_vec.extend_from_slice(encoded.as_slice());
//         }

//         output_vec
//     }

//     pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
//         let mut quote_version = [0; 2];
//         quote_version.copy_from_slice(&slice[0..2]);
//         let mut tee_type = [0; 4];
//         tee_type.copy_from_slice(&slice[2..6]);
//         let tcb_status = match slice[6] {
//             0 => TcbStatus::OK,
//             1 => TcbStatus::TcbSwHardeningNeeded,
//             2 => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
//             3 => TcbStatus::TcbConfigurationNeeded,
//             4 => TcbStatus::TcbOutOfDate,
//             5 => TcbStatus::TcbOutOfDateConfigurationNeeded,
//             6 => TcbStatus::TcbRevoked,
//             7 => TcbStatus::TcbUnrecognized,
//             _ => panic!("Invalid TCB Status"),
//         };
//         let mut fmspc = [0; 6];
//         fmspc.copy_from_slice(&slice[7..13]);

//         let mut offset = 13usize;
//         let quote_body = match u32::from_be_bytes(tee_type) {
//             SGX_TEE_TYPE => {
//                 let raw_quote_body = &slice[offset..offset + ENCLAVE_REPORT_LEN];
//                 offset += ENCLAVE_REPORT_LEN;
//                 QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(raw_quote_body))
//             }
//             TDX_TEE_TYPE => {
//                 let raw_quote_body = &slice[offset..offset + TD10_REPORT_LEN];
//                 offset += TD10_REPORT_LEN;
//                 QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(raw_quote_body))
//             }
//             _ => panic!("unknown TEE type"),
//         };

//         let mut advisory_ids = None;
//         if offset < slice.len() {
//             let advisory_ids_slice = &slice[offset..];
//             advisory_ids = Some(<Vec<String>>::abi_decode(advisory_ids_slice, true).unwrap());
//         }

//         VerifiedOutput {
//             quote_version: u16::from_be_bytes(quote_version),
//             tee_type: u32::from_be_bytes(tee_type),
//             tcb_status,
//             fmspc,
//             quote_body,
//             advisory_ids,
//         }
//     }
// }
