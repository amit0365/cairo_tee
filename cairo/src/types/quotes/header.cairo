use crate::types::quotes::body::QuoteBody;
use alexandria_bytes::BytesTrait;
use core::traits::TryInto;
use cairo::utils::{
    byte::{felt252s_to_u8s, SpanU8TryIntoArrayU8Fixed2, SpanU8TryIntoArrayU8Fixed4,
    SpanU8TryIntoArrayU8Fixed96, SpanU8TryIntoArrayU8Fixed20, SpanU8TryIntoArrayU8Fixed28, 
    SpanU8TryIntoArrayU8Fixed16, SpanU8TryIntoArrayU8Fixed32, SpanU8TryIntoArrayU8Fixed64, 
    SpanU8TryIntoArrayU8Fixed60, SpanU8TryIntoArrayU8Fixed48, felt252s_to_u32, felt252s_to_u16, felt252s_to_u64},
    compare::{PartialEqU8Array16, PartialEqU8Array20},
};


trait QuoteHeaderFromBytes {
    fn from_bytes(raw_bytes: Span<felt252>) -> QuoteHeader;
}

#[derive(Drop, Copy, PartialEq)]
pub struct QuoteHeader {
    pub version: u16,                   // [2 bytes]
                                        // Version of the quote data structure - 4, 5
    pub att_key_type: u16,              // [2 bytes]
                                        // Type of the Attestation Key used by the Quoting Enclave -
                                        // 2 (ECDSA-256-with-P-256 curve) 
                                        // 3 (ECDSA-384-with-P-384 curve)
    pub tee_type: u32,                  // [4 bytes]
                                        // TEE for this Attestation
                                        // 0x00000000: SGX
                                        // 0x00000081: TDX
    pub qe_svn: [u8; 2],                // [2 bytes]
                                        // Security Version of the Quoting Enclave - 1 (only applicable for SGX Quotes)
    pub pce_svn: [u8; 2],               // [2 bytes]
                                        // Security Version of the PCE - 0 (only applicable for SGX Quotes)
    pub qe_vendor_id: [u8; 16],         // [16 bytes]
                                        // Unique identifier of the QE Vendor. 
                                        // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
                                        // Note: Each vendor that decides to provide a customized Quote data structure should have
                                        // unique ID.
    pub user_data: [u8; 20],            // [20 bytes]
                                        // Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries, 
                                        // the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
}

impl QuoteHeaderImpl of QuoteHeaderFromBytes {
    fn from_bytes(raw_bytes: Span<felt252>) -> QuoteHeader {
        let version: u16 = felt252s_to_u16(raw_bytes.slice(0, 2));
        let att_key_type: u16 = felt252s_to_u16(raw_bytes.slice(2, 2));
        let tee_type: u32 = felt252s_to_u32(raw_bytes.slice(4, 4));
        let qe_svn: [u8; 2] = felt252s_to_u8s(raw_bytes.slice(8, 2)).try_into().unwrap();
        let pce_svn: [u8; 2] = felt252s_to_u8s(raw_bytes.slice(10, 2)).try_into().unwrap();
        let qe_vendor_id: [u8; 16] = felt252s_to_u8s(raw_bytes.slice(12, 16)).try_into().unwrap();
        let user_data: [u8; 20] = felt252s_to_u8s(raw_bytes.slice(28, 20)).try_into().unwrap();
        

        QuoteHeader {
            version,
            att_key_type,
            tee_type,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        }
    }
}

// #[generate_trait]
// impl QuoteHeaderToBytesImpl of QuoteHeaderToBytes {
//     fn to_bytes(self: @QuoteHeader) -> Span<u8> {
//         let mut data = array![];
//         data.append_span(self.version.to_bytes());
//         data.append_span(self.att_key_type.to_bytes());
//         data.append_span(self.tee_type.to_bytes());
//         data.append_span(self.qe_svn.span());
//         data.append_span(self.pce_svn.span());
//         data.append_span(self.qe_vendor_id.span());
//         data.append_span(self.user_data.span());
//         data.span()
//     }
// }
