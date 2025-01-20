use alexandria_bytes::BytesTrait;
use core::traits::TryInto;
use cairo::utils::byte::{felt252s_to_u8s, u8_to_u16_le, SpanU8TryIntoArrayU8Fixed2, SpanU8TryIntoArrayU8Fixed4,
    SpanU8TryIntoArrayU8Fixed96, SpanU8TryIntoArrayU8Fixed20, SpanU8TryIntoArrayU8Fixed28, 
    SpanU8TryIntoArrayU8Fixed16, SpanU8TryIntoArrayU8Fixed32, SpanU8TryIntoArrayU8Fixed64, 
    SpanU8TryIntoArrayU8Fixed60, SpanU8TryIntoArrayU8Fixed48, felt252s_to_u32, felt252s_to_u16, felt252s_to_u64};
use cairo::utils::compare::{PartialEqU8Array16, PartialEqU8Array20, PartialEqU8Array28, PartialEqU8Array32, PartialEqU8Array60, PartialEqU8Array64, PartialEqU8Array96};

#[derive(Drop, Copy)]
pub enum QuoteBody {
    SGXQuoteBody: EnclaveReport,
    TD10QuoteBody: TD10ReportBody
}

trait TD10ReportBodyFromBytes {
    fn from_bytes(raw_bytes: Span<felt252>) -> TD10ReportBody;
}

#[derive(Drop, Copy)]
pub struct TD10ReportBody {
    pub tee_tcb_svn: [u8; 16],          // [16 bytes]
                                        // Describes the TCB of TDX. (Refer to above)
    pub mrseam: [u8; 48],               // [48 bytes]
                                        // Measurement of the TDX Module.
    pub mrsignerseam: [u8; 48],         // [48 bytes]
                                        // Zero for Intel TDX Module
    pub seam_attributes: u64,           // [8 bytes]
                                        // Must be zero for TDX 1.0
    pub td_attributes: u64,             // [8 bytes]
                                        // TD Attributes (Refer to above)
    pub xfam: u64,                      // [8 bytes]
                                        // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format as XCR0 or IA32_XSS MSR.
    pub mrtd: [u8; 48],                 // [48 bytes]
                                        // (SHA384) Measurement of the initial contents of the TD.
    pub mrconfigid: [u8; 48],           // [48 bytes]
                                        // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS configuration.
    pub mrowner: [u8; 48],              // [48 bytes]
                                        // Software-defined ID for the TD’s owner
    pub mrownerconfig: [u8; 48],        // [48 bytes]
                                        // Software-defined ID for owner-defined configuration of the TD, 
                                        // e.g., specific to the workload rather than the runtime or OS.
    pub rtmr0: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr1: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr2: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub rtmr3: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    pub report_data: [u8; 64],          // [64 bytes]
                                        // Additional report data.
                                        // The TD is free to provide 64 bytes of custom data to the REPORT.
                                        // This can be used to provide specific data from the TD or it can be used to hold a hash of a larger block of data which is provided with the quote.
                                        // Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity is protected with a key rooted in an Intel CA.
}


impl TD10ReportBodyImpl of TD10ReportBodyFromBytes {
    fn from_bytes(raw_bytes: Span<felt252>) -> TD10ReportBody {
        assert_eq!(raw_bytes.len(), 584);

        let tee_tcb_svn: [u8; 16] = felt252s_to_u8s(raw_bytes.slice(0, 16)).try_into().unwrap();
        let mrseam: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(16, 48)).try_into().unwrap();
        let mrsignerseam: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(64, 48)).try_into().unwrap();
        let seam_attributes: u64 = felt252s_to_u64(raw_bytes.slice(112, 8));
        let td_attributes: u64 = felt252s_to_u64(raw_bytes.slice(120, 8));
        let xfam: u64 = felt252s_to_u64(raw_bytes.slice(128, 8));
        let mrtd: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(136, 48)).try_into().unwrap();
        let mrconfigid: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(184, 48)).try_into().unwrap();
        let mrowner: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(232, 48)).try_into().unwrap();
        let mrownerconfig: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(280, 48)).try_into().unwrap();
        let rtmr0: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(328, 48)).try_into().unwrap();
        let rtmr1: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(376, 48)).try_into().unwrap();
        let rtmr2: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(424, 48)).try_into().unwrap();
        let rtmr3: [u8; 48] = felt252s_to_u8s(raw_bytes.slice(472, 48)).try_into().unwrap();
        let report_data: [u8; 64] = felt252s_to_u8s(raw_bytes.slice(520, 64)).try_into().unwrap();

        TD10ReportBody {
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seam_attributes,
            td_attributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            report_data,
        }
    }
}


#[derive(Drop, Copy, PartialEq)]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],      // [16 bytes]
                                // Security Version of the CPU (raw value)
    pub misc_select: [u8; 4],   // [4 bytes]
                                // SSA Frame extended feature set. 
                                // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub reserved_1: [u8; 28],   // [28 bytes]
                                // Reserved for future use - 0
    pub attributes: [u8; 16],   // [16 bytes]
                                // Set of flags describing attributes of the enclave.
                                // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                // which determine allowed ATTRIBUTES.
                                // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub mrenclave: [u8; 32],    // [32 bytes] 
                                // Measurement of the enclave. 
                                // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub reserved_2: [u8; 32],   // [32 bytes] 
                                // Reserved for future use - 0
    pub mrsigner: [u8; 32],     // [32 bytes]
                                // Measurement of the enclave signer. 
                                // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    pub reserved_3: [u8; 96],   // [96 bytes]
                                // Reserved for future use - 0
    pub isv_prod_id: u16,       // [2 bytes]
                                // Product ID of the enclave. 
                                // The ISV should configure a unique ISVProdID for each product which may
                                // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                // may want to supply different data to identical enclaves signed for different products.
    pub isv_svn: u16,           // [2 bytes]
                                // Security Version of the enclave
    pub reserved_4: [u8; 60],   // [60 bytes]
                                // Reserved for future use - 0
    pub report_data: [u8; 64],  // [64 bytes]
                                // Additional report data.
                                // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                // This can be used to provide specific data from the enclave or it can be used to hold 
                                // a hash of a larger block of data which is provided with the quote. 
                                // The verification of the quote signature confirms the integrity of the
                                // report data (and the rest of the REPORT body).
    pub raw_bytes: Span<u8>,
}

#[generate_trait]
impl EnclaveReportImpl of EnclaveReportFromBytes {
    fn from_bytes(raw_bytes: Span<u8>) -> EnclaveReport{
        assert_eq!(raw_bytes.len(), 384);
        let cpu_svn: [u8; 16] = raw_bytes.slice(0, 16).try_into().unwrap();
        let misc_select: [u8; 4] = raw_bytes.slice(16, 4).try_into().unwrap();
        let reserved_1: [u8; 28] = raw_bytes.slice(20, 28).try_into().unwrap();
        let attributes: [u8; 16] = raw_bytes.slice(48, 16).try_into().unwrap();
        let mrenclave: [u8; 32] = raw_bytes.slice(64, 32).try_into().unwrap();
        let reserved_2: [u8; 32] = raw_bytes.slice(96, 32).try_into().unwrap();
        let mrsigner: [u8; 32] = raw_bytes.slice(128, 32).try_into().unwrap();
        let reserved_3: [u8; 96] = raw_bytes.slice(160, 96).try_into().unwrap();
        let isv_prod_id: u16 = u8_to_u16_le(raw_bytes.slice(256, 2));
        let isv_svn: u16 = u8_to_u16_le(raw_bytes.slice(258, 2));
        let reserved_4: [u8; 60] = raw_bytes.slice(260, 60).try_into().unwrap();
        let report_data: [u8; 64] = raw_bytes.slice(320, 64).try_into().unwrap();

        EnclaveReport{
            cpu_svn,
            misc_select,
            reserved_1,
            attributes,
            mrenclave,
            reserved_2,
            mrsigner,
            reserved_3,
            isv_prod_id,
            isv_svn,
            reserved_4,
            report_data,
            raw_bytes,
        }
    }
}


