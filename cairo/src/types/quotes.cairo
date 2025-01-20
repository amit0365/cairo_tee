pub mod body;
pub mod header;
pub mod version_4;

use cairo::types::cert::Certificates;
use cairo::utils::byte::{felt252s_to_u16, u8_to_u16_le, u8_to_u32_le, felt252s_to_u8s, felt252s_to_u32, SpanU8TryIntoArrayU8Fixed64};
use cairo::types::quotes::body::EnclaveReportImpl;
use cairo::types::quotes::body::EnclaveReport;

#[derive(Drop, Copy)]
pub struct CertData {
    pub cert_data_type: u16,            // [2 bytes]
                                        // Determines type of data required to verify the QE Report Signature in the Quote Signature Data structure. 
                                        // 1 - (PCK identifier: PPID in plain text, CPUSVN, and PCESVN)
                                        // 2 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, and PCESVN)
                                        // 3 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN, and QEID)
                                        // 4 - (PCK Leaf Certificate in plain text; currently not supported)
                                        // 5 - (Concatenated PCK Cert Chain)
                                        // 6 - (QE Report Certification Data)
                                        // 7 - (PLATFORM_MANIFEST; currently not supported)
    pub cert_data_size: u32,            // [4 bytes]
                                        // Size of Certification Data field.
    pub cert_data: Span<u8>,             // [variable bytes]
                                        // Data required to verify the QE Report Signature depending on the value of the Certification Data Type:
                                        // 1: Byte array that contains concatenation of PPID, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 2: Byte array that contains concatenation of PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 3: Byte array that contains concatenation of PPID encrypted using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 4: PCK Leaf Certificate
                                        // 5: Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert 
                                        // 6: QE Report Certification Data
                                        // 7: PLATFORM_MANIFEST
}

#[generate_trait]
impl CertDataImpl of CertDataFromBytes {
    fn from_bytes(raw_bytes: Span<u8>) -> CertData {
        let cert_data_type = u8_to_u16_le(raw_bytes.slice(0, 2));
        let cert_data_size = u8_to_u32_le(raw_bytes.slice(2, 4));
        let cert_data = raw_bytes.slice(6, cert_data_size);

        CertData {
            cert_data_type,
            cert_data_size,
            cert_data,
        }
    }
}

pub enum CertDataType {
    Unused,
    Type1: Span<u8>,
    Type2: Span<u8>,
    Type3: Span<u8>,
    Type4: Span<u8>,
    CertChain: Certificates,
    QeReportCertData: QeReportCertData,
    Type7: Span<u8>,
}

#[derive(Copy, Drop)]
pub struct QeReportCertDataRaw {
    pub qe_report: Span<u8>,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

#[derive(Copy, Drop)]
pub struct QeReportCertData {
    pub qe_report: EnclaveReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

#[derive(Copy, Drop)]
pub struct QeAuthData {
    pub size: u16,
    pub data: Span<u8>,
}

#[generate_trait]
impl QeAuthDataImpl of QeAuthDataFromBytes {
    fn from_bytes(raw_bytes: Span<u8>) -> QeAuthData {
        let size = u8_to_u16_le(raw_bytes.slice(0, 2));
        let size_u32 = size.try_into().unwrap();
        let data = raw_bytes.slice(2, size_u32);
        QeAuthData {
            size,
            data,
        }
    }
}


#[generate_trait]
impl QeReportCertDataImpl of QeReportCertDataFromBytes {
    fn from_bytes(raw_bytes: Span<u8>) -> QeReportCertData {
        // 384 bytes for qe_report
        let qe_report = EnclaveReportImpl::from_bytes(raw_bytes.slice(0, 384));
        // 64 bytes for qe_report_signature
        let qe_report_signature = raw_bytes.slice(384, 64).try_into().unwrap();
        // qe auth data is variable length, we'll pass remaining bytes to the from_bytes method
        let qe_auth_data = QeAuthDataImpl::from_bytes(raw_bytes.slice(448, raw_bytes.len() - 448));
        // get the length of qe_auth_data
        let qe_auth_data_size = 2 + qe_auth_data.size;
        // finish off with the parsing of qe_cert_data
        let qe_cert_data_start: u32 = (448 + qe_auth_data_size).try_into().unwrap();
        let qe_cert_data = CertDataImpl::from_bytes(raw_bytes.slice(qe_cert_data_start, raw_bytes.len() - qe_cert_data_start));

        QeReportCertData {
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        }
    }
}