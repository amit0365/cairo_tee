// use serde::{Serialize, Deserialize};
// use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

// use crate::utils::cert::{get_crl_uri, is_cert_revoked, parse_x509_der_multi, pem_to_der};

// use super::collaterals::IntelCollateral;

// #[derive(Default, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct SgxExtensionTcbLevel {
//     pub sgxtcbcomp01svn: u8,
//     pub sgxtcbcomp02svn: u8,
//     pub sgxtcbcomp03svn: u8,
//     pub sgxtcbcomp04svn: u8,
//     pub sgxtcbcomp05svn: u8,
//     pub sgxtcbcomp06svn: u8,
//     pub sgxtcbcomp07svn: u8,
//     pub sgxtcbcomp08svn: u8,
//     pub sgxtcbcomp09svn: u8,
//     pub sgxtcbcomp10svn: u8,
//     pub sgxtcbcomp11svn: u8,
//     pub sgxtcbcomp12svn: u8,
//     pub sgxtcbcomp13svn: u8,
//     pub sgxtcbcomp14svn: u8,
//     pub sgxtcbcomp15svn: u8,
//     pub sgxtcbcomp16svn: u8,
//     pub pcesvn: u16,
//     pub cpusvn: [u8; 16]
// }


// #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
// pub struct SgxExtensions {
//     pub ppid: [u8; 16],
//     pub tcb: SgxExtensionTcbLevel,
//     pub pceid: [u8; 2],
//     pub fmspc: [u8; 6],
//     pub sgx_type: u32,
//     pub platform_instance_id: Option<[u8; 16]>,
//     pub configuration: Option<PckPlatformConfiguration>,
// }

// #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
// pub struct PckPlatformConfiguration {
//     pub dynamic_platform: Option<bool>,
//     pub cached_keys: Option<bool>,
//     pub smt_enabled: Option<bool>,
// }

// #[derive(Debug)]
// pub struct IntelSgxCrls<'a> {
//     pub sgx_root_ca_crl: Option<CertificateRevocationList<'a>>,
//     pub sgx_pck_processor_crl: Option<CertificateRevocationList<'a>>,
//     pub sgx_pck_platform_crl: Option<CertificateRevocationList<'a>>,
// }

// impl<'a> IntelSgxCrls<'a> {
//     pub fn new(sgx_root_ca_crl: Option<CertificateRevocationList<'a>>, sgx_pck_processor_crl: Option<CertificateRevocationList<'a>>, sgx_pck_platform_crl: Option<CertificateRevocationList<'a>>) -> Self {
//         Self {
//             sgx_root_ca_crl,
//             sgx_pck_processor_crl,
//             sgx_pck_platform_crl,
//         }
//     }

//     pub fn from_collaterals(collaterals: &'a IntelCollateral) -> Self {
//         let sgx_root_ca_crl = collaterals.get_sgx_intel_root_ca_crl();
//         let sgx_pck_processor_crl = collaterals.get_sgx_pck_processor_crl();
//         let sgx_pck_platform_crl = collaterals.get_sgx_pck_platform_crl();

//         Self::new(sgx_root_ca_crl, sgx_pck_processor_crl, sgx_pck_platform_crl)
//     }

//     pub fn is_cert_revoked(&self, cert: &X509Certificate) -> bool {
//         let crl = match get_crl_uri(cert) {
//             Some(crl_uri) => {
//                 if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform")
//                     || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform") {
//                     self.sgx_pck_platform_crl.as_ref()
//                 } else if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor")
//                     || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor") {
//                     self.sgx_pck_processor_crl.as_ref()
//                 } else if crl_uri.contains("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der") {
//                     self.sgx_root_ca_crl.as_ref()
//                 } else {
//                     panic!("Unknown CRL URI: {}", crl_uri);
//                 }
//             },
//             None => {
//                 panic!("No CRL URI found in certificate");
//             }
//         }.unwrap();

//         // check if the cert is revoked given the crl
//         is_cert_revoked(cert, crl)
//     }
// }

#[derive(Drop, Copy)]
pub struct Certificates {
    pub certs_der: Span<u8>,
}

trait CertificatesFromBytes {
    fn from_bytes(certs_der: Span<u8>) -> Certificates;
}

trait CertificatesFromPem {
    fn from_pem(pem_bytes: Span<u8>) -> Certificates;
}

impl CertificatesFromBytesImpl of CertificatesFromBytes {
    fn from_bytes(certs_der: Span<u8>) -> Certificates {
        Certificates {
            certs_der: certs_der,
        }
    }

    // pub fn get_certs(&self) -> Vec<X509Certificate> {
    //     let certs = parse_x509_der_multi(&self.certs_der);
    //     certs
    // }
}

// impl CertificatesFromPemImpl of CertificatesFromPem {
//     fn from_pem(pem_bytes: Span<u8>) -> Certificates {
//         let certs_der = pem_to_der(pem_bytes);
//         CertificatesFromBytesImpl::from_bytes(certs_der)
//     }
// }

// pub fn pem_to_der(pem_bytes: Span<u8>) -> Span<u8> {
//     // convert from raw pem bytes to pem objects
//     let pems = parse_pem(pem_bytes).unwrap();
//     // convert from pem objects to der bytes
//     // to make it more optimize, we'll read get all the lengths of the der bytes
//     // and then allocate the buffer once
//     let der_bytes_len: usize = pems.iter().map(|pem| pem.contents.len()).sum();
//     let mut der_bytes = Vec::with_capacity(der_bytes_len);
//     for pem in pems {
//         der_bytes.extend_from_slice(&pem.contents);
//     }
//     der_bytes
// }