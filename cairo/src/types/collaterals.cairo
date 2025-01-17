// use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};
// use crate::utils::cert::{parse_crl_der, parse_x509_der, parse_x509_der_multi, pem_to_der};
use crate::types::cert::{X509CertificateData, CertificateRevocationList};
use super::enclave_identity::EnclaveIdentityV2;
use super::tcbinfo::{TcbInfoV2, TcbInfoV3};
use cairo::utils::x509_decode::X509CertObj;

#[derive(Clone, Debug)]
pub struct IntelCollateral {
    pub tcbinfo_bytes: Option<Span<u8>>,
    pub qeidentity_bytes: Option<Span<u8>>,
    pub sgx_intel_root_ca_der: Option<Span<u8>>,
    pub sgx_tcb_signing_der: Option<Span<u8>>,
    pub sgx_pck_certchain_der: Option<Span<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Span<u8>>,
    pub sgx_pck_processor_crl_der: Option<Span<u8>>,
    pub sgx_pck_platform_crl_der: Option<Span<u8>>,
}

#[derive(Drop)]
pub enum TcbInfo {
    V2: TcbInfoV2,
    V3: TcbInfoV3,
}

#[derive(Drop)]
pub struct IntelCollateralData {
    pub tcbinfo: TcbInfo,
    pub qeidentity: EnclaveIdentityV2,
    pub sgx_intel_root_ca: X509CertObj,
    pub sgx_tcb_signing: X509CertObj,
    pub sgx_pck_certchain: Span<X509CertObj>,
    pub sgx_intel_root_ca_crl: Option<CertificateRevocationList>,
    pub sgx_pck_processor_crl: Option<CertificateRevocationList>,
    pub sgx_pck_platform_crl: Option<CertificateRevocationList>,
}

// pub struct IntelCollateralDataV2 {
//     pub tcbinfo: TcbInfoV2,
//     pub qeidentity: EnclaveIdentityV2,
//     pub sgx_intel_root_ca: X509CertificateData,
//     pub sgx_tcb_signing: X509CertificateData,
//     pub sgx_pck_certchain: Span<X509CertificateData>,
//     pub sgx_intel_root_ca_crl: Option<CertificateRevocationList>,
//     pub sgx_pck_processor_crl: Option<CertificateRevocationList>,
//     pub sgx_pck_platform_crl: Option<CertificateRevocationList>,
// }

// builder pattern for IntelCollateralV3
// impl IntelCollateral {
//     pub fn new() -> IntelCollateral {
//         IntelCollateral {
//             tcbinfo_bytes: None,
//             qeidentity_bytes: None,
//             sgx_intel_root_ca_der: None,
//             sgx_tcb_signing_der: None,
//             sgx_pck_certchain_der: None,
//             sgx_intel_root_ca_crl_der: None,
//             sgx_pck_processor_crl_der: None,
//             sgx_pck_platform_crl_der: None,
//         }
//     }

//     pub fn to_bytes(&self) -> Vec<u8> {
//         // serialization scheme is simple: the bytestream is made of 2 parts 
//         // the first contains a u32 length for each of the members
//         // the second contains the actual data
//         // [lengths of each of the member][data segment]

//         let tcbinfo_bytes = match self.tcbinfo_bytes {
//             Some(ref tcbinfo) => tcbinfo.as_slice(),
//             None => &[],
//         };

//         let qeidentity_bytes = match self.qeidentity_bytes {
//             Some(ref qeidentity) => qeidentity.as_slice(),
//             None => &[],
//         };

//         let sgx_intel_root_ca_der_bytes = match &self.sgx_intel_root_ca_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         let sgx_tcb_signing_der_bytes = match &self.sgx_tcb_signing_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         let sgx_pck_certchain_der_bytes = match &self.sgx_pck_certchain_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         let sgx_intel_root_ca_crl_der_bytes = match &self.sgx_intel_root_ca_crl_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         let sgx_pck_processor_crl_der_bytes = match &self.sgx_pck_processor_crl_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         let sgx_pck_platform_crl_der_bytes = match &self.sgx_pck_platform_crl_der {
//             Some(der) => der.as_slice(),
//             None => &[],
//         };

//         // get the total length
//         let total_length = 4 * 8 + tcbinfo_bytes.len() + qeidentity_bytes.len() + sgx_intel_root_ca_der_bytes.len() + sgx_tcb_signing_der_bytes.len() + sgx_pck_certchain_der_bytes.len() + sgx_intel_root_ca_crl_der_bytes.len() + sgx_pck_processor_crl_der_bytes.len() + sgx_pck_platform_crl_der_bytes.len();

//         // create the vec and copy the data
//         let mut data = Vec::with_capacity(total_length);
//         data.extend_from_slice(&(tcbinfo_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(qeidentity_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_intel_root_ca_der_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_tcb_signing_der_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_pck_certchain_der_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_intel_root_ca_crl_der_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_pck_processor_crl_der_bytes.len() as u32).to_le_bytes());
//         data.extend_from_slice(&(sgx_pck_platform_crl_der_bytes.len() as u32).to_le_bytes());

//         data.extend_from_slice(&tcbinfo_bytes);
//         data.extend_from_slice(&qeidentity_bytes);
//         data.extend_from_slice(&sgx_intel_root_ca_der_bytes);
//         data.extend_from_slice(&sgx_tcb_signing_der_bytes);
//         data.extend_from_slice(&sgx_pck_certchain_der_bytes);
//         data.extend_from_slice(&sgx_intel_root_ca_crl_der_bytes);
//         data.extend_from_slice(&sgx_pck_processor_crl_der_bytes);
//         data.extend_from_slice(&sgx_pck_platform_crl_der_bytes);

//         data
//     }

//     pub fn from_bytes(slice: &[u8]) -> Self {
//         // reverse the serialization process
//         // each length is 4 bytes long, we have a total of 8 members
//         let tcbinfo_bytes_len = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as usize;
//         let qeidentity_bytes_len = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
//         let sgx_intel_root_ca_der_len = u32::from_le_bytes(slice[8..12].try_into().unwrap()) as usize;
//         let sgx_tcb_signing_der_len = u32::from_le_bytes(slice[12..16].try_into().unwrap()) as usize;
//         let sgx_pck_certchain_der_len = u32::from_le_bytes(slice[16..20].try_into().unwrap()) as usize;
//         let sgx_intel_root_ca_crl_der_len = u32::from_le_bytes(slice[20..24].try_into().unwrap()) as usize;
//         let sgx_pck_processor_crl_der_len = u32::from_le_bytes(slice[24..28].try_into().unwrap()) as usize;
//         let sgx_pck_platform_crl_der_len = u32::from_le_bytes(slice[28..32].try_into().unwrap()) as usize;

//         let mut offset = 4 * 8 as usize;
//         let tcbinfo_bytes: Option<Vec<u8>> = match tcbinfo_bytes_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += tcbinfo_bytes_len;

//         let qeidentity_bytes: Option<Vec<u8>> = match qeidentity_bytes_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += qeidentity_bytes_len;

//         let sgx_intel_root_ca_der: Option<Vec<u8>> = match sgx_intel_root_ca_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_intel_root_ca_der_len;

//         let sgx_tcb_signing_der: Option<Vec<u8>> = match sgx_tcb_signing_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_tcb_signing_der_len;

//         let sgx_pck_certchain_der: Option<Vec<u8>> = match sgx_pck_certchain_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_pck_certchain_der_len;

//         let sgx_intel_root_ca_crl_der: Option<Vec<u8>> = match sgx_intel_root_ca_crl_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_intel_root_ca_crl_der_len;

//         let sgx_pck_processor_crl_der: Option<Vec<u8>> = match sgx_pck_processor_crl_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_pck_processor_crl_der_len;

//         let sgx_pck_platform_crl_der: Option<Vec<u8>> = match sgx_pck_platform_crl_der_len {
//             0 => None,
//             len => Some(slice[offset..offset + len].to_vec())
//         };
//         offset += sgx_pck_platform_crl_der_len;

//         assert!(offset == slice.len());

//         IntelCollateral {
//             tcbinfo_bytes: tcbinfo_bytes,
//             qeidentity_bytes: qeidentity_bytes,
//             sgx_intel_root_ca_der,
//             sgx_tcb_signing_der,
//             sgx_pck_certchain_der,
//             sgx_intel_root_ca_crl_der,
//             sgx_pck_processor_crl_der,
//             sgx_pck_platform_crl_der,
//         }
//     }

//     pub fn get_tcbinfov2(&self) -> TcbInfoV2 {
//         match &self.tcbinfo_bytes {
//             Some(tcbinfov2) => {
//                 let tcbinfo: TcbInfoV2 = serde_json::from_slice(tcbinfov2).unwrap();
//                 assert_eq!(tcbinfo.tcb_info.version, 2);
//                 tcbinfo
//             },
//             None => panic!("TCB Info V2 not set"),
//         }
//     }

//     pub fn get_tcbinfov3(&self) -> TcbInfoV3 {
//         match &self.tcbinfo_bytes {
//             Some(tcbinfov3) => {
//                 let tcbinfo: TcbInfoV3 = serde_json::from_slice(tcbinfov3).unwrap();
//                 assert_eq!(tcbinfo.tcb_info.version, 3);
//                 tcbinfo
//             },
//             None => panic!("TCB Info V3 not set"),
//         }
//     }

//     pub fn set_tcbinfo_bytes(&mut self, tcbinfo_slice: &[u8]) {
//         self.tcbinfo_bytes = Some(tcbinfo_slice.to_vec());
//     }

//     pub fn get_qeidentityv2(&self) -> EnclaveIdentityV2 {
//         match &self.qeidentity_bytes {
//             Some(qeidentityv2) => {
//                 let qeidentity = serde_json::from_slice(qeidentityv2).unwrap();
//                 qeidentity
//             },
//             None => panic!("QE Identity V2 not set"),
//         }
//     }

//     pub fn set_qeidentity_bytes(&mut self, qeidentity_slice: &[u8]) {
//         self.qeidentity_bytes = Some(qeidentity_slice.to_vec());
//     }

//     pub fn get_sgx_intel_root_ca<'a>(&'a self) -> X509Certificate<'a> {
//         match self.sgx_intel_root_ca_der {
//             Some(ref der) => {
//                 let cert = parse_x509_der(der);
//                 cert
//             },
//             None => panic!("Intel Root CA not set"),
//         }
//     }

//     pub fn set_intel_root_ca_der(&mut self, intel_root_ca_der: &[u8]) {
//         self.sgx_intel_root_ca_der = Some(intel_root_ca_der.to_vec());
//     }

//     pub fn get_sgx_tcb_signing<'a>(&'a self) -> X509Certificate<'a> {
//         match self.sgx_tcb_signing_der {
//             Some(ref der) => {
//                 let cert = parse_x509_der(der);
//                 cert
//             },
//             None => panic!("SGX TCB Signing Cert not set"),
//         }
//     }

//     pub fn set_sgx_tcb_signing_der(&mut self, sgx_tcb_signing_der: &[u8]) {
//         self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der.to_vec());
//     }

//     pub fn set_sgx_tcb_signing_pem(&mut self, sgx_tcb_signing_pem: &[u8]) {
//         // convert pem to der
//         let sgx_tcb_signing_der = pem_to_der(sgx_tcb_signing_pem);
//         self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der);
//     }

//     pub fn get_sgx_pck_certchain<'a>(&'a self) -> Option<Vec<X509Certificate<'a>>> {
//         match &self.sgx_pck_certchain_der {
//             Some(certchain_der) => {
//                 let certchain = parse_x509_der_multi(certchain_der);
//                 Some(certchain)
//             },
//             None => None,
//         }
//     }

//     pub fn set_sgx_pck_certchain_der(&mut self, sgx_pck_certchain_der: Option<&[u8]>) {
//         match sgx_pck_certchain_der {
//             Some(certchain_der) => {
//                 self.sgx_pck_certchain_der = Some(certchain_der.to_vec());
//             },
//             None => {
//                 self.sgx_pck_certchain_der = None;
//             },
//         }
//     }

//     pub fn set_sgx_pck_certchain_pem(&mut self, sgx_pck_certchain_pem: Option<&[u8]>) {
//         match sgx_pck_certchain_pem {
//             Some(certchain_pem) => {
//                 // convert pem to der
//                 let sgx_pck_certchain_der = pem_to_der(certchain_pem);
//                 self.sgx_pck_certchain_der = Some(sgx_pck_certchain_der);
//             },
//             None => {
//                 self.sgx_pck_certchain_der = None;
//             },
//         }
//     }

//     pub fn get_sgx_intel_root_ca_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
//         match &self.sgx_intel_root_ca_crl_der {
//             Some(crl_der) => {
//                 let crl = parse_crl_der(crl_der);
//                 Some(crl)
//             },
//             None => None,
//         }
//     }

//     pub fn set_sgx_intel_root_ca_crl_der(&mut self, sgx_intel_root_ca_crl_der: &[u8]) {
//         self.sgx_intel_root_ca_crl_der = Some(sgx_intel_root_ca_crl_der.to_vec());
//     }

//     pub fn set_sgx_intel_root_ca_crl_pem(&mut self, sgx_intel_root_ca_crl_pem: &[u8]) {
//         // convert pem to der
//         let sgx_intel_root_ca_crl_der = pem_to_der(sgx_intel_root_ca_crl_pem);
//         self.sgx_intel_root_ca_crl_der = Some(sgx_intel_root_ca_crl_der);
//     }

//     pub fn get_sgx_pck_processor_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
//         match &self.sgx_pck_processor_crl_der {
//             Some(crl_der) => {
//                 let crl = parse_crl_der(crl_der);
//                 Some(crl)
//             },
//             None => None,
//         }
//     }

//     pub fn set_sgx_processor_crl_der(&mut self, sgx_pck_processor_crl_der: &[u8]) {
//         self.sgx_pck_processor_crl_der = Some(sgx_pck_processor_crl_der.to_vec());
//     }

//     pub fn set_sgx_processor_crl_der_pem(&mut self, sgx_pck_processor_crl_pem: &[u8]) {
//         // convert pem to der
//         let sgx_pck_processor_crl_der = pem_to_der(sgx_pck_processor_crl_pem);
//         self.sgx_pck_processor_crl_der = Some(sgx_pck_processor_crl_der);
//     }

//     pub fn get_sgx_pck_platform_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
//         match &self.sgx_pck_platform_crl_der {
//             Some(crl_der) => {
//                 let crl = parse_crl_der(crl_der);
//                 Some(crl)
//             },
//             None => None, 
//         }
//     }

//     pub fn set_sgx_platform_crl_der(&mut self, sgx_pck_platform_crl_der: &[u8]) {
//         self.sgx_pck_platform_crl_der = Some(sgx_pck_platform_crl_der.to_vec());
//     }

//     pub fn set_sgx_platform_crl_der_pem(&mut self, sgx_pck_platform_crl_pem: &[u8]) {
//         // convert pem to der
//         let sgx_pck_platform_crl_der = pem_to_der(sgx_pck_platform_crl_pem);
//         self.sgx_pck_platform_crl_der = Some(sgx_pck_platform_crl_der);
//     }
// }

// impl IntelCollateralImpl of IntelCollateral {
//     fn get_sgx_tcb_signing(collaterals: @IntelCollateral) -> X509CertificateData {
//         match collaterals.sgx_tcb_signing_der {
//             Some(der) => parse_x509_der(der),
//             None => panic!("SGX TCB Signing Cert not set"),
//         }
//     }
// }

// fn get_sgx_tcb_signing(collaterals: @IntelCollateral) -> X509CertificateData {
//     match collaterals.sgx_tcb_signing_der {
//         Some(der) => parse_x509_der(der),
//         None => panic!("SGX TCB Signing Cert not set"),
//     }
// }

//get_sgx_intel_root_ca
//get_sgx_pck_certchain
//get_sgx_intel_root_ca_crl
//get_sgx_pck_processor_crl
//get_sgx_pck_platform_crl