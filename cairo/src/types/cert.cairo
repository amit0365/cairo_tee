use starknet::secp256_trait::Signature;
// use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};
// use crate::utils::cert::{get_crl_uri, is_cert_revoked, parse_x509_der_multi, pem_to_der};
use super::collaterals::{IntelCollateralData, IntelCollateralDataRaw, IntelCollateralDataTrait};
use crate::utils::x509_decode::X509CertObj;
use crate::utils::x509crl_decode::{X509CRLObj, X509CRLDecodeTrait};

// #[derive(Default, Debug)]
pub struct SgxExtensionTcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
    pub cpusvn: [u8; 16]
}


// #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

//#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[derive(Drop)]
pub struct CertificateRevocationList {
    pub tbs_cert_list: TbsCertificateDataList,
    // pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Signature,
}

#[derive(Drop, Copy)]
pub struct IntelSgxCrls {
    pub sgx_root_ca_crl: Option<X509CRLObj>,
    pub sgx_pck_processor_crl: Option<X509CRLObj>,
    pub sgx_pck_platform_crl: Option<X509CRLObj>,
}

#[generate_trait]
impl IntelSgxCrlsImpl of IntelSgxCrlsTrait {
    fn from_collaterals(collaterals: @IntelCollateralDataRaw) -> IntelSgxCrls {
        IntelSgxCrls {
            sgx_pck_processor_crl: collaterals.get_sgx_pck_processor_crl(),
            sgx_pck_platform_crl: collaterals.get_sgx_pck_platform_crl(),
            sgx_root_ca_crl: collaterals.get_sgx_intel_root_ca_crl(),
        }
    }

    // fn is_cert_revoked(self: @IntelSgxCrls, cert: @X509CertificateData) -> bool {
    //     let crl = match get_crl_uri(cert) {
    //         Some(crl_uri) => {
    //             if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform")
    //                 || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform") {
    //                 self.sgx_pck_platform_crl.as_ref()
    //             } else if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor")
    //                 || crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor") {
    //                 self.sgx_pck_processor_crl.as_ref()
    //             } else if crl_uri.contains("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der") {
    //                 self.sgx_root_ca_crl.as_ref()
    //             } else {
    //                 panic!("Unknown CRL URI: {}", crl_uri);
    //             }
    //         },
    //         None => {
    //             panic!("No CRL URI found in certificate");
    //         }
    //     }.unwrap();

    //     // check if the cert is revoked given the crl
    //     is_cert_revoked(cert, crl)
    // }
}

// #[generate_trait]
// impl IntelSgxCrlsRevokedImpl of IntelSgxCrlsRevokedTrait {
//     fn is_cert_revoked(cert: @X509CertificateData, crl: @CertificateRevocationList) -> bool {
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

#[derive(PartialEq, Drop)]
pub struct X509CertificateData {
    pub tbs_certificate_data: TbsCertificateData,
    //pub signature_algorithm: Span<Span<u8>>, not needed
    pub signature_value: Signature,
}


#[derive(PartialEq, Drop)]
pub struct PublicKey{
    pub x: u256,
    pub y: u256,
}

#[derive(PartialEq, Drop)]
pub struct X509NameRaw{
    pub raw: Span<u8>,
}

#[derive(PartialEq, Drop)]
pub struct TbsCertificateData {
    pub version: u8,
    pub serial: felt252, //todo check this, should bebiguint
    pub signature: Signature,
    pub issuer: X509NameRaw,
    pub validity: Span<Span<u8>>,
    pub subject: X509NameRaw,
    pub subject_pki: PublicKey,
    pub issuer_uid: Option<Span<Span<u8>>>,
    pub subject_uid: Option<Span<Span<u8>>>,
    pub extensions: Option<Span<Span<u8>>>,
    pub (crate) raw: Span<u8>,
    pub (crate) raw_serial: Span<u8>,
}

// pub fn signature_to_span(signature: Signature) -> Span<u8> {
//     let mut signature_span = array![];
//     signature_span.append_span(signature.r.as_slice().try_into().unwrap());
//     signature_span.append_span(signature.s.as_slice().try_into().unwrap());
//     signature_span.span()
// }

#[generate_trait]
impl TbsCertificateDataImpl of TbsCertificateDataTrait {
    fn as_ref(self: @TbsCertificateData) -> Span<u8> {
        self.raw.deref()
    }
}

#[derive(Drop)]
pub struct TbsCertificateDataList {
    pub version: Option<u8>,
    pub signature: Signature,
    pub issuer: X509NameRaw,
    pub this_update: felt252, //ASN1Time using felt for now
    pub next_update: Option<felt252>, //ASN1Time using felt for now
    pub revoked_certificates: Span<RevokedCertificate>,
    pub extensions: Option<Span<Span<u8>>>,
    pub (crate) raw: Span<u8>,
}

#[generate_trait]
impl TbsCertificateDataListImpl of TbsCertificateDataListTrait {
    fn as_ref(self: @TbsCertificateDataList) -> Span<u8> {
        self.raw.deref()
    }
}

pub struct RevokedCertificate {
    /// The Serial number of the revoked certificate
    pub user_certificate: felt252, //todo check this, should bebiguint,
    /// The date on which the revocation occurred is specified.
    pub revocation_date: felt252, //ASN1Time using felt for now
    /// Additional information about revocation
    extensions: Span<Span<Span<u8>>>,
}