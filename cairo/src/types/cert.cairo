use starknet::secp256_trait::Signature;
// use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};
// use crate::utils::cert::{get_crl_uri, is_cert_revoked, parse_x509_der_multi, pem_to_der};
use super::collaterals::IntelCollateralData;
use crate::utils::x509_decode::X509CertObj;
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
    pub sgx_root_ca_crl: @Option<CertificateRevocationList>,
    pub sgx_pck_processor_crl: @Option<CertificateRevocationList>,
    pub sgx_pck_platform_crl: @Option<CertificateRevocationList>,
}

#[generate_trait]
impl IntelSgxCrlsImpl of IntelSgxCrlsTrait {
    fn from_collaterals(collaterals: @IntelCollateralData) -> IntelSgxCrls {
        IntelSgxCrls {
            sgx_root_ca_crl: collaterals.sgx_intel_root_ca_crl,
            sgx_pck_processor_crl: collaterals.sgx_pck_processor_crl,
            sgx_pck_platform_crl: collaterals.sgx_pck_platform_crl,
        }
    }
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

pub fn extract_sgx_extension(cert: @X509CertObj) -> SgxExtensions {
    // https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

    // <SGX Extensions OID>:
    //     <PPID OID>: <PPID value>
    //     <TCB OID>:
    //          <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
    //          <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
    //          …
    //          <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
    //          <PCESVN OID>: <PCESVN value>
    //          <CPUSVN OID>: <CPUSVN value>
    //     <PCE-ID OID>: <PCE-ID value>
    //     <FMSPC OID>: <FMSPC value>
    //     <SGX Type OID>: <SGX Type value>
    //     <PlatformInstanceID OID>: <PlatformInstanceID value>
    //     <Configuration OID>:
    //          <Dynamic Platform OID>: <Dynamic Platform flag value>
    //          <Cached Keys OID>: <Cached Keys flag value>
    //          <SMT Enabled OID>: <SMT Enabled flag value>

    // SGX Extensions       | 1.2.840.113741.1.13.1      | mandatory | ASN.1 Sequence
    // PPID                 | 1.2.840.113741.1.13.1.1    | mandatory | ASN.1 Octet String
    // TCB                  | 1.2.840.113741.1.13.1.2    | mandatory | ASN.1 Sequence
    // SGX TCB Comp01 SVN   | 1.2.840.113741.1.13.1.2.1  | mandatory | ASN.1 Integer
    // SGX TCB Comp02 SVN   | 1.2.840.113741.1.13.1.2.2  | mandatory | ASN.1 Integer
    // ...
    // SGX TCB Comp16 SVN   | 1.2.840.113741.1.13.1.2.16 | mandatory | ASN.1 Integer
    // PCESVN               | 1.2.840.113741.1.13.1.2.17 | mandatory | ASN.1 Integer
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Integer
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    // we'll process the sgx extensions here...
    let mut i = sgx_extensions.content.as_ref();

    // let's define the required information to create the SgxExtensions struct
    let mut ppid = [0; 16];
    let mut tcb = SgxExtensionTcbLevel {
        sgxtcbcomp01svn: 0,
        sgxtcbcomp02svn: 0,
        sgxtcbcomp03svn: 0,
        sgxtcbcomp04svn: 0,
        sgxtcbcomp05svn: 0,
        sgxtcbcomp06svn: 0,
        sgxtcbcomp07svn: 0,
        sgxtcbcomp08svn: 0,
        sgxtcbcomp09svn: 0,
        sgxtcbcomp10svn: 0,
        sgxtcbcomp11svn: 0,
        sgxtcbcomp12svn: 0,
        sgxtcbcomp13svn: 0,
        sgxtcbcomp14svn: 0,
        sgxtcbcomp15svn: 0,
        sgxtcbcomp16svn: 0,
        pcesvn: 0,
        cpusvn: [0; 16],
    };
    let mut pceid = [0; 2];
    let mut fmspc = [0; 6];
    let mut sgx_type = 0;
    let mut platform_instance_id: Option<[u8; 16]> = Option::None;
    let mut configuration: Option<PckPlatformConfiguration> = Option::None;

    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.1" => {
                let (k, ppid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                ppid.copy_from_slice(ppid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.2" => {
                let (k, tcb_sequence) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                // iterate through from 1 - 18
                let (k, sgxtcbcomp01svn) =
                    get_asn1_uint64(tcb_sequence.content.as_ref(), "1.2.840.113741.1.13.1.2.1");
                let (k, sgxtcbcomp02svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.2");
                let (k, sgxtcbcomp03svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.3");
                let (k, sgxtcbcomp04svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.4");
                let (k, sgxtcbcomp05svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.5");
                let (k, sgxtcbcomp06svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.6");
                let (k, sgxtcbcomp07svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.7");
                let (k, sgxtcbcomp08svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.8");
                let (k, sgxtcbcomp09svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.9");
                let (k, sgxtcbcomp10svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.10");
                let (k, sgxtcbcomp11svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.11");
                let (k, sgxtcbcomp12svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.12");
                let (k, sgxtcbcomp13svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.13");
                let (k, sgxtcbcomp14svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.14");
                let (k, sgxtcbcomp15svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.15");
                let (k, sgxtcbcomp16svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.16");
                let (k, pcesvn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.17");
                let (k, cpusvn) = get_asn1_bytes(k, "1.2.840.113741.1.13.1.2.18");

                assert_eq!(k.len(), 0);
                // copy the bytes into the tcb struct
                tcb.sgxtcbcomp01svn = sgxtcbcomp01svn as u8;
                tcb.sgxtcbcomp02svn = sgxtcbcomp02svn as u8;
                tcb.sgxtcbcomp03svn = sgxtcbcomp03svn as u8;
                tcb.sgxtcbcomp04svn = sgxtcbcomp04svn as u8;
                tcb.sgxtcbcomp05svn = sgxtcbcomp05svn as u8;
                tcb.sgxtcbcomp06svn = sgxtcbcomp06svn as u8;
                tcb.sgxtcbcomp07svn = sgxtcbcomp07svn as u8;
                tcb.sgxtcbcomp08svn = sgxtcbcomp08svn as u8;
                tcb.sgxtcbcomp09svn = sgxtcbcomp09svn as u8;
                tcb.sgxtcbcomp10svn = sgxtcbcomp10svn as u8;
                tcb.sgxtcbcomp11svn = sgxtcbcomp11svn as u8;
                tcb.sgxtcbcomp12svn = sgxtcbcomp12svn as u8;
                tcb.sgxtcbcomp13svn = sgxtcbcomp13svn as u8;
                tcb.sgxtcbcomp14svn = sgxtcbcomp14svn as u8;
                tcb.sgxtcbcomp15svn = sgxtcbcomp15svn as u8;
                tcb.sgxtcbcomp16svn = sgxtcbcomp16svn as u8;
                tcb.pcesvn = pcesvn as u16;
                tcb.cpusvn.copy_from_slice(cpusvn.as_ref());
            }
            "1.2.840.113741.1.13.1.3" => {
                let (k, pceid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                pceid.copy_from_slice(pceid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.5" => {
                let (k, sgx_type_enum) = Enumerated::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                sgx_type = sgx_type_enum.0;
            }
            "1.2.840.113741.1.13.1.6" => {
                let (k, platform_instance_id_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut temp = [0; 16];
                temp.copy_from_slice(platform_instance_id_bytes.as_ref());
                platform_instance_id = Some(temp);
            }
            "1.2.840.113741.1.13.1.7" => {
                let (k, configuration_seq) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut configuration_temp = PckPlatformConfiguration {
                    dynamic_platform: None,
                    cached_keys: None,
                    smt_enabled: None,
                };
                // iterate through from 1 - 3, note that some of them might be optional.
                let mut k = configuration_seq.content.as_ref();
                while k.len() > 0 {
                    let (l, asn1_seq) = Sequence::from_der(k).unwrap();
                    k = l;
                    let (l, current_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
                    match current_oid.to_id_string().as_str() {
                        "1.2.840.113741.1.13.1.7.1" => {
                            let (l, dynamic_platform_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.dynamic_platform =
                                Some(dynamic_platform_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.2" => {
                            let (l, cached_keys_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.cached_keys = Some(cached_keys_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.3" => {
                            let (l, smt_enabled_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.smt_enabled = Some(smt_enabled_bool.bool());
                        }
                        _ => {
                            unreachable!("Unknown OID: {}", current_oid.to_id_string());
                        }
                    }
                }
                // done parsing...
                configuration = Some(configuration_temp);
            }
            _ => {
                unreachable!("Unknown OID: {}", current_oid.to_id_string());
            }
        }
    }

    SgxExtensions {
        ppid,
        tcb,
        pceid,
        fmspc,
        sgx_type,
        platform_instance_id,
        configuration,
    }
}