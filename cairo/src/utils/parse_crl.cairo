

#[derive(Drop, Copy, Serde, PartialEq)]
pub struct CertificateRevocationList {
    pub tbs_cert_list: TbsCertList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TbsCertList<'a> {
    pub version: Option<X509Version>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    extensions: Vec<X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
}