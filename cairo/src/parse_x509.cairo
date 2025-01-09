use core::traits::Into;

// Define the trai
trait X509CertificateIndices {
    fn from_indices(indices: Span<FieldIndex>) -> X509CertificateIndex;
}

trait X509CertificateExtractData{
    fn extract_data(self: X509CertificateIndex, der_bytes_parsed: Span<Span<u8>>) -> X509CertificateData;
}

// Define the struct
#[derive(Debug, Drop, Copy)]
struct X509CertificateIndex {
    pub tbs_certificate: CertificateIndex,
    pub signature_algorithm: @FieldIndex,
    pub signature_value: @FieldIndex,
}

// Implement the trait
impl X509CertificateIndexImpl of X509CertificateIndices {
    fn from_indices(indices: Span<FieldIndex>) -> X509CertificateIndex {
        X509CertificateIndex {
            tbs_certificate: CertificateIndexTrait::from_indices(indices),
            signature_algorithm: indices[0],
            signature_value: indices[1],
        }
    }
}

impl X509CertificateExtractDataImpl of X509CertificateExtractData {
    fn extract_data(self: X509CertificateIndex, der_bytes_parsed: Span<Span<u8>>) -> X509CertificateData {
        let version = X509Version::from_der_parsed(
            der_bytes_parsed[self.tbs_certificate.version.start..self.tbs_certificate.version.end].to_vec(),
        );

        let serial = felt252::from_bytes_be(&der_bytes_parsed[self.tbs_certificate.serial.start + 2]);
        let signature = AlgorithmIdentifier::from_der_parsed(
            der_bytes_parsed[self.tbs_certificate.signature.start..self.tbs_certificate.signature.end].to_vec(),
        );

        let issuer_data_owned = der_bytes_parsed[self.tbs_certificate.issuer.first().unwrap().start - 6..self.tbs_certificate.issuer.last().unwrap().end].to_vec();
        let issuer = X509Name::from_der_parsed(issuer_data_owned);

        let validity = Validity::from_der_parsed(
            extract_data(&self.tbs_certificate.validity, der_bytes_parsed),
        );

        let subject_data_owned = der_bytes_parsed[self.tbs_certificate.subject.first().unwrap().start - 6..self.tbs_certificate.subject.last().unwrap().end].to_vec();
        let subject = X509Name::from_der_parsed(subject_data_owned);
        //println!("subject {:?}", subject.to_string());

        let subject_pki = SubjectPublicKeyInfo::from_der_parsed(
            der_bytes_parsed[self.tbs_certificate.subject_pki.first().unwrap().start - 6..self.tbs_certificate.subject_pki.last().unwrap().end].to_vec(),
        );
        // println!("subject_pki {:?}", subject_pki);

        let issuer_uid = self.tbs_certificate.issuer_uid.as_ref().map(|idx| 
            UniqueIdentifier::from_der_parsed(der_bytes_parsed[idx.start..idx.end].to_vec())
        );
        //println!("issuer_uid {:?}", issuer_uid);

        let subject_uid = self.tbs_certificate.subject_uid.as_ref().map(|idx| 
            UniqueIdentifier::from_der_parsed(der_bytes_parsed[idx.start..idx.end].to_vec())
        );
        //println!("subject_uid {:?}", subject_uid);

        //let extensions = Vec::new();
        let extensions = self.tbs_certificate.extensions.as_ref().map_or(Vec::new(), |idx| 
            Vec::<X509Extension>::from_der_parsed(der_bytes_parsed[idx.start..idx.end].to_vec())
        );
        //println!("extensions {:?}", extensions);
        println!("signature_algorithm after subject pki {:?}", &der_bytes_parsed[self.tbs_certificate.subject_pki.last().unwrap().end..]);
        let tbs_cert = TbsCertificateData {
            version,
            serial,
            signature,
            issuer,
            validity,
            subject,
            subject_pki,
            issuer_uid,
            subject_uid,
            extensions,
            raw: der_bytes_parsed[self.tbs_certificate.version.start..self.tbs_certificate.version.end].concat(),
            raw_serial: der_bytes_parsed[self.tbs_certificate.serial.start..self.tbs_certificate.serial.end][0].clone(), // Owned u8
        };

        println!("signature_algorithm start {:?}", self.signature_algorithm.start);
        println!("signature_algorithm end {:?}", self.signature_algorithm.end);
        let signature_algorithm_bytes = der_bytes_parsed[self.signature_algorithm.start..self.signature_algorithm.end].to_vec();
        println!("signature_algorithm_bytes {:?}", signature_algorithm_bytes);
        let signature_algorithm = AlgorithmIdentifier::from_der_parsed(
            signature_algorithm_bytes,
        );
        println!("signature_algorithm {:?}", signature_algorithm);
        let sig_value_bytes = der_bytes_parsed[self.signature_value.start..self.signature_value.end].to_vec();
        let signature_value = BitString::from_der_parsed(
            sig_value_bytes,
        );
        println!("signature_value {:?}", signature_value);
        X509CertificateData {
            tbs_certificate_data: tbs_cert,
            //signature_algorithm,
            signature_value,
        }
    }
}

// Define trait for CertificateIndex
trait CertificateIndexTrait {
    fn from_indices(indices: Span<FieldIndex>) -> CertificateIndex;
}

// Implement the trait
impl CertificateIndexImpl of CertificateIndexTrait {
    fn from_indices(indices: Span<FieldIndex>) -> CertificateIndex {
        CertificateIndex {
            version: indices[0],
            serial: indices[1],
            signature: indices[2],
            issuer: indices.slice(3, 10),
            validity: indices.slice(13, 2),
            subject: indices.slice(15, 10),
            subject_pki: indices.slice(25, 3),
            issuer_uid: Option::None,
            subject_uid: Option::None,
            extensions: Option::None,
        }
    }
}

#[derive(Debug, Copy, Drop)]
pub struct FieldIndex {pub index: usize}

#[derive(Debug, Drop, Copy)]
pub struct CertificateIndex {
    pub version: @FieldIndex,
    pub serial: @FieldIndex,
    pub signature: @FieldIndex,
    pub issuer: Span<FieldIndex>,
    pub validity: Span<FieldIndex>,
    pub subject: Span<FieldIndex>,
    pub subject_pki: Span<FieldIndex>,
    pub issuer_uid: Option<FieldIndex>,
    pub subject_uid: Option<FieldIndex>,
    pub extensions: Option<FieldIndex>,
}

pub struct X509CertificateData {
    pub tbs_certificate_data: TbsCertificateData,
    //pub signature_algorithm: Span<Span<u8>>, not needed
    pub signature_value: SignatureFelt,
}

/// todo but does not check that `r, s < stark_curve::ORDER`, which should be checked by the caller.
pub struct SignatureFelt{
    pub r: felt252,
    pub s: felt252,
}

pub struct PublicKeyFelt{
    pub x: felt252,
}

pub struct X509NameRaw{
    pub raw: Span<u8>,
}

pub struct TbsCertificateData {
    pub version: u8,
    pub serial: felt252, //biguint
    pub signature: SignatureFelt,
    pub issuer: X509NameRaw,
    pub validity: Span<Span<u8>>,
    pub subject: X509NameRaw,
    pub subject_pki: PublicKeyFelt,
    pub issuer_uid: Option<Span<Span<u8>>>,
    pub subject_uid: Option<Span<Span<u8>>>,
    pub extensions: Option<Span<Span<u8>>>,
    pub raw: Span<u8>,
    pub raw_serial: Span<u8>,
}

use core::ecdsa::check_ecdsa_signature;
use starknet::secp256_trait::Signature;
use alexandria_encoding::base64;
use snforge_std::fs::{FileTrait, read_txt};

fn verify_p256_signature_felt(data: felt252, public_key: felt252, r: felt252, s: felt252) -> bool {
    check_ecdsa_signature(data, public_key, r, s)
}

#[test]
fn test_verify_p256_signature_felt(parsed_inputs: Array<Array<u8>>, raw_inputs: Array<u8>) {     
    let path_bytes: ByteArray = "src/signature_inputs.txt";
    let file = FileTrait::new(path_bytes);
    let inputs: Array<felt252> = read_txt(@file);

    let mut x: Array<ByteArray> = ArrayTrait::new();
    let x_bytes: ByteArray = "src/signature_inputs.txt";
    x.append(x_bytes);

    let message_hash = *inputs.at(0);
    let pubkey = *inputs.at(1);
    let r = *inputs.at(2);
    let s = *inputs.at(3);

    let result = verify_p256_signature_felt(message_hash.clone(), pubkey.clone(), r.clone(), s.clone());
    assert(result, 'Signature verification failed');
}

