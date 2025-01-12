use std::borrow::Cow;
use num_bigint::BigUint;
use time::{format_description::BorrowedFormatItem, OffsetDateTime};
use x509_parser::{der_parser::{asn1_rs::{Any, BitString}, der::{Class, Header, Tag}, Oid}, prelude::{ParsedExtension, TbsCertificate, UniqueIdentifier, Validity, X509Certificate, X509Extension}, time::ASN1Time, x509::{AlgorithmIdentifier, AttributeTypeAndValue, RelativeDistinguishedName, SubjectPublicKeyInfo, X509Name, X509Version}};

pub trait ToNestedBytes {
    fn to_bytes(&self) -> Vec<Vec<u8>>;
    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>); 
}

pub trait FromDerParsed {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self;
}

#[derive(Debug, Clone)]
pub struct FieldIndex {
    pub start: usize,
    pub end: usize,
}

pub trait FieldIndexVec {
    fn to_index_vec(&self) -> Vec<usize>;
}

impl FieldIndexVec for Vec<FieldIndex> {
    fn to_index_vec(&self) -> Vec<usize> {
        self.iter().map(|index| index.start).collect()
    }
}

#[derive(Debug)]
pub struct CertificateIndex {
    pub version: FieldIndex,
    pub serial: FieldIndex,
    pub signature: FieldIndex,
    pub issuer: Vec<FieldIndex>,
    pub validity: Vec<FieldIndex>,
    pub subject: Vec<FieldIndex>,
    pub subject_pki: Vec<FieldIndex>,
    pub issuer_uid: Option<FieldIndex>,
    pub subject_uid: Option<FieldIndex>,
    pub extensions: Option<FieldIndex>,
}

// fn extract_data(indices: &Vec<FieldIndex>, bytes: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
//     // Check if the index is within bounds
//     let mut result = Vec::new();
//     for index in indices {
//         // Check if the range is valid within the validity_bytes
//         if let Some(bytes) = bytes.get(index.start) {
//             // Extract the data from the specified range
//             result.push(bytes.to_vec());
//         }
//     }
//     result
// }

fn extract_data(indices: &[FieldIndex], bytes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    indices.iter()
        .filter_map(|idx| bytes.get(idx.start).map(|b| b.clone()))
        .collect()
}

#[derive(Debug)]
pub struct X509CertificateIndex {
    pub tbs_certificate: CertificateIndex,
    pub signature_algorithm: FieldIndex,
    pub signature_value: FieldIndex,
}

impl CertificateIndex { //todo impl get schema
    pub fn from_indices(indices: Vec<FieldIndex>) -> Self {
        CertificateIndex {
            version: indices[0].clone(),
            serial: indices[1].clone(),
            signature: indices[2].clone(),
            issuer: indices[3..13].to_vec(),
            validity: indices[13..15].to_vec(),
            subject: indices[15..25].to_vec(),
            subject_pki: indices[25..28].to_vec(),
            issuer_uid: None,//indices.get(28).cloned(),
            subject_uid: None,//indices.get(29).cloned(),
            extensions: None,//indices.get(28).cloned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TbsCertificateWrapper<'a> {
    pub version: X509Version,
    pub serial: BigUint,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub validity: Validity,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    pub issuer_uid: Option<UniqueIdentifier<'a>>,
    pub subject_uid: Option<UniqueIdentifier<'a>>,
    pub extensions: Vec<X509Extension<'a>>,
    pub raw: Vec<u8>,
    pub raw_serial: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct X509CertificateWrapper<'a> {
    pub tbs_certificate: TbsCertificateWrapper<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitString<'a>,
}

impl AsRef<[u8]> for X509CertificateWrapper<'_> {
    fn as_ref(&self) -> &[u8] {
        self.tbs_certificate.as_ref()
    }
}

pub fn into_wrapper_x509_cert<'a>(cert: &'a X509Certificate<'a>) -> X509CertificateWrapper<'a> {
    let tbs_cert = into_wrapper_tbs_cert(&cert.tbs_certificate);
    X509CertificateWrapper {
        tbs_certificate: tbs_cert,
        signature_algorithm: cert.signature_algorithm.clone(),
        signature_value: cert.signature_value.clone(),
    }
}

pub fn into_wrapper_tbs_cert<'a>(cert: &'a TbsCertificate<'a>) -> TbsCertificateWrapper<'a> {
    TbsCertificateWrapper {
        version: cert.version,
        serial: cert.serial.clone(),
        signature: cert.signature.clone(),
        issuer: cert.issuer.clone(),
        validity: cert.validity.clone(),
        subject: cert.subject.clone(),
        subject_pki: cert.subject_pki.clone(),
        issuer_uid: cert.issuer_uid.clone(),
        subject_uid: cert.subject_uid.clone(),
        extensions: cert.extensions().to_vec(),
        raw: cert.as_ref().to_vec(),
        raw_serial: cert.raw_serial().to_vec(),
    }
}

impl<'a> TbsCertificateWrapper<'a> {
    pub fn extensions(&self) -> &[X509Extension<'a>] {
        &self.extensions
    }
}

impl AsRef<[u8]> for TbsCertificateWrapper<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl X509CertificateIndex {
    pub fn from_indices(indices: Vec<FieldIndex>) -> Self {
        let tbs_indices = indices[..28].to_vec(); // First 10 indices for TBS
        X509CertificateIndex {
            tbs_certificate: CertificateIndex::from_indices(tbs_indices),
            signature_algorithm: indices[28].clone(),
            signature_value: indices[29].clone(),
        }
    }

    pub fn extract_certificate<'a>(&self, der_bytes_parsed: &'a [Vec<u8>]) -> X509CertificateWrapper<'a> {
        let version = X509Version::from_der_parsed(
            der_bytes_parsed[self.tbs_certificate.version.start..self.tbs_certificate.version.end].to_vec(),
        );

        let serial = BigUint::from_bytes_be(&der_bytes_parsed[self.tbs_certificate.serial.start + 2]);
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
        let tbs_cert = TbsCertificateWrapper {
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
        X509CertificateWrapper {
            tbs_certificate: tbs_cert,
            signature_algorithm,
            signature_value,
        }
    }
}

impl ToNestedBytes for X509CertificateWrapper<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.extend(self.tbs_certificate.to_bytes());
        result.extend(self.signature_algorithm.to_bytes());
        result.push(self.signature_value.as_ref().to_vec());
        result
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut index = Vec::new();
        
        // Calculate initial offset after SEQUENCE tag and length bytes
        let initial_offset = offset + 2;

        // Add TBS Certificate
        let (tbs_certificate_idx, tbs_certificate_bytes) = self.tbs_certificate.to_der_bytes(initial_offset);
        index.extend(tbs_certificate_idx);
        content.extend(tbs_certificate_bytes);

        // Add Signature Algorithm
        let (signature_algorithm_idx, signature_algorithm_bytes) = self.signature_algorithm.to_der_bytes(index.last().unwrap().end + 50); //offset including extensions
        index.extend(signature_algorithm_idx);
        content.extend(signature_algorithm_bytes);
        
        // Add Signature Value as BIT STRING
        content.push(vec![0x03]); // BIT STRING tag
        let mut sig_bytes = vec![0x00]; // Number of unused bits
        sig_bytes.extend(self.signature_value.as_ref());
        content.push(encode_der_length(sig_bytes.len()));
        index.push(FieldIndex {
            start: index.last().unwrap().end + 2,
            end: index.last().unwrap().end + 3,
        });
        content.push(sig_bytes);
        
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (index, der)
    }
}

/// Encodes the length in DER format.
fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let mut len_bytes = Vec::new();
        let mut temp_len = len;
        while temp_len > 0 {
            len_bytes.insert(0, (temp_len & 0xFF) as u8);
            temp_len >>= 8;
        }
        let len_len = len_bytes.len();
        let mut der_length = vec![0x80 | len_len as u8];
        der_length.extend(len_bytes);
        der_length
    }
}

impl ToNestedBytes for TbsCertificateWrapper<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        // Add SEQUENCE wrapper
        let mut sequence = vec![0x30, 0x82, 0x02, 0x32]; // Fixed length for now
        result.extend(self.version.to_bytes());
        //result.push(self.serial.to_bytes_be());
        // Serial number with INTEGER tag
        let mut serial = vec![0x02, 0x14]; // INTEGER tag + length 20
        serial.extend(self.serial.to_bytes_be());
        result.push(serial);

        result.extend(self.signature.to_bytes());
        result.push(self.issuer.as_raw().to_vec());
        result.extend(self.validity.to_bytes());
        result.push(self.subject.as_raw().to_vec());
        result.extend(self.subject_pki.to_bytes());
        result.extend(self.issuer_uid.to_bytes());
        result.extend(self.subject_uid.to_bytes());
        result.extend(self.extensions()
                .iter()
                .flat_map(|e| e.to_bytes().into_iter())
        );
        // println!("result {:?}", result.concat().len());
        //assert_eq!(result.concat(), self.as_ref().to_vec());

        //result
        sequence.extend(result.concat());
        assert_eq!(sequence, self.as_ref().to_vec());

        // let concat = sequence;
        // let expected = self.as_ref().to_vec();
        // if concat != expected {
        //     for (i, (a, b)) in concat.iter().zip(expected.iter()).enumerate() {
        //         if a != b {
        //             println!("Mismatch at index {}: {:02x} != {:02x}", i, a, b);
        //         }
        //     }
        //     if concat.len() != expected.len() {
        //         println!("Length mismatch: {} != {}", concat.len(), expected.len());
        //     }
        // }

        result
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut index = Vec::new();
        
        // 1. Version [0] EXPLICIT
        let (version_idx, version_bytes) = self.version.to_der_bytes(offset + 2);
        index.extend(version_idx);
        content.extend(version_bytes);

        // 2. Serial Number (INTEGER)
        let mut serial = vec![vec![0x02]]; // INTEGER tag
        let serial_bytes = self.serial.to_bytes_be(); // Implement `to_der_bytes` for serial
        let serial_len = encode_der_length(serial_bytes.len());
        serial.extend(vec![serial_len.clone()]);
        serial.extend(vec![serial_bytes]);
        index.extend(vec![FieldIndex {
            start: index.last().unwrap().end + 2,
            end: index.last().unwrap().end + 3,
        }]);
        content.extend(serial);

        // 3. Signature Algorithm
        let (signature_idx, signature_bytes) = self.signature.to_der_bytes(index.last().unwrap().end);
        index.extend(signature_idx);
        content.extend(signature_bytes);

        // 4. Issuer (SEQUENCE)
        let (issuer_idx, issuer_bytes) = self.issuer.to_der_bytes(index.last().unwrap().end);
        index.extend(issuer_idx);
        content.extend(issuer_bytes);
        
        // 5. Validity (SEQUENCE)
        let (validity_idx, validity_bytes) = self.validity.to_der_bytes(index.last().unwrap().end);
        index.extend(validity_idx);
        content.extend(validity_bytes);

        // 6. Subject (SEQUENCE)
        let (subject_idx, subject_bytes) = self.subject.to_der_bytes(index.last().unwrap().end);
        index.extend(subject_idx);
        content.extend(subject_bytes);
        
        // 7. Subject Public Key Info
        let (subject_pki_idx, subject_pki_bytes) = self.subject_pki.to_der_bytes(index.last().unwrap().end);
        index.extend(subject_pki_idx);
        content.extend(subject_pki_bytes);
        
        // 8. issuerUniqueID [1] IMPLICIT (OPTIONAL)
        if let Some(uid) = &self.issuer_uid {
            let mut issuer_uid = vec![vec![0x81]]; // [1] IMPLICIT tag
            let (uid_idx, uid_bytes) = uid.to_der_bytes(index.last().unwrap().end); // Implement `to_der_bytes` for issuer_uid
            index.extend(uid_idx);
            issuer_uid.extend(vec![encode_der_length(uid_bytes.len())]);
            issuer_uid.extend(uid_bytes);
            content.extend(issuer_uid);
        }

        // 9. subjectUniqueID [2] IMPLICIT (OPTIONAL)
        if let Some(uid) = &self.subject_uid {
            let mut subject_uid = vec![vec![0x82]]; // [2] IMPLICIT tag
            let (uid_idx, uid_bytes) = uid.to_der_bytes(index.last().unwrap().end); // Implement `to_der_bytes` for subject_uid
            index.extend(uid_idx);
            subject_uid.extend(vec![encode_der_length(uid_bytes.len())]);
            subject_uid.extend(uid_bytes);
            content.extend(subject_uid);
        }

        let ext_before_len = content.len();
        // Extensions [3] EXPLICIT
        if !self.extensions().is_empty() {
            let mut ext_content = Vec::new();
            for ext in self.extensions() {
                let (ext_idx, ext_bytes) = ext.to_der_bytes(index.last().unwrap().end);
                //index.extend(ext_idx);
                ext_content.extend(ext_bytes);
            }
            
            // Inner SEQUENCE
            let mut inner_seq = Vec::new();
            inner_seq.push(vec![0x30]); // SEQUENCE tag
            let inner_len = ext_content.iter().map(|v| v.len()).sum();
            inner_seq.push(encode_der_length(inner_len));
            inner_seq.extend(ext_content);
            
            // [3] EXPLICIT wrapper
            content.push(vec![0xA3]); // [3] EXPLICIT tag
            let total_len = inner_seq.iter().map(|v| v.len()).sum();
            content.push(encode_der_length(total_len));
            content.extend(inner_seq);
        }
        // println!("extesnsion_len {:?}", ext_before_len);
        // println!("extension bytes before offset {:?}", &content[..ext_before_len].concat().len());
        // println!("extension bytes {:?}", &content[ext_before_len..]);
        // println!("extension bytes offset {:?}", &content[ext_before_len..].len());
        // println!("extension bytes len {:?}", &content[ext_before_len..].concat().len());

        // 11. Wrap everything in SEQUENCE
        let total_content = content.concat();
        let mut der = vec![vec![0x30]]; // SEQUENCE tag
        der.extend(vec![encode_der_length(total_content.len())]);
        der.extend(content);
        
        // let concat = der.clone().concat();
        // let expected = self.as_ref().to_vec();
        // if concat != expected {
        //     let mut mismatches = 0;
        //     for (i, (a, b)) in concat.iter().zip(expected.iter()).enumerate() {
        //         if a != b {
        //             println!("Mismatch at index {}: {:02x} != {:02x}", i, a, b);
        //             mismatches += 1;
        //             if mismatches >= 20 {
        //                 break;
        //             }
        //         }
        //     }
        //     if concat.len() != expected.len() {
        //         println!("Length mismatch: {} != {}", concat.len(), expected.len());
        //     }
        // }
        
        assert_eq!(der.concat(), self.as_ref().to_vec());

        (index, der)
    }
}

impl<T: ToNestedBytes> ToNestedBytes for Option<T> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        match self {
            Some(uid) => uid.to_bytes(),
            None => Vec::new(),
        }
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        match self {
            Some(uid) => uid.to_der_bytes(offset),
            None => (Vec::new(), Vec::new()),
        }
    }
}

impl ToNestedBytes for X509Version {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let version_bytes = match *self {
            X509Version::V1 => vec![0x02, 0x01, 0x00],  // INTEGER 0
            X509Version::V2 => vec![0x02, 0x01, 0x01],  // INTEGER 1
            X509Version::V3 => vec![0x02, 0x01, 0x02],  // INTEGER 2
            _ => panic!("Invalid X509Version"),
        };
        // [0] EXPLICIT wrapper
        let mut tagged = vec![0xA0, version_bytes.len() as u8];
        tagged.extend(version_bytes);
        vec![tagged]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut indices = Vec::new();
        let current_idx = offset;

        // INTEGER tag
        let integer_tag = vec![0x02];
        let integer_data = match *self {
            X509Version::V1 => vec![0x00], // INTEGER 0
            X509Version::V2 => vec![0x01], // INTEGER 1
            X509Version::V3 => vec![0x02], // INTEGER 2
            _ => panic!("Invalid X509Version"),
        };

        // Encode the length for the INTEGER
        let integer_length = encode_der_length(integer_data.len());

        // Combine tag, length, and data for INTEGER
        let integer_der = vec![
            integer_tag.clone(),
            integer_length.clone(),
            integer_data.clone(),
        ];

        // [0] EXPLICIT wrapper tag
        let wrapper_tag = vec![0xA0];

        // Encode the length for the wrapper
        let wrapper_length = encode_der_length(integer_der.len());
        
        // Record INTEGER position
        indices.push(FieldIndex {
            start: current_idx + 4, // wrapper_tag.len() + wrapper_length.len() + integer_tag.len() + integer_length.len() + integer_data.len()
            end: current_idx + 5,
        });

        // Combine tag, length, and data for [0] EXPLICIT
        let mut wrapper = vec![
            wrapper_tag,      // Tag
            wrapper_length,   // Length
        ];
        wrapper.extend(integer_der);
        
        (indices, wrapper)
    }
}

impl ToNestedBytes for X509Name<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        vec![self.as_raw().to_vec()]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();
        let mut current_idx = offset + 2;
        
        // Each RDN is wrapped in SET OF
        for rdn in self.iter() {
            current_idx += 2;
            let mut rdn_content = Vec::new();
            // Each AttributeTypeAndValue is wrapped in SEQUENCE
            for attr in rdn.iter() {
                let (attr_indices, attr_bytes) = attr.to_der_bytes(current_idx);
                //println!("attr_indices {:?}", attr_indices);
                indices.extend(attr_indices);
                current_idx = indices.last().unwrap().end;
                rdn_content.extend(attr_bytes);
            }
            
            // Wrap in SET
            content.push(vec![0x31]); // SET tag
            let rdn_len = rdn_content.iter().map(|v| v.len()).sum();
            content.push(encode_der_length(rdn_len));
            content.extend(rdn_content);
        }
        
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

impl ToNestedBytes for RelativeDistinguishedName<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        unimplemented!()
        // let mut content = Vec::new();
        // let mut indices = Vec::new();
        
        // // Add each AttributeTypeAndValue
        // for attr in self.iter() {
        //     let (attr_idx, attr_bytes) = attr.to_der_bytes(current_idx);
        //     indices.extend(attr_idx);
        //     content.extend(attr_bytes);
        // }
        
        // // Calculate total length
        // let total_length: usize = content.iter().map(|v| v.len()).sum();
        
        // // Create SET OF tag and length
        // let mut der = Vec::new();
        // der.push(vec![0x31]); // SET OF tag
        // der.extend(vec![encode_der_length(total_length)]);
        // der.extend(content);
        // der
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();
        let mut current_idx = offset;
        // Add each AttributeTypeAndValue
        for attr in self.iter() {
            let (attr_idx, attr_bytes) = attr.to_der_bytes(current_idx);
            indices.extend(attr_idx);
            content.extend(attr_bytes);
            current_idx += indices.last().unwrap().end;
        }
        
        // Calculate total length
        let total_length: usize = content.iter().map(|v| v.len()).sum();
        
        // Create SET OF tag and length
        let mut der = Vec::new();
        der.push(vec![0x31]); // SET OF tag
        der.extend(vec![encode_der_length(total_length)]);
        der.extend(content);
        (indices, der)
    }
}

impl ToNestedBytes for AttributeTypeAndValue<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        unimplemented!()
        // let mut content = Vec::new();
        
        // // Add OID
        // let (_, oid_bytes) = self.attr_type().to_der_bytes();
        // content.extend(oid_bytes);
        
        // // Add value
        // let (_, value_bytes) = self.attr_value().to_der_bytes();
        // content.extend(value_bytes);
        
        // // Calculate total length
        // let total_length: usize = content.iter().map(|v| v.len()).sum();

        // // Create SEQUENCE tag and length
        // let mut der = Vec::new();
        // der.push(vec![0x30]); // SEQUENCE tag
        // der.extend(vec![encode_der_length(total_length)]);
        // der.extend(content);
        // der
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();
        // println!("offset attr {:?}", offset);
        // Add OID
        let (oid_indices, oid_bytes) = self.attr_type().to_der_bytes(offset + 2);
        // println!("oid_indices {:?}", oid_indices);
        indices.extend(oid_indices);
        content.extend(oid_bytes);

        // Add value
        let (value_indices, value_bytes) = self.attr_value().to_der_bytes(indices.last().unwrap().end);
        // println!("value_indices {:?}", value_indices);
        indices.extend(value_indices);
        content.extend(value_bytes);
        
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

impl ToNestedBytes for AlgorithmIdentifier<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.extend(self.algorithm.to_bytes());
        if let Some(params) = &self.parameters {
            result.push(params.as_bytes().to_vec());
        }
        result
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();

        // Algorithm OID
        let (oid_indices, oid_bytes) = self.algorithm.to_der_bytes(offset + 2);
        indices.extend(oid_indices);
        content.extend(oid_bytes);

        // Parameters if they exist
        if let Some(params) = &self.parameters {
            let (params_indices, params_bytes) = params.to_der_bytes(indices.last().unwrap().end);
            indices.extend(params_indices);
            content.extend(params_bytes);
        }

        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

impl ToNestedBytes for Validity {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.extend(self.not_before.to_datetime().to_bytes());
        result.extend(self.not_after.to_datetime().to_bytes());
        result    
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();

        // Not Before
        let (not_before_indices, not_before_bytes) = self.not_before.to_der_bytes(offset + 2);
        indices.extend(not_before_indices);
        content.extend(not_before_bytes);

        // Not After
        let (not_after_indices, not_after_bytes) = self.not_after.to_der_bytes(indices.last().unwrap().end);
        indices.extend(not_after_indices);
        content.extend(not_after_bytes);
            
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

const UTC_FORMAT: &[BorrowedFormatItem<'static>] = time::macros::format_description!("[year repr:last_two][month][day][hour][minute][second]Z");
const GEN_FORMAT: &[BorrowedFormatItem<'static>] = time::macros::format_description!("[year][month][day][hour][minute][second]Z");

impl ToNestedBytes for OffsetDateTime {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        // Serialize to ASN.1 GeneralizedTime format
        let formatted = self.format(if self.year() < 2050 { UTC_FORMAT } else { GEN_FORMAT })
            .expect("Failed to format OffsetDateTime");
        vec![formatted.as_bytes().to_vec()]
    }

    fn to_der_bytes(&self, _: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let indices = Vec::new();
        // Serialize to ASN.1 GeneralizedTime format
        let formatted = self.format(if self.year() < 2050 { UTC_FORMAT } else { GEN_FORMAT })
            .expect("Failed to format OffsetDateTime");
        let tag = vec![0x18]; // GeneralizedTime tag
        let value = formatted.as_bytes().to_vec();
        let length = encode_der_length(value.len());
        (indices, vec![tag, length, value])
    }
}

impl ToNestedBytes for SubjectPublicKeyInfo<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.extend(self.algorithm.to_bytes());
        result.push(self.subject_public_key.as_ref().to_vec());
        result
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();
        
        // Algorithm
        let (alg_indices, alg_bytes) = self.algorithm.to_der_bytes(offset + 2);
        indices.extend(alg_indices);
        content.extend(alg_bytes);
        
        // Subject Public Key as BIT STRING
        content.push(vec![0x03]); // BIT STRING tag
        let mut key_bytes = vec![0x00]; // Number of unused bits
        key_bytes.extend(self.subject_public_key.as_ref());
        indices.push(FieldIndex {
            start: indices.last().unwrap().end + 2,
            end: indices.last().unwrap().end + 3,
        });
        content.push(encode_der_length(key_bytes.len()));
        content.push(key_bytes);
        
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

impl ToNestedBytes for UniqueIdentifier<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        vec![self.0.as_ref().to_vec()]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let indices = vec![FieldIndex {
            start: offset,
            end: offset + self.0.as_ref().len(),
        }];
        
        // Create DER encoding
        let tag = vec![0x03]; // BIT STRING tag
        let mut value = vec![0x00]; // Number of unused bits
        value.extend(self.0.as_ref());
        let length = encode_der_length(value.len());
        
        let der = vec![
            tag,
            length,
            value
        ];
        
        (indices, der)
    }
}

impl ToNestedBytes for X509Extension<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        result.extend(self.oid.to_bytes());
        result.push(vec![if self.critical { 0xFF } else { 0x00 }]);
        result.push(self.value.to_vec());
        result
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut content = Vec::new();
        let mut indices = Vec::new();

        // OID
        let (oid_indices, oid_bytes) = self.oid.to_der_bytes(offset + 2);
        indices.extend(oid_indices);
        content.extend(oid_bytes);

        // Critical (BOOLEAN) if true
        if self.critical {
            content.push(vec![0x01]); // BOOLEAN tag
            content.push(vec![0x01]); // Length
            content.push(vec![0xFF]); // TRUE
            indices.push(FieldIndex {
                start: indices.last().unwrap().end,
                end: indices.last().unwrap().end + 3, // tag + length + value
            });
        }
        
        // Value (OCTET STRING)
        content.push(vec![0x04]); // OCTET STRING tag
        let value_len = encode_der_length(self.value.len());
        content.push(value_len.clone());
        content.push(self.value.to_vec());
        indices.push(FieldIndex {
            start: indices.last().unwrap().end,
            end: indices.last().unwrap().end + self.value.len(),
        });
        
        // Wrap in SEQUENCE
        let total_len = content.iter().map(|v| v.len()).sum();
        let mut der = Vec::new();
        der.push(vec![0x30]); // SEQUENCE tag
        der.push(encode_der_length(total_len));
        der.extend(content);
        
        (indices, der)
    }
}

impl ToNestedBytes for Oid<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        vec![self.as_bytes().to_vec()]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let mut indices = Vec::new();
        
        // OID bytes
        let value = self.as_bytes().to_vec();
        let value_len = value.len();
        
        indices.push(FieldIndex {
            start: offset + 2,
            end: offset + 3,
        });
        
        // ASN.1 OBJECT IDENTIFIER tag
        let tag = vec![0x06];
        let length = encode_der_length(value_len);
        
        let der = vec![
            tag,
            length,
            value
        ];
        
        (indices, der)
    }
}

impl ToNestedBytes for ASN1Time {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        let datetime = self.to_datetime();
        
        // Choose tag based on year
        let tag = if datetime.year() < 2050 {
            vec![0x17]  // UTCTime
        } else {
            vec![0x18]  // GeneralizedTime
        };

        let formatted = datetime.format(if datetime.year() < 2050 { UTC_FORMAT } else { GEN_FORMAT }).unwrap();

        let value = formatted.as_bytes().to_vec();
        let length = encode_der_length(value.len());
        
        vec![tag, length, value]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {
        let datetime = self.to_datetime();
        
        // Choose format based on year
        let format = if datetime.year() < 2050 { UTC_FORMAT } else { GEN_FORMAT };
        let formatted = datetime.format(format).unwrap();
        let value = formatted.as_bytes().to_vec();
        
        // Record time value position
        let indices = vec![FieldIndex {
            start: offset + 2,
            end: offset + 3,
        }];
        
        // Create DER encoding
        let tag = if datetime.year() < 2050 { vec![0x17] } else { vec![0x18] };
        let length = encode_der_length(value.len());
        
        let der = vec![
            tag,
            length,
            value
        ];
        
        (indices, der)
    }
}

impl ToNestedBytes for Any<'_> {
    fn to_bytes(&self) -> Vec<Vec<u8>> {
        vec![
            self.tag().0.to_le_bytes().iter().take_while(|&&b| b != 0).copied().collect::<Vec<u8>>(),
            encode_der_length(self.data.len()),
            self.data.to_vec()
        ]
    }

    fn to_der_bytes(&self, offset: usize) -> (Vec<FieldIndex>, Vec<Vec<u8>>) {        
        let indices = vec![FieldIndex {
            start: offset + 2,
            end: offset + 3,
        }];
        
        // Create DER encoding
        let tag = self.tag().0.to_le_bytes().iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let length = encode_der_length(self.data.len());
        
        let der = vec![
            tag,
            length,
            self.data.to_vec()
        ];
        
        (indices, der)
    }
}

impl FromDerParsed for BitString<'static> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        let content = der_bytes_parsed[0].clone();
        let unused_bits = content[0];
        let data = Box::leak(content[1..].to_vec().into_boxed_slice());
        
        BitString::new(unused_bits, data)
    }
}

impl FromDerParsed for Validity {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        let not_before = ASN1Time::from_der_parsed(vec![der_bytes_parsed[0].clone()]);
        let not_after = ASN1Time::from_der_parsed(vec![der_bytes_parsed[1].clone()]);

        Validity {
            not_before,
            not_after
        }
    }
}

impl FromDerParsed for ASN1Time {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        let time_str = String::from_utf8(der_bytes_parsed[0].clone()).unwrap();
        // Parse ASN.1 time format (YYMMDDHHMMSSZ)
        let datetime = if time_str.len() == 13 {
            // UTCTime format
            let year = 2000 + time_str[0..2].parse::<i32>().unwrap();
            let month = time_str[2..4].parse::<u8>().unwrap();
            let day = time_str[4..6].parse::<u8>().unwrap();
            let hour = time_str[6..8].parse::<u8>().unwrap();
            let minute = time_str[8..10].parse::<u8>().unwrap();
            let second = time_str[10..12].parse::<u8>().unwrap();
            
            OffsetDateTime::from_unix_timestamp(
                time::Date::from_calendar_date(year, time::Month::try_from(month).unwrap(), day)
                    .unwrap()
                    .with_hms(hour, minute, second)
                    .unwrap()
                    .assume_utc()
                    .unix_timestamp()
            ).unwrap()
        } else {
            // GeneralizedTime format
            todo!("Implement GeneralizedTime parsing")
        };
        
        ASN1Time::from(datetime)
    }
}

impl FromDerParsed for Vec<X509Extension<'_>> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        println!("der_bytes_parsed xtn {:?}", der_bytes_parsed.len());
        println!("der_bytes_parsed xtn len {:?}", der_bytes_parsed.concat().len());
        // Skip [3] EXPLICIT tag and length
        let mut current_idx = 4; // todo fix thisSkip [3] tag + len + SEQUENCE tag + len
        let mut extensions = Vec::new();
        
        while current_idx < 0 {
            let ext = X509Extension::from_der_parsed(der_bytes_parsed.to_vec());
            extensions.push(ext);
            current_idx += 4;
        }
        
        extensions
    }
}

impl FromDerParsed for AlgorithmIdentifier<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        println!("der_bytes_parsed sig last {:?}", der_bytes_parsed);
        let algorithm = Oid::from_der_parsed(der_bytes_parsed[..1].to_vec());        
        let parameters = if der_bytes_parsed.len() > 1 {
            Some(Any::from_der_parsed(der_bytes_parsed[1..].to_vec()))
        } else {
            None
        };
        
        AlgorithmIdentifier {
            algorithm,
            parameters,
        }
    }
}

impl FromDerParsed for X509Name<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // Store raw bytes
        let raw_box = Box::new(der_bytes_parsed.concat());
        let raw_slice: &[u8] = Box::leak(raw_box);
        
        // Parse RDNs from the sequence
        let mut rdn_seq = Vec::new();
        for rdn_chunk in der_bytes_parsed.chunks(10) {
            let rdn = RelativeDistinguishedName::from_der_parsed(rdn_chunk.to_vec());
            rdn_seq.push(rdn);
        }
        
        X509Name::new(rdn_seq, raw_slice)
    }
}

impl FromDerParsed for RelativeDistinguishedName<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // println!("der_bytes_parsed rdn {:?}", der_bytes_parsed);
        let mut set = Vec::new();
        let offset = 6; // Skip SET tag and length
        for rdn_chunk in der_bytes_parsed.iter().skip(offset).cloned().collect::<Vec<_>>().chunks(4) {
            // println!("rdn_chunk {:?}", rdn_chunk);
            let attr = AttributeTypeAndValue::from_der_parsed(rdn_chunk.to_vec());
            set.push(attr);
        }
        
        RelativeDistinguishedName::new(set)
    }
}

impl FromDerParsed for AttributeTypeAndValue<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        let oid = Oid::from_der_parsed(der_bytes_parsed[..1].to_vec());
        let value = Any::from_der_parsed(der_bytes_parsed[1..].to_vec());
        AttributeTypeAndValue::new(oid, value)
    }
}

impl FromDerParsed for SubjectPublicKeyInfo<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        let content_bytes = &der_bytes_parsed[6..];
        let algorithm = AlgorithmIdentifier::from_der_parsed(content_bytes.to_vec());
        let subject_public_key = BitString::from_der_parsed(content_bytes[6..].to_vec());
        let raw_box = Box::new(der_bytes_parsed.concat());
        let raw_slice: &[u8] = Box::leak(raw_box); // TODO: fix this

        SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
            raw: raw_slice,
        }
    }
}

impl FromDerParsed for UniqueIdentifier<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // Skip the IMPLICIT tag (0x81 for issuer or 0x82 for subject) and length
        let bit_string = BitString::from_der_parsed(der_bytes_parsed.to_vec());
        UniqueIdentifier(bit_string)
    }
}

impl FromDerParsed for X509Version {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // [0] EXPLICIT tag (0xA0) + length
        // Then INTEGER tag (0x02) + length + value
        let version_int = der_bytes_parsed[0][0]; 
        match version_int {
            0 => X509Version::V1,
            1 => X509Version::V2,
            2 => X509Version::V3,
            _ => panic!("Invalid X509 version")
        }
    }
}

impl<T: FromDerParsed> FromDerParsed for Option<T> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        if der_bytes_parsed.is_empty() {
            None
        } else {
            Some(T::from_der_parsed(der_bytes_parsed))
        }
    }
}

impl FromDerParsed for X509Extension<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // Skip SEQUENCE tag and length
        let mut offset = 2;
        
        // Parse OID
        let oid = Oid::from_der_parsed(der_bytes_parsed.to_vec());
        offset += 2;
        
        // Check for optional BOOLEAN (critical)
        let critical = if der_bytes_parsed.clone()[0][1] == 0x01 {
            offset += 3; // Skip BOOLEAN tag, length, and value
            true
        } else {
            false
        };
        
        // Parse OCTET STRING value (skip tag and length)
        let value = Box::leak(der_bytes_parsed[offset].clone().into_boxed_slice());
        
        X509Extension::new(
            oid,
            critical,
            value,
            ParsedExtension::Unparsed
        )
    }
}

impl FromDerParsed for Oid<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // OID is directly encoded in the content after tag and length
        let oid_data = der_bytes_parsed[0].clone();
        Oid::new(Cow::Owned(oid_data))
    }
}

impl FromDerParsed for Any<'_> {
    fn from_der_parsed(der_bytes_parsed: Vec<Vec<u8>>) -> Self {
        // println!("der_bytes_parsed any {:?}", der_bytes_parsed);
        let tag_byte = der_bytes_parsed.clone()[0][0];
        let class = match tag_byte >> 6 { // todo can do matching here
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        };
        let constructed = (tag_byte & 0x20) != 0; // can do matches!(tag, Tag::Sequence | Tag::Set);
        // println!("constructed {:?}", constructed);
        let tag = Tag((tag_byte & 0x1F).into()); //todo can do match here
        let data = Box::leak(der_bytes_parsed[2].clone().into_boxed_slice());
        let data_len = der_bytes_parsed[1][0] as usize;
        
        Any::new(Header::new(class, constructed, tag, data_len.into()), data)
        //Any::from_tag_and_data(tag, data)
    }
}