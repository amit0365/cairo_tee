// use cairo::types::cert::X509CertificateData;
use cairo::utils::asn1_decode::Asn1DecodeTrait;
use cairo::utils::time_decode::TimeDecodeTrait;


#[generate_trait]
impl X509HelperImpl of X509HelperTrait {
    fn get_tbs_and_sig(self: Span<u8>) -> (Span<u8>, (Span<u8>, Span<u8>)) {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let sig_ptr = self.next_sibling_of(tbs_parent_ptr);
        let sig_ptr = self.next_sibling_of(sig_ptr);

        let tbs = self.all_bytes_at(tbs_parent_ptr);
        let sig = self.get_signature(sig_ptr);
        (tbs, sig)
    }

    fn get_serial_number(self: Span<u8>) -> felt252 {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.bytes_at(tbs_ptr).parse_serial_number()
    }

    fn get_issuer_common_name(self: Span<u8>) -> Span<u8> {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.get_common_name(self.first_child_of(tbs_ptr))
    }

    fn get_cert_validity(self: Span<u8>) -> (u32, u32) {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.get_validity(tbs_ptr)
    }

    fn get_subject_common_name(self: Span<u8>) -> Span<u8> {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.get_common_name(self.first_child_of(tbs_ptr))
    }

    fn get_subject_public_key(self: Span<u8>) -> (Span<u8>, Span<u8>) {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.get_subject_pki(self.first_child_of(tbs_ptr))
    }

    fn get_common_name(self: Span<u8>, common_name_parent_ptr: u256) -> Span<u8> {
        let mut common_name_parent_ptr = self.first_child_of(common_name_parent_ptr);
        common_name_parent_ptr = self.first_child_of(common_name_parent_ptr);
        common_name_parent_ptr = self.next_sibling_of(common_name_parent_ptr);
        self.bytes_at(common_name_parent_ptr)
    }

    fn get_validity(self: Span<u8>, validity_ptr: u256) -> (u32, u32) {
        let not_before_ptr = self.first_child_of(validity_ptr);
        let not_after_ptr = self.next_sibling_of(not_before_ptr);
        let not_before = self.bytes_at(not_before_ptr).from_der_to_timestamp();
        let not_after = self.bytes_at(not_after_ptr).from_der_to_timestamp();
        (not_before, not_after)
    }

    fn get_subject_pki(self: Span<u8>, subject_public_key_info_ptr: u256) -> (Span<u8>, Span<u8>) {
        let subject_public_key_info_ptr = self.next_sibling_of(subject_public_key_info_ptr);
        let pub_key = self.bitstring_at(subject_public_key_info_ptr);
        assert(pub_key.len() == 65, 'compressed key not supported');
        (pub_key.slice(0, 32), pub_key.slice(32, 64))
    }

    fn parse_serial_number(self: Span<u8>) -> felt252 {
        let mut result: felt252 = 0;
        let mut i = 0;
        loop {
            if i >= self.len() {
                break;
            }
            result = result * 256 + (*self.at(i)).into();
            i += 1;
        };
        result
    }

    fn get_signature(self: Span<u8>, sig_ptr: u256) -> (Span<u8>, Span<u8>) {
        let sig_ptr = self.root_of_bit_string_at(sig_ptr);
        let sig_ptr = self.first_child_of(sig_ptr);
        let r = self.bytes_at(sig_ptr).trim_bytes(32);
        let sig_ptr = self.next_sibling_of(sig_ptr);
        let s = self.bytes_at(sig_ptr).trim_bytes(32);
        (r, s)
    }


    fn trim_bytes(self: Span<u8>, expected_length: usize) -> Span<u8> {
        let n = self.len();
        if n == expected_length {
            return self;
        }
        if n < expected_length {
            let mut output = array::ArrayTrait::new();
            let pad_length = expected_length - n;
            let mut i = 0;
            loop {
                if i >= pad_length {
                    break;
                }
                output.append(0);
                i += 1;
            };
            let mut i = 0;
            loop {
                if i >= n {
                    break;
                }
                output.append(*self.at(i));
                i += 1;
            };
            output.span()
        } else {
            let length_diff = n - expected_length;
            self.slice(length_diff, expected_length)
        }
    }
}

    // / x509 Certificates generally contain a sequence of elements in the following order:
    // / 1. tbs
    // / - 1a. version
    // / - 1b. serial number
    // / - 1c. siganture algorithm
    // / - 1d. issuer
    // / - - 1d(a). common name
    // / - - 1d(b). organization name
    // / - - 1d(c). locality name
    // / - - 1d(d). state or province name
    // / - - 1d(e). country name
    // / - 1e. validity
    // / - - 1e(a) notBefore
    // / - - 1e(b) notAfter
    // / - 1f. subject
    // / - - contains the same set of elements as 1d
    // / - 1g. subject public key info
    // / - - 1g(a). algorithm
    // / - - 1g(b). subject public key
    // / - 1h. Extensions
    // / 2. Signature Algorithm
    // / 3. Signature
    // function parseX509DER(bytes calldata der) external pure returns (X509CertObj memory cert) {
    //     uint256 root = der.root();

    //     uint256 tbsParentPtr = der.firstChildOf(root);
    //     cert.tbs = der.allBytesAt(tbsParentPtr);

    //     uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

    //     tbsPtr = der.nextSiblingOf(tbsPtr);

    //     cert.serialNumber = _parseSerialNumber(der.bytesAt(tbsPtr));

    //     tbsPtr = der.nextSiblingOf(tbsPtr);
    //     tbsPtr = der.nextSiblingOf(tbsPtr);

    //     cert.issuerCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));

    //     tbsPtr = der.nextSiblingOf(tbsPtr);
    //     (cert.validityNotBefore, cert.validityNotAfter) = _getValidity(der, tbsPtr);

    //     tbsPtr = der.nextSiblingOf(tbsPtr);

    //     cert.subjectCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));

    //     tbsPtr = der.nextSiblingOf(tbsPtr);
    //     cert.subjectPublicKey = _getSubjectPublicKey(der, der.firstChildOf(tbsPtr));

    //     cert.extensionPtr = der.nextSiblingOf(tbsPtr);

    //     // tbs iteration completed
    //     // now we just need to look for the signature

    //     uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
    //     sigPtr = der.nextSiblingOf(sigPtr);
    //     cert.signature = _getSignature(der, sigPtr);
    // }

#[derive(Drop, Copy)]
pub struct X509CertObj {
    tbs: Span<u8>,
    serial_number: felt252,
    issuer_common_name: Span<u8>,
    validity_not_before: u32,
    validity_not_after: u32,
    subject_common_name: Span<u8>,
    subject_public_key: (Span<u8>, Span<u8>),
    signature: (Span<u8>, Span<u8>)  // (r, s)
}

#[generate_trait]
impl X509DecodeImpl of X509DecodeTrait {
    fn parse_x509_der(self: Span<u8>) -> X509CertObj {
        let root = self.root();
        
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs = self.all_bytes_at(tbs_parent_ptr);
        
        let mut tbs_ptr = self.first_child_of(tbs_parent_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        
        let serial_number = self.bytes_at(tbs_ptr).parse_serial_number();
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        
        let issuer_common_name = self.get_common_name(self.first_child_of(tbs_ptr));
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let (validity_not_before, validity_not_after) = self.get_validity(tbs_ptr);
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let subject_common_name = self.get_common_name(self.first_child_of(tbs_ptr));
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let subject_public_key = self.get_subject_pki(self.first_child_of(tbs_ptr));
        
        let sig_ptr = self.next_sibling_of(tbs_parent_ptr);
        let sig_ptr = self.next_sibling_of(sig_ptr);
        let signature = self.get_signature(sig_ptr);
        
        X509CertObj {
            tbs,
            serial_number,
            issuer_common_name,
            validity_not_before,
            validity_not_after,
            subject_common_name,
            subject_public_key,
            signature,
        }
    }
}