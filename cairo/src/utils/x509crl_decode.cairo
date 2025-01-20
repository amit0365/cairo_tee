use super::byte::ArrayU8ExtTrait;
use cairo::utils::asn1_decode::{Asn1DecodeTrait, NodePtrTrait};
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
        self.bytes_at(tbs_ptr).parse_serial_number()
    }

    fn get_issuer_common_name(self: Span<u8>) -> Span<u8> {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        let tbs_ptr = self.next_sibling_of(tbs_ptr);
        self.get_common_name(self.first_child_of(tbs_ptr))
    }

    
    fn crl_is_not_expired(self: Span<u8>, current_time: u32) -> bool {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let mut tbs_ptr = self.first_child_of(tbs_parent_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let (validity_not_before, validity_not_after) = self.get_validity(tbs_ptr);
        current_time > validity_not_before && current_time < validity_not_after
    }

    fn serial_number_is_revoked(self: Span<u8>, serial_number: felt252) -> bool {
        let root = self.root();
        let tbs_parent_ptr = self.first_child_of(root);
        let mut tbs_ptr = self.first_child_of(tbs_parent_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let revoked_numbers = self.get_revoked_serial_numbers(tbs_ptr, true, serial_number);
        revoked_numbers.len() == 1 && *revoked_numbers.at(0) == serial_number
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

    fn get_revoked_serial_numbers(
        self: Span<u8>, 
        revoked_parent_ptr: u256, 
        break_if_found: bool, 
        filter: felt252
    ) -> Array<felt252> {
        let CRL_NUMBER_OID: ByteArray = "551d14";
        let mut serial_numbers = ArrayTrait::new();
        let mut revoked_ptr = self.first_child_of(revoked_parent_ptr);

        // Check if it's a CRL extension
        if *self.at(revoked_ptr.ixs().try_into().unwrap()) == 0xA0 {
            let crl_extension_ptr = self.first_child_of(revoked_ptr);
            assert(self.bytes_at(crl_extension_ptr).into_byte_array() == CRL_NUMBER_OID, 'invalid CRL');
        } else {
            // Process revoked certificates
            loop {
                if revoked_ptr.ixl() > revoked_parent_ptr.ixl() {
                    break;
                }

                let serial_ptr = self.first_child_of(revoked_ptr);
                let serial_bytes = self.bytes_at(serial_ptr);
                let serial_number = serial_bytes.parse_serial_number();

                if break_if_found && filter == serial_number {
                    serial_numbers.append(filter);
                    break;
                }

                serial_numbers.append(serial_number);
                revoked_ptr = self.next_sibling_of(revoked_ptr);
            };
        }

        serial_numbers
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

#[derive(Drop, Copy)]
pub struct X509CRLObj {
    tbs: Span<u8>,
    serial_number: felt252,
    issuer_common_name: Span<u8>,
    validity_not_before: u32,
    validity_not_after: u32,
    revoked_serials: Span<felt252>,
    signature: (Span<u8>, Span<u8>), // (r, s)
}

/// x509 CRL generally contain a sequence of elements in the following order:
/// 1. tbs
/// - 1a. serial number
/// - 1b. signature algorithm
/// - 1c. issuer
/// - - 1c(a). common name
/// - - 1c(b). organization name
/// - - 1c(c). locality name
/// - - 1c(d). state or province name
/// - - 1c(e). country name
/// - 1d. not before
/// - 1e. not after
/// - 1f. revoked certificates
/// - - A list consists of revoked serial numbers and reasons.
/// - 1g. CRL extensions
/// - - 1g(a) CRL number
/// - - 1g(b) Authority Key Identifier
/// 2. Signature Algorithm
/// 3. Signature
#[generate_trait]
impl X509CRLDecodeImpl of X509CRLDecodeTrait {
    fn default() -> X509CRLObj {
        X509CRLObj { tbs: array![].span(), serial_number: 0, issuer_common_name: array![].span(), validity_not_before: 0, validity_not_after: 0, revoked_serials: array![].span(), signature: (array![].span(), array![].span()) }
    }

    fn parse_crl_der(self: Span<u8>) -> X509CRLObj {
        let root = self.root();
        println!("root crl: {}", root);
        let tbs_parent_ptr = self.first_child_of(root);
        let tbs = self.all_bytes_at(tbs_parent_ptr);
        println!("tbs crl: {}", tbs.len());
        let mut tbs_ptr = self.first_child_of(tbs_parent_ptr);
        let serial_number = self.bytes_at(tbs_ptr).parse_serial_number();
        println!("serial_number crl: {}", serial_number);
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        
        let issuer_common_name = self.get_common_name(self.first_child_of(tbs_ptr));
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);
        let (validity_not_before, validity_not_after) = self.get_validity(tbs_ptr);
        
        tbs_ptr = self.next_sibling_of(tbs_ptr);        
        tbs_ptr = self.next_sibling_of(tbs_ptr);

        let revoked_serials = self.get_revoked_serial_numbers(tbs_ptr, false, 0).span();
        
        let sig_ptr = self.next_sibling_of(tbs_parent_ptr);
        let sig_ptr = self.next_sibling_of(sig_ptr);
        let signature = self.get_signature(sig_ptr);
        
        X509CRLObj {
            tbs,
            serial_number,
            issuer_common_name,
            validity_not_before,
            validity_not_after,
            revoked_serials,
            signature,
        }
    }
}