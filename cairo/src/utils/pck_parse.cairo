use super::asn1_decode::NodePtrTrait;
use super::byte::ArrayU8ExtTrait;
use cairo::utils::asn1_decode::Asn1DecodeTrait;
use cairo::utils::time_decode::TimeDecodeTrait;
use cairo::utils::byte::SpanU8TryIntoArrayU8Fixed16;
use cairo::utils::x509_decode::{X509CertObj, X509DecodeImpl, };
const SGX_TCB_CPUSVN_SIZE: u32 = 16;

#[derive(Drop, Copy)]
struct PCKCollateral {
    pck_chain: Span<X509CertObj>,
    pck_extension: PCKCertTCB,
}

#[generate_trait]
impl PCKCollateralImpl of PCKCollateralTrait {
    fn new(pck_chain: Span<X509CertObj>, pck_extension: PCKCertTCB) -> PCKCollateral {
        PCKCollateral { pck_chain, pck_extension }
    }

    fn default() -> PCKCollateral {
        let pck_chain = array![X509DecodeImpl::default()].span();
        let pck_extension = PCKCertTCB { pcesvn: 0, cpusvns: array![].span(), fmspc_bytes: array![].span(), pceid_bytes: array![].span() };
        PCKCollateral { pck_chain, pck_extension }
    }
}

#[derive(Drop, Copy)]
struct PCKCertTCB {
    pcesvn: u16,
    cpusvns: Span<u8>,
    fmspc_bytes: Span<u8>,
    pceid_bytes: Span<u8>,
}

#[derive(Copy, Clone)]
struct PCKTCBFlags {
    fmspc_found: bool,
    pceid_found: bool,
    tcb_found: bool,
}

#[generate_trait]
impl PCKHelperImpl of PCKHelperTrait {
    fn parse_pck_extension(self: Span<u8>, extension_ptr: u256) -> (u16, Span<u8>, Span<u8>, Span<u8>) {
        // Check if extension starts with 0xA3
        if *self[extension_ptr.try_into().unwrap()] != 0xA3 {
            panic!("Not an extension");
        }

        let parent_ptr = self.first_child_of(extension_ptr.into());
        let child_ptr = self.first_child_of(parent_ptr);

        let (success, pcesvn, cpusvns, fmspc_bytes, pceid_bytes) = self.find_pck_tcb_info(child_ptr.try_into().unwrap(), parent_ptr.try_into().unwrap());
        if !success {
            panic!("invalid SGX extension");
        }

        (pcesvn, cpusvns, fmspc_bytes, pceid_bytes)
    }

    fn find_pck_tcb_info(self: Span<u8>, ptr: u256, parent_ptr: u256) -> (bool, u16, Span<u8>, Span<u8>, Span<u8>) {
        // Iterate through elements in Extension sequence until SGX Extension OID found
        let mut current_ptr = ptr;
        let mut pcesvn = 0;
        let mut success = false;
        let mut cpusvns = array![].span();
        let mut fmspc_bytes = array![].span(); 
        let mut pceid_bytes = array![].span();
        let mut result = (false, pcesvn, cpusvns, fmspc_bytes, pceid_bytes);

        let sgx_extension_oid_ba: ByteArray = "2A864886F84D010D01";
        let tcb_oid_ba: ByteArray = "2A864886F84D010D0102";
        let pcesvn_oid_ba: ByteArray = "2A864886F84D010D010211";
        let pceid_oid_ba: ByteArray = "2A864886F84D010D0103";
        let fmspc_oid_ba: ByteArray = "2A864886F84D010D0104";

        while current_ptr != 0 {
            let internal_ptr = self.first_child_of(current_ptr.into());
            if *self[internal_ptr.try_into().unwrap()] != 0x06 {
                result = (false, pcesvn, cpusvns, fmspc_bytes, pceid_bytes);
                break;
            }

            if self.bytes_at(internal_ptr).into_byte_array() == sgx_extension_oid_ba {
                let internal_ptr = self.next_sibling_of(internal_ptr.into());
                let extn_value_parent_ptr = self.root_of_octet_string_at(internal_ptr.into());
                let mut extn_value_ptr = self.first_child_of(extn_value_parent_ptr);

                let mut flags = PCKTCBFlags { fmspc_found: false, pceid_found: false, tcb_found: false };

                while !flags.fmspc_found || !flags.pceid_found || !flags.tcb_found {
                    let extn_value_oid_ptr = self.first_child_of(extn_value_ptr.into());
                    let oid_bytes = self.bytes_at(extn_value_oid_ptr);
                    
                    if self.bytes_at(extn_value_oid_ptr.ixs()).into_byte_array() != "0x06" {
                        result = (false, pcesvn, cpusvns, fmspc_bytes, pceid_bytes);
                        break;
                    } else if oid_bytes.into_byte_array() == tcb_oid_ba {
                        let (s, p, c) = self.find_tcb(extn_value_oid_ptr);
                        success = s;
                        pcesvn = p;
                        cpusvns = c.span();
                        flags.tcb_found = true;
                    } else if oid_bytes.into_byte_array() == pceid_oid_ba {
                        let value_ptr = self.next_sibling_of(extn_value_oid_ptr.into());
                        pceid_bytes = self.bytes_at(value_ptr);
                        flags.pceid_found = true;
                    } else if oid_bytes.into_byte_array() == fmspc_oid_ba {
                        let value_ptr = self.next_sibling_of(extn_value_oid_ptr.into());
                        fmspc_bytes = self.bytes_at(value_ptr);
                        flags.fmspc_found = true;
                    }

                    if extn_value_ptr.ixl() < extn_value_parent_ptr.ixl() {
                        extn_value_ptr = self.next_sibling_of(extn_value_ptr.into()).into();
                    } else {
                        break;
                    }
                };

                success = flags.fmspc_found && flags.pceid_found && flags.tcb_found;
                break;
            }

            if current_ptr.ixl() < parent_ptr.ixl() {
                current_ptr = self.next_sibling_of(current_ptr.into()).into();
            } else {
                current_ptr = 0;
            }
        };

        result
    }

    fn find_tcb(self: Span<u8>, oid_ptr: u256) -> (bool, u16, [u8; 16]) {
        // sibling of tcbOid
        let tcb_ptr = self.next_sibling_of(oid_ptr);
        
        // get the first svn object in the sequence
        let mut svn_parent_ptr = self.first_child_of(tcb_ptr);
        let mut cpusvns = array![];
        let mut pcesvn: u16 = 0;
        let mut i: u32 = 0;

        while i < 17 { // 16 cpusvns + 1 pcesvn
            let svn_ptr = self.first_child_of(svn_parent_ptr); // OID
            let svn_value_ptr = self.next_sibling_of(svn_ptr); // value
            let svn_value_bytes = self.bytes_at(svn_value_ptr);
            
            let svn_value = if svn_value_bytes.len() < 2 {
                let svn_value_bytes_u16: u16 = (*svn_value_bytes[0]).into();
                svn_value_bytes_u16
            } else {
                ((*svn_value_bytes[0]).into() * 256_u16) + (*svn_value_bytes[1]).into()
            };

            if self.bytes_at(svn_ptr).into_byte_array() == "PCESVN_OID" {
                // pcesvn is 2 bytes in size
                pcesvn = svn_value.into();
            } else {
                cpusvns.append(svn_value.try_into().unwrap());
            }

            // iterate to the next svn object in the sequence
            svn_parent_ptr = self.next_sibling_of(svn_parent_ptr);
            i += 1;
        };

        (true, pcesvn, cpusvns.span().try_into().unwrap())
    }

    fn get_pck_collateral(self: Span<u8>, cert_type: u16) -> (bool, PCKCollateral) {
        let mut pck_chain = array![];

        if cert_type == 5 {
            let (success, cert_array) = self.split_certificate_chain(3);
            if !success {
                return (false, PCKCollateralImpl::default());
            }

            let (pck, extension) = cert_array[0].deref().parse_pck();
            pck_chain.append(pck);

            let mut issuer_chain = array![];
            for i in 1..cert_array.len() {
                issuer_chain.append(*cert_array[i]);
            };

            let parsed_issuer_chain = issuer_chain.parse_pck_issuer();
            for i in 0..parsed_issuer_chain.len() {
                pck_chain.append(parsed_issuer_chain[i].deref());
            };

            (true, PCKCollateralImpl::new(pck_chain.span(), extension))
        } else {
            (false, PCKCollateralImpl::default())
        }
    }

    fn parse_pck(self: Span<u8>) -> (X509CertObj, PCKCertTCB) {
        let pck = X509DecodeImpl::parse_x509_der(self);
        let (pcesvn, cpusvns, fmspc_bytes, pceid_bytes) = self.parse_pck_extension(pck.extension_ptr);
        
        let extension = PCKCertTCB {
            pcesvn,
            cpusvns,
            fmspc_bytes,
            pceid_bytes
        };

        (pck, extension)
    }

    fn parse_pck_issuer(self: Array<Span<u8>>) -> Array<X509CertObj> {
        let mut chain = array![];
        for i in 0..self.len() {
            let issuer_cert = X509DecodeImpl::parse_x509_der(*self[i]);
            chain.append(issuer_cert);
        };
        chain
    }

    fn split_certificate_chain(self: Span<u8>, size: usize) -> (bool, Array<Span<u8>>) {
        let mut found = false;
        let mut certs = array![];
        let mut input = array![].span();
        let mut index = 0;
        let len = self.len();

        for i in 0..size {
            if i > 0 {
                input = self.slice(index, index + len);
            } else {
                input = self;
            }
            let (success, cert, increment) = self.remove_headers_and_footers(input);
            if !success {
                found = false;
                break;
            }

            // TODO: Base64 decode cert
            certs.append(cert);
            index += increment;
        };

        if !found {
            return (false, certs);
        }

        (true, certs)
    }

    fn remove_headers_and_footers(self: Span<u8>, pem_data: Span<u8>) -> (bool, Span<u8>, u32) {
        let x509_header = array![0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D].span();
        let x509_footer = array![0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D].span();

        let mut begin_pos = 0;
        let mut end_pos = 0;
        let mut header_found = false;
        let mut footer_found = false;

        // Find header position
        let mut i = 0;
        while i < pem_data.len() - x509_header.len() {
            let mut found = true;
            let mut j = 0;
            while j < x509_header.len() {
                if *pem_data[i + j] != *x509_header[j] {
                    found = false;
                    break;
                }
                j += 1;
            };
            if found {
                begin_pos = i;
                header_found = true;
                break;
            }
            i += 1;
        };

        // Find footer position 
        i = begin_pos + x509_header.len();
        while i < pem_data.len() - x509_footer.len() {
            let mut found = true;
            let mut j = 0;
            while j < x509_footer.len() {
                if *pem_data[i + j] != *x509_footer[j] {
                    found = false;
                    break;
                }
                j += 1;
            };
            if found {
                end_pos = i;
                footer_found = true;
                break;
            }
            i += 1;
        };

        if !header_found || !footer_found {
            return (false, array![].span(), 0);
        }

        let content_start = begin_pos + x509_header.len();
        let content = pem_data.slice(content_start, end_pos - content_start);

        // Remove newlines
        let mut filtered = ArrayTrait::new();
        let mut i = 0;
        while i < content.len() {
            if *content[i] != 0x0a {
                filtered.append(*content[i]);
            }
            i += 1;
        };

        (true, filtered.span(), end_pos + x509_footer.len())
    }
}