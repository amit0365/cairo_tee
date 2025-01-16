use super::asn1_decode::NodePtrTrait;
use super::byte::ArrayU8ExtTrait;
use cairo::utils::asn1_decode::Asn1DecodeTrait;
use cairo::utils::time_decode::TimeDecodeTrait;
use cairo::utils::byte::SpanU8TryIntoArrayU8Fixed16;

const SGX_TCB_CPUSVN_SIZE: u32 = 16;

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

        let (success, pcesvn, cpusvns, fmspc_bytes, pceid_bytes) = self._find_pck_tcb_info(child_ptr.try_into().unwrap(), parent_ptr.try_into().unwrap());
        if !success {
            panic!("invalid SGX extension");
        }

        (pcesvn, cpusvns, fmspc_bytes, pceid_bytes)
    }

    fn _find_pck_tcb_info(self: Span<u8>, ptr: u256, parent_ptr: u256) -> (bool, u16, Span<u8>, Span<u8>, Span<u8>) {
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
                // Found SGX extension
                // Found SGX extension, parse the remaining fields
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
}