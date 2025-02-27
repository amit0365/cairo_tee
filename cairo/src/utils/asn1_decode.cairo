use integer::{u128_byte_reverse, u256_safe_div_rem, u256_as_non_zero};
use cairo::utils::byte::{read_bytes_n, pow_256};

#[generate_trait]
impl NodePtrImpl of NodePtrTrait {
    // Unpack first byte index
    fn ixs(self: u256) -> u256 {
        self & 0xFFFFFFFFFFFFFFFFFFFF // First 80 bits
    }

    // Unpack first content byte index 
    fn ixf(self: u256) -> u256 {
        (self / 0x100000000000000000000) & 0xFFFFFFFFFFFFFFFFFFFF // Middle 80 bits
    }

    // Unpack last content byte index
    fn ixl(self: u256) -> u256 {
        (self / 0x10000000000000000000000000000000000000000) & 0xFFFFFFFFFFFFFFFFFFFF // Last 80 bits
    }
    
    // Pack 3 u80s into a u256
    fn get_ptr(ixs: u256, ixf: u256, ixl: u256) -> u256 {
        let mut result = ixs;
        result = result | (ixf * 0x100000000000000000000);  // << 80
        result = result | (ixl * 0x10000000000000000000000000000000000000000);  // << 160
        result
    }
}

#[generate_trait]
impl Asn1DecodeImpl of Asn1DecodeTrait {
    // Get the root node. First step in traversing an ASN1 structure
    fn root(self: Span<u8>) -> u256 {
        self.read_node_length(0)
    }

    // Get the root node of an ASN1 structure that's within a bit string value
    fn root_of_bit_string_at(self: Span<u8>, ptr: u256) -> u256 {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) == 0x03, 'Not type BIT STRING');
        self.read_node_length(ptr.ixf() + 1)
    }

    // Get the root node of an ASN1 structure that's within an octet string value
    fn root_of_octet_string_at(self: Span<u8>, ptr: u256) -> u256 {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) == 0x04, 'Not type OCTET STRING');
        self.read_node_length(ptr.ixf())
    }

    // Get the next sibling node
    fn next_sibling_of(self: Span<u8>, ptr: u256) -> u256 {
        self.read_node_length(ptr.ixl() + 1)
    }

    // Get the first child node of the current node
    fn first_child_of(self: Span<u8>, ptr: u256) -> u256 {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) & 0x20 == 0x20, 'Not a constructed type');
        self.read_node_length(ptr.ixf())
    }

    // Extract value of node from DER-encoded structure
    fn bytes_at(self: Span<u8>, ptr: u256) -> Span<u8> {
        let start = ptr.ixf().try_into().unwrap();
        let end = (ptr.ixl() + 1).try_into().unwrap();
        self.slice(start, end - start)
    }

    // Extract entire node from DER-encoded structure
    fn all_bytes_at(self: Span<u8>, ptr: u256) -> Span<u8> {
        let start = ptr.ixs().try_into().unwrap();
        let end = (ptr.ixl() + 1).try_into().unwrap();
        self.slice(start, end - start)
    }

    // Extract value of node from DER-encoded structure as u256
    fn uint_at(self: Span<u8>, ptr: u256) -> u256 {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) == 0x02, 'Not type INTEGER');
        let start = ptr.ixf().try_into().unwrap();
        assert(*self.at(start) & 0x80 == 0, 'Not positive');
        let len = (ptr.ixl() + 1 - ptr.ixf()).try_into().unwrap();
        let mut result = 0;
        let mut i = 0;
        loop {
            if i >= len {
                break;
            }
            result = result * 256 + (*self.at(start + i)).into();
            i += 1;
        };
        result
    }

    // Extract value of a positive integer node from DER-encoded structure
    fn uint_bytes_at(self: Span<u8>, ptr: u256) -> Span<u8> {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) == 0x02, 'Not type INTEGER');
        let start = ptr.ixf().try_into().unwrap();
        assert(*self.at(start) & 0x80 == 0, 'Not positive');
        let value_length = (ptr.ixl() + 1 - ptr.ixf()).try_into().unwrap();
        if *self.at(start) == 0 {
            self.slice(start + 1, value_length - 1)
        } else {
            self.slice(start, value_length)
        }
    }

    // Check if one node is child of another
    fn is_child_of(i: u256, j: u256) -> bool {
        ((i.ixf() <= j.ixs()) && (j.ixl() <= i.ixl())) || ((j.ixf() <= i.ixs()) && (i.ixl() <= j.ixl()))
    }

    // Read the length of an ASN1 node at a given offset
    fn read_node_length(self: Span<u8>, offset: u256) -> u256 {
        let ixs = offset;
        let index = (ixs + 1).try_into().unwrap();
        let length_byte = *self.at(index);
    
        let mut ix_first_content_byte = 0;
        let mut ix_last_content_byte = 0;

        if length_byte & 0x80 == 0 {
            // Short form
            let length = length_byte;
            ix_first_content_byte = ixs + 2;  // ix + 2 in Solidity
            ix_last_content_byte = ix_first_content_byte + length.into() - 1;
        } else {
            // Long form
            let length_bytes = length_byte & 0x7f;
            let mut length: u256 = 0;

            if length_bytes == 1 {
                length = (*self.at((ixs + 2).try_into().unwrap())).try_into().unwrap();
            } else if length_bytes == 2 {
                length = (*self.at((ixs + 2).try_into().unwrap())).try_into().unwrap() * 256 + (*self.at((ixs + 3).try_into().unwrap())).try_into().unwrap();
            } else {
                let denominator = pow_256(((32 - length_bytes) * 8).into());
                length = read_bytes_n(self, ixs + 2, length_bytes) / denominator;
            }

            ix_first_content_byte = ixs + 2 + length_bytes.into();
            ix_last_content_byte = ix_first_content_byte + length - 1;
        };
    
        NodePtrTrait::get_ptr(ixs, ix_first_content_byte, ix_last_content_byte)
    }

    // Extract value of a bit string node from DER-encoded structure
    fn bitstring_at(self: Span<u8>, ptr: u256) -> Span<u8> {
        let index = ptr.ixs().try_into().unwrap();
        assert(*self.at(index) == 0x03, 'Not type BIT STRING');
        let start = ptr.ixf().try_into().unwrap();
        assert(*self.at(start) == 0x00, 'Not 00 padded bitstr');
        let value_length = (ptr.ixl() + 1 - ptr.ixf()).try_into().unwrap();
        self.slice(start + 1, value_length - 1)
    }
}
