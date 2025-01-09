    use alexandria_bytes::bytes::{BytesTrait, Bytes};
    // /*
    //  * @dev Returns the 32 byte value at the specified index of self.
    //  * @param self The byte string.
    //  * @param idx The index into the bytes
    //  * @return The specified 32 bytes of the string.
    //  */
    // function readBytes20(bytes memory self, uint256 idx) internal pure returns (bytes20 ret) {
    //     require(idx + 20 <= self.length);
    //     assembly {
    //         ret :=
    //             and(mload(add(add(self, 32), idx)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000)
    //     }
    // }

    // /*
    //  * @dev Returns the n byte value at the specified index of self.
    //  * @param self The byte string.
    //  * @param idx The index into the bytes.
    //  * @param len The number of bytes.
    //  * @return The specified 32 bytes of the string.
    //  */
    // function readBytesN(bytes memory self, uint256 idx, uint256 len) internal pure returns (bytes32 ret) {
    //     require(len <= 32);
    //     require(idx + len <= self.length);
    //     assembly {
    //         let mask := not(sub(exp(256, sub(32, len)), 1))
    //         ret := and(mload(add(add(self, 32), idx)), mask)
    //     }
    // }

    // fn read_nbytes(inputs: Array<u128>, idx: u32, len: u32) -> Array<u8> {
    //     let mut bytes = BytesTrait::new_empty();
    //     bytes.append_u128(inputs);
    //     //assert(inputs == inputs, 'Inputs are not equal');
    //     //let arr = BytesTrait::new(bytes);
    //     assert(len <= 32, 'Length too large');
    //     assert(idx + len <= bytes.len(), 'Index out of bounds');
    //     read_bytes(bytes, idx, len)
    // }


    // function memcpy(uint256 dest, uint256 src, uint256 len) private pure {
    //     // Copy word-length chunks while possible
    //     for (; len >= 32; len -= 32) {
    //         assembly {
    //             mstore(dest, mload(src))
    //         }
    //         dest += 32;
    //         src += 32;
    //     }

    //     // Copy remaining bytes
    //     unchecked {
    //         uint256 mask = (256 ** (32 - len)) - 1;
    //         assembly {
    //             let srcpart := and(mload(src), not(mask))
    //             let destpart := and(mload(dest), mask)
    //             mstore(dest, or(destpart, srcpart))
    //         }
    //     }
    // }

    // /*
    //  * @dev Copies a substring into a new byte string.
    //  * @param self The byte string to copy from.
    //  * @param offset The offset to start copying at.
    //  * @param len The number of bytes to copy.
    //  */
    // function substring(bytes memory self, uint256 offset, uint256 len) internal pure returns (bytes memory) {
    //     require(offset + len <= self.length);

    //     bytes memory ret = new bytes(len);
    //     uint256 dest;
    //     uint256 src;

    //     assembly {
    //         dest := add(ret, 32)
    //         src := add(add(self, 32), offset)
    //     }
    //     memcpy(dest, src, len);

    //     return ret;
    // }

    