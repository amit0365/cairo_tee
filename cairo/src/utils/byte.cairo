/// @dev Leading zeros are ignored and the input must be at most 32 bytes long (both [1] and [0, 1] will be casted to 1)
impl SpanU8TryIntoU256 of TryInto<Span<u8>, u256> {
    fn try_into(mut self: Span<u8>) -> Option<u256> {
        if self.len() < 32 {
            let result: felt252 = self.try_into().unwrap();
            Option::Some(result.into())
        } else if self.len() == 32 {
            let higher_bytes: felt252 = self.slice(0, 31).try_into().unwrap();
            let last_byte = *self.at(31);
            Option::Some((0x100 * higher_bytes.into()) + last_byte.into())
        } else {
            Option::None
        }
    }
}

/// @dev Leading zeros are ignored and the input must be at most 32 bytes long (both [1] and [0, 1] will be casted to 1)
impl SpanU8TryIntoFelt252 of TryInto<Span<u8>, felt252> {
    fn try_into(mut self: Span<u8>) -> Option<felt252> {
        if self.len() < 32 {
            let mut result = 0;
            while let Option::Some(byte) = self
                .pop_front() {
                    let byte = (*byte).into();
                    result = (0x100 * result) + byte;
                };
            Option::Some(result)
        } else if self.len() == 32 {
            let result: u256 = self.try_into()?;
            Option::Some(result.try_into()?)
        } else {
            Option::None
        }
    }
}

// fn u256_to_u8s(word: u256) -> Array<u8> {
//     let (rest, byte_32) = integer::u128_safe_divmod(word.low, 0x100);
//     let (rest, byte_31) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_30) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_29) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_28) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_27) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_26) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_25) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_24) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_23) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_22) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_21) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_20) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_19) = integer::u128_safe_divmod(rest, 0x100);
//     let (byte_17, byte_18) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_16) = integer::u128_safe_divmod(word.high, 0x100);
//     let (rest, byte_15) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_14) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_13) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_12) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_11) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_10) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_9) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_8) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_7) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_6) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_5) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_4) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_3) = integer::u128_safe_divmod(rest, 0x100);
//     let (byte_1, byte_2) = integer::u128_safe_divmod(rest, 0x100);
//     array![
//         byte_1.try_into().unwrap(),
//         byte_2.try_into().unwrap(),
//         byte_3.try_into().unwrap(),
//         byte_4.try_into().unwrap(),
//         byte_5.try_into().unwrap(),
//         byte_6.try_into().unwrap(),
//         byte_7.try_into().unwrap(),
//         byte_8.try_into().unwrap(),
//         byte_9.try_into().unwrap(),
//         byte_10.try_into().unwrap(),
//         byte_11.try_into().unwrap(),
//         byte_12.try_into().unwrap(),
//         byte_13.try_into().unwrap(),
//         byte_14.try_into().unwrap(),
//         byte_15.try_into().unwrap(),
//         byte_16.try_into().unwrap(),
//         byte_17.try_into().unwrap(),
//         byte_18.try_into().unwrap(),
//         byte_19.try_into().unwrap(),
//         byte_20.try_into().unwrap(),
//         byte_21.try_into().unwrap(),
//         byte_22.try_into().unwrap(),
//         byte_23.try_into().unwrap(),
//         byte_24.try_into().unwrap(),
//         byte_25.try_into().unwrap(),
//         byte_26.try_into().unwrap(),
//         byte_27.try_into().unwrap(),
//         byte_28.try_into().unwrap(),
//         byte_29.try_into().unwrap(),
//         byte_30.try_into().unwrap(),
//         byte_31.try_into().unwrap(),
//         byte_32.try_into().unwrap(),
//     ]
// }

// fn u256_to_byte_array(word: u256) -> ByteArray {
//     let (rest, byte_32) = integer::u128_safe_divmod(word.low, 0x100);
//     let (rest, byte_31) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_30) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_29) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_28) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_27) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_26) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_25) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_24) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_23) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_22) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_21) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_20) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_19) = integer::u128_safe_divmod(rest, 0x100);
//     let (byte_17, byte_18) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_16) = integer::u128_safe_divmod(word.high, 0x100);
//     let (rest, byte_15) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_14) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_13) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_12) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_11) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_10) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_9) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_8) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_7) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_6) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_5) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_4) = integer::u128_safe_divmod(rest, 0x100);
//     let (rest, byte_3) = integer::u128_safe_divmod(rest, 0x100);
//     let (byte_1, byte_2) = integer::u128_safe_divmod(rest, 0x100);
//     let mut output: ByteArray = "";
    
//     output.append_byte(byte_1.try_into().unwrap());
//     output.append_byte(byte_2.try_into().unwrap());
//     output.append_byte(byte_3.try_into().unwrap());
//     output.append_byte(byte_4.try_into().unwrap());
//     output.append_byte(byte_5.try_into().unwrap());
//     output.append_byte(byte_6.try_into().unwrap());
//     output.append_byte(byte_7.try_into().unwrap());
//     output.append_byte(byte_8.try_into().unwrap());
//     output.append_byte(byte_9.try_into().unwrap());
//     output.append_byte(byte_10.try_into().unwrap());
//     output.append_byte(byte_11.try_into().unwrap());
//     output.append_byte(byte_12.try_into().unwrap());
//     output.append_byte(byte_13.try_into().unwrap());
//     output.append_byte(byte_14.try_into().unwrap());
//     output.append_byte(byte_15.try_into().unwrap());
//     output.append_byte(byte_16.try_into().unwrap());
//     output.append_byte(byte_17.try_into().unwrap());
//     output.append_byte(byte_18.try_into().unwrap());
//     output.append_byte(byte_19.try_into().unwrap());
//     output.append_byte(byte_20.try_into().unwrap());
//     output.append_byte(byte_21.try_into().unwrap());
//     output.append_byte(byte_22.try_into().unwrap());
//     output.append_byte(byte_23.try_into().unwrap());
//     output.append_byte(byte_24.try_into().unwrap());
//     output.append_byte(byte_25.try_into().unwrap());
//     output.append_byte(byte_26.try_into().unwrap());
//     output.append_byte(byte_27.try_into().unwrap());
//     output.append_byte(byte_28.try_into().unwrap());
//     output.append_byte(byte_29.try_into().unwrap());
//     output.append_byte(byte_30.try_into().unwrap());
//     output.append_byte(byte_31.try_into().unwrap());
//     output.append_byte(byte_32.try_into().unwrap());
    
//     output
// }

#[generate_trait]
impl ByteArrayExt of ByteArrayExtTrait {
    fn into_bytes(self: ByteArray) -> Array<u8> {
        let len = self.len();
        let mut output = array![];
        let mut i = 0;
        while i != len {
            output.append(self[i]);
            i += 1;
        };
        output
    }
}

#[generate_trait]
impl ArrayU8Ext of ArrayU8ExtTrait {
    fn into_byte_array(self: Span<u8>) -> ByteArray {
        let mut output: ByteArray = "";
        let len = self.len();
        let mut i = 0;
        while i != len {
            output.append_byte(*self[i]);
            i += 1;
        };
        output
    }
}

// Accepts felt252 for efficiency as it's the type of retdata but all values are expected to fit u32
fn u32s_to_u256(arr: Span<felt252>) -> u256 {
    assert!(arr.len() == 8, "u32s_to_u256: input must be 8 elements long");
    let low = *arr.at(7)
        + *arr.at(6) * 0x1_0000_0000
        + *arr.at(5) * 0x1_0000_0000_0000_0000
        + *arr.at(4) * 0x1_0000_0000_0000_0000_0000_0000;
    let low = low.try_into().expect('u32s_to_u256:overflow-low');
    let high = *arr.at(3)
        + *arr.at(2) * 0x1_0000_0000
        + *arr.at(1) * 0x1_0000_0000_0000_0000
        + *arr.at(0) * 0x1_0000_0000_0000_0000_0000_0000;
    let high = high.try_into().expect('u32s_to_u256:overflow-high');
    u256 { high, low }
}

fn u32s_typed_to_u256(arr: @[u32; 8]) -> u256 {
    let [arr0, arr1, arr2, arr3, arr4, arr5, arr6, arr7] = arr;
    let arr: Array<felt252> = array![
        (*arr0).into(),
        (*arr1).into(),
        (*arr2).into(),
        (*arr3).into(),
        (*arr4).into(),
        (*arr5).into(),
        (*arr6).into(),
        (*arr7).into(),
    ];
    u32s_to_u256(arr.span())
}

fn u8s_typed_to_u256(arr: @[u8; 32]) -> u256 {
    let [arr0, arr1, arr2, arr3, arr4, arr5, arr6, arr7, arr8, arr9, arr10, arr11, arr12, arr13, arr14, arr15, arr16, arr17, arr18, arr19, arr20, arr21, arr22, arr23, arr24, arr25, arr26, arr27, arr28, arr29, arr30, arr31] = arr;
    let arr: Array<felt252> = array![
        (*arr0).into(),
        (*arr1).into(),
        (*arr2).into(),
        (*arr3).into(),
        (*arr4).into(),
        (*arr5).into(),
        (*arr6).into(),
        (*arr7).into(),
        (*arr8).into(),
        (*arr9).into(),
        (*arr10).into(),
        (*arr11).into(),
        (*arr12).into(),
        (*arr13).into(),
        (*arr14).into(),
        (*arr15).into(),
        (*arr16).into(),
        (*arr17).into(),
        (*arr18).into(),
        (*arr19).into(),
        (*arr20).into(),
        (*arr21).into(),
        (*arr22).into(),
        (*arr23).into(),
        (*arr24).into(),
        (*arr25).into(),
        (*arr26).into(),
        (*arr27).into(),
        (*arr28).into(),
        (*arr29).into(),
        (*arr30).into(),
        (*arr31).into(),
    ];
    u32s_to_u256(arr.span())
}

// Accepts felt252 for efficiency as it's the type of retdata but all values are expected to fit u32
// fn u32s_to_u8s(mut words: Span<felt252>) -> Span<u8> {
//     let mut output = array![];
//     while let Option::Some(word) = words
//         .pop_front() {
//             let word: u32 = (*word).try_into().unwrap();
//             let (rest, byte_4) = integer::u32_safe_divmod(word, 0x100);
//             let (rest, byte_3) = integer::u32_safe_divmod(rest, 0x100);
//             let (byte_1, byte_2) = integer::u32_safe_divmod(rest, 0x100);
//             output.append(byte_1.try_into().unwrap());
//             output.append(byte_2.try_into().unwrap());
//             output.append(byte_3.try_into().unwrap());
//             output.append(byte_4.try_into().unwrap());
//         };
//     output.span()
// }

// fn u32s_to_byte_array(mut words: Span<u32>) -> ByteArray {
//     let mut output: ByteArray = "";
//     while let Option::Some(word) = words
//         .pop_front() {
//             let word: u32 = (*word).try_into().unwrap();
//             let (rest, byte_4) = integer::u32_safe_divmod(word, 0x100);
//             let (rest, byte_3) = integer::u32_safe_divmod(rest, 0x100);
//             let (byte_1, byte_2) = integer::u32_safe_divmod(rest, 0x100);
//             output.append_byte(byte_1.try_into().unwrap());
//             output.append_byte(byte_2.try_into().unwrap());
//             output.append_byte(byte_3.try_into().unwrap());
//             output.append_byte(byte_4.try_into().unwrap());
//         };
//     output
// }

// Takes an array of u8s and returns an array of u32s, padding the end with 0s if necessary
fn u8s_to_u32s_pad_end(mut bytes: Span<u8>) -> Array<u32> {
    let mut output = array![];
    while let Option::Some(byte1) = bytes
        .pop_front() {
            let byte1 = *byte1;
            let byte2 = *bytes.pop_front().unwrap_or_default();
            let byte3 = *bytes.pop_front().unwrap_or_default();
            let byte4 = *bytes.pop_front().unwrap_or_default();
            output.append(0x100_00_00 * byte1.into() + 0x100_00 * byte2.into() + 0x100 * byte3.into() + byte4.into());
        };
    output
}

fn u8s_to_felt252s(mut bytes: Span<u8>) -> Array<felt252> {
    let mut output = array![];
    for i in 0..bytes.len() {
        let bytes: felt252 = (*bytes[i]).try_into().unwrap();
        output.append(bytes);
    };
    output
}

impl SpanU8TryIntoArrayU8Fixed2 of TryInto<Span<u8>, [u8; 2]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 2]> {
        if self.len() == 2 {
            Option::Some([*self.at(0), *self.at(1)])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed16 of TryInto<Span<u8>, [u8; 16]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 16]> {
        if self.len() == 16 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed20 of TryInto<Span<u8>, [u8; 20]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 20]> {
        if self.len() == 20 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed4 of TryInto<Span<u8>, [u8; 4]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 4]> {
        if self.len() == 4 {
            Option::Some([*self.at(0), *self.at(1), *self.at(2), *self.at(3)])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed6 of TryInto<Span<u8>, [u8; 6]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 6]> {
        if self.len() == 6 {
            Option::Some([*self.at(0), *self.at(1), *self.at(2), *self.at(3), *self.at(4), *self.at(5)])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed28 of TryInto<Span<u8>, [u8; 28]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 28]> {
        if self.len() == 28 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed32 of TryInto<Span<u8>, [u8; 32]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 32]> {
        if self.len() == 32 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27),
                *self.at(28), *self.at(29), *self.at(30), *self.at(31)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed48 of TryInto<Span<u8>, [u8; 48]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 48]> {
        if self.len() == 48 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27),
                *self.at(28), *self.at(29), *self.at(30), *self.at(31),
                *self.at(32), *self.at(33), *self.at(34), *self.at(35),
                *self.at(36), *self.at(37), *self.at(38), *self.at(39),
                *self.at(40), *self.at(41), *self.at(42), *self.at(43),
                *self.at(44), *self.at(45), *self.at(46), *self.at(47)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed60 of TryInto<Span<u8>, [u8; 60]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 60]> {
        if self.len() == 60 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27),
                *self.at(28), *self.at(29), *self.at(30), *self.at(31),
                *self.at(32), *self.at(33), *self.at(34), *self.at(35),
                *self.at(36), *self.at(37), *self.at(38), *self.at(39),
                *self.at(40), *self.at(41), *self.at(42), *self.at(43),
                *self.at(44), *self.at(45), *self.at(46), *self.at(47),
                *self.at(48), *self.at(49), *self.at(50), *self.at(51),
                *self.at(52), *self.at(53), *self.at(54), *self.at(55),
                *self.at(56), *self.at(57), *self.at(58), *self.at(59)
            ])
        } else {
            Option::None
        }
    }
}

impl SpanU8TryIntoArrayU8Fixed64 of TryInto<Span<u8>, [u8; 64]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 64]> {
        if self.len() == 64 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27),
                *self.at(28), *self.at(29), *self.at(30), *self.at(31),
                *self.at(32), *self.at(33), *self.at(34), *self.at(35),
                *self.at(36), *self.at(37), *self.at(38), *self.at(39),
                *self.at(40), *self.at(41), *self.at(42), *self.at(43),
                *self.at(44), *self.at(45), *self.at(46), *self.at(47),
                *self.at(48), *self.at(49), *self.at(50), *self.at(51),
                *self.at(52), *self.at(53), *self.at(54), *self.at(55),
                *self.at(56), *self.at(57), *self.at(58), *self.at(59),
                *self.at(60), *self.at(61), *self.at(62), *self.at(63)
            ])
        } else {
            Option::None
        }
    }
}

// impl SpanU8TryIntoU16 of TryInto<Span<u8>, u16> {
//     fn try_into(self: Span<u8>) -> Option<u16> {
//         if self.len() == 2 {
//             let value = ((*self.at(0) as u16) << 8) | (*self.at(1) as u16);
//             Option::Some(value)
//         } else {
//             Option::None
//         }
//     }
// }

impl SpanU8TryIntoArrayU8Fixed96 of TryInto<Span<u8>, [u8; 96]> {
    fn try_into(self: Span<u8>) -> Option<[u8; 96]> {
        if self.len() == 96 {
            Option::Some([
                *self.at(0), *self.at(1), *self.at(2), *self.at(3),
                *self.at(4), *self.at(5), *self.at(6), *self.at(7),
                *self.at(8), *self.at(9), *self.at(10), *self.at(11),
                *self.at(12), *self.at(13), *self.at(14), *self.at(15),
                *self.at(16), *self.at(17), *self.at(18), *self.at(19),
                *self.at(20), *self.at(21), *self.at(22), *self.at(23),
                *self.at(24), *self.at(25), *self.at(26), *self.at(27),
                *self.at(28), *self.at(29), *self.at(30), *self.at(31),
                *self.at(32), *self.at(33), *self.at(34), *self.at(35),
                *self.at(36), *self.at(37), *self.at(38), *self.at(39),
                *self.at(40), *self.at(41), *self.at(42), *self.at(43),
                *self.at(44), *self.at(45), *self.at(46), *self.at(47),
                *self.at(48), *self.at(49), *self.at(50), *self.at(51),
                *self.at(52), *self.at(53), *self.at(54), *self.at(55),
                *self.at(56), *self.at(57), *self.at(58), *self.at(59),
                *self.at(60), *self.at(61), *self.at(62), *self.at(63),
                *self.at(64), *self.at(65), *self.at(66), *self.at(67),
                *self.at(68), *self.at(69), *self.at(70), *self.at(71),
                *self.at(72), *self.at(73), *self.at(74), *self.at(75),
                *self.at(76), *self.at(77), *self.at(78), *self.at(79),
                *self.at(80), *self.at(81), *self.at(82), *self.at(83),
                *self.at(84), *self.at(85), *self.at(86), *self.at(87),
                *self.at(88), *self.at(89), *self.at(90), *self.at(91),
                *self.at(92), *self.at(93), *self.at(94), *self.at(95)
            ])
        } else {
            Option::None
        }
    }
}

pub fn felt252s_to_u8s(arr: Span<felt252>) -> Span<u8> {
    let mut u8s = array![];
    for i in 0..arr.len() {
        let u8: u8 = arr.at(i).deref().try_into().unwrap();
        u8s.append(u8);
    };
    u8s.span()
}

pub fn felt252s_to_u16(arr: Span<felt252>) -> u16 {
    assert!(arr.len() == 2, "felt252s_to_u16: input must be 2 elements long");
    let value = *arr.at(1) + *arr.at(0) * 0x100;
    value.try_into().expect('felt252s_to_u16:overflow')
}

pub fn felt252s_to_u32(arr: Span<felt252>) -> u32 {
    assert!(arr.len() == 4, "felt252s_to_u32: input must be 4 elements long");
    let value = *arr.at(3)
        + *arr.at(2) * 0x100
        + *arr.at(1) * 0x10000
        + *arr.at(0) * 0x1000000;
    value.try_into().expect('felt252s_to_u32:overflow')
}

pub fn felt252s_to_u64(arr: Span<felt252>) -> u64 {
    assert!(arr.len() == 8, "felt252s_to_u64: input must be 8 elements long");
    let value = *arr.at(7)
        + *arr.at(6) * 0x100
        + *arr.at(5) * 0x10000
        + *arr.at(4) * 0x1000000
        + *arr.at(3) * 0x100000000
        + *arr.at(2) * 0x10000000000
        + *arr.at(1) * 0x1000000000000
        + *arr.at(0) * 0x100000000000000;
    value.try_into().expect('felt252s_to_u64:overflow')
}

pub fn u8_to_u16(arr: Span<u8>) -> u16 {
    assert!(arr.len() == 2, "u8_to_u16: input must be 2 elements long");
    let value: u16 = (*arr.at(0)).into() * 0x100_u16 + (*arr.at(1)).into();
    value
}

pub fn u8_to_u32(arr: Span<u8>) -> u32 {
    assert!(arr.len() == 4, "u8_to_u32: input must be 4 elements long");
    let value: u32 = (*arr.at(0)).into() * 0x100_u32 + (*arr.at(1)).into() * 0x100_u32 + (*arr.at(2)).into() * 0x100_u32 + (*arr.at(3)).into();
    value
}

pub fn u8_to_u64(arr: Span<u8>) -> u64 {
    assert!(arr.len() == 8, "u8_to_u64: input must be 8 elements long");
    let value: u64 = (*arr.at(0)).into() * 0x100_u64 + (*arr.at(1)).into() * 0x100_u64 + (*arr.at(2)).into() * 0x100_u64 + (*arr.at(3)).into() * 0x100_u64 + (*arr.at(4)).into() * 0x100_u64 + (*arr.at(5)).into() * 0x100_u64 + (*arr.at(6)).into() * 0x100_u64 + (*arr.at(7)).into();
    value
}