impl PartialEqU8Array16 of PartialEq<[u8; 16]> {
    fn eq(lhs: @[u8; 16], rhs: @[u8; 16]) -> bool {
        let mut i = 0;
        loop {
            if i == 16 {
                break true;
            }
            if lhs.deref().span()[i] != rhs.deref().span()[i] {
                break false;
            }
            i += 1;
        }
    }
    fn ne(lhs: @[u8; 16], rhs: @[u8; 16]) -> bool {
        !(lhs == rhs)
    }
}

impl PartialEqU8Array20 of PartialEq<[u8; 20]> {
    fn eq(lhs: @[u8; 20], rhs: @[u8; 20]) -> bool {
        let mut i = 0;
        loop {
            if i == 20 {
                break true;
            }
            if lhs.deref().span()[i] != rhs.deref().span()[i] {
                break false;
            }
            i += 1;
        }
    }
    fn ne(lhs: @[u8; 20], rhs: @[u8; 20]) -> bool {
        !(lhs == rhs)
    }
}