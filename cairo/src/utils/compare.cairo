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

impl PartialEqU8Array28 of PartialEq<[u8; 28]> {
    fn eq(lhs: @[u8; 28], rhs: @[u8; 28]) -> bool {
        let mut i = 0;
        loop {
            if i == 28 {
                break true;
            }
            if lhs.deref().span()[i] != rhs.deref().span()[i] {
                break false;
            }
            i += 1;
        }
    }
}

impl PartialEqU8Array32 of PartialEq<[u8; 32]> {
    fn eq(lhs: @[u8; 32], rhs: @[u8; 32]) -> bool {
        let mut i = 0;
        loop {
            if i == 32 {
                break true;
            }
            if lhs.deref().span()[i] != rhs.deref().span()[i] {
                break false;
            }
            i += 1;
        }
    }
    fn ne(lhs: @[u8; 32], rhs: @[u8; 32]) -> bool {
        !(lhs == rhs)
    }
}

impl PartialEqU8Array60 of PartialEq<[u8; 60]> {
    fn eq(lhs: @[u8; 60], rhs: @[u8; 60]) -> bool {
        lhs == rhs
    }
    fn ne(lhs: @[u8; 60], rhs: @[u8; 60]) -> bool {
        !(lhs == rhs)
    }
}

impl PartialEqU8Array64 of PartialEq<[u8; 64]> {
    fn eq(lhs: @[u8; 64], rhs: @[u8; 64]) -> bool {
        lhs == rhs
    }
    fn ne(lhs: @[u8; 64], rhs: @[u8; 64]) -> bool {
        !(lhs == rhs)
    }
}

impl PartialEqU8Array96 of PartialEq<[u8; 96]> {
    fn eq(lhs: @[u8; 96], rhs: @[u8; 96]) -> bool {
        lhs == rhs
    }
    fn ne(lhs: @[u8; 96], rhs: @[u8; 96]) -> bool {
        !(lhs == rhs)
    }
}