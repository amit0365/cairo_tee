
#[test]
fn test_raw_to_nested_bytes() {
    use nested_struct_bytes::ToNestedBytes;
    #[derive(ToNestedBytes, Debug)]
    struct Inner {
        data1: [u8; 4],
        data2: [u8; 4]
    }

    #[derive(ToNestedBytes, Debug)]
    struct Outer {
        field1: [u8; 8],
        inner: Inner,
        field2: [u8; 4]
    }

    let inner = Inner {
        data1: [1, 2, 3, 4],
        data2: [5, 6, 7, 8]
    };
    
    let outer = Outer {
        field1: [10, 11, 12, 13, 14, 15, 16, 17],
        inner,
        field2: [20, 21, 22, 23]
    };

    pub trait ToNestedBytes {
        fn to_bytes(&self) -> Vec<Vec<u8>>;
    }
    
    macro_rules! impl_to_nested_bytes_for_arrays {
        ($($len:expr),*) => {
            $(
                impl ToNestedBytes for [u8; $len] {
                    fn to_bytes(&self) -> Vec<Vec<u8>> {
                        vec![self.to_vec()]
                    }
                }
            )*
        };
    }
    
    impl_to_nested_bytes_for_arrays!(4, 8);
    
    let bytes = outer.to_bytes();
    assert_eq!(bytes, vec![vec![10, 11, 12, 13, 14, 15, 16, 17], vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![20, 21, 22, 23]]);
}
