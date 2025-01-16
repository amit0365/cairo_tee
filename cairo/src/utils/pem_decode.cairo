use alexandria_encoding::base64::Base64Decoder;

#[derive(Drop)]
struct Pem {
    label: felt252,
    contents: Span<u8>
}

trait PemParserTrait {
    fn parse_pem(raw_bytes: Span<u8>) -> Array<Pem>;
}

impl PemParserImpl of PemParserTrait {
    fn parse_pem(raw_bytes: Span<u8>) -> Array<Pem> {
        let mut result: Array<Pem> = ArrayTrait::new();
        let mut i = 0;
        
        loop {
            if i >= raw_bytes.len() {
                break;
            }

            // Look for "-----BEGIN "
            if is_begin_marker(raw_bytes.slice(i, 11)) {
                let mut j = i + 11;
                
                // Find end of label (until -----")
                while j < raw_bytes.len() && !is_end_label_marker(raw_bytes.slice(j, 5)) {
                    j += 1;
                };
                
                let label = extract_label(raw_bytes.slice(i + 11, j - i - 11));
                
                // Skip to content
                j += 5;
                let content_start = j;
                
                // Find "-----END "
                while j < raw_bytes.len() && !is_end_marker(raw_bytes.slice(j, 9)) {
                    j += 1;
                };
                
                if j < raw_bytes.len() {
                    let content = Base64Decoder::decode(raw_bytes.slice(content_start, j - content_start).into());
                    result.append(Pem { label, contents: content.span() });
                }
                
                i = j;
            }
            
            i += 1;
        };
        
        result
    }
}

// Helper functions
fn is_begin_marker(slice: Span<u8>) -> bool {
    if slice.len() < 11 {
        return false;
    }
    slice.at(0).deref() == '-' 
        && *slice.at(1) == '-'
        && *slice.at(2) == '-'
        && *slice.at(3) == '-'
        && *slice.at(4) == '-'
        && *slice.at(5) == 'B'
        && *slice.at(6) == 'E'
        && *slice.at(7) == 'G'
        && *slice.at(8) == 'I'
        && *slice.at(9) == 'N'
        && *slice.at(10) == ' '
}

fn is_end_marker(slice: Span<u8>) -> bool {
    if slice.len() < 9 {
        return false;
    }
    slice.at(0).deref() == '-'
        && *slice.at(1) == '-'
        && *slice.at(2) == '-'
        && *slice.at(3) == '-'
        && *slice.at(4) == '-'
        && *slice.at(5) == 'E'
        && *slice.at(6) == 'N'
        && *slice.at(7) == 'D'
        && *slice.at(8) == ' '
}

fn is_end_label_marker(slice: Span<u8>) -> bool {
    if slice.len() < 5 {
        return false;
    }
    slice.at(0).deref() == '-'
        && *slice.at(1) == '-'
        && *slice.at(2) == '-'
        && *slice.at(3) == '-'
        && *slice.at(4) == '-'
}

fn extract_label(slice: Span<u8>) -> felt252 {
    // Convert bytes to felt252
    let mut result = 0;
    let mut i = 0;
    loop {
        if i >= slice.len() {
            break;
        }
        result = result * 256 + (*slice.at(i)).into();
        i += 1;
    };
    result
}