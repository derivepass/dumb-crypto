#[macro_export]
macro_rules! wrapping_sum {
    ( $a:expr, $( $x:expr ),* ) => {
        {
            let mut acc = $a;
            $(
                acc = acc.wrapping_add($x);
            )*
            acc
        }
    };
}

#[cfg(test)]
pub fn hex_to_vec(hex: &str) -> Vec<u8> {
    let mut iter = hex.as_bytes().iter().map(|letter| match letter {
        b'0'...b'9' => letter - b'0',
        b'a'...b'f' => letter - b'a' + 10,
        b'A'...b'F' => letter - b'A' + 10,
        _ => panic!(),
    });

    let mut result: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    while let (Some(h), Some(l)) = (iter.next(), iter.next()) {
        result.push((h << 4) | l);
    }
    result
}
