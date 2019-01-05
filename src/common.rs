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
