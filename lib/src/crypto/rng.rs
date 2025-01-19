use rand_core::{CryptoRng, OsRng, RngCore};

#[inline]
pub fn get_rng() -> impl RngCore + CryptoRng {
    OsRng
}

#[inline]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut array = [0u8; N];
    get_rng().fill_bytes(&mut array);

    array
}

#[inline]
pub fn random_bytes_vec(size: usize) -> Vec<u8> {
    let mut array = vec![0u8; size];
    get_rng().fill_bytes(&mut array);

    array
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Doesn't check whether the RNG is safe/truly random,
    /// but quickly checks if we didn't do something bad by
    /// giving back zero bytes
    fn sanity_rng_check() {
        let zero_bytes = [0u8; 32];
        let bytes = random_bytes::<32>();
        let other_bytes = random_bytes::<32>();

        assert_ne!(
            bytes, zero_bytes,
            "random_bytes() should never give back zero bytes"
        );
        assert_ne!(
            other_bytes, zero_bytes,
            "random_bytes() should never give back zero bytes"
        );

        assert_ne!(
            bytes, other_bytes,
            "random_bytes() should generate a unique output"
        );
    }
}
