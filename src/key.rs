use const_hex::{FromHex, ToHexExt};
use hashes::sha1;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Error, Formatter},
    str::FromStr,
};

#[cfg(feature = "simd-unstable")]
use std::simd;

use crate::KEY_LEN;

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Returns a random, KEY_LEN long byte string.
    pub fn new() -> Key {
        Key(rand::random())
    }

    /// Returns the hashed Key of data.
    pub fn hash(data: &[u8]) -> Key {
        let hash = sha1::hash(data);
        Key(hash.into_bytes())
    }

    /// XORs two Keys.
    #[cfg(not(feature = "simd-unstable"))]
    pub fn distance(&self, y: &Key) -> Distance {
        let mut result = [0; KEY_LEN];
        for i in 0usize..KEY_LEN {
            result[i] = self.0[i] ^ y.0[i];
        }

        Distance(result)
    }

    // Not sure if it is going to be faster than stable implementation
    #[cfg(feature = "simd-unstable")]
    pub fn distance(&self, y: &Key) -> Distance {
        let mut result: Vec<u8> = Vec::with_capacity(KEY_LEN);

        result.extend(
            self.0
                .chunks(4)
                .zip(y.0.chunks(4))
                .map(|(yours, other)| {
                    let simd1 = simd::Simd::<u8, 4>::from_slice(yours);
                    let simd2 = simd::Simd::<u8, 4>::from_slice(other);

                    let result = simd1 ^ simd2;
                    result.to_array().into_iter()
                })
                .flatten(),
        );

        unsafe { Distance(result.try_into().unwrap_unchecked()) }
    }
}

impl From<[u8; KEY_LEN]> for Key {
    fn from(value: [u8; KEY_LEN]) -> Self {
        Key(value)
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode_hex_upper())
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.encode_hex_with_prefix())
    }
}

impl FromStr for Key {
    type Err = const_hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Key::from_hex(s)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Key {
    type Error = const_hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut key = [0u8; KEY_LEN];
        const_hex::decode_to_slice(hex, &mut key)?;
        Ok(Key(key))
    }
}

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct Distance([u8; KEY_LEN]);

impl Distance {
    #[cfg(target_endian = "big")]
    pub fn zeroes_in_prefix(&self) -> usize {
        let mut zeroes_count = 0;

        for n in self.0 {
            if n == 0 {
                zeroes_count += 8;
                continue;
            }

            zeroes_count += n.trailing_zeros() as usize;

            break;
        }

        zeroes_count
    }

    #[cfg(target_endian = "little")]
    pub fn zeroes_in_prefix(&self) -> usize {
        let mut zeroes_count = 0;

        for n in self.0 {
            if n == 0 {
                zeroes_count += 8;
                continue;
            }

            zeroes_count += n.leading_zeros() as usize;

            break;
        }

        zeroes_count
    }
}

impl Debug for Distance {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for x in self.0.iter() {
            write!(f, "{0:02x}", x)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Distance {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Distance {
    type Error = const_hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut distance = [0u8; KEY_LEN];
        const_hex::decode_to_slice(hex, &mut distance)?;
        Ok(Distance(distance))
    }
}
