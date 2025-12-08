//! Debug utilities for validation
//!
//! Enable with `--features debug`

extern crate alloc;

use crate::types::Fr;

/// Format Fr as hex string
pub fn fr_to_hex(fr: &Fr) -> alloc::string::String {
    use alloc::format;
    let mut s = alloc::string::String::from("0x");
    for byte in fr.iter() {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Debug print for Fr value (only when debug feature enabled)
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! dbg_fr {
    ($name:expr, $fr:expr) => {
        #[cfg(test)]
        {
            extern crate std;
            std::println!("{} = {}", $name, $crate::debug::fr_to_hex($fr));
        }
    };
}

/// Debug print for Fr value (noop when debug feature disabled)
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! dbg_fr {
    ($name:expr, $fr:expr) => {};
}

/// Debug trace macro
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        #[cfg(test)]
        {
            extern crate std;
            std::println!($($arg)*);
        }
    };
}

/// Debug trace macro (noop when debug feature disabled)
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {};
}

/// Format G1 point as hex
pub fn g1_to_hex(g1: &crate::types::G1) -> alloc::string::String {
    use alloc::format;
    let x_hex: alloc::string::String = g1[0..32].iter().map(|b| format!("{:02x}", b)).collect();
    let y_hex: alloc::string::String = g1[32..64].iter().map(|b| format!("{:02x}", b)).collect();
    format!("(0x{}, 0x{})", x_hex, y_hex)
}

/// Debug print for G1 value
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! dbg_g1 {
    ($name:expr, $g1:expr) => {
        #[cfg(test)]
        {
            extern crate std;
            std::println!("{} = {}", $name, $crate::debug::g1_to_hex($g1));
        }
    };
}

/// Debug print for G1 (noop when disabled)
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! dbg_g1 {
    ($name:expr, $g1:expr) => {};
}
