#![deny(missing_docs)]
#![doc(test(attr(deny(warnings))))]
#![doc = include_str!("../README.md")]

#[macro_use]
pub mod error;

pub mod clustering;
pub mod config;
pub mod criterion;
pub mod decision;
pub mod distance_metric;
pub mod fuzzer;
pub mod oracle;
pub mod trace;
