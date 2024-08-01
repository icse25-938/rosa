//! Show the distances between two traces
//!
//! Sometimes it is useful to be able to quickly know the distances (in terms of both edges &
//! syscalls) between two traces; this is what this tool is for.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use clap::Parser;
use colored::Colorize;

use rosa::{distance_metric::DistanceMetric, error::RosaError, trace::Trace};

#[macro_use]
#[allow(unused_macros)]
mod logging;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Calculate distance between two traces.",
    long_about = None,
    propagate_version = true)]
struct Cli {
    /// The first trace.
    trace1_uid: String,

    /// The second trace.
    trace2_uid: String,

    /// The ROSA output directory to pull traces from.
    #[arg(
        short = 'o',
        long = "output-dir",
        default_value = "out/",
        value_name = "DIR"
    )]
    output_dir: PathBuf,

    /// The distance metric to use.
    #[arg(short = 'd', long = "distance-metric", default_value = "hamming")]
    distance_metric: String,

    /// Display all edges and syscalls that differ.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

/// Run the distance calculation tool.
///
/// # Arguments
/// * `output_dir` - Path to the output directory where ROSA's findings are stored.
/// * `trace1_uid` - The unique ID of the first trace.
/// * `trace2_uid` - The unique ID of the second trace.
/// * `distance_metric` - The distance metric to use when calculating distances.
/// * `verbose` - Display fine-grained differences between edges and syscalls.
fn run(
    output_dir: &Path,
    trace1_uid: &str,
    trace2_uid: &str,
    distance_metric: &str,
    verbose: bool,
) -> Result<(), RosaError> {
    let trace1_path = output_dir.join("traces").join(trace1_uid);
    let trace1 = Trace::load("trace1", &trace1_path, &trace1_path.with_extension("trace"))?;

    let trace2_path = output_dir.join("traces").join(trace2_uid);
    let trace2 = Trace::load("trace2", &trace2_path, &trace2_path.with_extension("trace"))?;

    let distance_metric = DistanceMetric::from_str(distance_metric)?;

    let edge_wise_dist = distance_metric.dist(&trace1.edges, &trace2.edges);
    let syscall_wise_dist = distance_metric.dist(&trace1.syscalls, &trace2.syscalls);

    println_info!("Distances between '{}' and '{}':", trace1_uid, trace2_uid);
    println_info!("  Edge-wise: {}", edge_wise_dist);
    println_info!("  Syscall-wise: {}", syscall_wise_dist);

    if verbose {
        println_info!("");
        println_info!("Edges differing:");
        trace1
            .edges
            .into_iter()
            .zip(trace2.edges)
            .enumerate()
            .for_each(|(index, (edge1, edge2))| match edge1 == edge2 {
                false => {
                    println_info!("#{}: {} != {}", index, edge1, edge2);
                }
                true => {}
            });

        println_info!("");
        println_info!("Syscalls differing:");
        trace1
            .syscalls
            .into_iter()
            .zip(trace2.syscalls)
            .enumerate()
            .for_each(|(index, (edge1, edge2))| match edge1 == edge2 {
                false => {
                    println_info!("#{}: {} != {}", index, edge1, edge2);
                }
                true => {}
            });
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(
        &cli.output_dir,
        &cli.trace1_uid,
        &cli.trace2_uid,
        &cli.distance_metric,
        cli.verbose,
    ) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            println_error!(err);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}
