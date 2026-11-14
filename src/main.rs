use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use quicscope::eval::{self, primary_metrics};
use quicscope::experiment::{self, Artifacts};
use quicscope::gen::{self, Scenario, DEFAULT_SCALE};
use quicscope::tracker::Spec;
use quicscope::{oracle, protocol, report};

/// Fully offline synthetic benchmark: under partial passive observation of
/// encrypted QUIC traffic, when can a monitor safely associate observations
/// with the same connection, and when should it abstain?
///
/// Every trace is generated from a seed. This program captures nothing,
/// sends nothing, and opens no network interface.
#[derive(Parser)]
#[command(name = "quicscope", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Development run: threshold table on the development seeds, and the
    /// threshold the pre-declared rule selects. Uses no held-out seed.
    Dev(OutArg),
    /// The frozen held-out evaluation plus the exploratory sweeps: writes
    /// every table and figure. Requires a frozen threshold.
    Final(OutArg),
    /// Quick look at one seed (not part of the protocol).
    Run(RunArgs),
    /// Print the synthetic trace for one scenario family.
    Generate(GenerateArgs),
    /// Print one method's decision for every event of one scenario family,
    /// with its score and the oracle's label (includes ground truth).
    Inspect(InspectArgs),
    /// Print the frozen protocol constants.
    Protocol,
    /// List the scenario families, methods, and primary metrics.
    List,
}

#[derive(Args)]
struct OutArg {
    /// Directory to write results into. Created if missing.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum TraceFormat {
    Json,
    Csv,
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// Units (a connection, or a small constructed group) per family.
    #[arg(long, default_value_t = DEFAULT_SCALE)]
    scale: u32,

    /// Only this scenario family (repeatable). See `list`.
    #[arg(long = "scenario", value_name = "NAME")]
    scenarios: Vec<Scenario>,

    /// Only this method (repeatable). See `list`.
    #[arg(long = "tracker", value_name = "NAME")]
    trackers: Vec<String>,

    /// Abstention threshold in thousandths. Defaults to the frozen one.
    #[arg(long, value_name = "PER_MILLE")]
    threshold: Option<u16>,
}

#[derive(Args)]
struct GenerateArgs {
    #[arg(long, value_name = "NAME")]
    scenario: Scenario,

    #[arg(long, default_value_t = 1)]
    seed: u64,

    #[arg(long, default_value_t = DEFAULT_SCALE)]
    scale: u32,

    #[arg(long, value_enum, default_value_t = TraceFormat::Json)]
    format: TraceFormat,

    /// Omit the ground truth: print only what a passive observer could record.
    #[arg(long)]
    observer_view: bool,
}

#[derive(Args)]
struct InspectArgs {
    #[arg(long, value_name = "NAME")]
    scenario: Scenario,

    /// Method to run. See `list`.
    #[arg(long, value_name = "NAME")]
    tracker: String,

    #[arg(long, default_value_t = 1)]
    seed: u64,

    #[arg(long, default_value_t = DEFAULT_SCALE)]
    scale: u32,

    /// Abstention threshold in thousandths. Defaults to the frozen one.
    #[arg(long, value_name = "PER_MILLE")]
    threshold: Option<u16>,
}

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Threshold used when none is given and none is frozen yet.
const UNFROZEN_FALLBACK_PER_MILLE: u16 = 800;

fn threshold(given: Option<u16>) -> u16 {
    given
        .or(protocol::FROZEN_THRESHOLD_PER_MILLE)
        .unwrap_or(UNFROZEN_FALLBACK_PER_MILLE)
}

fn write_all(dir: &Path, artifacts: &Artifacts) -> Result<(), String> {
    for (relative, contents) in &artifacts.files {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        fs::write(&path, contents).map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

fn dev(args: &OutArg) -> CliResult {
    let (_, artifacts) =
        experiment::development_run(&protocol::development_seeds(), protocol::SCALE)?;
    write_all(&args.out, &artifacts)?;
    print!("{}", artifacts.headline);
    println!(
        "wrote {} files to {}",
        artifacts.files.len(),
        args.out.display()
    );
    Ok(())
}

fn final_evaluation(args: &OutArg) -> CliResult {
    let artifacts = experiment::final_evaluation()?;
    write_all(&args.out, &artifacts)?;
    print!("{}", artifacts.headline);
    println!(
        "wrote {} files to {}",
        artifacts.files.len(),
        args.out.display()
    );
    Ok(())
}

fn run(args: &RunArgs) -> CliResult {
    let theta = threshold(args.threshold);
    let specs: Vec<Spec> = if args.trackers.is_empty() {
        Spec::all(theta).to_vec()
    } else {
        args.trackers
            .iter()
            .map(|name| Spec::parse(name, theta))
            .collect::<Result<_, _>>()?
    };
    let scenarios: Vec<Scenario> = Scenario::ALL
        .iter()
        .copied()
        .filter(|s| args.scenarios.is_empty() || args.scenarios.contains(s))
        .collect();
    let rows = experiment::quick_run(args.seed, args.scale, &specs, &scenarios)?;
    println!(
        "quicscope quick look: seed {}, scale {}, {} families, threshold {:.2}. SYNTHETIC TRACES ONLY; not a protocol run.\n",
        args.seed,
        args.scale,
        scenarios.len(),
        f64::from(theta) / 1000.0
    );
    print!("{}", experiment::quick_summary(&rows));
    Ok(())
}

fn generate(args: &GenerateArgs) -> CliResult {
    let trace = gen::generate(args.scenario, args.seed, args.scale);
    let with_truth = !args.observer_view;
    match args.format {
        TraceFormat::Json => print!("{}", report::trace_json(&trace, with_truth)),
        TraceFormat::Csv => print!("{}", report::trace_csv(&trace, with_truth)),
    }
    Ok(())
}

fn inspect(args: &InspectArgs) -> CliResult {
    let trace = gen::generate(args.scenario, args.seed, args.scale);
    let spec = Spec::parse(&args.tracker, threshold(args.threshold))?;
    let mut tracker = spec.build();
    let decisions = eval::run(tracker.as_mut(), &trace);
    let annotations = oracle::annotate(&trace.observations());
    let scored = eval::score(spec.name(), &trace.events, &decisions, &annotations)?;
    print!(
        "{}",
        report::decisions_csv(&trace, &decisions, &scored, &annotations)
    );
    Ok(())
}

fn show_seeds(seeds: &[u64]) -> String {
    match (seeds.first(), seeds.last()) {
        (Some(a), Some(b)) => format!("{a}..={b} ({} seeds)", seeds.len()),
        _ => "none".to_string(),
    }
}

fn print_protocol() -> CliResult {
    println!("protocol version:        {}", protocol::PROTOCOL_VERSION);
    println!(
        "development seeds:       {}",
        show_seeds(&protocol::development_seeds())
    );
    println!(
        "held-out seeds:          {}",
        show_seeds(&protocol::heldout_seeds())
    );
    println!(
        "sweep seeds:             {}",
        show_seeds(&protocol::sweep_seeds())
    );
    println!("scale (units/family):    {}", protocol::SCALE);
    println!("sweep scale:             {}", protocol::SWEEP_SCALE);
    println!("threshold grid:          {:?}", protocol::THRESHOLD_GRID);
    println!(
        "selection rule:          lowest grid threshold with pooled development selective risk <= {}",
        protocol::TARGET_DEV_SELECTIVE_RISK
    );
    match protocol::FROZEN_THRESHOLD_PER_MILLE {
        Some(t) => println!("frozen threshold:        {t} per mille"),
        None => println!("frozen threshold:        NOT FROZEN (run `quicscope dev` first)"),
    }
    println!(
        "bootstrap resamples:     {}",
        quicscope::stats::BOOTSTRAP_RESAMPLES
    );
    Ok(())
}

fn list() -> CliResult {
    println!("Scenario families (synthetic):");
    for scenario in Scenario::ALL {
        println!("  {:<20} {}", scenario.as_str(), scenario.description());
    }
    println!("\nMethods:");
    for spec in Spec::all(threshold(None)) {
        println!("  {:<20} {}", spec.name(), spec.description());
    }
    println!("\nPrimary metrics:");
    for m in primary_metrics() {
        println!(
            "  {}\n      = {}\n      / {}",
            m.label, m.numerator, m.denominator
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Dev(args) => dev(args),
        Command::Final(args) => final_evaluation(args),
        Command::Run(args) => run(args),
        Command::Generate(args) => generate(args),
        Command::Inspect(args) => inspect(args),
        Command::Protocol => print_protocol(),
        Command::List => list(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
