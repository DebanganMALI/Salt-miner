use clap::{Parser, ValueEnum};
use saltminer_core::{audit, identify};

/// Identify and audit password hashes, offline.
#[derive(Parser)]
#[command(name = "saltminer", version, about)]
struct Cli {
    /// The hash to identify (wrap in single quotes if it contains $).
    hash: String,

    /// Pick your output color.
    #[arg(long, short, value_enum, default_value = "green")]
    color: Color,

    /// Also show the OWASP security audit.
    #[arg(long, short)]
    audit: bool,
}

/// The seven rainbow colors the user can choose from.
#[derive(Copy, Clone, ValueEnum)]
enum Color {
    Red,
    Orange,
    Yellow,
    Green,
    Blue,
    Indigo,
    Violet,
}

impl Color {
    /// The 256-color terminal code for this color.
    fn code(self) -> u8 {
        match self {
            Color::Red => 196,
            Color::Orange => 208,
            Color::Yellow => 220,
            Color::Green => 40,
            Color::Blue => 39,
            Color::Indigo => 63,
            Color::Violet => 135,
        }
    }
}

/// Wrap text in ANSI codes so the terminal prints it in color.
fn paint(text: &str, code: u8) -> String {
    format!("\x1b[38;5;{code}m{text}\x1b[0m")
}

fn main() {
    let cli = Cli::parse();
    let code = cli.color.code();

    let candidates = identify(&cli.hash);

    if candidates.is_empty() {
        eprintln!("{}", paint("No identification possible.", code));
        std::process::exit(1);
    }

    println!(
        "{}",
        paint(&format!("Candidates for: {}", cli.hash.trim()), code)
    );
    for candidate in &candidates {
        let confidence = format!("{:?}", candidate.confidence).to_lowercase();
        let line = format!(
            "  {:<22} {:<8} {}",
            candidate.algorithm, confidence, candidate.reason
        );
        println!("{}", paint(&line, code));
    }

    if cli.audit {
        match audit(&cli.hash) {
            Some(report) => {
                let line = format!(
                    "Audit: {} - {:?} - {}",
                    report.algorithm, report.verdict, report.detail
                );
                println!("\n{}", paint(&line, code));
            }
            None => {
                println!("\n{}", paint("Audit: no rating for this format.", code));
            }
        }
    }
}
