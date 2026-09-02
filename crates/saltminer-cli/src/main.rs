use clap::{Parser, ValueEnum};
use saltminer_core::{audit, identify};
use std::io::{self, Write};

const BANNER: &str = r#"
  _____         _   _______ __  __ _____ _   _ ______ _____
 / ____|  /\   | | |__   __|  \/  |_   _| \ | |  ____|  __ \
| (___   /  \  | |    | |  | \  / | | | |  \| | |__  | |__) |
 \___ \ / /\ \ | |    | |  | |\/| | | | | .    |  __| |  _  /
 ____) / ____ \| |____| |  | |  | |_| |_| |\  | |____| | \ \
|_____/_/    \_\______|_|  |_|  |_|_____|_| \_|______|_|  \_\
"#;

/// Identify and audit password hashes, offline.
#[derive(Parser)]
#[command(name = "saltminer", version, about)]
struct Cli {
    /// The hash to identify. Omit it to start interactive mode.
    hash: Option<String>,

    /// Pick your output color.
    #[arg(long, short, value_enum, default_value = "green")]
    color: Color,

    /// Also show the OWASP security audit (one-shot mode).
    #[arg(long, short)]
    audit: bool,
}

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

fn paint(text: &str, code: u8) -> String {
    format!("\x1b[38;5;{code}m{text}\x1b[0m")
}

fn show_candidates(input: &str, code: u8) -> bool {
    let candidates = identify(input);
    if candidates.is_empty() {
        println!("{}", paint("No identification possible.", code));
        return false;
    }
    println!(
        "{}",
        paint(&format!("Candidates for: {}", input.trim()), code)
    );
    for c in &candidates {
        let confidence = format!("{:?}", c.confidence).to_lowercase();
        let line = format!("  {:<22} {:<8} {}", c.algorithm, confidence, c.reason);
        println!("{}", paint(&line, code));
    }
    true
}

fn show_audit(input: &str, code: u8) {
    if let Some(report) = audit(input) {
        let line = format!(
            "Audit: {} - {:?} - {}",
            report.algorithm, report.verdict, report.detail
        );
        println!("{}", paint(&line, code));
    }
}

fn print_help(code: u8) {
    println!("{}", paint("Commands:", code));
    println!("  {:<12} identify and audit a hash", "<hash>");
    println!("  {:<12} show this help", "help");
    println!("  {:<12} clear the screen", "clear");
    println!("  {:<12} exit", "quit");
    println!();
}

fn interactive(code: u8) {
    println!("{}", paint(BANNER, code));
    println!(
        "{}",
        paint("Identify & audit password hashes - offline.", code)
    );
    println!(
        "{}",
        paint(
            "Type a hash and press Enter. No need to quote $ here.\n",
            code
        )
    );
    print_help(code);

    let stdin = io::stdin();
    loop {
        print!("{}", paint("saltminer> ", code));
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            println!();
            break;
        }

        let input = line.trim();
        match input {
            "" => {}
            "quit" | "exit" | "q" => break,
            "help" | "?" => print_help(code),
            "clear" | "cls" => print!("\x1b[2J\x1b[H"),
            _ => {
                println!();
                if show_candidates(input, code) {
                    show_audit(input, code);
                }
                println!();
            }
        }
    }
    println!("{}", paint("Bye.", code));
}

fn main() {
    let cli = Cli::parse();
    let code = cli.color.code();

    match cli.hash {
        Some(hash) => {
            if !show_candidates(&hash, code) {
                std::process::exit(1);
            }
            if cli.audit {
                show_audit(&hash, code);
            }
        }
        None => interactive(code),
    }
}
