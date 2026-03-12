use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

fn main() {
    let _args = Args::parse();
    println!("server-sentinel draft (no-op)");
}
