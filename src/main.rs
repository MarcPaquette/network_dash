//! NetPulse binary entrypoint: parse args, load config, run the dashboard.

use std::path::PathBuf;

use clap::Parser;
use network_dash::config::Config;

#[derive(Parser, Debug)]
#[command(
    name = "network_dash",
    about = "A colorful terminal network-health dashboard"
)]
struct Cli {
    /// Path to a TOML config file (defaults to the platform config dir).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print the resolved configuration and exit.
    #[arg(long)]
    print_config: bool,

    /// Run each probe once, print a text summary, and exit (no TUI).
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    let path = cli.config.or_else(Config::default_path);
    let config = match &path {
        Some(p) => Config::load_or_default(p)?,
        None => Config::default(),
    };

    if cli.print_config {
        println!("{}", config.to_toml_string()?);
        return Ok(());
    }

    if cli.once {
        return network_dash::event::run_once(config).await;
    }

    network_dash::tui::install_panic_hook();
    network_dash::event::run(config).await
}
