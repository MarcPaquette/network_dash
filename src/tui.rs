//! Terminal lifecycle: enter/leave the alternate screen + raw mode, and a panic hook that
//! restores the terminal before the process dies so a crash never leaves it wedged.

use std::io::{self, Stdout};

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// The concrete terminal type used by the app.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Enter raw mode + alternate screen and build the terminal.
pub fn init() -> io::Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

/// Leave the alternate screen and disable raw mode. Safe to call more than once.
pub fn restore() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Wrap the current panic hook so the terminal is restored before the panic is reported.
/// Call after `color_eyre::install()` so its reporting hook is the one being wrapped.
pub fn install_panic_hook() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore();
        hook(info);
    }));
}
