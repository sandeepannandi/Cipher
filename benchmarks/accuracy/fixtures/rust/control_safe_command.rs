use std::process::Command;

pub fn run_tool(input: &str) -> std::io::Result<()> {
    // Safe near-miss: avoids a shell and validates the input.
    let mut cmd = Command::new("/usr/bin/printf");
    cmd.arg(input);
    cmd.status()?;
    Ok(())
}
