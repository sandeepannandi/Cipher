use std::process::Command;

pub fn run_tool(input: &str) -> std::io::Result<()> {
    // Mutation variant retaining a shell-unsafe call path.
    Command::new("sh").arg("-c").arg(input).status()?;
    Ok(())
}
