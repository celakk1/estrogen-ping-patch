#![allow(non_snake_case)]

fn main() {
    if let Err(error) = checkComponents() {
        eprintln!("Startup preflight failed: {error}");
        std::process::exit(1);
    }
}

fn checkComponents() -> epp_core::AppResult<()> {
    let directory = epp_core::dataDirectory()?;
    epp_core::config::loadConfig(&directory)?;
    let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))?;
    let result: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(format!("Local database failed integrity validation: {result}").into());
    }
    let mut initialized = false;
    let result = epp_core::mcp::handle(
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        &mut initialized,
    )
    .ok_or("MCP initialization returned no response")?;
    if result.get("error").is_some() {
        return Err("MCP initialization failed".into());
    }
    println!("Local storage, configuration, and restricted MCP components are ready.");
    Ok(())
}
