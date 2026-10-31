use crate::{AppResult, config::Config};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};

pub const MAX_MESSAGE_BYTES: usize = 65_536;

pub fn tools() -> Value {
    json!([{
        "name": "get_current_constraints",
        "description": "Read safety constraints. Does not execute commands or modify the system.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}
    }, {
        "name": "get_candidate_catalog",
        "description": "Read the reviewed candidate catalog and implementation status.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}
    }])
}

pub fn handle(request: Value, initialized: &mut bool) -> Option<Value> {
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let error = |code, message| {
        Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
    };
    if request.get("jsonrpc") != Some(&json!("2.0")) || method.is_empty() {
        return error(-32600, "Invalid JSON-RPC request");
    }
    let result = match method {
        "initialize" => {
            *initialized = true;
            json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": false}}, "serverInfo": {"name": "estrogen-ping-patch", "version": env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        _ if !*initialized => return error(-32002, "Initialize the MCP session first"),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => {
            let params = &request["params"];
            if !params["arguments"].is_null() && params["arguments"] != json!({}) {
                return error(-32602, "This read-only tool accepts no arguments");
            }
            let content = match params["name"].as_str().unwrap_or("") {
                "get_current_constraints" => {
                    json!({"schemaVersion": 1, "modificationsEnabled": false, "arbitraryCommands": false, "aiMode": "disabled", "cloudBudget": 0, "defaultBenchmarkPolicy": Config::default()})
                }
                "get_candidate_catalog" => {
                    json!({"candidates": [], "reason": "No setting mutation is enabled until privileged service, capability checks, rollback, and failure testing are implemented."})
                }
                _ => {
                    return error(
                        -32602,
                        "Unknown or unsupported tool; command execution is never available",
                    );
                }
            };
            json!({"content": [{"type": "text", "text": content.to_string()}], "isError": false})
        }
        _ => return error(-32601, "Method not found"),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

pub fn serve(reader: impl BufRead, mut writer: impl Write) -> AppResult<()> {
    let mut initialized = false;
    let mut bounded = reader.take(u64::MAX);
    loop {
        let mut bytes = Vec::new();
        let length = (&mut bounded)
            .take((MAX_MESSAGE_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if length == 0 {
            return Ok(());
        }
        if length > MAX_MESSAGE_BYTES {
            return Err("MCP message exceeds the 64 KiB limit".into());
        }
        let response = match serde_json::from_slice(&bytes) {
            Ok(request) => handle(request, &mut initialized),
            Err(_) => Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}),
            ),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejectCommandsAndUnexpectedArguments() {
        let mut initialized = true;
        for name in ["execute_command", "propose_experiment", "open_browser"] {
            let response = handle(json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":name,"arguments":{}}}), &mut initialized).unwrap();
            assert_eq!(response["error"]["code"], -32602);
        }
        let response = handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_current_constraints","arguments":{"command":"anything"}}}), &mut initialized).unwrap();
        assert!(response.get("error").is_some());
    }

    #[test]
    fn stdioUsesOnlyNewlineDelimitedJsonAndRequiresInitialization() {
        let mut output = Vec::new();
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n";
        serve(Cursor::new(input), &mut output).unwrap();
        let messages: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["error"]["code"], -32002);
        assert_eq!(messages[2]["result"]["tools"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejectOversizedMessages() {
        assert!(serve(Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES + 1]), Vec::new()).is_err());
    }
}
