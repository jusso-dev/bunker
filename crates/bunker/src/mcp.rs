use crate::repository::{now, KeySource, Repository};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Read, Write},
    path::Path,
};

fn argument<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key].as_str().with_context(|| format!("missing {key}"))
}
fn public_plan(repo: &Repository, workspace: &Path, args: &Value) -> Result<Value> {
    let plan = repo
        .plan(
            argument(args, "snapshot")?,
            workspace,
            args["file"].as_str(),
        )
        .map_err(|_| anyhow::anyhow!("restore plan unavailable; inspect it locally"))?;
    // Explicit metadata allowlist: future plan fields (including Git refs) must
    // not silently become an MCP plaintext export surface.
    Ok(
        json!({"snapshot":plan.snapshot,"destination":plan.destination,
        "git":plan.git.as_ref().map(|g|json!({"included":true,"ref_count":g.desired_refs.len(),"index_entries":g.index.len(),"stash_entries":g.stash_oldest_first.len(),"imported_objects":g.imported_object_count})),
        "changes":plan.changes.iter().map(|c| json!({"path":c.path,"action":c.action,
            "before_size":c.before_size,"after_size":c.after_size,
            "before_executable":c.before_executable,"after_executable":c.after_executable,
            "requires_rebind":c.requires_rebind})).collect::<Vec<_>>()}),
    )
}
pub fn call(repo: &Repository, workspace: &Path, name: &str, args: &Value) -> Result<Value> {
    match name {
        "list_snapshots" => Ok(json!(repo.list()?.iter().map(|m|json!({"id":m.id,"created_at":m.created_at,"agent":m.agent,"session":m.session,"files":m.files.len()})).collect::<Vec<_>>())),
        "diff" => public_plan(repo, workspace, args),
        "request_restore" => {
            let plan = public_plan(repo, workspace, args)?;
            let id = repo.save_request(&json!({"plan":plan,"file":args["file"].as_str(),"expires_at":now()+900,"status":"pending"}))?;
            Ok(json!({"request_id":id,"status":"pending","expires_in_seconds":900,"message":"Request saved locally. Execution is unavailable without a configured independently authenticated control-plane bridge. No files were changed."}))
        },
        _ => bail!("unknown tool; only list_snapshots, diff and request_restore are available")
    }
}
pub fn serve(
    repo_path: &Path,
    passphrase: &str,
    workspace: &Path,
    input: impl BufRead,
    output: impl Write,
) -> Result<()> {
    serve_with_key_source(
        repo_path,
        &KeySource::passphrase(passphrase),
        workspace,
        input,
        output,
    )
}
pub fn serve_with_key_source(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    input: impl BufRead,
    output: impl Write,
) -> Result<()> {
    serve_with_requester(repo_path, key_source, workspace, input, output, None)
}

pub type RestoreRequester<'a> = dyn FnMut(&Repository, &Path, &Value) -> Result<Value> + 'a;

pub fn serve_with_requester(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    input: impl BufRead,
    mut output: impl Write,
    mut requester: Option<&mut RestoreRequester<'_>>,
) -> Result<()> {
    // MCP stdio uses newline-delimited JSON-RPC. Bound input before JSON parsing.
    let mut input = input;
    loop {
        let mut bytes = vec![];
        let n = Read::take(&mut input, 1024 * 1024 + 1).read_until(b'\n', &mut bytes)?;
        if n == 0 {
            break;
        }
        if bytes.len() > 1024 * 1024 {
            bail!("MCP request exceeds 1 MiB");
        }
        let request: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                writeln!(
                    output,
                    "{}",
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
                )?;
                continue;
            }
        };
        let Some(id) = request.get("id") else {
            continue;
        };
        let result: Result<Value> = match request["method"].as_str() {
            Some("initialize") => Ok(
                json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"bunker","version":env!("CARGO_PKG_VERSION")}}),
            ),
            Some("ping") => Ok(json!({})),
            Some("tools/list") => Ok(json!({"tools":[
                {"name":"list_snapshots","description":"List encrypted repository snapshot metadata","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
                {"name":"diff","description":"Preview metadata, size and executable-mode changes only; content remains local","inputSchema":{"type":"object","properties":{"snapshot":{"type":"string"},"file":{"type":"string"}},"required":["snapshot"],"additionalProperties":false}},
                {"name":"request_restore","description":"Request human approval; never executes a restore","inputSchema":{"type":"object","properties":{"snapshot":{"type":"string"},"file":{"type":"string"}},"required":["snapshot"],"additionalProperties":false}}
            ]})),
            Some("tools/call") => match Repository::open_with_key_source(repo_path, key_source)
                .and_then(|repo| {
                    if request["params"]["name"] == "request_restore" {
                        if let Some(requester) = requester.as_deref_mut() {
                            return requester(&repo, workspace, &request["params"]["arguments"]);
                        }
                    }
                    call(
                        &repo,
                        workspace,
                        request["params"]["name"].as_str().unwrap_or(""),
                        &request["params"]["arguments"],
                    )
                }) {
                Ok(value) => {
                    Ok(json!({"content":[{"type":"text","text":serde_json::to_string(&value)?}]}))
                }
                Err(_) => Ok(
                    json!({"isError":true,"content":[{"type":"text","text":"Operation failed. Inspect the request through the local CLI; private paths, content and identifiers are omitted from MCP errors."}]}),
                ),
            },
            _ => Err(anyhow::anyhow!("Method not found")),
        };
        let response = match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(error) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":error.to_string()}})
            }
        };
        writeln!(output, "{response}")?;
        output.flush()?;
    }
    Ok(())
}
