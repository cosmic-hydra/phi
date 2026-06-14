//! `phi-node` — a CLI for the persistent single-node Phi devnet.
//!
//! Examples:
//! ```text
//! phi-node init --chain-id 1 --supply 1000000
//! phi-node address alice
//! phi-node fund alice 1000
//! phi-node transfer alice bob 400
//! phi-node balance bob
//! phi-node state
//! ```
//! The chain file path defaults to `./phi-chain.snapshot` and can be
//! overridden with the `PHI_CHAIN` environment variable.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use phi_node::{init_chain, Node, NodeError, TREASURY};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn chain_path() -> PathBuf {
    std::env::var("PHI_CHAIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("phi-chain.snapshot"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn run(args: &[String]) -> Result<(), NodeError> {
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let path = chain_path();
    match cmd {
        "init" => {
            let chain_id = flag(args, "--chain-id").unwrap_or(1);
            let supply = flag(args, "--supply").unwrap_or(1_000_000);
            let node = init_chain(&path, chain_id, supply)?;
            println!("initialized chain {chain_id} at {}", path.display());
            println!("treasury address: {}", Node::address(TREASURY).0);
            println!("treasury funded with {supply} figs");
            println!("state root: {}", node.state_root());
        }
        "address" => {
            let label = positional(args, 1, "address <label>")?;
            println!("{}", Node::address(&label).0);
        }
        "balance" => {
            let label = positional(args, 1, "balance <label>")?;
            let node = Node::load(&path)?;
            println!("{label}: {} figs", node.balance(&label));
        }
        "fund" => {
            let label = positional(args, 1, "fund <label> <amount>")?;
            let amount = amount(args, 2, "fund <label> <amount>")?;
            let mut node = Node::load(&path)?;
            node.fund(&label, amount, now_ms())?;
            node.save(&path)?;
            println!(
                "funded {label} with {amount} figs (block #{}); balance now {}",
                node.height,
                node.balance(&label)
            );
        }
        "transfer" => {
            let from = positional(args, 1, "transfer <from> <to> <amount>")?;
            let to = positional(args, 2, "transfer <from> <to> <amount>")?;
            let amt = amount(args, 3, "transfer <from> <to> <amount>")?;
            let mut node = Node::load(&path)?;
            node.transfer(&from, &to, amt, now_ms())?;
            node.save(&path)?;
            println!(
                "transferred {amt} figs {from} -> {to} (block #{}); {from}={}, {to}={}",
                node.height,
                node.balance(&from),
                node.balance(&to)
            );
        }
        "state" => {
            let node = Node::load(&path)?;
            println!("chain id:   {}", node.chain_id());
            println!("height:     {}", node.height);
            println!("accounts:   {}", node.account_count());
            println!("supply:     {} figs", node.total_supply());
            println!("state root: {}", node.state_root());
        }
        _ => print_help(),
    }
    Ok(())
}

fn positional(args: &[String], i: usize, usage: &str) -> Result<String, NodeError> {
    args.get(i)
        .cloned()
        .ok_or_else(|| NodeError::Usage(format!("usage: phi-node {usage}")))
}

fn amount(args: &[String], i: usize, usage: &str) -> Result<u64, NodeError> {
    positional(args, i, usage)?
        .parse()
        .map_err(|_| NodeError::Usage(format!("usage: phi-node {usage} (amount must be a number)")))
}

/// Parse `--name <u64>` anywhere in `args`.
fn flag(args: &[String], name: &str) -> Option<u64> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1)?.parse().ok()
}

fn print_help() {
    println!(
        "phi-node — persistent single-node Phi devnet\n\n\
         USAGE:\n\
         \x20 phi-node init [--chain-id N] [--supply N]   create a new chain\n\
         \x20 phi-node address <label>                    print an account address\n\
         \x20 phi-node fund <label> <amount>              move figs from treasury to an account\n\
         \x20 phi-node transfer <from> <to> <amount>      move figs between accounts\n\
         \x20 phi-node balance <label>                    show an account balance\n\
         \x20 phi-node state                              show chain head and state root\n\n\
         Chain file: $PHI_CHAIN or ./phi-chain.snapshot"
    );
}
