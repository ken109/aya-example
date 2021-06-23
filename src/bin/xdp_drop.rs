use std::convert::TryInto;
use std::process;
use std::env;

use aya::Bpf;
use aya::programs::{Xdp, XdpFlags, Link};

use tokio;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        println!("You must be root to use eBPF.");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("You must set interface name.");
        process::exit(1);
    }

    let code = include_bytes!("../../probe/target/bpfel-unknown-none/debug/probe").to_vec();
    let mut bpf = Bpf::load(&code, None)?;

    let xdp_p: &mut Xdp = bpf.program_mut("xdp_drop")?.try_into()?;

    xdp_p.load()?;

    let mut xdp_l = match xdp_p.attach(&args[1], XdpFlags::default()) {
        Ok(link) => link,
        Err(_) => panic!("failed to attach xdp"),
    };

    signal::ctrl_c().await.expect("failed to listen for event");

    xdp_l.detach().expect("failed to detach xdp");

    Ok(())
}
