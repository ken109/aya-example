use std::convert::{TryFrom, TryInto};
use std::env;
use std::net;
use std::process;

use aya::{
    Bpf,
    maps::perf::AsyncPerfEventArray,
    programs::{Link, Xdp, XdpFlags},
    util::online_cpus,
};
use bytes::BytesMut;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use tokio::{self, task};

use aya_example::helper;
use bpf::xdp_drop::Event;

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

    let code = include_bytes!("../../target/bpfel-unknown-none/debug/xdp_drop").to_vec();
    let mut bpf = Bpf::load(&code, None)?;

    let xdp_p: &mut Xdp = bpf.program_mut("xdp")?.try_into()?;

    xdp_p.load()?;

    let mut xdp_l = match xdp_p.attach(&args[1], XdpFlags::default()) {
        Ok(link) => link,
        Err(_) => panic!("failed to attach xdp"),
    };

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf
                    .read_events(&mut buffers)
                    .await
                    .expect("failed to read events");

                for i in 0..events.read {
                    let &event = unsafe { helper::from_bytes::<Event>(&buffers[i]) };

                    println!(
                        "{} {} {} {}",
                        net::Ipv4Addr::from(event.saddr.to_be()),
                        event.sport.to_be(),
                        net::Ipv4Addr::from(event.daddr.to_be()),
                        event.dport.to_be(),
                    );
                }
            }
        });
    }

    let _ = Signals::new(&[SIGINT, SIGTERM]).unwrap().wait();

    xdp_l.detach().expect("failed to detach xdp");

    Ok(())
}
