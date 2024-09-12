use aya::maps::RingBuf;
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;

use uprobe_send_common::Buffer;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/uprobe-send"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/uprobe-send"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("uprobe_send").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("send"), 0, "libc", opt.pid)?;

    let mut ring = RingBuf::try_from(bpf.map_mut("RING_BUF").unwrap())?;

    info!("Waiting for Ctrl-C...");

    loop {
        if let Some(item) = ring.next() {
            info!("item: {:?}", &item);
            let buf: &Buffer = unsafe { &*(item.as_ptr() as *const Buffer) };
            info!("item.len: {}", buf.len);

            let len = buf.len as usize;
            if let Ok(str) = std::str::from_utf8(&buf.data[..len]) {
                info!("item.data: {}", str);
            }
            else {
                info!("item.data: invalid utf8");
            }
        }
    }

    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}
