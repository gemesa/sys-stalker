use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
//use tokio::signal;

use kprobe_sendto_common::Buffer;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
        "../../target/bpfel-unknown-none/debug/kprobe-sendto"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kprobe-sendto"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("kprobe_sendto").unwrap().try_into()?;
    program.load()?;
    program.attach("__sys_sendto", 0)?;

    let mut ring = RingBuf::try_from(bpf.map("RING_BUF").unwrap())?;

    info!("Waiting for Ctrl-C...");

    loop {
        if let Some(item) = ring.next() {
            info!("item: {:?}", &item);
            let buf: &Buffer = unsafe { &*(item.as_ptr() as *const Buffer) };
            info!("item.sockfd: {}", buf.sockfd);
            info!("item.len: {}", buf.len);

            let len = buf.len as usize;
            info!("item.data (raw): {:?}", buf.data);
            if let Ok(str) = std::str::from_utf8(&buf.data[..len]) {
                info!("item.data (str): {}", str);
            } else {
                info!("item.data: invalid utf8");
            }
        }
    }

    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}
