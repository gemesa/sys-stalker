#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, map},
    programs::ProbeContext,
    maps::RingBuf,
};
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use uprobe_send_common::Buffer;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(16_777_216u32, 0);

#[uprobe]
pub fn uprobe_send(ctx: ProbeContext) -> u32 {
    match try_uprobe_send(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_send(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;

    let filter_pid: u32 = 334096;

    if pid == filter_pid {
        info!(&ctx, "function send called by libc");
        let len: u32 = ctx.arg(2).ok_or(0u32)?;
        info!(&ctx, "len: {}", len);
    
        match RING_BUF.reserve::<Buffer>(0) {
            Some(mut event) => {
                let len: u32 = ctx.arg(2).ok_or(0u32)?;
                unsafe {
                    (*event.as_mut_ptr()).len = len;
                }
                event.submit(0);
            },
            None => {
                info!(&ctx, "Cannot reserve space in ring buffer.");
            }
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
