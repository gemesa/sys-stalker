#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, map},
    programs::ProbeContext,
    maps::RingBuf,
};
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use uprobe_send_common::Buffer;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(4096u32, 0);

#[uprobe]
pub fn uprobe_send(ctx: ProbeContext) -> u32 {
    match try_uprobe_send(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_send(ctx: ProbeContext) -> Result<u32, u32> {
    let data_ptr: u64 = ctx.arg(1).ok_or(0u32)?;
    let data_ptr = data_ptr as *const u8;

    match RING_BUF.reserve::<Buffer>(0) {
        Some(mut event) => {
            let len: u32 = ctx.arg(2).ok_or(0u32)?;
            unsafe {
                let ptr = event.as_mut_ptr();
                (*ptr).len = len;
                let _ = bpf_probe_read_user_str_bytes(data_ptr, &mut (*ptr).data);
            }
            event.submit(0);
        },
        None => {
            info!(&ctx, "Cannot reserve space in ring buffer.");
        }
    }
    

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
