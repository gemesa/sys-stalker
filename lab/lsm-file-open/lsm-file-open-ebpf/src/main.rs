#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::path,
    macros::{lsm, map},
    programs::LsmContext,
    maps::RingBuf,
};
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_d_path;
use lsm_file_open_common::Buffer;

mod vmlinux;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(4096u32, 0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    let path = unsafe { &(*file).f_path as *const _ as *mut path };

    match RING_BUF.reserve::<Buffer>(0) {
        Some(mut event) => {
            let ptr = event.as_mut_ptr();
            unsafe {
                bpf_d_path(path, (*ptr).data.as_mut_ptr() as *mut i8, (*ptr).data.len() as u32);
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
