#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    programs::LsmContext,
    maps::RingBuf,
};
use aya_log_ebpf::info;
use aya_ebpf::helpers::gen::bpf_probe_read_user;
use lsm_file_open_common::Buffer;

use aya_ebpf_cty::c_void;

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
    info!(&ctx, "lsm hook file_open called");

    let file: *const vmlinux::file = unsafe { ctx.arg(0) };

    let file_ref = unsafe { &*file };

    let dname = unsafe { (*file_ref.f_path.dentry).d_name };

    let name = dname.name;

    let mut len = unsafe { dname.__bindgen_anon_1.__bindgen_anon_1.len };

    match RING_BUF.reserve::<Buffer>(0) {
        Some(mut event) => {
            unsafe {
                let ptr = event.as_mut_ptr();
                if len > 200 { len = 200 };
                (*ptr).len = len;
                let _ = bpf_probe_read_user((*ptr).data.as_ptr() as *mut c_void, len,  name as *const c_void);
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
