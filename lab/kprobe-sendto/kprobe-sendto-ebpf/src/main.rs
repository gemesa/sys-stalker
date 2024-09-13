#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext, maps::RingBuf};
use aya_log_ebpf::info;

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::gen::bpf_probe_read_user;
use kprobe_sendto_common::Buffer;

use aya_ebpf_cty::c_void;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(4096u32, 0);

#[kprobe]
pub fn kprobe_sendto(ctx: ProbeContext) -> u32 {
    match try_kprobe_sendto(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobe_sendto(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;

    let filter_pid: u32 = 443035;

    if pid == filter_pid {
        let sockfd: u32 = ctx.arg(0).ok_or(0u32)?;

        let data_ptr: u64 = ctx.arg(1).ok_or(0u32)?;
        let data_ptr = data_ptr as *const u8;
    
        match RING_BUF.reserve::<Buffer>(0) {
            Some(mut event) => {
                let mut len: u32 = ctx.arg(2).ok_or(0u32)?;
                unsafe {
                    let ptr = event.as_mut_ptr();
                    (*ptr).sockfd = sockfd;
                    if len > 200 { len = 200 };
                    (*ptr).len = len;
                    let _ = bpf_probe_read_user((*ptr).data.as_ptr() as *mut c_void, len,  data_ptr as *const c_void);
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
