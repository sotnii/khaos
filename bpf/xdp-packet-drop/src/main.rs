#![no_std]
#![no_main]

use aya_ebpf::{
    macros::xdp,
    programs::XdpContext,
    bindings::xdp_action,
    helpers::bpf_printk,
};

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_hello(_ctx: XdpContext) -> u32 {
    unsafe {
        bpf_printk!(b"hello world from ebpf!\0");
    }

    xdp_action::XDP_PASS
}