#![no_std]
#![no_main]

use aya_ebpf::{
    macros::xdp,
    programs::XdpContext,
    bindings::xdp_action,
};

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn traffic_drop(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_DROP
}