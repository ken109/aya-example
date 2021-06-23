#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext
};

#[panic_handler]
fn panic_impl(_: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[xdp(name = "xdp_drop")]
pub fn xdp_drop(_ctx: XdpContext) -> u32 {
    return xdp_action::XDP_DROP;
}
