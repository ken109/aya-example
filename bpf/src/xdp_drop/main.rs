#![no_std]
#![no_main]

use core::mem::size_of;

use aya_bpf::{
    macros::{map, xdp},
    programs::XdpContext,
};
use aya_bpf::maps::PerfMap;

use bpf::gen::*;
use bpf::xdp_drop::Event;

#[panic_handler]
fn panic_impl(_: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut EVENTS: PerfMap<Event> = PerfMap::new(0);

#[xdp]
pub fn xdp_drop(ctx: XdpContext) -> u32 {
    let eth = unsafe { &*(ctx.data() as *const ethhdr) };

    let ip_offset = ctx.data() + size_of::<ethhdr>();
    if ip_offset > ctx.data_end() {
        return xdp_action::XDP_PASS;
    }
    let iph = unsafe { &*(ip_offset as *const iphdr) };

    if eth.h_proto != 0x0800 {
        return xdp_action::XDP_PASS;
    }


    let tcp_offset = ip_offset + size_of::<iphdr>();
    if tcp_offset > ctx.data_end() {
        return xdp_action::XDP_PASS;
    }
    let tcph = unsafe { &*(tcp_offset as *const tcphdr) };

    if tcp_offset + size_of::<tcphdr>() > ctx.data_end() {
        return xdp_action::XDP_PASS;
    }

    if tcph.dest == 80 {
        return xdp_action::XDP_DROP;
    }

    unsafe {
        EVENTS.output(&ctx, &Event {
            saddr: iph.saddr,
            daddr: iph.daddr,
            sport: tcph.source,
            dport: tcph.dest,
        }, 0);
    }

    return xdp_action::XDP_PASS;
}
