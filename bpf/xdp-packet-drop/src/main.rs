#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};

use core::panic::PanicInfo;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_TYPE_OFFSET: usize = 12;
const IPV4_SRC_OFFSET: usize = ETH_HDR_LEN + 12;
const IPV4_DST_OFFSET: usize = ETH_HDR_LEN + 16;
const IPV4_SRC_LEN: usize = 4;
const DECISION_PASS: u8 = 1;
const DECISION_DROP: u8 = 2;

#[map]
static ALLOWED_SOURCES: HashMap<[u8; 4], u8> = HashMap::with_max_entries(256, 0);

#[map]
static PACKET_LOGS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[repr(C)]
struct PacketLog {
    source: [u8; 4],
    destination: [u8; 4],
    eth_type: u16,
    decision: u8,
    _padding: u8,
    ingress_ifindex: u32,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn traffic_drop(ctx: XdpContext) -> u32 {
    try_traffic_drop(&ctx)
}

fn try_traffic_drop(ctx: &XdpContext) -> u32 {
    let eth_type = match read_u16_be(ctx, ETH_TYPE_OFFSET) {
        Ok(value) => value,
        Err(_) => {
            log_packet(ctx, [0; 4], [0; 4], 0, DECISION_DROP);
            return xdp_action::XDP_DROP;
        }
    };

    if eth_type != ETH_P_IP {
        log_packet(ctx, [0; 4], [0; 4], eth_type, DECISION_PASS);
        return xdp_action::XDP_PASS;
    }

    let source = match read_ipv4(ctx, IPV4_SRC_OFFSET) {
        Ok(value) => value,
        Err(_) => {
            log_packet(ctx, [0; 4], [0; 4], eth_type, DECISION_DROP);
            return xdp_action::XDP_DROP;
        }
    };
    let destination = match read_ipv4(ctx, IPV4_DST_OFFSET) {
        Ok(value) => value,
        Err(_) => {
            log_packet(ctx, source, [0; 4], eth_type, DECISION_DROP);
            return xdp_action::XDP_DROP;
        }
    };

    let source_allowed = unsafe { ALLOWED_SOURCES.get(&source).is_some() };
    let destination_allowed = unsafe { ALLOWED_SOURCES.get(&destination).is_some() };
    if source_allowed && destination_allowed {
        log_packet(ctx, source, destination, eth_type, DECISION_PASS);
        return xdp_action::XDP_PASS;
    }

    log_packet(ctx, source, destination, eth_type, DECISION_DROP);
    xdp_action::XDP_DROP
}

fn read_u16_be(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + offset + 2 > data_end {
        return Err(());
    }

    let ptr = (data + offset) as *const u8;
    Ok(u16::from_be_bytes(unsafe { [*ptr, *ptr.add(1)] }))
}

fn read_ipv4(ctx: &XdpContext, offset: usize) -> Result<[u8; 4], ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + offset + IPV4_SRC_LEN > data_end {
        return Err(());
    }

    let ptr = (data + offset) as *const u8;
    Ok(unsafe { [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)] })
}

fn log_packet(
    ctx: &XdpContext,
    source: [u8; 4],
    destination: [u8; 4],
    eth_type: u16,
    decision: u8,
) {
    let event = PacketLog {
        source,
        destination,
        eth_type,
        decision,
        _padding: 0,
        ingress_ifindex: unsafe { (*ctx.ctx).ingress_ifindex },
    };

    let _ = PACKET_LOGS.output(&event, 0);
}
