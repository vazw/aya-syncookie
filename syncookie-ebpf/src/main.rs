#![no_std]
#![no_main]

use aya_ebpf::maps::HashMap;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::gen::{
        bpf_csum_diff, bpf_ktime_get_ns, bpf_tcp_raw_gen_syncookie_ipv4, bpf_xdp_adjust_tail,
        bpf_xdp_get_buff_len,
    },
    macros::{map, xdp},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const MAX_PACKETS_LEN: usize = EthHdr::LEN + Ipv4Hdr::LEN + 60; // 60 is max TCP header size

const TCP_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN; // Max TCP header size is 60 bytes
const TCPOPT_NOP: u8 = 1;
const TCPOPT_EOL: u8 = 0;
const TCPOPT_MSS: u8 = 2;
const TCPOPT_WINDOW: u8 = 3;
const TCPOPT_SACK_PERM: u8 = 4;
const TCPOPT_TIMESTAMP: u8 = 8;

const TS_OPT_WSCALE_MASK: u32 = 0xf;
const TS_OPT_SACK: u32 = 1 << 4;
const TS_OPT_ECN: u32 = 1 << 5;
const TSMASK: u32 = (1 << 6) - 1;

const TCP_MAX_WSCALE: u8 = 14;

const TCPOLEN_MSS: u8 = 4;
const TCPOLEN_WINDOW: u8 = 3;
const TCPOLEN_SACK_PERM: u8 = 2;
const TCPOLEN_TIMESTAMP: u8 = 10;

// const IPS_CONFIRMED_BIT: u16 = 3;
// const IPS_CONFIRMED: u16 = 1 << IPS_CONFIRMED_BIT;

// const ETH_P_8021Q: u16 = 0x8100; /* 802.1Q VLAN Extended Header  */
// const ETH_P_8021AD: u16 = 0x88A8; /* 802.1ad Service VLAN		*/
// const BPF_F_CURRENT_NETNS: __s32 = -1;

// const DEFAULT_MSS4: u16 = 1460;
// const DEFAULT_MSS6: u16 = 1440;
const DEFAULT_WSCALE: u8 = 7;
const DEFAULT_TTL: u8 = 64;

#[derive(Debug, Clone, Copy, Default)]
struct TcpOptionsContext {
    tsval: u32,
    tsecr: u32,
    wscale: u8,
    sack_perm: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CookieResult {
    pub mss: u16,
    __pading: u16,
    pub seq: u32,
}

// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct nf_conn {}
//status live at bytes 128-136

// ---------------- FUNCTION ----------------------
// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct BpfCtOptsLocal {
//     pub netns_id: __s32,
//     pub error: __s32,
//     pub l4proto: u8,
//     pub dir: u8,
//     pub reserved: [u8; 2],
// }
// const CT_OPTS_LEN: u32 = size_of::<BpfCtOptsLocal>() as u32;
//
// impl BpfCtOptsLocal {
//     fn new_ipv4() -> Self {
//         Self {
//             netns_id: BPF_F_CURRENT_NETNS,
//             error: 0,
//             l4proto: 6, // TCP
//             dir: 0,
//             reserved: [0; 2],
//         }
//     }
// }

// Required ksyms/kfunc support in Aya first
// // #[allow(improper_ctypes)]
// extern "C" {
//     fn bpf_xdp_ct_lookup(
//         ctx: *mut xdp_md,
//         bpf_tuple: *const BpfSockTuple,
//         len_tuple: u32,
//         opts: *const BpfCtOptsLocal, // bpf_ct_opts
//         len_opts: u32,
//     ) -> *mut nf_conn;
//
//     fn bpf_ct_release(nf_conn: *mut nf_conn);
// }
//
/// # Safety
/// You have to bound check to make Ebpf verifier happy
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<(*mut T, &T), u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    let data = (start + offset) as *mut T;
    let data_ = unsafe { data.as_ref().ok_or(xdp_action::XDP_PASS)? };
    Ok((data, data_))
}

#[inline(always)]
pub fn csum_diff<T, U>(src: &T, dst: &U, seed: u32) -> Option<u32> {
    let src = src as *const _ as *mut u32;
    let dst = dst as *const _ as *mut u32;
    match unsafe { bpf_csum_diff(src, size_of::<T>() as u32, dst, size_of::<U>() as u32, seed) } {
        csum @ 0.. => Some(csum as u32),
        _ => None,
    }
}

#[inline(always)]
pub fn csum_fold(mut csum: u32) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline(always)]
pub fn csum_fold_helper(mut sum: u64) -> u16 {
    sum = (sum & 0xffffffff) + (sum >> 32);
    sum = (sum & 0xffffffff) + (sum >> 32);
    csum_fold(sum as u32)
}

#[inline(always)]
fn csum_ipv4_magic(saddr: u32, daddr: u32, len: u16, proto: u8, csum: u64) -> u16 {
    let mut sum: u64 = csum;

    sum += saddr as u64;
    sum += daddr as u64;

    sum += (proto as u64) << 8;
    sum += len as u64;

    csum_fold_helper(sum)
}

// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct BpfSockTuple {
//     pub ipv4: Ipv4Tuple,
// }
//
// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct Ipv4Tuple {
//     pub saddr: u32,
//     pub daddr: u32,
//     pub sport: u16,
//     pub dport: u16,
// }

// #[inline(always)]
// fn tcp_lookup(ctx: &XdpContext, ipv: &Ipv4Hdr, tcp_hdr: &TcpHdr) -> Result<bool, u32> {
//     let ct_opts = BpfCtOptsLocal::new_ipv4();
//     let tup = BpfSockTuple {
//         ipv4: Ipv4Tuple {
//             saddr: ipv.src_addr().to_bits().to_le(),
//             daddr: ipv.dst_addr().to_bits().to_be(),
//             sport: tcp_hdr.source,
//             dport: tcp_hdr.dest,
//         },
//     };
//     let tup_size = size_of::<Ipv4Tuple>() as u32;
//     let ct = unsafe {
//         bpf_xdp_ct_lookup(
//             ctx.ctx,
//             &tup as *const _,
//             tup_size,
//             &ct_opts as *const _,
//             CT_OPTS_LEN,
//         )
//     };
//     if !ct.is_null() {
//         let ct_ptr = ct as usize;
//         let status = (ct_ptr + 128usize) as u64;
//         unsafe { bpf_ct_release(ct) };
//         if status & (IPS_CONFIRMED as u64) != 0 {
//             return Ok(true);
//         }
//     } else if ct_opts.error != -2 {
//         return Err(xdp_action::XDP_ABORTED);
//     }
//     Ok(false)
// }

#[inline(always)]
fn time_get_ms() -> u32 {
    (unsafe { bpf_ktime_get_ns() } / 1_000_000) as u32
}

#[inline(always)]
fn timestamp_cookie(ctx: &XdpContext, tcp_hdr: &TcpHdr) -> TcpOptionsContext {
    let mut options_off = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
    let mut context = TcpOptionsContext {
        tsval: time_get_ms() & !TSMASK,
        wscale: DEFAULT_WSCALE,
        ..Default::default()
    };
    for _ in 0..7 {
        let Ok(option_kind) = (unsafe { ptr_at::<u8>(ctx, options_off) }) else {
            break;
        };
        if *option_kind.1 == TCPOPT_EOL {
            break;
        }
        if *option_kind.1 == TCPOPT_NOP {
            options_off += 1;
            continue;
        }
        let Ok(option_len) = (unsafe { ptr_at::<u8>(ctx, options_off + 1) }) else {
            break;
        };
        if *option_len.1 < 2 {
            break;
        };
        match *option_kind.1 {
            TCPOPT_WINDOW => {
                if *option_len.1 == TCPOLEN_WINDOW {
                    let Ok(wscale) = (unsafe { ptr_at::<u8>(ctx, options_off + 2) }) else {
                        break;
                    };
                    context.wscale = if TCP_MAX_WSCALE > wscale.1.to_le() {
                        *wscale.1
                    } else {
                        TCP_MAX_WSCALE
                    };
                }
            }
            TCPOPT_TIMESTAMP => {
                if *option_len.1 == TCPOLEN_TIMESTAMP {
                    let Ok(tsecr) = (unsafe { ptr_at::<u32>(ctx, options_off + 2) }) else {
                        break;
                    };
                    context.tsecr = *tsecr.1;
                }
            }
            TCPOPT_SACK_PERM => {
                if *option_len.1 == TCPOLEN_SACK_PERM {
                    context.sack_perm = true;
                }
            }
            _ => {}
        }
        options_off += *option_len.1 as usize;
    }
    context.tsval |= (context.wscale as u32) & TS_OPT_WSCALE_MASK;
    if context.sack_perm {
        context.tsval |= TS_OPT_SACK;
    }
    if tcp_hdr.ece() != 0 && tcp_hdr.cwr() != 0 {
        context.tsval |= TS_OPT_ECN;
    }
    context.tsval = context.tsval.to_be();
    context
}

#[inline(always)]
unsafe fn make_tcp_options(
    ctx: &XdpContext,
    start_offset: usize,
    tsecr: u32,
    tsval: u32,
    wscale: u8,
    mss: u16,
) -> u16 {
    let mut curent_offset = start_offset;
    let mut doff = 0;
    let Ok(data_ptr) = ptr_at::<u32>(ctx, curent_offset) else {
        return doff;
    };

    *data_ptr.0 = ((TCPOPT_MSS as u32) << 24 | ((TCPOLEN_MSS as u32) << 16) | (mss as u32)).to_be();
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    if tsecr == 0 {
        return doff;
    }

    let Ok(data_ptr) = ptr_at::<u32>(ctx, curent_offset) else {
        return doff;
    };
    if (tsval & (1u32 << 4).to_be()) != 0 {
        *data_ptr.0 = ((TCPOPT_SACK_PERM as u32) << 24
            | (TCPOLEN_SACK_PERM as u32) << 16
            | (TCPOPT_TIMESTAMP as u32) << 8
            | TCPOLEN_TIMESTAMP as u32)
            .to_be();
    } else {
        *data_ptr.0 = ((TCPOPT_NOP as u32) << 24
            | (TCPOPT_NOP as u32) << 16
            | (TCPOPT_TIMESTAMP as u32) << 8
            | TCPOLEN_TIMESTAMP as u32)
            .to_be();
    }
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    let Ok(data_ptr) = ptr_at::<u32>(ctx, curent_offset) else {
        return doff;
    };
    *data_ptr.0 = tsval;
    curent_offset += mem::size_of::<u32>();
    doff += 1;
    let Ok(data_ptr) = ptr_at::<u32>(ctx, curent_offset) else {
        return doff;
    };
    *data_ptr.0 = tsecr;
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    let Ok(data_ptr) = ptr_at::<u32>(ctx, curent_offset) else {
        return doff;
    };
    if (tsval & 0xfu32.to_be()) != 0xfu32.to_be() {
        *data_ptr.0 = ((TCPOPT_NOP as u32) << 24
            | (TCPOPT_WINDOW as u32) << 16
            | (TCPOLEN_WINDOW as u32) << 8
            | wscale as u32)
            .to_be();
        doff += 1;
    }
    doff
}

// ------------------ MAP -------------------
#[map(name = "CONNECTIONS")]
static CONNECTIONS: HashMap<u32, u32> = HashMap::with_max_entries(65535, 0);

// ---------------- XDP ----------------------
#[xdp]
pub fn syncookie(ctx: XdpContext) -> u32 {
    match try_syncookie(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_syncookie(ctx: XdpContext) -> Result<u32, u32> {
    let (_, ether_ref) = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    let ether_type = ether_ref.ether_type;
    if EtherType::Ipv4 != ether_type {
        return Ok(xdp_action::XDP_PASS);
    }
    let (_, ipv_ref) = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let remote_addr = ipv_ref.src_addr();
    let server_addr = ipv_ref.dst_addr();
    // let packet_len = ipv_ref.total_len();
    let protocal = ipv_ref.proto;
    if IpProto::Tcp.ne(&protocal) {
        return Ok(xdp_action::XDP_PASS);
    }
    let (_, header_ref) = unsafe { ptr_at::<TcpHdr>(&ctx, TCP_OFFSET)? };
    let tcp_flag: u8 = header_ref._bitfield_1.get(8, 6u8) as u8;
    let remote_port = u16::from_be(header_ref.source);
    let server_port = u16::from_be(header_ref.dest);
    if let Some(connected) = unsafe { CONNECTIONS.get(&remote_addr.to_bits()) } {
        if *connected != 0 {
            info!(
                &ctx,
                "PASS CT_TCP host:{:i}:{} <-- remote:{:i}:{}",
                server_addr,
                server_port,
                remote_addr,
                remote_port,
            );
            Ok(xdp_action::XDP_PASS)
        } else {
            info!(
                &ctx,
                "DROP host:{:i}:{} <-- remote:{:i}:{}",
                server_addr,
                server_port,
                remote_addr,
                remote_port,
            );
            Err(xdp_action::XDP_DROP)
        }
    } else if 2.eq(&tcp_flag) {
        // tcp_len = doff() x 4
        // tcp_off = EthHdr::LEN + Ipv4Hdr::LEN
        let current_xdp_len = unsafe { bpf_xdp_get_buff_len(ctx.ctx) } - TCP_OFFSET as u64;
        let header_len = (header_ref.doff() * 4) as u32;
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, 60i32 - current_xdp_len as i32) };
        if 0.ne(&ret) {
            info!(&ctx, "Cannot Adjust_Tail");
            return Err(xdp_action::XDP_ABORTED);
        }
        let start = ctx.data();
        let end = ctx.data_end();
        if start + MAX_PACKETS_LEN > end {
            info!(
                &ctx,
                "Packet too short for max TCP options after adjust_tail"
            );
            return Err(xdp_action::XDP_ABORTED);
        }

        let _ = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
        let (ipv, _) = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
        let (header, header_ref) = unsafe { ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
        let raw_cookie = unsafe {
            bpf_tcp_raw_gen_syncookie_ipv4(
                ipv as *mut _,
                header as *mut _,
                header_len, // (header.doff() * 4) as u32,
            )
        } as i64;
        // On failure, the returned value is one of the following:
        // -EINVAL if th_len is invalid. (OS error: 22)
        if raw_cookie < 0 {
            info!(&ctx, "raw_cookie {}", raw_cookie);
            return Err(xdp_action::XDP_ABORTED);
        };
        let cookie = unsafe { mem::transmute::<i64, CookieResult>(raw_cookie) };
        info!(
            &ctx,
            "cookie seq:{} mss:{}", cookie.seq, cookie.mss, cookie._pad
        );
        let tcp_options = timestamp_cookie(&ctx, header_ref);

        unsafe {
            let doff = make_tcp_options(
                &ctx,
                TCP_OFFSET + TcpHdr::LEN,
                tcp_options.tsecr,
                tcp_options.tsval,
                tcp_options.wscale,
                cookie.mss,
            );
            (*header).set_doff(5 + doff);
            let tcp_len = (*header).doff() * 4;
            if tcp_len > 60 {
                return Err(xdp_action::XDP_ABORTED);
            }

            let new_len = (size_of::<Ipv4Hdr>() as u16) + tcp_len;

            let (ether, _) = ptr_at::<EthHdr>(&ctx, 0)?;
            let (ipv, _) = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
            let (header, _) = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            mem::swap(&mut (*ether).src_addr, &mut (*ether).dst_addr);
            mem::swap(&mut (*ipv).src_addr, &mut (*ipv).dst_addr);
            mem::swap(&mut (*header).source, &mut (*header).dest);
            (*ipv).set_total_len(new_len);
            (*ipv).ttl = DEFAULT_TTL.to_be();
            (*ipv).tos = 0;
            (*ipv).set_id(0);
            (*ipv).set_checksum(0);

            // set syn-ack
            (*header)._bitfield_1.set(8, 6u8, 18);
            if tcp_options.tsecr != 0 && (tcp_options.tsval & (1u32 << 5).to_be() != 0) {
                (*header).set_ece(1);
            }
            (*header).ack_seq = (u32::from_be((*header).seq) + 1).to_be();
            (*header).seq = cookie.seq.to_be();
            (*header).window = 65160u16.to_be();
            (*header).urg_ptr = 0;
            (*header).check = 0;

            let full_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                ipv as *mut u32,
                Ipv4Hdr::LEN as u32,
                0,
            ) as u64;
            (*ipv).check = csum_fold_helper(full_sum).to_le_bytes();

            if ctx.data() + TCP_OFFSET + tcp_len as usize > ctx.data_end() {
                return Err(xdp_action::XDP_ABORTED);
            }
            let tcp_header_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                (ctx.data() + TCP_OFFSET) as *mut u32,
                tcp_len as u32,
                0,
            );
            if tcp_header_sum < 0 {
                info!(&ctx, "Error Checksum: {}", tcp_header_sum);
                return Err(xdp_action::XDP_ABORTED);
            }
            let tcp_sum = csum_ipv4_magic(
                (*ipv).src_addr().to_bits().to_be(),
                (*ipv).dst_addr().to_bits().to_be(),
                tcp_len.to_be(),
                6u8,
                tcp_header_sum as u64,
            );
            (*header).check = tcp_sum;

            let desired_end_offset = (EthHdr::LEN + Ipv4Hdr::LEN + tcp_len as usize) as i32;
            let new_data_end_target = ctx.data() as i32 + desired_end_offset; // Calculate target absolute end address
            let current_data_end_absolute = ctx.data_end() as i32; // Get current absolute end address

            let adjust_delta_2 = new_data_end_target - current_data_end_absolute;
            let ret = bpf_xdp_adjust_tail(ctx.ctx, adjust_delta_2);
            if 0.ne(&ret) {
                info!(&ctx, "Cannot Adjust_Tail (second)");
                return Err(xdp_action::XDP_ABORTED);
            }
            if ctx.data_end() <= ctx.data()
                || ctx.data_end() < (ctx.data() + desired_end_offset as usize)
            {
                info!(
                    &ctx,
                    "Packet too short for max TCP options after adjust_tail"
                );
                return Err(xdp_action::XDP_ABORTED);
            }
        }
        info!(
            &ctx,
            "XDP::TX TCP host:{:i}:{} --> remote:{:i}:{} cookies {}",
            server_addr,
            server_port,
            remote_addr,
            remote_port,
            cookie.seq,
        );
        Ok(xdp_action::XDP_TX)
    // } else if 16.eq(&tcp_flag) {
    //Ack
    // bpf_xdp_ct_lookup and bpf_ct_release are'nt here yet
    // if let Ok(connected) = tcp_lookup(&ctx, ipv_ref, header_ref) {
    // if let Some(connected) = unsafe { CONNECTIONS.get(&remote_addr.to_bits()) } {
    // if *connected != 0 {
    //     info!(
    //         &ctx,
    //         "PASS CT_TCP ACK host:{:i}:{} <-- remote:{:i}:{}",
    //         server_addr,
    //         server_port,
    //         remote_addr,
    //         remote_port,
    //     );
    //     Ok(xdp_action::XDP_PASS)
    // } else {
    // let result =
    //     unsafe { bpf_tcp_raw_check_syncookie_ipv4(ipv as *mut _, header as *mut _) };
    // if result != 0 {
    //     info!(
    //         &ctx,
    //         "DROP Invalid Cookie host:{:i}:{} <-- remote:{:i}:{} ={}",
    //         server_addr,
    //         server_port,
    //         remote_addr,
    //         remote_port,
    //         result
    //     );
    //     Ok(xdp_action::XDP_DROP)
    // } else {
    //     _ = CONNECTIONS.insert(&remote_addr.to_bits(), &1, 0);
    //     info!(
    //         &ctx,
    //         "PASS SynCookie host:{:i}:{} <-- remote:{:i}:{}",
    //         server_addr,
    //         server_port,
    //         remote_addr,
    //         remote_port,
    //     );
    //     Ok(xdp_action::XDP_PASS)
    // }
    //     info!(
    //         &ctx,
    //         "Aborted CT_ERROR host:{:i}:{} <-- remote:{:i}:{}",
    //         server_addr,
    //         server_port,
    //         remote_addr,
    //         remote_port,
    //     );
    //     Err(xdp_action::XDP_DROP)
    // }
    // } else if 18.eq(&tcp_flag) {
    //     //syn-ack
    //     _ = CONNECTIONS.insert(&remote_addr.to_bits(), &1, 0);
    //     info!(
    //         &ctx,
    //         "PASS SynAckRequest host:{:i}:{} <-- remote:{:i}:{}",
    //         server_addr,
    //         server_port,
    //         remote_addr,
    //         remote_port,
    //     );
    //     Ok(xdp_action::XDP_PASS)
    } else {
        _ = CONNECTIONS.insert(&remote_addr.to_bits(), &1, 0);
        info!(
            &ctx,
            "PASS Not_FILTERED host:{:i}:{} <-- remote:{:i}:{}",
            server_addr,
            server_port,
            remote_addr,
            remote_port,
        );
        Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
