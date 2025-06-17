#![allow(
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::ptr_offset_with_cast,
    non_camel_case_types,
    clippy::useless_transmute
)]
use crate::vmlinux::{iphdr, tcphdr};

pub type __s64 = ::aya_ebpf::cty::c_longlong;
pub type __u32 = ::aya_ebpf::cty::c_uint;
pub unsafe fn bpf_tcp_raw_gen_syncookie_ipv4(
    iph: *mut iphdr,
    th: *mut tcphdr,
    th_len: __u32,
) -> __s64 {
    let fun: unsafe extern "C" fn(iph: *mut iphdr, th: *mut tcphdr, th_len: __u32) -> __s64 =
        ::core::mem::transmute(204usize);
    fun(iph, th, th_len)
}

pub unsafe fn bpf_tcp_raw_check_syncookie_ipv4(
    iph: *mut iphdr,
    th: *mut tcphdr,
) -> ::aya_ebpf::cty::c_long {
    let fun: unsafe extern "C" fn(iph: *mut iphdr, th: *mut tcphdr) -> ::aya_ebpf::cty::c_long =
        ::core::mem::transmute(206usize);
    fun(iph, th)
}

