/// Checksum helpers for incremental IP and TCP checksum updates.
///
/// Implements RFC 1624 incremental checksum adjustment. When a packet field
/// changes, we subtract the old value and add the new value to the running
/// checksum, avoiding a full recomputation.
///
/// Cilium equivalent: `bpf/lib/csum.h` + parts of `bpf/lib/l3.h` and `bpf/lib/l4.h`.

/// Fold a 64-bit accumulator down to a ones-complement 16-bit checksum.
/// The result is already negated (bitwise NOT applied) — callers must not
/// negate again.
#[inline(always)]
fn csum_fold(mut csum: u64) -> u16 {
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    !(csum as u16)
}

/// Incrementally update a checksum when a 16-bit field changes (e.g. TCP port).
/// All values are raw from the packet (network byte order).
#[inline(always)]
pub fn csum_replace2(check_ptr: *mut u16, old: u16, new: u16) {
    let old_check = unsafe { core::ptr::read_unaligned(check_ptr) };
    let mut csum = !(old_check) as u64;
    csum += !(old) as u64;
    csum += new as u64;
    unsafe { core::ptr::write_unaligned(check_ptr, csum_fold(csum)) };
}

/// Incrementally update a checksum when a 32-bit field changes (e.g. IP address).
/// All values are raw from the packet (network byte order).
#[inline(always)]
pub fn csum_replace4(check_ptr: *mut u16, old: u32, new: u32) {
    let old_check = unsafe { core::ptr::read_unaligned(check_ptr) };
    let mut csum = !(old_check) as u64;
    csum += !((old >> 16) as u16) as u64 + !((old & 0xFFFF) as u16) as u64;
    csum += ((new >> 16) as u16) as u64 + ((new & 0xFFFF) as u16) as u64;
    unsafe { core::ptr::write_unaligned(check_ptr, csum_fold(csum)) };
}
