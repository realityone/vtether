use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

// ---- NAT config types ----

#[repr(C)]
pub struct NatKey {
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct NatConfigEntry {
    pub dst_ip: u32,
    pub snat_ip: u32,
    pub dst_port: u16,
    pub _pad: u16,
}

// ---- NAT config map ----

#[map]
pub static NAT_CONFIG: HashMap<NatKey, NatConfigEntry> = HashMap::with_max_entries(128, 0);
