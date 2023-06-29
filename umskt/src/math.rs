pub(crate) fn bitmask(n: u64) -> u64 {
    (1 << n) - 1
}

pub(crate) fn next_sn_bits(field: u64, n: u32, offset: u32) -> u64 {
    (field >> offset) & ((1u64 << n) - 1)
}

pub(crate) fn by_dword(n: &[u8]) -> u32 {
    (n[0] as u32) | (n[1] as u32) << 8 | (n[2] as u32) << 16 | (n[3] as u32) << 24
}
