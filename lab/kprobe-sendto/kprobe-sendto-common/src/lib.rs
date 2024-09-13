#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Buffer {
    pub sockfd: u32,
    pub len: u32,
    pub data: [u8; 200],
}
