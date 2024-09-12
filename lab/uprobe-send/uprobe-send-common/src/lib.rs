#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Buffer {
    pub len: u32,
    pub data: [u8; 200]
}
