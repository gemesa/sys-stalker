#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Buffer {
    pub len: usize,
    pub data: [u8; 200],
}
