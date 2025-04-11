use std::collections::VecDeque;
use std::ops::RangeBounds;

pub trait RingBuffer<T> {
	fn to_vec<R: RangeBounds<usize>>(&self, range: R) -> Vec<T>;
}

impl RingBuffer<u8> for VecDeque<u8> {
	fn to_vec<R: RangeBounds<usize>>(&self, range: R) -> Vec<u8> {
		self.range(range).copied().collect()
    }
}

pub enum IoFlag {
    Read = 0b00000001,
    Write = 0b00000010,
}
pub struct AvailableIo {
	flags: u8,
}

impl AvailableIo {
    pub fn new() -> AvailableIo {
        AvailableIo { flags: 0 }
    }

    pub fn set(&mut self, flag: IoFlag) {
        self.flags |= flag as u8
    }

    pub fn contains (&self, flag: IoFlag) -> bool {
        self.flags & flag as u8 != 0
    }
}

