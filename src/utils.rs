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