//! Plaintext oracle. The ground truth every encrypted operation is checked
//! against during development. Throw-away in production, load-bearing here.

pub struct PlainArray {
    pub data: Vec<u8>,
}

impl PlainArray {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn read(&self, idx: usize) -> u8 {
        self.data[idx]
    }

    pub fn write(&mut self, idx: usize, val: u8) {
        self.data[idx] = val;
    }
}
