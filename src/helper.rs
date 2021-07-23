pub unsafe fn from_bytes<T>(bytes: &[u8]) -> &T {
    bytes.as_ptr().cast::<T>().as_ref().unwrap()
}
