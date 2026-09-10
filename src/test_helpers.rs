pub fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
pub fn assert_normal_type<T: Sized + Send + Sync + Unpin>() {}
