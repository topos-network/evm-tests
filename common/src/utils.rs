use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};

#[macro_export]
macro_rules! unwrap_or_continue {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => continue,
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => continue,
        }
    };
}

pub fn init_env_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}
