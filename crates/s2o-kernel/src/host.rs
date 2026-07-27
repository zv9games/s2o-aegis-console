//! Host identity and demo flag.

/// True only when AEGIS_DEMO=1 or true (never default).
pub fn demo_mode() -> bool {
    std::env::var("AEGIS_DEMO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Stable-ish host id for events (hostname env, not cryptographic).
pub fn host_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("NAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}
