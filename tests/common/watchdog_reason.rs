// Not `contains("fail-closed")`: only the watchdog's own verdicts end this
// way, and a loaded runner tripping its 2s budget is a harness failure, not
// a behaviour change worth recording.
pub const WATCHDOG_REASON_SUFFIX: &str = "refusing to evaluate (fail-closed)";
