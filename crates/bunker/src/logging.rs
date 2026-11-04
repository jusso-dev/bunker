//! JSON-lines diagnostics on stderr. Set the level once from `--log-level` or `BUNKER_LOG`.
//! Callers pass bounded metadata only: never paths, file contents, secrets or parser output.
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}
impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}
impl std::str::FromStr for Level {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            _ => Err(format!(
                "invalid log level {value:?}; expected error, warn, info or debug"
            )),
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}
pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}
/// One line: `{"time","level","message",...fields}`. Non-object fields go under `fields`.
pub fn line(level: Level, message: &str, fields: Value) -> String {
    let mut object = Map::new();
    object.insert(
        "time".into(),
        chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .into(),
    );
    object.insert("level".into(), level.as_str().into());
    object.insert("message".into(), message.into());
    match fields {
        Value::Object(fields) => {
            for (key, value) in fields {
                object.entry(key).or_insert(value);
            }
        }
        Value::Null => {}
        other => {
            object.insert("fields".into(), other);
        }
    }
    Value::Object(object).to_string()
}
pub fn log(level: Level, message: &str, fields: Value) {
    if enabled(level) {
        eprintln!("{}", line(level, message, fields));
    }
}
pub fn error(message: &str, fields: Value) {
    log(Level::Error, message, fields)
}
pub fn warn(message: &str, fields: Value) {
    log(Level::Warn, message, fields)
}
pub fn info(message: &str, fields: Value) {
    log(Level::Info, message, fields)
}
pub fn debug(message: &str, fields: Value) {
    log(Level::Debug, message, fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn levels_parse_order_and_keep_reserved_keys() {
        assert_eq!("DEBUG".parse::<Level>().unwrap(), Level::Debug);
        assert!("verbose".parse::<Level>().unwrap_err().contains("verbose"));
        assert!(Level::Error < Level::Debug);
        let value: Value = serde_json::from_str(&line(
            Level::Warn,
            "fixture",
            serde_json::json!({"event":"e","level":"spoofed"}),
        ))
        .unwrap();
        assert_eq!(value["level"], "warn");
        assert_eq!(value["message"], "fixture");
        assert_eq!(value["event"], "e");
    }
}
