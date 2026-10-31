use crate::AppResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Profile {
    Latency,
    Balanced,
    Download,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub schemaVersion: u32,
    pub profile: Profile,
    pub sampleCount: u32,
    pub intervalMs: u64,
    pub timeoutMs: u64,
    pub sessionMinutes: u32,
    pub maxDownloadBytes: u64,
    pub maxUploadBytes: u64,
    pub aiMode: String,
    pub cloudBudget: u32,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schemaVersion: 1,
            profile: Profile::Balanced,
            sampleCount: 12,
            intervalMs: 500,
            timeoutMs: 1500,
            sessionMinutes: 15,
            maxDownloadBytes: 100_000_000,
            maxUploadBytes: 25_000_000,
            aiMode: "disabled".into(),
            cloudBudget: 0,
            extra: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> AppResult<()> {
        if self.schemaVersion != 1 {
            return Err("Unsupported configuration schema; the file has been preserved".into());
        }
        if !(3..=120).contains(&self.sampleCount)
            || !(250..=10_000).contains(&self.intervalMs)
            || !(100..=5000).contains(&self.timeoutMs)
            || !(1..=1440).contains(&self.sessionMinutes)
        {
            return Err(
                "Sample count, interval, timeout, or duration is outside safe bounds".into(),
            );
        }
        if self.aiMode != "disabled" || self.cloudBudget != 0 {
            return Err(
                "This build supports disabled AI only; no inference provider is configured".into(),
            );
        }
        Ok(())
    }
}

pub fn loadConfig(directory: &Path) -> AppResult<Config> {
    fs::create_dir_all(directory)?;
    let configPath = directory.join("config.json");
    let config = if configPath.exists() {
        serde_json::from_slice(&fs::read(configPath)?)?
    } else {
        Config::default()
    };
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaultIsLocalAndBounded() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.cloudBudget, 0);
        assert_eq!(config.profile, Profile::Balanced);
    }

    #[test]
    fn rejectUnboundedAndUnsupportedConfig() {
        let mut config = Config {
            sampleCount: 100_000,
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config = Config {
            schemaVersion: 999,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn preserveUnknownFields() {
        let mut value = serde_json::to_value(Config::default()).unwrap();
        value["futurePreference"] = serde_json::json!({"enabled": true});
        let config: Config = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(config).unwrap(), value);
    }
}
