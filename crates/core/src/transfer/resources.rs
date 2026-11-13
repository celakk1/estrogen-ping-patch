use crate::AppResult;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerCpu {
    pub schemaVersion: u32,
    pub creationTime100ns: String,
    pub exitTime100ns: String,
    pub kernelTime100ns: String,
    pub userTime100ns: String,
}

fn counter(value: &str) -> AppResult<u64> {
    let parsed: u64 = value.parse()?;
    if parsed.to_string() != value {
        return Err("Worker CPU counters require canonical unsigned decimal values".into());
    }
    Ok(parsed)
}

impl WorkerCpu {
    pub fn validate(&self) -> AppResult<()> {
        let creation = counter(&self.creationTime100ns)?;
        let exit = counter(&self.exitTime100ns)?;
        if self.schemaVersion != 1 || creation == 0 || exit < creation {
            return Err("Worker CPU evidence has invalid schema or process lifetime".into());
        }
        counter(&self.kernelTime100ns)?
            .checked_add(counter(&self.userTime100ns)?)
            .ok_or("Worker CPU time overflowed")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum WorkerCpuEvidence {
    Measured { usage: WorkerCpu },
    Unavailable { reason: String },
}

impl WorkerCpuEvidence {
    pub fn validate(&self) -> AppResult<()> {
        match self {
            Self::Measured { usage } => usage.validate(),
            Self::Unavailable { reason } => {
                if reason.is_empty()
                    || reason.chars().count() > 512
                    || reason.chars().any(char::is_control)
                {
                    return Err(
                        "Unavailable worker CPU evidence needs a bounded readable reason".into(),
                    );
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuEvidencePreservesExactCountersAndDoesNotConfuseMissingWithZero() {
        let mut usage = WorkerCpu {
            schemaVersion: 1,
            creationTime100ns: "134000000000000001".into(),
            exitTime100ns: "134000000000000002".into(),
            kernelTime100ns: "0".into(),
            userTime100ns: "0".into(),
        };
        let measured = WorkerCpuEvidence::Measured {
            usage: usage.clone(),
        };
        measured.validate().unwrap();
        let restored: WorkerCpuEvidence =
            serde_json::from_str(&serde_json::to_string(&measured).unwrap()).unwrap();
        assert_eq!(restored, measured);
        usage.userTime100ns = "100".into();
        usage.validate().unwrap();
        let unavailable = WorkerCpuEvidence::Unavailable {
            reason: "fixture query unavailable".into(),
        };
        unavailable.validate().unwrap();
        assert_ne!(
            serde_json::to_value(unavailable).unwrap(),
            serde_json::to_value(measured).unwrap()
        );
    }

    #[test]
    fn malformedLifetimeCountersAndReasonsAreRefused() {
        for failure in 0..7 {
            let mut usage = WorkerCpu {
                schemaVersion: 1,
                creationTime100ns: "1".into(),
                exitTime100ns: "2".into(),
                kernelTime100ns: "1".into(),
                userTime100ns: "2".into(),
            };
            match failure {
                0 => usage.schemaVersion = 2,
                1 => usage.creationTime100ns = "0".into(),
                2 => usage.exitTime100ns = "0".into(),
                3 => usage.userTime100ns = "01".into(),
                4 => usage.kernelTime100ns = "-1".into(),
                5 => usage.userTime100ns = u64::MAX.to_string(),
                _ => usage.exitTime100ns = "18446744073709551616".into(),
            }
            assert!(usage.validate().is_err());
        }
        for reason in [String::new(), "x".repeat(513), "bad\nreason".into()] {
            assert!(
                WorkerCpuEvidence::Unavailable { reason }
                    .validate()
                    .is_err()
            );
        }
    }
}
