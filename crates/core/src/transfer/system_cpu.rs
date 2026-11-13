use super::resources::{counter, validateUnavailableReason};
use crate::AppResult;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemCpuSnapshot {
    pub capturedAt: String,
    pub queryElapsedNs: String,
    pub processorGroups: u16,
    pub activeProcessors: u32,
    pub idleTime100ns: String,
    pub kernelTime100ns: String,
    pub userTime100ns: String,
}

impl SystemCpuSnapshot {
    pub fn validate(&self) -> AppResult<()> {
        if self.processorGroups != 1 || !(1..=64).contains(&self.activeProcessors) {
            return Err(
                "System CPU coverage requires one stable processor group of at most 64 processors"
                    .into(),
            );
        }
        if self.capturedAt.len() > 64 {
            return Err("System CPU timestamp exceeds its bound".into());
        }
        chrono::DateTime::parse_from_rfc3339(&self.capturedAt)?;
        counter(&self.queryElapsedNs)?;
        if counter(&self.idleTime100ns)? > counter(&self.kernelTime100ns)? {
            return Err("System CPU kernel time must include idle time".into());
        }
        counter(&self.userTime100ns)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemCpu {
    pub schemaVersion: u32,
    pub before: SystemCpuSnapshot,
    pub after: SystemCpuSnapshot,
    pub elapsedNs: String,
}

impl SystemCpu {
    pub fn validate(&self) -> AppResult<()> {
        self.before.validate()?;
        self.after.validate()?;
        if self.schemaVersion != 1 || self.before.activeProcessors != self.after.activeProcessors {
            return Err("System CPU schema or processor coverage changed".into());
        }
        let elapsed = counter(&self.elapsedNs)?;
        let queries = counter(&self.before.queryElapsedNs)?
            .checked_add(counter(&self.after.queryElapsedNs)?)
            .ok_or("System CPU query duration overflowed")?;
        if elapsed == 0
            || elapsed < queries
            || chrono::DateTime::parse_from_rfc3339(&self.before.capturedAt)?
                > chrono::DateTime::parse_from_rfc3339(&self.after.capturedAt)?
        {
            return Err("System CPU capture interval is invalid".into());
        }
        let delta = |before: &str, after: &str| -> AppResult<u64> {
            counter(after)?
                .checked_sub(counter(before)?)
                .ok_or_else(|| "System CPU counters regressed".into())
        };
        let idle = delta(&self.before.idleTime100ns, &self.after.idleTime100ns)?;
        let kernel = delta(&self.before.kernelTime100ns, &self.after.kernelTime100ns)?;
        let user = delta(&self.before.userTime100ns, &self.after.userTime100ns)?;
        kernel
            .checked_sub(idle)
            .ok_or("System CPU idle delta exceeds kernel delta")?;
        kernel
            .checked_add(user)
            .ok_or("System CPU total delta overflowed")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum SystemCpuEvidence {
    Measured { usage: Box<SystemCpu> },
    Unavailable { reason: String },
}

impl SystemCpuEvidence {
    pub fn validate(&self) -> AppResult<()> {
        match self {
            Self::Measured { usage } => usage.validate(),
            Self::Unavailable { reason } => validateUnavailableReason(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SystemCpu {
        let before = SystemCpuSnapshot {
            capturedAt: "2026-11-13T12:00:00Z".into(),
            queryElapsedNs: "100".into(),
            processorGroups: 1,
            activeProcessors: 8,
            idleTime100ns: "9007199254740993".into(),
            kernelTime100ns: "9007199254741000".into(),
            userTime100ns: "9007199254740993".into(),
        };
        let mut after = before.clone();
        after.capturedAt = "2026-11-13T12:00:01Z".into();
        after.idleTime100ns = "9007199254741013".into();
        after.kernelTime100ns = "9007199254741100".into();
        after.userTime100ns = "9007199254741093".into();
        SystemCpu {
            schemaVersion: 1,
            before,
            after,
            elapsedNs: "1000000000".into(),
        }
    }

    #[test]
    fn exactSystemCountersPreserveIdleAndZeroAdvanceWithoutInventingUtilization() {
        let mut usage = fixture();
        usage.validate().unwrap();
        let evidence = SystemCpuEvidence::Measured {
            usage: Box::new(usage.clone()),
        };
        let restored: SystemCpuEvidence =
            serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();
        assert_eq!(evidence, restored);
        usage.after = usage.before.clone();
        usage.validate().unwrap();
        SystemCpuEvidence::Unavailable {
            reason: "unsupported processor coverage".into(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn unsupportedCoverageRegressionAndInvalidIntervalsAreRefused() {
        for failure in 0..16 {
            let mut usage = fixture();
            match failure {
                0 => usage.before.processorGroups = 2,
                1 => usage.after.activeProcessors = 7,
                2 => usage.before.activeProcessors = 0,
                3 => usage.before.activeProcessors = 65,
                4 => usage.schemaVersion = 2,
                5 => usage.elapsedNs = "0".into(),
                6 => usage.elapsedNs = "199".into(),
                7 => usage.after.capturedAt = "2026-11-12T12:00:00Z".into(),
                8 => usage.after.idleTime100ns = "9007199254740992".into(),
                9 => usage.after.kernelTime100ns = "9007199254740999".into(),
                10 => usage.after.userTime100ns = "9007199254740992".into(),
                11 => usage.after.idleTime100ns = "9007199254741100".into(),
                12 => usage.before.queryElapsedNs = "01".into(),
                13 => usage.after.queryElapsedNs = u64::MAX.to_string(),
                14 => {
                    usage.after.kernelTime100ns = u64::MAX.to_string();
                    usage.after.userTime100ns = u64::MAX.to_string();
                }
                _ => usage.after.capturedAt = "invalid".into(),
            }
            assert!(usage.validate().is_err(), "accepted failure {failure}");
        }
    }
}
