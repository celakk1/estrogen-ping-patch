use crate::ServiceResult;
use epp_core::transfer::{SystemCpu, SystemCpuEvidence, SystemCpuSnapshot};
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetActiveProcessorGroupCount, GetSystemTimes,
    },
};

fn topology() -> ServiceResult<(u16, u32)> {
    let groups = unsafe { GetActiveProcessorGroupCount() };
    let processors = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    if groups != 1 || !(1..=64).contains(&processors) {
        return Err(
            "System CPU capture requires one active processor group of at most 64 processors"
                .into(),
        );
    }
    Ok((groups, processors))
}

fn snapshot() -> ServiceResult<SystemCpuSnapshot> {
    let started = Instant::now();
    let before = topology()?;
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
        return Err(format!(
            "Cannot read system CPU time: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    if topology()? != before {
        return Err("Processor coverage changed during system CPU capture".into());
    }
    let value = |time: FILETIME| {
        ((u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)).to_string()
    };
    let capturedAt = chrono::Utc::now().to_rfc3339();
    let result = SystemCpuSnapshot {
        capturedAt,
        queryElapsedNs: u64::try_from(started.elapsed().as_nanos())?.to_string(),
        processorGroups: before.0,
        activeProcessors: before.1,
        idleTime100ns: value(idle),
        kernelTime100ns: value(kernel),
        userTime100ns: value(user),
    };
    result.validate()?;
    Ok(result)
}

pub(super) struct Window {
    started: Instant,
    before: ServiceResult<SystemCpuSnapshot>,
}

impl Window {
    pub(super) fn start() -> Self {
        let started = Instant::now();
        Self {
            started,
            before: snapshot(),
        }
    }

    pub(super) fn finish(self) -> SystemCpuEvidence {
        self.finishWith(snapshot)
    }

    fn finishWith(
        self,
        after: impl FnOnce() -> ServiceResult<SystemCpuSnapshot>,
    ) -> SystemCpuEvidence {
        let captured = (|| -> ServiceResult<SystemCpu> {
            let before = self.before?;
            let after = after()?;
            let usage = SystemCpu {
                schemaVersion: 1,
                before,
                after,
                elapsedNs: u64::try_from(self.started.elapsed().as_nanos())?.to_string(),
            };
            usage.validate()?;
            Ok(usage)
        })();
        match captured {
            Ok(usage) => SystemCpuEvidence::Measured {
                usage: Box::new(usage),
            },
            Err(error) => SystemCpuEvidence::Unavailable {
                reason: error
                    .to_string()
                    .chars()
                    .take(512)
                    .map(|value| if value.is_control() { ' ' } else { value })
                    .collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nativeWindowPreservesCountersOrExplicitlyRefusesUnsupportedCoverage() {
        let window = Window::start();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let evidence = window.finish();
        evidence.validate().unwrap();
        if topology().is_ok() {
            let SystemCpuEvidence::Measured { usage } = evidence else {
                panic!("supported native CPU capture was unavailable");
            };
            assert!(usage.elapsedNs.parse::<u64>().unwrap() >= 30_000_000);
            assert!(
                usage.after.kernelTime100ns.parse::<u64>().unwrap()
                    > usage.before.kernelTime100ns.parse::<u64>().unwrap()
            );
        } else {
            assert!(matches!(evidence, SystemCpuEvidence::Unavailable { .. }));
        }
    }

    #[test]
    fn unavailableCapturesRemainUnavailableInsteadOfZeroUtilization() {
        let mut called = false;
        let evidence = Window {
            started: Instant::now(),
            before: Err("unavailable first capture".into()),
        }
        .finishWith(|| {
            called = true;
            panic!("unavailable start must not acquire a new baseline")
        });
        assert!(!called);
        assert!(
            matches!(&evidence, SystemCpuEvidence::Unavailable { reason } if reason == "unavailable first capture")
        );
        evidence.validate().unwrap();
        if let Ok(before) = snapshot() {
            let evidence = Window {
                started: Instant::now(),
                before: Ok(before),
            }
            .finishWith(|| Err("unavailable final capture".into()));
            assert!(
                matches!(&evidence, SystemCpuEvidence::Unavailable { reason } if reason == "unavailable final capture")
            );
            evidence.validate().unwrap();
        }
    }
}
