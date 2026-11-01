use epp_core::{
    AppResult,
    packet_size::{self, Report},
};
use epp_service::{
    journal::AddressFamily,
    mtu,
    routing::{self, Address, Capture, Snapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::atomic::AtomicBool,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    routeBefore: Snapshot,
    interfaceBefore: mtu::Snapshot,
    routeAfter: Option<Snapshot>,
    interfaceAfter: Option<mtu::Snapshot>,
    afterError: Option<String>,
}

impl Context {
    fn unchanged(&self) -> AppResult<bool> {
        self.routeBefore.matchesInterface(&self.interfaceBefore)?;
        let (Some(routeAfter), Some(interfaceAfter)) = (&self.routeAfter, &self.interfaceAfter)
        else {
            return Ok(false);
        };
        routeAfter.matchesInterface(interfaceAfter)?;
        let fingerprint = |snapshot: &Snapshot| {
            routing::fingerprint(&[Capture::Captured {
                snapshot: snapshot.clone(),
            }])
        };
        let before = fingerprint(&self.routeBefore)?;
        let after = fingerprint(routeAfter)?;
        let mut first = self.interfaceBefore.clone();
        let mut second = interfaceAfter.clone();
        first.capturedAtUnixMs = 1;
        second.capturedAtUnixMs = 1;
        Ok(self.afterError.is_none() && before.is_some() && before == after && first == second)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Check {
    schemaVersion: u32,
    id: i64,
    pub report: Report,
    context: Context,
    contextUnchanged: bool,
}

impl Check {
    fn validate(&self) -> AppResult<()> {
        self.report.validate()?;
        let route = &self.context.routeBefore;
        if self.schemaVersion != 1
            || self.id < 0
            || route.source.ip != IpAddr::V4(self.report.plan.source)
            || route.destination.ip != IpAddr::V4(self.report.plan.destination)
            || self.context.interfaceBefore.settings.nlMtu != self.report.plan.interfaceMtu
            || self.contextUnchanged != self.context.unchanged()?
        {
            return Err("Packet check does not match its native route and adapter evidence".into());
        }
        Ok(())
    }
}

fn capture(destination: Ipv4Addr, cancelled: &AtomicBool) -> AppResult<(Snapshot, mtu::Snapshot)> {
    let address = Address {
        ip: destination.into(),
        scopeId: 0,
    };
    let captures = routing::capture(&[address], cancelled)?;
    let route = match captures.into_iter().next() {
        Some(Capture::Captured { snapshot }) => snapshot,
        Some(Capture::Unavailable { error, .. }) => {
            return Err(format!("Windows could not select a route: {error}").into());
        }
        None => return Err("Windows returned no selected route".into()),
    };
    let interface = mtu::capture(route.adapterGuid, AddressFamily::Ipv4, cancelled)?;
    route.matchesInterface(&interface)?;
    Ok((route, interface))
}

pub(crate) fn run(
    destination: &str,
    cancelled: &AtomicBool,
    progress: impl FnMut(&packet_size::Sample),
) -> AppResult<Check> {
    let destination: Ipv4Addr = destination.parse().map_err(|_| "Enter a numeric IPv4 address, such as 1.1.1.1. IPv6 packet checks are not supported yet.")?;
    Address {
        ip: destination.into(),
        scopeId: 0,
    }
    .validateDestination()?;
    let (routeBefore, interfaceBefore) = capture(destination, cancelled)?;
    let IpAddr::V4(source) = routeBefore.source.ip else {
        return Err("Windows selected a non-IPv4 source".into());
    };
    let report = packet_size::diagnose(
        packet_size::Plan {
            source,
            destination,
            interfaceMtu: interfaceBefore.settings.nlMtu,
            timeoutMs: 750,
            intervalMs: 75,
            budgetMs: 120_000,
        },
        &mut packet_size::NativeProbe::default(),
        cancelled,
        progress,
    )?;
    let (routeAfter, interfaceAfter, afterError) = match capture(destination, cancelled) {
        Ok((route, interface)) => (Some(route), Some(interface), None),
        Err(error) => (
            None,
            None,
            Some(error.to_string().chars().take(512).collect()),
        ),
    };
    let context = Context {
        routeBefore,
        interfaceBefore,
        routeAfter,
        interfaceAfter,
        afterError,
    };
    let contextUnchanged = context.unchanged()?;
    let check = Check {
        schemaVersion: 1,
        id: 0,
        report,
        context,
        contextUnchanged,
    };
    check.validate()?;
    Ok(check)
}

pub(crate) fn save(directory: &Path, check: &mut Check) -> AppResult<()> {
    check.validate()?;
    let mut connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))?;
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO packet_checks(report_json,sha256) VALUES('{}','')",
        [],
    )?;
    check.id = transaction.last_insert_rowid();
    let json = serde_json::to_string(check)?;
    transaction.execute(
        "UPDATE packet_checks SET report_json=?1,sha256=?2 WHERE id=?3",
        (&json, epp_core::backups::checksum(&json), check.id),
    )?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn history(directory: &Path) -> AppResult<Vec<Check>> {
    let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))?;
    let mut statement = connection
        .prepare("SELECT id,report_json,sha256 FROM packet_checks ORDER BY id DESC LIMIT 50")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    rows.map(|row| {
        let (id, json, checksum) = row?;
        if json.len() > 500_000 || epp_core::backups::checksum(&json) != checksum {
            return Err(
                "Saved packet check integrity verification failed; its data was preserved".into(),
            );
        }
        let check: Check = serde_json::from_str(&json)?;
        check.validate()?;
        if check.id != id {
            return Err("Saved packet check identity does not match its database record".into());
        }
        Ok(check)
    })
    .collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use epp_core::packet_size::Outcome;

    #[test]
    fn nativeLoopbackCheckPreservesRouteAndDoesNotInventAnOptimization() {
        let cancelled = AtomicBool::new(false);
        let mut check = run("127.0.0.1", &cancelled, |_| {}).unwrap();
        assert_eq!(check.report.outcome, Outcome::TestedLimitReached);
        assert!(check.contextUnchanged);
        assert_eq!(check.report.confirmedBoundaryBytes, None);
        check.validate().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "epp-packet-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        save(&directory, &mut check).unwrap();
        let stored = history(&directory).unwrap();
        assert_eq!(
            serde_json::to_value(&stored[0]).unwrap(),
            serde_json::to_value(&check).unwrap()
        );
        check
            .context
            .interfaceAfter
            .as_mut()
            .unwrap()
            .settings
            .nlMtu -= 1;
        assert!(!check.context.unchanged().unwrap());
        assert!(check.validate().is_err());
        let connection =
            epp_core::storage::openDatabase(&directory.join("experiments.sqlite3")).unwrap();
        connection
            .execute("UPDATE packet_checks SET report_json='{}'", [])
            .unwrap();
        assert!(
            history(&directory)
                .unwrap_err()
                .to_string()
                .contains("integrity")
        );
        drop(connection);
        for name in [
            "experiments.sqlite3",
            "experiments.sqlite3-wal",
            "experiments.sqlite3-shm",
        ] {
            let path = directory.join(name);
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
        std::fs::remove_dir(directory).unwrap();
        assert!(run("::1", &cancelled, |_| {}).is_err());
        assert!(run("1.1.1.1", &AtomicBool::new(true), |_| {}).is_err());
    }
}
