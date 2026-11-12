use crate::{
    AppResult,
    backups::{BackupExport, BackupSummary, checksum, validatePayload},
    benchmark::BenchmarkRun,
};
use rusqlite::{Connection, params};
use std::path::Path;

pub fn openDatabase(path: &Path) -> AppResult<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    migrateDatabase(&connection)?;
    Ok(connection)
}

fn migrateDatabase(connection: &Connection) -> AppResult<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > 6 {
        return Err("Database is newer than this application; refusing to downgrade it".into());
    }
    if version == 0 {
        connection.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE benchmark_runs(id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, status TEXT NOT NULL, report_json TEXT NOT NULL);
            CREATE TABLE benchmark_samples(run_id INTEGER NOT NULL REFERENCES benchmark_runs(id), ordinal INTEGER NOT NULL, sample_json TEXT NOT NULL, PRIMARY KEY(run_id, ordinal));
            CREATE INDEX benchmark_run_time ON benchmark_runs(started_at);
            CREATE TABLE application_events(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, kind TEXT NOT NULL, detail TEXT NOT NULL);
            PRAGMA user_version = 1;
            COMMIT;")?;
    }
    if version < 2 {
        connection.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE configuration_snapshots(id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, sha256 TEXT NOT NULL, captured_sections INTEGER NOT NULL, unavailable_sections INTEGER NOT NULL, payload_json TEXT NOT NULL);
            PRAGMA user_version = 2;
            COMMIT;")?;
    }
    if version < 3 {
        connection.execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 3; COMMIT;")?;
    }
    if version < 4 {
        connection.execute_batch("BEGIN IMMEDIATE; PRAGMA user_version = 4; COMMIT;")?;
    }
    if version < 5 {
        connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE load_sessions(id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, status TEXT NOT NULL, report_json TEXT NOT NULL); PRAGMA user_version = 5; COMMIT;")?;
    }
    if version < 6 {
        connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE packet_checks(id INTEGER PRIMARY KEY, report_json TEXT NOT NULL, sha256 TEXT NOT NULL); PRAGMA user_version = 6; COMMIT;")?;
    }
    Ok(())
}

pub fn saveBackup(
    connection: &mut Connection,
    payload: &serde_json::Value,
) -> AppResult<BackupSummary> {
    let (capturedSections, unavailableSections) = validatePayload(payload)?;
    let payloadJson = serde_json::to_string_pretty(payload)?;
    if payloadJson.len() > 2_500_000 {
        return Err("Snapshot exceeds the 2.5 MB backup limit".into());
    }
    let sha256 = checksum(&payloadJson);
    let capturedAt = payload["capturedAt"]
        .as_str()
        .ok_or("Snapshot timestamp missing")?
        .to_string();
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let count: u32 =
        transaction.query_row("SELECT COUNT(*) FROM configuration_snapshots", [], |row| {
            row.get(0)
        })?;
    if count >= 200 {
        return Err("The 200-snapshot safety limit has been reached. Existing backups were preserved; export and archive them before continuing.".into());
    }
    transaction.execute("INSERT INTO configuration_snapshots(captured_at,sha256,captured_sections,unavailable_sections,payload_json) VALUES(?1,?2,?3,?4,?5)", params![capturedAt,sha256,capturedSections as u32,unavailableSections as u32,payloadJson])?;
    let id = transaction.last_insert_rowid();
    transaction.commit()?;
    Ok(BackupSummary {
        id,
        capturedAt,
        sha256,
        capturedSections,
        unavailableSections,
    })
}

pub fn backupHistory(connection: &Connection) -> AppResult<Vec<BackupSummary>> {
    let mut statement = connection.prepare("SELECT id,captured_at,sha256,captured_sections,unavailable_sections FROM configuration_snapshots ORDER BY id DESC LIMIT 200")?;
    let rows = statement.query_map([], |row| {
        Ok(BackupSummary {
            id: row.get(0)?,
            capturedAt: row.get(1)?,
            sha256: row.get(2)?,
            capturedSections: row.get::<_, u32>(3)? as usize,
            unavailableSections: row.get::<_, u32>(4)? as usize,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn loadBackup(connection: &Connection, id: i64) -> AppResult<BackupExport> {
    let (capturedAt, sha256, capturedSections, unavailableSections, payloadJson): (String,String,u32,u32,String) = connection.query_row("SELECT captured_at,sha256,captured_sections,unavailable_sections,payload_json FROM configuration_snapshots WHERE id=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
    if checksum(&payloadJson) != sha256 {
        return Err("Backup integrity verification failed. The stored settings have been preserved, but this snapshot must not be used for restoration.".into());
    }
    let payload: serde_json::Value = serde_json::from_str(&payloadJson)?;
    let counts = validatePayload(&payload)?;
    if payload["capturedAt"].as_str() != Some(capturedAt.as_str())
        || counts != (capturedSections as usize, unavailableSections as usize)
    {
        return Err("Backup metadata does not match its verified settings document".into());
    }
    Ok(BackupExport {
        summary: BackupSummary {
            id,
            capturedAt,
            sha256,
            capturedSections: capturedSections as usize,
            unavailableSections: unavailableSections as usize,
        },
        payloadJson,
    })
}

pub fn saveRun(connection: &mut Connection, run: &mut BenchmarkRun) -> AppResult<()> {
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO benchmark_runs(started_at,status,report_json) VALUES(?1,?2,'{}')",
        params![run.startedAt, run.status],
    )?;
    run.id = transaction.last_insert_rowid();
    for (ordinal, sample) in run.samples.iter().enumerate() {
        transaction.execute(
            "INSERT INTO benchmark_samples VALUES(?1,?2,?3)",
            params![run.id, ordinal as i64, serde_json::to_string(sample)?],
        )?;
    }
    transaction.execute(
        "UPDATE benchmark_runs SET report_json=?1 WHERE id=?2",
        params![serde_json::to_string(run)?, run.id],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn history(connection: &Connection, limit: u32) -> AppResult<Vec<BenchmarkRun>> {
    let mut statement =
        connection.prepare("SELECT report_json FROM benchmark_runs ORDER BY id DESC LIMIT ?1")?;
    let rows = statement.query_map([limit.min(100)], |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

pub fn saveLoadSession(
    connection: &mut Connection,
    run: &mut crate::transfer::session::SessionRun,
) -> AppResult<()> {
    let transaction = connection.transaction()?;
    saveLoadSessionInTransaction(&transaction, run)?;
    transaction.commit()?;
    Ok(())
}

pub fn saveLoadSessionInTransaction(
    transaction: &rusqlite::Transaction<'_>,
    run: &mut crate::transfer::session::SessionRun,
) -> AppResult<()> {
    transaction.execute(
        "INSERT INTO load_sessions(started_at,status,report_json) VALUES(?1,?2,'{}')",
        params![run.startedAt, run.status],
    )?;
    run.id = transaction.last_insert_rowid();
    transaction.execute(
        "UPDATE load_sessions SET report_json=?1 WHERE id=?2",
        params![serde_json::to_string(run)?, run.id],
    )?;
    Ok(())
}

pub fn loadSessionHistory(
    connection: &Connection,
    limit: u32,
) -> AppResult<Vec<crate::transfer::session::SessionRun>> {
    let mut statement =
        connection.prepare("SELECT report_json FROM load_sessions ORDER BY id DESC LIMIT ?1")?;
    let rows = statement.query_map([limit.min(100)], |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benchmark::{Endpoint, ProbeProtocol, runBenchmark},
        config::Config,
    };
    use std::sync::atomic::AtomicBool;

    #[test]
    fn addingBackupsPreservesVersionOneHistory() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE application_events(id INTEGER PRIMARY KEY, kind TEXT); INSERT INTO application_events VALUES(1,'preserve'); PRAGMA user_version=1;").unwrap();
        migrateDatabase(&connection).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT kind FROM application_events WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "preserve"
        );
        assert_eq!(backupHistory(&connection).unwrap().len(), 0);
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
            6
        );
    }

    #[test]
    fn migrationAndReportRoundTripPreserveRawSamples() {
        let mut connection = openDatabase(Path::new(":memory:")).unwrap();
        let mut run = runBenchmark(
            Config::default(),
            vec![
                Endpoint {
                    id: "a".into(),
                    address: "127.0.0.1:1".into(),
                    protocol: ProbeProtocol::TcpConnect,
                    dnsQuery: None,
                },
                Endpoint {
                    id: "b".into(),
                    address: "127.0.0.1:2".into(),
                    protocol: ProbeProtocol::TcpConnect,
                    dnsQuery: None,
                },
            ],
            &AtomicBool::new(true),
            |_, _, _| {},
        )
        .unwrap();
        saveRun(&mut connection, &mut run).unwrap();
        assert_eq!(run.id, 1);
        let records = history(&connection, 20).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, "cancelled");
        assert_eq!(records[0].id, 1);
        assert!(records[0].samples.is_empty());
        let mut legacy = serde_json::to_value(&run).unwrap();
        for result in legacy["results"].as_array_mut().unwrap() {
            result["endpoint"]
                .as_object_mut()
                .unwrap()
                .remove("protocol");
        }
        connection
            .execute(
                "UPDATE benchmark_runs SET report_json=?1 WHERE id=1",
                [legacy.to_string()],
            )
            .unwrap();
        connection
            .execute_batch("DROP TABLE load_sessions; DROP TABLE packet_checks")
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        migrateDatabase(&connection).unwrap();
        let legacyRecords = history(&connection, 20).unwrap();
        assert_eq!(legacyRecords[0].protocol, "tcpConnect");
        assert_eq!(
            legacyRecords[0].results[0].endpoint.protocol,
            ProbeProtocol::TcpConnect
        );
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn refuseFutureSchema() {
        let directory =
            std::env::temp_dir().join(format!("epp-schema-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("future.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 999).unwrap();
        drop(connection);
        assert!(openDatabase(&path).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
