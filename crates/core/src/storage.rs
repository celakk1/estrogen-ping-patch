use crate::{AppResult, benchmark::BenchmarkRun};
use rusqlite::{Connection, params};
use std::path::Path;

pub fn openDatabase(path: &Path) -> AppResult<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > 1 {
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
    Ok(connection)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benchmark::{Endpoint, runBenchmark},
        config::Config,
    };
    use std::sync::atomic::AtomicBool;

    #[test]
    fn migrationAndReportRoundTripPreserveRawSamples() {
        let mut connection = openDatabase(Path::new(":memory:")).unwrap();
        let mut run = runBenchmark(
            Config::default(),
            vec![
                Endpoint {
                    id: "a".into(),
                    address: "127.0.0.1:1".parse().unwrap(),
                },
                Endpoint {
                    id: "b".into(),
                    address: "127.0.0.1:2".parse().unwrap(),
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
