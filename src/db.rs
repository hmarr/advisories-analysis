use std::{
    collections::HashSet,
    error::Error,
    sync::{Arc, Mutex},
};

use rusqlite::{params, Connection};

use crate::osv;

pub struct DB {
    locked_conn: Arc<Mutex<Connection>>,
}

const CREATE_ADVISORIES_TABLE: &str = r#"
CREATE TABLE advisories (
    ghsa TEXT PRIMARY KEY,
    modified TEXT NOT NULL,
    published TEXT,
    withdrawn TEXT,
    cve TEXT,
    ecosystems TEXT,
    summary TEXT,
    details TEXT,
    severity TEXT,
    cwes TEXT
)"#;

const CREATE_AFFECTED_PACKAGES_TABLE: &str = r#"
CREATE TABLE affected_packages (
    ghsa TEXT,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    ranges TEXT,
    versions TEXT
)"#;

const INSERT_ADVISORY: &str = r#"
INSERT INTO advisories (
     ghsa,  modified,  published,  withdrawn,  cve,  ecosystems,  summary,
     details,  severity,  cwes
) VALUES (
    :ghsa, :modified, :published, :withdrawn, :cve, :ecosystems, :summary,
    :details, :severity, :cwes
)"#;

const INSERT_AFFECTED_PACKAGE: &str = r#"
INSERT INTO affected_packages (
     ghsa,  name,  ecosystem,  ranges,  versions
) VALUES (
    :ghsa, :name, :ecosystem, :ranges, :versions
)"#;

impl DB {
    pub fn new(db_path: &str) -> Result<Self, Box<dyn Error>> {
        let conn = Connection::open(db_path)?;
        conn.execute(CREATE_ADVISORIES_TABLE, ())?;
        conn.execute(CREATE_AFFECTED_PACKAGES_TABLE, ())?;
        Ok(Self {
            locked_conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn bulk_insert(
        &self,
        entries: &[osv::GitHubAdvisory],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut conn = self
            .locked_conn
            .lock()
            .map_err(|e| format!("obtaining connection lock: {}", e))?;
        let tx = conn.transaction()?;
        for entry in entries {
            let mut ecosystems = HashSet::new();
            if let Some(affected) = entry.affected.as_ref() {
                for a in affected {
                    ecosystems.insert(&a.package.ecosystem);
                }
            }
            tx.execute(
                INSERT_ADVISORY,
                params![
                    entry.id,
                    entry.modified,
                    entry.published,
                    entry.withdrawn,
                    entry.aliases.as_ref().and_then(|v| v.first()),
                    serde_json::to_string(&ecosystems)?,
                    entry.summary,
                    entry.details,
                    entry
                        .database_specific
                        .as_ref()
                        .map(|d| d.severity.as_ref()),
                    entry
                        .database_specific
                        .as_ref()
                        .and_then(|d| d.cwe_ids.as_ref())
                        .map(serde_json::to_value)
                        .transpose()?
                ],
            )?;

            if let Some(affected) = entry.affected.as_ref() {
                for a in affected {
                    tx.execute(
                        INSERT_AFFECTED_PACKAGE,
                        params![
                            entry.id,
                            a.package.name,
                            serde_json::to_value(&a.package.ecosystem)?.as_str(),
                            serde_json::to_string(&a.ranges)?,
                            serde_json::to_string(&a.versions)?,
                        ],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
