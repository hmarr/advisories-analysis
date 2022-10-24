use serde::{Deserialize, Serialize};

pub type GitHubAdvisory = Advisory<GitHubMetadata>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Advisory<T = serde_json::Value> {
    pub id: String,
    pub modified: String,
    pub published: Option<String>,
    pub withdrawn: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub related: Option<Vec<String>>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<Vec<Severity>>,
    pub affected: Option<Vec<Affected>>,
    pub references: Option<Vec<Reference>>,
    pub credits: Option<Vec<Credit>>,
    pub database_specific: Option<T>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Severity {
    #[serde(rename = "CVSS_V2")]
    CvssV2 { score: String },
    #[serde(rename = "CVSS_V3")]
    CvssV3 { score: String },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Affected {
    pub package: Package,
    pub versions: Option<Vec<String>>,
    pub ranges: Option<Vec<Range>>,
    pub ecosystem_specific: Option<serde_json::Value>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Go,
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "OSS-Fuzz")]
    OssFuzz,
    #[serde(rename = "PyPI")]
    PyPi,
    #[serde(rename = "RubyGems")]
    RubyGems,
    #[serde(rename = "crates.io")]
    CratesIo,
    Packagist,
    Maven,
    NuGet,
    Linux,
    Debian,
    Hex,
    Android,
    #[serde(rename = "GitHub Actions")]
    GitHubActions,
    Pub,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Range {
    #[serde(rename = "SEMVER")]
    Semver {
        events: Vec<Event>,
        repo: Option<String>,
        database_specific: Option<serde_json::Value>,
    },

    #[serde(rename = "ECOSYSTEM")]
    Ecosystem {
        events: Vec<Event>,
        repo: Option<String>,
        database_specific: Option<serde_json::Value>,
    },

    #[serde(rename = "GIT")]
    Git {
        events: Vec<Event>,
        repo: String,
        database_specific: Option<serde_json::Value>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Event {
    #[serde(rename = "introduced")]
    Introduced(String),
    #[serde(rename = "fixed")]
    Fixed(String),
    #[serde(rename = "last_affected")]
    LastAffected(String),
    #[serde(rename = "limit")]
    Limit(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub typ: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Credit {
    pub name: String,
    pub contact: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GitHubMetadata {
    pub cwe_ids: Option<Vec<String>>,
    pub severity: Option<String>,
    pub github_reviewed: Option<bool>,
}
