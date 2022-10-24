# GitHub Advisory Database Analysis

Scripts for performing analysis on the GitHub Advisory Database.

## Building a sqlite database of GHSAs

The public [GitHub Advisory Database](https://github.com/github/advisory-database) is a repo with 180k+ JSON files, which is not very easy to work with. This repo contains a script to download the data, and a small Rust program to build a sqlite database of the GHSAs, which is much easier to work with.

Note: you'll need a recent version of Rust installed to import the data.

1. Download the data by running `./download-data.sh`. This will download the GHSA OSV-formatted JSON files to `data/advisory-database-main`.
2. Build the sqlite database by running `cargo run --release`. The database will be written to `data/advisory-database.db`.

Here's the schema for the database:

```sql
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
);
CREATE TABLE affected_packages (
  ghsa TEXT,
  name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  ranges TEXT,
  versions TEXT
);
```

## Analysis notebook

The `analysis.ipynb` notebook contains some basic analysis of the data, and should serve as a good starting point for anyone who wants to dig into the data. You'll need pandas, matplotlib, and jupyter (or the notebook plugin for vscode) installed to run the notebook.
