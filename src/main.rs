use indicatif::ProgressBar;
use rayon::prelude::*;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::{error::Error, fs::File};
use walkdir::WalkDir;

mod db;
mod osv;

const DB_PATH: &str = "data/advisory-database.db";
const ADVISORY_DATA_PATH: &str = "data/advisory-database-main";

fn main() -> Result<(), Box<dyn Error>> {
    if Path::new(DB_PATH).exists() {
        println!("Database already exists, overwriting...");
        fs::remove_file(DB_PATH)?;
    }
    let db = db::DB::new(DB_PATH)?;

    // Find the OSV JSON files in the advisory data directory
    let spinner = ProgressBar::new_spinner().with_message("Finding advisory files...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    let json_files = find_advisory_files(ADVISORY_DATA_PATH);
    spinner.finish();

    // Parse the JSON files and insert them into the database
    println!("Importing {} advisories into {}", json_files.len(), DB_PATH);
    let bar = ProgressBar::new(json_files.len() as u64);
    json_files
        // There are a lot of JSON files, so use rayon to parse them in parallel
        .par_iter()
        .map(
            |path| -> Result<osv::GitHubAdvisory, Box<dyn Error + Send + Sync>> {
                let reader = BufReader::new(File::open(path)?);
                let entry: osv::GitHubAdvisory = serde_json::from_reader(reader)?;

                bar.inc(1);

                Ok(entry)
            },
        )
        // Bulk inserts are much faster than individual inserts, so do 1000 at a time
        .chunks(1000)
        .for_each(|chunk| {
            let entries = chunk.into_iter().filter_map(Result::ok).collect::<Vec<_>>();
            if let Err(err) = db.bulk_insert(&entries) {
                eprintln!("Error: {}", err);
            }
        });
    bar.finish();

    Ok(())
}

fn find_advisory_files(root_path: &str) -> Vec<std::path::PathBuf> {
    WalkDir::new(root_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().unwrap_or_default() == "json")
        .map(|e| e.path().to_owned())
        .collect::<Vec<_>>()
}
