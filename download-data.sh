#!/bin/bash

set -eo pipefail

[ -d data ] || mkdir data

if [ ! -d data/advisory-database-main ]; then
  echo "Downloading advisory database from GitHub"
  wget -O data/advisory-database-main.zip \
    https://github.com/github/advisory-database/archive/refs/heads/main.zip

  echo "Extracting advisory database"
  unzip -q -d data data/advisory-database-main.zip

  rm data/advisory-database-main.zip
fi

echo "Advisory database downloaded"

[ -d data/cwes ] || mkdir data/cwes
if [ ! -f data/cwes/699.csv ]; then
  echo "Downloading software development CWEs"
  wget -O data/cwes/699.csv.zip https://cwe.mitre.org/data/csv/699.csv.zip
  unzip -q -d data/cwes data/cwes/699.csv.zip
  rm data/cwes/699.csv.zip
fi

if [ ! -f data/cwes/1194.csv ]; then
  echo "Downloading hardware design CWEs"
  wget -O data/cwes/1194.csv.zip https://cwe.mitre.org/data/csv/1194.csv.zip
  unzip -q -d data/cwes data/cwes/1194.csv.zip
  rm data/cwes/1194.csv.zip
fi

if [ ! -f data/cwes/1000.csv ]; then
  echo "Downloading research concepts CWEs"
  wget -O data/cwes/1000.csv.zip https://cwe.mitre.org/data/csv/1000.csv.zip
  unzip -q -d data/cwes data/cwes/1000.csv.zip
  rm data/cwes/1000.csv.zip
fi

echo "CWE data downloaded"

echo Done
