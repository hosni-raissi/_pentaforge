#!/bin/bash
set -e

BASE_DIR="/home/hosnizap/projects/PentaForge/server/share"

mkdir -p "$BASE_DIR/wordlists/dns"
mkdir -p "$BASE_DIR/wordlists/web"
mkdir -p "$BASE_DIR/seclists/Passwords/Common-Credentials"
mkdir -p "$BASE_DIR/seclists/Usernames"
mkdir -p "$BASE_DIR/seclists/Discovery/Web-Content"

echo "Downloading and sizing DNS..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -o "$BASE_DIR/wordlists/dns/subdomains_large.txt"
head -n 8000 "$BASE_DIR/wordlists/dns/subdomains_large.txt" > temp && mv temp "$BASE_DIR/wordlists/dns/subdomains_large.txt"
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -o "$BASE_DIR/wordlists/dns/subdomains_medium.txt"
head -n 3000 "$BASE_DIR/wordlists/dns/subdomains_medium.txt" > temp && mv temp "$BASE_DIR/wordlists/dns/subdomains_medium.txt"
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o "$BASE_DIR/wordlists/dns/subdomains_short.txt"
head -n 1000 "$BASE_DIR/wordlists/dns/subdomains_short.txt" > temp && mv temp "$BASE_DIR/wordlists/dns/subdomains_short.txt"

echo "Downloading and sizing WEB FILES..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt -o "$BASE_DIR/wordlists/web/files.txt"
head -n 8000 "$BASE_DIR/wordlists/web/files.txt" > "$BASE_DIR/wordlists/web/files_large.txt"
head -n 3000 "$BASE_DIR/wordlists/web/files.txt" > "$BASE_DIR/wordlists/web/files_medium.txt"
head -n 1000 "$BASE_DIR/wordlists/web/files.txt" > "$BASE_DIR/wordlists/web/files_short.txt"
rm "$BASE_DIR/wordlists/web/files.txt"

echo "Downloading and sizing WEB FOLDERS..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -o "$BASE_DIR/wordlists/web/folders.txt"
head -n 8000 "$BASE_DIR/wordlists/web/folders.txt" > "$BASE_DIR/wordlists/web/folders_large.txt"
head -n 3000 "$BASE_DIR/wordlists/web/folders.txt" > "$BASE_DIR/wordlists/web/folders_medium.txt"
head -n 1000 "$BASE_DIR/wordlists/web/folders.txt" > "$BASE_DIR/wordlists/web/folders_short.txt"
rm "$BASE_DIR/wordlists/web/folders.txt"

echo "Downloading and sizing PASSWORDS..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt -o "$BASE_DIR/seclists/Passwords/Common-Credentials/pass.txt"
head -n 8000 "$BASE_DIR/seclists/Passwords/Common-Credentials/pass.txt" > "$BASE_DIR/seclists/Passwords/Common-Credentials/passwords_large.txt"
head -n 3000 "$BASE_DIR/seclists/Passwords/Common-Credentials/pass.txt" > "$BASE_DIR/seclists/Passwords/Common-Credentials/passwords_medium.txt"
head -n 1000 "$BASE_DIR/seclists/Passwords/Common-Credentials/pass.txt" > "$BASE_DIR/seclists/Passwords/Common-Credentials/passwords_short.txt"
rm "$BASE_DIR/seclists/Passwords/Common-Credentials/pass.txt"

echo "Downloading and sizing USERNAMES..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt -o "$BASE_DIR/seclists/Usernames/names.txt"
head -n 8000 "$BASE_DIR/seclists/Usernames/names.txt" > "$BASE_DIR/seclists/Usernames/usernames_large.txt"
head -n 3000 "$BASE_DIR/seclists/Usernames/names.txt" > "$BASE_DIR/seclists/Usernames/usernames_medium.txt"
head -n 1000 "$BASE_DIR/seclists/Usernames/names.txt" > "$BASE_DIR/seclists/Usernames/usernames_short.txt"
rm "$BASE_DIR/seclists/Usernames/names.txt"

echo "Downloading and sizing WEB CONTENT (common pages)..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o "$BASE_DIR/seclists/Discovery/Web-Content/common.txt"
head -n 4000 "$BASE_DIR/seclists/Discovery/Web-Content/common.txt" > "$BASE_DIR/seclists/Discovery/Web-Content/common_large.txt"
head -n 2000 "$BASE_DIR/seclists/Discovery/Web-Content/common.txt" > "$BASE_DIR/seclists/Discovery/Web-Content/common_medium.txt"
head -n 500 "$BASE_DIR/seclists/Discovery/Web-Content/common.txt" > "$BASE_DIR/seclists/Discovery/Web-Content/common_short.txt"
rm "$BASE_DIR/seclists/Discovery/Web-Content/common.txt"

echo "Done restoring wordlists."
