# VMess Decode + Geo + Connectivity Report

Tool Python untuk:
- parse daftar `vmess://` dari `vmess_configs.txt`
- decode VMess base64 JSON / URI-style
- resolve domain ke IP
- lookup geolocation IP (ipgeolocation.io + fallback ip-api)
- cek konektivitas VMess (via `xray` + `curl ifconfig.me/ip`)
- generate `report.json` dan `report.html` dengan UI filter modern

## Requirements

- Python 3.9+
- `curl`
- `xray` binary di PATH (wajib untuk connectivity check yang akurat)

## Install Xray (Google Colab)

Jalankan cell berikut:

```bash
!curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
!unzip -o xray.zip -d xray-bin
!chmod +x xray-bin/xray
!./xray-bin/xray version
```

Saat run script, inject PATH di command yang sama:

```bash
!PATH="$PWD/xray-bin:$PATH" python vmess_report.py
```

## Input

- Default source: `https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt`
- Jika `-i/--input` diarahkan ke file lokal dan file itu ada, script akan pakai file lokal.
- Script akan ekstrak semua token `vmess://...` dari file text campuran.

## Output

- `report.json`: data hasil parse/geo/connectivity
- `report.html`: UI filter (search, country, ISP, connectivity) + tombol copy VMess

## Usage

### 1) Proses penuh dari file config

```bash
python vmess_report.py
```

### 2) Testing sebagian entry saja

```bash
python vmess_report.py --max-entries 10
```

### 3) Proses semua entry

```bash
python vmess_report.py --all
```

### 4) Aktifkan connectivity check (recommended)

```bash
python vmess_report.py --check-connectivity --connect-timeout 10 --connect-workers 40
```

### 4b) Nonaktifkan connectivity check (opsional)

```bash
python vmess_report.py --no-check-connectivity
```

### 5) Generate HTML dari JSON yang sudah ada (tanpa parse ulang config)

```bash
python vmess_report.py --report-only --report-json report.json --output report_updated.html
```

### 6) Update connectivity di JSON existing + regenerate HTML

```bash
python vmess_report.py --report-only --report-json report.json --check-connectivity --connect-timeout 10 --connect-workers 40 --output report_updated.html
```

## Argumen Penting

- `-i, --input` path file vmess text (default: remote VMess source URL)
- `-o, --output` path output HTML (default: `report.html`)
- `--json` path output JSON saat mode normal (default: `report.json`)
- `--report-only` generate HTML dari JSON existing
- `--report-json` path JSON untuk mode `--report-only`
- `--max-entries` batasi jumlah entry (default: `0` = all)
- `--all` paksa proses semua entry
- `--timeout` timeout lookup geolocation
- `--check-connectivity` / `--no-check-connectivity` toggle test konektivitas VMess (default: aktif)
- `--connect-timeout` budget waktu per VMess connectivity check (default: `10`)
- `--connect-workers` jumlah worker paralel connectivity check (default: `80`)
- `--no-progress` nonaktifkan progress bar CLI

## Catatan Connectivity

- Status `ok`: `ifconfig.me/ip` via VMess cocok dengan salah satu IP endpoint valid.
- Status `not matched`: koneksi ada, tapi IP keluar tidak cocok.
- Status `failed`: VMess tidak bisa dipakai untuk load `ifconfig.me/ip` dalam budget waktu.
- Status `skipped`: entry geolocation/status awal tidak layak diuji.

## GitHub Actions + GitHub Pages

Workflow sudah disiapkan di `.github/workflows/report-pages.yml` dengan fitur:

- schedule otomatis tiap 6 jam (`0 */6 * * *`)
- trigger manual (`workflow_dispatch`)
- deploy hasil report ke GitHub Pages via GitHub Actions

### Cara pakai

1. Push repository ini ke GitHub.
2. Di GitHub repo, buka **Settings -> Pages**.
3. Pada **Build and deployment**, set **Source** ke **GitHub Actions**.
4. Jalankan workflow `Build And Deploy VMess Report`.

### Auto-update deskripsi repo dengan URL public

Workflow juga akan mencoba menulis URL GitHub Pages ke deskripsi repo dalam format `Pages: <url>`.

- Disarankan set secret `REPO_DESC_TOKEN` di **Settings -> Secrets and variables -> Actions**.
- Nilai secret: GitHub PAT dengan scope `repo` (dan `workflow` jika kamu juga push perubahan workflow via token itu).
- Jika secret tidak ada / izin kurang, deploy tetap jalan karena step ini `continue-on-error`.

### Trigger manual opsional

Saat menjalankan manual (`Run workflow`), tersedia input:

- `check_connectivity` (`true/false`): jalankan connectivity check via xray.
- `max_entries` (`0` = semua): batasi jumlah entry yang diproses.

Output Pages:

- `index.html` (report utama)
- `report.json` (data mentah)
