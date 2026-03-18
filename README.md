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
!PATH="$PWD/xray-bin:$PATH" python vmess_report.py --check-connectivity --connect-timeout 10 --connect-workers 40
```

## Input

- Default input: `vmess_configs.txt`
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

### 5) Generate HTML dari JSON yang sudah ada (tanpa parse ulang config)

```bash
python vmess_report.py --report-only --report-json report.json --output report_updated.html
```

### 6) Update connectivity di JSON existing + regenerate HTML

```bash
python vmess_report.py --report-only --report-json report.json --check-connectivity --connect-timeout 10 --connect-workers 40 --output report_updated.html
```

## Argumen Penting

- `-i, --input` path file vmess text (default: `vmess_configs.txt`)
- `-o, --output` path output HTML (default: `report.html`)
- `--json` path output JSON saat mode normal (default: `report.json`)
- `--report-only` generate HTML dari JSON existing
- `--report-json` path JSON untuk mode `--report-only`
- `--max-entries` batasi jumlah entry (default: `0` = all)
- `--all` paksa proses semua entry
- `--timeout` timeout lookup geolocation
- `--check-connectivity` aktifkan test konektivitas VMess
- `--connect-timeout` budget waktu per VMess connectivity check (default: `10`)
- `--connect-workers` jumlah worker paralel connectivity check (default: `80`)
- `--no-progress` nonaktifkan progress bar CLI

## Catatan Connectivity

- Status `ok`: `ifconfig.me/ip` via VMess cocok dengan salah satu IP endpoint valid.
- Status `not matched`: koneksi ada, tapi IP keluar tidak cocok.
- Status `failed`: VMess tidak bisa dipakai untuk load `ifconfig.me/ip` dalam budget waktu.
- Status `skipped`: entry geolocation/status awal tidak layak diuji.
