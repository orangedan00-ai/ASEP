# ASEP — Manual Penggunaan

## Daftar Isi
1. [Overview](#overview)
2. [Setup Awal](#setup-awal)
3. [Dashboard Utama](#dashboard-utama)
4. [Discovery & Network Scan](#discovery--network-scan)
5. [Target Inventory](#target-inventory)
6. [Intelligence](#intelligence)
7. [Autonomous Attack Workflow](#autonomous-attack-workflow)
8. [Exploitation & Sessions](#exploitation--sessions)
9. [Post-Exploitation & Demo Account](#post-exploitation--demo-account)
10. [Skill Reasoning (LLM)](#skill-reasoning-llm)
11. [Troubleshooting](#troubleshooting)

---

## Overview

ASEP (Advanced Security Evaluation Platform) adalah platform assessment keamanan berbasis evidence. **Selalu butuh otorisasi tertulis sebelum pengujian aktif.**

### Indikator Status
| Badge | Arti |
|-------|------|
| ⏳ RUNNING | Proses sedang berjalan |
| ✓ COMPLETE | Proses selesai |
| ✗ ERROR | Terjadi kesalahan |
| ⚡ ATTACK READY | Target punya cukup informasi untuk serangan autonomous |
| ⚠ DEEP SCAN FAILED | Scan mendalam gagal pada IP tersebut |

### Activity Ticker (Topbar)
Bar di pojok kanan atas menampilkan proses yang sedang berjalan secara realtime.

---

## Setup Awal

### .env Wajib
```
ASEP_SHELL_ENABLED=true           # Aktifkan shell lokal
ASEP_INTERNET_RESEARCH_ENABLED=true  # Aktifkan NVD CVE lookup
ASEP_LLM_MODE=auto               # auto / cloud / local / claude_code
```

### LLM
- **Settings** → dropdown LLM mode → pilih → **Terapkan**
- Badge internet (🌐) di dashboard menunjukkan status koneksi

---

## Dashboard Utama

- **Live Assets**: IP aktif di jaringan, refresh tiap 5 detik
- **Badge ⚠**: IP yang gagal deep scan + tooltip error
- **LLM Badge**: mode aktif + WORKING saat LLM sedang berpikir
- **Klik Attack Graph**: zoom in/out dengan scroll wheel, drag untuk pan

---

## Discovery & Network Scan

### Target & Active Hosts (menu Targets)
1. Klik **Discover Current Network** → deteksi jaringan otomatis
2. Klik **Discover Hosts** pada subnet yang muncul
3. **Deep Scan** jalan otomatis setelah host ditemukan (default concurrency=3)
4. Logo **Windows** 🪟 atau **Linux** 🐧 muncul di kartu target setelah OS terdeteksi dari hasil scan

### Captive Portal / Client Isolation
Kalau Live Assets kosong: lihat pesan diagnostik di panel. Kemungkinan:
- Captive portal belum login
- AP Isolation aktif — matikan di admin panel AP Anda

---

## Target Inventory

### OS Logo
- 🪟 Windows (terdeteksi dari `OS Name` di hasil scan — harus dari data scan, bukan tebakan)
- 🐧 Linux (terdeteksi dari `uname`, banner service, dll)

### Kandidat Exploit
Klik **🔎 CEK KANDIDAT EXPLOIT** di kartu target:
1. Hanya untuk service dengan `product`/`version` yang teridentifikasi
2. Cek dari 3 sumber: **Metasploit lokal** + **ExploitDB (searchsploit)** + **NVD CVE**
3. Semua hasil berlabel **CANDIDATE** — wajib verifikasi manual
4. Klik **🧠 Analisis dengan Skill Reasoning** → Intelligence page dengan konteks terisi otomatis

---

## Intelligence

### Klik Metrik yang Bisa Diklik
Di **Intelligence → ASEP Intelligence**, klik kartu metrik:
- **ACTIVE HOSTS** → popup daftar host aktif + detail
- **IDENTIFIED** → host dengan identity evidence
- **SERVICES** → host dengan service evidence
- **PLATFORM** → host dengan role/platform teridentifikasi
- **CONFIRMED** → validated findings

### Attack Graph Zoom
- **Scroll wheel** → zoom in/out
- **Drag** → pan
- **Tombol ＋ / － / ⤢** → zoom kontrol
- **Klik node di Attack Paths** → popup informasi node

---

## Autonomous Attack Workflow

Menu **⚡ Autonomous Attack** di sidebar (merah).

Target muncul di sini **hanya jika**:
- Deep Scan sudah selesai
- Ada service dengan product/version
- Ada ≥2 evidence items

### 6 Langkah Workflow (step terkunci sampai step sebelumnya selesai)
1. **Konfirmasi scope & otorisasi** — operator harus klik konfirmasi
2. **Cari kandidat exploit** — Metasploit + ExploitDB + NVD otomatis
3. **Validasi & pilih exploit terbaik** — kandidat terbaik dipilih
4. **CHECK** — cek modul sebelum eksekusi (TIDAK otomatis)
5. **RUN** — eksekusi exploit (butuh approve operator lagi)
6. **Analisis session** — intelligence otomatis dari session aktif

---

## Exploitation & Sessions

### Metasploit
- **Exploitation → Metasploit** → auto match dari service evidence
- **CHECK** sebelum **RUN** — ini aturan baku ASEP
- Session aktif muncul di **Sessions**

### Shell Lokal (OPERATIONS → Shell)
- Butuh `ASEP_SHELL_ENABLED=true` di .env
- Field "Shell Command" diisi perintah (bukan IP)
- Hasil tampil formatted, bukan raw JSON
- Semua perintah tercatat di audit log

---

## Post-Exploitation & Demo Account

### Probe Session (Sessions → Probe)
Setelah session Metasploit terbuka:
1. Masuk ke **Sessions**
2. Isi `controller_id` dan `session_id`
3. Klik **Probe Session** → ASEP otomatis: deteksi OS, user, privilege, interface jaringan
4. Hasilnya masuk ke evidence trail

### Demo Account
**Hanya tersedia jika**:
- OS teridentifikasi (linux/windows, bukan "unknown")
- Privilege cukup (root/administrator)
- Username selalu `asep_demo_<timestamp>`

**PENTING**: Cleanup demo account **HANYA** via tombol di UI + konfirmasi dua kali. ASEP tidak pernah auto-hapus.

---

## Skill Reasoning (LLM)

**Intelligence → Skill Reasoning**:
1. Pilih skill dari dropdown (Auto = pilih otomatis dari konteks)
2. Isi konteks (evidence, target, tujuan)
3. Klik **Jalankan Reasoning**

### Entry Point dari Halaman Lain
- **Target Inventory** → setelah CEK KANDIDAT EXPLOIT → **🧠 Analisis dengan Skill Reasoning**
- **Attack Paths** → tombol **🧠 Analisis dengan Skill Reasoning**
- Kedua entry point otomatis mengisi konteks dari data yang ada

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| Shell tidak jalan | Set `ASEP_SHELL_ENABLED=true` di `.env`, restart ASEP |
| Live Assets kosong | Cek captive portal / AP isolation; lihat pesan diagnostik |
| Recommend Capabilities tidak ada hasil | Isi Objective + Target, pastikan API `/api/capabilities/recommend` accessible |
| Deep Scan ⚠ | Lihat tooltip error di badge IP yang gagal |
| ExploitDB tidak jalan | `apt install exploitdb && searchsploit -u` |
| LLM tidak jalan | Cek Settings → Internet (harus ONLINE) + Provider health |

---

*ASEP v2.9.33 — Selalu jalankan dalam lingkungan yang sudah diberi otorisasi*
