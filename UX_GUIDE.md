# ASEP v2.9.6 — Manual Penggunaan Intelligence Workflow

ASEP menggunakan workflow berbasis **evidence readiness**, bukan wizard yang memaksa semua target melewati langkah yang sama. Tahap berikutnya hanya dibuka ketika evidence yang dibutuhkan sudah tersedia.

## 1. Alur utama

```text
ENV
  ↓
DISCOVER
  ↓
IDENTIFY
  ↓
SERVICES
  ↓
ANALYZE
  ↓
VALIDATE
  ↓
PATH
  ↓
ACTION
  ↓
SESSION
  ↓
REPORT
```

**Prinsip:** Evidence → Analysis → Validation → Action. Jangan menganggap port/service sebagai vulnerability sebelum divalidasi.

## 2. ENV — pahami mesin ASEP dan environment
1. Buka Dashboard.
2. Periksa **Scope** dan **Local Resource**.
3. Pastikan interface, network candidate, gateway, CPU, RAM dan disk terlihat normal.
4. Jika network belum diketahui, lanjut ke **DISCOVER**.

## 3. DISCOVER — Network Discovery
1. Buka **Network Discovery**.
2. ASEP mendeteksi network lokal secara pasif terlebih dahulu.
3. Pilih network yang memang merupakan environment pengujian.
4. Konfirmasi discovery.
5. Jalankan **DISCOVER HOSTS**.
6. ASEP menggunakan host-discovery-only pada tahap ini; discovery host tidak otomatis berarti port scan.
7. Periksa Active Hosts dan discovery history.

## 4. IDENTIFY — Target & Asset Identity
1. Buka **Targets**.
2. Pilih host yang ditemukan.
3. Periksa IP, hostname, MAC, manufacturer, asset type, network role dan confidence/basis.
4. Ingat: vendor/OUI adalah evidence vendor, bukan bukti mutlak bentuk fisik perangkat.
5. Jika asset baru berada di luar scope, ASEP boleh melakukan passive deep-dive untuk mencari hubungan; active testing menunggu konfirmasi scope.

## 5. SERVICES — Port & Service Discovery
1. Buka detail target.
2. Pilih **RUN SERVICE DISCOVERY**.
3. ASEP menjalankan service/version detection berbasis Nmap `-sV --top-ports 100`.
4. Setelah selesai, target detail menampilkan:
   - PORT
   - PROTO
   - STATE
   - SERVICE
   - PRODUCT / VERSION
   - DETECTION
5. Evidence disimpan sebagai `service_scan`.
6. Jika tidak ada service terbuka/teridentifikasi, ASEP menampilkan kondisi tersebut dan menyediakan **REFRESH SERVICE DISCOVERY**.
7. Untuk coverage lebih dalam, gunakan **Deep Recon** sesuai scope dan readiness.

Nmap `-sV` melakukan probing terhadap port untuk mengidentifikasi protokol, aplikasi dan versi bila tersedia; nama service dari nomor port saja tidak boleh diperlakukan sebagai kepastian.

## 6. ANALYZE — Intelligence
Setelah identity dan service evidence tersedia, buka **Intelligence**. ASEP merangkum:
- environment understanding
- asset types / network roles
- service landscape
- knowledge gaps
- readiness state
- Next Best Action
- evidence correlation

Raw JSON bukan output utama operator; gunakan detail evidence bila perlu audit teknis.

## 7. VALIDATE — verifikasi hypothesis
Gunakan Validation untuk memeriksa evidence yang sudah ditemukan.

Status penting:
- `OBSERVED` — teramati
- `INDICATOR` — indikator
- `HYPOTHESIS` — hipotesis
- `CONFIRMED` — tervalidasi
- `EXPLOITABLE` — ada kondisi eksploitasi yang tervalidasi
- `FALSE POSITIVE` — tidak terbukti
- `UNKNOWN` — evidence belum cukup

**Port terbuka ≠ vulnerability.** Versi software juga bukan bukti tunggal vulnerability karena patch dapat di-backport.

## 8. PATH — Attack Path
ASEP menghubungkan asset, identity, services, findings dan trust relationship untuk mencari candidate attack paths. Setiap path harus memiliki evidence dan next validation step.

## 9. ACTION — Exploitation
Exploitation tetap berada di belakang scope/policy dan approval. Untuk Metasploit, prinsipnya:

```text
Fingerprint
 → Module Match
 → CHECK
 → Vulnerable + In-Scope + Approval
 → RUN
 → Session / Evidence
```

Module match bukan vulnerability confirmation.

## 10. SESSION — Post-Exploitation
Jika action menghasilkan session, buka **Sessions**. Session dikelola sebagai persistent session; operator dapat refresh/background/interact/close sesuai capability yang tersedia. Post-session intelligence menggunakan evidence dan context, bukan asumsi.

## 11. REPORT — Findings, Evidence, Timeline, Reports
Sebelum report:
1. Re-check evidence.
2. Revalidate bila memungkinkan.
3. Periksa false positive.
4. Pastikan scope.
5. Verifikasi detail teknis/version/config.
6. Verifikasi exploitability dan impact.
7. Mapping CWE/CVE/CVSS/ATT&CK/OWASP hanya jika relevan dan didukung evidence.
8. Label uncertainty.

## 12. Aturan penggunaan harian
- **Objective > Tool**
- **Evidence > Assumption**
- **Attack Path > Finding Count**
- **Recommendation > Raw Output**
- **Validation > Confidence**
- **Context > Generic Severity**
- **Failure → Re-plan**
- **Scope selalu terlihat**
- **Kesimpulan penting harus traceable ke evidence**

## 13. Contoh workflow normal

```text
1. Dashboard
2. Network Discovery
3. Discover Hosts
4. Targets
5. Buka target
6. RUN SERVICE DISCOVERY
7. Lihat port/service/version jika ditemukan
8. Intelligence
9. Validate
10. Attack Paths
11. Action hanya setelah gate terpenuhi
12. Sessions jika session diperoleh
13. Findings / Evidence / Report
```

ASEP v2.9.6 menempatkan **service evidence sebagai input resmi Intelligence**, sehingga hasil port/service tidak lagi hanya tampil sebagai raw scan output.

## Comprehensive Network Scan (v2.9.9)

After automatic discovery has populated the live-host inventory, use **FULL NETWORK SCAN** on the Dashboard to perform an explicit comprehensive inventory scan against the currently live hosts on the directly connected local network. It checks TCP ports 1–65535 and performs Nmap service/version detection. UDP is not scanned. This can be resource- and time-intensive, so it is operator-triggered rather than part of the continuous 30-second awareness loop.

Results are persisted as `deep_service_scan` evidence and replace/enrich the target port/service inventory. The dashboard then shows the observed open ports and identified services. A port being open or a service being identified is observation/evidence, not a vulnerability finding.
