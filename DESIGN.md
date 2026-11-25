# Foster: Dokumen Desain (draft v0.1)

> **Satu kalimat:** Foster menambal package open source kritis yang sudah ditinggal maintainernya, lalu menyalurkan tambalan itu ke jutaan proyek yang masih memakainya. Foster tidak merebut nama package siapa pun.

Status: **v0.1 sudah diimplementasikan** (2026-11-26). Orphan Index, CLI `scan`/`fix`/`check`, server MCP, skill, GitHub Action, Patch Lab dengan tambalan pertama (`ip`), dan dokumen tata kelola semuanya sudah ada. Lihat README.md untuk pemakaian dan LAUNCH.md untuk langkah peluncuran. Dokumen ini adalah desain awal; bagian yang berubah saat implementasi dicatat di bawah.

Perubahan dari draf:
- Prioritas pertama ternyata bukan ambil alih package, tetapi **tambalan dengan namespace sendiri dan disalurkan lewat npm alias**. Tidak perlu fork nama, dan `require("ip")` tetap jalan.
- Hasil Orphan Index pertama (Nov 2026): 2.817 package kritis, 28% mati/dormant, dan setelah advisory malware dan advisory yang sudah teratasi di rilis lebih baru disaring, tersisa **5 advisory tanpa perbaikan di 4 package** (ip, extract-zip, elliptic, aws-sdk). Semuanya package yang tidak dirawat.
Nama kerja "Foster" sudah dipakai di npm, PyPI, dan sebagai org GitHub. Untuk sementara aku pakai `foster-oss`, karena nama itu masih kosong di npm, PyPI, dan GitHub (dicek 2026-11-26).

---

## 1. Masalah

Analisis Andrew Nesbitt (pembuat ecosyste.ms, Mei 2026) terhadap **8.606 package paling kritis** di 16 package manager:

| Status repo | Porsi |
|---|---|
| Aktif | 48,8% |
| Dormant | 20,2% |
| **Mati** (diarsipkan, atau setahun tidak ada respons dari pemegang akses tulis) | **12,1% (713 repo)** |
| Tidak diketahui | 18,9% |

- Repo yang mati menopang sekitar **290 juta** relasi dependent-repo. Kalau yang dormant dan tidak diketahui ikut dihitung, totalnya lewat **1 miliar**.
- Ada **110 advisory keamanan** di set kritis yang **tidak punya versi tambalan**.
- Ada **1.414** package mati atau dormant yang hak publish-nya dipegang **satu akun saja**.
- Di antara 713 repo mati, 243 punya PR yang dibuka tapi tidak satu pun di-merge. Perbaikannya sudah ada, tapi tidak pernah sampai ke registry.
- Yang mati bukan hanya package kecil. Contohnya `fast-deep-equal` dan `utils-merge`, yang masing-masing punya jutaan dependents.

Nesbitt juga menyebut celah yang belum diisi siapa pun:
1. Bahasa pemrograman **tidak punya "packager hilir"** seperti distro Linux, yang bisa merilis tambalan tanpa memiliki nama package-nya.
2. Aturan registry soal package terlantar mengasumsikan ada yang **ingin mengambil alih nama**, padahal yang sering dibutuhkan hanya **satu rilis perbaikan**.
3. **Version pin yang ketat** di package mati bisa memblokir rilis keamanan dependensi lain.

Dia menutup dengan seruan bahwa registry dan komunitasnya butuh "an actual process", tanpa mengusulkan mekanisme konkret. **Mekanisme itulah yang mau dibangun Foster.**

## 2. Kenapa sekarang

- **Jazzband tutup (Maret 2026).** Koperasi yang merawat 84 proyek Python (150 juta+ download per bulan) itu bubar. Penyebabnya dua: banjir PR dan issue spam buatan AI (mereka menyebutnya "slopocalypse") yang membuat model keanggotaan terbuka mustahil, dan operasional yang selama ini bergantung pada satu orang. Rumah untuk package yatim berkurang satu.
- **Abandonware makin cepat muncul.** Proyek buatan AI cepat lahir dan cepat ditinggal (LeadDev, 2026).
- **AI agent sekarang cukup mampu** mereproduksi bug, menulis tambalan, dan menulis test. Yang langka adalah **reviewer manusia yang bisa dipercaya** dan **jalur distribusi yang aman**.

## 3. Yang sudah ada vs celah

| Yang sudah ada | Apa yang dilakukan | Yang tidak dilakukan |
|---|---|---|
| ecosyste.ms, Package Health Check, freshdeps-mcp | Mendeteksi dan memberi label package mati | Tidak menambal apa pun |
| Dependabot, Renovate, Snyk Agent Fix | Menaikkan versi dependensi | Tidak membantu kalau versi tambalannya memang tidak ada |
| e18e / module-replacements | Menyarankan package pengganti modern | Mengharuskan migrasi kode; tidak menambal package lama |
| PEP 541 (PyPI) | Serah terima nama package terlantar | Prosesnya lambat; tidak ada padanannya di npm |
| Jazzband | Koperasi perawat proyek | Sudah tutup, dan tidak tahan spam AI |
| Chainguard Repository | Gateway package yang aman | Komersial; bukan perawat komunitas |

**Celah yang diisi Foster:** jalur yang terbuka, aman, dan bisa diaudit untuk menambal → mereview → merilis → menyalurkan perbaikan bagi package kritis yang mati.

> Catatan kejujuran: ini hasil beberapa kali pencarian, bukan audit menyeluruh. Langkah pertama sebelum menulis kode adalah menghubungi Nesbitt/ecosyste.ms dan menanyakan apakah ada yang sedang membangun hal serupa.

## 4. Prinsip desain

Prinsip ini diambil dari pelajaran kasus xz-utils dan bubarnya Jazzband:

1. **Tambal, bukan ambil alih.** Foster tidak pernah merebut nama package. Tambalan dirilis di namespace Foster sendiri. Nama asli hanya diambil lewat serah terima sukarela atau PEP 541, dan hanya kalau komunitas memintanya.
2. **Upstream dulu.** Setiap tambalan pertama-tama dikirim sebagai PR ke repo asli. Foster baru merilis sendiri kalau PR itu tidak direspons dalam batas waktu tertentu.
3. **AI mengusulkan, manusia memutuskan.** Agent boleh menulis tambalan dan test. Setiap rilis wajib disetujui **minimal 2 reviewer manusia** dari organisasi yang berbeda.
4. **Tidak ada keanggotaan terbuka dengan akses push.** Kontribusi terbuka lewat PR, tetapi hak merge dan rilis hanya dimiliki reviewer yang terverifikasi. Ini pelajaran langsung dari Jazzband.
5. **Rilis yang bisa diaudit.** Trusted publishing (OIDC), provenance Sigstore/npm, build yang reproducible, dan diff yang minimal terhadap versi asli.
6. **Bus factor ≥ 3 sejak awal.** Jangan jadi operasi satu orang. Kalau perlu, Foster lebih baik tumbuh lebih lambat.
7. **Bukan mesin spam.** PR yang dikirim Foster ke proyek orang lain dibatasi jumlahnya, ditulis dengan jelas, dan selalu ditandai kalau dibuat dengan bantuan AI.
8. **Diff sekecil mungkin.** Foster hanya memperbaiki keamanan dan kerusakan. Tidak ada fitur baru dan tidak ada refactor.

## 5. Komponen

```
            ┌───────────────────────────────┐
            │ 1. Orphan Index (data publik) │  ← ecosyste.ms, OSV/GHSA, registry API
            └──────────────┬────────────────┘
                           │ pilih kandidat
            ┌──────────────▼────────────────┐
            │ 2. Patch Lab (monorepo)       │  ← agent menulis tambalan + test
            │    review ≥2 manusia          │
            └──────┬───────────────┬────────┘
     PR ke upstream│               │ tidak direspons
                   ▼               ▼
         (selesai kalau     ┌──────────────────────────────┐
          di-merge)         │ 3. Rilis di @foster-oss/*     │  ← trusted publishing + provenance
                            └──────────────┬───────────────┘
                                           │
            ┌──────────────────────────────▼───────────────┐
            │ 4. foster CLI / GitHub Action / MCP + skill   │  ← menulis override ke proyek pengguna
            └──────────────────────────────────────────────┘
```

### 5.1 Orphan Index
- **Data:** set kritis ecosyste.ms (API publik, kira-kira 5.000 request/jam tanpa kunci), advisory dari OSV/GitHub Advisory Database, dan metadata registry.
- **Klasifikasi:** Aktif / Dormant / Mati / Tidak diketahui, memakai kriteria yang sama dengan Nesbitt supaya bisa dibandingkan.
- **Skor prioritas:** `dependents × keparahan advisory tanpa tambalan × lama tidak ada respons`.
- **Keluaran:** situs statis dan dataset JSON/CSV terbuka yang diperbarui setiap minggu. Inilah **pemicu viralnya**: angka yang mengejutkan dan bisa dikutip media.

### 5.2 Patch Lab
- Satu monorepo `foster-oss/patches`. Setiap package punya folder berisi: snapshot sumber asli, file patch, test reproduksi, dan `ADOPTION.md` (riwayat upaya menghubungi maintainer, alasan adopsi).
- **Alur agent:** reproduksi advisory dengan test yang gagal → tulis perbaikan minimal → test lulus → buka PR ke Patch Lab dengan label `ai-assisted`.
- **CI:** jalankan test asli dan test baru, hitung diff terhadap versi asli, cek lisensi, cek build reproducible.

### 5.3 Rilis
- **npm:** `@foster-oss/<nama-asli>`, dengan versi `<versi-asli>-foster.<n>`. Contoh: `@foster-oss/utils-merge@1.0.1-foster.1`.
- **PyPI:** PyPI tidak punya scope, jadi pakai awalan `foster-oss-<nama>`. Tetap utamakan PR ke upstream atau PEP 541 kalau memang layak.
- Setiap rilis dilengkapi provenance dan changelog yang menjelaskan **persis** apa yang diubah dan kenapa.

### 5.4 foster CLI, GitHub Action, MCP + skill
- `npx foster-oss scan`: membaca lockfile, lalu menampilkan dependensi yang mati dan punya advisory tanpa tambalan.
- `npx foster-oss fix`: menulis override ke proyek pengguna, yaitu `overrides` untuk npm, `pnpm.overrides`, `resolutions` untuk Yarn, dan `override-dependencies` untuk uv atau file constraints untuk pip.
- **GitHub Action:** menjalankan `scan` di CI dan memberi komentar di PR.
- **MCP server + skill** untuk Claude, Codex, dan agent lain: "sebelum menambah dependensi, cek ke Foster". Ini sejalan dengan tren 2026 bahwa tool harus bisa dipanggil agent.

> CLI dan Action yang berjalan di CI menghasilkan download dan dependents setiap kali dipakai. Ini mesin kelayakan program (lihat §8).

## 6. Siklus hidup adopsi

```
Terdeteksi → Diverifikasi mati → Upaya kontak (6 minggu, mengikuti PEP 541)
   → Tambalan ditulis → Review ≥2 manusia → PR ke upstream
        ├─ di-merge upstream → SELESAI (Foster tidak merilis apa pun)
        └─ tidak direspons N minggu → Rilis @foster-oss → Disalurkan lewat CLI/Action
               └─ maintainer kembali / ada pengganti → Kembalikan ke upstream, tandai deprecated
```

Kriteria agar sebuah package boleh diadopsi (semuanya wajib terpenuhi):
- termasuk set kritis ecosyste.ms, **atau** punya lebih dari 1.000 dependents;
- ada advisory atau kerusakan nyata yang **belum ditambal**;
- maintainer tidak merespons sesuai aturan di atas;
- lisensinya mengizinkan fork dan redistribusi.

## 7. Strategi viral dan peluncuran

Strategi ini mengikuti pola dari survey (`reports/Survey proyek GitHub viral bermanfaat.md`):

1. **Menumpang momentum.** Narasinya: "Jazzband tutup. Nesbitt menemukan 110 advisory tanpa tambalan. Siapa yang merawat package yatim?"
2. **Janji satu kalimat dan satu angka.** Contohnya: "X miliar download per bulan masuk ke package yang tidak dirawat siapa pun". Angka X **harus dihitung dari data asli** sebelum dipublikasikan.
3. **Demo ajaib.** Rekaman `npx foster-oss scan` pada proyek terkenal: menemukan dependensi mati, lalu `fix` dan test lulus, semuanya dalam 30 detik.
4. **Saluran:** Show HN (efeknya cepat hilang dengan half-life sekitar 24 jam, jadi harus jadi titik masuk ke sesuatu yang bertahan), r/programming, X, dan **langsung ke Nesbitt/ecosyste.ms dan komunitas OpenSSF**.
5. **Yang membuat proyek bertahan:** dataset mingguan, GitHub Action yang dipasang orang, dan rilis tambalan yang terus berjalan.

## 8. Peta ke syarat program

| Jalur | Cara Foster mencapainya | Kira-kira kapan |
|---|---|---|
| Anthropic: 20+ kontributor luar dengan PR di-merge dalam 12 bulan | Setiap adopsi butuh tambalan dan test; data index bisa dikoreksi lewat PR | 6–12 bulan |
| Anthropic: 100+ PR di-merge ke repo orang lain | PR tambalan ke upstream dan PR migrasi ke dependents (dibatasi, bukan spam) | 6–12 bulan |
| Anthropic: 500+ dependent repo / 200 ribu+ download per bulan | CLI dan Action di CI, ditambah package `@foster-oss/*` yang dipakai lewat override | 12–18 bulan, tidak pasti |
| Anthropic: OpenSSF criticality ≥ 0,4 | Infrastruktur supply chain dengan banyak kontributor dari banyak organisasi | 18+ bulan |
| OpenAI Codex for OSS | Cerita kuat soal "kepentingan ekosistem" ditambah data Orphan Index | Bisa daftar sejak ada bukti pemakaian pertama |

**Metrik yang dipantau sejak hari pertama:** kontributor luar unik dengan PR di-merge, PR ke repo lain yang di-merge, download per bulan, dependents (GitHub "Used by"), dan jumlah tambalan yang dirilis.

## 9. Roadmap

| Fase | Waktu | Hasil |
|---|---|---|
| 0. Validasi | Minggu 1–2 | Hubungi Nesbitt/ecosyste.ms; pastikan belum ada yang membangun; ajak 2–3 calon reviewer awal |
| 1. Orphan Index v0 | Minggu 2–5 | Pipeline data + situs statis + dataset; angka headline yang terverifikasi |
| 2. Tambalan pertama | Minggu 5–9 | 3 package npm dengan advisory tanpa tambalan: PR ke upstream, lalu rilis `@foster-oss` kalau tidak direspons |
| 3. CLI + Action | Minggu 8–12 | `scan` / `fix` untuk npm dan pnpm; GitHub Action |
| 4. Peluncuran | Bulan 3 | Show HN + demo + laporan Orphan Index |
| 5. Perluasan | Bulan 4–9 | PyPI (uv/pip), MCP server + skill, program reviewer, Hacktoberfest 2027 |
| 6. Kelembagaan | Bulan 9–18 | Pendanaan (Sovereign Tech Fund, Alpha-Omega, GitHub Secure OSS Fund), tata kelola formal, daftar ke program Anthropic dan OpenAI |

## 10. Risiko dan mitigasi

| Risiko | Mitigasi |
|---|---|
| **Dianggap pola serangan xz** (orang asing merilis kode untuk package populer) | Namespace sendiri, provenance, review oleh ≥2 manusia, diff minimal yang publik, tidak pernah mengambil nama |
| Maintainer asli tersinggung | Upstream dulu, kontak sopan sesuai aturan PEP 541, siap mengembalikan kapan saja |
| Jadi sumber spam AI | Batas PR per minggu, label `ai-assisted`, setiap PR harus disetujui manusia |
| Beban perawatan meledak | Mulai dari 3 package, kriteria adopsi ketat, tidak menerima fitur baru |
| Bergantung pada satu orang (seperti Jazzband) | Reviewer dari ≥3 organisasi sebelum rilis pertama |
| Pengguna tidak mau memakai override | Utamakan PR ke upstream; CLI membuat override cukup satu perintah |
| Registry mengubah aturan, atau menyediakan fitur serupa | Itu justru hasil yang baik. Foster bisa jadi bukti konsep yang mendorong registry. |
| Klaim "belum ada" ternyata salah | Fase 0 khusus untuk validasi; kalau sudah ada, bergabung dan berkontribusi ke sana |

## 11. Keputusan yang masih terbuka

1. **Nama final.** "Foster" sudah dipakai. Alternatif: `foster-oss`, atau nama lain.
2. **Stack.** Saran: TypeScript (Node) untuk CLI, Action, dan MCP, karena npm adalah ekosistem pertama. Pipeline data juga bisa TypeScript, atau Python kalau lebih nyaman.
3. **Ekosistem pertama.** Saran: npm (dead share 11,3%, komunitas terbesar). PyPI menyusul.
4. **Bahasa dokumentasi.** Saran: README dalam bahasa Inggris (target global), diskusi internal bebas.

## Sumber
- Nesbitt, "Weekend at Bernie's" (Mei 2026): https://nesbitt.io/2026/05/08/weekend-at-bernies
- Nesbitt, "Showing our work" (Mei 2026): https://nesbitt.io/2026/05/13/showing-our-work
- ecosyste.ms API: https://ecosyste.ms/api · Packages docs: https://docs.ecosyste.ms/docs/services/data-services/packages/
- Jazzband, "Sunsetting Jazzband" (14 Mar 2026): https://jazzband.co/news/2026/03/14/sunsetting-jazzband
- PEP 541: https://peps.python.org/pep-0541/ · PyPI name retention: https://docs.pypi.org/project-management/name-retention/
- npm Package Name Disputes: https://docs.npmjs.com/policies/disputes
- LeadDev, AI-generated abandonware: https://leaddev.com/software-quality/ai-generated-abandonware-is-hollowing-out-open-source
- Chainguard Repository: https://thenewstack.io/chainguard-repository-ai-agents/
- Package Health Check: https://apify.com/m_ctim/package-health-check · freshdeps-mcp: https://catalog.agentage.io/mcp/io-github-solvohq-freshdeps-mcp
- Laporan survey internal: `../reports/Survey proyek GitHub viral bermanfaat.md`

## Perubahan arah (26 Nov 2026, setelah repo terbit)

Saat menyiapkan kontak ke upstream `ip`, ternyata [Keep LTS](https://keep-lts.com) sudah menerbitkan
tambalan drop-in untuk 12 package npm terlantar (termasuk `ip` dan `extract-zip`), dengan model yang
sama seperti Patch Lab. Ada juga fork `@bybrave/ip2` dan PR perbaikan di upstream. Klaim "belum ada
yang membangun" di bagian 3 ternyata salah untuk bagian penambalan.

Keputusan: Foster menjadi **index dan scanner yang netral**. Registry menautkan tambalan dari
penyedia mana pun, dan Patch Lab hanya dipakai untuk celah yang belum ditambal siapa pun. Tambalan
`ip` milik Foster dipensiunkan (status `retired`) dan disimpan sebagai verifikasi independen.
