# Panduan peluncuran Foster

## Status (26 Nov 2026)

Sudah selesai:

- Paket npm **foster-oss@0.2.0** sudah terbit (27 Nov 2026): `npx foster-oss scan` bisa dipakai siapa saja.
- Organisasi GitHub **foster-oss** (owner: rekalnx) dengan logo Foster sebagai foto profil.
- Repo publik: <https://github.com/foster-oss/foster>, dipindah dari `rekalnx/foster` (URL lama otomatis diarahkan ke sini). CI lulus.
- Foster 0.2: 6 ekosistem, SBOM, monorepo (`--recursive`), saran pengganti, SARIF, dan laporan mingguan.
  Kode inti sudah di-review; 12 bug yang ditemukan sudah diperbaiki dan dikunci dengan tes regresi.
- Situs Orphan Index: <https://foster-oss.github.io/foster/>, dibangun ulang setiap Senin lewat GitHub Actions.
- Tag `v0` untuk GitHub Action.
- Registry berisi 12 tambalan drop-in yang sudah dirilis (dari Keep LTS). `foster-oss fix` sudah
  teruji end-to-end: setelah fix dan `npm install`, `socks` langsung memuat `@keep-lts/ip`, dan
  celah SSRF-nya tertutup.

**Perubahan arah.** Saat menyiapkan kontak ke upstream `ip`, ternyata
[Keep LTS](https://keep-lts.com) sudah menerbitkan tambalan drop-in untuk 12 package terlantar,
termasuk `ip` dan `extract-zip`, dengan model yang sama persis seperti Patch Lab Foster. Jadi Foster
sekarang tidak menerbitkan tambalan duplikat. Peran Foster adalah index dan scanner yang netral:
menunjukkan dependency mana yang terlantar, lalu menghubungkannya ke tambalan dari penyedia mana pun.
Tambalan `ip` buatan Foster dipensiunkan, dan foldernya tetap disimpan sebagai verifikasi independen.
Aku tidak mengirim pesan apa pun ke upstream, karena issue `ip` sudah punya tiga solusi (Keep LTS,
`@bybrave/ip2`, dan PR #166).

## Langkah yang butuh akun kamu

1. **~~Terbitkan CLI ke npm~~ (sudah, 0.2.0).** Untuk rilis berikutnya, aktifkan Trusted publishing (di bawah)
   supaya rilis lewat CI tanpa token. Perintah publish manual, untuk referensi:
   ```powershell
   cd D:\DEV\SOCIETY-PROJECT\foster
   npm login
   npm publish --access public
   ```
   Nama `foster-oss` masih kosong di npm (dicek 26 Nov). Setelah rilis pertama, aktifkan
   *Trusted publishing* di npmjs.com → package foster-oss → Settings (GitHub Actions, repo
   `foster-oss/foster`, workflow `release.yml`, environment `npm-release`). Rilis berikutnya cukup:
   naikkan versi, commit, lalu `git tag v0.1.1 && git push --tags`.
2. **Pengaturan repo** (opsional, tapi disarankan):
   - Settings → Code security → aktifkan *Private vulnerability reporting*.
   - Settings → Branches → lindungi `main` (require status checks: CI).

## Kontak (draf, kirim sendiri kalau setuju)

4. **Keep LTS** (hello@keep-lts.com). Kabari bahwa Foster menautkan tambalan mereka, lalu tawarkan
   dua hal: Orphan Index sebagai sumber kandidat package berikutnya, dan agar mereka menambah entri
   registry sendiri lewat PR.

   > Hi! I maintain Foster (github.com/foster-oss/foster), an open, vendor-neutral scanner and weekly
   > index of abandoned npm/PyPI packages (foster-oss.github.io/foster). `foster-oss fix` now points
   > projects at your drop-in releases (all 12 are in our registry, credited to Keep LTS). Two ideas:
   > the Orphan Index lists orphaned packages with unfixed advisories that might be useful for your
   > roadmap (e.g. elliptic), and you're very welcome to add new releases to registry/patches.json by
   > PR. Happy to adjust how we describe Keep LTS. Thanks for doing this work.

5. **Andrew Nesbitt / ecosyste.ms** (hello@ecosyste.ms). Minta masukan soal metodologi index.

   > Hi Andrew, your "Weekend at Bernie's" post was the starting point for Foster
   > (github.com/foster-oss/foster): a weekly, public classification of the ecosyste.ms critical set
   > (foster-oss.github.io/foster), plus a scanner that tells projects which of their dependencies are
   > orphaned and links them to published drop-in patches when they exist. I approximated your "no
   > write-access response" rule with closes/merges (METHODOLOGY.md) and would value your view on it.
   > Thanks for ecosyste.ms: Foster wouldn't exist without it.

## Peluncuran (setelah npm siap)

6. **Show HN.** Waktu terbaik: Selasa–Kamis pagi waktu AS. Lonjakan HN cepat habis (half-life
   sekitar 24 jam), jadi pastikan pengunjung bisa langsung mencoba.

   > **Show HN: Foster – 28% of the most depended-on npm/PyPI packages are unmaintained**
   >
   > I classified the 2,817 most depended-on npm and PyPI packages (the ecosyste.ms critical set):
   > 790 are dead or dormant, together ~190B downloads/month. A few have security advisories that no
   > upstream release fixes, e.g. ip (SSRF) and extract-zip (path traversal). `npm audit` just says
   > "no fix available", but often someone *has* published a drop-in fix. Foster connects the two:
   > `npx foster-oss scan` tells you which of your dependencies are orphaned and which have a published
   > patch, and `foster-oss fix` switches to it via an npm alias, no code changes. The index is public
   > and rebuilt weekly; there's also a GitHub Action and an MCP server so AI agents check packages
   > before adding them. Feedback on the methodology is very welcome.

7. **Hacktoberfest 2027** (Oktober): beri label `hacktoberfest` dan `good first issue` pada tugas
   seperti dukungan lockfile Cargo/Go/Maven, `fix` untuk Python, koreksi index, dan entri registry.
   Ini mesin untuk target 20+ kontributor luar.

## Pendaftaran program (setelah ada bukti pemakaian)

**Anthropic Claude for Open Source** (claude.com/contact-sales/claude-for-oss). Jalur paling
realistis: *20+ kontributor eksternal dalam 12 bulan*, atau *100+ PR yang di-merge ke repo orang
lain*. Jalur kedua ini paling bisa kamu kendalikan: perbaikan kecil di library populer, sekitar 2 per minggu.

**OpenAI Codex for Open Source** (openai.com/form/codex-for-oss). Draf jawaban (maks 500 karakter):

> Foster helps projects find dependencies nobody maintains. Its weekly public Orphan Index shows 790
> of the 2,817 most depended-on npm/PyPI packages are dead or dormant (~190B downloads/month). The
> foster-oss CLI, GitHub Action and MCP server flag orphaned and unfixable dependencies and switch
> projects to published drop-in security patches via npm aliases, so developers and AI agents stop
> shipping abandoned, vulnerable code.

Perbarui angka-angkanya dengan data terbaru sebelum mengirim.

## Metrik yang dipantau setiap bulan

- download `foster-oss` per bulan (npmjs.com/package/foster-oss);
- repo yang memakai Action (`uses: foster-oss/foster`, cari lewat GitHub code search);
- kontributor eksternal unik dengan PR di-merge (target 20 dalam 12 bulan);
- PR kamu yang di-merge di repo orang lain (target 100 dalam 12 bulan);
- jumlah entri di registry tambalan.
