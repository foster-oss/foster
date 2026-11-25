# Panduan peluncuran Foster

Kode, data, dan tambalan pertama sudah selesai dan teruji di laptop. Langkah di bawah ini butuh
**akun dan keputusan kamu sendiri**: membuat organisasi, menerbitkan package, dan menghubungi
orang. Aku sengaja tidak melakukannya atas nama kamu. Urutannya sudah disusun supaya kamu bisa
mengikuti dari atas ke bawah.

## Minggu 1: buka ke publik

1. **Buat organisasi GitHub `foster-oss`** di github.com/organizations/new (gratis), lalu buat
   repo `foster` yang publik.
2. **Push kode:**
   ```powershell
   cd D:\DEV\SOCIETY-PROJECT\foster
   git remote add origin https://github.com/rekalnx/foster.git
   git push -u origin main
   ```
3. **Pengaturan repo** di GitHub, Settings:
   - Pages, Source = "GitHub Actions". Situs Orphan Index terbit setelah workflow `Orphan Index`
     dijalankan sekali (Actions → Orphan Index → Run workflow).
   - Code security: aktifkan *Private vulnerability reporting*.
   - Branches: lindungi `main` dengan "require pull request" dan "require status checks: CI".
   - Environments: buat `npm-release` dan `patch-release`. Isi *required reviewers* di `patch-release`
     setelah ada maintainer kedua.
4. **Buat organisasi npm `foster-oss`** di npmjs.com (gratis untuk package publik). Ini memberi
   scope `@foster-oss/*`.
5. **Terbitkan CLI-nya.** Untuk rilis pertama, cara paling mudah adalah `npm login` lalu
   `npm publish --access public` dari laptop. Setelah itu, aktifkan *Trusted publishing* di
   npmjs.com → foster-oss → Settings (GitHub Actions, repo `rekalnx/foster`, workflow `release.yml`,
   environment `npm-release`). Rilis berikutnya cukup: naikkan versi di package.json, commit, lalu
   `git tag v0.1.1 && git push --tags`.
6. **Buat tag `v0` untuk GitHub Action** supaya `uses: rekalnx/foster@v0` di README bisa dipakai:
   `git tag v0 && git push origin v0`. Setiap rilis baru, pindahkan tag ini dengan `git tag -f v0 && git push -f origin v0`.
7. **Isi `MAINTAINERS.md`** dengan akun GitHub kamu.

## Minggu 1–2: validasi dan kontak

8. **Hubungi Andrew Nesbitt / ecosyste.ms** (hello@ecosyste.ms, atau lewat Mastodon atau blognya).
   Tujuannya dua: memastikan belum ada yang membangun hal serupa, dan minta masukan soal metodologi.
   Draf pesan:

   > Hi Andrew, your "Weekend at Bernie's" post ended with registries needing "an actual process" for
   > unowned packages with valid CVEs. I've built an open prototype of one: Foster
   > (github.com/rekalnx/foster). It classifies the ecosyste.ms critical set weekly, and for dead
   > packages with unfixed advisories it publishes minimal, reproducible patches under its own scope
   > (never taking names). Projects switch to them through npm aliases. The first patch fixes the `ip`
   > SSRF (GHSA-2p57-rm9w-gvfp). I'd value your view on the methodology, and whether anyone else is
   > already doing this. Thanks for ecosyste.ms: Foster wouldn't exist without it.

9. **Mulai jendela 6 minggu untuk `ip`.** Buka issue atau PR di `indutny/node-ip` berisi
   `patches/npm/ip/fix.patch` dan tautan ke tesnya, lalu catat tanggalnya di `patches/npm/ip/ADOPTION.md`.
   Draf pesan:

   > Hi! GHSA-2p57-rm9w-gvfp is still open for `ip` 2.0.1 and many projects still depend on it
   > (~38M downloads/month). Here is a minimal patch (lib/ip.js only) that parses addresses numerically
   > before the range checks, with regression tests; your existing test suite still passes. We'd much
   > prefer you merge and release it here. If we don't hear back in six weeks, Foster will publish it as
   > `@foster-oss/ip` so affected users have an option, and will point everyone back here as soon as you
   > release a fix. Thank you for maintaining `ip` all these years.

10. **Cari 2 reviewer awal** dari organisasi lain. Tempat yang cocok: komunitas OpenSSF (Slack
   openssf.slack.com, channel #securing-critical-projects), forum Python Packaging, dan teman
   developer yang paham security.

## Bulan 1–3: peluncuran

11. **Show HN.** Luncurkan setelah situs Orphan Index aktif dan `npx foster-oss scan` sudah bisa
    dipakai. Waktu terbaik menurut riset kita: Selasa–Kamis pagi waktu AS. Ingat, lonjakan HN cepat
    habis (half-life sekitar 24 jam), jadi pastikan pengunjung bisa langsung mencoba. Draf judul:

    > Show HN: Foster – 28% of the most-used npm/PyPI packages are unmaintained; patching the dangerous ones

    Draf isi:

    > I classified the 2,817 most depended-on npm and PyPI packages (ecosyste.ms critical set). 790
    > are dead or dormant, together ~190B downloads/month. Four have security advisories that no
    > release fixes, e.g. `ip` (SSRF, 38M downloads/month) and `extract-zip` (path traversal, 113M).
    > Upgrade bots can't help when no fixed version exists, and registries only have processes for
    > taking over names. Foster is an open attempt at the missing piece: minimal, reviewed,
    > reproducible patches under its own scope, offered upstream first, delivered via npm aliases
    > (`npx foster-oss fix`). Index, method and patches are all public. Feedback on the governance
    > model is especially welcome: this is exactly what a supply-chain attack looks like if done wrong.

12. **Tambalan kedua: `extract-zip`** (113 juta download/bulan, 2 HIGH). Ini kandidat paling
    berdampak. Buka issue "Adopt: npm/extract-zip" dan ajak kontributor.
13. **Hacktoberfest 2027** (Oktober): beri label `hacktoberfest` dan `good first issue` pada tugas
    seperti dukungan Cargo/Go lockfile, koreksi index, atau tes tambahan. Ini mesin untuk target
    20+ kontributor luar.

## Pendaftaran program (setelah ada bukti pemakaian)

**Anthropic Claude for Open Source** (claude.com/contact-sales/claude-for-oss). Jalur yang paling
realistis untuk Foster: *20+ kontributor eksternal dalam 12 bulan*, *100+ PR yang di-merge ke repo
orang lain* (PR tambalan ke upstream ikut dihitung), atau "apply anyway" karena ekosistem bergantung padanya.

**OpenAI Codex for Open Source** (openai.com/form/codex-for-oss). Draf jawaban untuk "Why does this
repository qualify?" (maks 500 karakter):

> Foster keeps critical but abandoned npm/PyPI packages safe. Its weekly Orphan Index shows 790 of the
> 2,817 most depended-on packages are dead or dormant (~190B downloads/month), and 4 have security
> advisories no release fixes. Foster ships minimal, reviewed, reproducible patches (first: `ip` SSRF,
> 38M downloads/month) without taking names, and a CLI/GitHub Action/MCP server so projects and AI
> agents avoid orphaned dependencies.

Perbarui angka-angkanya dengan data terbaru sebelum mengirim.

## Metrik yang dipantau setiap bulan

- kontributor eksternal unik dengan PR di-merge (target 20 dalam 12 bulan);
- PR kamu yang di-merge di repo orang lain (target 100 dalam 12 bulan);
- download `foster-oss` per bulan (npmjs.com/package/foster-oss);
- repo yang memakai Action (`uses: rekalnx/foster`, cari lewat GitHub code search);
- jumlah tambalan yang sudah `released`.
