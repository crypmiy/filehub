# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/),
penomoran mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## [Unreleased]

## [1.1.0] - 2026-09-15

### Ditambahkan
- Tombol "Unduh" pada baris aksi pilihan: satu file terpilih langsung terunduh
  apa adanya, beberapa item terpilih dibungkus jadi satu arsip `.zip`.
- Endpoint `GET /api/bundle` yang menerima banyak parameter `paths`.

## [1.0.0] - 2026-09-15

Rilis pertama.

### Ditambahkan
- Penjelajah direktori dengan breadcrumb dan info ukuran, waktu ubah, serta mode file.
- Unggah banyak file sekaligus, termasuk drag-and-drop.
- Unduh file satuan dan unduh folder sebagai arsip `.zip`.
- Editor teks bawaan untuk file di bawah 2 MB dengan penyimpanan atomik.
- Pratinjau gambar di dalam halaman.
- Buat folder, buat file, ganti nama, pindahkan, dan hapus massal.
- Login opsional berbasis password dengan cookie bertanda tangan HMAC.
- Mode baca saja lewat `FILEHUB_READONLY`.
- Indikator sisa ruang disk.
- Endpoint `/health` untuk pemeriksaan service.

### Keamanan
- Semua path divalidasi terhadap `FILEHUB_ROOT`; percobaan keluar root ditolak.
- Password dibandingkan dengan `hmac.compare_digest` dan diberi jeda saat gagal.
- Default bind ke `127.0.0.1`; akses dari luar diharapkan lewat Tailscale.

[Unreleased]: https://github.com/crypmiy/filehub/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/crypmiy/filehub/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/crypmiy/filehub/releases/tag/v1.0.0
