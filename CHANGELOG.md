# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/),
penomoran mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## [Unreleased]

## [1.3.0] - 2026-09-23

### Ditambahkan
- Pilihan bahasa antarmuka: Indonesia dan Inggris, lewat tombol di bilah alat.
  Pilihan disimpan di peramban, dan bahasa pertama mengikuti pengaturan peramban.
- Pesan galat dari server kini membawa kode tetap, sehingga antarmuka bisa
  menampilkannya dalam bahasa yang sedang dipakai.

### Diperbaiki
- Menu aksi per berkas kini bisa digulir. Sebelumnya, pada layar pendek daftar
  aksi terpotong sehingga **Ganti nama** dan **Hapus** tidak terlihat.
- **Ganti nama** dipindah ke urutan teratas menu aksi, dan lembarnya menampilkan
  path lengkap berkas yang sedang diganti.
- Bilah pilihan menyembunyikan Salin, Potong, dan Hapus saat mode baca saja aktif;
  sebelumnya tombolnya tetap muncul lalu ditolak server.

## [1.2.0] - 2026-09-23

### Ditambahkan
- Papan klip: pilih item lalu **Salin** atau **Potong**, buka folder tujuan, tekan
  tombol tempel. Nama yang bentrok otomatis diberi akhiran `(1)`, `(2)`, dan seterusnya.
- **Duplikat** satu item di tempat, tanpa perlu berpindah folder.
- **Ekstrak** arsip `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, dan `.tar.xz`
  ke folder baru di sebelahnya.
- **Cari** berdasarkan nama file secara rekursif dari folder yang sedang dibuka.
- Urutkan daftar menurut nama, ukuran, atau waktu ubah.
- Tombol tampilkan/sembunyikan berkas bertitik, dan pilih semua/batal pilih.
- Ubah izin jalankan berkas (`chmod +x`) lewat menu aksi.
- Endpoint baru: `POST /api/copy`, `/api/duplicate`, `/api/extract`, `/api/chmod`,
  dan `GET /api/search`.

### Diubah
- Memindahkan berkas ke folder yang sudah punya nama sama tidak lagi menimpa diam-diam;
  berkas baru diberi akhiran bernomor.

### Keamanan
- Ekstraksi arsip menolak entri yang menunjuk ke luar folder tujuan; arsip tar
  diekstrak dengan filter `data` sehingga tautan simbolik dan berkas khusus diabaikan.

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

[Unreleased]: https://github.com/crypmiy/filehub/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/crypmiy/filehub/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/crypmiy/filehub/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/crypmiy/filehub/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/crypmiy/filehub/releases/tag/v1.0.0
