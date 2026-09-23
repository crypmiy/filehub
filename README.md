# filehub

Pengelola file berbasis web dalam satu berkas Python. Dibuat untuk mengurus isi
Jetson Orin Nano dari ponsel atau laptop lewat Tailscale, tanpa perlu membuka
sesi SSH.

Tampilan dirancang untuk layar sempit lebih dulu: daftar file satu kolom, aksi
lewat lembar geser, dan tombol besar yang enak ditekan dengan jempol.

## Kemampuan

- Jelajah direktori dengan breadcrumb, ukuran, waktu ubah, dan mode file
- Unggah banyak file sekaligus, termasuk seret-dan-lepas
- Unduh file satuan, satu folder penuh, atau beberapa item terpilih sebagai `.zip`
- Editor teks bawaan untuk file di bawah 2 MB, penyimpanan atomik
- Pratinjau gambar langsung di halaman
- Buat folder, buat file, ganti nama, duplikat, hapus massal
- Salin dan pindahkan lewat papan klip, dengan penanganan nama bentrok
- Ekstrak arsip `.zip` dan `.tar.*` ke folder baru
- Cari nama berkas secara rekursif, urutkan menurut nama/ukuran/waktu
- Tampilkan berkas bertitik, pilih semua, ubah izin jalankan (`chmod +x`)
- Login password opsional, mode baca saja, indikator sisa disk

## Pemasangan

```bash
git clone https://github.com/crypmiy/filehub.git ~/filehub
cd ~/filehub
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp filehub.env.example filehub.env && chmod 600 filehub.env
```

Buka `filehub.env`, isi `FILEHUB_PASSWORD` dan `FILEHUB_SECRET` dengan nilai
sendiri, lalu jalankan:

```bash
set -a; . ./filehub.env; set +a
python filehub.py
```

## Pengaturan

| Variabel | Bawaan | Keterangan |
| --- | --- | --- |
| `FILEHUB_ROOT` | `/home/jetson` | Direktori paling atas yang boleh dibuka |
| `FILEHUB_PASSWORD` | kosong | Kosong berarti tanpa login |
| `FILEHUB_SECRET` | acak tiap restart | Kunci tanda tangan cookie; isi agar sesi bertahan |
| `FILEHUB_HOST` | `127.0.0.1` | Alamat bind |
| `FILEHUB_PORT` | `8791` | Port bind |
| `FILEHUB_READONLY` | `0` | Isi `1` untuk menonaktifkan semua perubahan |

## Menjalankan sebagai service

```bash
sudo cp deploy/filehub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now filehub
```

Sesuaikan `User` dan jalur di berkas service bila akun atau lokasinya berbeda.

## Akses lewat Tailscale

```bash
sudo tailscale serve --bg --set-path /files http://127.0.0.1:8791
tailscale serve status
```

Alamatnya menjadi `https://<nama-mesin>.<tailnet>.ts.net/files/`.

Konfigurasi Tailscale Serve berlaku untuk seluruh mesin. Selalu pakai
`--set-path` agar tidak menimpa aplikasi lain, dan hindari `tailscale serve
reset` yang menghapus semua pemetaan sekaligus.

## Catatan keamanan

Semua path dicocokkan ulang terhadap `FILEHUB_ROOT`, sehingga permintaan yang
mencoba keluar dari root ditolak. Password dibandingkan dengan waktu tetap dan
sesi disimpan pada cookie bertanda tangan HMAC.

Meski begitu, aplikasi ini ditujukan untuk jaringan pribadi. Biarkan bind pada
`127.0.0.1` dan andalkan Tailscale sebagai lapisan akses. Jangan paparkan ke
internet publik lewat Funnel atau reverse proxy terbuka.

## Lisensi

MIT. Lihat [LICENSE](LICENSE).
