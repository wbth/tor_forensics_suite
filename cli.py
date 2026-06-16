# cli.py
import argparse
import json
from pathlib import Path
from core.detector import TorLocationFinder
from core.analyzer import TorForensicEngine

def cetak_garis():
    print("-" * 60)

def main():
    parser = argparse.ArgumentParser(description="Tor and Dark Web Forensic Suite - CLI Mode")
    parser.add_argument("--path", help="Jalur direktori profil Tor secara manual", type=str, default=None)
    parser.add_argument("--output", help="Nama dasar untuk file laporan (tanpa ekstensi)", type=str, default="laporan_forensik")
    parser.add_argument("--case-id", help="Nomor Kasus / LP", type=str, default="LP/CLI/2026")
    parser.add_argument("--suspect", help="Nama Tersangka", type=str, default="Anonim")
    parser.add_argument("--examiner", help="Nama Pemeriksa", type=str, default="Analis CLI")
    
    args = parser.parse_args()

    print("=== Tor and Dark Web Forensic Suite ===")
    cetak_garis()

    # 1. Inisialisasi Finder dan Jalur Target
    finder = TorLocationFinder()
    selected_path = None

    if args.path:
        selected_path = Path(args.path)
        print(f"[+] Menggunakan jalur manual: {selected_path}")
    else:
        print("[*] Mencari instalasi Tor secara otomatis...")
        detected_paths = finder.get_potential_paths()
        if detected_paths:
            selected_path = detected_paths[0]
            print(f"[+] Jalur otomatis ditemukan: {selected_path}")
        else:
            print("[-] Tor Browser tidak ditemukan otomatis. Gunakan argumen --path")
            return

    actual_profile_path = finder.find_profile_folder(selected_path)
    engine = TorForensicEngine(actual_profile_path)

    # 2. Analisis Tingkat OS & RAM
    print("\n[*] Menjalankan Analisis Tingkat OS & RAM...")
    cetak_garis()
    sys_tor = engine.analyze_system_tor()
    print(f"Status Tor Daemon: {sys_tor['status']}")
    print(f"Proxychains      : {'Terdeteksi' if engine.check_proxychains() else 'Tidak Ada'}")
    if sys_tor.get("details"):
        print(f"Detail Jaringan  : {json.dumps(sys_tor['details'], indent=2)}")

    # 3. Verifikasi Integritas Kriptografi
    print("\n[*] Menghitung Kontrol Hash Kriptografi (Chain of Custody)...")
    cetak_garis()
    hash_places = engine.calculate_file_hashes("places.sqlite")
    hash_prefs = engine.calculate_file_hashes("prefs.js")
    print(f"places.sqlite SHA-256: {hash_places['SHA-256']}")
    print(f"prefs.js      SHA-256: {hash_prefs['SHA-256']}")

    # 4. Audit OpSec & Kredensial
    print("\n[*] Mengaudit Pengaturan OpSec & Kredensial...")
    cetak_garis()
    opsec_data = engine.analyze_opsec_settings()
    print(f"Level Slider Keamanan: {opsec_data['Security Level']}")
    print(f"Status JavaScript     : {opsec_data['JavaScript Status']}")
    
    saved_users = engine.get_saved_usernames()
    print(f"Kredensial Ditemukan : {len(saved_users)} entri")
    for user in saved_users:
        print(f"  - {user['Field Nama']}: {user['Input Nilai/Username']}")

    # 5. Riwayat Kunjungan & Analisis Temporal
    print("\n[*] Mengekstrak Riwayat Kunjungan .onion...")
    cetak_garis()
    history = engine.get_history()
    print(f"Total URL Terdaftar  : {len(history)}")
    for row in history[:5]: # Tampilkan 5 teratas saja di CLI agar bersih
        print(f"  - URL: {row[0]} (Kunjungan: {row[2]})")
    if len(history) > 5:
        print(f"  ... dan {len(history) - 5} riwayat lainnya.")

    velocity_data = engine.analyze_temporal_velocity()
    print(f"Jam Puncak Aktivitas : {velocity_data.get('Jam Puncak Aktivitas')}")
    print(f"Pola Perilaku        : {velocity_data.get('Pola Perilaku')}")

    # 6. Pemulihan Data Terhapus (WAL Carving)
    print("\n[*] Menjalankan Pemulihan Data Biner (WAL Carving)...")
    cetak_garis()
    deleted_onions = engine.carve_wal_files()
    print(f"Total URL Dipulihkan : {len(deleted_onions)}")
    for onion in deleted_onions:
        print(f"  [!] RECOVERED: {onion}")

    # 7. Ekspor Laporan Otomatis ke File
    print("\n[*] Mengekspor Hasil Laporan Forensik...")
    cetak_garis()
    
    case_meta = {"case_id": args.case_id, "suspect_name": args.suspect, "examiner": args.examiner}
    compiled_results = {
        "hashes_places": hash_places,
        "hashes_prefs": hash_prefs,
        "opsec": opsec_data,
        "bridge_status": engine.get_bridge_usage(),
        "history": history,
        "carved_wal": deleted_onions
    }

    # Ekspor JSON
    json_file = Path(f"{args.output}.json")
    json_file.write_text(json.dumps({**case_meta, **compiled_results}, indent=4))
    print(f"[+] Laporan JSON disimpan ke: {json_file}")

    # Ekspor HTML (Siap cetak ke PDF)
    html_report = engine.generate_html_report(case_meta, compiled_results)
    html_file = Path(f"{args.output}.html")
    html_file.write_text(html_report)
    print(f"[+] Laporan HTML (Siap Cetak) disimpan ke: {html_file}")
    
    cetak_garis()
    print("=== Proses Analisis CLI Selesai ===")

if __name__ == "__main__":
    main()