import sqlite3
import re
import json
import socket
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

class TorForensicEngine:
    def __init__(self, profile_path: Path):
        self.profile_path = profile_path

    def _query_db(self, db_name: str, query: str) -> List[Any]:
        """
        [Standar Industri - Tahan Banting] 
        Mengeksekusi kueri SQL dengan mode Read-Only dan fitur anti-locking 
        untuk mengantisipasi peramban yang sedang aktif berjalan.
        """
        db_path = self.profile_path / db_name
        if not db_path.exists():
            return []
        try:
            # Menambahkan parameter timeout agar SQLite menunggu lock terbuka, 
            # dan query string nol untuk isolasi penuh.
            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro&nolock=1", 
                uri=True, 
                timeout=5.0
            )
            cursor = conn.cursor()
            cursor.execute(query)
            data = cursor.fetchall()
            conn.close()
            return data
        except sqlite3.OperationalError:
            # Jika tetap gagal karena proteksi ketat OS (terutama pada macOS/Windows modern)
            return self._query_db_fallback_copy(db_path, query)
        except Exception:
            return []

    def _query_db_fallback_copy(self, src_path: Path, query: str) -> List[Any]:
        """Metode cadangan: Menyalin berkas ke memori/temp jika file asli dikunci OS."""
        try:
            import shutil
            import tempfile
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir) / src_path.name
                shutil.copy2(src_path, tmp_path)
                
                conn = sqlite3.connect(tmp_path)
                cursor = conn.cursor()
                cursor.execute(query)
                data = cursor.fetchall()
                conn.close()
                return data
        except Exception:
            return []

    def calculate_file_hashes(self, filename: str) -> Dict[str, str]:
        """Menghitung nilai hash MD5 dan SHA-256 berkas bukti digital."""
        target_file = self.profile_path / filename
        if not target_file.exists():
            return {"MD5": "Berkas Tidak Ditemukan", "SHA-256": "Berkas Tidak Ditemukan"}
        try:
            data = target_file.read_bytes()
            return {
                "MD5": hashlib.md5(data).hexdigest(),
                "SHA-256": hashlib.sha256(data).hexdigest()
            }
        except Exception as e:
            return {"MD5": f"Error: {str(e)}", "SHA-256": f"Error: {str(e)}"}

    def get_history(self) -> List[Any]:
        """Mengekstrak seluruh riwayat aktif kunjungan domain .onion."""
        query = "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE url LIKE '%.onion%'"
        return self._query_db("places.sqlite", query)

    def extract_onion_favicons(self) -> List[Dict[str, Any]]:
        """Mengambil cache ikon grafis (favicons) dari situs .onion."""
        query = "SELECT page_url, icon_url FROM moz_pages_w_icons WHERE page_url LIKE '%.onion%'"
        rows = self._query_db("favicons.sqlite", query)
        return [{"Target Onion": r[0], "Icon Source URL": r[1]} for r in rows]

    def get_saved_usernames(self) -> List[Dict[str, str]]:
        """Mengekstrak data riwayat input formulir login pada situs .onion."""
        query = "SELECT fieldname, value FROM moz_formhistory WHERE fieldname LIKE '%user%' OR fieldname LIKE '%login%' OR fieldname LIKE '%email%'"
        rows = self._query_db("formhistory.sqlite", query)
        return [{"Field Nama": r[0], "Input Nilai/Username": r[1]} for r in rows]

    def is_port_active(self, ip: str, port: int) -> bool:
        """Memeriksa sisa artefak jaringan aktif (Soket RAM) untuk Tor Daemon."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex((ip, port)) == 0

    def analyze_system_tor(self) -> Dict[str, Any]:
        """Mendeteksi Tor Service aktif di memori RAM dan file konfigurasi fisik."""
        results = {"status": "Tidak Aktif / Tidak Ditemukan", "details": {}}
        
        tor_socks_active = self.is_port_active("127.0.0.1", 9050)
        tor_control_active = self.is_port_active("127.0.0.1", 9051)
        tor_browser_socks = self.is_port_active("127.0.0.1", 9150)

        if tor_socks_active or tor_browser_socks:
            results["status"] = "Layanan Tor Terdeteksi AKTIF di RAM"
            results["details"] = {
                "socks_port": "9050 (System Daemon)" if tor_socks_active else "9150 (Tor Browser Bundle)",
                "control_port_active": "Ya (9051)" if tor_control_active else "Tidak",
                "evidence_source": "Live Network Socket (RAM Artifact)",
                "is_hosting": "Tidak Diketahui (Berjalan Langsung di Memori)"
            }
        
        torrc_paths = [
            Path("/etc/tor/torrc"),
            Path("/opt/homebrew/etc/tor/torrc"),
            Path("/usr/local/etc/tor/torrc"),
        ]
        
        for p in torrc_paths:
            if p.exists():
                if results["status"] == "Tidak Aktif / Tidak Ditemukan":
                    results["status"] = "Layanan Terinstal di Sistem (Status: Inaktif)"
                
                content = p.read_text(errors='ignore')
                is_hosting = "Tidak"
                if "HiddenServiceDir" in content and not content.strip().startswith("#"):
                    is_hosting = "Ya (Terdeteksi HiddenServiceDir / Menghosting Situs .onion)"
                
                if "details" not in results or not results["details"]:
                    results["details"] = {}
                results["details"].update({
                    "config_file_found": "Ya",
                    "config_path": str(p),
                    "is_hosting": is_hosting
                })
                break
                
        return results

    def analyze_opsec_settings(self) -> Dict[str, Any]:
        """Menganalisis konfigurasi privasi dan celah keamanan OpSec pada profil peramban."""
        prefs_path = self.profile_path / "prefs.js"
        results = {
            "Security Level": "Standard (Default Protection)",
            "JavaScript Status": "Enabled (Potentially Vulnerable)",
            "Bridges Configuration": "Tidak / Koneksi Langsung",
            "Third-Party Extensions": "Tidak Terdeteksi Modifikasi"
        }
        
        if prefs_path.exists():
            content = prefs_path.read_text(errors='ignore')
            
            if "browser.security_level.security_slider" in content:
                level_match = re.search(r'security_slider",\s*(\d+)', content)
                if level_match:
                    val = level_match.group(1)
                    if val == "1": results["Security Level"] = "Safest (Maksimal)"
                    elif val == "2": results["Security Level"] = "Safer (Menengah)"
            
            if 'javascript.enabled", false' in content:
                results["JavaScript Status"] = "Disabled (Aman dari Exploit)"
                
            if 'torbrowser.settings.bridges.enabled", true' in content or 'use_bridges", true' in content:
                results["Bridges Configuration"] = "Ya (Tersangka Menggunakan Bridge Obfuscation)"
                
            if "extensions.enabledAddons" in content:
                addons_match = re.search(r'enabledAddons",\s*"(.*?)"', content)
                if addons_match:
                    results["Third-Party Extensions"] = f"Terdeteksi Modifikasi: {addons_match.group(1)}"

        return results

    def get_bridge_usage(self) -> str:
        """Mendeteksi apakah profil menggunakan penyamaran Bridge Obfuscation."""
        prefs_path = self.profile_path / "prefs.js"
        if prefs_path.exists():
            try:
                content = prefs_path.read_text(errors='ignore')
                if 'torbrowser.settings.bridges.enabled", true' in content or 'use_bridges", true' in content:
                    return "Ya (Tersangka Menggunakan Bridge Obfuscation)"
            except Exception:
                return "Gagal Membaca Konfigurasi Bridge"
        return "Tidak / Koneksi Langsung"

    def analyze_temporal_velocity(self) -> Dict[str, Any]:
        """Menganalisis total intensitas dan jam aktivitas puncak di Dark Web."""
        rows = self._query_db("places.sqlite", "SELECT last_visit_date FROM moz_places WHERE url LIKE '%.onion%'")
        hours = []
        for row in rows:
            if row[0]:
                dt = datetime.fromtimestamp(row[0] / 1000000)
                hours.append(dt.hour)
                
        if not hours:
            return {"Total Kunjungan": 0, "Jam Puncak Aktivitas": "Tidak Ada Data Temporal"}
            
        peak_hour = max(set(hours), key=hours.count)
        return {
            "Total Kunjungan Kategori .Onion": len(hours),
            "Jam Puncak Aktivitas": f"{peak_hour}:00 Local Time",
            "Pola Perilaku": "Operasi Malam/Dini Hari (OpSec Tinggi)" if peak_hour in [23, 0, 1, 2, 3, 4, 5] else "Operasi Jam Kerja Umum/Siang Hari"
        }

    def check_proxychains(self) -> bool:
        """Mendeteksi eksistensi berkas konfigurasi Proxychains di sistem Unix/macOS."""
        paths = [
            Path("/etc/proxychains.conf"), 
            Path("/etc/proxychains4.conf"),
            Path("/opt/homebrew/etc/proxychains.conf"),
            Path("/usr/local/etc/proxychains.conf")
        ]
        return any(p.exists() for p in paths)

    def carve_wal_files(self) -> List[str]:
        """Memulihkan fragmen tautan .onion yang telah dihapus dari file log biner WAL."""
        wal_path = self.profile_path / "places.sqlite-wal"
        if not wal_path.exists():
            return []
        try:
            content = wal_path.read_bytes()
            found = re.findall(b"[a-z2-7]{56}\.onion", content)
            return list(set([f.decode(errors='ignore') for f in found]))
        except Exception:
            return []

    # =========================================================================
    # MODUL BARU: IMPLEMENTASI STANDAR INDUSTRI KOMERSIAL (ADVANCED FORENSICS)
    # =========================================================================

    def parse_moz_lz4(self, file_path: Path) -> bytes:
        """Mendekompresi mekanisme kompresi internal Mozilla lz4 non-standar (magic bytes: mozLz4)."""
        if not file_path.exists():
            return b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
                if magic != b"mozLz4\x00":
                    return b""
                import lz4.block
                f.seek(12) # Lompat melewati header ukuran kompresi asli
                return lz4.block.decompress(f.read())
        except Exception:
            return b""

    def get_download_history(self) -> List[Dict[str, Any]]:
        """Mengekstraksi manifes unduhan berkas dari domain jaringan gelap."""
        query = """
        SELECT b.url, a.content, d.dateAdded 
        FROM moz_annos a
        JOIN moz_anno_attributes c ON a.annoattribute_id = c.id
        JOIN moz_places b ON a.place_id = b.id
        JOIN moz_historyvisits d ON d.place_id = b.id
        WHERE c.name = 'downloads/destinationFileURI'
        """
        rows = self._query_db("places.sqlite", query)
        results = []
        for r in rows:
            clean_local_path = r[1].replace("file:///", "") if r[1] else "Tidak Diketahui"
            results.append({
                "Source URL": r[0],
                "Local Target Path": clean_local_path,
                "Download Timestamp": datetime.fromtimestamp(r[2] / 1000000).strftime("%Y-%m-%d %H:%M:%S") if r[2] else "N/A"
            })
        return results

    def extract_credential_metadata(self) -> Dict[str, Any]:
        """Mengaudit status dan jumlah akun terenkripsi pada password manager bawaan (logins.json)."""
        logins_path = self.profile_path / "logins.json"
        key_path = self.profile_path / "key4.db"
        
        analysis = {
            "Vault Status": "Tidak Ditemukan",
            "Total Encrypted Accounts": 0,
            "Key Database Present": "Tidak"
        }
        
        if key_path.exists():
            analysis["Key Database Present"] = "Ya (key4.db Terdeteksi)"
            
        if logins_path.exists():
            analysis["Vault Status"] = "Terdeteksi (Terenkripsi)"
            try:
                data = json.loads(logins_path.read_text(errors='ignore'))
                if "logins" in data:
                    analysis["Total Encrypted Accounts"] = len(data["logins"])
            except Exception:
                analysis["Vault Status"] = "Terdeteksi (Gagal Parsing Struktur)"
                
        return analysis

    def get_suspended_tabs(self) -> List[str]:
        """Memulihkan daftar tab aktif yang membeku di memori sesi saat terjadi crash atau penutupan paksa."""
        session_file = self.profile_path / "sessionstore.jsonlz4"
        recovered_urls = []
        
        try:
            decompressed_data = self.parse_moz_lz4(session_file)
            if decompressed_data:
                urls = re.findall(r'"url":"(.*?)"', decompressed_data.decode(errors='ignore'))
                for u in urls:
                    if ".onion" in u and u not in recovered_urls:
                        recovered_urls.append(u)
        except Exception:
            pass
            
        if not recovered_urls and session_file.exists():
            try:
                content = session_file.read_bytes()
                urls = re.findall(b'"url":"(.*?)"', content)
                for u in urls:
                    decoded_url = u.decode(errors='ignore')
                    if ".onion" in decoded_url and decoded_url not in recovered_urls:
                        recovered_urls.append(decoded_url)
            except Exception:
                pass
                
        return recovered_urls

    def get_tor_connection_state(self) -> Dict[str, str]:
        """Membaca berkas log fisik state untuk validasi kronologi waktu koneksi sirkuit."""
        state_path = self.profile_path.parent / "Tor" / "state"
        metrics = {"Last Tor Connection Established": "Tidak Terdeteksi"}
        
        if state_path.exists():
            try:
                content = state_path.read_text(errors='ignore')
                for line in content.splitlines():
                    if line.startswith("LastWritten"):
                        parts = line.split()
                        if len(parts) >= 3:
                            metrics["Last Tor Connection Established"] = f"{parts[1]} {parts[2]}"
                            break
            except Exception:
                pass
        return metrics

    def get_noscript_whitelist(self) -> List[str]:
        """Mengekstrak domain .onion yang diberi pengecualian eksekusi skrip oleh tersangka pada NoScript."""
        pref_file = self.profile_path / "extension-preferences.json"
        whitelist = []
        if pref_file.exists():
            try:
                data = json.loads(pref_file.read_text(errors='ignore'))
                for key, value in data.get("noscript", {}).get("settings", {}).items():
                    if ".onion" in key and "trusted" in str(value):
                        whitelist.append(key)
            except Exception:
                pass
        return whitelist

    def analyze_telemetry_sessions(self) -> List[Dict[str, Any]]:
        """Menganalisis arsip telemetri lokal untuk mengetahui akumulasi durasi sesi penggunaan peramban."""
        telemetry_dir = self.profile_path / "datareporting" / "archived"
        session_logs = []
        if telemetry_dir.exists():
            try:
                for file_path in telemetry_dir.glob("*.jsonlz4"):
                    decompressed = self.parse_moz_lz4(file_path)
                    if decompressed:
                        log_data = json.loads(decompressed.decode(errors='ignore'))
                        payload = log_data.get("payload", {})
                        simple_measurements = payload.get("simpleMeasurements", {})
                        
                        session_logs.append({
                            "File": file_path.name,
                            "Session Duration (Sec)": simple_measurements.get("totalTime", 0),
                            "Max Tabs Open": simple_measurements.get("maxTabsOpen", 0)
                        })
            except Exception:
                pass
        return session_logs

    def get_live_cookies(self) -> List[Dict[str, Any]]:
        """Mengekstrak session cookies aktif dari situs .onion guna analisis pembajakan sesi (Live Forensics)."""
        query = "SELECT host, name, value, expiry FROM moz_cookies WHERE host LIKE '%.onion%'"
        rows = self._query_db("cookies.sqlite", query)
        results = []
        for r in rows:
            results.append({
                "Host Domain": r[0],
                "Cookie Name": r[1],
                "Token Value": r[2],
                "Expiry Timestamp": datetime.fromtimestamp(r[3]).strftime("%Y-%m-%d %H:%M:%S") if r[3] else "Session Only"
            })
        return results

    def carve_raw_cache_signatures(self) -> List[Dict[str, str]]:
        """Memindai struktur biner berkas entri cache2 untuk mendeteksi sisa fragmen gambar digital tersembunyi."""
        cache_dir = self.profile_path / "cache2" / "entries"
        discovered_artifacts = []
        
        if cache_dir.exists():
            for file_path in cache_dir.iterdir():
                if file_path.is_file():
                    try:
                        header = file_path.read_bytes()[:4]
                        file_type = "Unknown Data"
                        if header.startswith(b"\x89PNG"):
                            file_type = "PNG Image Artifact"
                        elif header.startswith(b"\xff\xd8\xff"):
                            file_type = "JPEG Image Artifact"
                        elif header.startswith(b"%PDF"):
                            file_type = "PDF Document Artifact"
                        
                        if file_type != "Unknown Data":
                            discovered_artifacts.append({
                                "Cache File Name": file_path.name,
                                "Inferred Type": file_type,
                                "Size (Bytes)": str(file_path.stat().st_size)
                            })
                    except Exception:
                        pass
        return discovered_artifacts

    def generate_html_report(self, case_info: Dict[str, str], analysis_results: Dict[str, Any]) -> str:
        """Membuat laporan forensik formal berformat HTML yang bersih dan siap cetak."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        history_rows = ""
        for item in analysis_results.get("history", []):
            history_rows += f"<tr><td>{item[0]}</td><td>{item[1]}</td><td>{item[2]}</td></tr>"
        if not history_rows:
            history_rows = "<tr><td colspan='3' style='text-align:center;'>Tidak ada data riwayat aktif</td></tr>"

        wal_rows = ""
        for item in analysis_results.get("carved_wal", []):
            wal_rows += f"<tr><td><code>{item}</code></td><td>places.sqlite-wal</td></tr>"
        if not wal_rows:
            wal_rows = "<tr><td colspan='2' style='text-align:center;'>Tidak ada fragmen terhapus yang ditemukan</td></tr>"

        # Kompilasi baris untuk Riwayat Unduhan Terenkripsi/Situs .onion
        download_rows = ""
        for dl in analysis_results.get("downloads", []):
            download_rows += f"<tr><td>{dl['Source URL']}</td><td>{dl['Local Target Path']}</td><td>{dl['Download Timestamp']}</td></tr>"
        if not download_rows:
            download_rows = "<tr><td colspan='3' style='text-align:center;'>Tidak ada manifes unduhan</td></tr>"

        # Kompilasi baris untuk Session Cookies Aktif Jaringan Gelap
        cookie_rows = ""
        for ck in analysis_results.get("cookies", []):
            cookie_rows += f"<tr><td>{ck['Host Domain']}</td><td>{ck['Cookie Name']}</td><td>{ck['Expiry Timestamp']}</td></tr>"
        if not cookie_rows:
            cookie_rows = "<tr><td colspan='3' style='text-align:center;'>Tidak ada session cookies aktif terdeteksi</td></tr>"

        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
                .header {{ text-align: center; border-bottom: 3px solid #333; padding-bottom: 20px; }}
                .case-info {{ margin-top: 20px; background: #f9f9f9; padding: 15px; border-left: 5px solid #0056b3; }}
                h2 {{ color: #0056b3; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ margin-top: 50px; text-align: center; font-size: 11px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>LAPORAN HASIL PEMERIKSAAN DIGITAL FORENSIK</h1>
                <h3>Analisis Aktivitas Tor Browser dan Jaringan Dark Web</h3>
            </div>
            
            <div class="case-info">
                <h3>INFORMASI KASUS</h3>
                <table>
                    <tr><td><b>Nomor Kasus / Laporan:</b></td><td>{case_info.get("case_id", "N/A")}</td></tr>
                    <tr><td><b>Nama Tersangka / Target:</b></td><td>{case_info.get("suspect_name", "N/A")}</td></tr>
                    <tr><td><b>Analis Forensik:</b></td><td>{case_info.get("examiner", "N/A")}</td></tr>
                    <tr><td><b>Waktu Analisis (Sistem):</b></td><td>{now}</td></tr>
                    <tr><td><b>Direktori Bukti Target:</b></td><td><code>{str(self.profile_path)}</code></td></tr>
                </table>
            </div>

            <h2>INTEGRITAS BARANG BUKTI (CHAIN OF CUSTODY)</h2>
            <table>
                <tr><th>Berkas Bukti</th><th>Nilai Kontrol MD5 Hash</th><th>Nilai Kontrol SHA-256 Hash</th></tr>
                <tr><td>places.sqlite</td><td>{analysis_results['hashes_places']['MD5']}</td><td>{analysis_results['hashes_places']['SHA-256']}</td></tr>
                <tr><td>prefs.js</td><td>{analysis_results['hashes_prefs']['MD5']}</td><td>{analysis_results['hashes_prefs']['SHA-256']}</td></tr>
            </table>

            <h2>AUDIT KEAMANAN OPERASIONAL (OPSEC) TERSANGKA</h2>
            <table>
                <tr><td><b>Slider Level Keamanan:</b></td><td>{analysis_results['opsec']['Security Level']}</td></tr>
                <tr><td><b>Status Akses JavaScript:</b></td><td>{analysis_results['opsec']['JavaScript Status']}</td></tr>
                <tr><td><b>Penggunaan Jembatan (Bridge):</b></td><td>{analysis_results['bridge_status']}</td></tr>
            </table>

            <h2>RIWAYAT AKTIF KUNJUNGAN (.ONION)</h2>
            <table>
                <tr><th>URL Tor Target</th><th>Judul Halaman</th><th>Jumlah Kunjungan</th></tr>
                {history_rows}
            </table>

            <h2>RIWAYAT MANIFES UNDUHAN BERKAS (DARK WEB DOWNLOADS)</h2>
            <table>
                <tr><th>Source URL</th><th>Local Target Path</th><th>Download Timestamp</th></tr>
                {download_rows}
            </table>

            <h2>SESSION COOKIES AKTIF (LIVE FORENSICS ARTIFACTS)</h2>
            <table>
                <tr><th>Host Domain</th><th>Cookie Name</th><th>Expiry Timestamp</th></tr>
                {cookie_rows}
            </table>

            <h2>FRAGMEN DATA DIHAPUS YANG DIPULIHKAN (WAL CARVING)</h2>
            <table>
                <tr><th>Tautan .Onion yang Dipulihkan</th><th>Sumber Bukti Fisik</th></tr>
                {wal_rows}
            </table>

            <div class="footer">
                <p>Dokumen ini diproduksi secara otomatis oleh Tor and Dark Web Forensic Suite (v2026).</p>
                <p><b>RAHASIA - HANYA UNTUK KEPENTINGAN PENEGAKAN HUKUM</b></p>
            </div>
        </body>
        </html>
        """
        return html_template
