# app.py
import json
import streamlit as st
import pandas as pd
from pathlib import Path
from core.detector import TorLocationFinder
from core.analyzer import TorForensicEngine

st.set_page_config(page_title="Tor Forensic Suite v3.0", layout="wide")

st.title("Tor and Dark Web Forensic Suite (Enterprise Edition)")
st.caption("Rancangan Framework Forensik Digital Sesuai Metodologi Rantai Bukti Hukum (Chain of Custody)")
st.markdown("---")

# Menu Sidebar Kontrol Regulasi
finder = TorLocationFinder()
detected_paths = finder.get_potential_paths()

st.sidebar.header("Deteksi Jalur dan Input")
selected_path = None

if detected_paths:
    path_options = {str(p): p for p in detected_paths}
    choice = st.sidebar.selectbox("Lokasi Tor Terdeteksi Otomatis:", list(path_options.keys()))
    selected_path = path_options[choice]
else:
    st.sidebar.info("Tidak ada instalasi standar Tor Browser terdeteksi di disk.")
    manual_input = st.sidebar.text_input("Masukkan Jalur Direktori Bukti Secara Manual:")
    if manual_input:
        selected_path = Path(manual_input)

# Inisialisasi Objek Forensik
actual_profile_path = finder.find_profile_folder(selected_path) if selected_path else Path(".")
engine = TorForensicEngine(actual_profile_path)

# Analisis Tingkat OS & Memori Live
st.header("Analisis Sistem Operasi (OS Level) dan Deteksi Soket RAM")
col1, col2, col3 = st.columns(3)

sys_tor = engine.analyze_system_tor()
with col1:
    if "AKTIF" in sys_tor["status"]:
        st.error(sys_tor["status"])
    else:
        st.metric("Status Tor Daemon (Sistem)", sys_tor["status"])
        
with col2:
    has_pc = "Terdeteksi di Sistem" if engine.check_proxychains() else "Tidak Ada"
    if has_pc == "Terdeteksi di Sistem":
        st.warning(f"Proxychains: {has_pc}")
    else:
        st.metric("Konfigurasi Proxychains", has_pc)
        
with col3:
    hosting_status = sys_tor["details"].get("is_hosting", "Tidak Terdeteksi")
    st.metric("Status Hosting Server (.onion)", hosting_status)

if sys_tor["details"]:
    st.write("Data Parameter Log Jaringan Terdeteksi:")
    st.json(sys_tor["details"])

st.markdown("---")

# Ekstraksi dan Metodologi Artefak
st.header("Analisis Artefak Aktivitas Klien")

if selected_path:
    tab_history, tab_carving, tab_identity, tab_industry, tab_integrity = st.tabs([
        "Riwayat Aktif dan Visual", 
        "Carving Data (Terhapus)", 
        "Identitas dan Audit OpSec",
        "Modul Standar Industri",
        "Integritas Forensik (Chain of Custody)"
    ])

    with tab_history:
        st.subheader("Tabel Riwayat Kunjungan Situs Gelap (.onion)")
        history = engine.get_history()
        if history:
            df_hist = pd.DataFrame(history, columns=["URL Situs", "Judul Halaman", "Jumlah Kunjungan", "Timestamp Intel"])
            st.dataframe(df_hist, use_container_width=True)
        else:
            st.info("Tidak ada alamat domain .onion yang tercatat di riwayat aktif database saat ini.")
            
        st.markdown("---")
        st.subheader("Cache Ikonografi Gambar Situs (.onion Favicons)")
        favicons = engine.extract_onion_favicons()
        if favicons:
            st.dataframe(pd.DataFrame(favicons), use_container_width=True)
        else:
            st.info("Tidak ada data jejak logo visual (favicons) situs .onion yang tersisa di penyimpanan.")

    with tab_carving:
        st.subheader("Pemulihan Jejak String Melalui Metode Carving File places.sqlite-wal")
        deleted_onions = engine.carve_wal_files()
        if deleted_onions:
            st.warning(f"Sinyal Forensik: Berhasil memulihkan {len(deleted_onions)} tautan terhapus dari berkas WAL.")
            for onion in deleted_onions:
                st.code(onion, language="text")
        else:
            st.info("Sistem Pemindaian Bersih: Tidak ditemukan fragmen alamat terhapus pada komponen WAL.")
            
        st.markdown("---")
        st.subheader("Carving Penanda Biner File Entri Cache2")
        st.caption("Mendeteksi file gambar tersembunyi berdasarkan analisis Magic Bytes.")
        cache_artifacts = engine.carve_raw_cache_signatures()
        if cache_artifacts:
            st.dataframe(pd.DataFrame(cache_artifacts), use_container_width=True)
        else:
            st.info("Tidak ditemukan fragmen gambar berkas PNG/JPEG pada folder cache2.")

    with tab_identity:
        st.subheader("Hasil Audit Celah Keamanan Identitas Operasional (OpSec)")
        opsec_data = engine.analyze_opsec_settings()
        
        col_op1, col_op2 = st.columns(2)
        with col_op1:
            st.write(f"**Tingkat Slider Keamanan:** {opsec_data['Security Level']}")
            st.write(f"**Status Eksekusi JavaScript:** {opsec_data['JavaScript Status']}")
        with col_op2:
            st.write(f"**Modifikasi Komponen Tambahan:** {opsec_data['Third-Party Extensions']}")
            
        st.markdown("---")
        st.subheader("Jejak Input Data Formulir dan Identitas Login")
        saved_users = engine.get_saved_usernames()
        if saved_users:
            st.table(saved_users)
        else:
            st.info("Tidak ada data riwayat kredensial (formhistory) yang terekam pada direktori ini.")
            
        st.markdown("---")
        st.subheader("Pengecualian Domain Terpercaya pada NoScript")
        noscript_domains = engine.get_noscript_whitelist()
        if noscript_domains:
            st.write(noscript_domains)
        else:
            st.info("Tersangka tidak mengonfigurasi whitelist modifikasi pada komponen NoScript.")

    with tab_industry:
        st.subheader("Pemulihan Tab Memori Beku (Sessionstore Recovery)")
        suspended_tabs = engine.get_suspended_tabs()
        if suspended_tabs:
            st.error(f"Peringatan: Ditemukan {len(suspended_tabs)} tab situs aktif saat aplikasi ditutup paksa.")
            for tab in suspended_tabs:
                st.code(tab, language="text")
        else:
            st.info("Tidak ada riwayat tab gantung terkompresi jsonlz4 yang terdeteksi.")
            
        st.markdown("---")
        st.subheader("Manifes Riwayat Unduhan File Berkas")
        downloads = engine.get_download_history()
        if downloads:
            st.dataframe(pd.DataFrame(downloads), use_container_width=True)
        else:
            st.info("Tidak ada manifes berkas unduhan lokal yang tercatat di repositori peramban.")
            
        st.markdown("---")
        st.subheader("Audit Enkripsi Vault Kata Sandi Lokal")
        st.json(engine.extract_credential_metadata())
        
        st.markdown("---")
        st.subheader("Manifes Live Session Cookies")
        cookies = engine.get_live_cookies()
        if cookies:
            st.dataframe(pd.DataFrame(cookies), use_container_width=True)
        else:
            st.info("Tidak ada session cookies aktif yang tersimpan.")

    with tab_integrity:
        st.subheader("Verifikasi Validitas Bukti Hukum Digital")
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            st.write("**Hash places.sqlite:**")
            st.json(engine.calculate_file_hashes("places.sqlite"))
        with col_h2:
            st.write("**Hash prefs.js:**")
            st.json(engine.calculate_file_hashes("prefs.js"))
            
        st.markdown("---")
        st.subheader("Analisis Sinkronisasi Log Konsensus Sirkuit Fisik")
        st.json(engine.get_tor_connection_state())
            
        st.markdown("---")
        st.subheader("Analisis Kecepatan Temporal (Temporal Velocity dan Pola Perilaku)")
        st.json(engine.analyze_temporal_velocity())
        
        st.markdown("---")
        st.subheader("Arsip Durasi Sesi Penggunaan Lokal (Telemetri)")
        telemetry = engine.analyze_telemetry_sessions()
        if telemetry:
            st.dataframe(pd.DataFrame(telemetry), use_container_width=True)
        else:
            st.info("Tidak ditemukan berkas kompresi pelaporan telemetri lokal.")

    # Format Laporan dan Dokumen Hukum Case Assembly
    st.markdown("---")
    st.header("Form Laporan dan Dokumen Hukum")
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        case_id = st.text_input("Nomor Kasus / LP:", placeholder="LP/B/102/VI/2026/RES")
    with col_f2:
        suspect_name = st.text_input("Nama Tersangka / Identitas Target:", placeholder="John Doe")
    with col_f3:
        examiner = st.text_input("Nama Pemeriksa (Analis Forensik):", placeholder="Analis Forensik Senior")

    case_meta = {"case_id": case_id, "suspect_name": suspect_name, "examiner": examiner}
    compiled_results = {
        "hashes_places": engine.calculate_file_hashes("places.sqlite"),
        "hashes_prefs": engine.calculate_file_hashes("prefs.js"),
        "opsec": opsec_data,
        "bridge_status": engine.get_bridge_usage(),
        "history": history,
        "carved_wal": deleted_onions
    }

    st.write("Pilih format berkas laporan resmi yang ingin diterbitkan untuk persidangan:")
    col_btn1, col_btn2 = st.columns(2)
    
    with col_btn1:
        st.download_button(
            label="Unduh Data Mentah Kasus (JSON Archive)",
            data=json.dumps({**case_meta, **compiled_results}, indent=4),
            file_name=f"kasus_{case_id or 'darkweb'}.json",
            mime="application/json",
            use_container_width=True
        )
        
    with col_btn2:
        html_report = engine.generate_html_report(case_meta, compiled_results)
        st.download_button(
            label="Unduh Laporan Formal Siap Cetak (HTML / PDF)",
            data=html_report,
            file_name=f"Laporan_Forensik_{case_id or 'Tor'}.html",
            mime="text/html",
            use_container_width=True
        )
else:
    st.info("Pilih atau masukkan direktori jalur profil Tor Browser di sidebar sebelah kiri untuk memulai siklus ekstraksi digital forensik.")