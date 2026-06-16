# core/detector.py
import os
import platform
from pathlib import Path
from typing import List

class TorLocationFinder:
    def __init__(self):
        self.os_type = platform.system()

    def get_potential_paths(self) -> List[Path]:
        """Mendeteksi jalur dasar instalasi Tor Browser di berbagai OS."""
        paths = []
        home = Path.home()
        
        if self.os_type == "Windows":
            paths.extend([
                home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Data",
                home / "Downloads" / "Tor Browser" / "Browser" / "TorBrowser" / "Data",
                Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Data"),
            ])
        elif self.os_type == "Linux":
            paths.extend([
                home / ".tor-browser" / "Browser" / "TorBrowser" / "Data",
                home / "tor-browser_en-US" / "Browser" / "TorBrowser" / "Data",
                Path("/etc/tor"),
                Path("/var/lib/tor"),
            ])
        elif self.os_type == "Darwin": # macOS
            paths.extend([
                home / "Library/Application Support/TorBrowser-Data",
                home / "Applications" / "Tor Browser.app" / "Contents" / "Resources" / "TorBrowser" / "Data"
            ])
            
        return [p for p in paths if p.exists()]

    def find_profile_folder(self, base_path: Path) -> Path:
        """Mengarahkan jalur dari folder induk instalasi ke folder profil tempat database berada."""
        standard_profile = base_path / "Browser" / "profile.default"
        if standard_profile.exists():
            return standard_profile
            
        alt_profile = base_path / "profile.default"
        if alt_profile.exists():
            return alt_profile
            
        return base_path