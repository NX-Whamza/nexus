#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build script to create executable for NEXUS
Uses PyInstaller to bundle backend, frontend, and dependencies
"""
import os
import sys
import subprocess
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        return True
    except ImportError:
        return False

def install_pyinstaller():
    """Install PyInstaller"""
    print("Installing PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def build_exe():
    """Build the executable with unified backend"""
    script_dir = Path(__file__).parent
    vm_dir = script_dir / "vm_deployment"
    
    print("=" * 70)
    print("NEXUS - Unified Backend Builder")
    print("=" * 70)
    print()
    print("Building single executable with integrated backend...")
    print()
    
    # Check PyInstaller
    if not check_pyinstaller():
        print("Installing PyInstaller...")
        install_pyinstaller()
        print()
    
    # Determine path separator for PyInstaller
    if sys.platform == 'win32':
        sep = ';'
    else:
        sep = ':'

    def data_arg(src_rel: str, dest_rel: str) -> str:
        src = vm_dir / src_rel
        if not src.exists():
            raise FileNotFoundError(f"Missing build input: {src}")
        return f"--add-data={src}{sep}{dest_rel}"
    
    # Build PyInstaller command with clean, minimal imports
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=NEXUS",
        "--onefile",
        "--console",  # Keep console for backend logs
        "--clean",  # Clean PyInstaller cache before building
        
        # Data files (IMPORTANT: secure_data is NOT bundled - it stays separate for data persistence)
        data_arg("nexus.html", "."),
        data_arg("login.html", "."),
        data_arg("change-password.html", "."),
        data_arg("config_policies", "config_policies"),
        data_arg("nextlink_standards.py", "."),
        data_arg("nextlink_enterprise_reference.py", "."),
        data_arg("nextlink_compliance_reference.py", "."),
        # NOTE: secure_data/ folder is intentionally NOT included here
        # This ensures SQLite databases persist across EXE updates
        
        # Core dependencies (explicitly include everything needed)
        "--hidden-import=flask",
        "--hidden-import=flask_cors",
        "--hidden-import=werkzeug",
        "--hidden-import=werkzeug.serving",
        "--hidden-import=requests",
        "--hidden-import=sqlite3",
        "--hidden-import=dotenv",
        # SMTP/email is no longer used (feedback is stored locally)
        
        # Our modules (unified backend structure)
        "--hidden-import=api_server",
        "--hidden-import=nextlink_standards",
        "--hidden-import=nextlink_enterprise_reference",
        "--hidden-import=nextlink_compliance_reference",
        
        # Authentication modules (standard library, but explicit for clarity)
        "--hidden-import=hashlib",
        "--hidden-import=secrets",
        "--hidden-import=base64",
        "--hidden-import=json",
        
        # JWT support (optional - will work without PyJWT using fallback)
        "--hidden-import=jwt",
        "--hidden-import=jwt.algorithms",
        
        # Collect Flask and Werkzeug completely
        "--collect-all=flask",
        "--collect-all=werkzeug",
        
        # Entry point
        str(vm_dir / "launcher.py")
    ]
    
    print("Building executable...")
    print("This may take several minutes...")
    print()
    
    # Write build start time to file for verification
    import datetime
    with open('build_start.txt', 'w') as f:
        f.write(f"Build started at: {datetime.datetime.now()}\n")
    
    try:
        # Run with real-time output
        process = subprocess.Popen(cmd, cwd=script_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        # Stream output
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)
        
        print()
        print("=" * 70)
        print("Build successful!")
        print("=" * 70)
        print()
        print(f"Executable location: {script_dir / 'dist' / 'NEXUS.exe'}")
        print()
        print("You can now distribute this .exe file to users.")
        print("They can run it without installing Python or dependencies.")
        print()
    except subprocess.CalledProcessError as e:
        print()
        print("=" * 70)
        print("Build failed!")
        print("=" * 70)
        print(f"Error: {e}")
        print()
        return False
    
    return True

if __name__ == '__main__':
    build_exe()
