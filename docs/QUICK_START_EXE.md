# Quick Start - Building the Executable

## Step 1: Build the Executable

Run this command:
```batch
build_exe.bat
```

Or manually:
```bash
python build_exe.py
```

## Step 2: Find Your Executable

After building, the executable is here:
```
dist\NEXUS.exe
```

## Step 3: Test It

1. Double-click `NEXUS.exe`
2. A console window will open showing status
3. Your browser will open automatically to `http://localhost:8000/nexus.html`
4. The application is ready to use!

## Step 4: Distribute

Share the `NEXUS.exe` file with your team. They can:
- Download it
- Run it (no Python installation needed)
- Use the tool immediately

## What Gets Bundled?

✅ Backend API server (Flask)
✅ Frontend web interface (HTML)
✅ All Python dependencies
✅ Configuration policies
✅ All required Python modules

## Requirements for Users

- Windows 10/11
- Internet connection (for AI features)

## Troubleshooting

**Build fails?**
- Run: `pip install -r requirements.txt`
- Then: `pip install pyinstaller`
- Try again: `build_exe.bat`

**Executable won't start?**
- Check Windows Defender (may block new .exe files)
- Look at console window for error messages
- Ensure ports 5000 and 8000 are available

**Port already in use?**
- Close other applications using those ports
- Or restart your computer

## File Size

The .exe will be about 50-100 MB (includes everything).

