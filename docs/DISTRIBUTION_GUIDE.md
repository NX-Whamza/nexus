# NEXUS - Distribution & Update Guide

## Architecture Decision: Web UI vs Native App

**Current Choice: Web UI (Recommended)**

The application uses a **web-based interface** served locally. This is the best approach because:

### ✅ Advantages of Web UI:
1. **Easy Updates**: Update `nexus.html` without rebuilding the entire executable
2. **Cross-Platform**: Works on Windows, Mac, Linux (if you build for each)
3. **Familiar Interface**: Users already know how to use web browsers
4. **Network Access**: Can be accessed from other devices on the network
5. **No Installation**: Just run the .exe, browser opens automatically
6. **Development Speed**: Faster to update HTML/CSS/JS than native UI code

### When to Consider Native App:
- Need system tray integration
- Require file system access beyond browser capabilities
- Need native OS notifications
- Want offline-first with no server component

**For your use case (config generation tool), Web UI is perfect!**

## Distribution Best Practices

### 1. Versioning
- Include version number in executable name: `NEXUS-v1.0.exe`
- Or use a version file: `VERSION.txt` bundled with the exe
- Display version in the web UI footer

### 2. Update Strategy

#### Option A: Full Executable Replacement (Current)
- **Pros**: Simple, everything bundled
- **Cons**: Large file size (50-100 MB), slower downloads
- **Best for**: Major updates, infrequent releases

#### Option B: Incremental Updates (Recommended)
- **Structure**:
  ```
  NEXUS.exe (launcher only, ~5 MB)
  ├── nexus.html (update this file)
  ├── config_policies/ (update as needed)
  └── data/ (other updateable files)
  ```
- **Pros**: Small updates, faster distribution
- **Cons**: More complex setup
- **Best for**: Frequent updates, HTML/JS changes

#### Option C: Auto-Update System (Advanced)
- Check for updates on startup
- Download only changed files
- Requires update server

### 3. File Structure for Distribution

**Recommended Structure:**
```
NEXUS-v1.0/
├── NEXUS.exe (main launcher)
├── README.txt (user instructions)
├── CHANGELOG.txt (what's new)
└── (optional) config_policies/ (if not bundled)
```

### 4. User Instructions (README.txt)

Include this with your distribution:

```
NEXUS - Quick Start
==============================

1. Double-click NEXUS.exe
2. Wait for browser to open automatically
3. Use the web interface
4. Keep the console window open while using

Requirements:
- Windows 10/11
- Internet connection (for AI features)

Ports Used:
- 5000: Backend API
- 8000: Web Interface

Troubleshooting:
- If ports are in use, close other applications
- Check Windows Firewall if network access needed
- See console window for error messages
```

## Update Workflow

### For Minor Updates (HTML/JS changes):
1. Update `nexus.html`
2. Rebuild executable: `rebuild_exe_safe.bat`
3. Distribute new `.exe` file
4. Users replace old `.exe` with new one

### For Major Updates (Backend changes):
1. Update source code
2. Test thoroughly
3. Update version number
4. Rebuild: `rebuild_exe_safe.bat`
5. Distribute with changelog

### Version Numbering:
- **Major** (v1.0 → v2.0): Breaking changes, new features
- **Minor** (v1.0 → v1.1): New features, backward compatible
- **Patch** (v1.0.0 → v1.0.1): Bug fixes

## Distribution Channels

1. **Internal Network Share**: For team distribution
2. **Email**: Attach .exe (if size allows)
3. **Cloud Storage**: Google Drive, OneDrive, Dropbox
4. **Version Control**: Git releases (GitHub, GitLab)
5. **Internal Wiki/Portal**: Company documentation site

## Security Considerations

1. **Code Signing**: Sign the executable (prevents Windows warnings)
2. **Antivirus Whitelisting**: May need to whitelist in corporate AV
3. **Network Access**: Firewall rules for ports 5000/8000
4. **File Permissions**: Ensure users can run .exe

## Testing Checklist Before Distribution

- [ ] Executable runs on clean Windows machine
- [ ] Backend starts successfully
- [ ] Frontend loads in browser
- [ ] All features work (config generation, validation, etc.)
- [ ] Ports don't conflict with other apps
- [ ] Error messages are clear
- [ ] README instructions are accurate

## Future Enhancements

1. **Auto-Update Check**: Check for new versions on startup
2. **Portable Mode**: Extract to folder instead of temp directory
3. **System Tray**: Minimize to tray instead of console window
4. **Update Server**: Centralized update distribution
5. **Installer**: Use NSIS/Inno Setup for professional installation

