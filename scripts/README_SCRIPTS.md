# Scripts Folder - Quick Reference

## CURRENT STATUS: Most scripts are OBSOLETE

**Reason**: The NOC ConfigMaker now has a unified backend entrypoint (`api_server.py` from the repo root) and a Docker-first quick start. The EXE auto-starts all services.

---

## ✅ USE THESE (Updated, Current)

### `QUICK_START.bat` (in root folder, NOT scripts/)
**Purpose**: Development launcher - starts the app (Docker-first)  
**When to use**: When developing/testing locally  
**Location**: Root folder (not in scripts/)

### `scripts\\start_docker_local.bat` / `scripts\\stop_docker_local.bat`
**Purpose**: One-click start/stop for the Docker Compose stack  
**When to use**: Local testing with the same stack used on the VM  

URLs:
- App: `http://localhost:8000/app`
- Health: `http://localhost:8000/api/health`

### `scripts\\send_weekly_summary.py`
**Purpose**: Build a weekly activity summary from `secure_data/activity_log.db` and post it to a Microsoft Teams incoming webhook  
**When to use**: Weekly recap, leadership update, or operational reporting  

Example:
```bash
python scripts/send_weekly_summary.py --dry-run
python scripts/send_weekly_summary.py --webhook-url "https://your-org.webhook.office.com/webhookb2/..."
```

Env vars:
- `TEAMS_WEEKLY_SUMMARY_WEBHOOK_URL`
- `WEEKLY_SUMMARY_DB_PATH`
- `WEEKLY_SUMMARY_TIMEZONE`
- `WEEKLY_SUMMARY_DAYS`
- `WEEKLY_SUMMARY_TOP_N`
- `WEEKLY_SUMMARY_TITLE`
- `WEEKLY_SUMMARY_THEME_COLOR`
- `WEEKLY_SUMMARY_FOOTER`

### `build_exe.py` (in root folder)
**Purpose**: Build the distributable EXE  
**When to use**: After making code changes, rebuild EXE  
**Location**: Root folder

---

## ⚠️ LEGACY (Old, Kept for Reference Only)

### `start_backend_services.bat`
**Status**: OBSOLETE - Replaced by `QUICK_START.bat` in root  
**Why obsolete**: New launcher handles this automatically

### `deploy_ai_server.bat`
**Status**: OBSOLETE - AI is now integrated into api_server.py  
**Old Purpose**: Set up dedicated AI server PC  
**Why obsolete**: Backend is unified, AI is built-in

### `build_exe.bat`
**Status**: OBSOLETE - Use `python build_exe.py` instead  
**Old Purpose**: Build EXE with batch wrapper  
**Why obsolete**: Direct Python script is cleaner


### `install_fast_model.bat` / `install_phi3.bat`
**Status**: REFERENCE ONLY  
**Why kept**: Useful shortcuts for model installation

### GitHub Scripts
- `setup_github.bat`
- `push_to_github.bat`
**Status**: REFERENCE ONLY - Use git commands directly

### Network Scripts
- `setup_network_access.bat`
**Status**: REFERENCE ONLY - Windows Firewall rules  
**Why kept**: Useful for LAN deployment

---

## 🎯 FOR END USERS

**Just run**: `NOC-ConfigMaker.exe`  
Everything auto-starts:
- Backend API (port 5000)
- Frontend UI (port 8000)
- Browser opens automatically

**No scripts needed!**

---

## 🛠️ FOR DEVELOPERS

### Daily Development:
```bash
# Option 1: Quick start
QUICK_START.bat

# Option 2: Manual backend
python -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000
```

### After Code Changes:
```bash
# Rebuild EXE
python build_exe.py
```

```bash
```

### Install AI Model (one-time):
```bash
```

---

## Summary

| Script | Status | Use |
|--------|--------|-----|
| `QUICK_START.bat` (root) | ✅ CURRENT | Dev launcher |
| `build_exe.py` (root) | ✅ CURRENT | Build EXE |
| `start_backend_services.bat` | ❌ OBSOLETE | Don't use |
| `deploy_ai_server.bat` | ❌ OBSOLETE | Don't use |
| `build_exe.bat` | ❌ OBSOLETE | Don't use |
| `install_*.bat` | 📖 REFERENCE | Model installers |
| Network/GitHub scripts | 📖 REFERENCE | Useful for specific tasks |

**Bottom Line**: Most scripts are obsolete. Use `QUICK_START.bat` for dev, `python build_exe.py` for builds, or just run the EXE for production.


