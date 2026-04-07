#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS - Unified Launcher
Starts both backend API and frontend server in a single executable
"""
import sys
import io
import os
import threading
import time
import webbrowser
import subprocess
from pathlib import Path

# Fix Windows console encoding and ensure output is visible
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    except:
        pass  # If already wrapped or not available, continue

# Force immediate output
print("NEXUS - Starting...", flush=True)
sys.stdout.flush()
sys.stderr.flush()

# Get the directory where the executable is located
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    # PyInstaller extracts files to sys._MEIPASS
    BASE_DIR = Path(sys._MEIPASS)  # Temporary extraction directory
    APP_DIR = Path(sys.executable).parent  # Where .exe is located
    print(f"[DEBUG] Running as executable", flush=True)
    print(f"[DEBUG] BASE_DIR (extracted): {BASE_DIR}", flush=True)
    print(f"[DEBUG] APP_DIR (exe location): {APP_DIR}", flush=True)
else:
    # Running as script
    BASE_DIR = Path(__file__).parent
    APP_DIR = BASE_DIR
    print(f"[DEBUG] Running as script", flush=True)
    print(f"[DEBUG] BASE_DIR: {BASE_DIR}", flush=True)

# Change to app directory to ensure relative paths work
try:
    os.chdir(APP_DIR)
    print(f"[DEBUG] Changed to directory: {APP_DIR}", flush=True)
except Exception as e:
    print(f"[WARNING] Could not change directory: {e}", flush=True)

# Import servers with error handling
HAS_FLASK = False
try:
    from flask import Flask
    import flask
    HAS_FLASK = True
    print("[IMPORT] Flask loaded successfully", flush=True)
except ImportError as e:
    HAS_FLASK = False
    print(f"[ERROR] Flask not found: {e}", flush=True)
    print("[ERROR] Please install requirements.txt", flush=True)
except Exception as e:
    HAS_FLASK = False
    print(f"[ERROR] Failed to import Flask: {e}", flush=True)

try:
    import http.server
    import socketserver
    import requests
    import socket
    print("[IMPORT] Standard modules loaded", flush=True)
except Exception as e:
    print(f"[ERROR] Failed to import standard modules: {e}", flush=True)
    sys.exit(1)

# CRITICAL: Import api_server at module level so PyInstaller can detect it
# PyInstaller analyzes ALL imports at module level, even in try/except
# This ensures api_server.py is included in the bundle
try:
    import api_server  # NOQA: F401 - Imported for PyInstaller analysis
    API_SERVER_AVAILABLE = True
    print("[IMPORT] api_server module detected", flush=True)
except (ImportError, ModuleNotFoundError):
    # This is OK during build - PyInstaller will still include it if it sees the import
    # At runtime, we'll handle it in start_backend()
    API_SERVER_AVAILABLE = False
    print("[IMPORT] api_server will be loaded dynamically", flush=True)
except Exception as e:
    API_SERVER_AVAILABLE = False
    print(f"[IMPORT] api_server import check: {e}", flush=True)

# Configuration
BACKEND_PORT = 5000
FRONTEND_PORT = 8000
BACKEND_URL = f"http://localhost:{BACKEND_PORT}"
FRONTEND_URL = f"http://localhost:{FRONTEND_PORT}/nexus.html"

# Global flags
backend_process = None
frontend_thread = None
backend_ready = False
frontend_ready = False


def check_port(port):
    """Check if a port is available"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0
    except:
        return False


def wait_for_service(url, name, timeout=30):
    """Wait for a service to become available"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            if response.status_code in [200, 404]:  # 404 is OK, means server is running
                return True
        except:
            pass
        time.sleep(1)
    return False


def start_backend():
    """Start the Flask backend server"""
    global backend_process, backend_ready
    
    print(f"[BACKEND] ==========================================", flush=True)
    print(f"[BACKEND] Starting API server on port {BACKEND_PORT}...", flush=True)
    print(f"[BACKEND] ==========================================", flush=True)
    sys.stdout.flush()
    
    # Check if port is already in use
    if check_port(BACKEND_PORT):
        print(f"[BACKEND] Port {BACKEND_PORT} is already in use", flush=True)
        print(f"[BACKEND] Attempting to verify existing backend...", flush=True)
        try:
            response = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
            if response.status_code == 200:
                print(f"[BACKEND] Existing backend is running and healthy", flush=True)
                backend_ready = True
                return
        except:
            print(f"[BACKEND] Port in use but not responding - may need to free port {BACKEND_PORT}", flush=True)
            print(f"[BACKEND] CRITICAL: Kill existing process on port 5000:", flush=True)
            print(f"[BACKEND]   netstat -ano | findstr :5000", flush=True)
            print(f"[BACKEND]   taskkill /PID <pid> /F", flush=True)
            backend_ready = False
            return
    
    # Import and start backend
    try:
        # Add multiple paths to sys.path to find api_server
        paths_to_add = [
            str(APP_DIR),      # Where exe is located
            str(BASE_DIR),     # Extracted temp directory
            str(Path.cwd()),   # Current working directory
        ]
        
        for path in paths_to_add:
            if path not in sys.path:
                sys.path.insert(0, path)
                print(f"[BACKEND] Added to path: {path}", flush=True)
        
        # Try to import api_server
        print(f"[BACKEND] Attempting to import api_server...", flush=True)
        
        # If already imported at module level, use it
        if API_SERVER_AVAILABLE and 'api_server' in sys.modules:
            api_server = sys.modules['api_server']
            print(f"[BACKEND] ✓ Using pre-imported api_server", flush=True)
        else:
            try:
                import api_server
                print(f"[BACKEND] ✓ Successfully imported api_server", flush=True)
            except ImportError as ie:
                # Try to find api_server.py file
                api_server_path = None
                for path in paths_to_add:
                    test_path = Path(path) / "api_server.py"
                    if test_path.exists():
                        api_server_path = test_path
                        print(f"[BACKEND] Found api_server.py at: {api_server_path}", flush=True)
                        break
                
                if api_server_path:
                    # Try importing from file path
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("api_server", api_server_path)
                    if spec and spec.loader:
                        api_server = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(api_server)
                        print(f"[BACKEND] ✓ Loaded api_server from file path", flush=True)
                    else:
                        raise ImportError(f"Could not load api_server from {api_server_path}")
                else:
                    print(f"[BACKEND ERROR] api_server.py not found in any path", flush=True)
                    for path in paths_to_add:
                        print(f"  - Checked: {path}", flush=True)
                    raise ie
        
        # Start Flask app in a thread
        def run_backend():
            global backend_ready
            try:
                print(f"[BACKEND] Starting Flask app...", flush=True)
                sys.stdout.flush()
                # Disable Flask's reloader and debug mode for production
                # Set threaded=True for concurrent requests
                print(f"[BACKEND] Flask app starting on 0.0.0.0:{BACKEND_PORT}", flush=True)
                api_server.app.run(host='0.0.0.0', port=BACKEND_PORT, debug=False, use_reloader=False, threaded=True)
            except OSError as e:
                if 'address already in use' in str(e).lower():
                    print(f"[BACKEND ERROR] Port {BACKEND_PORT} already in use!", flush=True)
                    print(f"[BACKEND] Another instance may be running. Kill it with:", flush=True)
                    print(f"[BACKEND]   netstat -ano | findstr :{BACKEND_PORT}", flush=True)
                else:
                    print(f"[BACKEND ERROR] OS error: {e}", flush=True)
                import traceback
                traceback.print_exc()
                backend_ready = False
            except Exception as e:
                print(f"[BACKEND ERROR] Flask run error: {e}", flush=True)
                import traceback
                traceback.print_exc()
                backend_ready = False
        
        backend_thread = threading.Thread(target=run_backend, daemon=True)
        backend_thread.start()
        
        # Wait for backend to start
        print(f"[BACKEND] Waiting for backend to respond...", flush=True)
        if wait_for_service(f"{BACKEND_URL}/api/health", "Backend", timeout=15):
            print(f"[BACKEND] ✓ Started successfully", flush=True)
            backend_ready = True
        else:
            print(f"[BACKEND] ⚠ Started but not responding yet (may still be initializing)", flush=True)
            backend_ready = True  # Assume it's starting
    except Exception as e:
        print(f"[BACKEND ERROR] Failed to start: {e}", flush=True)
        import traceback
        traceback.print_exc()
        backend_ready = False


def start_frontend():
    """Start the HTML frontend server"""
    global frontend_thread, frontend_ready
    
    print(f"[FRONTEND] Starting web server on port {FRONTEND_PORT}...")
    
    # Check if port is already in use
    if check_port(FRONTEND_PORT):
        print(f"[FRONTEND] Port {FRONTEND_PORT} is already in use")
        try:
            response = requests.get(FRONTEND_URL, timeout=2)
            if response.status_code == 200:
                print(f"[FRONTEND] Existing frontend is running")
                frontend_ready = True
                return
        except:
            print(f"[FRONTEND] Port in use but not responding")
            frontend_ready = False
            return
    
    # Find HTML file - check both BASE_DIR (extracted) and APP_DIR (exe location)
    html_file = None
    possible_paths = [
        BASE_DIR / "nexus.html",  # In extracted temp directory
        APP_DIR / "nexus.html",    # Next to executable
        Path("nexus.html"),        # Current directory
    ]
    
    for path in possible_paths:
        if path.exists():
            html_file = path
            print(f"[FRONTEND] Found HTML file at: {html_file}", flush=True)
            break
    
    if not html_file or not html_file.exists():
        print(f"[FRONTEND ERROR] HTML file not found in any location:", flush=True)
        for path in possible_paths:
            print(f"  - {path} (exists: {path.exists()})", flush=True)
        frontend_ready = False
        return
    
    # Create custom request handler
    class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def list_directory(self, path):
            self.send_error(403, "Forbidden")
            return None
        
        def _proxy_api_request(self, method='GET'):
            """Proxy API requests to the backend server"""
            try:
                # Check if backend is ready
                if not backend_ready:
                    # Backend not ready - return JSON error instead of HTML
                    error_response = {
                        'success': False,
                        'error': 'Backend server is not ready yet. Please wait a moment and try again.',
                        'code': 'BACKEND_NOT_READY'
                    }
                    self.send_response(503)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(str(error_response))))
                    self.end_headers()
                    import json
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))
                    return
                
                import urllib.parse
                # Get the full path including query string
                full_path = self.path
                if '?' in full_path:
                    path, query = full_path.split('?', 1)
                else:
                    path = full_path
                    query = ''
                
                # Build backend URL
                backend_url = f"{BACKEND_URL}{path}"
                if query:
                    backend_url += f"?{query}"
                
                # Get request headers (excluding host)
                headers = {}
                for header_name, header_value in self.headers.items():
                    if header_name.lower() not in ['host', 'connection']:
                        headers[header_name] = header_value
                
                # Get request body for POST/PUT/PATCH
                body = None
                if method in ['POST', 'PUT', 'PATCH']:
                    content_length = self.headers.get('Content-Length')
                    if content_length:
                        body = self.rfile.read(int(content_length))
                
                # Make request to backend with shorter timeout for faster failure
                try:
                    if method == 'GET':
                        response = requests.get(backend_url, headers=headers, timeout=5)
                    elif method == 'POST':
                        response = requests.post(backend_url, headers=headers, data=body, timeout=5)
                    elif method == 'PUT':
                        response = requests.put(backend_url, headers=headers, data=body, timeout=5)
                    elif method == 'DELETE':
                        response = requests.delete(backend_url, headers=headers, timeout=5)
                    else:
                        error_response = {'success': False, 'error': 'Method not allowed', 'code': 'METHOD_NOT_ALLOWED'}
                        self.send_response(405)
                        self.send_header('Content-Type', 'application/json')
                        import json
                        self.end_headers()
                        self.wfile.write(json.dumps(error_response).encode('utf-8'))
                        return
                except requests.exceptions.ConnectionError as ce:
                    # Backend connection refused - return JSON error
                    error_response = {
                        'success': False,
                        'error': 'Backend server is not running. Please restart the application.',
                        'code': 'BACKEND_CONNECTION_REFUSED',
                        'details': 'The backend API server on port 5000 is not accessible.'
                    }
                    self.send_response(503)
                    self.send_header('Content-Type', 'application/json')
                    import json
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))
                    print(f"[PROXY ERROR] Backend connection refused: {ce}", flush=True)
                    return
                except requests.exceptions.Timeout:
                    # Backend timeout - return JSON error
                    error_response = {
                        'success': False,
                        'error': 'Backend server is not responding. Please wait a moment and try again.',
                        'code': 'BACKEND_TIMEOUT'
                    }
                    self.send_response(504)
                    self.send_header('Content-Type', 'application/json')
                    import json
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))
                    return
                
                # Forward response
                self.send_response(response.status_code)
                # Forward headers (excluding some that shouldn't be forwarded)
                for header_name, header_value in response.headers.items():
                    if header_name.lower() not in ['content-encoding', 'transfer-encoding', 'connection']:
                        self.send_header(header_name, header_value)
                self.end_headers()
                self.wfile.write(response.content)
            except Exception as e:
                print(f"[PROXY ERROR] Failed to proxy API request: {e}", flush=True)
                import traceback
                traceback.print_exc()
                # Return JSON error instead of HTML
                error_response = {
                    'success': False,
                    'error': f'Proxy error: {str(e)}',
                    'code': 'PROXY_ERROR'
                }
                self.send_response(502)
                self.send_header('Content-Type', 'application/json')
                import json
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode('utf-8'))

        def do_GET(self):
            path = self.path.split('?')[0]
            clean_path = path.lstrip('/').strip()
            
            # Proxy API requests to backend
            if clean_path.startswith('api/'):
                self._proxy_api_request('GET')
                return
            
            if clean_path == "" or clean_path == "/":
                # Default redirect to login page (authentication will handle routing)
                self.send_response(302)
                self.send_header('Location', '/login.html')
                self.end_headers()
                return
            
            # Special routes that should serve the main app
            if clean_path == "app" or clean_path == "tool":
                # Serve main application HTML
                if html_file and html_file.exists():
                    with open(html_file, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_error(404, "Main application file not found")
                return
            
            # Allowed HTML files - check multiple locations
            login_paths = [
                BASE_DIR / "login.html",
                APP_DIR / "login.html",
                Path("login.html")
            ]
            login_file = None
            for path in login_paths:
                if path.exists():
                    login_file = path
                    break
            
            change_pwd_paths = [
                BASE_DIR / "change-password.html",
                APP_DIR / "change-password.html",
                Path("change-password.html")
            ]
            change_pwd_file = None
            for path in change_pwd_paths:
                if path.exists():
                    change_pwd_file = path
                    break
            
            allowed_files = {
                "nexus.html": html_file,
            }
            if login_file:
                allowed_files["login.html"] = login_file
            if change_pwd_file:
                allowed_files["change-password.html"] = change_pwd_file
            
            if clean_path in allowed_files:
                file_path = allowed_files[clean_path]
                if file_path.exists():
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_error(404, "File not found")
            else:
                self.send_error(404, "File not found")

        def do_POST(self):
            """Handle POST requests - proxy API requests to backend"""
            path = self.path.split('?')[0]
            clean_path = path.lstrip('/').strip()
            
            # Proxy API requests to backend
            if clean_path.startswith('api/'):
                self._proxy_api_request('POST')
                return
            
            # For non-API POST requests, return 404
            self.send_error(404, "Not found")
        
        def do_PUT(self):
            """Handle PUT requests - proxy API requests to backend"""
            path = self.path.split('?')[0]
            clean_path = path.lstrip('/').strip()
            
            # Proxy API requests to backend
            if clean_path.startswith('api/'):
                self._proxy_api_request('PUT')
                return
            
            # For non-API PUT requests, return 404
            self.send_error(404, "Not found")
        
        def do_DELETE(self):
            """Handle DELETE requests - proxy API requests to backend"""
            path = self.path.split('?')[0]
            clean_path = path.lstrip('/').strip()
            
            # Proxy API requests to backend
            if clean_path.startswith('api/'):
                self._proxy_api_request('DELETE')
                return
            
            # For non-API DELETE requests, return 404
            self.send_error(404, "Not found")

        def log_message(self, format, *args):
            # Suppress noisy logs from network scanners and bots
            if args and len(args) >= 2:
                # Extract client IP and status code
                # Format: log_message(format, client_ip, status_code, ...)
                try:
                    # Try to extract IP from first arg (might be in different positions)
                    log_line = ' '.join(str(arg) for arg in args)
                    client_ip = None
                    status_code = None
                    
                    # Look for IP address pattern
                    import re
                    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_line)
                    if ip_match:
                        client_ip = ip_match.group(1)
                    
                    # Look for status code (400, 404, etc.)
                    status_match = re.search(r'\b(400|404|403)\b', log_line)
                    if status_match:
                        status_code = int(status_match.group(1))
                    
                    # Suppress bad request errors from broadcast addresses or scanner IPs
                    if status_code == 400 and client_ip:
                        # Check if it's a broadcast address or suspicious pattern
                        if '.255' in client_ip or client_ip.startswith('192.168.225'):
                            return  # Suppress these noisy scanner requests
                    
                    # Suppress all 400 errors (bad requests) - they're usually scanners
                    if status_code == 400:
                        return  # Suppress all bad request errors
                    
                    # Only log successful access to the UI file
                    if 'GET' in log_line and ('nexus.html' in log_line or 'GET / HTTP' in log_line):
                        super().log_message(format, *args)
                except:
                    # If parsing fails, suppress the log to avoid errors
                    pass
            # Suppress all other logs by default
    
    # Start server in thread
    def run_frontend():
        global frontend_ready
        try:
            os.chdir(APP_DIR)  # Ensure we're in the right directory
            Handler = SecureHTTPRequestHandler
            # Allow reuse of address to prevent "Address already in use" errors
            socketserver.TCPServer.allow_reuse_address = True
            httpd = socketserver.TCPServer(("0.0.0.0", FRONTEND_PORT), Handler)
            httpd.allow_reuse_address = True
            frontend_ready = True
            print(f"[FRONTEND] ✓ Started successfully on port {FRONTEND_PORT}", flush=True)
            sys.stdout.flush()
            httpd.serve_forever()
        except OSError as e:
            if 'address already in use' in str(e).lower():
                print(f"[FRONTEND ERROR] Port {FRONTEND_PORT} already in use!", flush=True)
                print(f"[FRONTEND] Another instance may be running. Kill it with:", flush=True)
                print(f"[FRONTEND]   netstat -ano | findstr :{FRONTEND_PORT}", flush=True)
                print(f"[FRONTEND]   taskkill /PID <pid> /F", flush=True)
            else:
                print(f"[FRONTEND ERROR] OS error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            frontend_ready = False
        except Exception as e:
            print(f"[FRONTEND ERROR] {e}", flush=True)
            import traceback
            traceback.print_exc()
            frontend_ready = False
    
    frontend_thread = threading.Thread(target=run_frontend, daemon=True)
    frontend_thread.start()
    
    # Wait for frontend to start
    time.sleep(2)
    if check_port(FRONTEND_PORT):
        frontend_ready = True
        print(f"[FRONTEND] ✓ Started successfully")
    else:
        print(f"[FRONTEND] ⚠ May still be starting...")


def main():
    """Main launcher function"""
    # Force output immediately with visible header
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║           NOC CONFIG MAKER - UNIFIED APPLICATION               ║
    ║                      Backend + AI + Frontend                   ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    try:
        print(banner, flush=True)
        print("", flush=True)
        print("=" * 70, flush=True)
        print("LAUNCHER STARTED - Initializing services...", flush=True)
        print("=" * 70, flush=True)
        print("", flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception as e:
        # If print fails, try writing directly
        try:
            sys.stdout.write("NEXUS - Starting...\n")
            sys.stdout.flush()
        except:
            pass
    
    # Start backend
    print("[MAIN] Starting backend...", flush=True)
    start_backend()
    print(flush=True)
    
    # Wait for backend to be ready before starting frontend
    global backend_ready
    print("[MAIN] Waiting for backend to be ready...", flush=True)
    max_wait = 20  # Maximum seconds to wait
    waited = 0
    while not backend_ready and waited < max_wait:
        time.sleep(1)
        waited += 1
        # Check if backend is actually responding
        try:
            response = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
            if response.status_code == 200:
                backend_ready = True
                print(f"[MAIN] ✓ Backend is ready after {waited} seconds", flush=True)
                break
        except:
            if waited % 3 == 0:  # Print status every 3 seconds
                print(f"[MAIN] Still waiting for backend... ({waited}/{max_wait}s)", flush=True)
    
    if not backend_ready:
        print(f"[MAIN] ⚠ Backend not ready after {max_wait} seconds, starting frontend anyway", flush=True)
        print(f"[MAIN] ⚠ Some features may not work until backend is ready", flush=True)
    else:
        print(f"[MAIN] ✓ Backend confirmed ready", flush=True)
    
    # Start frontend
    print("[MAIN] Starting frontend...", flush=True)
    start_frontend()
    print(flush=True)
    
    # Wait a moment for everything to initialize
    time.sleep(2)
    
    # Open browser
    print("")
    print("=" * 70)
    print(" " * 20 + "SERVICE STATUS")
    print("=" * 70)
    
    backend_status = "✓ READY" if backend_ready else "✗ NOT READY"
    frontend_status = "✓ READY" if frontend_ready else "✗ NOT READY"
    
    print(f"Backend API:  {backend_status:15} - {BACKEND_URL}")
    print(f"Frontend:     {frontend_status:15} - {FRONTEND_URL}")
    print("")
    
    if not backend_ready:
        print("⚠️  WARNING: Backend did not start!")
        print("   Check error messages above for details.")
        print("")
    
    if not frontend_ready:
        print("⚠️  WARNING: Frontend did not start!")
        print("   Check error messages above for details.")
        print("")
    
    if frontend_ready:
        print("Opening browser...")
        try:
            webbrowser.open(FRONTEND_URL)
        except:
            print(f"Please open manually: {FRONTEND_URL}")
    else:
        print(f"Frontend not ready. Please check errors above.")
        print(f"Try opening manually: {FRONTEND_URL}")
    
    print()
    print("=" * 70)
    print("Application is running. Keep this window open.")
    print("Press Ctrl+C to stop all services.")
    print("=" * 70)
    print()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
            # Check if services are still running
            if backend_ready and not check_port(BACKEND_PORT):
                print("[WARNING] Backend appears to have stopped")
            if frontend_ready and not check_port(FRONTEND_PORT):
                print("[WARNING] Frontend appears to have stopped")
    except KeyboardInterrupt:
        print()
        print("Shutting down...")
        print("Services stopped.")


if __name__ == '__main__':
    # Show immediate startup message
    print("\n" + "=" * 70)
    print("NEXUS - STARTING...")
    print("=" * 70 + "\n")
    sys.stdout.flush()
    
    try:
        # Ensure output is visible
        print("", flush=True)  # Force console to appear
        sys.stdout.flush()
        sys.stderr.flush()
        
        # Run main
        main()
    except Exception as e:
        # Critical error - try to show it
        try:
            print("\n" + "!" * 70)
            print("CRITICAL ERROR IN LAUNCHER")
            print("!" * 70)
            error_msg = f"\nError: {str(e)}\n"
            sys.stderr.write(error_msg)
            sys.stderr.flush()
            import traceback
            traceback.print_exc()
            print("\n" + "!" * 70)
            print("Press Enter to exit...")
            print("!" * 70 + "\n")
        except:
            pass
        # Keep window open so user can see error
        try:
            print("\n" + "=" * 70)
            print("CRITICAL ERROR - Application cannot start")
            print("=" * 70)
            print("\nPlease check the error messages above.")
            print("Common issues:")
            print("  - Port 5000 or 8000 already in use")
            print("  - Firewall blocking ports")
            print("  - Missing dependencies")
            print("\nPress Enter to exit...")
            input()
        except:
            time.sleep(60)  # Wait 60 seconds so error is visible

