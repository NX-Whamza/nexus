# Quick Fix for Tar Extraction

## The Problem
You're using the wrong filename. The `ls` command shows:
```
nexus-vm-20251208-210556.tar.gz
```

But you tried to extract:
```
nexus-vm-20251208-210255.tar.gz  ❌ (wrong timestamp)
```

## Solution - Use the EXACT filename:

```bash
cd ~/vm_deployment
tar -xzf nexus-vm-20251208-210556.tar.gz
```

## Or use this safer method:

```bash
cd ~/vm_deployment

# Method 1: Copy the exact filename from ls output
ls -1 nexus-vm-*.tar.gz
# Then use that EXACT filename:
tar -xzf nexus-vm-20251208-210556.tar.gz

# Method 2: Use wildcard with proper syntax
tar -xzf nexus-vm-*.tar.gz

# Method 3: Extract to current directory explicitly
tar -xzf nexus-vm-*.tar.gz -C .
```

## Complete Step-by-Step:

```bash
# 1. Make sure you're in the right directory
cd ~/vm_deployment

# 2. List files to see exact name
ls -lh nexus-vm-*.tar.gz

# 3. Extract using the EXACT filename shown above
tar -xzf nexus-vm-20251208-210556.tar.gz

# 4. Verify extraction
ls -la

# 5. Start the Docker stack
cd ~/nexus
docker compose up -d --build

# 6. Run domain setup
bash vm_deployment/configure_nginx_domain.sh
```

## If you still get errors:

Try extracting with verbose output to see what's happening:
```bash
tar -xzvf nexus-vm-20251208-210556.tar.gz
```

The `-v` flag shows what files are being extracted so you can see progress.
