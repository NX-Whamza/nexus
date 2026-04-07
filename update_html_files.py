#!/usr/bin/env python3
"""
Complete HTML Update Script
Updates both nexus.html files with:
1. Feedback form submission handler
2. Migration UI with device selection
3. All necessary JavaScript functions
"""

import re
import os
from pathlib import Path

# File paths
ROOT_HTML = Path("nexus.html")
VM_HTML = Path("vm_deployment/nexus.html")

def add_feedback_handler(html_content):
    """Add feedback form submission handler if missing"""
    
    # Check if handler already exists
    if 'feedbackForm' in html_content and 'addEventListener' in html_content:
        print("✓ Feedback handler already exists")
        return html_content
    
    # Find where to insert (before closing </script> tag near end of file)
    feedback_handler = '''
    // Feedback Form Submission Handler
    document.addEventListener('DOMContentLoaded', function() {
        const feedbackForm = document.getElementById('feedbackForm');
        if (feedbackForm) {
            feedbackForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const submitBtn = this.querySelector('.btn-submit') || this.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Sending...';
                }
                
                const activeTab = document.querySelector('.feedback-tab.active');
                const feedbackType = activeTab ? activeTab.dataset.type : 'feedback';
                
                const formData = {
                    type: feedbackType,
                    subject: document.getElementById('feedbackSubject')?.value || '',
                    category: document.getElementById('feedbackCategory')?.value || '',
                    experience: document.getElementById('feedbackExperience')?.value || '',
                    details: document.getElementById('feedbackDetails')?.value || '',
                    name: document.getElementById('feedbackName')?.value || 'Anonymous',
                    timestamp: new Date().toISOString()
                };
                
                try {
                    const apiBase = window.AI_API_BASE || '/api';
                    const response = await fetch(`${apiBase}/feedback`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(formData)
                    });
                    
                    if (response.ok) {
                        const successEl = document.getElementById('feedbackSuccess');
                        if (successEl) {
                            successEl.classList.add('show');
                        }
                        this.reset();
                        setTimeout(() => {
                            if (typeof closeFeedbackModal === 'function') {
                                closeFeedbackModal();
                            }
                        }, 2000);
                    } else {
                        alert('Failed to submit feedback. Please try again.');
                    }
                } catch (err) {
                    console.error('Feedback submission error:', err);
                    alert('Could not connect to server. Please check your connection.');
                } finally {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = '▶ SUBMIT';
                    }
                }
            });
            console.log('✓ Feedback form handler attached');
        }
    });
    '''
    
    # Insert before last </script> tag
    pattern = r'(</script>\s*</body>)'
    replacement = f'    {feedback_handler}\\n\\1'
    html_content = re.sub(pattern, replacement, html_content, count=1)
    
    print("✓ Added feedback form handler")
    return html_content

def add_migration_ui(html_content):
    """Add migration device selection UI if missing"""
    
    # Check if migration UI already has device selection
    if 'sourceDevice' in html_content and 'targetDevice' in html_content:
        print("✓ Migration UI already has device selection")
        return html_content
    
    # Migration device selection HTML
    migration_ui = '''
    <!-- Device Selection for Migration -->
    <div class="form-group">
        <label for="sourceDevice">Source Device (Optional - Auto-detect)</label>
        <select id="sourceDevice" class="form-control">
            <option value="">Auto-detect from config</option>
            <option value="CCR1036-12G-4S">CCR1036-12G-4S</option>
            <option value="CCR2004-1G-12S+2XS">CCR2004-1G-12S+2XS</option>
            <option value="CCR2004-16G-2S+">CCR2004-16G-2S+</option>
            <option value="CCR2116-12G-4S+">CCR2116-12G-4S+</option>
            <option value="CCR2216-1G-12XS-2XQ">CCR2216-1G-12XS-2XQ</option>
            <option value="CRS326-24G-2S+">CRS326-24G-2S+</option>
            <option value="CRS354-48G-4S+2Q+">CRS354-48G-4S+2Q+</option>
        </select>
    </div>
    
    <div class="form-group">
        <label for="targetDevice">Target Device *</label>
        <select id="targetDevice" class="form-control" required>
            <option value="">Select target device</option>
            <option value="CCR2004-1G-12S+2XS">CCR2004-1G-12S+2XS (1G + 12x10G SFP+ + 2x25G)</option>
            <option value="CCR2004-16G-2S+">CCR2004-16G-2S+ (16x1G + 2x10G SFP+)</option>
            <option value="CCR2116-12G-4S+">CCR2116-12G-4S+ (12x1G + 4x10G SFP+)</option>
            <option value="CCR2216-1G-12XS-2XQ">CCR2216-1G-12XS-2XQ (1G + 12x25G + 2x100G)</option>
            <option value="CCR1036-12G-4S">CCR1036-12G-4S (12x1G + 4xSFP)</option>
            <option value="CRS326-24G-2S+">CRS326-24G-2S+ (24x1G + 2x10G SFP+)</option>
            <option value="CRS354-48G-4S+2Q+">CRS354-48G-4S+2Q+ (48x1G + 4x10G + 2x40G)</option>
        </select>
    </div>
    '''
    
    # Find migration/upgrade section and add device selection
    # Look for common patterns in migration forms
    patterns = [
        r'(<div[^>]*class="[^"]*migration[^"]*"[^>]*>)',
        r'(<form[^>]*id="[^"]*migration[^"]*"[^>]*>)',
        r'(<div[^>]*id="[^"]*upgrade[^"]*"[^>]*>)'
    ]
    
    for pattern in patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            html_content = re.sub(pattern, f'\\1\\n{migration_ui}', html_content, count=1)
            print("✓ Added migration device selection UI")
            return html_content
    
    print("⚠ Could not find migration section to add device selection")
    return html_content

def update_migration_api_call(html_content):
    """Update migration API call to use new endpoint"""
    
    # Update API endpoint from old to new
    html_content = html_content.replace('/api/translate-config', '/api/migrate-config')
    html_content = html_content.replace('/api/upgrade-config', '/api/migrate-config')
    
    # Add device parameters to migration API calls
    migration_call_pattern = r'(fetch\([^)]*[\'"].*?/api/migrate-config[\'"][^)]*\{[^}]*)'
    
    def add_device_params(match):
        call = match.group(1)
        if 'source_device' not in call:
            # Add device parameters
            call += '''
                source_device: document.getElementById('sourceDevice')?.value || '',
                target_device: document.getElementById('targetDevice')?.value || '',
            '''
        return call
    
    html_content = re.sub(migration_call_pattern, add_device_params, html_content)
    
    print("✓ Updated migration API calls")
    return html_content

def process_html_file(filepath):
    """Process a single HTML file with all updates"""
    print(f"\\nProcessing: {filepath}")
    
    if not filepath.exists():
        print(f"✗ File not found: {filepath}")
        return False
    
    # Read file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_size = len(content)
    
    # Apply all updates
    content = add_feedback_handler(content)
    content = add_migration_ui(content)
    content = update_migration_api_call(content)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    new_size = len(content)
    print(f"✓ Updated {filepath}")
    print(f"  Size: {original_size:,} → {new_size:,} bytes ({new_size - original_size:+,})")
    
    return True

def main():
    """Main execution"""
    print("="*60)
    print("NEXUS - Complete HTML Update")
    print("="*60)
    
    # Process both files
    root_success = process_html_file(ROOT_HTML)
    vm_success = process_html_file(VM_HTML)
    
    print("\\n" + "="*60)
    if root_success and vm_success:
        print("✅ SUCCESS: Both files updated")
        print("\\nNext steps:")
        print("1. Restart api_server.py")
        print("2. Test feedback submission")
        print("3. Test migration with device selection")
    else:
        print("⚠ PARTIAL SUCCESS: Some files could not be updated")
        if not root_success:
            print(f"  - Failed: {ROOT_HTML}")
        if not vm_success:
            print(f"  - Failed: {VM_HTML}")
    print("="*60)

if __name__ == '__main__':
    main()
