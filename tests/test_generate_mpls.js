const fs = require('fs');
const path = require('path');
let JSDOM;
try {
  ({ JSDOM } = require('jsdom'));
} catch (e) {
  console.error('Missing dependency: jsdom');
  console.error('Install (from repo root): npm init -y && npm i jsdom');
  process.exit(2);
}

const htmlPath = path.join(__dirname, '..', 'vm_deployment', 'nexus.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const dom = new JSDOM(html, {
  runScripts: 'dangerously',
  resources: 'usable',
  pretendToBeVisual: true,
  url: 'http://localhost/app',
  beforeParse(window) {
    window.alert = function (msg) { console.log('ALERT:', msg); };
    // Bypass the immediate auth redirect in the SPA (it requires these to exist).
    try {
      window.localStorage.setItem('auth_token', 'test-token');
      window.localStorage.setItem('user_info', JSON.stringify({ username: 'test', isAdmin: true }));
    } catch (_) {}
    // jsdom doesn't provide fetch in the window realm by default.
    if (typeof window.fetch === 'undefined' && typeof global.fetch === 'function') {
      window.fetch = global.fetch.bind(global);
      window.Headers = global.Headers;
      window.Request = global.Request;
      window.Response = global.Response;
    }
  },
});
const { window } = dom;
// Wait for scripts to load
function waitFor(selector, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    (function poll() {
      const el = window.document.querySelector(selector);
      if (el) return resolve(el);
      if (Date.now() - start > timeout) return reject(new Error('Timeout waiting for ' + selector));
      setTimeout(poll, 100);
    })();
  });
}

setTimeout(async () => {
  try {
    await waitFor('#ent_mpls_routerboard_device', 5000);

    const deviceTypes = ['ccr2004', 'ccr1036', 'rb5009', 'ccr2216', 'ccr1072'];
    for (const dt of deviceTypes) {
      console.log('\n========================');
      console.log('Generating for device:', dt);
      console.log('========================\n');

      // set basic form
      const deviceSelect = window.document.getElementById('ent_mpls_routerboard_device');
      deviceSelect.value = dt;
      deviceSelect.dispatchEvent(new window.Event('change', { bubbles: true }));

      window.document.getElementById('ent_mpls_customerCode').value = 'IL-CARMI';
      window.document.getElementById('ent_mpls_loopbackIP').value = '10.5.0.57/32';

      // Auto-fill identity (readonly) via app helper
      if (typeof window.updateMPLSDeviceName === 'function') {
        window.updateMPLSDeviceName();
      }

      // Ensure interface dropdowns are populated
      if (typeof window.updateMPLSEnterpriseInterfaces === 'function') {
        window.updateMPLSEnterpriseInterfaces();
      }

      // ensure uplink exists
      const container = window.document.getElementById('ent_mpls_uplinksContainer');
      container.innerHTML = '';

      const deviceCfg = (window.DEVICE_CONFIGS && window.DEVICE_CONFIGS[dt]) ? window.DEVICE_CONFIGS[dt] : null;
      const firstPort =
        (deviceCfg && deviceCfg.sfpPorts && deviceCfg.sfpPorts[0]) ||
        (deviceCfg && deviceCfg.ports && deviceCfg.ports[0]) ||
        'ether1';

      const div = window.document.createElement('div');
      div.className = 'interface-item';
      const sel = window.document.createElement('select'); sel.className = 'ent_mpls_uplinkInterface';
      sel.innerHTML = `<option value="${firstPort}">${firstPort}</option>`;
      const ipIn = window.document.createElement('input'); ipIn.className = 'ent_mpls_uplinkIP'; ipIn.value = '10.1.253.84/29';
      const cIn = window.document.createElement('input'); cIn.className = 'ent_mpls_uplinkComment'; cIn.value = 'IL-CARMI-CN-1';
      div.appendChild(sel); div.appendChild(ipIn); div.appendChild(cIn); container.appendChild(div);

      const handoff = window.document.getElementById('ent_mpls_customerHandoff');
      if (handoff) {
        let opt = Array.from(handoff.options || []).find(o => o.value === firstPort);
        if (!opt) {
          opt = window.document.createElement('option');
          opt.value = firstPort;
          opt.text = firstPort;
          handoff.add(opt);
        }
        handoff.value = firstPort;
      }

      // call generator
      const genFn = window.generateMPLSEnterpriseConfig;
      try { genFn(); } catch(e){ console.error('Generator error:', e && e.stack ? e.stack : e); }
      // wait
      await new Promise(r=>setTimeout(r,300));
      const real = window.mplsEnterpriseConfigOriginal || '';
      console.log(real);
    }
    process.exit(0);
  } catch (e) {
    console.error('Test harness error:', e && e.stack ? e.stack : e);
    process.exit(2);
  }
}, 1200);
