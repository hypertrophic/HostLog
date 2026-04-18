// ============================================================
//  APP.JS — HostLog Dashboard
// ============================================================

(function () {
    'use strict';

    // ─── THEME ────────────────────────────────────────────────

    const root   = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const saved  = localStorage.getItem('hl-theme') || 'dark';
    root.setAttribute('data-theme', saved);

    if (toggle) {
        toggle.addEventListener('click', () => {
            const current = root.getAttribute('data-theme');
            const next    = current === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            localStorage.setItem('hl-theme', next);
        });
    }

    // ─── NAVIGATION ───────────────────────────────────────────

    const navItems  = document.querySelectorAll('.nav-item[data-section]');
    const sections  = document.querySelectorAll('.section');

    function showSection(id) {
        sections.forEach(s => s.classList.remove('active'));
        navItems.forEach(n => n.classList.remove('active'));

        const section = document.getElementById(id);
        const navItem = document.querySelector(`.nav-item[data-section="${id}"]`);

        if (section) {
            section.classList.add('active');
            // Re-trigger animation
            section.style.animation = 'none';
            section.offsetHeight;
            section.style.animation = '';
        }
        if (navItem) navItem.classList.add('active');
        location.hash = id;
    }

    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            showSection(item.dataset.section);
        });
    });

    // Restore section from hash
    const hash = location.hash.replace('#', '');
    if (hash && document.getElementById(hash)) {
        showSection(hash);
    }

    // ─── TOAST ────────────────────────────────────────────────

    function toast(message, type = 'ok') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const el = document.createElement('div');
        el.className = `toast toast-${type}`;

        const icon = { ok: '✓', error: '✕', warn: '⚠' }[type] || '•';
        el.innerHTML = `<span>${icon}</span><span>${message}</span>`;

        container.appendChild(el);

        setTimeout(() => {
            el.style.animation = 'toastOut 0.3s ease both';
            el.addEventListener('animationend', () => el.remove());
        }, 3500);
    }

    // ─── API HELPER ───────────────────────────────────────────

    async function api(action, data = {}) {
        const form = new FormData();
        form.append('action',     action);
        form.append('csrf_token', typeof CSRF !== 'undefined' ? CSRF : '');
        Object.entries(data).forEach(([k, v]) => {
            if (Array.isArray(v)) v.forEach(item => form.append(k + '[]', item));
            else form.append(k, v);
        });

        try {
            const res  = await fetch('actions.php', { method: 'POST', body: form });
            const json = await res.json();
            return json;
        } catch (err) {
            return { ok: false, error: 'Network error' };
        }
    }

    // ─── BLOCK / UNBLOCK ──────────────────────────────────────

    window.blockIP = async function (ip) {
        if (!ip || !ip.trim()) { toast('Enter an IP address', 'warn'); return; }
        ip = ip.trim();
        if (!confirm(`Block ${ip}?`)) return;

        const res = await api('block_ip', { ip });
        if (res.ok) {
            toast(res.message, 'ok');
            addBlockedRow(ip);
        } else {
            toast(res.error, 'error');
        }
    };

    window.unblockIP = async function (ip) {
        if (!confirm(`Unblock ${ip}?`)) return;
        const res = await api('unblock_ip', { ip });
        if (res.ok) {
            toast(res.message, 'ok');
            removeBlockedRow(ip);
        } else {
            toast(res.error, 'error');
        }
    };

    window.unblockAll = async function () {
        if (!confirm('Remove ALL HostLog block rules from .htaccess?')) return;
        const res = await api('unblock_all');
        if (res.ok) {
            toast(res.message, 'ok');
            const tbody = document.getElementById('blockedTableBody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No IPs currently blocked.</td></tr>';
            const count = document.getElementById('blockedCount');
            if (count) count.textContent = '0';
        } else {
            toast(res.error, 'error');
        }
    };

    function addBlockedRow(ip) {
        const tbody = document.getElementById('blockedTableBody');
        const count = document.getElementById('blockedCount');

        if (!tbody) return;

        // Remove empty state if present
        const empty = tbody.querySelector('.empty-state');
        if (empty) empty.closest('tr')?.remove();

        const id  = 'blocked-' + btoa(ip).replace(/=/g, '');
        if (document.getElementById(id)) return;

        const tr  = document.createElement('tr');
        tr.id     = id;
        tr.innerHTML = `
            <td><span class="mono">${escHtml(ip)}</span></td>
            <td><button class="btn btn-sm btn-outline" onclick="unblockIP('${escHtml(ip)}')">Unblock</button></td>
        `;
        tbody.appendChild(tr);

        if (count) count.textContent = parseInt(count.textContent || '0') + 1;
    }

    function removeBlockedRow(ip) {
        const id  = 'blocked-' + btoa(ip).replace(/=/g, '');
        const row = document.getElementById(id);
        if (row) {
            row.style.animation = 'toastOut 0.3s ease both';
            row.addEventListener('animationend', () => row.remove());
        }
        const count = document.getElementById('blockedCount');
        if (count) count.textContent = Math.max(0, parseInt(count.textContent || '1') - 1);
    }

    // ─── WHITELIST ────────────────────────────────────────────

    window.whitelistIP = async function (ip) {
        if (!confirm(`Add ${ip} to whitelist?`)) return;
        const res = await api('whitelist_add', { type: 'ips', value: ip });
        if (res.ok) toast(res.message, 'ok');
        else        toast(res.error, 'error');
    };

    window.addWhitelist = async function () {
        const type  = document.getElementById('wlType')?.value;
        const value = document.getElementById('wlValue')?.value?.trim();
        if (!value) { toast('Enter a value', 'warn'); return; }

        const res = await api('whitelist_add', { type, value });
        if (res.ok) {
            toast(res.message, 'ok');
            document.getElementById('wlValue').value = '';
            refreshWhitelist();
        } else {
            toast(res.error, 'error');
        }
    };

    window.removeWhitelist = async function (type, value) {
        const res = await api('whitelist_remove', { type, value });
        if (res.ok) { toast(res.message, 'ok'); refreshWhitelist(); }
        else          toast(res.error, 'error');
    };

    async function refreshWhitelist() {
        const res = await api('get_whitelist');
        if (!res.ok) return;

        const wl     = res.whitelist;
        const labels = { ips: 'IP Addresses', paths: 'Paths', user_agents: 'User Agents' };
        const display = document.getElementById('whitelistDisplay');
        if (!display) return;

        display.innerHTML = Object.entries(labels).map(([type, label]) => {
            const items = wl[type] || [];
            const rows  = items.length
                ? items.map(item => `
                    <div class="wl-item">
                        <span class="mono">${escHtml(item)}</span>
                        <button class="btn btn-xs btn-ghost" onclick="removeWhitelist('${type}','${escHtml(item)}')">✕</button>
                    </div>`).join('')
                : '<span class="text-muted small">None</span>';
            return `<div class="wl-group"><div class="wl-group-label">${label}</div>${rows}</div>`;
        }).join('');
    }

    // ─── LOGS — DOWNLOAD ──────────────────────────────────────

    window.downloadLogs = function (filtered) {
        const domain   = document.getElementById('dlDomain')?.value;
        const dateFrom = document.getElementById('dlFrom')?.value;
        const dateTo   = document.getElementById('dlTo')?.value;

        if (!domain) { toast('Select a domain', 'warn'); return; }

        const form   = document.createElement('form');
        form.method  = 'POST';
        form.action  = 'actions.php';
        const fields = {
            action:     'download_logs',
            csrf_token: typeof CSRF !== 'undefined' ? CSRF : '',
            domain,
            date_from:  dateFrom,
            date_to:    dateTo,
            filtered:   filtered ? '1' : '0',
        };
        Object.entries(fields).forEach(([k, v]) => {
            const input = document.createElement('input');
            input.type  = 'hidden';
            input.name  = k;
            input.value = v;
            form.appendChild(input);
        });
        document.body.appendChild(form);
        form.submit();
        form.remove();
    };

    // ─── LOGS — DELETE ────────────────────────────────────────

    window.deleteLogs = async function () {
        const select  = document.getElementById('delDomains');
        const domains = Array.from(select?.selectedOptions || []).map(o => o.value);
        const range   = document.getElementById('delRange')?.value;
        const specific= document.getElementById('specificDay')?.value;

        if (!domains.length) { toast('Select at least one domain', 'warn'); return; }

        const label = range === 'specific' ? `day ${specific}` : `last ${range} days`;
        if (!confirm(`Delete logs for ${domains.join(', ')} — ${label}?\n\nThis cannot be undone.`)) return;

        const res = await api('delete_logs', { domains, range, specific_day: specific });
        if (res.ok) toast(res.message, 'ok');
        else        toast(res.error, 'error');
    };

    window.toggleSpecificDay = function () {
        const range = document.getElementById('delRange')?.value;
        const wrap  = document.getElementById('specificDayWrap');
        if (wrap) wrap.style.display = range === 'specific' ? '' : 'none';
    };

    // ─── CUSTOM FIELD EXPORT ──────────────────────────────────

    window.exportCustom = function () {
        const domain = document.getElementById('cfDomain')?.value;
        const from   = document.getElementById('cfFrom')?.value;
        const to     = document.getElementById('cfTo')?.value;

        const form   = document.createElement('form');
        form.method  = 'POST';
        form.action  = 'actions.php';
        const fields = {
            action:     'export_custom',
            csrf_token: typeof CSRF !== 'undefined' ? CSRF : '',
            domain,
            date_from:  from,
            date_to:    to,
        };
        Object.entries(fields).forEach(([k, v]) => {
            const input = document.createElement('input');
            input.type  = 'hidden';
            input.name  = k;
            input.value = v;
            form.appendChild(input);
        });
        document.body.appendChild(form);
        form.submit();
        form.remove();
    };

    // ─── UTILS ────────────────────────────────────────────────

    function escHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // ─── LOGIN FORM UX ────────────────────────────────────────

    const loginForm = document.querySelector('.login-form');
    if (loginForm) {
        const btn = loginForm.querySelector('button[type="submit"]');
        loginForm.addEventListener('submit', () => {
            if (btn) {
                btn.disabled    = true;
                btn.innerHTML   = '<span>Authenticating…</span>';
            }
        });
    }

})();
