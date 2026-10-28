// PII-Shield rule server panel. Plain script, no build step: hash routes,
// fetch against the JSON API, the DOM built with small helpers. Every
// state-changing call carries X-Requested-With, which the server requires
// with a session cookie (CSRF), and the session cookie itself.
'use strict';

(function () {
  // ---- helpers ----
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') el.className = v;
      else if (k === 'html') el.innerHTML = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c)));
    return el;
  }
  const $ = (sel, root) => (root || document).querySelector(sel);
  const app = $('#app'), nav = $('#nav');
  let toastTimer;
  function toast(text) {
    const t = $('#toast'); t.textContent = text; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
  }
  function fmtDate(s) { return s ? new Date(s).toLocaleString() : ''; }
  function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

  class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
  async function api(method, path, body, raw) {
    const opts = { method, headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const resp = await fetch(path, opts);
    if (resp.status === 204) return null;
    const text = await resp.text();
    let data = null; try { data = JSON.parse(text); } catch (e) { /* not json */ }
    if (!resp.ok) {
      if (resp.status === 401 && !raw) { state.me = null; route(); }
      throw new ApiError(resp.status, (data && data.error) || text || resp.statusText);
    }
    return data;
  }

  // ---- verify page (magic link) ----
  const verifyForm = $('#verify');
  if (verifyForm) {
    const token = new URLSearchParams(location.search).get('token') || '';
    $('#token').value = token;
    if (!token) { verifyForm.hidden = true; $('#missing').hidden = false; }
    return;
  }

  // ---- state and routing ----
  const state = { me: null, org: null };

  function orgSlug() { return state.me && state.me.org ? state.me.org.slug : state.org; }
  function base() { return '/api/orgs/' + encodeURIComponent(orgSlug()); }

  function renderNav() {
    nav.replaceChildren();
    const me = state.me;
    if (!me) return;
    if (me.org) nav.append(h('a', { href: '#/' }, 'Rule sets'), h('a', { href: '#/members' }, 'Members'));
    if (me.mode === 'admin') nav.append(h('a', { href: '#/orgs' }, 'Organizations'));
    nav.append(h('span', { class: 'small' }, me.mode === 'session' ? me.email : me.mode === 'admin' ? 'admin token' : 'single tenant'));
    if (me.mode === 'session') nav.append(h('button', { class: 'link', onclick: async () => { await api('POST', '/auth/logout'); state.me = null; location.hash = '#/login'; route(); } }, 'Sign out'));
  }

  async function route() {
    const hash = location.hash.replace(/^#/, '') || '/';
    const [path, query] = hash.split('?');
    const parts = path.split('/').filter(Boolean);
    try {
      if (!state.me) {
        try { state.me = await api('GET', '/api/me', undefined, true); }
        catch (e) { if (e.status === 401) { renderNav(); return renderLogin(new URLSearchParams(query || '')); } throw e; }
      }
      renderNav();
      if (state.me.mode === 'admin' && !state.me.org && parts[0] !== 'orgs' && !state.org) return renderOrgs();
      if (parts[0] === 'orgs') { if (parts[1]) { state.org = parts[1]; location.hash = '#/'; return; } return renderOrgs(); }
      if (parts[0] === 'members') return renderMembers();
      if (parts[0] === 'sets' && parts[1]) return renderSet(parts[1], parts[2] || 'editor');
      return renderSets();
    } catch (e) {
      app.replaceChildren(h('div', { class: 'msg error' }, e.message || String(e)));
    }
  }
  window.addEventListener('hashchange', route);

  // ---- login ----
  function renderLogin(params) {
    const err = params.get('error');
    const email = h('input', { type: 'email', required: true, autocomplete: 'email', placeholder: 'you@company.com' });
    const msg = h('div');
    if (err === 'link') msg.append(h('div', { class: 'msg error' }, 'This link has expired or was already used. Ask for a new one.'));
    if (err === 'no-account') msg.append(h('div', { class: 'msg error' }, 'This address has no account here and sign-up is closed. Ask a member of your organization to invite you.'));
    const form = h('form', { onsubmit: async ev => {
      ev.preventDefault();
      const btn = $('button', form); btn.disabled = true;
      try {
        const r = await api('POST', '/auth/login', { email: email.value });
        msg.replaceChildren(h('div', { class: 'msg ok' }, r.message));
      } catch (e) { msg.replaceChildren(h('div', { class: 'msg error' }, e.message)); }
      btn.disabled = false;
    } },
      h('label', null, 'E-mail'), email,
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Send me a sign-in link')));
    app.replaceChildren(h('div', { class: 'card narrow' },
      h('h1', null, 'Sign in'),
      h('p', { class: 'muted' }, 'No password: a link is mailed to you and signs you in once.'),
      msg, form));
  }

  // ---- organizations (admin) ----
  async function renderOrgs() {
    const { orgs } = await api('GET', '/api/orgs');
    const slug = h('input', { type: 'text', placeholder: 'acme', pattern: '[a-z0-9][a-z0-9-]{0,62}' });
    const name = h('input', { type: 'text', placeholder: 'ACME Ltd' });
    app.replaceChildren(
      h('h1', null, 'Organizations'),
      h('div', { class: 'card' },
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'Slug'), h('th', null, 'Name'), h('th', null, 'Created'))),
          h('tbody', null, (orgs || []).map(o => h('tr', null, h('td', null, h('a', { href: '#/orgs/' + o.slug }, o.slug)), h('td', null, o.name), h('td', null, fmtDate(o.createdAt)))))),
        (orgs || []).length ? null : h('p', { class: 'muted' }, 'No organizations yet.')),
      h('div', { class: 'card' }, h('h2', null, 'New organization'),
        h('div', { class: 'row' }, h('div', null, h('label', null, 'Slug'), slug), h('div', null, h('label', null, 'Name'), name),
          h('div', { class: 'fixed' }, h('button', { class: 'primary', onclick: async () => {
            try { await api('POST', '/api/orgs', { slug: slug.value, name: name.value }); toast('Organization created'); renderOrgs(); }
            catch (e) { toast(e.message); }
          } }, 'Create')))));
  }

  // ---- rule sets ----
  async function renderSets() {
    const { sets } = await api('GET', base() + '/sets');
    const slug = h('input', { type: 'text', placeholder: 'payments', pattern: '[a-z0-9][a-z0-9-]{0,62}' });
    const name = h('input', { type: 'text', placeholder: 'Payments service' });
    app.replaceChildren(
      h('h1', null, 'Rule sets', ' ', h('span', { class: 'muted small' }, orgSlug())),
      h('div', { class: 'card' },
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'Set'), h('th', null, 'Published'), h('th', null, 'Latest'), h('th', null, 'Created'))),
          h('tbody', null, (sets || []).map(s => h('tr', null,
            h('td', null, h('a', { href: '#/sets/' + s.slug }, s.slug), s.name ? h('span', { class: 'muted' }, ' · ' + s.name) : null),
            h('td', null, s.publishedRevision ? h('span', { class: 'badge ok' }, 'r' + s.publishedRevision) : h('span', { class: 'badge off' }, 'nothing')),
            h('td', null, s.latestRevision ? 'r' + s.latestRevision : '—'),
            h('td', null, fmtDate(s.createdAt)))))),
        (sets || []).length ? null : h('p', { class: 'muted' }, 'No rule sets yet. Create one below, then write its rules, try them on a few log lines, publish, and issue a token for the cluster.')),
      h('div', { class: 'card' }, h('h2', null, 'New rule set'),
        h('div', { class: 'row' }, h('div', null, h('label', null, 'Slug ', h('span', { class: 'hint' }, 'part of the URL the cluster pulls')), slug),
          h('div', null, h('label', null, 'Name'), name),
          h('div', { class: 'fixed' }, h('button', { class: 'primary', onclick: async () => {
            try { await api('POST', base() + '/sets', { slug: slug.value, name: name.value }); location.hash = '#/sets/' + slug.value; }
            catch (e) { toast(e.message); }
          } }, 'Create')))));
  }

  // ---- one rule set ----
  const draftCache = {}; // slug -> draft content being edited, kept across tabs

  async function renderSet(slug, tab) {
    const setBase = base() + '/sets/' + encodeURIComponent(slug);
    const data = await api('GET', setBase);
    const set = data.set, versions = data.versions || [], tokens = data.tokens || [];
    const tabs = [['editor', 'Rules'], ['preview', 'Preview'], ['versions', 'Versions'], ['tokens', 'Tokens'], ['connect', 'Connect a cluster']];
    const head = [
      h('h1', null, slug, set.name ? h('span', { class: 'muted small' }, ' ' + set.name) : null, ' ',
        set.publishedRevision ? h('span', { class: 'badge ok' }, 'published r' + set.publishedRevision) : h('span', { class: 'badge off' }, 'nothing published')),
      h('div', { class: 'tabs' }, tabs.map(([id, label]) => h('a', { href: '#/sets/' + slug + '/' + id, class: id === tab ? 'active' : '' }, label)))
    ];
    const ctx = { slug, setBase, set, versions, tokens, policyPath: data.policyPath };
    const body = await ({ editor: renderEditor, preview: renderPreview, versions: renderVersions, tokens: renderTokens, connect: renderConnect }[tab] || renderEditor)(ctx);
    app.replaceChildren(...head, body);
  }

  async function loadContent(ctx, revision) {
    const r = await api('GET', ctx.setBase + '/versions/' + revision);
    return r.content || {};
  }

  // ---- editor ----
  function linesOf(v) { return (v || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean); }

  function ruleRows(container, rules) {
    container.replaceChildren();
    const add = r => {
      const name = h('input', { type: 'text', placeholder: 'name (optional)', value: r.name || '' });
      const pattern = h('input', { type: 'text', class: 'mono', placeholder: 'RE2 pattern, e.g. ^TX-\\d{6}$', value: r.pattern || '' });
      const row = h('div', { class: 'rule' }, name, pattern, h('button', { type: 'button', onclick: () => row.remove() }, '×'));
      container.append(row);
    };
    (rules || []).forEach(add);
    return () => add({});
  }
  function readRules(container) {
    return [...container.querySelectorAll('.rule')].map(row => {
      const [name, pattern] = row.querySelectorAll('input');
      return pattern.value.trim() ? { name: name.value.trim() || undefined, pattern: pattern.value } : null;
    }).filter(Boolean);
  }

  async function renderEditor(ctx) {
    const latest = ctx.versions.length ? Math.max(...ctx.versions.map(v => v.revision)) : 0;
    let content = draftCache[ctx.slug];
    let loadedFrom = 'draft';
    if (!content) {
      if (ctx.set.publishedRevision) { content = await loadContent(ctx, ctx.set.publishedRevision); loadedFrom = 'published r' + ctx.set.publishedRevision; }
      else if (latest) { content = await loadContent(ctx, latest); loadedFrom = 'latest r' + latest; }
      else { content = {}; loadedFrom = 'empty'; }
    }
    const f = {
      entropy: h('input', { type: 'number', step: '0.1', min: '0', class: 'short', value: content.entropy_threshold ?? '' }),
      confidence: h('input', { type: 'number', step: '0.1', min: '0', class: 'short', value: content.confidence_score ?? '' }),
      minLen: h('input', { type: 'number', step: '1', min: '1', max: '1024', class: 'short', value: content.min_secret_length ?? '' }),
      keys: h('textarea', { class: 'mono' }, (content.sensitive_keys || []).join('\n')),
      keyPatterns: h('textarea', { class: 'mono' }, (content.sensitive_key_patterns || []).join('\n')),
      custom: h('div', { class: 'rules' }), safe: h('div', { class: 'rules' }),
      bigram: h('input', { type: 'checkbox', checked: !!content.disable_bigram_check }),
      adaptive: h('input', { type: 'checkbox', checked: !!content.adaptive_threshold }),
      labels: h('input', { type: 'checkbox', checked: !!content.entity_type_labels }),
      author: h('input', { type: 'text', placeholder: state.me.email || 'who' , value: state.me.email || '' , disabled: !!state.me.email }),
      comment: h('input', { type: 'text', placeholder: 'why this change' }),
    };
    const addCustom = ruleRows(f.custom, content.custom_regexes);
    const addSafe = ruleRows(f.safe, content.safe_regexes);
    const msg = h('div');

    function draft() {
      const d = {};
      const num = (el, key, int) => { if (el.value !== '') d[key] = int ? parseInt(el.value, 10) : parseFloat(el.value); };
      num(f.entropy, 'entropy_threshold'); num(f.confidence, 'confidence_score'); num(f.minLen, 'min_secret_length', true);
      const keys = linesOf(f.keys.value); if (keys.length) d.sensitive_keys = keys;
      const kp = linesOf(f.keyPatterns.value); if (kp.length) d.sensitive_key_patterns = kp;
      const cr = readRules(f.custom); if (cr.length) d.custom_regexes = cr;
      const sr = readRules(f.safe); if (sr.length) d.safe_regexes = sr;
      if (f.bigram.checked) d.disable_bigram_check = true;
      if (f.adaptive.checked) d.adaptive_threshold = true;
      if (f.labels.checked) d.entity_type_labels = true;
      draftCache[ctx.slug] = d;
      return d;
    }
    const form = h('div', { class: 'card', oninput: draft, onchange: draft },
      h('p', { class: 'muted small' }, 'Loaded from: ' + loadedFrom + '. Fields left empty keep the scanner defaults. The salt and the fail policy are not rules: they stay with the pod.'),
      h('div', { class: 'grid2' },
        h('div', null,
          h('div', { class: 'row' },
            h('div', null, h('label', null, 'Entropy threshold ', h('span', { class: 'hint' }, 'default 3.6')), f.entropy),
            h('div', null, h('label', null, 'Confidence ', h('span', { class: 'hint' }, 'default 1.0')), f.confidence),
            h('div', null, h('label', null, 'Min secret length ', h('span', { class: 'hint' }, 'default 6')), f.minLen)),
          h('label', null, 'Sensitive keys ', h('span', { class: 'hint' }, 'one per line; replaces the default list')), f.keys,
          h('label', null, 'Sensitive key patterns ', h('span', { class: 'hint' }, 'regexes matched against keys, one per line')), f.keyPatterns,
          h('div', { class: 'checks' }, h('label', null, f.bigram, 'Disable bigram check (non-English logs)'), h('label', null, f.adaptive, 'Adaptive threshold'), h('label', null, f.labels, 'Entity type labels'))),
        h('div', null,
          h('label', null, 'Custom rules ', h('span', { class: 'hint' }, 'a match is hidden')), f.custom,
          h('button', { type: 'button', onclick: () => { addCustom(); } }, '+ rule'),
          h('label', null, 'Safe rules ', h('span', { class: 'hint' }, 'a match is never hidden')), f.safe,
          h('button', { type: 'button', onclick: () => { addSafe(); } }, '+ rule'))),
      msg,
      h('div', { class: 'row' }, h('div', null, h('label', null, 'Author'), f.author), h('div', null, h('label', null, 'Comment'), f.comment)),
      h('div', { class: 'actions' },
        h('button', { onclick: async () => {
          try {
            const r = await api('POST', ctx.setBase + '/validate', { content: draft() });
            msg.replaceChildren(h('div', { class: 'msg ok' }, `Accepted. Effective: entropy ${r.entropyThreshold}, confidence ${r.confidenceThreshold}, min length ${r.minSecretLength}; ${r.sensitiveKeys} keys, ${r.sensitiveKeyPatterns} key patterns, ${r.customRegexes} custom and ${r.safeRegexes} safe rules; ${r.bytes} bytes.`));
          } catch (e) { msg.replaceChildren(h('div', { class: 'msg error' }, e.message)); }
        } }, 'Validate'),
        h('a', { href: '#/sets/' + ctx.slug + '/preview' }, h('button', null, 'Preview on log lines')),
        h('button', { class: 'primary', onclick: async () => {
          try {
            const v = await api('POST', ctx.setBase + '/versions', { content: draft(), author: f.author.value, comment: f.comment.value });
            delete draftCache[ctx.slug];
            toast('Saved as revision ' + v.revision + '. Publish it on the Versions tab.');
            location.hash = '#/sets/' + ctx.slug + '/versions';
          } catch (e) { msg.replaceChildren(h('div', { class: 'msg error' }, e.message)); }
        } }, 'Save as a new version'),
        h('button', { onclick: () => { delete draftCache[ctx.slug]; renderSet(ctx.slug, 'editor'); } }, 'Discard draft')));
    draft();
    return form;
  }

  // ---- preview ----
  async function renderPreview(ctx) {
    const lines = h('textarea', { class: 'mono', rows: 8, placeholder: 'Paste up to 200 log lines, one per line' }, sessionStorage.getItem('preview-lines:' + ctx.slug) || '');
    const out = h('div');
    const hasDraft = !!draftCache[ctx.slug];
    async function run(withDraft) {
      sessionStorage.setItem('preview-lines:' + ctx.slug, lines.value);
      const req = { text: lines.value };
      if (withDraft) req.content = draftCache[ctx.slug];
      try {
        const r = await api('POST', ctx.setBase + '/preview', req);
        out.replaceChildren(
          h('p', { class: 'muted small' }, `${r.source === 'draft' ? 'The draft' : 'Published r' + r.revision}: ${r.changed} of ${r.lines.length} lines changed. ${r.note}.`),
          h('table', { class: 'preview' }, h('thead', null, h('tr', null, h('th', null, 'In'), h('th', null, 'Out'))),
            h('tbody', null, r.lines.map(l => h('tr', { class: l.changed ? 'changed' : '' }, h('td', { class: 'mono' }, l.in), h('td', { class: 'mono' }, l.out))))));
      } catch (e) { out.replaceChildren(h('div', { class: 'msg error' }, e.message)); }
    }
    return h('div', { class: 'card' },
      h('p', { class: 'muted small' }, 'Lines are scanned on the same scanner the sidecars run, with a preview salt: the hashes match no cluster. Nothing is stored.'),
      lines,
      h('div', { class: 'actions' },
        h('button', { class: 'primary', disabled: !hasDraft, title: hasDraft ? '' : 'Edit the rules first; the draft is kept while you switch tabs', onclick: () => run(true) }, 'Preview with the draft'),
        h('button', { disabled: !ctx.set.publishedRevision, onclick: () => run(false) }, 'Preview with the published version'),
        hasDraft ? h('span', { class: 'badge warn' }, 'unsaved draft') : h('span', { class: 'muted small' }, 'no draft: go to Rules to edit')),
      out);
  }

  // ---- versions ----
  function diffLines(a, b) {
    // Longest common subsequence on lines, enough for two policy files.
    const n = a.length, m = b.length, dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const outEl = h('div', { class: 'diff' });
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && a[i] === b[j]) { outEl.append(h('div', null, '  ' + a[i])); i++; j++; }
      else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { outEl.append(h('div', { class: 'add' }, '+ ' + b[j])); j++; }
      else { outEl.append(h('div', { class: 'del' }, '- ' + a[i])); i++; }
    }
    return outEl;
  }
  async function renderVersions(ctx) {
    const { publications } = await api('GET', ctx.setBase + '/publications');
    const versions = [...ctx.versions].sort((x, y) => y.revision - x.revision);
    const pub = ctx.set.publishedRevision;
    const diffOut = h('div');
    const selA = h('select', null, versions.map(v => h('option', { value: v.revision }, 'r' + v.revision)));
    const selB = h('select', null, versions.map(v => h('option', { value: v.revision }, 'r' + v.revision)));
    if (versions.length > 1) selA.value = versions[1].revision;
    const content = h('pre');
    async function show(rev) {
      const c = await loadContent(ctx, rev);
      content.textContent = JSON.stringify(c, null, 2);
    }
    return h('div', null,
      h('div', { class: 'card' },
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'Revision'), h('th', null, 'Author'), h('th', null, 'Comment'), h('th', null, 'Created'), h('th', null, 'ETag'), h('th', null, ''))),
          h('tbody', null, versions.map(v => h('tr', null,
            h('td', null, 'r' + v.revision, ' ', v.revision === pub ? h('span', { class: 'badge ok' }, 'published') : null),
            h('td', null, v.author || '—'), h('td', null, v.comment || '—'), h('td', null, fmtDate(v.createdAt)),
            h('td', null, h('code', null, v.etag)),
            h('td', null,
              h('button', { class: 'link', onclick: () => show(v.revision) }, 'show'), ' ',
              h('button', { class: 'link', onclick: () => { draftCache[ctx.slug] = null; loadContent(ctx, v.revision).then(c => { draftCache[ctx.slug] = c; location.hash = '#/sets/' + ctx.slug + '/editor'; }); } }, 'edit as draft'), ' ',
              v.revision === pub ? null : h('button', { class: 'link', onclick: async () => {
                if (!confirm((pub && v.revision < pub ? 'Roll back to' : 'Publish') + ' r' + v.revision + '? Every cluster pulling this set gets it on its next poll.')) return;
                try { await api('POST', ctx.setBase + '/publish', { revision: v.revision }); toast('Published r' + v.revision); renderSet(ctx.slug, 'versions'); }
                catch (e) { toast(e.message); }
              } }, pub && v.revision < pub ? 'roll back to this' : 'publish')))))),
        versions.length ? null : h('p', { class: 'muted' }, 'No versions yet: write rules on the Rules tab and save them.'),
        content),
      versions.length > 1 ? h('div', { class: 'card' }, h('h2', null, 'Compare two versions'),
        h('div', { class: 'row' }, h('div', { class: 'fixed' }, selA), h('div', { class: 'fixed' }, '→'), h('div', { class: 'fixed' }, selB),
          h('div', { class: 'fixed' }, h('button', { onclick: async () => {
            const [a, b] = await Promise.all([loadContent(ctx, selA.value), loadContent(ctx, selB.value)]);
            diffOut.replaceChildren(diffLines(JSON.stringify(a, null, 2).split('\n'), JSON.stringify(b, null, 2).split('\n')));
          } }, 'Diff'))),
        diffOut) : null,
      h('div', { class: 'card' }, h('h2', null, 'Publish history'),
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'Revision'), h('th', null, 'By'), h('th', null, 'When'))),
          h('tbody', null, (publications || []).map(p => h('tr', null, h('td', null, 'r' + p.revision), h('td', null, p.author || '—'), h('td', null, fmtDate(p.publishedAt)))))),
        (publications || []).length ? null : h('p', { class: 'muted' }, 'Nothing published yet.')));
  }

  // ---- tokens ----
  async function renderTokens(ctx) {
    const name = h('input', { type: 'text', placeholder: 'prod-eu cluster' });
    const shown = h('div');
    return h('div', null,
      h('div', { class: 'card' },
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', null, 'Prefix'), h('th', null, 'Created'), h('th', null, 'Status'), h('th', null, ''))),
          h('tbody', null, ctx.tokens.map(t => h('tr', null, h('td', null, t.name), h('td', null, h('code', null, t.prefix + '…')), h('td', null, fmtDate(t.createdAt)),
            h('td', null, t.revokedAt ? h('span', { class: 'badge off' }, 'revoked ' + fmtDate(t.revokedAt)) : h('span', { class: 'badge ok' }, 'active')),
            h('td', null, t.revokedAt ? null : h('button', { class: 'danger', onclick: async () => {
              if (!confirm('Revoke "' + t.name + '"? The cluster holding it keeps its last good rules and stops receiving updates.')) return;
              try { await api('DELETE', ctx.setBase + '/tokens/' + t.id); toast('Revoked'); renderSet(ctx.slug, 'tokens'); } catch (e) { toast(e.message); }
            } }, 'Revoke')))))),
        ctx.tokens.length ? null : h('p', { class: 'muted' }, 'No tokens yet. A token is read-only and pulls this set only.')),
      h('div', { class: 'card' }, h('h2', null, 'Issue a token'),
        h('div', { class: 'row' }, h('div', null, h('label', null, 'Name ', h('span', { class: 'hint' }, 'which cluster or team holds it')), name),
          h('div', { class: 'fixed' }, h('button', { class: 'primary', onclick: async () => {
            try {
              const r = await api('POST', ctx.setBase + '/tokens', { name: name.value });
              shown.replaceChildren(h('p', null, 'Copy it now; it is shown once.'), h('div', { class: 'secret' }, r.value), h('p', { class: 'muted small' }, r.note));
              ctx.tokens.push(r.token);
            } catch (e) { toast(e.message); }
          } }, 'Issue'))),
        shown));
  }

  // ---- connect ----
  function renderConnect(ctx) {
    const url = location.origin + ctx.policyPath;
    const yaml = `apiVersion: v1
kind: Secret
metadata: { name: rules-token, namespace: <your namespace> }
stringData:
  authorization: "Bearer psr_…"        # a token from the Tokens tab
---
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata: { name: default, namespace: <your namespace> }
spec:
  injectionMode: file
  saltSecretKeyRef: { name: pii-shield-salt, key: salt }
  remoteConfig:
    url: ${url}
    intervalSeconds: 300
    headerSecretRef: { name: rules-token, key: authorization }`;
    return h('div', { class: 'card' },
      h('p', null, 'The cluster pulls the published version of this set from'),
      h('pre', null, url),
      h('p', null, 'with a read-only token in the Authorization header, every ', h('code', null, 'intervalSeconds'), ', keeping its last good copy when this server is unreachable. Nothing about the cluster is sent here.'),
      h('pre', null, yaml),
      h('p', { class: 'muted small' }, 'Check with: curl -H "Authorization: Bearer psr_…" ' + url));
  }

  // ---- members ----
  async function renderMembers() {
    const { members } = await api('GET', base() + '/members');
    const email = h('input', { type: 'email', placeholder: 'colleague@company.com' });
    const msg = h('div');
    app.replaceChildren(
      h('h1', null, 'Members', ' ', h('span', { class: 'muted small' }, orgSlug())),
      h('div', { class: 'card' },
        h('table', null, h('thead', null, h('tr', null, h('th', null, 'E-mail'), h('th', null, 'Invited by'), h('th', null, 'Joined'), h('th', null, 'Last sign-in'))),
          h('tbody', null, (members || []).map(m => h('tr', null, h('td', null, m.email), h('td', null, m.invitedBy || '—'), h('td', null, fmtDate(m.createdAt)), h('td', null, m.lastLogin ? fmtDate(m.lastLogin) : h('span', { class: 'badge off' }, 'never'))))))),
      h('div', { class: 'card' }, h('h2', null, 'Invite'),
        h('p', { class: 'muted small' }, 'The address gets a sign-in link by mail. An account belongs to one organization.'),
        h('div', { class: 'row' }, h('div', null, h('label', null, 'E-mail'), email),
          h('div', { class: 'fixed' }, h('button', { class: 'primary', onclick: async () => {
            try {
              const r = await api('POST', base() + '/members', { email: email.value });
              msg.replaceChildren(h('div', { class: r.mailed ? 'msg ok' : 'msg error' }, r.mailed ? 'Invited; the link is on its way.' : 'Added, but the mail could not be sent; ask them to request a link on the sign-in page.'));
              renderMembers();
            } catch (e) { msg.replaceChildren(h('div', { class: 'msg error' }, e.message)); }
          } }, 'Invite'))),
        msg));
  }

  route();
})();
