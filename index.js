// modules_cache/msauth/1.0.0/index.js
// Microsoft OAuth using Device Code flow + Refresh with scope mapping.

(function () {
  const httpx = require('http@latest');
  const j = require('json@latest');
  const log = require('log@latest').create('msauth');
  const b64 = require('b64@latest');
  const AUTH_HOST = 'https://login.microsoftonline.com';
  const notifyOncePerRestart = {};
  const defaults = {
    tenant: null,
    clientId: null,
    clientSecret: null,
    scope: null,
    mode: null
  };

  const SCOPE_MAP = {
    'mail': ['https://graph.microsoft.com/Mail.ReadWrite'],
    'mail.readonly': ['https://graph.microsoft.com/Mail.Read'],
    'calendar': ['https://graph.microsoft.com/Calendars.ReadWrite'],
    'calendar.readonly': ['https://graph.microsoft.com/Calendars.Read'],
    'contacts': ['https://graph.microsoft.com/Contacts.ReadWrite'],
    'contacts.readonly': ['https://graph.microsoft.com/Contacts.Read'],
    'todo': ['https://graph.microsoft.com/Tasks.ReadWrite'],
    'todo.readonly': ['https://graph.microsoft.com/Tasks.Read'],
    'planner': ['https://graph.microsoft.com/Tasks.ReadWrite', 'https://graph.microsoft.com/Group.ReadWrite.All', 'https://graph.microsoft.com/User.Read'],
    'planner.readonly': ['https://graph.microsoft.com/Tasks.Read', 'https://graph.microsoft.com/Group.Read.All', 'https://graph.microsoft.com/User.Read'],
    'files': ['https://graph.microsoft.com/Files.ReadWrite.All'],
    'files.readonly': ['https://graph.microsoft.com/Files.Read.All'],
    'sharepoint': ['https://graph.microsoft.com/Sites.ReadWrite.All'],
    'sharepoint.readonly': ['https://graph.microsoft.com/Sites.Read.All'],
    'teams': ['https://graph.microsoft.com/Chat.ReadWrite', 'https://graph.microsoft.com/OnlineMeetings.ReadWrite', 'https://graph.microsoft.com/User.Read'],
    'teams.chat': ['https://graph.microsoft.com/Chat.ReadWrite', 'https://graph.microsoft.com/User.Read'],
    'teams.meetings': ['https://graph.microsoft.com/OnlineMeetings.ReadWrite', 'https://graph.microsoft.com/User.Read'],
    'user.read': ['https://graph.microsoft.com/User.Read']
  };

  function aliasScope(name) {
    if (!name) return name;
    return String(name).trim().replace(/:ro$/i, '.readonly');
  }

  function parseScopeInput(input) {
    if (Array.isArray(input)) return input.map(String);
    if (typeof input !== 'string') return [];
    const s = input.trim();
    if (!s) return [];
    try {
      if (s[0] === '[' && s[s.length - 1] === ']') {
        const arr = JSON.parse(s);
        if (Array.isArray(arr)) return arr.map(String);
      }
    } catch {}
    return s.split(/[,\s]+/).filter(Boolean);
  }

  function normalizeScope(input, fallback) {
    const raw = parseScopeInput(input);
    const picked = raw.length ? raw : parseScopeInput(fallback);
    const out = [];
    for (const entry of picked) {
      const key = aliasScope(entry);
      if (key === 'all' || key === '*') {
        for (const list of Object.values(SCOPE_MAP)) {
          for (const m of list) out.push(m);
        }
        continue;
      }
      const mapped = SCOPE_MAP[key];
      if (mapped && mapped.length) {
        for (const m of mapped) out.push(m);
      } else {
        out.push(entry);
      }
    }
    const uniq = Array.from(new Set(out.map((v) => String(v).trim()).filter(Boolean)));
    uniq.sort();
    const scopeString = uniq.join(' ');
    const scopeKey = scopeString || 'default';
    return { scopeList: uniq, scopeString, scopeKey };
  }

  const getMsEnv = (key, legacy, fallback) => {
    const primary = sys.env.get(key, undefined);
    if (primary !== undefined && primary !== null && primary !== '') return primary;
    if (legacy) {
      const legacyList = Array.isArray(legacy) ? legacy : [legacy];
      for (const entry of legacyList) {
        const legacyVal = sys.env.get(entry, undefined);
        if (legacyVal !== undefined && legacyVal !== null && legacyVal !== '') return legacyVal;
      }
    }
    return fallback;
  };

  function nowSec() { return Math.floor(Date.now() / 1000); }
  function dbgOn() {
    try {
      const v = getMsEnv('msauth.debug', ['ms.debug', 'msDebug'], false);
      return v === true || v === '1' || v === 'true';
    } catch { return false; }
  }
  function utcYmd() {
    const d = new Date();
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, '0');
    const da = String(d.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${da}`;
  }
  function resolveStoragePaths() {
    return {
      tokenPath: 'oauth/ms_tokens.json',
      devicePath: 'oauth/ms_device.json',
      notifyPath: 'oauth/ms_notify.json',
      notifyKey: 'shared'
    };
  }
  function moduleStorage() {
    return sys.storage.get('msauth');
  }
  function legacyStorage() {
    return sys.storage.get('oauth_ms');
  }
  async function readJson(path) {
    const storage = moduleStorage();
    if (!path) return null;
    try {
      const r = await storage.read({ path });
      return b64.decodeJson((r && r.dataBase64) || '') || null;
    } catch { return null; }
  }
  async function writeJson(path, obj) {
    const storage = moduleStorage();
    if (!path || !obj) return;
    try { await storage.save({ path, dataBase64: b64.encodeJson(obj) }); } catch {}
  }
  async function readJsonWithLegacy(path) {
    const current = await readJson(path);
    if (current) return current;
    try {
      const legacy = legacyStorage();
      const r = await legacy.read({ path });
      const decoded = b64.decodeJson((r && r.dataBase64) || '') || null;
      if (decoded) {
        await writeJson(path, decoded);
        return decoded;
      }
    } catch {}
    return null;
  }
  function emptyStore() {
    return { version: 2, byScope: {}, lastScope: '' };
  }
  function readScopedEntry(store, scopeKey) {
    if (!store || typeof store !== 'object') return null;
    if (scopeKey && store.byScope && store.byScope[scopeKey]) return store.byScope[scopeKey];
    if (!scopeKey && store.lastScope && store.byScope && store.byScope[store.lastScope]) {
      return store.byScope[store.lastScope];
    }
    return null;
  }
  async function readScopedJson(path, scopeKey, wrapLegacy) {
    const data = await readJsonWithLegacy(path);
    if (!data) return { store: emptyStore(), entry: null, legacy: null };
    if (data.byScope && typeof data.byScope === 'object') {
      return { store: data, entry: readScopedEntry(data, scopeKey), legacy: null };
    }
    const legacy = wrapLegacy ? wrapLegacy(data) : null;
    return { store: emptyStore(), entry: null, legacy };
  }

  function resolveOptions(opts = {}) {
    const baseScope = defaults.scope || getMsEnv('msauth.scope', ['ms.scope', 'msScope'], 'offline_access Files.ReadWrite.All');
    const scopeInfo = normalizeScope(opts.scope || opts.scopes || opts.services, baseScope);
    return {
      tenant: opts.tenant || defaults.tenant || getMsEnv('msauth.tenant', ['ms.tenant', 'msTenant'], 'common'),
      clientId: opts.clientId || defaults.clientId || getMsEnv('msauth.clientId', ['ms.clientId', 'msClientId']),
      clientSecret: opts.clientSecret || defaults.clientSecret || getMsEnv('msauth.clientSecret', ['ms.clientSecret', 'msClientSecret']),
      mode: opts.mode || opts.authMode || defaults.mode || getMsEnv('msauth.mode', ['ms.mode', 'msMode'], 'device'),
      scopeInfo
    };
  }

  async function deviceCodeStart({ tenant, clientId, scope }) {
    if (!clientId) throw new Error('msauth: missing clientId');
    const url = `${AUTH_HOST}/${tenant}/oauth2/v2.0/devicecode`;
    const { json: outRaw, raw, status } = await httpx.form({ url, method: 'POST', fields: { client_id: clientId, scope }, debug: dbgOn() });
    if (dbgOn()) log.debug('deviceCodeStart', { status });
    let out = outRaw || j.parseSafe(raw, {});
    if (!out.device_code) throw new Error('msauth: device code start failed');
    return out;
  }

  async function deviceCodePoll({ tenant, clientId, device_code, interval, scope, clientSecret }) {
    if (!clientId || !device_code) throw new Error('msauth: missing clientId/device_code');
    const url = `${AUTH_HOST}/${tenant}/oauth2/v2.0/token`;
    const iv = Math.max(2, Number(interval || 5));
    const deadline = Date.now() + 15 * 60 * 1000;
    while (Date.now() < deadline) {
      const form = {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code
      };
      const withSecret = (!!clientSecret && typeof clientSecret === 'string' && clientSecret.length > 0);
      if (withSecret) form.client_secret = clientSecret;
      if (dbgOn()) log.debug('token:withSecret', { withSecret, len: (clientSecret ? clientSecret.length : 0) });
      const { json: outRaw, raw, status } = await httpx.form({ url, method: 'POST', fields: form, debug: dbgOn() });
      if (dbgOn()) log.debug('token:status', { status });
      let out = outRaw || j.parseSafe(raw, {});
      if (out.access_token) {
        out.obtained_at = nowSec();
        return out;
      }
      if (out.error === 'authorization_pending' || out.error === 'slow_down') {
        const wait = out.error === 'slow_down' ? iv + 2 : iv;
        await new Promise(r => setTimeout(r, wait * 1000));
        continue;
      }
      log.error('token:error', out && out.error || 'unknown');
      throw new Error('msauth: device poll failed: ' + (out.error || 'unknown'));
    }
    throw new Error('msauth: device poll timeout');
  }

  async function refresh({ tenant, clientId, refresh_token, scope, clientSecret }) {
    if (!clientId || !refresh_token) throw new Error('msauth: missing clientId/refresh_token');
    const url = `${AUTH_HOST}/${tenant}/oauth2/v2.0/token`;
    const form = { grant_type: 'refresh_token', client_id: clientId, refresh_token, scope };
    const withSecret = (!!clientSecret && typeof clientSecret === 'string' && clientSecret.length > 0);
    if (withSecret) form.client_secret = clientSecret;
    if (dbgOn()) log.debug('refresh:withSecret', { withSecret, len: (clientSecret ? clientSecret.length : 0) });
    const { json: outRaw, raw, status } = await httpx.form({ url, method: 'POST', fields: form, debug: dbgOn() });
    if (dbgOn()) log.debug('refresh:status', { status });
    let out = outRaw || j.parseSafe(raw, {});
    if (!out.access_token) throw new Error('msauth: refresh failed');
    out.obtained_at = nowSec();
    return out;
  }

  async function clientCredentialsToken({ tenant, clientId, clientSecret, scope }) {
    if (!clientId || !clientSecret) throw new Error('msauth: missing clientId/clientSecret');
    const url = `${AUTH_HOST}/${tenant}/oauth2/v2.0/token`;
    const { json: outRaw, raw } = await httpx.form({ url, method: 'POST', fields: { grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, scope } });
    let out = outRaw || j.parseSafe(raw, {});
    if (!out.access_token) throw new Error('msauth: client credentials failed');
    out.obtained_at = nowSec();
    return out;
  }

  async function ensureAuthenticated(opts = {}) {
    const resolved = resolveOptions(opts);
    const scopeInfo = resolved.scopeInfo;
    const scope = scopeInfo.scopeString || getMsEnv('msauth.scope', ['ms.scope', 'msScope'], 'offline_access Files.ReadWrite.All');
    const scopeKey = scopeInfo.scopeKey || 'default';
    const tenant = resolved.tenant;
    const clientId = resolved.clientId;
    const mode = resolved.mode;
    const useSecret = (mode === 'app' || mode === 'client' || opts.useClientSecret === true);
    const clientSecret = useSecret ? (resolved.clientSecret || '') : '';
    const paths = resolveStoragePaths();
    const tokenPath = paths.tokenPath;
    const devicePath = paths.devicePath;
    const maxPollAttempts = opts.maxPollAttempts || 10;
    const now = nowSec();
    const isValid = (tok) => tok && tok.access_token && (tok.obtained_at || 0) + (tok.expires_in || 0) - 120 > now;

    const tokenWrap = (legacy) => legacy && (legacy.access_token || legacy.refresh_token)
      ? ({ scope, tokens: legacy })
      : null;
    const tokenRead = await readScopedJson(tokenPath, scopeKey, tokenWrap);
    let tokenStore = tokenRead.store;
    let entry = tokenRead.entry || tokenRead.legacy;
    let tok = entry && entry.tokens;

    if (isValid(tok)) return { status: 'ok', tokens: tok };

    if (tok && tok.refresh_token && clientId) {
      try {
        const refreshed = await refresh({ tenant, clientId, clientSecret, refresh_token: tok.refresh_token, scope });
        const merged = {
          refresh_token: refreshed.refresh_token || tok.refresh_token,
          access_token: refreshed.access_token,
          obtained_at: refreshed.obtained_at || now,
          expires_in: refreshed.expires_in || tok.expires_in || 3600,
          scope
        };
        tokenStore.byScope = tokenStore.byScope || {};
        tokenStore.byScope[scopeKey] = { scope, tokens: merged };
        tokenStore.lastScope = scopeKey;
        await writeJson(tokenPath, tokenStore);
        return { status: 'ok', tokens: merged };
      } catch (e) {
        log.error('refresh failed', (e && (e.message || e)) || 'unknown');
      }
    }

    if ((mode === 'app' || mode === 'client') && clientSecret && clientId) {
      try {
        const appScope = (opts.scope || opts.scopes || opts.services)
          ? normalizeScope(opts.scope || opts.scopes || opts.services, '').scopeString
          : 'https://graph.microsoft.com/.default';
        const appTok = await clientCredentialsToken({ tenant, clientId, clientSecret, scope: appScope });
        const merged = {
          refresh_token: tok && tok.refresh_token ? tok.refresh_token : '',
          access_token: appTok.access_token,
          obtained_at: appTok.obtained_at || now,
          expires_in: appTok.expires_in || 3600,
          scope: appScope
        };
        tokenStore.byScope = tokenStore.byScope || {};
        tokenStore.byScope[scopeKey] = { scope, tokens: merged };
        tokenStore.lastScope = scopeKey;
        await writeJson(tokenPath, tokenStore);
        return { status: 'ok', tokens: merged };
      } catch (e) {
        log.error('client credentials failed', (e && (e.message || e)) || 'unknown');
      }
    }

    const devWrap = (legacy) => legacy && legacy.device_code ? legacy : null;
    const deviceRead = await readScopedJson(devicePath, scopeKey, devWrap);
    let deviceStore = deviceRead.store;
    let dev = deviceRead.entry || deviceRead.legacy;
    const stillValid = dev && dev.device_code && ((dev.saved_at || dev.obtained_at || 0) + (dev.expires_in || 900) > now);
    if (dev && dev.device_code && !stillValid) {
      await writeJson(devicePath, deviceStore);
      dev = null;
    }
    if (dev && dev.device_code && stillValid) {
      const interval = dev.interval || 5;
      for (let i = 0; i < maxPollAttempts; i++) {
        try {
          const polled = await deviceCodePoll({ tenant, clientId, device_code: dev.device_code, interval, scope, clientSecret });
          const merged = {
            refresh_token: polled.refresh_token || '',
            access_token: polled.access_token,
            obtained_at: polled.obtained_at || nowSec(),
            expires_in: polled.expires_in || 3600,
            scope
          };
          tokenStore.byScope = tokenStore.byScope || {};
          tokenStore.byScope[scopeKey] = { scope, tokens: merged };
          tokenStore.lastScope = scopeKey;
          await writeJson(tokenPath, tokenStore);
          return { status: 'ok', tokens: merged };
        } catch (e) {
          const msg = (e && (e.message || e)) || 'unknown';
          if (typeof msg === 'string' && msg.includes('authorization_pending')) {
            await new Promise(res => setTimeout(res, interval * 1000));
            continue;
          }
          return { status: 'pending', device: dev };
        }
      }
      return { status: 'pending', device: dev };
    }
    if (dev && dev.device_code) {
      return { status: 'pending', device: dev };
    }

    try {
      const info = await deviceCodeStart({ tenant, clientId, scope });
      const payload = Object.assign({}, info, { saved_at: nowSec(), scope });
      deviceStore.byScope = deviceStore.byScope || {};
      deviceStore.byScope[scopeKey] = payload;
      deviceStore.lastScope = scopeKey;
      await writeJson(devicePath, deviceStore);
      return { status: 'pending', device: payload };
    } catch (e) {
      return { status: 'error', error: (e && (e.message || e)) || 'unknown' };
    }
  }

  async function getToken(opts = {}) {
    return await ensureAuthenticated(opts);
  }

  async function auth(opts = {}) {
    const res = await ensureAuthenticated(opts);
    if (res && res.status === 'ok' && res.tokens && res.tokens.access_token) {
      return res.tokens.access_token;
    }
    return '';
  }

  function configure(opts) {
    if (!opts || typeof opts !== 'object') return;
    if (opts.tenant) defaults.tenant = String(opts.tenant);
    if (opts.clientId) defaults.clientId = String(opts.clientId);
    if (opts.clientSecret) defaults.clientSecret = String(opts.clientSecret);
    if (opts.scope) defaults.scope = opts.scope;
    if (opts.mode) defaults.mode = String(opts.mode);
  }

  async function clear(opts = {}) {
    const resolved = resolveOptions(opts);
    const scopeKey = resolved.scopeInfo.scopeKey || 'default';
    const paths = resolveStoragePaths();
    const tokenPath = paths.tokenPath;
    const devicePath = paths.devicePath;
    const tokenRead = await readScopedJson(tokenPath, scopeKey);
    const deviceRead = await readScopedJson(devicePath, scopeKey);
    if (tokenRead.store.byScope && tokenRead.store.byScope[scopeKey]) {
      delete tokenRead.store.byScope[scopeKey];
      await writeJson(tokenPath, tokenRead.store);
    }
    if (deviceRead.store.byScope && deviceRead.store.byScope[scopeKey]) {
      delete deviceRead.store.byScope[scopeKey];
      await writeJson(devicePath, deviceRead.store);
    }
  }

  async function shouldNotifyMsAuth(opts = {}) {
    const paths = resolveStoragePaths();
    const key = paths.notifyKey;
    const scopeInfo = normalizeScope(opts.scope || opts.scopes || opts.services, defaults.scope || '');
    const scopeKey = scopeInfo.scopeKey || 'default';
    const deviceCode = (opts && opts.device_code) ? String(opts.device_code) : '';
    const userCode = (opts && opts.user_code) ? String(opts.user_code) : '';
    const ymd = utcYmd();
    const prevRead = await readScopedJson(paths.notifyPath, scopeKey);
    const prev = prevRead.entry || prevRead.legacy;
    const hasCode = !!(deviceCode || userCode);
    const sameCode = prev
      ? (hasCode ? ((userCode && prev.user_code === userCode) || (deviceCode && prev.device_code === deviceCode)) : true)
      : false;
    if (notifyOncePerRestart[key] && sameCode) return false;
    if (prev && prev.last_notified_ymd === ymd && sameCode) return false;
    notifyOncePerRestart[key] = true;
    const store = prevRead.store || emptyStore();
    store.byScope = store.byScope || {};
    store.byScope[scopeKey] = {
      last_notified_ymd: ymd,
      updated_at: nowSec(),
      device_code: deviceCode,
      user_code: userCode
    };
    store.lastScope = scopeKey;
    await writeJson(paths.notifyPath, store);
    return true;
  }

  module.exports = {
    configure,
    auth,
    getToken,
    clear,
    ensureAuthenticated,
    ensureTokens: ensureAuthenticated,
    getAuthToken: auth,
    refresh,
    clientCredentialsToken,
    shouldNotifyMsAuth
  };
})();
