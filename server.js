import express from 'express';
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 3000;

/* ════════════════════════════════
   LOAD ENV
════════════════════════════════ */
function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!existsSync(envPath)) return;
  readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) return;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (key && !process.env[key]) process.env[key] = val;
  });
}
loadEnv();

const ANTHROPIC_API_KEY  = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL       = process.env.SUPABASE_URL;
const SUPABASE_KEY       = process.env.SUPABASE_SERVICE_KEY;
const PAYSTACK_SECRET    = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PLAN_CODE = process.env.PAYSTACK_PLAN_CODE;
const APP_URL            = process.env.APP_URL || 'https://reelscript-studio-2.onrender.com';
const ADMIN_SECRET       = process.env.ADMIN_SECRET || 'reelscript_admin_2026';

/* ════════════════════════════════
   SUPABASE HELPER
════════════════════════════════ */
async function sb(method, table, opts = {}) {
  const { filter, body, select, order, limit } = opts;
  let url = `${SUPABASE_URL}/rest/v1/${table}`;
  const params = [];
  if (select) params.push(`select=${encodeURIComponent(select)}`);
  if (filter) params.push(filter);
  if (order)  params.push(`order=${order}`);
  if (limit)  params.push(`limit=${limit}`);
  if (params.length) url += '?' + params.join('&');

  const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': method === 'POST' ? 'return=representation' : 'return=representation',
  };
  if (method === 'PATCH' || method === 'DELETE') {
    headers['Prefer'] = 'return=representation';
  }

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Supabase ${method} ${table} failed (${res.status})`);
  }
  return res.json().catch(() => null);
}

/* ════════════════════════════════
   MIDDLEWARE
════════════════════════════════ */
app.use(express.json({ limit: '20kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://js.paystack.co https://*.paystack.co https://paystack.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://*.paystack.co https://paystack.com https://checkout.paystack.com https://www.gstatic.com",
    "font-src 'self' https://fonts.gstatic.com https://www.gstatic.com https://*.paystack.co",
    "img-src 'self' data: https:",
    "connect-src 'self' https://api.anthropic.com https://*.supabase.co https://api.paystack.co https://*.paystack.co https://paystack.com https://open.er-api.com",
    "frame-src 'self' https://*.paystack.co https://paystack.com https://checkout.paystack.com https://js.paystack.co",
  ].join('; '));
  next();
});

/* ════════════════════════════════
   RATE LIMITING
════════════════════════════════ */
const ipMap = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'x';
    const now = Date.now();
    const rec = ipMap.get(ip) || { n: 0, t: now };
    if (now - rec.t > windowMs) { rec.n = 1; rec.t = now; } else rec.n++;
    ipMap.set(ip, rec);
    if (rec.n > max) return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    next();
  };
}

/* ════════════════════════════════
   SANITISE (preserves Unicode)
════════════════════════════════ */
function sanitise(str, maxLen = 4000) {
  if (typeof str !== 'string') return '';
  return str.replace(/</g, '').replace(/>/g, '').replace(/`/g, '').trim().slice(0, maxLen);
}
function sanitiseShort(str) { return sanitise(str, 200); }

/* ════════════════════════════════
   PASSWORD HASHING
════════════════════════════════ */
function hashPassword(password, salt) {
  const str = salt + password + 'reelscript_2026';
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36) + salt.slice(0, 4);
}
function makeToken() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

/* ════════════════════════════════
   IN-MEMORY SESSIONS (30 min TTL)
════════════════════════════════ */
const sessions  = new Map();
const anonMap   = new Map();
const SESSION_TTL = 30 * 60 * 1000;
const ANON_LIMIT  = 3;
const FREE_LIMIT  = 10;

/* ════════════════════════════════
   SERVE FRONTEND
════════════════════════════════ */
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true }));

/* ════════════════════════════════
   EMAIL SIGN UP
════════════════════════════════ */
app.post('/api/auth/signup', rateLimit(5, 60000), async (req, res) => {
  const email    = sanitiseShort(req.body.email    || '').toLowerCase();
  const password = sanitise(req.body.password || '', 100);

  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  try {
    // Check if email already exists
    const existing = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(email)}`,
      select: 'email',
    });
    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'An account with this email already exists. Please sign in.' });
    }

    const salt   = Math.random().toString(36).slice(2);
    const hashed = hashPassword(password, salt);

    await sb('POST', 'rs_users', {
      body: {
        email,
        password_hash: hashed,
        salt,
        plan: 'free',
        scripts_used: 0,
        preferred_platform: 'instagram',
        preferred_tone: 'bold_educative',
        preferred_industry: '',
      }
    });

    const token = makeToken();
    sessions.set(token, { email, plan: 'free', used: 0, platform: 'instagram', tone: 'bold_educative', industry: '', createdAt: Date.now() });
    setTimeout(() => sessions.delete(token), SESSION_TTL);

    res.json({ success: true, token, email });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'Could not create account. Please try again.' });
  }
});

/* ════════════════════════════════
   EMAIL SIGN IN
════════════════════════════════ */
app.post('/api/auth/signin', rateLimit(10, 60000), async (req, res) => {
  const email    = sanitiseShort(req.body.email    || '').toLowerCase();
  const password = sanitise(req.body.password || '', 100);

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  try {
    const rows = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(email)}`,
    });

    if (!rows || rows.length === 0) {
      return res.status(401).json({ error: 'No account found with this email. Please sign up first.' });
    }

    const user   = rows[0];
    const hashed = hashPassword(password, user.salt);

    if (hashed !== user.password_hash) {
      return res.status(401).json({ error: 'Incorrect password. Please try again.' });
    }

    // Check if Pro subscription is still valid
    const isPaid = user.plan === 'paid' &&
      user.subscription_expires &&
      new Date(user.subscription_expires) > new Date();

    const token = makeToken();
    sessions.set(token, {
      email:    user.email,
      plan:     isPaid ? 'paid' : 'free',
      used:     user.scripts_used || 0,
      platform: user.preferred_platform || 'instagram',
      tone:     user.preferred_tone     || 'bold_educative',
      industry: (user.preferred_industry && !user.preferred_industry.includes('@')) ? user.preferred_industry : '',
      createdAt: Date.now(),
    });
    setTimeout(() => sessions.delete(token), SESSION_TTL);

    res.json({ success: true, token, email: user.email });
  } catch (err) {
    console.error('Signin error:', err.message);
    res.status(500).json({ error: 'Sign in failed. Please try again.' });
  }
});

/* ════════════════════════════════
   GET PROFILE
════════════════════════════════ */
app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });
  res.json({
    email: user.email,
    plan:  user.plan,
    scripts_used_this_month: user.used,
    scripts_limit: user.plan === 'paid' ? 999999 : FREE_LIMIT,
    preferred_platform: user.platform,
    preferred_tone:     user.tone,
    preferred_industry: user.industry,
  });
});

/* ════════════════════════════════
   SCRIPTS — GET
════════════════════════════════ */
app.get('/api/scripts', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    const scripts = await sb('GET', 'rs_scripts', {
      filter: `user_email=eq.${encodeURIComponent(user.email)}`,
      order:  'created_at.desc',
      limit:  50,
    });
    res.json({ scripts: scripts || [], total: (scripts || []).length });
  } catch (err) {
    res.json({ scripts: [], total: 0 });
  }
});

/* ════════════════════════════════
   SCRIPTS — DELETE
════════════════════════════════ */
app.delete('/api/scripts/:id', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    await sb('DELETE', 'rs_scripts', {
      filter: `id=eq.${req.params.id}&user_email=eq.${encodeURIComponent(user.email)}`,
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed.' });
  }
});

/* ════════════════════════════════
   GENERATE SCRIPT
════════════════════════════════ */
app.post('/api/generate', rateLimit(20, 3600000), async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'API key not configured.' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;

  const systemPrompt = sanitise(req.body.systemPrompt, 6000);
  const userPrompt   = sanitise(req.body.userPrompt,   2000);
  const fingerprint  = sanitiseShort(req.body.fingerprint || 'anon');
  const platform     = sanitiseShort(req.body.platform  || '');
  const industry     = sanitiseShort(req.body.industry  || '');
  const tone         = sanitiseShort(req.body.tone      || '');
  const topic        = sanitiseShort(req.body.topic     || '');
  const duration     = sanitiseShort(req.body.duration  || '');

  if (!systemPrompt || !userPrompt) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  // ── Usage check ──
  let usage;
  if (user) {
    const isPaid = user.plan === 'paid';
    if (!isPaid && user.used >= FREE_LIMIT) {
      return res.status(403).json({
        error: `You have used all ${FREE_LIMIT} free scripts this month. Upgrade to Pro for unlimited scripts.`,
        showUpgrade: true,
      });
    }
    user.used++;
    if (platform) user.platform = platform;
    if (tone)     user.tone     = tone;
    // Never save email addresses as industry (data corruption guard)
    if (industry && !industry.includes('@')) user.industry = industry;
    // Update usage in Supabase
    sb('PATCH', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      body: {
        scripts_used: user.used,
        preferred_platform: user.platform,
        preferred_tone:     user.tone,
        preferred_industry: user.industry,
      }
    }).catch(e => console.error('Usage update failed:', e.message));
    usage = { plan: isPaid ? 'paid' : 'free', used: user.used, limit: FREE_LIMIT };
  } else {
    const fp   = fingerprint.slice(0, 64);
    const used = (anonMap.get(fp) || 0) + 1;
    if (used > ANON_LIMIT) {
      return res.status(403).json({
        error: `You have used all ${ANON_LIMIT} free scripts. Sign up free to get ${FREE_LIMIT} per month.`,
        showSignup: true,
      });
    }
    anonMap.set(fp, used);
    usage = { plan: 'anonymous', used, limit: ANON_LIMIT };
  }

  // ── Call Claude ──
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1200,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || `API error (${response.status})` });
    }

    const text = data.content?.map(b => b.text || '').join('') || '';

    // Save script to Supabase
    if (user && text) {
      sb('POST', 'rs_scripts', {
        body: {
          id:          Date.now().toString(36) + Math.random().toString(36).slice(2),
          user_email:  user.email,
          platform, industry, topic, tone, duration,
          script_text: text,
        }
      }).catch(e => console.error('Script save failed:', e.message));
    }

    res.json({ text, usage });
  } catch (err) {
    console.error('Generate error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/* ════════════════════════════════
   EXCHANGE RATES
════════════════════════════════ */
let ratesCache = null;
let ratesCacheTime = 0;

app.get('/api/rates', async (_req, res) => {
  try {
    const now = Date.now();
    if (ratesCache && now - ratesCacheTime < 3600000) {
      return res.json({ rates: ratesCache });
    }
    const resp = await fetch('https://open.er-api.com/v6/latest/NGN');
    const data = await resp.json();
    if (data.rates) {
      ratesCache = { NGN:1, GHS:data.rates.GHS||0.0086, KES:data.rates.KES||0.13, EGP:data.rates.EGP||0.048, XOF:data.rates.XOF||0.6, ZAR:data.rates.ZAR||0.019, USD:data.rates.USD||0.00065 };
      ratesCacheTime = now;
      return res.json({ rates: ratesCache });
    }
    throw new Error('No rates');
  } catch {
    res.json({ rates: { NGN:1, GHS:0.0086, KES:0.13, EGP:0.048, XOF:0.6, ZAR:0.019, USD:0.00065 } });
  }
});

/* ════════════════════════════════
   PAYSTACK — SUBSCRIBE
════════════════════════════════ */
const PRICES = { NGN:1500000, GHS:13000, KES:195000, EGP:72500, XOF:1500000, ZAR:28000, USD:1000 };

app.post('/api/subscribe', rateLimit(5, 60000), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Please sign in to subscribe.' });
  if (!PAYSTACK_SECRET) return res.status(500).json({ error: 'Payment not configured on server.' });

  const currency         = sanitiseShort(req.body.currency         || 'NGN').toUpperCase();
  const paystackCurrency = sanitiseShort(req.body.paystackCurrency || 'NGN').toUpperCase();
  const amount           = PRICES[currency] || PRICES.NGN;

  try {
    const resp = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: user.email,
        amount,
        currency: paystackCurrency,
        plan: paystackCurrency === 'NGN' ? PAYSTACK_PLAN_CODE : undefined,
        metadata: { token, email: user.email, currency },
        callback_url: `${APP_URL}/api/paystack/callback`,
      }),
    });
    const data = await resp.json();
    if (!data.status) return res.status(400).json({ error: data.message || 'Paystack error' });
    res.json({ authorization_url: data.data.authorization_url });
  } catch (err) {
    console.error('Subscribe error:', err.message);
    res.status(500).json({ error: 'Payment initiation failed. Try again.' });
  }
});

/* ════════════════════════════════
   PAYSTACK CALLBACK
════════════════════════════════ */
app.get('/api/paystack/callback', async (req, res) => {
  const { reference } = req.query;
  if (!reference) return res.redirect('/?payment=failed');
  try {
    const resp = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}` },
    });
    const data = await resp.json();
    if (data.data?.status === 'success') {
      const email = data.data.metadata?.email;
      const sessionToken = data.data.metadata?.token;

      // Update session
      const sessionUser = sessionToken ? sessions.get(sessionToken) : null;
      if (sessionUser) { sessionUser.plan = 'paid'; sessionUser.used = 0; }

      // Persist to Supabase
      if (email) {
        const expires = new Date();
        expires.setMonth(expires.getMonth() + 1);
        await sb('PATCH', 'rs_users', {
          filter: `email=eq.${encodeURIComponent(email.toLowerCase())}`,
          body: { plan: 'paid', scripts_used: 0, subscription_expires: expires.toISOString() }
        }).catch(e => console.error('Pro upgrade failed:', e.message));
        console.log(`✅ Upgraded ${email} to Pro via Paystack`);
      }
      return res.redirect('/?payment=success');
    }
    res.redirect('/?payment=failed');
  } catch (err) {
    console.error('Callback error:', err.message);
    res.redirect('/?payment=failed');
  }
});

/* ════════════════════════════════
   ADMIN — UPGRADE USER
════════════════════════════════ */
app.post('/api/admin/upgrade', async (req, res) => {
  const secret = req.query.secret || req.body.secret;
  const email  = (req.query.email || req.body.email || '').toLowerCase().trim();
  if (secret !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const expires = new Date();
    expires.setMonth(expires.getMonth() + 1);
    await sb('PATCH', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(email)}`,
      body: { plan: 'paid', scripts_used: 0, subscription_expires: expires.toISOString() }
    });
    // Update active sessions
    sessions.forEach(s => { if (s.email === email) { s.plan = 'paid'; s.used = 0; } });
    console.log(`✅ Admin upgraded ${email} to Pro`);
    res.json({ success: true, email, plan: 'paid', expires: expires.toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ════════════════════════════════
   ADMIN — LIST USERS
════════════════════════════════ */
app.get('/api/admin/users', async (req, res) => {
  if (req.query.secret !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const users = await sb('GET', 'rs_users', { select: 'email,plan,scripts_used,created_at,subscription_expires', order: 'created_at.desc' });
    res.json({ total: (users||[]).length, users: users||[] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ════════════════════════════════
   HEALTH CHECK
════════════════════════════════ */
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok', version: '4.0.0',
    anthropic: ANTHROPIC_API_KEY ? '✓' : '✗',
    supabase:  SUPABASE_URL      ? '✓' : '✗',
    paystack:  PAYSTACK_SECRET   ? '✓' : '✗',
  });
});

/* ════════════════════════════════
   SPA FALLBACK
════════════════════════════════ */
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎬 ReelScript Studio v4.0 → http://localhost:${PORT}`);
  console.log(`   Anthropic : ${ANTHROPIC_API_KEY ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Supabase  : ${SUPABASE_URL      ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Paystack  : ${PAYSTACK_SECRET   ? '✓ loaded' : '✗ not set'}\n`);
});