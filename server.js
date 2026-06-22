import express from 'express';
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

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
const PAYSTACK_PLAN_CODE = process.env.PAYSTACK_PLAN_CODE;        // legacy monthly (fallback)
const PLAN_MONTHLY       = process.env.PAYSTACK_PLAN_MONTHLY || PAYSTACK_PLAN_CODE || '';
const PLAN_ANNUAL        = process.env.PAYSTACK_PLAN_ANNUAL  || '';
const APP_URL            = process.env.APP_URL || 'https://reelscript-studio-2.onrender.com';
const ADMIN_SECRET       = process.env.ADMIN_SECRET || 'reelscript_admin_2026';

// Plan catalogue — amounts in kobo (NGN). Annual = 10 months price (2 months free)
const PLANS = {
  monthly: { code: PLAN_MONTHLY, amount: 1500000,  interval: 'monthly', label: 'Pro Monthly' },
  annual:  { code: PLAN_ANNUAL,  amount: 15000000, interval: 'annually', label: 'Pro Annual' },
};

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
   ANALYTICS — log an event (fire & forget)
════════════════════════════════ */
function logEvent(type, { email = '', state = 'anonymous', platform = '', industry = '', fingerprint = '', metadata = {} } = {}) {
  sb('POST', 'rs_events', {
    body: {
      event_type: type,
      user_email: email,
      user_state: state,
      platform,
      industry,
      fingerprint: fingerprint.slice(0, 64),
      metadata,
    }
  }).catch(e => console.error('Event log failed:', e.message));
}

/* ════════════════════════════════
   MIDDLEWARE
════════════════════════════════ */
// Webhook needs RAW body for signature verification — must come BEFORE json parser
app.use('/api/paystack/webhook', express.raw({ type: '*/*', limit: '1mb' }));

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
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
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

    // Analytics: log signup (include fingerprint to link prior anonymous activity)
    logEvent('signup', {
      email,
      state: 'free',
      fingerprint: sanitiseShort(req.body.fingerprint || ''),
    });

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

    // Reset monthly usage if it's a new month
    const now       = new Date();
    const lastReset = user.last_reset ? new Date(user.last_reset) : null;
    const isNewMonth = !lastReset ||
      lastReset.getMonth() !== now.getMonth() ||
      lastReset.getFullYear() !== now.getFullYear();

    let scriptsUsed = user.scripts_used || 0;
    if (isNewMonth && !isPaid) {
      scriptsUsed = 0;
      // Reset in Supabase
      sb('PATCH', 'rs_users', {
        filter: `email=eq.${encodeURIComponent(user.email)}`,
        body: { scripts_used: 0, last_reset: now.toISOString() }
      }).catch(e => console.error('Reset failed:', e.message));
    }

    const token = makeToken();
    sessions.set(token, {
      email:    user.email,
      plan:     isPaid ? 'paid' : 'free',
      used:     scriptsUsed,
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
   RESTORE SESSION
   Re-establishes a session after server restart/timeout.
   Security: only restores if the email exists in the database.
   The token itself is opaque; we trust localStorage possession +
   email existence. (For higher security, switch to signed JWTs.)
════════════════════════════════ */
app.post('/api/auth/restore', rateLimit(20, 60000), async (req, res) => {
  const email = sanitiseShort(req.body.email || '').toLowerCase();
  const oldToken = sanitiseShort(req.body.token || '');

  if (!email || !email.includes('@') || !oldToken) {
    return res.status(400).json({ error: 'Invalid restore request.' });
  }

  try {
    // Verify the account exists
    const rows = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(email)}`,
    });
    if (!rows || rows.length === 0) {
      return res.status(401).json({ error: 'Account not found.' });
    }

    const user = rows[0];
    const isPaid = user.plan === 'paid' &&
      user.subscription_expires &&
      new Date(user.subscription_expires) > new Date();

    // Monthly usage reset check
    const now = new Date();
    const lastReset = user.last_reset ? new Date(user.last_reset) : null;
    const isNewMonth = !lastReset ||
      lastReset.getMonth() !== now.getMonth() ||
      lastReset.getFullYear() !== now.getFullYear();
    let scriptsUsed = user.scripts_used || 0;
    if (isNewMonth && !isPaid) {
      scriptsUsed = 0;
      sb('PATCH', 'rs_users', {
        filter: `email=eq.${encodeURIComponent(user.email)}`,
        body: { scripts_used: 0, last_reset: now.toISOString() }
      }).catch(() => {});
    }

    // Issue a fresh session token
    const token = makeToken();
    sessions.set(token, {
      email:    user.email,
      plan:     isPaid ? 'paid' : 'free',
      used:     scriptsUsed,
      platform: user.preferred_platform || 'instagram',
      tone:     user.preferred_tone     || 'bold_educative',
      industry: (user.preferred_industry && !user.preferred_industry.includes('@')) ? user.preferred_industry : '',
      createdAt: Date.now(),
    });
    setTimeout(() => sessions.delete(token), SESSION_TTL);

    res.json({ success: true, token, email: user.email });
  } catch (err) {
    console.error('Restore error:', err.message);
    res.status(500).json({ error: 'Could not restore session.' });
  }
});

/* ════════════════════════════════
   GET PROFILE
════════════════════════════════ */
app.get('/api/profile', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  // Fetch full profile from Supabase including brand fields
  try {
    const rows = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      select: 'email,plan,scripts_used,preferred_platform,preferred_tone,preferred_industry,brand_name,brand_industry,brand_tone,brand_city,brand_difference,onboarding_done,subscription_expires',
    });
    const dbUser = rows?.[0];
    res.json({
      email: user.email,
      plan:  user.plan,
      scripts_used_this_month: user.used,
      scripts_limit: user.plan === 'paid' ? 999999 : FREE_LIMIT,
      preferred_platform: user.platform,
      preferred_tone:     user.tone,
      preferred_industry: user.industry,
      // Brand voice fields
      brand_name:       dbUser?.brand_name       || '',
      brand_industry:   dbUser?.brand_industry   || '',
      brand_tone:       dbUser?.brand_tone       || '',
      brand_city:       dbUser?.brand_city       || '',
      brand_difference: dbUser?.brand_difference || '',
      onboarding_done:  dbUser?.onboarding_done  || false,
    });
  } catch {
    // Fallback to session data only
    res.json({
      email: user.email,
      plan:  user.plan,
      scripts_used_this_month: user.used,
      scripts_limit: user.plan === 'paid' ? 999999 : FREE_LIMIT,
      preferred_platform: user.platform,
      preferred_tone:     user.tone,
      preferred_industry: user.industry,
      brand_name:'', brand_industry:'', brand_tone:'', brand_city:'', brand_difference:'', onboarding_done:false,
    });
  }
});

/* ════════════════════════════════
   SAVE BRAND VOICE
════════════════════════════════ */
app.post('/api/profile/brand', rateLimit(10, 60000), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  const {
    brand_name, brand_industry, brand_tone,
    brand_city, brand_difference, onboarding_done
  } = req.body;

  try {
    await sb('PATCH', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      body: {
        brand_name:       sanitise(brand_name       || '', 100),
        brand_industry:   sanitise(brand_industry   || '', 100),
        brand_tone:       sanitise(brand_tone       || '', 50),
        brand_city:       sanitise(brand_city       || '', 100),
        brand_difference: sanitise(brand_difference || '', 300),
        onboarding_done:  Boolean(onboarding_done),
      }
    });
    // Update session
    user.brand_name       = brand_name;
    user.onboarding_done  = true;
    res.json({ success: true });
  } catch (err) {
    console.error('Brand save error:', err.message);
    res.status(500).json({ error: 'Could not save brand profile.' });
  }
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

    // ── Analytics: log script generation with user state ──
    if (text) {
      const state = user ? (user.plan === 'paid' ? 'pro' : 'free') : 'anonymous';
      logEvent('script_generated', {
        email: user?.email || '',
        state,
        platform,
        industry,
        fingerprint,
        metadata: { tone, duration },
      });
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
   PAYSTACK — SUBSCRIBE (recurring plans)
   Body: { plan: 'monthly' | 'annual' }
════════════════════════════════ */
app.post('/api/subscribe', rateLimit(5, 60000), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Please sign in to subscribe.' });
  if (!PAYSTACK_SECRET) return res.status(500).json({ error: 'Payment not configured on server.' });

  const planKey = (req.body.plan === 'annual') ? 'annual' : 'monthly';
  const plan    = PLANS[planKey];

  if (!plan.code) {
    return res.status(500).json({ error: `${plan.label} plan not configured. Add the plan code in settings.` });
  }

  try {
    const resp = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: user.email,
        amount: plan.amount,
        currency: 'NGN',
        plan: plan.code,                 // recurring subscription via plan code
        metadata: {
          email: user.email,
          plan_key: planKey,
          interval: plan.interval,
        },
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
   PAYSTACK CALLBACK (browser redirect after pay)
   This is for UX only — real truth comes from the webhook.
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
      // The webhook will do the authoritative DB update.
      // We optimistically update here too for instant UX.
      const email = data.data.customer?.email || data.data.metadata?.email;
      if (email) await activateSubscription(email.toLowerCase(), data.data);
      return res.redirect('/?payment=success');
    }
    res.redirect('/?payment=failed');
  } catch (err) {
    console.error('Callback error:', err.message);
    res.redirect('/?payment=failed');
  }
});

/* ════════════════════════════════
   PAYSTACK WEBHOOK (authoritative)
   Verifies signature, handles lifecycle events.
════════════════════════════════ */
app.post('/api/paystack/webhook', async (req, res) => {
  // req.body is a Buffer (raw) because of express.raw middleware
  const signature = req.headers['x-paystack-signature'];
  if (!PAYSTACK_SECRET) return res.sendStatus(500);

  // Verify signature
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
  if (hash !== signature) {
    console.warn('⚠️  Webhook signature mismatch — rejected');
    return res.sendStatus(401);
  }

  // Acknowledge immediately so Paystack doesn't retry
  res.sendStatus(200);

  let event;
  try { event = JSON.parse(req.body.toString()); }
  catch { return; }

  const type = event.event;
  const data = event.data || {};
  const email = (data.customer?.email || data.metadata?.email || '').toLowerCase();
  if (!email) return;

  console.log(`📩 Webhook: ${type} for ${email}`);

  try {
    switch (type) {
      case 'charge.success':
      case 'subscription.create':
        await activateSubscription(email, data);
        break;

      case 'invoice.create':
      case 'invoice.update':
        // Recurring renewal succeeded
        if (data.status === 'success' || data.paid) {
          await activateSubscription(email, data);
        }
        break;

      case 'invoice.payment_failed':
        await markPastDue(email);
        break;

      case 'subscription.not_renew':
        // User/Paystack flagged subscription to not renew → cancelling
        await markCancelling(email);
        break;

      case 'subscription.disable':
        // Subscription fully ended
        await expireSubscription(email);
        break;

      default:
        // ignore other events
        break;
    }
  } catch (err) {
    console.error('Webhook handler error:', err.message);
  }
});

/* ════════════════════════════════
   SUBSCRIPTION STATE HELPERS
════════════════════════════════ */
async function activateSubscription(email, data) {
  const interval = data.plan?.interval || data.metadata?.interval || 'monthly';
  const now = new Date();
  const next = new Date(now);
  if (interval === 'annually' || interval === 'annual') next.setFullYear(next.getFullYear() + 1);
  else next.setMonth(next.getMonth() + 1);

  const body = {
    plan: 'paid',
    subscription_status: 'active',
    subscription_interval: interval,
    subscription_start: now.toISOString(),
    subscription_next_payment: next.toISOString(),
    subscription_expires: next.toISOString(),
    cancel_at_period_end: false,
    scripts_used: 0,
  };
  if (data.subscription_code || data.plan?.subscription_code) {
    body.subscription_code = data.subscription_code || data.plan.subscription_code;
  }
  if (data.customer?.customer_code) body.paystack_customer_code = data.customer.customer_code;
  if (data.plan?.plan_code || data.metadata?.plan_key) {
    body.subscription_plan = data.plan?.plan_code || data.metadata?.plan_key;
  }

  await sb('PATCH', 'rs_users', {
    filter: `email=eq.${encodeURIComponent(email)}`,
    body,
  });

  // Update any live session
  sessions.forEach(s => { if (s.email === email) { s.plan = 'paid'; s.used = 0; } });
  console.log(`✅ Activated ${interval} Pro for ${email}`);

  // Analytics: log subscription
  logEvent('subscribe', {
    email,
    state: 'pro',
    metadata: { interval },
  });
}

async function markPastDue(email) {
  await sb('PATCH', 'rs_users', {
    filter: `email=eq.${encodeURIComponent(email)}`,
    body: { subscription_status: 'past_due' },
  });
  console.log(`⚠️  ${email} marked past_due`);
}

async function markCancelling(email) {
  await sb('PATCH', 'rs_users', {
    filter: `email=eq.${encodeURIComponent(email)}`,
    body: { subscription_status: 'cancelling', cancel_at_period_end: true },
  });
  console.log(`🔻 ${email} set to cancel at period end`);
}

async function expireSubscription(email) {
  await sb('PATCH', 'rs_users', {
    filter: `email=eq.${encodeURIComponent(email)}`,
    body: { plan: 'free', subscription_status: 'expired', cancel_at_period_end: false },
  });
  sessions.forEach(s => { if (s.email === email) s.plan = 'free'; });
  console.log(`⛔ ${email} subscription expired → downgraded to free`);
}

/* ════════════════════════════════
   CANCEL SUBSCRIPTION (self-service)
   Disables auto-renew; user keeps Pro until period ends.
════════════════════════════════ */
app.post('/api/subscription/cancel', rateLimit(5, 60000), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  try {
    const rows = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      select: 'subscription_code,email',
    });
    const subCode = rows?.[0]?.subscription_code;

    if (subCode && PAYSTACK_SECRET) {
      // Fetch subscription to get email token for disable
      const subResp = await fetch(`https://api.paystack.co/subscription/${subCode}`, {
        headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}` },
      });
      const subData = await subResp.json();
      const emailToken = subData.data?.email_token;

      if (emailToken) {
        await fetch('https://api.paystack.co/subscription/disable', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: subCode, token: emailToken }),
        });
      }
    }

    // Mark as cancelling — keeps Pro until period end
    await sb('PATCH', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      body: { subscription_status: 'cancelling', cancel_at_period_end: true },
    });

    res.json({ success: true, message: 'Subscription will not renew. You keep Pro until your billing period ends.' });
  } catch (err) {
    console.error('Cancel error:', err.message);
    res.status(500).json({ error: 'Could not cancel. Please try again or contact support.' });
  }
});

/* ════════════════════════════════
   GET SUBSCRIPTION STATUS
════════════════════════════════ */
app.get('/api/subscription', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  try {
    const rows = await sb('GET', 'rs_users', {
      filter: `email=eq.${encodeURIComponent(user.email)}`,
      select: 'plan,subscription_status,subscription_interval,subscription_next_payment,subscription_expires,cancel_at_period_end',
    });
    const u = rows?.[0] || {};
    res.json({
      plan: u.plan || 'free',
      status: u.subscription_status || 'free',
      interval: u.subscription_interval || '',
      next_payment: u.subscription_next_payment || null,
      expires: u.subscription_expires || null,
      cancel_at_period_end: u.cancel_at_period_end || false,
    });
  } catch (err) {
    res.status(500).json({ error: 'Could not load subscription.' });
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
   ADMIN — ANALYTICS DASHBOARD
   GET /api/admin/analytics?secret=XXX
════════════════════════════════ */
app.get('/api/admin/analytics', async (req, res) => {
  if (req.query.secret !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });

  try {
    // Pull all events (cap at 10k for safety)
    const events = await sb('GET', 'rs_events', {
      select: 'event_type,user_state,platform,created_at,user_email',
      order: 'created_at.desc',
      limit: 10000,
    }) || [];

    // Scripts generated by user state
    const scriptEvents = events.filter(e => e.event_type === 'script_generated');
    const scriptsByState = {
      anonymous: scriptEvents.filter(e => e.user_state === 'anonymous').length,
      free:      scriptEvents.filter(e => e.user_state === 'free').length,
      pro:       scriptEvents.filter(e => e.user_state === 'pro').length,
    };

    // Conversion counts
    const signups = events.filter(e => e.event_type === 'signup').length;
    const subscribes = events.filter(e => e.event_type === 'subscribe').length;

    // Scripts by platform
    const byPlatform = {};
    scriptEvents.forEach(e => {
      if (e.platform) byPlatform[e.platform] = (byPlatform[e.platform] || 0) + 1;
    });

    // Time windows
    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    const last24h = scriptEvents.filter(e => now - new Date(e.created_at).getTime() < day).length;
    const last7d  = scriptEvents.filter(e => now - new Date(e.created_at).getTime() < 7 * day).length;
    const last30d = scriptEvents.filter(e => now - new Date(e.created_at).getTime() < 30 * day).length;

    // User totals
    const allUsers = await sb('GET', 'rs_users', { select: 'plan' }) || [];
    const totalUsers = allUsers.length;
    const proUsers = allUsers.filter(u => u.plan === 'paid').length;

    const totalScripts = scriptEvents.length;

    res.json({
      summary: {
        total_scripts: totalScripts,
        total_users: totalUsers,
        pro_users: proUsers,
        free_users: totalUsers - proUsers,
        total_signups: signups,
        total_subscriptions: subscribes,
        signup_to_pro_rate: signups ? ((subscribes / signups) * 100).toFixed(1) + '%' : '0%',
      },
      scripts_by_state: scriptsByState,
      scripts_by_platform: byPlatform,
      scripts_over_time: {
        last_24h: last24h,
        last_7d:  last7d,
        last_30d: last30d,
      },
      funnel: {
        anonymous_scripts: scriptsByState.anonymous,
        then_signed_up: signups,
        then_subscribed: subscribes,
      },
    });
  } catch (err) {
    console.error('Analytics error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ════════════════════════════════
   HEALTH CHECK
════════════════════════════════ */
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok', version: '5.0.0',
    anthropic: ANTHROPIC_API_KEY ? '✓' : '✗',
    supabase:  SUPABASE_URL      ? '✓' : '✗',
    paystack:  PAYSTACK_SECRET   ? '✓' : '✗',
    plan_monthly: PLAN_MONTHLY ? '✓' : '✗',
    plan_annual:  PLAN_ANNUAL  ? '✓' : '✗',
  });
});

/* ════════════════════════════════
   LEGAL PAGES
════════════════════════════════ */
app.get(['/legal', '/terms', '/privacy', '/refund'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'legal.html'));
});

/* ════════════════════════════════
   ANALYTICS DASHBOARD PAGE
════════════════════════════════ */
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

/* ════════════════════════════════
   SPA FALLBACK
════════════════════════════════ */
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎬 ReelScript Studio v5.0 → http://localhost:${PORT}`);
  console.log(`   Anthropic : ${ANTHROPIC_API_KEY ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Supabase  : ${SUPABASE_URL      ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Paystack  : ${PAYSTACK_SECRET   ? '✓ loaded' : '✗ not set'}`);
  console.log(`   Plan (M)  : ${PLAN_MONTHLY ? '✓ ' + PLAN_MONTHLY : '✗ not set'}`);
  console.log(`   Plan (A)  : ${PLAN_ANNUAL  ? '✓ ' + PLAN_ANNUAL  : '✗ not set'}\n`);
});