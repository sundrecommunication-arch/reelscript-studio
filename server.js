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
const TERMII_API_KEY     = process.env.TERMII_API_KEY;
const TERMII_SENDER_ID   = process.env.TERMII_SENDER_ID || 'N-Alert';
const PAYSTACK_SECRET    = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PLAN_CODE = process.env.PAYSTACK_PLAN_CODE;
const APP_URL            = process.env.APP_URL || 'https://reelscript-studio-2.onrender.com';

/* ════════════════════════════════
   MIDDLEWARE
════════════════════════════════ */
app.use(express.json({ limit: '20kb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://js.paystack.co",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://js.paystack.co https://checkout.paystack.com https://paystack.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://api.anthropic.com https://*.supabase.co https://api.paystack.co https://api.ng.termii.com",
    "frame-src 'self' https://js.paystack.co https://checkout.paystack.com",
  ].join('; '));
  next();
});

// Rate limiting
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
   SANITISE
   — preserves Unicode (Yoruba, Hausa, Igbo, French accents)
   — only strips actual dangerous HTML/script chars
════════════════════════════════ */
function sanitise(str, maxLen = 4000) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/</g, '').replace(/>/g, '')   // strip < >
    .replace(/`/g, '')                      // strip backticks
    .trim()
    .slice(0, maxLen);
}
function sanitiseShort(str) { return sanitise(str, 200); }

/* ════════════════════════════════
   IN-MEMORY STORES
════════════════════════════════ */
// OTP store: kept for compatibility
const otpStore = new Map();
// User accounts: email → { email, salt, password, plan, used, ... }
const userStore = new Map();
// Anonymous usage: fingerprint → count
const anonMap  = new Map();
// User sessions: token → { email, plan, used, ... }
const sessions = new Map();

const ANON_LIMIT  = 3;
const FREE_LIMIT  = 10;
const SESSION_TTL = 30 * 60 * 1000; // 30 min auto-logout

// Simple password hash (no bcrypt needed — no extra packages)
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
   EMAIL SIGN UP
════════════════════════════════ */
app.post('/api/auth/signup', rateLimit(5, 60000), (req, res) => {
  const email    = sanitiseShort(req.body.email    || '').toLowerCase();
  const password = sanitise(req.body.password || '', 100);

  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (userStore.has(email)) return res.status(400).json({ error: 'An account with this email already exists. Please sign in.' });

  const salt  = Math.random().toString(36).slice(2);
  const hashed = hashPassword(password, salt);

  userStore.set(email, {
    email, salt, password: hashed,
    plan: 'free', used: 0,
    industry: '', platform: 'instagram', tone: 'bold_educative',
    createdAt: Date.now(),
  });

  const token = makeToken();
  sessions.set(token, { email, plan: 'free', used: 0, industry: '', platform: 'instagram', tone: 'bold_educative', createdAt: Date.now() });
  setTimeout(() => sessions.delete(token), SESSION_TTL);

  res.json({ success: true, token, email });
});

/* ════════════════════════════════
   EMAIL SIGN IN
════════════════════════════════ */
app.post('/api/auth/signin', rateLimit(10, 60000), (req, res) => {
  const email    = sanitiseShort(req.body.email    || '').toLowerCase();
  const password = sanitise(req.body.password || '', 100);

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const user = userStore.get(email);
  if (!user) return res.status(401).json({ error: 'No account found with this email. Please sign up first.' });

  const hashed = hashPassword(password, user.salt);
  if (hashed !== user.password) return res.status(401).json({ error: 'Incorrect password. Please try again.' });

  const token = makeToken();
  sessions.set(token, {
    email: user.email,
    plan: user.plan,
    used: user.used,
    industry: user.industry,
    platform: user.platform,
    tone: user.tone,
    createdAt: Date.now(),
  });
  setTimeout(() => sessions.delete(token), SESSION_TTL);

  res.json({ success: true, token, email: user.email });
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
    plan: user.plan,
    scripts_used_this_month: user.used,
    scripts_limit: user.plan === 'paid' ? 999999 : FREE_LIMIT,
    preferred_platform: user.platform,
    preferred_tone: user.tone,
    preferred_industry: user.industry,
  });
});

/* ════════════════════════════════
   GENERATE SCRIPT
════════════════════════════════ */
app.post('/api/generate', rateLimit(20, 3600000), async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'API key not configured. Add ANTHROPIC_API_KEY to Render environment variables.' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;

  // Sanitise prompts — preserve Unicode for language support
  const systemPrompt = sanitise(req.body.systemPrompt, 6000);
  const userPrompt   = sanitise(req.body.userPrompt,   2000);
  const fingerprint  = sanitiseShort(req.body.fingerprint || 'anon');
  const platform     = sanitiseShort(req.body.platform  || '');
  const industry     = sanitiseShort(req.body.industry  || '');
  const tone         = sanitiseShort(req.body.tone      || '');

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
    // Save preferences
    if (platform) user.platform = platform;
    if (tone)     user.tone     = tone;
    if (industry) user.industry = industry;
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

  // ── Call Anthropic ──
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
    res.json({ text, usage });

  } catch (err) {
    console.error('Generate error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/* ════════════════════════════════
   PAYSTACK — SUBSCRIBE
════════════════════════════════ */
app.post('/api/subscribe', rateLimit(5, 60000), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = token ? sessions.get(token) : null;
  if (!user) return res.status(401).json({ error: 'Please sign in to subscribe.' });
  if (!PAYSTACK_SECRET) return res.status(500).json({ error: 'Payment not configured.' });

  const email = user.phone.replace('+', '') + '@reelscript.app';

  try {
    const resp = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        amount: 1500000,
        plan: PAYSTACK_PLAN_CODE,
        metadata: { token, phone: user.phone },
        callback_url: `${APP_URL}/api/paystack/callback`,
      }),
    });
    const data = await resp.json();
    if (!data.status) return res.status(400).json({ error: data.message });
    res.json({ authorization_url: data.data.authorization_url });
  } catch (err) {
    res.status(500).json({ error: 'Payment initiation failed.' });
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
      const sessionToken = data.data.metadata?.token;
      const user = sessionToken ? sessions.get(sessionToken) : null;
      if (user) { user.plan = 'paid'; user.used = 0; }
      return res.redirect('/?payment=success');
    }
    res.redirect('/?payment=failed');
  } catch { res.redirect('/?payment=failed'); }
});

/* ════════════════════════════════
   HEALTH CHECK
════════════════════════════════ */
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '3.1.0',
    anthropic: ANTHROPIC_API_KEY  ? '✓' : '✗ missing',
    termii:    TERMII_API_KEY     ? '✓' : '✗ not set (dev mode)',
    paystack:  PAYSTACK_SECRET    ? '✓' : '✗ not set',
  });
});

/* ════════════════════════════════
   SERVE FRONTEND
════════════════════════════════ */
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true }));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎬 ReelScript Studio v3.1 → http://localhost:${PORT}`);
  console.log(`   Anthropic : ${ANTHROPIC_API_KEY  ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Termii    : ${TERMII_API_KEY     ? '✓ loaded' : '⚠ not set — dev mode (OTP logged to console)'}`);
  console.log(`   Paystack  : ${PAYSTACK_SECRET    ? '✓ loaded' : '✗ not set'}\n`);
});