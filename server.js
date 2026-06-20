import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

/* ════════════════════════════════
   LOAD ENV
════════════════════════════════ */
function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!existsSync(envPath)) return;
  readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const [key, ...rest] = line.split('=');
    if (key && rest.length && !process.env[key.trim()]) {
      process.env[key.trim()] = rest.join('=').trim();
    }
  });
}
loadEnv();

const {
  ANTHROPIC_API_KEY,
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  SUPABASE_ANON_KEY,
  PAYSTACK_SECRET_KEY,
  PAYSTACK_PLAN_CODE,
} = process.env;

/* ════════════════════════════════
   SUPABASE CLIENTS
════════════════════════════════ */
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const supabaseAnon  = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

/* ════════════════════════════════
   SECURITY MIDDLEWARE
════════════════════════════════ */
// Helmet — secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", "https://js.paystack.co", "https://fonts.googleapis.com"],
      styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      fontSrc:     ["'self'", "https://fonts.gstatic.com"],
      connectSrc:  ["'self'", "https://api.anthropic.com", "https://*.supabase.co", "https://api.paystack.co"],
      frameSrc:    ["'self'", "https://js.paystack.co"],
      imgSrc:      ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' })); // block oversized payloads

// Global rate limit — 100 requests per 15 minutes per IP
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please wait a few minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// Strict rate limit on generate — 20 per hour per IP
const generateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Script generation limit reached. Please try again in an hour.' },
});

// Auth rate limit — 10 per 15 min (block brute force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts. Please wait 15 minutes.' },
});

// Sanitise string — strip HTML/script tags
function sanitise(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<[^>]*>/g, '')
    .replace(/[<>'"`;]/g, '')
    .trim()
    .slice(0, 500);
}

/* ════════════════════════════════
   SERVE FRONTEND
════════════════════════════════ */
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true,
}));

/* ════════════════════════════════
   AUTH MIDDLEWARE
════════════════════════════════ */
async function getUser(req) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return null;
  try {
    const { data: { user }, error } = await supabaseAnon.auth.getUser(token);
    if (error || !user) return null;
    return user;
  } catch { return null; }
}

/* ════════════════════════════════
   USAGE LIMITS
════════════════════════════════ */
const ANON_LIMIT     = 3;   // anonymous users
const FREE_LIMIT     = 10;  // registered free users
// paid users = unlimited

async function checkAndIncrementUsage(user, fingerprint) {
  // ── Paid user — unlimited ──
  if (user) {
    const { data: profile } = await supabaseAdmin
      .from('profiles')
      .select('plan, scripts_used_this_month, scripts_limit, subscription_expires_at')
      .eq('id', user.id)
      .single();

    if (!profile) return { allowed: false, reason: 'Profile not found.' };

    // Check if paid plan is still active
    const isPaid = profile.plan === 'paid' &&
      profile.subscription_expires_at &&
      new Date(profile.subscription_expires_at) > new Date();

    if (isPaid) {
      // Increment usage but don't block
      await supabaseAdmin.from('profiles')
        .update({ scripts_used_this_month: profile.scripts_used_this_month + 1, updated_at: new Date() })
        .eq('id', user.id);
      return { allowed: true, plan: 'paid', used: profile.scripts_used_this_month + 1, limit: -1 };
    }

    // Free registered user
    if (profile.scripts_used_this_month >= FREE_LIMIT) {
      return { allowed: false, reason: `You have used all ${FREE_LIMIT} free scripts this month. Upgrade to Pro for unlimited scripts.`, showUpgrade: true };
    }
    await supabaseAdmin.from('profiles')
      .update({ scripts_used_this_month: profile.scripts_used_this_month + 1, updated_at: new Date() })
      .eq('id', user.id);
    return { allowed: true, plan: 'free', used: profile.scripts_used_this_month + 1, limit: FREE_LIMIT };
  }

  // ── Anonymous user — track by fingerprint ──
  if (!fingerprint) return { allowed: false, reason: 'Unable to track usage.' };

  const fp = sanitise(fingerprint).slice(0, 64);
  const { data: anon } = await supabaseAdmin
    .from('anonymous_usage')
    .select('id, scripts_used')
    .eq('fingerprint', fp)
    .single();

  if (anon) {
    if (anon.scripts_used >= ANON_LIMIT) {
      return { allowed: false, reason: `You have used all ${ANON_LIMIT} free scripts. Sign up free to get ${FREE_LIMIT} scripts per month.`, showSignup: true };
    }
    await supabaseAdmin.from('anonymous_usage')
      .update({ scripts_used: anon.scripts_used + 1, last_used_at: new Date() })
      .eq('fingerprint', fp);
    return { allowed: true, plan: 'anonymous', used: anon.scripts_used + 1, limit: ANON_LIMIT };
  } else {
    await supabaseAdmin.from('anonymous_usage')
      .insert({ fingerprint: fp, scripts_used: 1 });
    return { allowed: true, plan: 'anonymous', used: 1, limit: ANON_LIMIT };
  }
}

/* ════════════════════════════════
   GENERATE ENDPOINT
════════════════════════════════ */
app.post('/api/generate', generateLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'Server not configured. Contact support.' });
  }

  const user = await getUser(req);
  const { systemPrompt, userPrompt, fingerprint, platform, industry, topic, tone, duration } = req.body;

  // Sanitise all inputs
  const cleanSystem   = sanitise(systemPrompt);
  const cleanUser     = sanitise(userPrompt);
  const cleanIndustry = sanitise(industry);
  const cleanTopic    = sanitise(topic);
  const cleanPlatform = sanitise(platform);
  const cleanTone     = sanitise(tone);
  const cleanDuration = sanitise(duration);

  if (!cleanSystem || !cleanUser) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  // Check usage limits
  const usage = await checkAndIncrementUsage(user, fingerprint);
  if (!usage.allowed) {
    return res.status(403).json({
      error: usage.reason,
      showUpgrade: usage.showUpgrade || false,
      showSignup:  usage.showSignup  || false,
    });
  }

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
        system: cleanSystem,
        messages: [{ role: 'user', content: cleanUser }],
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || 'AI error' });
    }

    const text = data.content?.map(b => b.text || '').join('') || '';

    // Save script to database if user is logged in
    if (user && text) {
      await supabaseAdmin.from('scripts').insert({
        user_id:     user.id,
        platform:    cleanPlatform,
        industry:    cleanIndustry,
        topic:       cleanTopic,
        tone:        cleanTone,
        duration:    cleanDuration,
        script_text: text,
      });

      // Update user preferences
      await supabaseAdmin.from('profiles').update({
        preferred_platform: cleanPlatform,
        preferred_tone:     cleanTone,
        preferred_industry: cleanIndustry,
        updated_at: new Date(),
      }).eq('id', user.id);
    }

    res.json({ text, usage });

  } catch (err) {
    console.error('Generate error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/* ════════════════════════════════
   USER PROFILE
════════════════════════════════ */
app.get('/api/profile', async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  const { data: profile } = await supabaseAdmin
    .from('profiles')
    .select('*')
    .eq('id', user.id)
    .single();

  res.json({ user: { id: user.id, email: user.email, phone: user.phone }, profile });
});

/* ════════════════════════════════
   USER SCRIPTS LIBRARY
════════════════════════════════ */
app.get('/api/scripts', async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  const page  = parseInt(req.query.page  || '1');
  const limit = parseInt(req.query.limit || '20');
  const from  = (page - 1) * limit;

  const { data: scripts, count } = await supabaseAdmin
    .from('scripts')
    .select('*', { count: 'exact' })
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .range(from, from + limit - 1);

  res.json({ scripts: scripts || [], total: count || 0, page, limit });
});

app.delete('/api/scripts/:id', async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  const { id } = req.params;
  await supabaseAdmin.from('scripts')
    .delete()
    .eq('id', id)
    .eq('user_id', user.id); // RLS: only own scripts

  res.json({ success: true });
});

/* ════════════════════════════════
   PAYSTACK — INITIATE SUBSCRIPTION
════════════════════════════════ */
app.post('/api/subscribe', authLimiter, async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Please sign in to subscribe.' });

  const { data: profile } = await supabaseAdmin
    .from('profiles').select('email, phone').eq('id', user.id).single();

  const email = profile?.email || user.email || `user_${user.id.slice(0,8)}@reelscript.app`;

  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        amount: 500000, // ₦5,000 in kobo
        plan: PAYSTACK_PLAN_CODE,
        metadata: { user_id: user.id, cancel_action: 'https://reelscript-studio-2.onrender.com' },
        callback_url: `${process.env.APP_URL || 'https://reelscript-studio-2.onrender.com'}/api/paystack/callback`,
      }),
    });

    const data = await response.json();
    if (!data.status) return res.status(400).json({ error: data.message });

    res.json({ authorization_url: data.data.authorization_url, reference: data.data.reference });
  } catch (err) {
    res.status(500).json({ error: 'Payment initiation failed. Try again.' });
  }
});

/* ════════════════════════════════
   PAYSTACK — CALLBACK (after payment)
════════════════════════════════ */
app.get('/api/paystack/callback', async (req, res) => {
  const { reference } = req.query;
  if (!reference) return res.redirect('/?payment=failed');

  try {
    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const data = await response.json();

    if (data.data?.status === 'success') {
      const userId = data.data.metadata?.user_id;
      if (userId) {
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 1);

        await supabaseAdmin.from('profiles').update({
          plan: 'paid',
          subscription_code: data.data.subscription_code || reference,
          subscription_expires_at: expiresAt.toISOString(),
          scripts_used_this_month: 0,
          updated_at: new Date(),
        }).eq('id', userId);
      }
      return res.redirect('/?payment=success');
    }
    res.redirect('/?payment=failed');
  } catch {
    res.redirect('/?payment=failed');
  }
});

/* ════════════════════════════════
   PAYSTACK WEBHOOK (subscription renewals)
════════════════════════════════ */
app.post('/api/paystack/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const hash = req.headers['x-paystack-signature'];
  // Verify webhook signature
  const crypto = await import('crypto');
  const expected = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.body).digest('hex');
  if (hash !== expected) return res.status(401).send('Invalid signature');

  const event = JSON.parse(req.body);

  if (event.event === 'charge.success' || event.event === 'subscription.create') {
    const userId = event.data?.metadata?.user_id;
    if (userId) {
      const expiresAt = new Date();
      expiresAt.setMonth(expiresAt.getMonth() + 1);
      await supabaseAdmin.from('profiles').update({
        plan: 'paid',
        subscription_expires_at: expiresAt.toISOString(),
        scripts_used_this_month: 0,
        updated_at: new Date(),
      }).eq('id', userId);
    }
  }

  if (event.event === 'subscription.disable') {
    const userId = event.data?.metadata?.user_id;
    if (userId) {
      await supabaseAdmin.from('profiles').update({
        plan: 'free',
        updated_at: new Date(),
      }).eq('id', userId);
    }
  }

  res.sendStatus(200);
});

/* ════════════════════════════════
   RESET MONTHLY USAGE (call via cron or manual)
════════════════════════════════ */
app.post('/api/admin/reset-monthly', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  await supabaseAdmin.from('profiles').update({ scripts_used_this_month: 0 });
  await supabaseAdmin.from('anonymous_usage').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  res.json({ success: true, message: 'Monthly usage reset.' });
});

/* ════════════════════════════════
   HEALTH CHECK
════════════════════════════════ */
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '3.0.0',
    anthropic:  ANTHROPIC_API_KEY  ? '✓' : '✗',
    supabase:   SUPABASE_URL       ? '✓' : '✗',
    paystack:   PAYSTACK_SECRET_KEY? '✓' : '✗',
  });
});

/* ════════════════════════════════
   SPA FALLBACK
════════════════════════════════ */
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎬 ReelScript Studio v3`);
  console.log(`   Running  → http://localhost:${PORT}`);
  console.log(`   Anthropic: ${ANTHROPIC_API_KEY   ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Supabase : ${SUPABASE_URL         ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Paystack : ${PAYSTACK_SECRET_KEY  ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`   Security : helmet + rate limiting + input sanitisation\n`);
});
