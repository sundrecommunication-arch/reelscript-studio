import express from 'express';
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 3000;

// ── Load API key ──
function loadApiKey() {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  const envPath = path.join(__dirname, '.env');
  if (!existsSync(envPath)) return null;
  const line = readFileSync(envPath, 'utf8')
    .split('\n')
    .find(l => l.startsWith('ANTHROPIC_API_KEY='));
  return line ? line.split('=')[1]?.trim() : null;
}
const API_KEY = loadApiKey();

// ── Simple in-memory rate limiting ──
const ipHits = new Map();
function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const max = 20;
  const rec = ipHits.get(ip) || { count: 0, start: now };
  if (now - rec.start > windowMs) { rec.count = 1; rec.start = now; }
  else rec.count++;
  ipHits.set(ip, rec);
  if (rec.count > max) {
    return res.status(429).json({ error: 'Too many requests. Please wait an hour and try again.' });
  }
  next();
}

// ── Anonymous usage tracking (in-memory) ──
const anonUsage = new Map();
const ANON_LIMIT = 3;

function checkAnonUsage(fp) {
  const used = anonUsage.get(fp) || 0;
  if (used >= ANON_LIMIT) {
    return { allowed: false, used, limit: ANON_LIMIT };
  }
  anonUsage.set(fp, used + 1);
  return { allowed: true, used: used + 1, limit: ANON_LIMIT };
}

app.use(express.json({ limit: '10kb' }));

// ── Security headers ──
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── Serve frontend ──
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h', etag: true
}));

// ── Sanitise input ──
function sanitise(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').replace(/[<>'"`;]/g, '').trim().slice(0, 500);
}

// ── Generate endpoint ──
app.post('/api/generate', rateLimit, async (req, res) => {
  if (!API_KEY) {
    return res.status(500).json({ error: 'API key not configured. Add ANTHROPIC_API_KEY to Render environment variables.' });
  }

  const { systemPrompt, userPrompt, fingerprint } = req.body;

  const cleanSystem = sanitise(systemPrompt);
  const cleanUser   = sanitise(userPrompt);

  if (!cleanSystem || !cleanUser) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  // Check anonymous usage
  const fp = sanitise(fingerprint || 'unknown').slice(0, 64);
  const usage = checkAnonUsage(fp);
  if (!usage.allowed) {
    return res.status(403).json({
      error: `You have used all ${ANON_LIMIT} free scripts. Sign up to get 10 scripts per month.`,
      showSignup: true,
      usage,
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
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
      return res.status(response.status).json({
        error: data.error?.message || `API error (${response.status})`
      });
    }

    const text = data.content?.map(b => b.text || '').join('') || '';
    res.json({ text, usage });

  } catch (err) {
    console.error('Generate error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── Health check ──
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '3.0.0',
    apiKey: API_KEY ? '✓ loaded' : '✗ missing',
  });
});

// ── SPA fallback ──
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎬 ReelScript Studio v3 running → http://localhost:${PORT}`);
  console.log(`   API key : ${API_KEY ? '✓ loaded' : '✗ MISSING — add ANTHROPIC_API_KEY to Render'}\n`);
});
