# ReelScript Studio v2 🎬
### AI Script Generator — Any Industry · 6 Platforms · Session History

---

## What's in this folder

```
reelscript-v2/
├── server.js          ← Your backend (keeps API key safe)
├── package.json       ← Project config
├── .env               ← Your API key goes here (NEVER share this file)
└── public/
    └── index.html     ← The full app
```

---

## Setup in VS Code (do this once)

### 1. Make sure Node.js is installed
Open the VS Code Terminal (Terminal → New Terminal) and type:
```
node --version
```
If you see a version number, you're good. If not, download Node from nodejs.org.

### 2. Install dependencies
In the Terminal, make sure you're in this folder, then run:
```
npm install
```

### 3. Add your API key
Open the `.env` file and replace the placeholder with your real key:
```
ANTHROPIC_API_KEY=sk-ant-YOUR-REAL-KEY-HERE
```
Get your key from: https://console.anthropic.com

### 4. Start the server
```
npm run dev
```
You'll see:
```
🎬 ReelScript Studio v2 running → http://localhost:3000
   API key : ✓ loaded
```

### 5. Open the app
Go to http://localhost:3000 in your browser.

---

## Share with people on the same WiFi

1. In the VS Code Terminal, type:
   - Windows: `ipconfig`  → find "IPv4 Address"
   - Mac: `ifconfig | grep "inet "` → find address starting with 192.168
2. Share: `http://192.168.X.X:3000`
3. Anyone on the same network can use it

---

## To stop the server
Press Ctrl + C in the Terminal

## To restart
```
npm run dev
```

---

## What's new in v2
- ✅ Any industry — free text + smart autocomplete (50+ suggestions)
- ✅ 6 platforms: Instagram, YouTube, TikTok, Facebook, LinkedIn, X/Twitter
- ✅ Session history — last 10 scripts, tap to reload any
- ✅ Fully adaptive — desktop two-column + mobile accordion with tabs
- ✅ Secure backend — API key never exposed to the browser
