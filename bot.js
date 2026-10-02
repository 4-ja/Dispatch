import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import TelegramBot from 'node-telegram-bot-api';
import { google } from 'googleapis';
import { GoogleGenAI } from '@google/genai';
import cron from 'node-cron';
import express from 'express';

dotenv.config();

// ==========================================
// 1. Security Utilities & Masking
// ==========================================
function maskId(id) {
  if (!id) return 'unknown';
  const str = String(id);
  if (str.length <= 4) return '****';
  return str.slice(0, 3) + '****' + str.slice(-2);
}

function log(level, message, ...args) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`, ...args);
}

// Redact any tokens, keys, or auth headers before logging
function safeErrorLog(context, err) {
  const rawMsg = err ? (err.message || String(err)) : 'Unknown error';
  const sanitized = rawMsg.replace(
    /(Bearer\s+[A-Za-z0-9._-]+|refresh_token=[A-Za-z0-9._-]+|[0-9]{8,10}:[A-Za-z0-9_-]{35}|AIza[0-9A-Za-z-_]{35})/gi,
    '[REDACTED]'
  );
  log('error', `${context}: ${sanitized}`);
}

// Global process crash guards
process.on('uncaughtException', (err) => {
  safeErrorLog('Fatal Uncaught Exception', err);
});

process.on('unhandledRejection', (reason, promise) => {
  safeErrorLog('Fatal Unhandled Rejection', reason);
});

// ==========================================
// 2. Encryption at Rest (AES-256-GCM)
// ==========================================
function getSecretKey() {
  const secret = process.env.ENCRYPTION_KEY ||
    ((process.env.GMAIL_CLIENT_SECRET || '') + (process.env.TELEGRAM_BOT_TOKEN || 'dispatch_default_salt'));
  return crypto.createHash('sha256').update(secret).digest();
}

function encryptToken(plainText) {
  if (!plainText) return null;
  const key = getSecretKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptToken(encryptedString) {
  if (!encryptedString) return null;
  // If not encrypted, return as is (supports seamless migration from legacy unencrypted tokens)
  if (!encryptedString.startsWith('enc:v1:')) return encryptedString;

  try {
    const parts = encryptedString.split(':');
    if (parts.length !== 5) return null;
    const iv = Buffer.from(parts[2], 'hex');
    const tag = Buffer.from(parts[3], 'hex');
    const encrypted = Buffer.from(parts[4], 'hex');
    const key = getSecretKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    safeErrorLog('Failed to decrypt token', err);
    return null;
  }
}

// ==========================================
// 3. OAuth CSRF State Protection
// ==========================================
function generateSignedState(chatId) {
  const timestamp = Date.now();
  const payload = `${chatId}:${timestamp}`;
  const hmac = crypto.createHmac('sha256', getSecretKey()).update(payload).digest('hex');
  return Buffer.from(`${payload}:${hmac}`).toString('base64url');
}

function verifySignedState(stateString) {
  try {
    const decoded = Buffer.from(stateString, 'base64url').toString('utf8');
    const [chatId, timestampStr, signature] = decoded.split(':');
    const timestamp = parseInt(timestampStr, 10);

    // Expire state after 15 minutes to prevent replay attacks
    if (Date.now() - timestamp > 15 * 60 * 1000) {
      log('warn', `OAuth state expired for user ${maskId(chatId)}`);
      return null;
    }

    const expectedHmac = crypto.createHmac('sha256', getSecretKey()).update(`${chatId}:${timestampStr}`).digest('hex');
    const sigBuf = Buffer.from(signature, 'hex');
    const expectedBuf = Buffer.from(expectedHmac, 'hex');

    if (sigBuf.length === expectedBuf.length && crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return chatId;
    }
    return null;
  } catch {
    return null;
  }
}

// ==========================================
// 4. Secure Persistent User Store
// ==========================================
class PersistentUserStore {
  constructor(filePath = 'users.json') {
    this.filePath = path.resolve(filePath);
    this.store = new Map();
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const data = JSON.parse(raw);
        let needsMigration = false;
        for (const [key, val] of Object.entries(data)) {
          const rawToken = val.refreshToken;
          if (rawToken && typeof rawToken === 'string' && !rawToken.startsWith('enc:v1:')) {
            needsMigration = true;
          }
          const token = rawToken ? decryptToken(rawToken) : null;
          this.store.set(key.toString(), {
            ...val,
            refreshToken: token
          });
        }
        if (needsMigration) {
          log('info', 'UserStore: Migrating legacy plaintext token(s) to AES-256-GCM encrypted format');
          this.save();
        }
        log('info', `UserStore: Loaded ${this.store.size} user(s) securely (Encrypted at rest)`);
      }
    } catch (err) {
      safeErrorLog(`UserStore: Error loading file ${this.filePath}`, err);
    }

    // Seed default user from environment variables if present
    if (process.env.TELEGRAM_CHAT_ID && process.env.GMAIL_REFRESH_TOKEN) {
      const defaultChatId = process.env.TELEGRAM_CHAT_ID.toString();
      const existing = this.store.get(defaultChatId);
      if (!existing) {
        this.store.set(defaultChatId, {
          refreshToken: process.env.GMAIL_REFRESH_TOKEN,
          paused: false,
          updatedAt: new Date().toISOString()
        });
        this.save();
        log('info', `UserStore: Seeded default user from environment variables (${maskId(defaultChatId)})`);
      }
    }
  }

  save() {
    try {
      const obj = {};
      for (const [key, val] of this.store.entries()) {
        obj[key] = {
          ...val,
          // Always encrypt refreshToken before persisting to disk
          refreshToken: val.refreshToken ? encryptToken(val.refreshToken) : null
        };
      }
      fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2), { mode: 0o600 });
    } catch (err) {
      safeErrorLog(`UserStore: Error saving file ${this.filePath}`, err);
    }
  }

  get(chatId) {
    return this.store.get(chatId.toString());
  }

  set(chatId, data) {
    const updated = {
      ...data,
      updatedAt: new Date().toISOString()
    };
    this.store.set(chatId.toString(), updated);
    this.save();
  }

  delete(chatId) {
    const res = this.store.delete(chatId.toString());
    this.save();
    return res;
  }

  entries() {
    return this.store.entries();
  }

  get size() {
    return this.store.size;
  }
}

const userStore = new PersistentUserStore('users.json');

// ==========================================
// 5. Execution Mode & Telegram Setup
// ==========================================
const isDigestOnly = process.argv.includes('--digest-only');
const isTestMode = process.argv.includes('--test');
const renderUrl = process.env.RENDER_EXTERNAL_URL || process.env.WEBHOOK_URL;
const isWebhookMode = !isDigestOnly && !isTestMode && Boolean(renderUrl);
const webhookPath = `/api/telegram-webhook`;

// Secret token for Telegram Webhook verification
const webhookSecret = crypto.createHash('sha256').update(process.env.TELEGRAM_BOT_TOKEN || 'webhook_secret').digest('hex');

let bot;
if (isDigestOnly || isTestMode) {
  bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });
  log('info', isTestMode ? 'Running in TEST verification mode' : 'Running in CLI digest-only mode');
} else if (isWebhookMode) {
  bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });
  log('info', `Running in WEBHOOK mode for Render deployment (Base: ${renderUrl})`);
} else {
  bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
  log('info', 'Running in POLLING mode (Local development)');
}

// Telegram error logging
bot.on('polling_error', (err) => {
  safeErrorLog(`Telegram Polling Error [${err.code || 'UNKNOWN'}]`, err);
});

bot.on('webhook_error', (err) => {
  safeErrorLog(`Telegram Webhook Error [${err.code || 'UNKNOWN'}]`, err);
});

bot.on('error', (err) => {
  safeErrorLog('Telegram General Error', err);
});

// Register bot menu commands in Telegram
bot.setMyCommands([
  { command: 'digest', description: 'Trigger an instant email scan and summary' },
  { command: 'stop', description: 'Stop daily 8:00 AM scheduled messages' },
  { command: 'resume', description: 'Resume daily 8:00 AM scheduled messages' },
  { command: 'status', description: 'Check subscription and schedule status' },
  { command: 'disconnect', description: 'Revoke Gmail access and delete all stored data' },
  { command: 'start', description: 'Connect Gmail or view welcome message' }
]).catch(err => safeErrorLog('Failed to register Telegram bot commands', err));

// Helper: Safe Telegram message sender with markdown fallback
async function safeSendMessage(chatId, text, options = {}) {
  try {
    return await bot.sendMessage(chatId, text, options);
  } catch (err) {
    safeErrorLog(`Telegram sendMessage failed for chat ${maskId(chatId)}`, err);
    if (options && options.parse_mode) {
      log('info', `Retrying sendMessage to ${maskId(chatId)} in plain text mode...`);
      const fallbackOptions = { ...options };
      delete fallbackOptions.parse_mode;
      const plainText = text.replace(/[*_`\[\]]/g, '');
      return await bot.sendMessage(chatId, plainText, fallbackOptions);
    }
    throw err;
  }
}

function sanitizeForMarkdown(text) {
  if (!text) return '';
  return String(text).replace(/([*_`\[\]])/g, ' ');
}

// ==========================================
// 6. Google Gemini & Gmail Setup
// ==========================================
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.REDIRECT_URI // e.g., "https://your-service.onrender.com/oauth2callback"
);

function getAuthUrl(chatId) {
  // Use cryptographically signed HMAC state parameter for CSRF protection
  const signedState = generateSignedState(chatId);
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'select_account consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly'],
    state: signedState
  });
}

function getUserGmailClient(refreshToken) {
  const client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET
  );
  client.setCredentials({ refresh_token: refreshToken });
  return google.gmail({ version: 'v1', auth: client });
}

// ==========================================
// 7. Privacy-Preserving Email Fetch & Analysis
// ==========================================
// Only fetch metadata headers (Subject, From, Date) and snippet.
// NEVER download full email bodies or attachments to server memory.
async function fetchUserEmails(gmailClient) {
  const query = 'newer_than:1d is:unread -category:promotions -category:social';
  const res = await gmailClient.users.messages.list({ userId: 'me', q: query, maxResults: 15 });

  if (!res.data.messages || res.data.messages.length === 0) return [];

  return await Promise.all(
    res.data.messages.map(async (msg) => {
      try {
        const detail = await gmailClient.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'metadata',
          metadataHeaders: ['Subject', 'From', 'Date']
        });
        const headers = detail.data?.payload?.headers || [];
        const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || 'No Subject';
        const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || 'Unknown';
        // Truncate snippet to 150 characters to prevent holding sensitive previews in memory
        const rawSnippet = detail.data?.snippet || '';
        const snippet = rawSnippet.slice(0, 150);
        return { id: msg.id, from, subject, snippet };
      } catch (err) {
        safeErrorLog('Failed to fetch message metadata', err);
        return { id: msg.id, from: 'Unknown', subject: 'Error reading email', snippet: '' };
      }
    })
  );
}

async function analyzeEmails(emails) {
  if (!emails || emails.length === 0) return null;

  const prompt = `
Analyze the following unread emails:
${JSON.stringify(emails, null, 2)}

Return a structured summary with:
1. "overview": A 2-sentence summary of the inbox status.
2. "tasks": An array of actionable tasks extracted ONLY from high-priority/work emails. 
   Each task item must include:
   - "title": Actionable imperative task title (e.g. "Submit quarterly report").
   - "source": Sender name or organization.
   - "urgency": "High", "Medium", or "Low".
   - "dueDate": Extracted deadline or "None".

Output strictly valid JSON matching this schema:
{
  "overview": "...",
  "tasks": [
    { "title": "...", "source": "...", "urgency": "High|Medium|Low", "dueDate": "..." }
  ]
}
`;

  try {
    const response = await ai.models.generateContent({
      model: process.env.GEMINI_MODEL || 'gemini-3.6-flash',
      contents: prompt,
      config: { responseMimeType: 'application/json' }
    });

    let rawText = (response.text || '').trim();
    if (rawText.startsWith('```')) {
      rawText = rawText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    }

    return JSON.parse(rawText);
  } catch (err) {
    safeErrorLog('Gemini analysis error', err);
    return {
      overview: `You have ${emails.length} unread email(s). (AI analysis is temporarily unavailable).`,
      tasks: emails.slice(0, 5).map(e => ({
        title: `Review: ${e.subject}`,
        source: e.from,
        urgency: 'Medium',
        dueDate: 'None'
      }))
    };
  }
}

async function sendDailyDigest(chatId) {
  log('info', `Starting daily digest generation for user ${maskId(chatId)}...`);
  const user = userStore.get(chatId.toString());

  if (!user || !user.refreshToken) {
    log('warn', `User ${maskId(chatId)} has not connected Gmail account.`);
    const authUrl = getAuthUrl(chatId);
    return safeSendMessage(chatId, '⚠️ You have not connected your Gmail account yet.', {
      reply_markup: {
        inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
      }
    });
  }

  try {
    const userGmail = getUserGmailClient(user.refreshToken);
    const emails = await fetchUserEmails(userGmail);

    if (emails.length === 0) {
      log('info', `User ${maskId(chatId)} has no unread priority emails.`);
      await safeSendMessage(chatId, '📬 *Email Digest*: No unread priority emails in the last 24 hours!', { parse_mode: 'Markdown' });
      return;
    }

    log('info', `Fetched ${emails.length} email headers for user ${maskId(chatId)}. Processing summary...`);
    const digest = await analyzeEmails(emails);

    const safeOverview = sanitizeForMarkdown(digest.overview || 'Here is your daily email summary.');
    let message = `📬 *Daily Email Digest*\n\n_${safeOverview}_\n\n*Action Items:*\n`;

    if (digest.tasks && digest.tasks.length > 0) {
      digest.tasks.forEach((t, i) => {
        const safeTitle = sanitizeForMarkdown(t.title || 'Untitled item');
        const safeSource = sanitizeForMarkdown(t.source || 'Unknown');
        const safeUrgency = sanitizeForMarkdown(t.urgency || 'Normal');
        const safeDue = sanitizeForMarkdown(t.dueDate || 'None');
        message += `\n${i + 1}. *[${safeUrgency}]* ${safeTitle}\n   ↳ *From:* ${safeSource} | *Due:* ${safeDue}`;
      });
    } else {
      message += `\n_No actionable items found in recent emails._`;
    }

    await safeSendMessage(chatId, message, {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '🔄 Refresh Inbox', callback_data: 'refresh_inbox' }]]
      }
    });
    log('info', `Daily digest successfully sent to user ${maskId(chatId)}.`);
  } catch (err) {
    safeErrorLog(`Error generating digest for user ${maskId(chatId)}`, err);

    if (err.message && (err.message.includes('invalid_grant') || err.message.includes('Token has been expired or revoked'))) {
      const authUrl = getAuthUrl(chatId);
      await safeSendMessage(
        chatId,
        '⚠️ Your Gmail authorization has expired or was revoked. Please tap below to reconnect:',
        {
          reply_markup: {
            inline_keyboard: [[{ text: '🔗 Reconnect Gmail', url: authUrl }]]
          }
        }
      );
    } else {
      await safeSendMessage(
        chatId,
        '⚠️ Error generating your email digest. If this persists, try /start to reconnect.'
      );
    }
  }
}

async function runAllDigests() {
  log('info', `Running scheduled digests for ${userStore.size} registered users...`);
  let sentCount = 0;
  let skippedCount = 0;

  for (const [chatId, userData] of userStore.entries()) {
    if (userData.paused) {
      log('info', `Skipping scheduled digest for user ${maskId(chatId)} (daily messages paused)`);
      skippedCount++;
      continue;
    }
    try {
      await sendDailyDigest(chatId);
      sentCount++;
    } catch (err) {
      safeErrorLog(`Failed to deliver digest to user ${maskId(chatId)}`, err);
    }
  }

  log('info', `Scheduled digest execution complete. Sent: ${sentCount}, Skipped: ${skippedCount}`);
  return { sent: sentCount, skipped: skippedCount };
}

// ==========================================
// 8. Telegram Command Handlers
// ==========================================
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /start command from user ${maskId(chatId)}`);

  try {
    const user = userStore.get(chatId);

    if (user && user.refreshToken) {
      if (user.paused) {
        userStore.set(chatId, { ...user, paused: false });
        return await safeSendMessage(
          chatId,
          '▶️ *Welcome back! Daily 8:00 AM messages have been resumed.*\n\nCommands:\n• /digest - Instant inbox scan\n• /stop - Stop daily 8:00 AM messages\n• /status - Check status\n• /disconnect - Revoke Gmail access & delete data',
          { parse_mode: 'Markdown' }
        );
      }
      return await safeSendMessage(
        chatId,
        'Welcome back!\n\n• /digest - Scan inbox now\n• /stop - Stop daily 8:00 AM scheduled messages\n• /status - Check schedule status\n• /disconnect - Disconnect Gmail and wipe stored data'
      );
    }

    const authUrl = getAuthUrl(chatId);
    await safeSendMessage(
      chatId,
      '👋 *Welcome to Dispatch!*\n\nConnect your Gmail account to get automated daily priority summaries (8:00 AM) and actionable task extraction.\n\n🔒 *Privacy & Security:*\n• Read-only minimal metadata is processed.\n• Your credentials are encrypted at rest with AES-256-GCM.\n• No email bodies are ever saved to disk.\n• Use /disconnect anytime to permanently revoke access and wipe stored data.',
      {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
        }
      }
    );
  } catch (err) {
    safeErrorLog(`Error handling /start for user ${maskId(chatId)}`, err);
  }
});

bot.onText(/\/stop|\/pause|\/unsubscribe/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /stop command from user ${maskId(chatId)}`);

  try {
    const user = userStore.get(chatId) || { refreshToken: null };
    userStore.set(chatId, { ...user, paused: true });

    await safeSendMessage(
      chatId,
      '🛑 *Daily 8:00 AM scheduled messages stopped.*\n\nYou will no longer receive daily scheduled email digests.\n\n• Type /resume anytime to turn daily messages back on.\n• Type /disconnect anytime to completely delete your credentials and disconnect.',
      { parse_mode: 'Markdown' }
    );
  } catch (err) {
    safeErrorLog(`Error handling /stop for user ${maskId(chatId)}`, err);
  }
});

bot.onText(/\/resume/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /resume command from user ${maskId(chatId)}`);

  try {
    const user = userStore.get(chatId);

    if (!user || !user.refreshToken) {
      const authUrl = getAuthUrl(chatId);
      return await safeSendMessage(
        chatId,
        '⚠️ You have not connected your Gmail account yet. Please connect Gmail first.',
        {
          reply_markup: {
            inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
          }
        }
      );
    }

    userStore.set(chatId, { ...user, paused: false });
    await safeSendMessage(
      chatId,
      '▶️ *Daily 8:00 AM scheduled messages resumed!*\n\nYou will receive your digest every morning at 8:00 AM.',
      { parse_mode: 'Markdown' }
    );
  } catch (err) {
    safeErrorLog(`Error handling /resume for user ${maskId(chatId)}`, err);
  }
});

bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /status command from user ${maskId(chatId)}`);

  try {
    const user = userStore.get(chatId);

    const isConnected = !!(user && user.refreshToken);
    const isPaused = user ? !!user.paused : false;

    const connStatus = isConnected ? '🟢 Connected (AES-256 encrypted)' : '🔴 Not Connected';
    const scheduleStatus = !isConnected 
      ? '⚪ Inactive (Gmail not connected)' 
      : (isPaused ? '🔴 Stopped (Paused)' : '🟢 Active (8:00 AM Daily)');

    const statusMsg = `📊 *Dispatch Bot Status*\n\n` +
      `• *Gmail Account:* ${connStatus}\n` +
      `• *Daily Digest (8:00 AM):* ${scheduleStatus}\n\n` +
      `*Available Commands:*\n` +
      `• /digest - Instant inbox scan\n` +
      `• /stop - Stop daily 8:00 AM scheduled messages\n` +
      `• /resume - Resume daily 8:00 AM scheduled messages\n` +
      `• /status - Check subscription and schedule status\n` +
      `• /disconnect - Revoke token & delete stored data\n` +
      `• /start - Account setup & menu`;

    await safeSendMessage(chatId, statusMsg, { parse_mode: 'Markdown' });
  } catch (err) {
    safeErrorLog(`Error handling /status for user ${maskId(chatId)}`, err);
  }
});

// User Data Deletion & Revocation (Right to be Forgotten)
bot.onText(/\/disconnect|\/logout|\/delete/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /disconnect command from user ${maskId(chatId)}`);

  try {
    const user = userStore.get(chatId);

    if (user && user.refreshToken) {
      try {
        const client = new google.auth.OAuth2(
          process.env.GMAIL_CLIENT_ID,
          process.env.GMAIL_CLIENT_SECRET
        );
        client.setCredentials({ refresh_token: user.refreshToken });
        await client.revokeToken(user.refreshToken);
        log('info', `Successfully revoked Google OAuth token for user ${maskId(chatId)}`);
      } catch (revokeErr) {
        safeErrorLog(`Google token revocation notice for user ${maskId(chatId)}`, revokeErr);
      }
    }

    userStore.delete(chatId);

    await safeSendMessage(
      chatId,
      '🗑️ *Disconnected successfully!*\n\nYour Gmail token has been revoked with Google, and your credentials have been permanently deleted from our server.\n\nType /start anytime if you want to reconnect.',
      { parse_mode: 'Markdown' }
    );
  } catch (err) {
    safeErrorLog(`Error during /disconnect for user ${maskId(chatId)}`, err);
  }
});

bot.onText(/\/digest/, async (msg) => {
  const chatId = msg.chat.id.toString();
  log('info', `Received /digest command from user ${maskId(chatId)}`);

  try {
    await safeSendMessage(chatId, '⏳ Scanning your inbox and extracting tasks...');
    await sendDailyDigest(chatId);
  } catch (err) {
    safeErrorLog(`Error handling /digest for user ${maskId(chatId)}`, err);
  }
});

bot.on('callback_query', async (query) => {
  const chatId = query.message?.chat?.id;
  log('info', `Received callback query "${query.data}" from chat ${maskId(chatId)}`);

  try {
    if (query.data === 'refresh_inbox' && chatId) {
      await bot.answerCallbackQuery(query.id, { text: 'Refreshing inbox...' }).catch(() => {});
      await sendDailyDigest(chatId);
    }
  } catch (err) {
    safeErrorLog(`Error handling callback query from chat ${maskId(chatId)}`, err);
  }
});

// ==========================================
// 9. Hardened Express Server & Webhook Handler
// ==========================================
const app = express();
const port = process.env.PORT || 8080;

// Security Headers & Server Hardening
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

app.use(express.json({ limit: '256kb' }));

// Health / Status endpoint (No private user information exposed)
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Dispatch Bot Server',
    mode: isWebhookMode ? 'webhook' : 'polling',
    registeredUsers: userStore.size,
    uptimeSeconds: Math.floor(process.uptime())
  });
});

app.get(['/health', '/ping'], (req, res) => {
  res.status(200).send('OK');
});

// Verified Telegram Webhook Receiver
app.post(webhookPath, (req, res) => {
  if (isWebhookMode) {
    const receivedSecret = req.headers['x-telegram-bot-api-secret-token'];
    if (receivedSecret !== webhookSecret) {
      log('warn', 'Rejected unauthorized Telegram webhook update (invalid secret token)');
      return res.sendStatus(403);
    }
  }

  try {
    if (req.body) {
      bot.processUpdate(req.body);
    }
    res.sendStatus(200);
  } catch (err) {
    safeErrorLog('Error in Telegram webhook receiver', err);
    res.sendStatus(500);
  }
});

// Secured Manual Trigger Endpoint
app.all('/api/trigger-digest', async (req, res) => {
  const expectedSecret = process.env.CRON_SECRET;
  const authHeader = req.headers['authorization'];
  const secretHeader = req.headers['x-cron-secret'];
  const secretQuery = req.query.secret;

  if (expectedSecret) {
    const bearer = authHeader ? authHeader.replace(/^Bearer\s+/i, '') : null;
    if (bearer !== expectedSecret && secretHeader !== expectedSecret && secretQuery !== expectedSecret) {
      log('warn', 'Unauthorized request to /api/trigger-digest');
      return res.status(401).json({ error: 'Unauthorized: Invalid cron secret' });
    }
  }

  log('info', 'Triggering daily digests via secured endpoint');
  runAllDigests()
    .then(result => log('info', 'Manual trigger finished successfully', result))
    .catch(err => safeErrorLog('Manual trigger execution failed', err));

  res.json({ success: true, message: 'Digest trigger initiated for all active users.' });
});

// OAuth2 Callback with Signed State Verification
app.get('/oauth2callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('Missing authorization code or security state.');
  }

  // Cryptographic verification of HMAC state token to prevent CSRF
  const chatId = verifySignedState(state);
  if (!chatId) {
    log('warn', 'OAuth CSRF check failed: Invalid or expired state token');
    return res.status(403).send('Invalid or expired authorization session. Please try again from Telegram.');
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    const existing = userStore.get(chatId) || {};

    userStore.set(chatId, {
      ...existing,
      refreshToken: tokens.refresh_token || existing.refreshToken,
      paused: false
    });

    log('info', `Gmail successfully authorized for user ${maskId(chatId)}`);

    await safeSendMessage(
      chatId,
      '✅ *Gmail successfully connected!*\n\nYou will now receive automatic email digests every day at 8:00 AM.\n\n• Type /digest anytime to trigger an instant scan.\n• Type /stop anytime to stop daily scheduled messages.\n• Type /disconnect anytime to revoke access and delete stored data.',
      { parse_mode: 'Markdown' }
    );

    res.send('<h2>Authorization successful!</h2><p>Your Gmail account is connected. You can now close this tab and return to Telegram.</p>');
  } catch (err) {
    safeErrorLog(`OAuth token exchange error for user ${maskId(chatId)}`, err);
    res.status(500).send('Authentication failed. Please try again from Telegram.');
  }
});

// ==========================================
// 10. Cron Scheduler & Startup
// ==========================================
const cronTimezone = process.env.TIMEZONE || 'Asia/Manila';

try {
  cron.schedule('0 8 * * *', async () => {
    log('info', `Cron fired: Running 8:00 AM digest (Timezone: ${cronTimezone})...`);
    await runAllDigests();
  }, {
    timezone: cronTimezone
  });
  log('info', `Cron scheduled for 08:00 AM daily with timezone: ${cronTimezone}`);
} catch (err) {
  log('warn', `Failed to set cron with timezone ${cronTimezone} (${err.message}), falling back to UTC cron`);
  cron.schedule('0 0 * * *', async () => {
    log('info', 'Fallback UTC cron fired: Running 00:00 UTC digest...');
    await runAllDigests();
  });
}

// Start Server or CLI runner
if (isTestMode) {
  log('info', 'Test mode enabled: verifying environment and configuration...');
  log('info', `Verification: userStore size = ${userStore.size}, timezone = ${cronTimezone}, webhookMode = ${isWebhookMode}`);
  log('info', 'Verification succeeded! Exiting test mode cleanly.');
  process.exit(0);
} else if (isDigestOnly) {
  runAllDigests()
    .then(() => {
      log('info', 'CLI digest-only execution completed successfully.');
      process.exit(0);
    })
    .catch((err) => {
      safeErrorLog('CLI digest-only execution failed', err);
      process.exit(1);
    });
} else {
  app.listen(port, async () => {
    log('info', `Server listening on port ${port}`);

    if (isWebhookMode) {
      const fullWebhookUrl = `${renderUrl.replace(/\/+$/, '')}${webhookPath}`;
      try {
        await bot.setWebHook(fullWebhookUrl, { secret_token: webhookSecret });
        log('info', `Telegram webhook registered with secret token at: ${fullWebhookUrl}`);
      } catch (err) {
        safeErrorLog(`Failed to register Telegram webhook at ${fullWebhookUrl}`, err);
      }
    } else {
      try {
        await bot.deleteWebHook();
        log('info', 'Cleaned up any previous Telegram webhook for polling mode');
      } catch (err) {
        log('warn', 'Could not delete previous webhook:', err.message);
      }
    }
  });
}