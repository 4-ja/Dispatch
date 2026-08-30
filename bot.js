import dotenv from 'dotenv';
import TelegramBot from 'node-telegram-bot-api';
import { google } from 'googleapis';
import { GoogleGenAI } from '@google/genai';
import cron from 'node-cron';
import express from 'express';

dotenv.config();

// 1. Initialize Telegram Bot & Gemini
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, {
  polling: true
});

// Register bot menu commands in Telegram
bot.setMyCommands([
  { command: 'digest', description: 'Trigger an instant email scan and summary' },
  { command: 'stop', description: 'Stop daily 8:00 AM scheduled messages' },
  { command: 'resume', description: 'Resume daily 8:00 AM scheduled messages' },
  { command: 'status', description: 'Check subscription and schedule status' },
  { command: 'start', description: 'Connect Gmail or view welcome message' }
]).catch(err => console.error('Failed to register Telegram bot commands:', err));

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

// In-memory user store: Map<chatId, { refreshToken: string|null, paused: boolean }>.
// NOTE: For persistent production storage, swap this with MongoDB, PostgreSQL, or SQLite.
const userStore = new Map();

// Initialize user store with env variables if provided
if (process.env.TELEGRAM_CHAT_ID && process.env.GMAIL_REFRESH_TOKEN) {
  userStore.set(process.env.TELEGRAM_CHAT_ID.toString(), {
    refreshToken: process.env.GMAIL_REFRESH_TOKEN,
    paused: false
  });
}

// 2. OAuth2 Base Client Setup
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.REDIRECT_URI // e.g., "https://your-service.onrender.com/oauth2callback"
);

function getAuthUrl(chatId) {
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'select_account consent', // Forces account selector + consent screen
    scope: ['https://www.googleapis.com/auth/gmail.readonly'],
    state: chatId.toString()
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

// 3. Express Web Server (Health Checks + OAuth Callback)
const app = express();
const port = process.env.PORT || 8080;

app.get('/', (req, res) => {
  res.send('Dispatch Bot Server is running!');
});

app.get('/oauth2callback', async (req, res) => {
  const { code, state: chatId } = req.query;

  if (!code || !chatId) {
    return res.status(400).send('Missing authorization code or user state.');
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    const existing = userStore.get(chatId.toString()) || {};
    userStore.set(chatId.toString(), {
      ...existing,
      refreshToken: tokens.refresh_token,
      paused: false
    });

    await bot.sendMessage(
      chatId,
      '✅ *Gmail successfully connected!*\n\nYou will now receive automatic email digests every day at 8:00 AM.\n\n• Type /digest anytime to trigger an instant scan.\n• Type /stop anytime to stop daily scheduled messages.',
      { parse_mode: 'Markdown' }
    );

    res.send('<h2>Authorization successful!</h2><p>You can now close this tab and return to Telegram.</p>');
  } catch (err) {
    console.error('OAuth token exchange error:', err);
    res.status(500).send('Authentication failed. Please try again from Telegram.');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

// 4. Gmail Fetching & Task Analysis
async function fetchUserEmails(gmailClient) {
  const query = 'newer_than:1d is:unread -category:promotions -category:social';
  const res = await gmailClient.users.messages.list({ userId: 'me', q: query, maxResults: 15 });

  if (!res.data.messages || res.data.messages.length === 0) return [];

  return await Promise.all(
    res.data.messages.map(async (msg) => {
      const detail = await gmailClient.users.messages.get({ userId: 'me', id: msg.id });
      const headers = detail.data.payload.headers;
      const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
      const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
      return { id: msg.id, from, subject, snippet: detail.data.snippet };
    })
  );
}

async function analyzeEmails(emails) {
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

Output strictly valid JSON matching this schema.
`;

  const response = await ai.models.generateContent({
    model: 'gemini-3.6-flash',
    contents: prompt,
    config: { responseMimeType: 'application/json' }
  });

  return JSON.parse(response.text);
}

async function sendDailyDigest(chatId) {
  const user = userStore.get(chatId.toString());

  if (!user || !user.refreshToken) {
    const authUrl = getAuthUrl(chatId);
    return bot.sendMessage(chatId, '⚠️ You have not connected your Gmail account yet.', {
      reply_markup: {
        inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
      }
    });
  }

  try {
    const userGmail = getUserGmailClient(user.refreshToken);
    const emails = await fetchUserEmails(userGmail);

    if (emails.length === 0) {
      await bot.sendMessage(chatId, '📬 *Email Digest*: No unread priority emails in the last 24 hours!', { parse_mode: 'Markdown' });
      return;
    }

    const digest = await analyzeEmails(emails);
    let message = `📬 *Daily Email Digest*\n\n_${digest.overview}_\n\n*Action Items:*\n`;

    if (digest.tasks && digest.tasks.length > 0) {
      digest.tasks.forEach((t, i) => {
        message += `\n${i + 1}. *[${t.urgency}]* ${t.title}\n   ↳ *From:* ${t.source} | *Due:* ${t.dueDate}`;
      });
    } else {
      message += `\n_No actionable items found in recent emails._`;
    }

    await bot.sendMessage(chatId, message, {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '🔄 Refresh Inbox', callback_data: 'refresh_inbox' }]]
      }
    });
  } catch (err) {
    console.error(`Error generating digest for user ${chatId}:`, err);
    await bot.sendMessage(chatId, '⚠️ Error generating your email digest. Your token may have expired. Try /start to reconnect.');
  }
}

// 5. Telegram Handlers
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id.toString();
  const user = userStore.get(chatId);

  if (user && user.refreshToken) {
    if (user.paused) {
      user.paused = false;
      return bot.sendMessage(
        chatId,
        '▶️ *Welcome back! Daily 8:00 AM messages have been resumed.*\n\nCommands:\n• /digest - Instant inbox scan\n• /stop - Stop daily 8:00 AM messages\n• /status - Check status',
        { parse_mode: 'Markdown' }
      );
    }
    return bot.sendMessage(
      chatId,
      'Welcome back!\n\n• /digest - Scan inbox now\n• /stop - Stop daily 8:00 AM scheduled messages\n• /status - Check schedule status'
    );
  }

  const authUrl = getAuthUrl(chatId);
  await bot.sendMessage(
    chatId,
    '👋 *Welcome to Dispatch!*\n\nConnect your Gmail account to get automated daily priority summaries (8:00 AM) and actionable task extraction.\n\nYou can use /stop anytime to disable daily scheduled messages.',
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
      }
    }
  );
});

bot.onText(/\/stop|\/pause|\/unsubscribe/, async (msg) => {
  const chatId = msg.chat.id.toString();
  const user = userStore.get(chatId);

  if (!user) {
    userStore.set(chatId, { refreshToken: null, paused: true });
  } else {
    user.paused = true;
  }

  await bot.sendMessage(
    chatId,
    '🛑 *Daily 8:00 AM scheduled messages stopped.*\n\nYou will no longer receive daily scheduled email digests.\n\n• Type /resume or /start anytime to turn daily messages back on.\n• Type /digest to manually request an instant email scan.',
    { parse_mode: 'Markdown' }
  );
});

bot.onText(/\/resume/, async (msg) => {
  const chatId = msg.chat.id.toString();
  const user = userStore.get(chatId);

  if (!user || !user.refreshToken) {
    const authUrl = getAuthUrl(chatId);
    return bot.sendMessage(
      chatId,
      '⚠️ You have not connected your Gmail account yet. Please connect Gmail first.',
      {
        reply_markup: {
          inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
        }
      }
    );
  }

  user.paused = false;
  await bot.sendMessage(
    chatId,
    '▶️ *Daily 8:00 AM scheduled messages resumed!*\n\nYou will receive your digest every morning at 8:00 AM. Type /stop anytime to pause scheduled messages.',
    { parse_mode: 'Markdown' }
  );
});

bot.onText(/\/status/, async (msg) => {
  const chatId = msg.chat.id.toString();
  const user = userStore.get(chatId);

  const isConnected = !!(user && user.refreshToken);
  const isPaused = user ? !!user.paused : false;

  const connStatus = isConnected ? '🟢 Connected' : '🔴 Not Connected';
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
    `• /start - Account setup & menu`;

  await bot.sendMessage(chatId, statusMsg, { parse_mode: 'Markdown' });
});

bot.onText(/\/digest/, async (msg) => {
  const chatId = msg.chat.id.toString();
  await bot.sendMessage(chatId, '⏳ Scanning your inbox and extracting tasks...');
  await sendDailyDigest(chatId);
});

bot.on('callback_query', async (query) => {
  if (query.data === 'refresh_inbox') {
    await bot.answerCallbackQuery(query.id, { text: 'Refreshing inbox...' });
    await sendDailyDigest(query.message.chat.id);
  }
});

// 6. Scheduled Multi-User Cron at 8:00 AM daily
cron.schedule('0 8 * * *', async () => {
  console.log(`Running scheduled digests for ${userStore.size} registered users...`);
  for (const [chatId, userData] of userStore.entries()) {
    if (userData.paused) {
      console.log(`Skipping scheduled digest for user ${chatId} (daily messages paused)`);
      continue;
    }
    await sendDailyDigest(chatId);
  }
});

console.log('Bot is running successfully with multi-user support...');