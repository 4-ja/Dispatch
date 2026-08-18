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

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

// In-memory user store: Map<chatId, { refreshToken }>.
// NOTE: For persistent production storage, swap this with MongoDB, PostgreSQL, or SQLite.
const userStore = new Map();

// 2. OAuth2 Base Client Setup
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.REDIRECT_URI // e.g., "https://your-service.onrender.com/oauth2callback"
);

function getAuthUrl(chatId) {
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly'],
    state: chatId.toString() // Passed through OAuth so we know which Telegram user to bind
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
    userStore.set(chatId.toString(), { refreshToken: tokens.refresh_token });

    await bot.sendMessage(
      chatId,
      '✅ *Gmail successfully connected!*\n\nYou will now receive automatic email digests every day at 8:00 AM. You can also type /digest anytime to trigger an instant scan.',
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
  if (userStore.has(chatId)) {
    return bot.sendMessage(chatId, 'Welcome back! Type /digest to scan your inbox or wait for your daily 8:00 AM summary.');
  }

  const authUrl = getAuthUrl(chatId);
  await bot.sendMessage(
    chatId,
    '👋 *Welcome to Dispatch!*\n\nConnect your Gmail account to get automated daily priority summaries and actionable task extraction.',
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '🔗 Connect Gmail', url: authUrl }]]
      }
    }
  );
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
  console.log(`Running scheduled digests for ${userStore.size} active users...`);
  for (const [chatId] of userStore.entries()) {
    await sendDailyDigest(chatId);
  }
});

console.log('Bot is running successfully with multi-user support...');