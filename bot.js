import 'dotenv/config';
import { google } from 'googleapis';
import { GoogleGenAI } from '@google/genai';
import TelegramBot from 'node-telegram-bot-api';
import cron from 'node-cron';

const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// 1. Authenticate Gmail
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET
);
oauth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

// 2. Fetch Unread / Last 24 Hours Emails
async function fetchRecentEmails() {
  const query = 'newer_than:1d is:unread -category:promotions -category:social';
  const res = await gmail.users.messages.list({ userId: 'me', q: query, maxResults: 15 });
  
  if (!res.data.messages || res.data.messages.length === 0) return [];

  const emails = await Promise.all(
    res.data.messages.map(async (msg) => {
      const detail = await gmail.users.messages.get({ userId: 'me', id: msg.id });
      const headers = detail.data.payload.headers;
      const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
      const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
      const snippet = detail.data.snippet;
      return { id: msg.id, from, subject, snippet };
    })
  );

  return emails;
}

// 3. Process with AI: Filter Priority & Extract Actionable Tasks
async function analyzeEmails(emails) {
  if (emails.length === 0) return null;

  const prompt = `
Analyze the following batch of unread emails:
${JSON.stringify(emails, null, 2)}

Return a structured summary with:
1. "overview": A 2-sentence summary of the inbox status.
2. "tasks": An array of actionable tasks extracted ONLY from high-priority/work emails. 
   Each task item must include:
   - "title": Actionable imperative task title (e.g. "Review Q3 deck for Alex").
   - "source": Sender name or organization.
   - "urgency": "High", "Medium", or "Low".
   - "dueDate": Extracted deadline or "None".

Output strictly valid JSON matching this schema.
`;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: { responseMimeType: 'application/json' }
  });

  return JSON.parse(response.text);
}

// 4. Send Digest to Telegram
async function sendDailyDigest() {
  try {
    const emails = await fetchRecentEmails();
    if (emails.length === 0) {
      await bot.sendMessage(process.env.TELEGRAM_CHAT_ID, '📬 *Email Digest*: No unread priority emails today!', { parse_mode: 'Markdown' });
      return;
    }

    const digest = await analyzeEmails(emails);
    
    let message = `📬 *Daily Email Digest*\n\n_${digest.overview}_\n\n*Action Items:*\n`;

    if (digest.tasks && digest.tasks.length > 0) {
      digest.tasks.forEach((t, index) => {
        message += `\n${index + 1}. *[${t.urgency}]* ${t.title}\n   ↳ *From:* ${t.source} | *Due:* ${t.dueDate}`;
      });
    } else {
      message += `\n_No actionable items found in recent emails._`;
    }

    // Inline button to trigger interactive options
    const inlineKeyboard = {
      inline_keyboard: [
        [{ text: '🔄 Refresh Inbox', callback_data: 'refresh_inbox' }]
      ]
    };

    await bot.sendMessage(process.env.TELEGRAM_CHAT_ID, message, {
      parse_mode: 'Markdown',
      reply_markup: inlineKeyboard
    });
  } catch (err) {
    console.error('Error generating daily digest:', err);
  }
}

// 5. Telegram Callback Handlers & Commands
bot.onText(/\/digest/, async (msg) => {
  if (msg.chat.id.toString() !== process.env.TELEGRAM_CHAT_ID) return;
  bot.sendMessage(msg.chat.id, '⏳ Scanning your inbox and extracting tasks...');
  await sendDailyDigest();
});

bot.on('callback_query', async (query) => {
  if (query.data === 'refresh_inbox') {
    bot.answerCallbackQuery(query.id, { text: 'Checking inbox...' });
    await sendDailyDigest();
  }
});

// 6. Schedule Daily Digest at 8:00 AM
cron.schedule('0 8 * * *', () => {
  console.log('Running daily scheduled email digest...');
  sendDailyDigest();
});

console.log('Bot is running...');