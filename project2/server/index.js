const express = require('express');
const cron = require('node-cron');
const Database = require('better-sqlite3');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Initialize SQLite database
const db = new Database('scans.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, -- 'url' or 'ip'
    input TEXT,
    result JSON,
    timestamp TEXT
  )
`);

// Telegram configuration (replace with your values)
const TELEGRAM_BOT_TOKEN = 'YOUR_BOT_TOKEN'; // TODO: Replace with your Telegram bot token
const TELEGRAM_CHAT_ID = 'YOUR_CHAT_ID'; // TODO: Replace with your Telegram chat ID
const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

// API URL
const API_URL = 'https://cyberregisserver-production.up.railway.app';

// Helper to send Telegram message
async function sendTelegramMessage(message) {
  try {
    await axios.post(TELEGRAM_API, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'Markdown',
    });
    console.log('Telegram message sent:', message);
  } catch (error) {
    console.error('Error sending Telegram message:', error.message);
  }
}

// Helper to recheck URL or IP
async function recheckScan(type, input) {
  try {
    const endpoint = type === 'url' ? '/api/check-url' : '/api/check-ip';
    const response = await axios.post(`${API_URL}${endpoint}`, { [type]: input }, {
      headers: { 'Content-Type': 'application/json' },
    });
    return response.data;
  } catch (error) {
    console.error(`Error rechecking ${type} ${input}:`, error.message);
    return null;
  }
}

// Daily monitoring job (runs at midnight)
cron.schedule('0 0 * * *', async () => {
  console.log('Running daily monitoring job');
  const scans = db.prepare('SELECT * FROM scans WHERE type IN (?, ?)').all('url', 'ip');
  for (const scan of scans) {
    const { type, input, result: oldResult } = scan;
    const newResult = await recheckScan(type, input);
    if (newResult && newResult.status === 'success') {
      const oldIsMalicious = oldResult.data?.threat_analysis?.is_malicious || false;
      const newIsMalicious = newResult.data?.threat_analysis?.is_malicious || false;
      if (oldIsMalicious !== newIsMalicious) {
        // Update database
        db.prepare('UPDATE scans SET result = ?, timestamp = ? WHERE type = ? AND input = ?')
          .run(JSON.stringify(newResult), new Date().toISOString(), type, input);
        // Notify via Telegram
        const status = newIsMalicious ? 'Malicious' : 'Safe';
        await sendTelegramMessage(
          `🚨 *${type.toUpperCase()} Status Change*\n` +
          `${type}: ${input}\n` +
          `New Status: ${status}\n` +
          `Checked: ${new Date().toLocaleString()}`
        );
      }
    }
  }
});

// Weekly Telegram report (runs every Sunday at 9 AM)
cron.schedule('0 9 * * 0', async () => {
  console.log('Sending weekly Telegram report');
  const scans = db.prepare('SELECT * FROM scans WHERE type IN (?, ?)').all('url', 'ip');
  if (scans.length === 0) {
    await sendTelegramMessage('📊 *Weekly CyberRegis Report*\nNo URLs or IPs monitored.');
    return;
  }

  let message = '📊 *Weekly CyberRegis Report*\n\n';
  for (const scan of scans) {
    const { type, input, result, timestamp } = scan;
    const isMalicious = result.data?.threat_analysis?.is_malicious ? 'Malicious' : 'Safe';
    message += `*${type.toUpperCase()}: ${input}*\n`;
    message += `Status: ${isMalicious}\n`;
    message += `Risk Level: ${result.data?.additional_checks?.domain_analysis?.risk_level || 'Unknown'}\n`;
    message += `Last Checked: ${new Date(timestamp).toLocaleString()}\n\n`;
  }
  await sendTelegramMessage(message);
});

// API to sync scans from client
app.post('/api/sync-scans', (req, res) => {
  const { urls, ips } = req.body;
  try {
    const stmt = db.prepare('INSERT OR REPLACE INTO scans (type, input, result, timestamp) VALUES (?, ?, ?, ?)');
    if (urls) {
      for (const scan of urls) {
        stmt.run('url', scan.input, JSON.stringify(scan.result), scan.timestamp);
      }
    }
    if (ips) {
      for (const scan of ips) {
        stmt.run('ip', scan.input, JSON.stringify(scan.result), scan.timestamp);
      }
    }
    res.json({ status: 'success' });
  } catch (error) {
    console.error('Error syncing scans:', error);
    res.status(500).json({ status: 'error', message: 'Failed to sync scans' });
  }
});

// API to get monitoring results
app.get('/api/monitoring-results', (req, res) => {
  try {
    const urls = db.prepare('SELECT * FROM scans WHERE type = ?').all('url');
    const ips = db.prepare('SELECT * FROM scans WHERE type = ?').all('ip');
    res.json({
      urls: urls.map((scan) => ({
        input: scan.input,
        result: JSON.parse(scan.result),
        timestamp: scan.timestamp,
      })),
      ips: ips.map((scan) => ({
        input: scan.input,
        result: JSON.parse(scan.result),
        timestamp: scan.timestamp,
      })),
    });
  } catch (error) {
    console.error('Error fetching monitoring results:', error);
    res.status(500).json({ status: 'error', message: 'Failed to fetch monitoring results' });
  }
});

app.listen(4001, () => {
  console.log('Monitoring server running on http://localhost:4001');
});