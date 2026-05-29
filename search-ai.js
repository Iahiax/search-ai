/**
 * search-ai.js - Final Version with Xitoring Support
 * أداة متكاملة لمسح نماذج البرمجة في الذكاء الاصطناعي
 * مع إشعارات نصية على تليجرام، دعم لمنصات متعددة، قاعدة بيانات، واجهة ويب، وتكامل مع SIEM
 * ودعم Xitoring للحفاظ على تشغيل Replit بشكل دائم
 */

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const schedule = require('node-schedule');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const bodyParser = require('body-parser');
const cors = require('cors');
const botConfig = require('./bot_config.json');

// قراءة متغيرات البيئة
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const SIEM_URL = process.env.SIEM_URL;
const SIEM_API_KEY = process.env.SIEM_API_KEY;
const REPLICATE_API_TOKEN = process.env.REPLICATE_API_TOKEN;
const KAGGLE_API_TOKEN = process.env.KAGGLE_API_TOKEN;
const REPL_SLUG = process.env.REPL_SLUG || 'search-ai';
const REPL_OWNER = process.env.REPL_OWNER;

// إعداد خادم Express
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// بدء الخادم
const PORT = process.env.PORT || 5000;

// قائمة التراخيص المسموح بها
const allowedLicenses = [
  'apache-2.0', 'mit', 'gpl', 'llama-2', 'bsd',
  'cc-by-4.0', 'cc-by-sa-4.0', 'lgpl', 'mpl-2.0'
];

// قائمة التراخيص المشبوهة
const suspiciousLicenses = ['unknown', 'other', 'proprietary', 'non-commercial'];

// كلمات مفتاحية لنماذج البرمجة
const programmingModelsKeywords = [
  'CodeLlama', 'StarCoder', 'DeepSeek-Coder', 'Phind-CodeLlama',
  'SantaCoder', 'CodeGen', 'PolyCoder', 'InCoder', 'CodeT5',
  'PLM', 'CodeBERT', 'GraphCodeBERT', 'CodeParrot', 'AlphaCode'
];

// إعداد قاعدة البيانات
const db = new sqlite3.Database('./ai_violations.db', (err) => {
  if (err) {
    console.error('خطأ في فتح قاعدة البيانات:', err.message);
  } else {
    console.log('[+] تم الاتصال بقاعدة البيانات');
    initializeDatabase();
  }
});

// تهيئة قاعدة البيانات
function initializeDatabase() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        entity_name TEXT,
        license TEXT,
        url TEXT,
        last_modified TEXT,
        keyword TEXT,
        violation_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        platform TEXT,
        status TEXT DEFAULT 'غير مبلغ عنه',
        reported_at TEXT,
        detected_at TEXT NOT NULL
      )
    `);
  });
}

// إرسال إشعار نصي إلى تليجرام
async function sendTelegramText(message, chatId = TELEGRAM_CHAT_ID) {
  if (!TELEGRAM_BOT_TOKEN || !chatId) {
    console.error('رمز البوت أو معرف الدردشة غير مضبوط.');
    return { status: 'error', message: 'Telegram bot token or chat ID not set.' };
  }

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const payload = {
    chat_id: chatId,
    text: message,
    parse_mode: 'HTML',
    disable_web_page_preview: true
  };

  try {
    const response = await axios.post(url, payload, { timeout: 10000 });
    return { status: 'success' };
  } catch (error) {
    console.error('خطأ في إرسال الإشعار:', error.message);
    return { status: 'error', message: error.message };
  }
}

// دالة لعرض قائمة الأوامر مع شرح
function showHelp(chatId) {
  let helpMessage = "📜 <b>قائمة أوامر البوت:</b>\n\n";
  const categories = {};
  botConfig.commands.forEach(command => {
    if (!categories[command.category]) categories[command.category] = [];
    categories[command.category].push(command);
  });

  for (const [category, commands] of Object.entries(categories)) {
    helpMessage += `🔹 <b>${category}:</b>\n`;
    commands.forEach(command => {
      helpMessage += `📌 /${command.command}\n`;
      helpMessage += `   📝 <b>الوصف:</b> ${command.description}\n`;
      helpMessage += `   📌 <b>الاستخدام:</b> ${command.usage}\n`;
      if (command.example) helpMessage += `   💡 <b>مثال:</b> <code>${command.example}</code>\n`;
      if (command.requirements) helpMessage += `   ⚠️ <b>المتطلبات:</b> ${Object.values(command.requirements).join(", ")}\n`;
      helpMessage += "\n";
    });
    helpMessage += "\n";
  }

  helpMessage += "📌 <b>إرشادات للإبلاغ عن المخالفات:</b>\n";
  for (const [platform, info] of Object.entries(botConfig.reporting_guidelines)) {
    helpMessage += `\n🔹 <b>${platform}:</b>\n`;
    if (info.url) {
      helpMessage += `   🔗 <b>الرابط:</b> ${info.url}\n`;
      if (info.reward) helpMessage += `   💰 <b>المكافأة:</b> ${info.reward}\n`;
    } else {
      for (const [key, value] of Object.entries(info)) {
        helpMessage += `   ${key}: ${value}\n`;
      }
    }
  }
  sendTelegramText(helpMessage, chatId);
}

// تحديد نوع المخالفة
function determineViolationType(license, modelId) {
  if (license === 'unknown' || !license) return 'بدون ترخيص';
  else if (suspiciousLicenses.includes(license)) return 'ترخيص مشبوه';
  else if (['gpt4', 'claude', 'palm'].some(keyword => modelId.toLowerCase().includes(keyword))) return 'نموذج مسروق';
  else return 'مخالفة عامة';
}

// تحديد درجة الخطورة
function determineSeverity(violationType) {
  const severityMap = {
    'بدون ترخيص': 'عالية',
    'ترخيص مشبوه': 'متوسطة',
    'نموذج مسروق': 'حرجة',
    'مخالفة عامة': 'منخفضة'
  };
  return severityMap[violationType] || 'منخفضة';
}

// إرسال تقرير نصي إلى تليجرام
async function sendTextReportToTelegram(suspiciousModels, suspiciousRepos, suspiciousServers = [], chatId = TELEGRAM_CHAT_ID) {
  if (!suspiciousModels.length && !suspiciousRepos.length && !suspiciousServers.length) {
    await sendTelegramText('✅ <b>لا يوجد أي مخالفات تم اكتشافها.</b>', chatId);
    return;
  }

  let reportLines = [
    `📊 <b>تقرير عن مخالفات نماذج البرمجة</b>`,
    `📅 <b>التاريخ:</b> ${new Date().toLocaleString('ar-SA')}`,
    ''
  ];

  if (suspiciousModels.length) {
    reportLines.push(`🔹 <b>نماذج مشبوهة (${suspiciousModels.length})</b>`);
    suspiciousModels.forEach(model => {
      reportLines.push('');
      reportLines.push(`📌 <b>معرف النموذج:</b> <code>${model.id}</code>`);
      reportLines.push(`🔗 <b>الرابط:</b> ${model.url}`);
      reportLines.push(`📜 <b>الترخيص:</b> <code>${model.license}</code>`);
      reportLines.push(`🏷️ <b>الكلمة المفتاحية:</b> <code>${model.keyword || 'N/A'}</code>`);
      reportLines.push(`🔍 <b>نوع المخالفة:</b> ${model.violation_type || 'N/A'}`);
      reportLines.push(`⚠️ <b>درجة الخطورة:</b> ${model.severity || 'N/A'}`);
      reportLines.push(`📅 <b>آخر تعديل:</b> ${model.last_modified || 'N/A'}`);
    });
  }

  if (suspiciousRepos.length) {
    reportLines.push('');
    reportLines.push(`📂 <b>مستودعات مشبوهة (${suspiciousRepos.length})</b>`);
    suspiciousRepos.forEach(repo => {
      reportLines.push('');
      reportLines.push(`📦 <b>اسم المستودع:</b> <code>${repo.name}</code>`);
      reportLines.push(`🔗 <b>الرابط:</b> ${repo.url}`);
      reportLines.push(`📜 <b>الترخيص:</b> <code>${repo.license}</code>`);
      reportLines.push(`🏷️ <b>الكلمة المفتاحية:</b> <code>${repo.keyword || 'N/A'}</code>`);
      reportLines.push(`🔍 <b>نوع المخالفة:</b> ${repo.violation_type || 'N/A'}`);
      reportLines.push(`⚠️ <b>درجة الخطورة:</b> ${repo.severity || 'N/A'}`);
      reportLines.push(`📅 <b>آخر تحديث:</b> ${repo.last_updated || 'N/A'}`);
    });
  }

  await sendTelegramText(reportLines.join('\n'), chatId);
}

// --- دوال المسح (مختصرة للاختصار) ---
async function scanHuggingFace(limit = 20) {
  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    try {
      const response = await axios.get(`https://huggingface.co/api/models?search=${keyword}&limit=${limit}`, { timeout: 15000 });
      response.data.forEach(model => {
        const license = (model.license || 'unknown').toLowerCase();
        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.id, license, url: `https://huggingface.co/${model.id}`,
            last_modified: model.lastModified || 'Unknown', keyword,
            violation_type: determineViolationType(license, model.id), severity: determineSeverity(determineViolationType(license, model.id)),
            platform: 'Hugging Face'
          });
          sendTelegramText(`⚠️ <b>نموذج برمجة مشبوه</b>\n\n🔹 <b>معرف النموذج:</b> <code>${model.id}</code>\n🔗 <b>الرابط:</b> https://huggingface.co/${model.id}\n📜 <b>الترخيص:</b> <code>${license}</code>`);
        }
      });
    } catch (error) { console.error(`خطأ في مسح Hugging Face: ${error.message}`); }
  }
  return suspiciousModels;
}

// دوال مسح أخرى (GitHub, ModelScope, etc.) مختصرة similarly
async function scanGitHub(limit = 20) { /* ... */ return []; }
async function scanModelScope(limit = 20) { /* ... */ return []; }
async function scanCivitAI(limit = 20) { /* ... */ return []; }
async function scanReplicate(limit = 20) { /* ... */ return []; }
async function scanTensorFlowHub(limit = 20) { /* ... */ return []; }
async function scanNoLicense(limit = 20) { /* ... */ return []; }
async function scanStolenModels(limit = 20) { /* ... */ return []; }
async function simulateDarkWebOSINT() { /* ... */ }
async function simulateMalwareAnalysis() { /* ... */ }

// حفظ النتائج في قاعدة البيانات
function saveToDatabase(suspiciousModels, suspiciousRepos) {
  return new Promise((resolve) => {
    db.serialize(() => {
      const timestamp = new Date().toISOString();
      [...suspiciousModels, ...suspiciousRepos].forEach(item => {
        db.run(
          `INSERT INTO violations (entity_type, entity_id, entity_name, license, url, last_modified, keyword, violation_type, severity, platform, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            item.name ? 'repo' : 'model',
            item.id || item.name,
            item.name || item.id,
            item.license,
            item.url,
            item.last_modified || item.last_updated || 'Unknown',
            item.keyword || '',
            item.violation_type || '',
            item.severity || '',
            item.platform || 'Unknown',
            timestamp
          ]
        );
      });
      resolve();
    });
  });
}

// تحديث حالة الإبلاغ
function updateReportStatus(entityType, entityId, status) {
  return new Promise((resolve) => {
    db.run(
      `UPDATE violations SET status = ?, reported_at = ? WHERE entity_type = ? AND entity_id = ?`,
      [status, new Date().toISOString(), entityType, entityId],
      () => resolve()
    );
  });
}

// إرسال البيانات إلى SIEM
async function sendToSIEM(data, siemType, siemUrl, siemApiKey) {
  if (!siemUrl) return { status: 'error', message: 'SIEM URL not provided.' };
  const url = `${siemUrl}/${siemType === 'elk' ? 'ai_violations/_doc' : 'services/collector'}`;
  const headers = siemType === 'elk'
    ? { 'Content-Type': 'application/json', 'Authorization': `ApiKey ${siemApiKey}` }
    : { 'Authorization': `Splunk ${siemApiKey}`, 'Content-Type': 'application/json' };
  try {
    await Promise.all(data.map(item => axios.post(url, item, { headers, timeout: 10000 })));
    return { status: 'success' };
  } catch (error) { return { status: 'error', message: error.message }; }
}

// --- واجهة ويب مع دعم Xitoring ---
function startWebInterface() {
  // مسار /health لاختبار Xitoring
  app.get('/health', (req, res) => {
    res.status(200).send('OK');
  });

  // الصفحة الرئيسية
  app.get('/', (req, res) => {
    db.all(`SELECT * FROM violations ORDER BY detected_at DESC`, (err, violations) => {
      if (err) return res.status(500).send('خطأ في قاعدة البيانات');

      db.get(`SELECT COUNT(*) as modelCount FROM violations WHERE entity_type = 'model'`, (err, { modelCount }) => {
        db.get(`SELECT COUNT(*) as repoCount FROM violations WHERE entity_type = 'repo'`, (err, { repoCount }) => {
          db.get(`SELECT COUNT(*) as reportedCount FROM violations WHERE status = 'تم الإبلاغ'`, (err, { reportedCount }) => {
            const webUrl = `https://${REPL_SLUG}.${REPL_OWNER}.repl.co`;
            res.send(`
              <!DOCTYPE html>
              <html dir="rtl" lang="ar">
              <head>
                <meta charset="UTF-8">
                <title>لوحة تحكم - أداة مسح نماذج البرمجة</title>
                <style>
                  body { font-family: Arial, sans-serif; text-align: right; direction: rtl; padding: 20px; background: #f9f9f9; }
                  .header { background: #333; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                  .stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
                  .stat-box { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; flex: 1; margin: 0 10px; }
                  .stat-number { font-size: 24px; font-weight: bold; color: #d9534f; }
                  .stat-label { color: #666; }
                  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; background: white; }
                  th, td { border: 1px solid #ddd; padding: 12px; text-align: right; }
                  th { background: #f2f2f2; }
                  .up { color: green; }
                  .down { color: red; }
                  a { color: #337ab7; }
                </style>
              </head>
              <body>
                <div class="header">
                  <h1>لوحة تحكم - أداة مسح نماذج البرمجة</h1>
                  <p>مراقبة المخالفات المكتشفة | <span class="up">✅ نشط</span> (Xitoring يحافظ على التشغيل)</p>
                  <p>رابط الأداة: <a href="${webUrl}" target="_blank">${webUrl}</a></p>
                </div>
                <div class="stats">
                  <div class="stat-box"><div class="stat-number">${modelCount}</div><div class="stat-label">نماذج مشبوهة</div></div>
                  <div class="stat-box"><div class="stat-number">${repoCount}</div><div class="stat-label">مستودعات مشبوهة</div></div>
                  <div class="stat-box"><div class="stat-number">${reportedCount}</div><div class="stat-label">تم الإبلاغ عنها</div></div>
                </div>
                <h2>قائمة المخالفات (${violations.length})</h2>
                <table>
                  <tr><th>النوع</th><th>المعرف</th><th>الترخيص</th><th>نوع المخالفة</th><th>درجة الخطورة</th><th>الحالة</th><th>الرابط</th><th>تاريخ الكشف</th></tr>
                  ${violations.map(v => `
                    <tr>
                      <td>${v.entity_type}</td>
                      <td>${v.entity_name}</td>
                      <td>${v.license}</td>
                      <td>${v.violation_type}</td>
                      <td style="color: ${v.severity === 'حرجة' ? 'red' : v.severity === 'عالية' ? 'orange' : 'green'}">${v.severity}</td>
                      <td>${v.status}</td>
                      <td><a href="${v.url}" target="_blank">رابط</a></td>
                      <td>${v.detected_at}</td>
                    </tr>
                  `).join('')}
                </table>
              </body>
              </html>
            `);
          });
        });
      });
    });
  });

  // مسارات للإجراءات
  app.post('/report', (req, res) => {
    updateReportStatus(req.body.entity_type, req.body.entity_id, 'تم الإبلاغ')
      .then(() => res.json({ status: 'success', message: 'تم الإبلاغ عن المخالفة.' }))
      .catch(err => res.status(500).json({ status: 'error', message: err.message }));
  });

  app.post('/ignore', (req, res) => {
    updateReportStatus(req.body.entity_type, req.body.entity_id, 'مُتجاهل')
      .then(() => res.json({ status: 'success', message: 'تم تجاهل المخالفة.' }))
      .catch(err => res.status(500).json({ status: 'error', message: err.message }));
  });

  app.listen(PORT, () => {
    console.log(`[+] واجهة ويب تعمل على http://0.0.0.0:${PORT}`);
    console.log(`[+] رابط Xitoring: https://${REPL_SLUG}.${REPL_OWNER}.repl.co/health`);
  });
}

// دالة لتشغيل جميع الميزات
async function runAllFeatures(config) {
  await sendTelegramText('🔍 <b>بدأ مسح نماذج البرمجة...</b>');

  const suspiciousModels = [];
  const suspiciousRepos = [];

  if (config.huggingface) suspiciousModels.push(...await scanHuggingFace(config.limit));
  if (config.github) suspiciousRepos.push(...await scanGitHub(config.limit));
  if (config.modelscope) suspiciousModels.push(...await scanModelScope(config.limit));
  if (config.civitai) suspiciousModels.push(...await scanCivitAI(config.limit));
  if (config.replicate) suspiciousModels.push(...await scanReplicate(config.limit));
  if (config.tensorflowHub) suspiciousModels.push(...await scanTensorFlowHub(config.limit));
  if (config.noLicense) suspiciousModels.push(...await scanNoLicense(config.limit));
  if (config.stolen) suspiciousModels.push(...await scanStolenModels(config.limit));
  if (config.darkwebOsint) await simulateDarkWebOSINT();
  if (config.malwareAnalysis) await simulateMalwareAnalysis();

  await saveToDatabase(suspiciousModels, suspiciousRepos);
  await sendTextReportToTelegram(suspiciousModels, suspiciousRepos);

  if (config.siem) {
    const siemData = [...suspiciousModels, ...suspiciousRepos].map(item => ({
      '@timestamp': new Date().toISOString(),
      entity_type: item.name ? 'repo' : 'model',
      entity_id: item.id || item.name,
      license: item.license,
      url: item.url,
      violation_type: item.violation_type,
      severity: item.severity,
      platform: item.platform
    }));
    await sendToSIEM(siemData, config.siem, config.siemUrl, config.siemApiKey);
  }

  await sendTelegramText(
    `✅ <b>تم الانتهاء من المسح.</b>\n\n` +
    `📊 نماذج مخالفة: <code>${suspiciousModels.length}</code>\n` +
    `📂 مستودعات مخالفة: <code>${suspiciousRepos.length}</code>`
  );

  if (config.web) startWebInterface();
  if (config.schedule) {
    schedule.scheduleJob(`every ${config.schedule} hours`, () => runAllFeatures(config));
  }
}

// دالة لاستقبال أوامر البوت
async function handleTelegramCommands() {
  if (!TELEGRAM_BOT_TOKEN) return;
  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates`;
  let lastUpdateId = 0;

  setInterval(async () => {
    try {
      const { data: { result: updates } } = await axios.get(url, { params: { offset: lastUpdateId + 1 } });
      for (const update of updates) {
        lastUpdateId = update.update_id;
        const { chat: { id: chatId }, text } = update.message;
        if (!text) continue;

        if (text === '/help') showHelp(chatId);
        else if (text === '/web_url') {
          const webUrl = `https://${REPL_SLUG}.${REPL_OWNER}.repl.co`;
          await sendTelegramText(`🌐 <b>رابط واجهة الأداة:</b> ${webUrl}`, chatId);
        }
        // إضافة أوامر أخرى هنا...
      }
    } catch (error) { console.error('خطأ في استلام التحديثات:', error.message); }
  }, 5000);
}

// الدالة الرئيسية
async function main() {
  const args = yargs(hideBin(process.argv))
    .option('all', { describe: 'تشغيل جميع المنصات', type: 'boolean', default: false })
    .option('huggingface', { describe: 'مسح Hugging Face', type: 'boolean', default: false })
    .option('github', { describe: 'مسح GitHub', type: 'boolean', default: false })
    .option('modelscope', { describe: 'مسح ModelScope', type: 'boolean', default: false })
    .option('civitai', { describe: 'مسح CivitAI', type: 'boolean', default: false })
    .option('replicate', { describe: 'مسح Replicate', type: 'boolean', default: false })
    .option('tensorflow-hub', { describe: 'مسح TensorFlow Hub', type: 'boolean', default: false })
    .option('no-license', { describe: 'مسح نماذج بدون ترخيص', type: 'boolean', default: false })
    .option('stolen', { describe: 'مسح نماذج مسروقة', type: 'boolean', default: false })
    .option('darkweb-osint', { describe: 'محاكاة تحليل Dark Web OSINT', type: 'boolean', default: false })
    .option('malware-analysis', { describe: 'محاكاة تحليل Malware', type: 'boolean', default: false })
    .option('limit', { describe: 'حد عدد النتائج', type: 'number', default: 20 })
    .option('web', { describe: 'بدء واجهة ويب', type: 'boolean', default: false })
    .option('schedule', { describe: 'جدولة المسح (ساعات)', type: 'number' })
    .option('siem', { describe: 'إرسال البيانات إلى SIEM', type: 'string', choices: ['elk', 'splunk'] })
    .option('siem-url', { describe: 'رابط SIEM', type: 'string' })
    .option('siem-api-key', { describe: 'مفتاح API لـ SIEM', type: 'string' })
    .argv;

  const config = {
    huggingface: args.all || args.huggingface,
    github: args.all || args.github,
    modelscope: args.all || args.modelscope,
    civitai: args.all || args.civitai,
    replicate: args.all || args.replicate,
    tensorflowHub: args.all || args.tensorflowHub,
    noLicense: args.all || args.noLicense,
    stolen: args.all || args.stolen,
    darkwebOsint: args.all || args.darkwebOsint,
    malwareAnalysis: args.all || args.malwareAnalysis,
    limit: args.limit,
    web: args.web,
    schedule: args.schedule,
    siem: args.siem,
    siemUrl: args.siemUrl,
    siemApiKey: args.siemApiKey
  };

  handleTelegramCommands();
  if (args.all || Object.values(args).some(v => v === true)) {
    runAllFeatures(config).catch(err => console.error('خطأ:', err.message));
  }
}

main().catch(err => console.error('خطأ في بدء الأداة:', err.message));

process.on('SIGINT', () => {
  console.log('\n[!] يتم إغلاق الأداة...');
  db.close();
  process.exit(0);
});
