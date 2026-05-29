/**
 * search-ai.js - Complete Final Version
 * أداة متكاملة لمسح نماذج البرمجة في الذكاء الاصطناعي
 * مع إشعارات نصية على تليجرام، دعم لمنصات متعددة، قاعدة بيانات، واجهة ويب، وتكامل مع SIEM
 *
 * Usage: node search-ai.js --all
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
const REPL_SLUG = process.env.REPL_SLUG || 'AI-Programming-Models-Scanner';
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

  // تصنيف الأوامر حسب الفئة
  const categories = {};
  botConfig.commands.forEach(command => {
    if (!categories[command.category]) {
      categories[command.category] = [];
    }
    categories[command.category].push(command);
  });

  // عرض الأوامر حسب الفئة
  for (const [category, commands] of Object.entries(categories)) {
    helpMessage += `🔹 <b>${category}:</b>\n`;
    commands.forEach(command => {
      helpMessage += `📌 /${command.command}\n`;
      helpMessage += `   📝 <b>الوصف:</b> ${command.description}\n`;
      helpMessage += `   📌 <b>الاستخدام:</b> ${command.usage}\n`;
      if (command.example) {
        helpMessage += `   💡 <b>مثال:</b> <code>${command.example}</code>\n`;
      }
      if (command.requirements) {
        helpMessage += `   ⚠️ <b>المتطلبات:</b> ${Object.values(command.requirements).join(", ")}\n`;
      }
      helpMessage += "\n";
    });
    helpMessage += "\n";
  }

  // إضافة إرشادات للإبلاغ
  helpMessage += "📌 <b>إرشادات للإبلاغ عن المخالفات:</b>\n";
  for (const [platform, info] of Object.entries(botConfig.reporting_guidelines)) {
    helpMessage += `\n🔹 <b>${platform}:</b>\n`;
    if (info.url) {
      helpMessage += `   🔗 <b>الرابط:</b> ${info.url}\n`;
      if (info.reward) {
        helpMessage += `   💰 <b>المكافأة:</b> ${info.reward}\n`;
      }
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
  if (license === 'unknown' || !license) {
    return 'بدون ترخيص';
  } else if (suspiciousLicenses.includes(license)) {
    return 'ترخيص مشبوه';
  } else if (['gpt4', 'claude', 'palm'].some(keyword => modelId.toLowerCase().includes(keyword))) {
    return 'نموذج مسروق';
  } else {
    return 'مخالفة عامة';
  }
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

  let reportLines = [];
  reportLines.push(`📊 <b>تقرير عن مخالفات نماذج البرمجة</b>`);
  reportLines.push(`📅 <b>التاريخ:</b> ${new Date().toLocaleString('ar-SA')}`);
  reportLines.push('');

  // إضافة نماذج مشبوهة
  if (suspiciousModels.length) {
    reportLines.push(`🔹 <b>نماذج مشبوهة (${suspiciousModels.length})</b>`);
    for (const model of suspiciousModels) {
      reportLines.push('');
      reportLines.push(`📌 <b>معرف النموذج:</b> <code>${model.id}</code>`);
      reportLines.push(`🔗 <b>الرابط:</b> ${model.url}`);
      reportLines.push(`📜 <b>الترخيص:</b> <code>${model.license}</code>`);
      reportLines.push(`🏷️ <b>الكلمة المفتاحية:</b> <code>${model.keyword || 'N/A'}</code>`);
      reportLines.push(`🔍 <b>نوع المخالفة:</b> ${model.violation_type || 'N/A'}`);
      reportLines.push(`⚠️ <b>درجة الخطورة:</b> ${model.severity || 'N/A'}`);
      reportLines.push(`📅 <b>آخر تعديل:</b> ${model.last_modified || 'N/A'}`);
    }
  }

  // إضافة مستودعات مشبوهة
  if (suspiciousRepos.length) {
    reportLines.push('');
    reportLines.push(`📂 <b>مستودعات مشبوهة (${suspiciousRepos.length})</b>`);
    for (const repo of suspiciousRepos) {
      reportLines.push('');
      reportLines.push(`📦 <b>اسم المستودع:</b> <code>${repo.name}</code>`);
      reportLines.push(`🔗 <b>الرابط:</b> ${repo.url}`);
      reportLines.push(`📜 <b>الترخيص:</b> <code>${repo.license}</code>`);
      reportLines.push(`🏷️ <b>الكلمة المفتاحية:</b> <code>${repo.keyword || 'N/A'}</code>`);
      reportLines.push(`🔍 <b>نوع المخالفة:</b> ${repo.violation_type || 'N/A'}`);
      reportLines.push(`⚠️ <b>درجة الخطورة:</b> ${repo.severity || 'N/A'}`);
      reportLines.push(`📅 <b>آخر تحديث:</b> ${repo.last_updated || 'N/A'}`);
    }
  }

  // إرسال التقرير
  const fullReport = reportLines.join('\n');
  await sendTelegramText(fullReport, chatId);
}

// البحث في Hugging Face
async function scanHuggingFace(limit = 20) {
  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://huggingface.co/api/models?search=${keyword}&limit=${limit}`;
    try {
      const response = await axios.get(url, { timeout: 15000 });
      const models = response.data;
      for (const model of models) {
        const license = (model.license || 'unknown').toLowerCase();
        const violationType = determineViolationType(license, model.id || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.id,
            license,
            url: `https://huggingface.co/${model.id}`,
            last_modified: model.lastModified || 'Unknown',
            keyword,
            violation_type: violationType,
            severity,
            platform: 'Hugging Face'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>نموذج برمجة مشبوه</b>

🔹 <b>معرف النموذج:</b> <code>\${model.id}</code>
🔗 <b>الرابط:</b> \${`https://huggingface.co/${model.id}`}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح Hugging Face للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// البحث في GitHub
async function scanGitHub(limit = 20) {
  const suspiciousRepos = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://api.github.com/search/repositories?q=${keyword}+in:readme&per_page=${limit}`;
    const headers = { Accept: 'application/vnd.github.v3+json' };
    try {
      const response = await axios.get(url, { headers, timeout: 15000 });
      const repos = response.data.items;
      for (const repo of repos) {
        const licenseKey = (repo.license?.key || 'unknown').toLowerCase();
        const violationType = determineViolationType(licenseKey, repo.full_name || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(licenseKey) || suspiciousLicenses.includes(licenseKey)) {
          suspiciousRepos.push({
            name: repo.full_name,
            license: licenseKey,
            url: repo.html_url,
            last_updated: repo.updated_at,
            keyword,
            violation_type: violationType,
            severity,
            platform: 'GitHub'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>مستودع برمجة مشبوه</b>

📦 <b>اسم المستودع:</b> <code>\${repo.full_name}</code>
🔗 <b>الرابط:</b> \${repo.html_url}
📜 <b>الترخيص:</b> <code>${licenseKey}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح GitHub للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousRepos;
}

// البحث في ModelScope
async function scanModelScope(limit = 20) {
  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://www.modelscope.cn/api/v1/models?page=1&pageSize=${limit}&search=${keyword}`;
    try {
      const response = await axios.get(url, { timeout: 15000 });
      const models = response.data.data?.models || [];
      for (const model of models) {
        const license = (model.license || 'unknown').toLowerCase();
        const violationType = determineViolationType(license, model.modelId || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.modelId,
            license,
            url: `https://www.modelscope.cn/models/${model.modelId}`,
            last_modified: model.updateTime || 'Unknown',
            keyword,
            violation_type: violationType,
            severity,
            platform: 'ModelScope'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>نموذج برمجة مشبوه (ModelScope)</b>

🔹 <b>معرف النموذج:</b> <code>\${model.modelId}</code>
🔗 <b>الرابط:</b> \${`https://www.modelscope.cn/models/${model.modelId}`}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح ModelScope للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// البحث في CivitAI
async function scanCivitAI(limit = 20) {
  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://civitai.com/api/v1/models?query=${keyword}&limit=${limit}`;
    try {
      const response = await axios.get(url, {
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        timeout: 15000
      });

      const models = response.data.items || [];
      for (const model of models) {
        const license = (model.license || 'unknown').toLowerCase();
        const violationType = determineViolationType(license, model.name || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.id,
            name: model.name,
            license,
            url: `https://civitai.com/models/${model.id}`,
            last_modified: model.updatedAt || 'Unknown',
            keyword,
            violation_type: violationType,
            severity,
            platform: 'CivitAI'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>نموذج مشبوه على CivitAI</b>

🔹 <b>اسم النموذج:</b> <code>${model.name}</code>
🔗 <b>الرابط:</b> https://civitai.com/models/${model.id}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح CivitAI للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// البحث في Replicate
async function scanReplicate(limit = 20) {
  if (!REPLICATE_API_TOKEN) {
    console.error('REPLICATE_API_TOKEN غير مضبوط.');
    return [];
  }

  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://api.replicate.com/v1/models?search=${keyword}&limit=${limit}`;
    try {
      const response = await axios.get(url, {
        headers: {
          'Authorization': `Token ${REPLICATE_API_TOKEN}`,
          'Accept': 'application/json'
        },
        timeout: 15000
      });

      const models = response.data.results || [];
      for (const model of models) {
        const license = (model.license || 'unknown').toLowerCase();
        const violationType = determineViolationType(license, model.name || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.id,
            name: model.name,
            license,
            url: `https://replicate.com/${model.owner}/${model.name}`,
            last_modified: model.updated_at || 'Unknown',
            keyword,
            violation_type: violationType,
            severity,
            platform: 'Replicate'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>نموذج مشبوه على Replicate</b>

🔹 <b>اسم النموذج:</b> <code>${model.name}</code>
🔗 <b>الرابط:</b> https://replicate.com/${model.owner}/${model.name}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>\${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح Replicate للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// البحث في TensorFlow Hub
async function scanTensorFlowHub(limit = 20) {
  const suspiciousModels = [];
  for (const keyword of programmingModelsKeywords) {
    const url = `https://tfhub.dev/api/v1/search?query=${keyword}&limit=${limit}`;
    try {
      const response = await axios.get(url, { timeout: 15000 });
      const models = response.data.models || [];

      for (const model of models) {
        const license = (model.license || 'unknown').toLowerCase();
        const violationType = determineViolationType(license, model.name || '');
        const severity = determineSeverity(violationType);

        if (!allowedLicenses.includes(license) || suspiciousLicenses.includes(license)) {
          suspiciousModels.push({
            id: model.id,
            name: model.name,
            license,
            url: `https://tfhub.dev/${model.author}/${model.name}`,
            last_modified: model.last_updated || 'Unknown',
            keyword,
            violation_type: violationType,
            severity,
            platform: 'TensorFlow Hub'
          });

          // إرسال إشعار فوري
          const message = `
⚠️ <b>نموذج مشبوه على TensorFlow Hub</b>

🔹 <b>اسم النموذج:</b> <code>\${model.name}</code>
🔗 <b>الرابط:</b> https://tfhub.dev/${model.author}/${model.name}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> \${violationType}
⚠️ <b>درجة الخطورة:</b> \${severity}
`;
          await sendTelegramText(message);
        }
      }
    } catch (error) {
      console.error(`خطأ في مسح TensorFlow Hub للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// البحث عن نماذج بدون ترخيص
async function scanNoLicense(limit = 20) {
  const suspiciousModels = [];
  const url = `https://huggingface.co/api/models?limit=${limit}`;
  try {
    const response = await axios.get(url, { timeout: 15000 });
    const models = response.data;
    for (const model of models) {
      const modelName = model.id.toLowerCase();
      const isProgrammingModel = programmingModelsKeywords.some(
        keyword => modelName.includes(keyword.toLowerCase())
      );

      if (isProgrammingModel && (!model.license || model.license.toLowerCase() === 'unknown')) {
        suspiciousModels.push({
          id: model.id,
          license: model.license || 'None',
          url: `https://huggingface.co/${model.id}`,
          last_modified: model.lastModified || 'Unknown',
          keyword: 'No License',
          violation_type: 'بدون ترخيص',
          severity: 'عالية',
          platform: 'Hugging Face'
        });

        // إرسال إشعار فوري
        const message = `
⚠️ <b>نموذج برمجة بدون ترخيص</b>

🔹 <b>معرف النموذج:</b> <code>\${model.id}</code>
🔗 <b>الرابط:</b> \${`https://huggingface.co/${model.id}`}
📜 <b>الترخيص:</b> <code>\${model.license || 'None'}</code>
🔍 <b>نوع المخالفة:</b> بدون ترخيص
⚠️ <b>درجة الخطورة:</b> عالية
`;
        await sendTelegramText(message);
      }
    }
  } catch (error) {
    console.error('خطأ في مسح نماذج بدون ترخيص:', error.message);
  }
  return suspiciousModels;
}

// البحث عن نماذج مسروقة
async function scanStolenModels(limit = 20) {
  const stolenKeywords = ['gpt4', 'claude', 'palm', 'gemini', 'llama3'];
  const suspiciousModels = [];
  for (const keyword of stolenKeywords) {
    const url = `https://huggingface.co/api/models?search=${keyword}&limit=${limit}`;
    try {
      const response = await axios.get(url, { timeout: 15000 });
      const models = response.data;
      for (const model of models) {
        suspiciousModels.push({
          id: model.id,
          license: model.license || 'unknown',
          url: `https://huggingface.co/${model.id}`,
          last_modified: model.lastModified || 'Unknown',
          keyword,
          violation_type: 'نموذج مسروق',
          severity: 'حرجة',
          platform: 'Hugging Face'
        });

        // إرسال إشعار فوري
        const message = `
🕵️ <b>نموذج مسروق محتمل</b>

🔹 <b>معرف النموذج:</b> <code>\${model.id}</code>
🔗 <b>الرابط:</b> \${`https://huggingface.co/${model.id}`}
🔍 <b>السبب:</b> كلمة مشبوهة: \${keyword}
⚠️ <b>درجة الخطورة:</b> حرجة
`;
        await sendTelegramText(message);
      }
    } catch (error) {
      console.error(`خطأ في مسح نماذج مسروقة للكلمة ${keyword}:`, error.message);
      continue;
    }
  }
  return suspiciousModels;
}

// محاكاة تحليل Dark Web OSINT
async function simulateDarkWebOSINT() {
  const osintSources = [
    {
      source: 'GitHub Issues',
      type: 'مناقشات حول نماذج مسروقة',
      data: 'تم اكتشاف مناقشات حول نماذج CodeLlama غير مرخصة'
    },
    {
      source: 'Reddit',
      type: 'منشورات حول ثغرات',
      data: 'منشورات حول ثغرات في نماذج StarCoder'
    },
    {
      source: 'Twitter',
      type: 'تغريدات حول نماذج مخترقة',
      data: 'تغريدات حول نماذج DeepSeek-Coder مع أبواب خلفية'
    }
  ];

  for (const source of osintSources) {
    const message = `
🕵️ <b>معلومات استخبارية من \${source.source}</b>

🔍 <b>النوع:</b> \${source.type}
📌 <b>البيانات:</b> \${source.data}
`;
    await sendTelegramText(message);
  }
}

// محاكاة تحليل Malware
async function simulateMalwareAnalysis() {
  const malwareSamples = [
    {
      filename: 'suspicious_model.bin',
      type: 'Backdoor',
      severity: 'حرجة',
      description: 'تم اكتشاف باب خلفي في نموذج برمجة'
    },
    {
      filename: 'poisoned_dataset.json',
      type: 'Data Poisoning',
      severity: 'عالية',
      description: 'تم اكتشاف بيانات تدريب مسممة'
    }
  ];

  for (const sample of malwareSamples) {
    const message = `
🦠 <b>برمجية خبيثة مكتشفة</b>

📌 <b>اسم الملف:</b> <code>\${sample.filename}</code>
🔍 <b>النوع:</b> \${sample.type}
⚠️ <b>درجة الخطورة:</b> \${sample.severity}
📝 <b>الوصف:</b> \${sample.description}
`;
    await sendTelegramText(message);
  }
}

// حفظ النتائج في قاعدة البيانات
function saveToDatabase(suspiciousModels, suspiciousRepos, suspiciousServers = []) {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      const timestamp = new Date().toISOString();

      // إدراج النماذج
      for (const model of suspiciousModels) {
        db.run(
          `INSERT INTO violations (
            entity_type, entity_id, entity_name, license, url, last_modified,
            keyword, violation_type, severity, platform, detected_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            'model',
            model.id,
            model.name || model.id,
            model.license,
            model.url,
            model.last_modified,
            model.keyword || '',
            model.violation_type || '',
            model.severity || '',
            model.platform || 'Hugging Face',
            timestamp
          ]
        );
      }

      // إدراج المستودعات
      for (const repo of suspiciousRepos) {
        db.run(
          `INSERT INTO violations (
            entity_type, entity_id, entity_name, license, url, last_modified,
            keyword, violation_type, severity, platform, detected_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            'repo',
            repo.name,
            repo.name,
            repo.license,
            repo.url,
            repo.last_updated,
            repo.keyword || '',
            repo.violation_type || '',
            repo.severity || '',
            'GitHub',
            timestamp
          ]
        );
      }

      resolve({ status: 'success', message: 'تم حفظ البيانات في قاعدة البيانات' });
    });
  });
}

// تحديث حالة الإبلاغ
function updateReportStatus(entityType, entityId, status) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE violations SET status = ?, reported_at = ? WHERE entity_type = ? AND entity_id = ?`,
      [status, new Date().toISOString(), entityType, entityId],
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve({ status: 'success', message: `تم تحديث حالة الإبلاغ لـ ${entityId}` });
        }
      }
    );
  });
}

// إرسال البيانات إلى SIEM
async function sendToSIEM(data, siemType, siemUrl, siemApiKey) {
  if (siemType === 'elk') {
    if (!siemUrl) {
      return { status: 'error', message: 'Elasticsearch URL not provided.' };
    }

    const url = `${siemUrl}/ai_violations/_doc`;
    const headers = { 'Content-Type': 'application/json' };
    if (siemApiKey) {
      headers['Authorization'] = `ApiKey ${siemApiKey}`;
    }

    try {
      for (const item of data) {
        await axios
