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

  // إضافة خادمات غير آمنة
  if (suspiciousServers.length) {
    reportLines.push('');
    reportLines.push(`🖥️ <b>خادمات غير آمنة (${suspiciousServers.length})</b>`);
    for (const server of suspiciousServers) {
      reportLines.push('');
      reportLines.push(`📌 <b>IP:</b> <code>${server.ip}</code>`);
      reportLines.push(`🔍 <b>نوع المخالفة:</b> ${server.violation_type || 'N/A'}`);
      reportLines.push(`⚠️ <b>درجة الخطورة:</b> ${server.severity || 'N/A'}`);
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

🔹 <b>معرف النموذج:</b> <code>${model.id}</code>
🔗 <b>الرابط:</b> ${`https://huggingface.co/${model.id}`}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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

📦 <b>اسم المستودع:</b> <code>${repo.full_name}</code>
🔗 <b>الرابط:</b> ${repo.html_url}
📜 <b>الترخيص:</b> <code>${licenseKey}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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

🔹 <b>معرف النموذج:</b> <code>${model.modelId}</code>
🔗 <b>الرابط:</b> ${`https://www.modelscope.cn/models/${model.modelId}`}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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

🔹 <b>اسم النموذج:</b> <code>${model.name}</code>
🔗 <b>الرابط:</b> https://tfhub.dev/${model.author}/${model.name}
📜 <b>الترخيص:</b> <code>${license}</code>
🏷️ <b>الكلمة المفتاحية:</b> <code>${keyword}</code>
🔍 <b>نوع المخالفة:</b> ${violationType}
⚠️ <b>درجة الخطورة:</b> ${severity}
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

🔹 <b>معرف النموذج:</b> <code>${model.id}</code>
🔗 <b>الرابط:</b> ${`https://huggingface.co/${model.id}`}
📜 <b>الترخيص:</b> <code>${model.license || 'None'}</code>
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

🔹 <b>معرف النموذج:</b> <code>${model.id}</code>
🔗 <b>الرابط:</b> ${`https://huggingface.co/${model.id}`}
🔍 <b>السبب:</b> كلمة مشبوهة: ${keyword}
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
🕵️ <b>معلومات استخبارية من ${source.source}</b>

🔍 <b>النوع:</b> ${source.type}
📌 <b>البيانات:</b> ${source.data}
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

📌 <b>اسم الملف:</b> <code>${sample.filename}</code>
🔍 <b>النوع:</b> ${sample.type}
⚠️ <b>درجة الخطورة:</b> ${sample.severity}
📝 <b>الوصف:</b> ${sample.description}
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
        await axios.post(url, item, { headers, timeout: 10000 });
      }
      return { status: 'success', message: 'Data sent to Elasticsearch.' };
    } catch (error) {
      console.error('خطأ في إرسال البيانات إلى Elasticsearch:', error.message);
      return { status: 'error', message: error.message };
    }
  } else if (siemType === 'splunk') {
    if (!siemUrl) {
      return { status: 'error', message: 'Splunk HEC URL not provided.' };
    }

    const url = `${siemUrl}/services/collector`;
    const headers = {
      'Authorization': `Splunk ${siemApiKey}`,
      'Content-Type': 'application/json'
    };

    try {
      for (const item of data) {
        await axios.post(url, item, { headers, timeout: 10000 });
      }
      return { status: 'success', message: 'Data sent to Splunk.' };
    } catch (error) {
      console.error('خطأ في إرسال البيانات إلى Splunk:', error.message);
      return { status: 'error', message: error.message };
    }
  } else {
    return { status: 'error', message: `Unsupported SIEM type: ${siemType}` };
  }
}

// بدء واجهة ويب
function startWebInterface() {
  app.get('/', (req, res) => {
    db.all(`SELECT * FROM violations ORDER BY detected_at DESC`, (err, violations) => {
      if (err) {
        console.error('خطأ في جلب البيانات:', err.message);
        return res.status(500).send('خطأ في قاعدة البيانات');
      }

      db.get(`SELECT COUNT(*) as count FROM violations WHERE entity_type = 'model'`, (err, row) => {
        const modelCount = row.count;
        db.get(`SELECT COUNT(*) as count FROM violations WHERE entity_type = 'repo'`, (err, row) => {
          const repoCount = row.count;
          db.get(`SELECT COUNT(*) as count FROM violations WHERE status = 'تم الإبلاغ'`, (err, row) => {
            const reportedCount = row.count;

            const html = `
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <title>لوحة تحكم - أداة مسح نماذج البرمجة</title>
                <style>
                    body { font-family: 'Arial', 'Segoe UI', sans-serif; text-align: right; direction: rtl; padding: 20px; background-color: #f9f9f9; }
                    .header { background-color: #333; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                    .stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
                    .stat-box { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; flex: 1; margin: 0 10px; }
                    .stat-number { font-size: 24px; font-weight: bold; color: #d9534f; }
                    .stat-label { color: #666; font-size: 14px; }
                    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background-color: white; }
                    th, td { border: 1px solid #ddd; padding: 12px; text-align: right; }
                    th { background-color: #f2f2f2; color: #333; }
                    .critical { background-color: #ffcccc; }
                    .high { background-color: #ffdddd; }
                    .medium { background-color: #fff3cd; }
                    .low { background-color: #d4edda; }
                    a { color: #337ab7; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    .severity { font-weight: bold; }
                    .critical-severity { color: #d9534f; }
                    .high-severity { color: #f0ad4e; }
                    .medium-severity { color: #ffc107; }
                    .low-severity { color: #5cb85c; }
                    .status { padding: 5px 10px; border-radius: 3px; font-size: 12px; }
                    .status-reported { background-color: #d4edda; color: #155724; }
                    .status-not-reported { background-color: #fff3cd; color: #856404; }
                    .actions { margin-top: 10px; }
                    .btn { padding: 5px 10px; margin: 0 5px; border: none; border-radius: 3px; cursor: pointer; }
                    .btn-report { background-color: #28a745; color: white; }
                    .btn-ignore { background-color: #dc3545; color: white; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>لوحة تحكم - أداة مسح نماذج البرمجة</h1>
                    <p>مراقبة المخالفات المكتشفة</p>
                </div>

                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">${modelCount}</div>
                        <div class="stat-label">نماذج مشبوهة</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${repoCount}</div>
                        <div class="stat-label">مستودعات مشبوهة</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${reportedCount}</div>
                        <div class="stat-label">تم الإبلاغ عنها</div>
                    </div>
                </div>

                <h2>قائمة المخالفات (${violations.length})</h2>
                <table>
                    <tr>
                        <th>النوع</th>
                        <th>المعرف</th>
                        <th>الترخيص</th>
                        <th>نوع المخالفة</th>
                        <th>درجة الخطورة</th>
                        <th>الحالة</th>
                        <th>الرابط</th>
                        <th>تاريخ الكشف</th>
                        <th>الإجراءات</th>
                    </tr>
                    ${violations.map(violation => `
                    <tr class="${violation.severity}">
                        <td>${violation.entity_type}</td>
                        <td>${violation.entity_name}</td>
                        <td>${violation.license}</td>
                        <td>${violation.violation_type}</td>
                        <td class="severity ${violation.severity}-severity">${violation.severity}</td>
                        <td><span class="status status-${violation.status}">${violation.status}</span></td>
                        <td><a href="${violation.url}" target="_blank">رابط</a></td>
                        <td>${violation.detected_at}</td>
                        <td class="actions">
                            <button class="btn btn-report" onclick="reportViolation('${violation.entity_type}', '${violation.entity_id}')">إبلاغ</button>
                            <button class="btn btn-ignore" onclick="ignoreViolation('${violation.entity_type}', '${violation.entity_id}')">تجاهل</button>
                        </td>
                    </tr>
                    `).join('')}
                </table>

                <script>
                    function reportViolation(entityType, entityId) {
                        fetch('/report', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ entity_type: entityType, entity_id: entityId })
                        }).then(response => response.json()).then(data => {
                            alert(data.message);
                            location.reload();
                        });
                    }

                    function ignoreViolation(entityType, entityId) {
                        fetch('/ignore', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ entity_type: entityType, entity_id: entityId })
                        }).then(response => response.json()).then(data => {
                            alert(data.message);
                            location.reload();
                        });
                    }
                </script>
            </body>
            </html>
            `;
            res.send(html);
          });
        });
      });
    });
  });

  app.post('/report', (req, res) => {
    const { entity_type, entity_id } = req.body;
    updateReportStatus(entity_type, entity_id, 'تم الإبلاغ')
      .then(result => res.json(result))
      .catch(err => res.status(500).json({ status: 'error', message: err.message }));
  });

  app.post('/ignore', (req, res) => {
    const { entity_type, entity_id } = req.body;
    updateReportStatus(entity_type, entity_id, 'مُتجاهل')
      .then(result => res.json(result))
      .catch(err => res.status(500).json({ status: 'error', message: err.message }));
  });

  app.listen(PORT, () => {
    console.log(`[+] واجهة ويب تعمل على http://0.0.0.0:${PORT}`);
  });
}

// دالة لتشغيل جميع الميزات
async function runAllFeatures(config) {
  // إرسال إشعار بداية المسح
  await sendTelegramText('🔍 <b>بدأ مسح نماذج البرمجة...</b>');

  const suspiciousModels = [];
  const suspiciousRepos = [];
  const suspiciousServers = [];

  // تشغيل جميع ميزات المسح
  if (config.huggingface) {
    console.log('[+] مسح Hugging Face...');
    const models = await scanHuggingFace(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.github) {
    console.log('[+] مسح GitHub...');
    const repos = await scanGitHub(config.limit);
    suspiciousRepos.push(...repos);
  }

  if (config.modelscope) {
    console.log('[+] مسح ModelScope...');
    const models = await scanModelScope(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.civitai) {
    console.log('[+] مسح CivitAI...');
    const models = await scanCivitAI(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.replicate) {
    console.log('[+] مسح Replicate...');
    const models = await scanReplicate(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.tensorflowHub) {
    console.log('[+] مسح TensorFlow Hub...');
    const models = await scanTensorFlowHub(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.noLicense) {
    console.log('[+] مسح نماذج بدون ترخيص...');
    const models = await scanNoLicense(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.stolen) {
    console.log('[+] مسح نماذج مسروقة...');
    const models = await scanStolenModels(config.limit);
    suspiciousModels.push(...models);
  }

  if (config.darkwebOsint) {
    console.log('[+] محاكاة تحليل Dark Web OSINT...');
    await simulateDarkWebOSINT();
  }

  if (config.malwareAnalysis) {
    console.log('[+] محاكاة تحليل Malware...');
    await simulateMalwareAnalysis();
  }

  // حفظ النتائج في قاعدة البيانات
  await saveToDatabase(suspiciousModels, suspiciousRepos, suspiciousServers);

  // إرسال التقرير النصي إلى تليجرام
  await sendTextReportToTelegram(suspiciousModels, suspiciousRepos, suspiciousServers);

  // إرسال البيانات إلى SIEM إذا تم تحديده
  if (config.siem) {
    console.log(`[+] إرسال البيانات إلى ${config.siem}...`);
    const siemData = [];
    for (const model of suspiciousModels) {
      siemData.push({
        '@timestamp': new Date().toISOString(),
        entity_type: 'model',
        entity_id: model.id,
        entity_name: model.name || model.id,
        license: model.license,
        url: model.url,
        violation_type: model.violation_type,
        severity: model.severity,
        platform: model.platform
      });
    }
    for (const repo of suspiciousRepos) {
      siemData.push({
        '@timestamp': new Date().toISOString(),
        entity_type: 'repo',
        entity_id: repo.name,
        entity_name: repo.name,
        license: repo.license,
        url: repo.url,
        violation_type: repo.violation_type,
        severity: repo.severity,
        platform: repo.platform
      });
    }
    await sendToSIEM(siemData, config.siem, config.siemUrl, config.siemApiKey);
  }

  // إرسال إشعار نهاية المسح
  await sendTelegramText(
    `✅ <b>تم الانتهاء من مسح نماذج البرمجة.</b>\n\n` +
    `📊 <b>عدد النماذج المخالفة:</b> <code>${suspiciousModels.length}</code>\n` +
    `📂 <b>عدد المستودعات المخالفة:</b> <code>${suspiciousRepos.length}</code>\n` +
    `🖥️ <b>عدد الخادمات غير الآمنة:</b> <code>${suspiciousServers.length}</code>`
  );

  // عرض إرشادات للإبلاغ
  console.log('\n[+] إرشادات للإبلاغ عن المخالفات:');
  for (const [platform, info] of Object.entries(botConfig.reporting_guidelines)) {
    console.log(`\n${platform}:`);
    if (info.url) {
      console.log(`  - البرنامج: ${info.url}`);
      console.log(`  - المكافأة: ${info.reward || 'غير محدد'}`);
    } else {
      for (const [key, value] of Object.entries(info)) {
        console.log(`  - ${key}: ${value}`);
      }
    }
  }

  // بدء واجهة ويب إذا تم تحديدها
  if (config.web) {
    startWebInterface();
  }

  // بدء الجدولة إذا تم تحديدها
  if (config.schedule) {
    console.log(`[+] بدء جدولة المسح التلقائي كل ${config.schedule} ساعات...`);
    schedule.scheduleJob(`every ${config.schedule} hours`, async () => {
      console.log(`[+] بدء المسح التلقائي في ${new Date()}`);
      await runAllFeatures(config);
    });
  }
}

// دالة لاستقبال أوامر البوت
async function handleTelegramCommands() {
  if (!TELEGRAM_BOT_TOKEN) {
    console.error('TELEGRAM_BOT_TOKEN غير مضبوط.');
    return;
  }

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates`;
  let lastUpdateId = 0;

  setInterval(async () => {
    try {
      const response = await axios.get(url, {
        params: { offset: lastUpdateId + 1, timeout: 10000 }
      });

      const updates = response.data.result;
      for (const update of updates) {
        lastUpdateId = update.update_id;
        const message = update.message;
        const chatId = message.chat.id;
        const text = message.text;

        if (!text) continue;

        // البحث عن الأمر في botConfig
        const command = botConfig.commands.find(cmd => `/${cmd.command}` === text);

        if (command) {
          // إرسال الاستجابة المخصصة للأمر
          await sendTelegramText(command.response, chatId);

          // تنفيذ الإجراء المخصص للأمر (إذا كان هناك)
          if (command.action) {
            const config = {
              ...command.action,
              limit: 20,
              web: false,
              schedule: false,
              siem: false,
              telegramChatId: chatId
            };
            await runAllFeatures(config);
          }
        } else if (text === '/help') {
          // عرض قائمة الأوامر مع شرح
          showHelp(chatId);
        } else if (text === '/report') {
          // عرض آخر 5 مخالفات
          db.all(`SELECT * FROM violations ORDER BY detected_at DESC LIMIT 5`, (err, violations) => {
            if (err || !violations.length) {
              sendTelegramText(`❌ <b>لا يوجد مخالفات مسجلة.</b>`, chatId);
              return;
            }

            let report = `📄 <b>آخر 5 مخالفات:</b>\n\n`;
            for (const violation of violations) {
              report += `📌 <b>النوع:</b> ${violation.entity_type}\n`;
              report += `🔹 <b>المعرف:</b> <code>${violation.entity_name}</code>\n`;
              report += `📜 <b>الترخيص:</b> <code>${violation.license}</code>\n`;
              report += `🔍 <b>نوع المخالفة:</b> ${violation.violation_type}\n`;
              report += `⚠️ <b>درجة الخطورة:</b> ${violation.severity}\n`;
              report += `📅 <b>تاريخ الكشف:</b> ${violation.detected_at}\n\n`;
            }
            sendTelegramText(report, chatId);
          });
        } else if (text === '/stats') {
          // عرض إحصائيات
          db.get(`SELECT COUNT(*) as count FROM violations WHERE entity_type = 'model'`, (err, row) => {
            const modelCount = row.count;
            db.get(`SELECT COUNT(*) as count FROM violations WHERE entity_type = 'repo'`, (err, row) => {
              const repoCount = row.count;
              db.get(`SELECT COUNT(*) as count FROM violations WHERE status = 'تم الإبلاغ'`, (err, row) => {
                const reportedCount = row.count;
                sendTelegramText(
                  `📊 <b>إحصائيات المخالفات:</b>\n\n` +
                  `🔹 نماذج مشبوهة: <code>${modelCount}</code>\n` +
                  `📂 مستودعات مشبوهة: <code>${repoCount}</code>\n` +
                  `✅ تم الإبلاغ عنها: <code>${reportedCount}</code>`,
                  chatId
                );
              });
            });
          });
        } else if (text === '/web') {
          await sendTelegramText(
            `🌐 <b>واجهة ويب تعمل على:</b> http://${process.env.HOST || 'localhost'}:${PORT}\n` +
            `يمكنك فتح هذا الرابط في متصفحك.`,
            chatId
          );
          startWebInterface();
        } else if (text.startsWith('/schedule_on')) {
          const hours = parseInt(text.split(' ')[1]);
          if (isNaN(hours) || hours <= 0) {
            await sendTelegramText(`❌ <b>الرجاء تحديد عدد الساعات (مثال: /schedule_on 24).</b>`, chatId);
            break;
          }
          await sendTelegramText(`⏰ <b>تم تفعيل الجدولة التلقائية كل ${hours} ساعات.</b>`, chatId);
          schedule.scheduleJob(`every ${hours} hours`, async () => {
            console.log(`[+] بدء المسح التلقائي في ${new Date()}`);
            await runAllFeatures({
              huggingface: true,
              github: true,
              modelscope: true,
              civitai: true,
              replicate: true,
              tensorflowHub: true,
              noLicense: true,
              stolen: true,
              darkwebOsint: true,
              malwareAnalysis: true,
              limit: 20,
              web: false,
              schedule: false,
              siem: false,
              telegramChatId: chatId
            });
          });
        } else if (text === '/schedule_off') {
          await sendTelegramText(`⏹️ <b>تم إيقاف الجدولة التلقائية.</b>`, chatId);
          schedule.gracefulShutdown();
        } else if (text.startsWith('/siem_on')) {
          const siemArgs = text.split(' ');
          if (siemArgs.length < 3) {
            await sendTelegramText(
              `❌ <b>الرجاء تحديد نوع SIEM ورابطه (مثال: /siem_on elk http://your-elasticsearch:9200).</b>`,
              chatId
            );
            break;
          }
          const siemType = siemArgs[1];
          const siemUrl = siemArgs[2];
          await sendTelegramText(
            `🔗 <b>تم تفعيل إرسال البيانات إلى ${siemType} على ${siemUrl}.</b>`,
            chatId
          );
          // هنا يمكنك تحديث إعدادات SIEM في الكود
        } else if (text === '/siem_off') {
          await sendTelegramText(`🔗 <b>تم إيقاف إرسال البيانات إلى SIEM.</b>`, chatId);
        } else {
          await sendTelegramText(`❌ <b>أمر غير معروف. استخدم /help لعرض قائمة الأوامر.</b>`, chatId);
        }
      }
    } catch (error) {
      console.error('خطأ في استلام التحديثات:', error.message);
    }
  }, 5000); // التحقق كل 5 ثوان
}

// الدالة الرئيسية
async function main() {
  const args = yargs(hideBin(process.argv))
    .option('all', {
      describe: 'تشغيل جميع المنصات (Hugging Face, GitHub, ModelScope, CivitAI, Replicate, TensorFlow Hub).',
      type: 'boolean',
      default: false
    })
    .option('huggingface', {
      describe: 'مسح Hugging Face بحثًا عن نماذج برمجة مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('github', {
      describe: 'مسح GitHub بحثًا عن مستودعات برمجة مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('modelscope', {
      describe: 'مسح ModelScope بحثًا عن نماذج برمجة مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('civitai', {
      describe: 'مسح CivitAI بحثًا عن نماذج مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('replicate', {
      describe: 'مسح Replicate بحثًا عن نماذج مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('tensorflow-hub', {
      describe: 'مسح TensorFlow Hub بحثًا عن نماذج مخالفة.',
      type: 'boolean',
      default: false
    })
    .option('no-license', {
      describe: 'مسح نماذج برمجة بدون ترخيص.',
      type: 'boolean',
      default: false
    })
    .option('stolen', {
      describe: 'مسح نماذج برمجة مسروقة.',
      type: 'boolean',
      default: false
    })
    .option('darkweb-osint', {
      describe: 'محاكاة تحليل Dark Web OSINT.',
      type: 'boolean',
      default: false
    })
    .option('malware-analysis', {
      describe: 'محاكاة تحليل Malware.',
      type: 'boolean',
      default: false
    })
    .option('limit', {
      describe: 'حد عدد النتائج لكل كلمة مفتاحية.',
      type: 'number',
      default: 20
    })
    .option('web', {
      describe: 'بدء واجهة ويب لعرض النتائج.',
      type: 'boolean',
      default: false
    })
    .option('schedule', {
      describe: 'جدولة المسح التلقائي كل X ساعات.',
      type: 'number'
    })
    .option('siem', {
      describe: 'إرسال البيانات إلى SIEM (elk أو splunk).',
      type: 'string',
      choices: ['elk', 'splunk']
    })
    .option('siem-url', {
      describe: 'رابط SIEM.',
      type: 'string'
    })
    .option('siem-api-key', {
      describe: 'مفتاح API لـ SIEM.',
      type: 'string'
    })
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

  // بدء استلام أوامر البوت
  handleTelegramCommands();

  // تشغيل جميع الميزات إذا تم تحديدها من سطر الأوامر
  if (args.all || Object.values(args).some(v => v === true)) {
    runAllFeatures(config).catch(err => {
      console.error('خطأ في تشغيل الأداة:', err.message);
    });
  }
}

// بدء الأداة
main().catch(err => {
  console.error('خطأ في بدء الأداة:', err.message);
});

// التعامل مع إغلاق البرنامج
process.on('SIGINT', () => {
  console.log('\n[!] يتم إغلاق الأداة...');
  db.close();
  process.exit(0);
});
