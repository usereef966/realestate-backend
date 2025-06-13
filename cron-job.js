const cron = require('node-cron');
const { exec } = require('child_process');

// كل يوم الساعة 9 صباحًا (بتوقيت السيرفر)
cron.schedule('0 9 * * *', () => {
  exec('node notify-expiring-tenants.js', (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ خطأ في تنفيذ السكربت: ${stderr}`);
    } else {
      console.log(`✅ تم تشغيل السكربت بنجاح: ${stdout}`);
    }
  });
});

console.log('🔄 تم بدء مهمة الجدولة بنجاح...');
