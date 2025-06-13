require('dotenv').config();
const { query } = require('./database');
const sendWhatsAppMessage = require('./whatsapp');

async function notifyExpiringAdmins() {
  try {
    const admins = await query(`
      SELECT 
        u.id AS admin_id, 
        u.name AS admin_name, 
        u.phone_number, 
        s.end_date AS subscription_end
      FROM admin_subscriptions s
      JOIN users u ON s.admin_id = u.id
      WHERE s.status = 'active'
        AND s.end_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 10 DAY)
    `);

    for (const admin of admins) {
      const message = `
أهلاً ${admin.admin_name} 👋،

نود إعلامك بأن اشتراكك سينتهي بتاريخ ${admin.subscription_end} 📅.
يرجى التواصل مع الإدارة لتجديد الاشتراك.

شكرًا لاستخدام منصتنا 🌟
`.trim();

      const formattedPhone = admin.phone_number.replace('+', '');

      await sendWhatsAppMessage(formattedPhone, message);
      console.log(`✅ تم إرسال تنبيه انتهاء الاشتراك إلى ${admin.admin_name}`);
    }

    console.log('🎉 تم الانتهاء من إرسال جميع التنبيهات بنجاح.');

  } catch (err) {
    console.error('❌ خطأ في إرسال إشعارات انتهاء الاشتراكات:', err);
  }
}

notifyExpiringAdmins();
