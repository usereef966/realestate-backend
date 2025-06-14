const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();
const fetch = require('node-fetch');
const pdfParse = require('pdf-parse');

const PDFDocument = require('pdfkit');


const { pool, query } = require('./database');



const app = express();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
app.use(express.json());
app.use(cors());




function formatInternationalPhoneNumber(phone) {
  phone = phone.replace(/\D/g, '').trim();

  // Saudi Arabia
  if ((phone.startsWith('05') && phone.length === 10) ||
      (phone.startsWith('9665') && phone.length === 12) ||
      (phone.startsWith('5') && phone.length === 9)) {
    return '+966' + phone.slice(-9);
  }

  // Turkey
  if ((phone.startsWith('05') && phone.length === 11) ||
      (phone.startsWith('905') && phone.length === 12) ||
      (phone.startsWith('5') && phone.length === 10)) {
    return '+90' + phone.slice(-10);
  }

  // Already correct international format
  if ((phone.startsWith('+966') && phone.length === 13) ||
      (phone.startsWith('+90') && phone.length === 13)) {
    return phone;
  }

  throw new Error('صيغة رقم الهاتف غير صحيحة: ' + phone);
}


// اتصال Pool يدير الاتصال تلقائيًا



// تجهيز multer لحفظ الملفات


// JWT Middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'لا يوجد توكن، تم رفض الوصول' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'توكن غير صالح أو منتهي الصلاحية' });
    }

    // ✅ أضف فقط السطرين التاليين:
    req.user = {
      userId: decoded.userId,     // لن يتأثر نظامك الحالي نهائيًا
      userType: decoded.userType, // لن يتأثر نظامك الحالي نهائيًا
      id: decoded.id              // 👈 فقط أضف هذا
    };

    next();
  });
}

const sendWhatsAppMessage = require('./whatsapp');



const cron = require('node-cron');
const { exec } = require('child_process');

// شغل السكربت يوميًا الساعة 9 صباحًا
cron.schedule('0 9 * * *', () => {
  exec('node notify-expiring-tenants.js', (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ خطأ في تشغيل السكربت التلقائي: ${stderr}`);
    } else {
      console.log(`✅ تم تشغيل السكربت التلقائي بنجاح: ${stdout}`);
    }
  });
});

console.log('🔄 تم تفعيل التشغيل التلقائي للسكربتات بنجاح.');



// Login Endpoint (بدون حماية)
app.post('/api/login', async (req, res) => {
  const { userId, token } = req.body;

  try {
    const results = await query(
      'SELECT id, user_id, name, user_type FROM users WHERE user_id = ? AND token = ?',
      [userId, token]
    );

    if (results.length === 0) {
      return res.status(401).json({ message: 'بيانات الدخول غير صحيحة' });
    }

    const user = results[0];

    if (user.user_type === 'admin') {
      const subResults = await query(
        `SELECT 1 FROM admin_subscriptions WHERE admin_id = ? AND end_date >= CURDATE() LIMIT 1`,
        [user.id]
      );

      if (subResults.length === 0) {
        return res.status(403).json({ message: 'انتهى اشتراك المالك أو غير موجود' });
      }

      return sendLoginSuccess(res, user);
    }

    if (user.user_type === 'viewer') { // 👈 إضافة التحقق من viewer هنا
      const subResults = await query(
        `SELECT 1 FROM admin_subscriptions WHERE admin_id = ? AND end_date >= CURDATE() LIMIT 1`,
        [user.id]
      );

      if (subResults.length === 0) {
        return res.status(403).json({ message: 'انتهى اشتراك الـ Viewer أو غير موجود' });
      }

      return sendLoginSuccess(res, user);
    }

    if (user.user_type === 'user') {
      const contractResults = await query(
        `SELECT 1 FROM rental_contracts WHERE tenant_id = ? AND contract_end >= CURDATE() LIMIT 1`,
        [user.id]
      );

      if (contractResults.length === 0) {
        return res.status(403).json({ message: 'انتهى عقد المستأجر أو غير موجود' });
      }

      return sendLoginSuccess(res, user);
    }

    if (user.user_type === 'super') {
      return sendLoginSuccess(res, user);
    }

    return res.status(403).json({ message: 'نوع مستخدم غير مدعوم' });

  } catch (err) {
    console.error('❌ Login Error:', err);
    return res.status(500).json({ message: 'خطأ داخلي في الخادم' });
  }
});


// دالة مساعدة لإرسال الرد الناجح وتوليد التوكن
function sendLoginSuccess(res, user) {
  const jwtToken = jwt.sign(
    {
      userId: user.user_id,
      name: user.name,
      userType: user.user_type,
      id: user.id
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    message: 'تم تسجيل الدخول بنجاح',
    token: jwtToken,
    user: {
      userId: user.user_id,
      name: user.name,
      userType: user.user_type,
      id: user.id // أضف id هنا لتسهيل الوصول إليه في المستقبل
    },
  });
}










// جميع ما يلي محمي بـ JWT
app.post('/api/validate-admin', verifyToken, async (req, res) => {
  const { userId } = req.body;

  const sql = `
    SELECT u.user_id, s.end_date 
    FROM users u
    INNER JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.user_id = ? AND s.end_date >= CURDATE();
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.json({ valid: false });
    }

    res.json({ valid: true });

  } catch (err) {
    console.error('❌ Validate-admin Error:', err);
    res.status(500).json({ valid: false });
  }
});

app.post('/api/validate-session', verifyToken, async (req, res) => {
  const { userId } = req.body;

  const sql = `SELECT user_id FROM users WHERE user_id = ? AND user_type='super' LIMIT 1`;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.json({ valid: false });
    }

    res.json({ valid: true });

  } catch (err) {
    console.error('❌ Validate-session Error:', err);
    res.status(500).json({ valid: false });
  }
});




app.post('/api/validate-user', verifyToken, async (req, res) => {
  const { userId } = req.body;

  const sql = `
    SELECT u.user_id, r.contract_end
    FROM users u
    INNER JOIN rental_contracts r ON u.id = r.tenant_id
    WHERE u.user_id = ? AND r.contract_end >= CURDATE();
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.json({ valid: false });
    }

    res.json({ valid: true });

  } catch (err) {
    console.error('❌ Validate-user Error:', err);
    res.status(500).json({ valid: false });
  }
});


app.post('/api/validate-viewer', verifyToken, async (req, res) => {
  const { userId } = req.body;

  try {
    const [user] = await query(`
      SELECT u.user_id
      FROM users u
      JOIN admin_subscriptions s ON s.admin_id = u.id
      WHERE u.user_id = ? AND u.user_type = 'viewer' AND s.status = 'active' AND s.end_date >= CURDATE()
    `, [userId]);

    if (user) {
      return res.json({ valid: true });
    }

    res.json({ valid: false });
  } catch (error) {
    console.error(error);
    res.status(500).json({ valid: false, error });
  }
});



app.put('/api/admin/update-name', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;
  const { name } = req.body;

  if (userType !== 'admin' && userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط المالك أو السوبر يمكنه تعديل الاسم' });
  }

  if (!name || !name.trim()) {
    return res.status(400).json({ message: '❗ الاسم الجديد مطلوب' });
  }

  try {
    await query('UPDATE users SET name = ? WHERE id = ?', [name.trim(), adminId]);
    res.json({ message: '✅ تم تحديث اسم المالك بنجاح' });
  } catch (err) {
    console.error('❌ Update-admin-name Error:', err);
    res.status(500).json({ message: 'فشل في تحديث الاسم', error: err });
  }
});



app.get('/api/admin-token-count/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  try {
    const [row] = await query(
      'SELECT COUNT(*) AS count FROM admin_tokens WHERE created_by = ?',
      [adminId]
    );
    res.json({ count: row.count });
  } catch (err) {
    res.status(500).json({ message: 'DB Error', error: err });
  }
});





app.post('/api/get-admin-details', verifyToken, async (req, res) => {
  const { userId } = req.body;

  const sql = `
    SELECT 
      u.user_id, 
      u.name, 
      u.user_type, 
      u.viewer_id,
      s.subscription_type,
      s.start_date,
      s.end_date,
      s.status
    FROM users u
    INNER JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.id = ?;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    const admin = results[0];

    // تحديد الارتباط بشكل واضح
    const isLinkedToViewer = admin.viewer_id !== null;

    res.json({ 
      admin: {
        user_id: admin.user_id,
        name: admin.name,
        user_type: admin.user_type,
        linked_viewer_id: admin.viewer_id,
        subscription_type: admin.subscription_type,
        start_date: admin.start_date,
        end_date: admin.end_date,
        status: admin.status,
        isLinkedToViewer
      } 
    });

  } catch (err) {
    console.error('❌ Get-admin-details Error:', err);
    res.status(500).json({ message: 'خطأ داخلي في الخادم' });
  }
});



app.get('/api/admin-token/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  const sql = 'SELECT token FROM users WHERE id = ?';
  try {
    const [row] = await query(sql, [adminId]);
    if (!row) return res.status(404).json({ message: 'المالك غير موجود' });
    res.json({ token: row.token });
  } catch (err) {
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.post('/api/generate-admin-token', verifyToken, async (req, res) => {
  const { permissions, created_by } = req.body;

  const token = Math.floor(10000000 + Math.random() * 90000000).toString(); // ⬅️ توكن 8 أرقام

  const sql = `
    INSERT INTO admin_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE token = VALUES(token), permissions = VALUES(permissions)
  `;

  try {
    await query(sql, [token, JSON.stringify(permissions), created_by]);
    res.json({ token, permissions });
  } catch (err) {
    console.error('❌ Generate-admin-token Error:', err);
    res.status(500).json({ error: 'فشل في إنشاء توكن المالك' });
  }
});


app.post('/api/generate-user-token', verifyToken, async (req, res) => {
  const { permissions, created_by } = req.body;

  const token = Math.floor(10000000 + Math.random() * 90000000).toString(); // ⬅️ توكن 8 أرقام


  const sql = `
    INSERT INTO user_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

  try {
    await query(sql, [token, JSON.stringify(permissions), created_by]);
    res.json({ token, permissions });
  } catch (err) {
    console.error('❌ Generate-user-token Error:', err);
    res.status(500).json({ error: 'فشل في إنشاء توكن المستأجر' });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////// Create Admin Functions /////

app.post('/api/create-admin', verifyToken, async (req, res) => {
  const { userType, id: created_by } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إنشاء مالك.' });
  }

  const { user_id, name, phone_number, email, subscription_type, tenant_limit, permissions = {} } = req.body;

  if (!user_id || !name || !phone_number || !subscription_type || tenant_limit === undefined) {
    return res.status(400).json({ message: '❗ الحقول user_id, name, phone_number, subscription_type, tenant_limit مطلوبة.' });
  }

  if (!/^[0-9]+$/.test(user_id)) {
    return res.status(400).json({ message: '❗ user_id يجب أن يكون أرقام فقط.' });
  }

  // ✅ التحقق الجديد من تكرار user_id
  const existingUserCheck = await query(`SELECT id FROM users WHERE user_id = ? LIMIT 1`, [user_id]);
  if (existingUserCheck.length > 0) {
    return res.status(400).json({ message: '❗ رقم المستخدم (user_id) موجود بالفعل، الرجاء اختيار رقم مختلف.' });
  }

  const token = Math.floor(10000000 + Math.random() * 90000000).toString();

  let subscription_start_date = new Date();
  let subscription_end_date;

  if (subscription_type === 'monthly') {
    subscription_end_date = new Date(subscription_start_date);
    subscription_end_date.setMonth(subscription_end_date.getMonth() + 1);
  } else if (subscription_type === 'yearly') {
    subscription_end_date = new Date(subscription_start_date);
    subscription_end_date.setFullYear(subscription_end_date.getFullYear() + 1);
  } else {
    return res.status(400).json({ message: '❗ نوع الاشتراك غير صالح (monthly, yearly).' });
  }

  const startDateSql = subscription_start_date.toISOString().slice(0,10);
  const endDateSql = subscription_end_date.toISOString().slice(0,10);

  const insertUserSql = `
    INSERT INTO users (user_id, name, user_type, token, phone_number, created_by, created_at)
    VALUES (?, ?, 'admin', ?, ?, ?, NOW())
  `;

  const insertTokenSql = `
    INSERT INTO admin_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

const insertSubscriptionSql = `
  INSERT INTO admin_subscriptions (admin_id, start_date, end_date, status, tenant_limit, subscription_type)
  VALUES (?, ?, ?, 'active', ?, ?)
`;

  

  try {
    const userResult = await query(insertUserSql, [user_id, name, token, phone_number, created_by]);
    const adminId = userResult.insertId;

    await query(insertTokenSql, [token, JSON.stringify(permissions), created_by]);
    await query(insertSubscriptionSql, [adminId, startDateSql, endDateSql, tenant_limit, subscription_type]);
    // إدراج سجل review_permissions مباشرة بعد إنشاء المستخدم
await query(`
  INSERT INTO review_permissions (admin_id, enabled) VALUES (?, 1)
`, [adminId]);


    // ✅ إرسال رسالة WhatsApp
    const formattedPhone = phone_number.replace('+', '');
    const whatsappMessage = `
    أهلاً ${name} 👋،

    تم إنشاء حسابك بنجاح 🎉

    تفاصيل اشتراكك:
    - نوع الاشتراك: ${subscription_type === 'monthly' ? 'شهري' : 'سنوي'}
    - بداية الاشتراك: ${startDateSql}
    - نهاية الاشتراك: ${endDateSql}
    - عدد المستأجرين المسموح لك إضافتهم: ${tenant_limit}

    رمز الدخول الخاص بك: ${token}

    شكرًا لاستخدام منصتنا 🌟
    `;

    await sendWhatsAppMessage(formattedPhone, whatsappMessage.trim());

    res.json({
      message: '✅ تم إنشاء المالك والتوكن والاشتراك وإرسال تفاصيل الاشتراك بنجاح.',
      adminId,
      token,
      subscription_start_date: startDateSql,
      subscription_end_date: endDateSql,
      tenant_limit
    });

  } catch (err) {
    console.error('❌ Create-admin Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء المالك أو التوكن أو الاشتراك أو إرسال الرسالة.' });
  }
});


app.get('/api/active-subscriptions', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول لهذه البيانات.' });
  }

  const sql = `
    SELECT 
      u.id AS admin_id,
      u.name,
      u.user_id,
      u.phone_number,
      s.start_date,
      s.end_date,
      s.tenant_limit
    FROM admin_subscriptions s
    JOIN users u ON s.admin_id = u.id
    WHERE s.status = 'active'
      AND s.end_date >= CURDATE()
      AND u.user_type = 'admin'
      AND u.viewer_id IS NULL
    ORDER BY s.end_date ASC
  `;

  try {
    const activeSubscriptions = await query(sql);
    
    res.json({ 
      activeSubscriptionsCount: activeSubscriptions.length,
      subscriptions: activeSubscriptions 
    });

  } catch (err) {
    console.error('❌ Error fetching active subscriptions:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الاشتراكات الفعالة.' });
  }
});




app.get('/api/expired-subscriptions', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول لهذه البيانات.' });
  }

  const sql = `
    SELECT 
      u.id AS admin_id,
      u.name,
      u.user_id,
      u.phone_number,
      s.start_date,
      s.end_date
    FROM admin_subscriptions s
    JOIN users u ON s.admin_id = u.id
    WHERE s.status = 'expired' OR s.end_date < CURDATE()
    ORDER BY s.end_date DESC
  `;

  try {
    const expiredSubscriptions = await query(sql);
    
    res.json({ 
      expiredSubscriptionsCount: expiredSubscriptions.length,
      subscriptions: expiredSubscriptions 
    });

  } catch (err) {
    console.error('❌ Error fetching expired subscriptions:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الاشتراكات المنتهية.' });
  }
});


app.post('/api/subscriptions/:adminId/renew', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId } = req.params;
  const { subscription_type } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه تجديد الاشتراك.' });
  }

  try {
    const [currentSub] = await query(
      `SELECT id, end_date FROM admin_subscriptions WHERE admin_id = ?`, 
      [adminId]
    );

    let currentEndDate = currentSub?.end_date ? new Date(currentSub.end_date) : new Date();

    if (currentEndDate < new Date()) {
      currentEndDate = new Date();
    }

    let newEndDate;

    if (subscription_type === 'monthly') {
      newEndDate = new Date(currentEndDate);
      newEndDate.setMonth(newEndDate.getMonth() + 1);
    } else if (subscription_type === 'yearly') {
      newEndDate = new Date(currentEndDate);
      newEndDate.setFullYear(newEndDate.getFullYear() + 1);
    } else {
      return res.status(400).json({ message: 'نوع الاشتراك غير صالح.' });
    }

    const formattedEndDate = newEndDate.toISOString().slice(0, 10);

    // تحديث اشتراك الـ Viewer
    const sql = `
      UPDATE admin_subscriptions
      SET start_date = CURDATE(), end_date = ?, status = 'active', subscription_type = ?
      WHERE admin_id = ?
    `;

    await query(sql, [formattedEndDate, subscription_type, adminId]);

    // تحديث اشتراكات الوكلاء المرتبطة بهذا الاشتراك
    const updateLinkedAgentsSql = `
      UPDATE admin_subscriptions
      SET start_date = CURDATE(), end_date = ?, status = 'active', subscription_type = ?
      WHERE linked_subscription_id = ?
    `;

    await query(updateLinkedAgentsSql, [formattedEndDate, subscription_type, currentSub.id]);

    // بيانات المستخدم لإرسال الإشعار
    const [adminData] = await query(`SELECT name, phone_number FROM users WHERE id = ?`, [adminId]);

    if (adminData && adminData.phone_number) {
      const formattedPhone = adminData.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${adminData.name} 👋،

      تم تجديد اشتراكك بنجاح 🎉

      نوع الاشتراك الجديد: ${subscription_type === 'monthly' ? 'شهري' : 'سنوي'}
      تاريخ الانتهاء الجديد: ${formattedEndDate}

      شكرًا لاستخدام منصتنا 🌟
      `.trim();

      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({
      message: '✅ تم تجديد الاشتراك بنجاح وإرسال الإشعار، وتم تحديث اشتراكات الوكلاء المرتبطة.',
      newEndDate: formattedEndDate
    });

  } catch (error) {
    console.error('❌ Error renewing subscription:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تجديد الاشتراك.' });
  }
});



// 🔹 تحديث عدد المستأجرين المسموح لمالك منفرد (Admin)
app.post('/api/subscriptions/:adminId/update-tenant-limit', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId } = req.params;
  const { tenant_limit } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه تحديث الحد.' });
  }

  if (typeof tenant_limit !== 'number' || tenant_limit < 0) {
    return res.status(400).json({ message: '❌ عدد المستأجرين المسموح بهم غير صالح.' });
  }

  try {
    const [userCheck] = await query(
      `SELECT id FROM users WHERE id = ? AND user_type IN ('admin', 'viewer')`, 
      [adminId]
    );

    if (!userCheck) {
      return res.status(404).json({ message: '❌ لم يتم العثور على المستخدم.' });
    }

    // تحديث tenant_limit_per_agent في users
    await query(`
      UPDATE users SET tenant_limit_per_agent = ?
      WHERE id = ?
    `, [tenant_limit, adminId]);

    // تحديث tenant_limit في admin_subscriptions
    await query(`
      UPDATE admin_subscriptions SET tenant_limit = ?
      WHERE admin_id = ?
    `, [tenant_limit, adminId]);

    // تحديث اشتراكات الوكلاء المرتبطة (إذا وجد)
    const [currentSub] = await query(`SELECT id FROM admin_subscriptions WHERE admin_id = ?`, [adminId]);
    if (currentSub) {
      await query(`
        UPDATE admin_subscriptions SET tenant_limit = ?
        WHERE linked_subscription_id = ?
      `, [tenant_limit, currentSub.id]);
    }

    // بيانات المستخدم لإرسال الإشعار (اختياري)
    const [adminData] = await query(`SELECT name, phone_number FROM users WHERE id = ?`, [adminId]);

    if (adminData && adminData.phone_number) {
      const formattedPhone = adminData.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${adminData.name} 👋،

      تم تحديث عدد المستأجرين المسموح بهم بنجاح 🎉

      العدد الجديد المسموح به: ${tenant_limit}

      شكرًا لاستخدام منصتنا 🌟
      `.trim();

      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({
      message: '✅ تم تحديث عدد المستأجرين المسموح بنجاح.',
      tenant_limit
    });

  } catch (error) {
    console.error('❌ Error updating tenant limit:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث عدد المستأجرين.' });
  }
});



app.post('/api/subscriptions/:adminId/cancel', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId } = req.params;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إنهاء الاشتراك.' });
  }

  const sql = `
    UPDATE admin_subscriptions
    SET status = 'expired', end_date = CURDATE()
    WHERE admin_id = ?
  `;

  try {
    await query(sql, [adminId]);

    const [adminData] = await query(`
      SELECT name, phone_number FROM users WHERE id = ?
    `, [adminId]);

    if (adminData && adminData.phone_number) {
      const formattedPhone = adminData.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${adminData.name} 👋،

      تم إنهاء اشتراكك بنجاح.

      شكرًا لاستخدام منصتنا 🌟
      `.trim();

      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({ message: '✅ تم إنهاء الاشتراك بنجاح وإرسال الإشعار.' });
  } catch (error) {
    console.error('❌ Error cancelling subscription:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء إنهاء الاشتراك.' });
  }
});


app.get('/api/admins/active-with-tenant-count', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه رؤية التفاصيل.' });
  }

  try {
    const activeAdmins = await query(`
      SELECT 
        u.id AS admin_id,
        u.name,
        u.user_id,
        s.tenant_limit,
        (SELECT COUNT(*) 
         FROM rental_contracts rc
         JOIN users tenants ON tenants.id = rc.tenant_id
         WHERE tenants.created_by = u.id AND rc.status = 'active') AS active_tenants_count
      FROM admin_subscriptions s
      JOIN users u ON s.admin_id = u.id
      WHERE s.status = 'active' 
        AND s.end_date >= CURDATE()
        AND u.user_type = 'admin'
        AND u.viewer_id IS NULL
      ORDER BY u.name ASC
    `);

    res.json({
      active_admins_count: activeAdmins.length,
      admins: activeAdmins,
    });

  } catch (error) {
    console.error('❌ Error fetching admins:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب بيانات المالكين.' });
  }
});



app.post('/api/admins/:adminId/update-tenant-limit', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId } = req.params;
  const { tenant_limit } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  if (typeof tenant_limit !== 'number' || tenant_limit < 0) {
    return res.status(400).json({ message: '❗ يجب تحديد عدد المستأجرين المسموح بهم بشكل صحيح.' });
  }

  try {
    const [userCheck] = await query(`SELECT viewer_id FROM users WHERE id = ? AND user_type = 'admin'`, [adminId]);
    
    if (userCheck?.viewer_id !== null) {
      return res.status(400).json({ message: '❌ هذا المستخدم ليس مالكًا مستقلًا.' });
    }

    await query(`
      UPDATE admin_subscriptions SET tenant_limit = ? WHERE admin_id = ?
    `, [tenant_limit, adminId]);

    const [adminData] = await query(`
      SELECT name, phone_number FROM users WHERE id = ?
    `, [adminId]);

    if (adminData && adminData.phone_number) {
      const formattedPhone = adminData.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${adminData.name} 👋،

      تم تحديث عدد المستأجرين المسموح لك بإضافتهم 🎉
      العدد الجديد المسموح به: ${tenant_limit}

      شكرًا لاستخدام منصتنا 🌟
      `.trim();

      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({
      message: '✅ تم تحديث عدد المستأجرين للمالك المستقل بنجاح.',
      adminId,
      tenant_limit
    });

  } catch (error) {
    console.error('❌ Error updating tenant limit:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث عدد المستأجرين.' });
  }
});



app.get('/api/super/finance-6months', verifyToken, async (req, res) => {
  const { userType, id: superId } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه الوصول لهذه البيانات.' });
  }

 const sql = `
    SELECT
      IFNULL(SUM(rcd.periodic_rent_payment * 
        LEAST(
          TIMESTAMPDIFF(MONTH, GREATEST(CURDATE(), rcd.contract_start), LEAST(DATE_ADD(CURDATE(), INTERVAL 6 MONTH), rcd.contract_end))
          , 6
        )), 0) AS total_expected_income,
      COUNT(DISTINCT rcd.id) AS contracts_count
    FROM rental_contracts_details rcd
    WHERE rcd.admin_id = ?
      AND rcd.contract_end >= CURDATE()
      AND rcd.contract_start <= DATE_ADD(CURDATE(), INTERVAL 6 MONTH);
  `;

  try {
    const rows = await query(sql, [superId]);
    res.json({ six_months: rows });
  } catch (err) {
    console.error('❌ Super-finance-6months Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


app.get('/api/super/subscription-income', verifyToken, async (req, res) => {
const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  try {
    const [prices] = await query(`
      SELECT monthly_price, yearly_price FROM subscription_prices WHERE price_type = 'regular_admin' LIMIT 1
    `);

    if (!prices) {
      return res.status(400).json({ message: '❗️ لم يتم إدخال أسعار اشتراكات المالكين المستقلين بعد.' });
    }

    const subscriptions = await query(`
      SELECT s.subscription_type, s.start_date, s.end_date
      FROM admin_subscriptions s
      JOIN users u ON s.admin_id = u.id
      WHERE s.status = 'active' 
        AND s.end_date >= CURDATE()
        AND u.user_type = 'admin'
        AND u.viewer_id IS NULL
    `);

    let monthlyIncome = 0;
    let yearlyIncome = 0;

    subscriptions.forEach(sub => {
      const remainingDays = Math.ceil((new Date(sub.end_date) - new Date()) / (1000 * 60 * 60 * 24));
      if (sub.subscription_type === 'monthly') {
        monthlyIncome += (prices.monthly_price / 30) * Math.min(remainingDays, 30);
      } else if (sub.subscription_type === 'yearly') {
        yearlyIncome += (prices.yearly_price / 365) * Math.min(remainingDays, 365);
      }
    });

    res.json({
      monthly_income: monthlyIncome.toFixed(2),
      yearly_income: yearlyIncome.toFixed(2),
      total_income: (monthlyIncome + yearlyIncome).toFixed(2),
      current_prices: prices
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'DB Error', error });
  }
});



// لحفظ أسعار اشتراكات المالكين المستقلين (admins بدون viewer)
app.post('/api/super/admins/subscription-prices', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const { monthly_price, yearly_price } = req.body;

  if (monthly_price === undefined || yearly_price === undefined) {
    return res.status(400).json({ message: '❗️ يجب إدخال monthly_price و yearly_price.' });
  }

  try {
    // حفظ أو تحديث أسعار المالكين المستقلين (regular_admin)
    await query(`
      INSERT INTO subscription_prices (id, monthly_price, yearly_price, price_type) VALUES (1, ?, ?, 'regular_admin')
      ON DUPLICATE KEY UPDATE monthly_price = ?, yearly_price = ?
    `, [monthly_price, yearly_price, monthly_price, yearly_price]);

    res.json({ message: '✅ تم حفظ أسعار اشتراكات المالكين المستقلين بنجاح.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'حدث خطأ أثناء حفظ أسعار الاشتراكات.' });
  }
});









////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.post('/api/create-tenant', verifyToken, async (req, res) => {
  const { userType, id: creatorId } = req.user;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر أو المالك يمكنه إنشاء مستأجر.' });
  }

  const { user_id, name, permissions = {} } = req.body;

  if (!user_id || !name) {
    return res.status(400).json({ message: '❗ user_id و name مطلوبة.' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  const insertUserSql = `
    INSERT INTO users (user_id, name, user_type, token, created_at, created_by)
    VALUES (?, ?, 'user', ?, NOW(), ?)
  `;

  const insertTokenSql = `
    INSERT INTO user_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

  try {
    // إنشاء المستأجر
    const userResult = await query(insertUserSql, [user_id, name, token, creatorId]);

    // إنشاء توكن المستأجر
    await query(insertTokenSql, [token, JSON.stringify(permissions), creatorId]);

    res.json({
      message: '✅ تم إنشاء المستأجر والتوكن بنجاح.',
      tenantId: userResult.insertId,
      token
    });

  } catch (err) {
    console.error('❌ Create-tenant Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء المستأجر أو التوكن.' });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////Super Admin Functions///////
app.get('/api/superadmin', verifyToken, async (req, res) => {
  try {
    const result = await query("SELECT id, user_id, name, user_type FROM users WHERE user_type = 'super' LIMIT 1");

    if (result.length === 0) {
      return res.status(404).json({ message: 'No super admin found.' });
    }

    res.json(result[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server Error', error });
  }
});

// ---------------------------------------------
// Super Admin Tenants Page API Endpoints
// ---------------------------------------------

// 1. Tenant Stats
app.get('/api/super/tenant-stats', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    // جلب إحصائيات المستأجرين
    const [tenantCount] = await query(
      'SELECT COUNT(*) AS total_tenants FROM rental_contracts_details WHERE admin_id = ? AND contract_end >= CURDATE()',
      [superAdminId]
    );

    const [activeContracts] = await query(
      'SELECT COUNT(*) AS active_contracts FROM rental_contracts_details WHERE admin_id = ? AND contract_end >= CURDATE()',
      [superAdminId]
    );

    const [expiredContracts] = await query(
      'SELECT COUNT(*) AS expired_contracts FROM rental_contracts_details WHERE admin_id = ? AND contract_end < CURDATE()',
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_total_tenants, last_active_contracts, last_expired_contracts) VALUES (?, ?, ?, ?)`,
        [superAdminId, tenantCount.total_tenants, activeContracts.active_contracts, expiredContracts.expired_contracts]
      );
      cache = {
        last_total_tenants: 0,
        last_active_contracts: 0,
        last_expired_contracts: 0
      };
    }

    // جلب FCM Token الخاص بالسوبر الحالي
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد أي رقم
    let shouldNotify = false;
    if (
      tenantCount.total_tenants > (cache.last_total_tenants || 0) ||
      activeContracts.active_contracts > (cache.last_active_contracts || 0) ||
      expiredContracts.expired_contracts > (cache.last_expired_contracts || 0)
    ) {
      shouldNotify = true;
    }

    // إذا لازم إشعار، أرسل الإشعار وحدث القيم
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'تحديث إحصائيات المستأجرين',
            body: `تم استعراض إحصائيات المستأجرين لديك: ${tenantCount.total_tenants} مستأجر`
          },
          data: {
            screen: 'tenant-stats'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث القيم في الجدول
      await query(
        `UPDATE super_stats_cache SET last_total_tenants = ?, last_active_contracts = ?, last_expired_contracts = ? WHERE super_id = ?`,
        [
          tenantCount.total_tenants,
          activeContracts.active_contracts,
          expiredContracts.expired_contracts,
          superAdminId
        ]
      );
    }

    // إرسال النتائج النهائية
    res.json({
      total_tenants: tenantCount.total_tenants,
      active_contracts: activeContracts.active_contracts,
      expired_contracts: expiredContracts.expired_contracts,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching tenant stats' });
  }
});


// 2. Tenant Reports (Payment Status)
app.get('/api/super/tenant-reports', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const paymentStatusReport = await query(
      `SELECT p.payment_status, COUNT(*) AS count 
       FROM payments p 
       JOIN rental_contracts_details rcd ON p.contract_id = rcd.id 
       WHERE rcd.admin_id = ? AND rcd.contract_end >= CURDATE()
       GROUP BY p.payment_status`,
      [superAdminId]
    );

    const totalReports = paymentStatusReport.reduce((sum, row) => sum + Number(row.count), 0);

    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_reports_status_count) VALUES (?, ?)`,
        [superAdminId, totalReports]
      );
      cache = { last_reports_status_count: 0 };
    }

    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    let shouldNotify = false;
    if (totalReports > (cache.last_reports_status_count || 0)) {
      shouldNotify = true;
    }

    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'تقرير الدفعات المحدّث',
            body: `تم استعراض تقرير الدفعات للمستأجرين`
          },
          data: {
            screen: 'tenant-reports'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      await query(
        `UPDATE super_stats_cache SET last_reports_status_count = ? WHERE super_id = ?`,
        [totalReports, superAdminId]
      );
    }

    res.json(paymentStatusReport);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching tenant reports' });
  }
});



app.get('/api/super/reports-count', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    // استعلام لإحضار عدد التقارير (دفعات المستأجرين)
    const [reportsCount] = await query(
      `SELECT COUNT(*) AS total_reports
FROM payments p
JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
WHERE rcd.admin_id = ? AND rcd.contract_end >= CURDATE()
`,
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_reports_count) VALUES (?, ?)`,
        [superAdminId, reportsCount.total_reports]
      );
      cache = { last_reports_count: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد العدد
    let shouldNotify = false;
    if (reportsCount.total_reports > (cache.last_reports_count || 0)) {
      shouldNotify = true;
    }

    // إرسال إشعار فقط إذا زاد العدد
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'استعراض عدد التقارير',
            body: `لديك ${reportsCount.total_reports} تقرير متوفر`
          },
          data: {
            screen: 'reports-count'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث القيم في الجدول
      await query(
        `UPDATE super_stats_cache SET last_reports_count = ? WHERE super_id = ?`,
        [reportsCount.total_reports, superAdminId]
      );
    }

    res.json({ total_reports: reportsCount.total_reports });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching reports count' });
  }
});




app.get('/api/super/tenant-payments-details', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const paymentsDetails = await query(
      `SELECT
        p.id AS payment_id,
        p.payment_number,
        p.payment_amount,
        p.due_date,
        p.payment_status,
        p.paid_date,
        p.payment_note,
        rcd.tenant_name,
        rcd.tenant_phone,
        rcd.unit_number,
        rcd.contract_number,
        rcd.contract_start,
        rcd.contract_end
      FROM payments p
      JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
      WHERE rcd.admin_id = ? AND rcd.contract_end >= CURDATE()
      ORDER BY p.due_date ASC`,
      [superAdminId]
    );

    const hash = crypto.createHash('md5').update(JSON.stringify(paymentsDetails)).digest('hex');

    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_payments_details_hash) VALUES (?, ?)`,
        [superAdminId, hash]
      );
      cache = { last_payments_details_hash: null };
    }

    let shouldNotify = false;
    if (hash !== (cache.last_payments_details_hash || '')) {
      shouldNotify = true;
    }

    if (shouldNotify) {
      const [superAdmin] = await query(
        'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
        [superAdminId, 'super']
      );

      if (superAdmin && superAdmin.fcm_token) {
        const notificationPayload = {
          message: {
            token: superAdmin.fcm_token,
            notification: {
              title: 'تفاصيل دفعات المستأجرين',
              body: `تم استعراض تفاصيل جميع الدفعات. لديك ${paymentsDetails.length} دفعة.`
            },
            data: {
              screen: 'tenant-payments-details'
            }
          }
        };

        const accessToken = await getAccessToken();

        await fetch(
          `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(notificationPayload),
          }
        );

        await query(
          `UPDATE super_stats_cache SET last_payments_details_hash = ? WHERE super_id = ?`,
          [hash, superAdminId]
        );
      }
    }

    res.json(paymentsDetails);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching tenant payments details' });
  }
});



// 3. Tenants Details
app.get('/api/super/tenants', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const tenants = await query(
      'SELECT tenant_name, tenant_phone, contract_number, contract_end FROM rental_contracts_details WHERE admin_id = ?',
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_total_tenants) VALUES (?, ?)`,
        [superAdminId, tenants.length]
      );
      cache = { last_total_tenants: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد العدد
    let shouldNotify = false;
    if (tenants.length > (cache.last_total_tenants || 0)) {
      shouldNotify = true;
    }

    // إرسال إشعار فقط إذا زاد العدد
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'استعراض بيانات المستأجرين',
            body: `تم استعراض قائمة المستأجرين لديك.`
          },
          data: {
            screen: 'tenants-list'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث العدد في الجدول
      await query(
        `UPDATE super_stats_cache SET last_total_tenants = ? WHERE super_id = ?`,
        [tenants.length, superAdminId]
      );
    }

    res.json(tenants);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching tenants details' });
  }
});

// 4. Maintenance Requests
app.get('/api/super/maintenance-requests', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const requests = await query(
      'SELECT mr.id, mr.category, mr.description, mr.status, mr.created_at, rcd.tenant_name, rcd.unit_number, rcd.tenant_phone FROM maintenance_requests mr JOIN rental_contracts_details rcd ON mr.tenant_id = rcd.tenant_id WHERE mr.owner_id = ? ORDER BY mr.created_at DESC',
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_maintenance_requests_count) VALUES (?, ?)`,
        [superAdminId, requests.length]
      );
      cache = { last_maintenance_requests_count: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد العدد
    let shouldNotify = false;
    if (requests.length > (cache.last_maintenance_requests_count || 0)) {
      shouldNotify = true;
    }

    // إرسال إشعار فقط إذا زاد العدد
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'استعراض طلبات الصيانة',
            body: `تم استعراض طلبات الصيانة لديك`
          },
          data: {
            screen: 'maintenance-requests'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث العدد في الجدول
      await query(
        `UPDATE super_stats_cache SET last_maintenance_requests_count = ? WHERE super_id = ?`,
        [requests.length, superAdminId]
      );
    }

    res.json(requests);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching maintenance requests' });
  }
});


app.post('/api/super/update-maintenance-request-status', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;
  const { request_id, new_status, admin_notes } = req.body;

  if (!request_id || !new_status) {
    return res.status(400).json({ message: '❗️ الطلب غير مكتمل: مطلوب رقم الطلب والحالة الجديدة.' });
  }

  try {
    // تحديث حالة الطلب مع ملاحظات الأدمن
    const updateResult = await query(
      `UPDATE maintenance_requests
       SET status = ?, admin_notes = ?, is_read = 0
       WHERE id = ? AND owner_id = ?`,
      [new_status, admin_notes || null, request_id, superAdminId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: '❌ لم يتم العثور على طلب الصيانة أو غير مرتبط بك.' });
    }

    // جلب بيانات المستأجر لإرسال الإشعار
    const [tenantInfo] = await query(`
      SELECT u.fcm_token, u.name, mr.category
      FROM maintenance_requests mr
      JOIN users u ON mr.tenant_id = u.id
      WHERE mr.id = ?`, [request_id]);

    if (tenantInfo && tenantInfo.fcm_token) {
      const notificationPayload = {
        message: {
          token: tenantInfo.fcm_token,
          notification: {
            title: `تم تحديث حالة طلب الصيانة`,
            body: `طلب الصيانة (${tenantInfo.category}) أصبح بحالة: ${new_status}`
          },
          data: {
            screen: 'maintenance-details',
            requestId: request_id.toString()
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(notificationPayload)
        }
      );
    }

    res.json({
      message: '✅ تم تحديث حالة طلب الصيانة وإرسال إشعار للمستأجر بنجاح.',
      request_id,
      new_status
    });

  } catch (err) {
    console.error('❌ Maintenance request status update error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث حالة طلب الصيانة.' });
  }
});



// 5. Noise Complaints
app.get('/api/super/noise-complaints', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const complaints = await query(
      'SELECT nc.id, nc.category, nc.description, nc.status, nc.created_at, rcd.tenant_name, rcd.unit_number, rcd.tenant_phone FROM noise_complaints nc JOIN rental_contracts_details rcd ON nc.tenant_id = rcd.tenant_id WHERE nc.admin_id = ? ORDER BY nc.created_at DESC',
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_noise_complaints_count) VALUES (?, ?)`,
        [superAdminId, complaints.length]
      );
      cache = { last_noise_complaints_count: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد العدد
    let shouldNotify = false;
    if (complaints.length > (cache.last_noise_complaints_count || 0)) {
      shouldNotify = true;
    }

    // إرسال إشعار فقط إذا زاد العدد
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'استعراض شكاوى الإزعاج',
            body: `تم استعراض شكاوى الإزعاج لدى مستأجريك`
          },
          data: {
            screen: 'noise-complaints'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث العدد في الجدول
      await query(
        `UPDATE super_stats_cache SET last_noise_complaints_count = ? WHERE super_id = ?`,
        [complaints.length, superAdminId]
      );
    }

    res.json(complaints);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching noise complaints' });
  }
});


app.post('/api/super/update-noise-complaint-status', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;
  const { complaint_id, new_status, admin_notes } = req.body;

  const allowedStatuses = ['جديد', 'قيد المعالجة', 'تم الحل'];

  if (!complaint_id || !new_status || !allowedStatuses.includes(new_status)) {
    return res.status(400).json({ 
      message: '❗️ يرجى توفير رقم الشكوى وحالة جديدة صحيحة (جديد، قيد المعالجة، تم الحل).' 
    });
  }

  try {
    const updateResult = await query(
      `UPDATE noise_complaints
       SET status = ?, admin_notes = ?, is_read = 0
       WHERE id = ? AND admin_id = ?`,
      [new_status, admin_notes || null, complaint_id, superAdminId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: '❌ لم يتم العثور على شكوى الإزعاج أو أنها غير مرتبطة بك.' });
    }

    const [tenantInfo] = await query(`
      SELECT u.fcm_token, u.name, nc.category
      FROM noise_complaints nc
      JOIN users u ON nc.tenant_id = u.id
      WHERE nc.id = ?`, [complaint_id]);

    if (tenantInfo && tenantInfo.fcm_token) {
      const notificationPayload = {
        message: {
          token: tenantInfo.fcm_token,
          notification: {
            title: `تحديث حالة شكوى الإزعاج`,
            body: `شكواك (${tenantInfo.category}) أصبحت بحالة: ${new_status}`
          },
          data: {
            screen: 'noise-complaint-details',
            complaintId: complaint_id.toString()
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(notificationPayload)
        }
      );
    }

    res.json({
      message: '✅ تم تحديث حالة شكوى الإزعاج وإرسال إشعار للمستأجر بنجاح.',
      complaint_id,
      new_status
    });

  } catch (err) {
    console.error('❌ Noise complaint status update error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث حالة شكوى الإزعاج.' });
  }
});




app.get('/api/super/full-active-contracts', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const contracts = await query(
      `SELECT
        id, contract_number, contract_type, contract_date,
        contract_start, contract_end, contract_location,
        owner_name, owner_nationality, owner_id_type, owner_id_number,
        owner_email, owner_phone, owner_address,
        tenant_name, tenant_nationality, tenant_id_type, tenant_id_number,
        tenant_email, tenant_phone, tenant_address,
        property_national_address, property_building_type, property_usage,
        property_units_count, property_floors_count, unit_type, unit_number,
        unit_floor_number, unit_area, unit_furnishing_status,
        unit_ac_units_count, unit_ac_type, annual_rent,
        periodic_rent_payment, rent_payment_cycle, rent_payments_count,
        total_contract_value, pdf_path, tenant_id,
        admin_id, property_id, created_at, tenant_serial_number
      FROM rental_contracts_details
      WHERE admin_id = ? AND contract_end >= CURDATE()
      ORDER BY contract_end ASC`,
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_full_active_contracts_count) VALUES (?, ?)`,
        [superAdminId, contracts.length]
      );
      cache = { last_full_active_contracts_count: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // تحقق إذا زاد العدد
    let shouldNotify = false;
    if (contracts.length > (cache.last_full_active_contracts_count || 0)) {
      shouldNotify = true;
    }

    // إرسال إشعار فقط إذا زاد العدد
    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'تم استعراض تفاصيل العقود الفعالة',
            body: `تم جلب تفاصيل ${contracts.length} عقد فعّال لديك.`
          },
          data: {
            screen: 'full-active-contracts'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث العدد في الجدول
      await query(
        `UPDATE super_stats_cache SET last_full_active_contracts_count = ? WHERE super_id = ?`,
        [contracts.length, superAdminId]
      );
    }

    res.json(contracts);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching full active contracts' });
  }
});




app.get('/api/super/expired-contracts', verifyToken, async (req, res) => {
  const superAdminId = req.user.id;

  try {
    const expiredContracts = await query(
      `SELECT
        id,
        contract_number,
        contract_type,
        contract_date,
        contract_start,
        contract_end,
        contract_location,
        tenant_name,
        tenant_phone,
        tenant_email,
        unit_number,
        unit_area,
        annual_rent,
        total_contract_value,
        pdf_path,
        created_at
      FROM rental_contracts_details
      WHERE admin_id = ? AND contract_end < CURDATE()
      ORDER BY contract_end DESC`,
      [superAdminId]
    );

    // جلب آخر القيم من جدول super_stats_cache
    let [cache] = await query(
      'SELECT * FROM super_stats_cache WHERE super_id = ?',
      [superAdminId]
    );

    // إذا لم يوجد صف، أنشئ واحد جديد
    if (!cache) {
      await query(
        `INSERT INTO super_stats_cache (super_id, last_expired_contracts_count) VALUES (?, ?)`,
        [superAdminId, expiredContracts.length]
      );
      cache = { last_expired_contracts_count: 0 };
    }

    // جلب FCM Token للسوبر
    const [superAdmin] = await query(
      'SELECT user_id, fcm_token FROM users WHERE id = ? AND user_type = ?',
      [superAdminId, 'super']
    );

    // إرسال إشعار فقط إذا تغير العدد
    let shouldNotify = false;
    if (expiredContracts.length !== (cache.last_expired_contracts_count || 0)) {
      shouldNotify = true;
    }

    if (shouldNotify && superAdmin && superAdmin.fcm_token) {
      const notificationPayload = {
        message: {
          token: superAdmin.fcm_token,
          notification: {
            title: 'تفاصيل العقود المنتهية',
            body: `تم استعراض تفاصيل ${expiredContracts.length} عقد منتهي لديك.`
          },
          data: {
            screen: 'expired-contracts'
          }
        }
      };

      const accessToken = await getAccessToken();

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );

      // تحديث العدد في الجدول
      await query(
        `UPDATE super_stats_cache SET last_expired_contracts_count = ? WHERE super_id = ?`,
        [expiredContracts.length, superAdminId]
      );
    }

    res.json(expiredContracts);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching expired contracts details' });
  }
});


app.post('/api/super/notify-all-admins', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { title, body } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إرسال الإشعارات.' });
  }

  if (!title || !body) {
    return res.status(400).json({ message: '❗️ العنوان والمحتوى مطلوبان.' });
  }

  try {
    const admins = await query(`
      SELECT fcm_token FROM users WHERE user_type = 'admin' AND fcm_token IS NOT NULL
    `);

    const tokens = admins.map(admin => admin.fcm_token).filter(Boolean);

    if (tokens.length === 0) {
      return res.status(404).json({ message: 'لا يوجد ملاك لديهم FCM tokens.' });
    }

    const accessToken = await getAccessToken();

    // إرسال الإشعارات بشكل متزامن (بالتوازي)
    await Promise.all(tokens.map(token => {
      const notificationPayload = {
        message: {
          token,
          notification: { title, body },
          data: { screen: 'super-notifications' }
        }
      };

      return fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationPayload),
        }
      );
    }));

    res.json({ message: '✅ تم إرسال الإشعار لجميع الملاك بنجاح.' });

  } catch (err) {
    console.error('❌ Notify all admins error:', err);
    res.status(500).json({ message: 'خطأ في إرسال الإشعارات', error: err });
  }
});


app.post('/api/super/notify-admin/:adminId', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId } = req.params;
  const { title, body } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إرسال الإشعارات.' });
  }

  if (!title || !body) {
    return res.status(400).json({ message: '❗️ العنوان والمحتوى مطلوبان.' });
  }

  try {
    const [admin] = await query(`
      SELECT fcm_token FROM users WHERE id = ? AND user_type = 'admin'
    `, [adminId]);

    if (!admin || !admin.fcm_token) {
      return res.status(404).json({ message: 'هذا المالك ليس لديه FCM token.' });
    }

    const notificationPayload = {
      message: {
        notification: { title, body },
        token: admin.fcm_token,
        data: { screen: 'super-notifications' }
      }
    };

    const accessToken = await getAccessToken();

    await fetch(
      `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationPayload),
      }
    );

    res.json({ message: `✅ تم إرسال الإشعار إلى المالك بنجاح.` });

  } catch (err) {
    console.error('❌ Notify admin error:', err);
    res.status(500).json({ message: 'خطأ في إرسال الإشعار', error: err });
  }
});


app.post('/api/super/notify-admins', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { title, body, adminIds } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  if (!title || !body || !adminIds || !adminIds.length) {
    return res.status(400).json({ message: 'بيانات غير مكتملة.' });
  }

  try {
    // ✅ هنا التصحيح الرئيسي
    const placeholders = adminIds.map(() => '?').join(',');
    const tokensResult = await query(
      `SELECT fcm_token FROM users WHERE id IN (${placeholders}) AND fcm_token IS NOT NULL`,
      adminIds
    );

    const tokens = tokensResult.map(admin => admin.fcm_token).filter(Boolean);
    const accessToken = await getAccessToken();

    await Promise.all(tokens.map(token => fetch(
      `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: {
            token,
            notification: { title, body },
            data: { screen: 'super-notifications' }
          }
        })
      }
    )));

    res.json({ message: '✅ تم الإرسال للمجموعة بنجاح.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ أثناء الإرسال.' });
  }
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////Viewer user type APIs//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



app.post('/api/super/create-viewer-with-agents', verifyToken, async (req, res) => {
  const { userType, id: created_by } = req.user;


  

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }



  const { viewer, agents } = req.body;

if (!viewer || !Array.isArray(agents) || agents.length === 0) {
  return res.status(400).json({ message: '❌ بيانات غير مكتملة.' });
}

// التحقق من عدد أرقام user_id للفيور
if (!/^\d{10}$/.test(viewer.user_id)) {
  return res.status(400).json({ message: '❗ رقم هوية الـ Viewer يجب أن يكون 10 أرقام.' });
}

// تحقق من عدم وجود user_id مكرر (في النظام)
const [existingViewer] = await query(`SELECT 1 FROM users WHERE user_id = ?`, [viewer.user_id]);
if (existingViewer) {
  return res.status(400).json({ message: `❌ رقم هوية المتطلع (${viewer.user_id}) مستخدم مسبقًا.` });
}

// التحقق من جميع الوكلاء
for (const agent of agents) {
  if (!/^\d{10}$/.test(agent.user_id)) {
    return res.status(400).json({ message: `❗ رقم هوية الوكيل (${agent.user_id}) يجب أن يكون 10 أرقام.` });
  }

  const [existingAgent] = await query(`SELECT 1 FROM users WHERE user_id = ?`, [agent.user_id]);
  if (existingAgent) {
    return res.status(400).json({ message: `❌ رقم هوية الوكيل (${agent.user_id}) مستخدم مسبقًا.` });
  }
}



  if (!viewer || !Array.isArray(agents) || agents.length === 0) {
    return res.status(400).json({ message: 'بيانات غير مكتملة: يجب توفير بيانات الـViewer والوكلاء.' });
  }

  const viewerToken = Math.floor(10000000 + Math.random() * 90000000).toString();

  try {
    // إنشاء حساب Viewer
    const viewerResult = await query(`
      INSERT INTO users (user_id, name, phone_number, user_type, token, created_by, max_agents, tenant_limit_per_agent)
      VALUES (?, ?, ?, 'viewer', ?, ?, ?, ?)
    `, [
      viewer.user_id,
      viewer.name,
      viewer.phone_number,
      viewerToken,
      created_by,
      viewer.max_agents,
      viewer.tenant_limit_per_agent
    ]);

    const viewerId = viewerResult.insertId;

    // إنشاء اشتراك Viewer
    const startDate = new Date();
    let endDate = new Date();
    if (viewer.subscription_type === 'monthly') {
      endDate.setMonth(endDate.getMonth() + 1);
    } else {
      endDate.setFullYear(endDate.getFullYear() + 1);
    }

    const viewerSubscriptionResult = await query(`
      INSERT INTO admin_subscriptions (admin_id, start_date, end_date, status, subscription_type, tenant_limit)
      VALUES (?, ?, ?, 'active', ?, ?)
    `, [
      viewerId,
      startDate,
      endDate,
      viewer.subscription_type,
      viewer.tenant_limit_per_agent
    ]);

    const viewerSubscriptionId = viewerSubscriptionResult.insertId;

    // إنشاء الوكلاء واشتراكاتهم
    const createdAgents = [];

    for (const agent of agents) {
      const agentToken = Math.floor(10000000 + Math.random() * 90000000).toString();

      const agentResult = await query(`
        INSERT INTO users (user_id, name, phone_number, user_type, token, created_by, viewer_id)
        VALUES (?, ?, ?, 'admin', ?, ?, ?)
      `, [
        agent.user_id,
        agent.name,
        agent.phone_number,
        agentToken,
        created_by,
        viewerId
      ]);

      const agentId = agentResult.insertId;

      await query(`
        INSERT INTO admin_subscriptions (admin_id, start_date, end_date, status, subscription_type, tenant_limit, linked_subscription_id)
        VALUES (?, ?, ?, 'active', ?, ?, ?)
      `, [
        agentId,
        startDate,
        endDate,
        viewer.subscription_type,
        viewer.tenant_limit_per_agent,
        viewerSubscriptionId
      ]);

      createdAgents.push({
        user_id: agent.user_id,
        name: agent.name,
        token: agentToken
      });
    }

    res.json({
      message: '✅ تم إنشاء المتطلع وجميع الوكلاء واشتراكاتهم بنجاح.',
      viewer: {
        user_id: viewer.user_id,
        name: viewer.name,
        token: viewerToken
      },
      agents: createdAgents
    });

  } catch (error) {
    console.error('❌ Error creating viewer and agents:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء الحسابات.' });
  }
});



///////////🔹 اشتراكات الـViewers والوكلاء المرتبطين بهم (Active Viewer & Agents Subscriptions):

app.get('/api/viewers-agents/viewers-subscriptions', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      u.id AS viewer_id,
      u.name,
      u.user_id,
      u.phone_number,
      s.start_date,
      s.end_date,
      s.subscription_type,
      s.status,
      u.created_at,
      COUNT(agents.id) AS agents_count
    FROM users u
    JOIN admin_subscriptions s ON s.admin_id = u.id
    LEFT JOIN users agents ON agents.viewer_id = u.id
    WHERE u.user_type = 'viewer' 
      AND s.status = 'active'
      AND s.end_date >= CURDATE()
    GROUP BY u.id, s.id
    ORDER BY s.end_date ASC
  `;

  try {
    const viewers = await query(sql);
    res.json({
      total_count: viewers.length,
      viewers
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب اشتراكات المتطلعين.' });
  }
});


app.get('/api/viewers/:viewerId/agents', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const { viewerId } = req.params;

  const sql = `
    SELECT 
      u.id AS agent_id,
      u.name,
      u.user_id,
      u.phone_number,
      s.start_date,
      s.end_date,
      s.subscription_type,
      s.status,
      s.tenant_limit, -- ✅ أضفنا عدد المستأجرين المسموح به
      (
        SELECT COUNT(*) 
        FROM rental_contracts rc
        JOIN users tenants ON tenants.id = rc.tenant_id
        WHERE tenants.created_by = u.id AND rc.status = 'active'
      ) AS active_tenants_count
    FROM users u
    JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.viewer_id = ? AND u.user_type = 'admin'
  `;

  try {
    const agents = await query(sql, [viewerId]);
    res.json({
      total_agents: agents.length,
      agents,
    });
  } catch (err) {
    console.error('❌ Error fetching agents:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب بيانات الوكلاء.' });
  }
});




/////////////////🔹 الاشتراكات المنتهية للـViewers والوكلاء المرتبطين بهم (Expired Viewer & Agents Subscriptions):
app.get('/api/viewers-agents/expired-subscriptions', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      u.id AS viewer_id,
      u.user_id,
      u.name,
      u.phone_number,
      s.start_date,
      s.end_date,
      s.subscription_type,
      s.status
    FROM admin_subscriptions s
    JOIN users u ON s.admin_id = u.id
    WHERE 
      u.user_type = 'viewer' AND
      (s.status = 'expired' OR s.status = 'cancelled' OR s.end_date < CURDATE())
    ORDER BY s.end_date DESC
  `;

  try {
    const subscriptions = await query(sql);
    res.json({
      total_count: subscriptions.length,
      viewers: subscriptions
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب اشتراكات الفيور المنتهية.' });
  }
});





/////////////////🔹 الدخل المتوقع من اشتراكات الـViewers والوكلاء المرتبطين بهم (Viewer & Agents Subscription Income):
app.get('/api/viewers-agents/subscription-income', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  try {
    // 1. جلب الاشتراكات الفعالة للـ Viewers مع عدد وكلائهم
    const subscriptions = await query(`
      SELECT 
        s.subscription_type,
        u.id AS viewer_id,
        (
          SELECT COUNT(*) 
          FROM users a 
          WHERE a.viewer_id = u.id AND a.user_type = 'admin'
        ) AS agents_count
      FROM admin_subscriptions s
      JOIN users u ON s.admin_id = u.id
      WHERE u.user_type = 'viewer' 
        AND s.status = 'active' 
        AND s.end_date >= CURDATE()
    `);

    // 2. جلب شرائح التسعير من جدول tiers
    const tiers = await query(`SELECT * FROM viewer_subscription_tiers`);

    let monthlyIncome = 0;
    let yearlyIncome = 0;
    let viewerMonthlyCount = 0;
    let viewerYearlyCount = 0;

    // 3. حساب كل اشتراك حسب عدد الوكلاء وتحديد الشريحة المناسبة
    subscriptions.forEach(sub => {
      const agents = sub.agents_count;

      const tier = tiers.find(t => 
        agents >= t.min_agents && agents <= t.max_agents
      );

      if (!tier) return;

      if (sub.subscription_type === 'monthly') {
        monthlyIncome += parseFloat(tier.monthly_price);
        viewerMonthlyCount++;
      } else if (sub.subscription_type === 'yearly') {
        yearlyIncome += parseFloat(tier.yearly_price);
        viewerYearlyCount++;
      }
    });

    // 4. إرسال النتائج
    res.json({
      viewer_monthly_count: viewerMonthlyCount,
      viewer_yearly_count: viewerYearlyCount,
      monthly_income: monthlyIncome.toFixed(2),
      yearly_income: yearlyIncome.toFixed(2),
      total_income: (monthlyIncome + yearlyIncome).toFixed(2),
      tiers_used: tiers,
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'DB Error', error });
  }
});


// ✅ API لتحديث شريحة تسعير معينة أو إضافتها إذا لم تكن موجودة
app.post('/api/super/update-viewer-tier', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { tier_id, min_agents, max_agents, monthly_price, yearly_price } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  if (
    typeof min_agents !== 'number' ||
    typeof max_agents !== 'number' ||
    typeof monthly_price !== 'number' ||
    typeof yearly_price !== 'number' ||
    min_agents < 1 ||
    max_agents < min_agents
  ) {
    return res.status(400).json({ message: '⚠️ بيانات غير صحيحة للشريحة.' });
  }

  try {
    if (tier_id) {
      // تعديل شريحة موجودة
      await query(`
        UPDATE viewer_subscription_tiers
        SET min_agents = ?, max_agents = ?, monthly_price = ?, yearly_price = ?
        WHERE id = ?
      `, [min_agents, max_agents, monthly_price, yearly_price, tier_id]);
    } else {
      // إضافة شريحة جديدة
      await query(`
        INSERT INTO viewer_subscription_tiers (min_agents, max_agents, monthly_price, yearly_price)
        VALUES (?, ?, ?, ?)
      `, [min_agents, max_agents, monthly_price, yearly_price]);
    }

    res.json({
      message: '✅ تم حفظ/تحديث الشريحة بنجاح.'
    });

  } catch (error) {
    console.error('❌ Tier Update Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث البيانات.', error });
  }
});


app.get('/api/viewer-subscription-tiers', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول.' });
  }

  try {
    const tiers = await query(`
      SELECT id, min_agents, max_agents, monthly_price, yearly_price 
      FROM viewer_subscription_tiers 
      ORDER BY min_agents ASC
    `);

    res.json({
      total: tiers.length,
      tiers,
    });

  } catch (error) {
    console.error('❌ Error fetching tiers:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب شرائح التسعير.' });
  }
});






//////////////////////////🔹 إحصائيات الـViewers مع عدد وكلائهم وعدد المستأجرين لكل وكيل (Viewers & Agents Stats):

app.get('/api/viewers-agents/stats', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  try {
    const viewers = await query(`
      SELECT 
        u.id AS viewer_id,
        u.name AS viewer_name,
        u.user_id AS viewer_user_id,
        COUNT(DISTINCT agents.id) AS agents_count,
        IFNULL(SUM(agent_sub.tenant_limit), 0) AS total_tenant_limit,
        IFNULL(SUM(active_tenants_count.active_count), 0) AS active_tenants_count
      FROM users u
      LEFT JOIN users agents ON agents.viewer_id = u.id
      LEFT JOIN admin_subscriptions agent_sub ON agent_sub.admin_id = agents.id
      LEFT JOIN (
        SELECT tenants.created_by AS agent_id, COUNT(*) AS active_count
        FROM rental_contracts rc
        JOIN users tenants ON tenants.id = rc.tenant_id
        WHERE rc.status = 'active'
        GROUP BY tenants.created_by
      ) AS active_tenants_count ON active_tenants_count.agent_id = agents.id
      WHERE u.user_type = 'viewer'
      GROUP BY u.id, u.name, u.user_id
      ORDER BY u.name ASC
    `);

    res.json({
      viewers_count: viewers.length,
      viewers
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'DB Error', error });
  }
});



/////////////////////////🔹 إنشاء API جديد خاص فقط بأسعار اشتراكات الـViewers الذين لديهم وكلاء:

// لحفظ أسعار اشتراكات الـViewers مع وكلائهم
app.post('/api/super/viewers/subscription-prices', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const { monthly_price, yearly_price } = req.body;

  if (monthly_price === undefined || yearly_price === undefined) {
    return res.status(400).json({ message: '❗️ يجب إدخال monthly_price و yearly_price.' });
  }

  try {
    // حفظ أو تحديث أسعار الـ viewers
    await query(`
      INSERT INTO subscription_prices (id, monthly_price, yearly_price, price_type) VALUES (2, ?, ?, 'viewer')
      ON DUPLICATE KEY UPDATE monthly_price = ?, yearly_price = ?
    `, [monthly_price, yearly_price, monthly_price, yearly_price]);

    res.json({ message: '✅ تم حفظ أسعار اشتراكات الـViewers بنجاح.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'حدث خطأ أثناء حفظ أسعار اشتراكات الـViewers.' });
  }
});

//////////////////الهدف منه تحديث عدد المستأجرين المسموح بهم لكل وكيل مرتبط بالـ Viewer.

app.post('/api/viewers/:viewerId/update-agent-tenant-limit', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { viewerId } = req.params;
  const { tenant_limit } = req.body;

  console.log('🟡 طلب تحديث tenant_limit:', { viewerId, tenant_limit });

  if (userType !== 'super') {
    console.log('🔴 رفض: المستخدم ليس super');
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  if (typeof tenant_limit !== 'number' || tenant_limit < 0) {
    console.log('🔴 tenant_limit غير صالح:', tenant_limit);
    return res.status(400).json({ message: '❗ يجب تحديد عدد المستأجرين المسموح بهم بشكل صحيح.' });
  }

  try {
    const [viewerCheck] = await query(`
      SELECT id, name FROM users 
      WHERE id = ? AND user_type = 'viewer'
    `, [viewerId]);

    if (!viewerCheck) {
      console.log('🔴 لم يتم العثور على viewer:', viewerId);
      return res.status(404).json({ message: '❌ لم يتم العثور على الـ Viewer.' });
    }

    console.log('✅ تم العثور على الـ Viewer:', viewerCheck);

    // تأكيد عدد الوكلاء المرتبطين
    const agents = await query(`
      SELECT id, name FROM users
      WHERE viewer_id = ?
    `, [viewerId]);

    console.log(`📦 عدد الوكلاء المرتبطين بالـ Viewer ${viewerId}:`, agents.length);

    if (agents.length === 0) {
      console.log('⚠️ لا يوجد وكلاء مرتبطين بهذا الـ Viewer');
    } else {
      console.log('👥 الوكلاء:', agents.map(a => ({ id: a.id, name: a.name })));
    }



    // التحديث الفعلي
    const result =
    await query(`
  UPDATE users
  SET tenant_limit_per_agent = ?
  WHERE id = ? AND user_type = 'viewer'
`, [tenant_limit, viewerId]);
    await query(`
      UPDATE admin_subscriptions
      SET tenant_limit = ?
      WHERE admin_id IN (SELECT id FROM users WHERE viewer_id = ?)
    `, [tenant_limit, viewerId]);

    console.log('✅ نتيجة التحديث:', result);

    const [viewerData] = await query(`
      SELECT phone_number FROM users WHERE id = ?
    `, [viewerId]);

    if (viewerData && viewerData.phone_number) {
      const formattedPhone = viewerData.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${viewerCheck.name} 👋،

      تم تحديث عدد المستأجرين المسموح لوكلائك بإضافتهم 🎉
      العدد الجديد لكل وكيل: ${tenant_limit}

      شكرًا لاستخدام منصتنا 🌟
      `.trim();

      console.log('📤 إرسال رسالة واتساب إلى:', formattedPhone);
      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({
      message: '✅ تم تحديث عدد المستأجرين لجميع الوكلاء بنجاح وإرسال الإشعار.',
      viewerId,
      tenant_limit
    });

  } catch (error) {
    console.error('❌ Error updating agents tenant limit:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث عدد المستأجرين لوكلاء الـViewer.' });
  }
});



app.post('/api/viewers-agents/subscriptions/:userId/renew', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { userId } = req.params;
  const { subscription_type } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  try {
    const [currentSub] = await query(`
      SELECT end_date FROM admin_subscriptions
      WHERE admin_id = ?
    `, [userId]);

    const today = new Date();
    let baseDate;

    if (currentSub?.end_date) {
      const end = new Date(currentSub.end_date);
      baseDate = end > today ? end : today;
    } else {
      baseDate = today;
    }

    const newEndDate = new Date(baseDate);
    if (subscription_type === 'monthly') {
      newEndDate.setMonth(newEndDate.getMonth() + 1);
    } else if (subscription_type === 'yearly') {
      newEndDate.setFullYear(newEndDate.getFullYear() + 1);
    } else {
      return res.status(400).json({ message: '❗ نوع الاشتراك غير صالح (monthly أو yearly).' });
    }

    const formattedStartDate = today.toISOString().slice(0, 10); // نسجل التمديد من اليوم، حتى لو بدينا من end_date
    const formattedEndDate = newEndDate.toISOString().slice(0, 10);

    // تحديث اشتراك الفيور
    await query(`
      UPDATE admin_subscriptions
      SET start_date = ?, end_date = ?, subscription_type = ?, status = 'active'
      WHERE admin_id = ?
    `, [formattedStartDate, formattedEndDate, subscription_type, userId]);

    // تحديث الوكلاء المرتبطين بنفس الاشتراك
    await query(`
      UPDATE admin_subscriptions s
      JOIN users u ON s.admin_id = u.id
      SET s.start_date = ?, s.end_date = ?, s.subscription_type = ?, s.status = 'active'
      WHERE u.viewer_id = ? AND s.linked_subscription_id IS NOT NULL
    `, [formattedStartDate, formattedEndDate, subscription_type, userId]);

    res.json({
      message: '✅ تم تجديد الاشتراك بنجاح.',
      userId,
      subscription_type,
      newEndDate: formattedEndDate
    });

  } catch (error) {
    console.error('❌ Error renewing subscription:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تجديد الاشتراك.' });
  }
});



app.post('/api/viewers/:viewerId/cancel-subscription', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { viewerId } = req.params;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  try {
    // إلغاء اشتراك الـ Viewer
    await query(`
      UPDATE admin_subscriptions
      SET status = 'cancelled', end_date = CURDATE()
      WHERE admin_id = ?
    `, [viewerId]);

    // إلغاء اشتراكات جميع الوكلاء المرتبطين بهذا الـ Viewer
    await query(`
      UPDATE admin_subscriptions
      SET status = 'cancelled', end_date = CURDATE()
      WHERE admin_id IN (SELECT id FROM users WHERE viewer_id = ?)
    `, [viewerId]);

    res.json({
      message: '✅ تم إلغاء اشتراك المتطلع وجميع الوكلاء المرتبطين به بنجاح.',
      viewerId,
    });

  } catch (error) {
    console.error('❌ Error cancelling subscriptions:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء إلغاء الاشتراك.' });
  }
});


// 1. إظهار كل الخدمات
app.get('/api/dynamic-services', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول.' });
  }

  try {
    const services = await query('SELECT * FROM dynamic_services ORDER BY display_order');
    res.json({ services });
  } catch (error) {
    console.error('❌ خطأ في جلب الخدمات:', error);
    res.status(500).json({ message: 'خطأ في السيرفر', error });
  }
});

// 2. تعديل خدمة معينة
app.put('/api/dynamic-services/:id', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه التعديل.' });
  }

  const { id } = req.params;
  const { title, icon, description, route, display_order, is_default } = req.body;

  try {
    await query(`
      UPDATE dynamic_services
      SET title = ?, icon = ?, description = ?, route = ?, display_order = ?, is_default = ?
      WHERE id = ?
    `, [title, icon, description, route, display_order, is_default, id]);

    res.json({ message: '✅ تم تعديل الخدمة بنجاح' });
  } catch (error) {
    console.error('❌ خطأ في تعديل الخدمة:', error);
    res.status(500).json({ message: 'خطأ في السيرفر', error });
  }
});

// 3. تفعيل أو تعطيل خدمة
app.patch('/api/dynamic-services/:id/status', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه التعديل.' });
  }

  const { id } = req.params;
  const { is_active } = req.body;

  try {
    await query(`
      UPDATE dynamic_services
      SET is_active = ?
      WHERE id = ?
    `, [is_active ? 1 : 0, id]);

    res.json({ message: `✅ تم ${is_active ? 'تفعيل' : 'تعطيل'} الخدمة بنجاح` });
  } catch (error) {
    console.error('❌ خطأ في تحديث حالة الخدمة:', error);
    res.status(500).json({ message: 'خطأ في السيرفر', error });
  }
});


app.get('/api/super/viewers-with-agent-count', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول.' });
  }

  try {
    const viewers = await query(`
      SELECT 
        v.id AS viewer_id,
        v.name AS viewer_name,
        v.user_id AS viewer_user_id,
        v.phone_number,
        COUNT(a.id) AS agents_count
      FROM users v
      LEFT JOIN users a ON a.viewer_id = v.id AND a.user_type = 'admin'
      WHERE v.user_type = 'viewer'
      GROUP BY v.id, v.name, v.user_id, v.phone_number
      ORDER BY v.name ASC
    `);

    res.json({
      total_viewers: viewers.length,
      viewers
    });

  } catch (error) {
    console.error('❌ Error fetching viewers with agent count:', error);
    res.status(500).json({ message: 'خطأ داخلي في الخادم', error });
  }
});


app.get('/api/super/viewers-agents-count', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول.' });
  }

  try {
    const [viewerCountResult] = await query(`
      SELECT COUNT(*) AS total_viewers FROM users WHERE user_type = 'viewer'
    `);

    const [agentsCountResult] = await query(`
      SELECT COUNT(*) AS total_agents FROM users WHERE user_type = 'admin' AND viewer_id IS NOT NULL
    `);

    res.json({
      total_viewers: viewerCountResult.total_viewers,
      total_agents: agentsCountResult.total_agents
    });

  } catch (error) {
    console.error('❌ Error fetching total viewers and agents:', error);
    res.status(500).json({ message: 'خطأ داخلي في الخادم', error });
  }
});


app.get('/api/super/agents', verifyToken, async (req, res) => {
  if (req.user.userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه الوصول.' });
  }

  try {
    const agents = await query(`
      SELECT
        a.id AS agent_id,
        a.user_id AS agent_user_id,
        a.name AS agent_name,
        a.phone_number,
        a.viewer_id,
        v.name AS viewer_name
      FROM users a
      LEFT JOIN users v ON a.viewer_id = v.id
      WHERE a.user_type = 'admin' AND a.viewer_id IS NOT NULL
      ORDER BY a.name ASC
    `);

    res.json({
      total_agents: agents.length,
      agents
    });

  } catch (error) {
    console.error('❌ Error fetching agents data:', error);
    res.status(500).json({ message: 'خطأ داخلي في الخادم', error });
  }
});

app.put('/api/super/agents/:agentId/update-agent-details', verifyToken, async (req, res) => {
  const { agentId } = req.params;
  const { user_id, name, phone_number } = req.body;
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  // تحقق من صحة البيانات
  if (!/^\d{10}$/.test(user_id)) {
    return res.status(400).json({ message: '❗ رقم الهوية يجب أن يكون 10 أرقام.' });
  }

  try {
    // تأكد من أن رقم الهوية الجديد غير مستخدم
    const [existingUser] = await query(`SELECT id FROM users WHERE user_id = ? AND id != ?`, [user_id, agentId]);
    if (existingUser) {
      return res.status(400).json({ message: `❌ رقم الهوية (${user_id}) مستخدم مسبقاً.` });
    }

    const newToken = Math.floor(10000000 + Math.random() * 90000000).toString();

    // تحديث بيانات الوكيل
    await query(`
      UPDATE users SET
        user_id = ?,
        name = ?,
        phone_number = ?,
        token = ?
      WHERE id = ? AND user_type = 'admin'
    `, [user_id, name, phone_number, newToken, agentId]);

    res.json({
      message: '✅ تم تعديل بيانات الوكيل بنجاح مع توليد توكن جديد.',
      agentId,
      newToken
    });

  } catch (error) {
    console.error('❌ Error updating agent details:', error);
    res.status(500).json({ message: 'حدث خطأ داخلي في الخادم.' });
  }
});


app.post('/api/super/viewers/:viewerId/add-agent', verifyToken, async (req, res) => {
  const { viewerId } = req.params;
  const { user_id, name, phone_number } = req.body;
  const { userType, id: created_by } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  if (!/^\d{10}$/.test(user_id)) {
    return res.status(400).json({ message: '❗ رقم هوية الوكيل يجب أن يكون 10 أرقام.' });
  }

  try {
    // تحقق من وجود رقم الهوية للوكيل
    const [existingAgent] = await query('SELECT 1 FROM users WHERE user_id = ?', [user_id]);
    if (existingAgent) {
      return res.status(400).json({ message: `❌ رقم هوية الوكيل (${user_id}) مستخدم مسبقًا.` });
    }

    // تحقق من وجود اشتراك فعال للمتطلع
    const [viewerSubscription] = await query(`
      SELECT * FROM admin_subscriptions
      WHERE admin_id = ? AND status = 'active'
      ORDER BY end_date DESC LIMIT 1
    `, [viewerId]);

    if (!viewerSubscription) {
      return res.status(400).json({ message: '❌ لا يوجد اشتراك فعال للمتطلع.' });
    }

    const agentToken = Math.floor(10000000 + Math.random() * 90000000).toString();

    // إضافة الوكيل
    const agentResult = await query(`
      INSERT INTO users (user_id, name, phone_number, user_type, token, created_by, viewer_id)
      VALUES (?, ?, ?, 'admin', ?, ?, ?)
    `, [
      user_id,
      name,
      phone_number,
      agentToken,
      created_by,
      viewerId
    ]);

    const agentId = agentResult.insertId;

    // إنشاء اشتراك الوكيل بنفس تواريخ اشتراك المتطلع
    await query(`
      INSERT INTO admin_subscriptions (admin_id, start_date, end_date, status, subscription_type, tenant_limit, linked_subscription_id)
      VALUES (?, ?, ?, 'active', ?, ?, ?)
    `, [
      agentId,
      viewerSubscription.start_date,
      viewerSubscription.end_date,
      viewerSubscription.subscription_type,
      viewerSubscription.tenant_limit,
      viewerSubscription.id
    ]);

    res.json({
      message: '✅ تم إضافة الوكيل وربطه باشتراك المتطلع بنجاح.',
      agent: {
        user_id,
        name,
        token: agentToken,
        start_date: viewerSubscription.start_date,
        end_date: viewerSubscription.end_date
      }
    });

  } catch (error) {
    console.error('❌ Error adding agent:', error);
    res.status(500).json({ message: 'حدث خطأ داخلي أثناء إضافة الوكيل.' });
  }
});






////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const multer = require('multer');
const { Storage } = require('@google-cloud/storage');
const path = require('path');
const os = require('os');
const fs = require('fs');


const upload = multer({ dest: os.tmpdir() }); // التخزين المؤقت

const storage = new Storage({
  credentials: JSON.parse(process.env.GOOGLE_CLOUD_KEY_JSON),
  projectId: JSON.parse(process.env.GOOGLE_CLOUD_KEY_JSON).project_id,
});
const bucket = storage.bucket('rental-contracts-pdfs'); // اسم الباكِت تبعك



// ... الإعدادات السابقة كما هي

app.post('/api/analyze-local-pdf', upload.single('pdf'), async (req, res) => {
  console.log("Current working directory:", process.cwd());
  console.log("File saved at:", req.file.path);



  const admin_id = req.user?.id || req.body.adminId; // حسب كيف بتمرر الادمن
  
  const [subscription] = await query(`
  SELECT tenant_limit FROM admin_subscriptions
  WHERE admin_id = ? AND status = 'active' AND end_date >= CURDATE()
  LIMIT 1
`, [admin_id]);

if (!subscription) {
  return res.status(400).json({ message: '❌ اشتراك المالك غير فعال أو غير موجود.' });
}

const tenant_limit = subscription.tenant_limit;

// ثانيًا نجيب عدد المستأجرين الحاليين الفعالين
const [currentTenantCountResult] = await query(`
  SELECT COUNT(*) AS active_tenants_count
  FROM rental_contracts rc
  JOIN users tenants ON tenants.id = rc.tenant_id
  WHERE tenants.created_by = ? AND rc.status = 'active'
`, [admin_id]);

const currentTenantCount = currentTenantCountResult.active_tenants_count;

// ثالثًا التحقق إذا تم تجاوز الحد الأقصى
if (currentTenantCount >= tenant_limit) {
  return res.status(400).json({
    message: `❌ لقد وصلت للحد الأقصى المسموح (${tenant_limit}) من المستأجرين.`,
    tenant_limit,
    currentTenantCount
  });
}

  let createdTenant = false;
  let createdToken = false;
  let tenantDbId, token;

  try {
    const tempPath = req.file.path;
    const gcsFileName = `${Date.now()}-${req.file.originalname}`;

    await bucket.upload(tempPath, {
      destination: gcsFileName,
      resumable: false,
      contentType: req.file.mimetype,
      metadata: {
        cacheControl: 'public, max-age=31536000',
      },
    });

    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${gcsFileName}`;
    const fileBuffer = fs.readFileSync(tempPath); // ⬅️ لتحليل المحتوى
    const pdfData = await pdfParse(fileBuffer);   // ⬅️ تحليل الملف
    const text = pdfData.text;                    // ⬅️ النص اللي راح تستخدمه
    const extract = (regex) => (text.match(regex) || [])[1]?.trim() || '';
    const toFloat = (v) => parseFloat(v) || 0;
    const toInt = (v) => parseInt(v) || 0;
    console.log('📄 Temp Path:', tempPath);
    console.log('📄 File Exists:', fs.existsSync(tempPath));
    console.log('📄 File Size:', fs.statSync(tempPath).size);




    const data = {
      contract_number: extract(/Contract No\.(.+?):العقد سجل رقم/),
      contract_type: extract(/Contract Type(.+?):العقد نوع/),
      contract_date: extract(/Contract Sealing Date(\d{4}-\d{2}-\d{2})/),
      contract_start: extract(/Tenancy Start Date(\d{4}-\d{2}-\d{2})/),
      contract_end: extract(/Tenancy End Date(\d{4}-\d{2}-\d{2})/),
      contract_location: extract(/Location\n(.+?):العقد إبرام مكان/),

      // Tenant Information
      tenant_name: (() => {
        let raw = '';
        let match = text.match(/Name\s*الاسم:?\s*(.+)/);
        if (match && match[1]) {
          raw = match[1].trim();
        } else {
          match = text.match(/Tenant Data[\s\S]*?Name(.+?):الاسم/);
          if (match && match[1]) raw = match[1].trim();
        }
        return !raw ? '' : raw.split(/\s+/).reverse().join(' ');
      })(),

      tenant_nationality: extract(/Tenant Data[\s\S]*?Nationality(.+?):الجنسي/),
      tenant_id_type: (() => {
        const raw = extract(/Tenant Data[\s\S]*?ID Type(.+?):الهوي/).trim();
        return !raw ? '' : raw.split(/\s+/).reverse().join(' ');
      })(),
      tenant_id_number: extract(/Tenant Data[\s\S]*?ID No\.(\d+):الهوي/),
      tenant_email: extract(/Tenant Data[\s\S]*?Email(.+?):الإلكتروني البريد/) || '-',
      tenant_phone: extract(/Tenant Data[\s\S]*?Mobile No\.(\+?\d+):الجو/),
      tenant_address: (() => {
        const raw = extract(/Tenant Data[\s\S]*?National Address(.+?):الوطني العنوان/).trim();
        if (!raw) return '';
        const parts = raw.split(/,\s*/);
        return parts.map(part => part.split(/\s+/).reverse().join(' ')).reverse().join(', ');
      })(),

      // Owner Information
      owner_name: extract(/Lessor Data[\s\S]*?Name(.+?):الاسم/).split(' ').reverse().join(' '),
      owner_nationality: (() => {
        const lines = text.split('\n');
        const i = lines.findIndex(line => line.includes('Nationality'));
        if (i !== -1 && lines[i + 1] && lines[i + 2]) {
          const raw = `${lines[i + 1].trim()} ${lines[i + 2].trim()}`;
          const words = raw.split(/\s+/);
          if (words.includes('السعودية') && words.includes('العربية') && words.includes('المملكة')) {
            return 'المملكة العربية السعودية';
          }
          return raw;
        }
        return (i !== -1 && lines[i + 1]) ? lines[i + 1].trim() : '';
      })(),
      owner_id_type: (() => {
        const lines = text.split('\n');
        const idx = lines.findIndex(line => line.includes('ID Type'));
        let result = '';
        if (idx !== -1) {
          const line = lines[idx];
          const match = line.match(/ID Type\s*([^\:]+):الهوي/);
          if (match && match[1]) result = match[1].trim();
          else {
            const start = line.indexOf('ID Type') + 'ID Type'.length;
            const end = line.indexOf(':الهوي');
            if (end > start) result = line.substring(start, end).trim();
          }
        }
        if (result) {
          const words = result.split(/\s+/);
          if (words.length === 2 && (words[0].endsWith('ية') || words[0].endsWith('يم'))) {
            return `${words[1]} ${words[0]}`;
          }
        }
        return result;
      })(),
      owner_id_number: extract(/Lessor Data[\s\S]*?ID No\.(\d+):الهوي/),
      owner_email: extract(/Lessor Data[\s\S]*?Email(.+?):الإلكتروني البريد/),
      owner_phone: extract(/Lessor Data[\s\S]*?Mobile No\.(\+?\d+):الجو/),
      owner_address: (() => {
        let addr = '';
        const match = text.match(/National Address\s*:?([^\n:]+):الوطني العنوان/);
        if (match && match[1]) addr = match[1].replace(/\s+/g, ' ').trim();
        else {
          const alt = text.match(/العنوان الوطني:\s*([^\n:]+)\s*Address National/);
          if (alt && alt[1]) addr = alt[1].replace(/\s+/g, ' ').trim();
        }
        return addr.split(/\s+/).reverse().join(' ');
      })(),

      // Financial Data
      annual_rent: toFloat(extract(/Annual Rent\s*(\d+\.\d+)/)),
      periodic_rent_payment: toFloat(extract(/Regular Rent Payment:\s*(\d+\.\d+)/)),
      rent_payment_cycle: extract(/Rent payment cycle\s*(\S+)/).replace(/الايجار.*/, '').trim(),
      rent_payments_count: toInt(extract(/Number of Rent\s*Payments:\s*(\d+)/)),
      total_contract_value: toFloat(extract(/Total Contract value\s*(\d+\.\d+)/)),

      // Property Information
      property_usage: (() => {
        const raw = extract(/Property Usage\s*(.+?)\s*استخدام/).trim();
        return !raw ? '' : raw.split(/,\s*/).map(part => part.split(/\s+/).reverse().join(' ')).join(', ');
      })(),
      property_building_type: extract(/Property Type(.+?):العقار بناء نوع/),
      property_units_count: toInt(extract(/Number of Units(\d+)/)),
      property_floors_count: toInt(extract(/Number of Floors(\d+)/)),
      property_national_address: extract(/Property Data[\s\S]*?National Address(.+?):الوطني العنوان/),

      // Unit Information
      unit_type: extract(/Unit Type(.+?):الوحدة نوع/),
      unit_number: extract(/Unit No\.(.+?):الوحدة رقم/),
      unit_floor_number: toInt(extract(/Floor No\.(\d+):الطابق رقم/)),
      unit_area: toFloat(extract(/Unit Area(\d+\.\d+):الوحدة مساحة/)),
      unit_furnishing_status: extract(/Furnishing Status\s*[-:]?\s*(.*?)\s*Number of AC units/),
      unit_ac_units_count: toInt(extract(/Number of AC units(\d+)/)),
      unit_ac_type: (() => {
        const raw = extract(/AC Type(.+?)التكييف نوع/).trim();
        return !raw ? '' : raw.split(/,\s*/).map(part => part.split(/\s+/).reverse().join(' ')).join(', ');
      })(),
      pdf_path: publicUrl,
      tenant_id: null, // بنعبيها بعدين
      admin_id: admin_id
    };

const user_id = data.tenant_id_number;

const today = new Date();
const contractEndDate = new Date(data.contract_end);

// تحقق إذا كان العقد منتهي أو ينتهي اليوم
if (contractEndDate <= today) {

    if (!data.contract_id) {
    delete data.contract_id;
  }

  // Property ID logic
  let property_id;
  const [existingProperty] = await query(`
    SELECT property_id FROM properties
    WHERE property_national_address = ? AND admin_id = ?
    LIMIT 1
  `, [data.property_national_address, admin_id]);

  if (existingProperty) {
    property_id = existingProperty.property_id;
  } else {
    const insertResult = await query(`
      INSERT INTO properties (property_national_address, property_units_count, admin_id)
      VALUES (?, ?, ?)
    `, [data.property_national_address, data.property_units_count, admin_id]);
    property_id = insertResult.insertId;
  }

  data.property_id = property_id;

  // إدخال مباشر إلى جدول الأرشيف فقط (دون إدخال في rental_contracts_details)
  const fields = Object.keys(data).join(', ');
  const placeholders = Object.keys(data).map(() => '?').join(', ');
  const values = Object.values(data);

  const archiveQuery = `
    INSERT INTO contracts_archive (${fields}, archived_at)
    VALUES (${placeholders}, NOW())
  `;

  let archiveResult;
  try {
    archiveResult = await query(archiveQuery, values);
  } catch (err) {
    console.error('❌ DB Error (Archive Contract):', err);
    return res.status(500).json({ message: 'فشل في حفظ بيانات العقد المنتهي في الأرشيف' });
  }

  const archivedContractId = archiveResult.insertId;

  // تحديث الحالة في جدول rental_contracts
  try {
    await query(`
      UPDATE rental_contracts
      SET status = 'expired'
      WHERE tenant_id = ? AND contract_end <= CURDATE()
    `, [data.tenant_id]);
  } catch (err) {
    console.error('❌ DB Error (Update Contract Status):', err);
    return res.status(500).json({ message: 'تم الأرشفة لكن فشل تحديث الحالة' });
  }

  return res.json({
    message: '✅ تم إضافة العقد المنتهي وإرساله للأرشيف بنجاح.',
    archived_contract_id: archivedContractId,
    archived: true
  });
}



    if (!user_id) {
      return res.status(400).json({ message: '❌ تعذّر استخراج رقم الهوية من الملف.' });
    }

    const userCheckSql = 'SELECT user_id FROM users WHERE user_id = ? LIMIT 1';

    const tenant_name_from_pdf = data.tenant_name || '---';

    try {
      const existing = await query(userCheckSql, [user_id]);
      console.log('🔍 existing user check:', existing);  // 👈 هنا

if (existing.length === 0) {
  token = Math.floor(10000000 + Math.random() * 90000000).toString();

  let formattedPhone;

  try {
    formattedPhone = formatInternationalPhoneNumber(data.tenant_phone);
  } catch (err) {
    console.error('⚠️ خطأ في صيغة رقم الهاتف:', err.message);
    formattedPhone = null;
  }

  const insertUserSql = `
  INSERT INTO users (user_id, name, user_type, token, phone_number, created_at, created_by)
  VALUES (?, ?, 'user', ?, ?, NOW(), ?)
  ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    phone_number = VALUES(phone_number),
    token = VALUES(token);
`;

const userResult = await query(insertUserSql, [
  user_id,
  tenant_name_from_pdf,
  token,
  formattedPhone,
  admin_id
]);
  console.log('🟢 بعد إدخال المستخدم:', user_id);

  tenantDbId = userResult.insertId;
  createdTenant = true;

  const insertTokenSql = `
    INSERT INTO user_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;
  await query(insertTokenSql, [token, '{}', admin_id]);
  createdToken = true;

  // ✅ رسالة واتساب ذكية وواضحة
  const welcomeMessage = `
مرحبًا ${tenant_name_from_pdf || 'عميلنا العزيز'} 👋،

تم إنشاء حسابك بنجاح 🎉

${user_id ? `رقم الهوية: ${user_id}` : ''}
${token ? `رمز الدخول: ${token}` : ''}

مرحبًا بك في منصتنا!
`.trim();

  // ✅ إرسال الرسالة فقط في حال توفر الرقم الصحيح
  if (formattedPhone) {
    sendWhatsAppMessage(formattedPhone, welcomeMessage)
      .then(() => console.log('✅ تم إرسال بيانات المستأجر عبر واتساب بنجاح'))
      .catch((err) => console.error('❌ خطأ في إرسال واتساب:', err));
  } else {
    console.warn('⚠️ لم يتم إرسال رسالة واتساب بسبب رقم الهاتف غير متوفر أو غير صحيح.');
  }

} else {
  return res.status(400).json({
    message: '❌ هذا المستأجر مسجّل بالفعل برقم الهوية نفسه ولا يمكن إضافته مرة أخرى.'
  });
}

data.tenant_id = tenantDbId;

} catch (err) {
  console.error('❌ User Creation Error:', err);
  return res.status(500).json({ message: 'فشل في إنشاء أو التحقق من المستأجر' });
}





    // === 2. إدخال بيانات العقد وكامل العملية بنفس المنطق ===


    // --- ابدأ من هنا (Property ID logic) ---
    let property_id;
    const [existingProperty] = await query(`
  SELECT property_id FROM properties
  WHERE property_national_address = ? AND admin_id = ?
  LIMIT 1
`, [data.property_national_address, admin_id]);

    if (existingProperty) {
      property_id = existingProperty.property_id;
    } else {
      const insertResult = await query(`
    INSERT INTO properties (property_national_address, property_units_count, admin_id)
    VALUES (?, ?, ?)
  `, [data.property_national_address, data.property_units_count, admin_id]);

      property_id = insertResult.insertId;
    }

    // هنا تضيف property_id في البيانات
    data.property_id = property_id;


    const fields = Object.keys(data).join(', ');
    const values = Object.values(data);
    const placeholders = Object.keys(data).map(() => '?').join(', ');

    // --- انتهى الجزء الخاص بالـ Property ID ---


    const insertQuery = `INSERT INTO rental_contracts_details (${fields}) VALUES (${placeholders})`;

    let contractResult;
    try {
      contractResult = await query(insertQuery, values);
    } catch (err) {
      console.error('❌ DB Error:', err);
      return res.status(500).json({ message: 'فشل في حفظ بيانات العقد' });
    }

    const contractId = contractResult.insertId;
    const tenantId = data.tenant_id;
    const adminId = data.admin_id;

    const getUsersQuery = `
      SELECT 
        (SELECT user_id FROM users WHERE id = ?) AS tenantUserId,
        (SELECT user_id FROM users WHERE id = ?) AS adminUserId
    `;

    let userResults;
    try {
      userResults = await query(getUsersQuery, [tenantId, adminId]);
      if (userResults.length === 0) throw new Error('No users found');
    } catch (userErr) {
      console.error('❌ خطأ في جلب بيانات المستخدمين:', userErr);
      return res.status(500).json({ message: 'خطأ في جلب بيانات المستخدمين' });
    }

    const { tenantUserId, adminUserId } = userResults[0];

    const checkChatRoomQuery = `
      SELECT id FROM chat_rooms WHERE tenant_user_id = ? AND admin_user_id = ? LIMIT 1
    `;

    let checkResults;
    try {
      checkResults = await query(checkChatRoomQuery, [tenantUserId, adminUserId]);
    } catch (checkErr) {
      console.error('❌ خطأ في التحقق من غرفة الدردشة:', checkErr);
      return res.status(500).json({ message: 'خطأ في التحقق من غرفة الدردشة' });
    }

    const createPaymentsAndSubscriptions = async () => {
      const payments = [];
      const startDate = new Date(data.contract_start);
      const cycleMonths = parseInt(data.rent_payment_cycle) || 1;
      const paymentsCount = parseInt(data.rent_payments_count) || 1;

      for (let i = 1; i <= paymentsCount; i++) {
        const dueDate = new Date(startDate);
        dueDate.setMonth(dueDate.getMonth() + cycleMonths * (i - 1));

        payments.push([
          contractId,
          i,
          data.periodic_rent_payment,
          dueDate.toISOString().slice(0, 10),
          'غير مدفوعة'
        ]);
      }

      const paymentsQuery = `
        INSERT INTO payments (contract_id, payment_number, payment_amount, due_date, payment_status)
        VALUES ${payments.map(() => '(?,?,?,?,?)').join(',')}
      `;

      try {
        const flatPayments = payments.flat();
        await query(paymentsQuery, flatPayments);
      } catch (paymentsErr) {
        console.error('❌ Payments DB Error:', paymentsErr);
        return res.status(500).json({ message: 'تم حفظ العقد، لكن فشل في إنشاء الدفعات' });
      }

      const updateSubscriptionQuery = `
        UPDATE rental_contracts SET contract_start = ?, contract_end = ?, status = 'active', created_at = NOW()
        WHERE tenant_id = ?
      `;

      const updateResult = await query(updateSubscriptionQuery, [
        data.contract_start,
        data.contract_end,
        tenantId
      ]);

      if (updateResult.affectedRows === 0) {
        const subscriptionData = {
          tenant_id: tenantId,
          property_name: "عقار مستأجر",
          rent_amount: data.periodic_rent_payment,
          contract_start: data.contract_start,
          contract_end: data.contract_end,
          status: 'active',
          created_at: new Date(),
        };

        const fields = Object.keys(subscriptionData).join(', ');
        const values = Object.values(subscriptionData);
        const placeholders = Object.keys(subscriptionData).map(() => '?').join(', ');
        const subscriptionQuery = `INSERT INTO rental_contracts (${fields}) VALUES (${placeholders})`;

        try {
          await query(subscriptionQuery, values);
          return res.json({
            message: '✅ تم رفع وتحليل الـPDF وإنشاء المستأجر والعقد وكافة العمليات بنجاح',
            tenant: {
              created: createdTenant,
              name: tenant_name_from_pdf,
              user_id: user_id,
              db_id: tenantDbId,
              token: token || null,
            },
            contract_id: contractId,
            contract_number: data.contract_number,
            payments: paymentsCount,
            chat_room: true,
            subscription: 'created',
            property_id: data.property_id
          });
        } catch (insertSubErr) {
          console.error('❌ Subscription DB Error:', insertSubErr);
          return res.status(500).json({ message: 'تم حفظ العقد لكن فشل في إنشاء الاشتراك' });
        }
      } else {
        return res.json({
          message: '✅ تم رفع وتحليل الـPDF وإنشاء المستأجر وتحديث العقد وكافة العمليات بنجاح',
          tenant: {
            created: createdTenant,
            name: tenant_name_from_pdf,
            user_id: user_id,
            db_id: tenantDbId,
            token: token || null,
          },
          contract_id: contractId,
          contract_number: data.contract_number,
          payments: paymentsCount,
          chat_room: true,
          subscription: 'updated',
          property_id: data.property_id
        });
      }
    };

    if (checkResults.length > 0) {
      console.log('🔵 غرفة الدردشة موجودة مسبقًا.');
      await createPaymentsAndSubscriptions();
    } else {
      const chatRoomQuery = `
        INSERT INTO chat_rooms (contract_id, tenant_user_id, admin_user_id)
        VALUES (?, ?, ?)
      `;
      try {
        await query(chatRoomQuery, [contractId, tenantUserId, adminUserId]);
        console.log('✅ تم إنشاء غرفة الدردشة بنجاح.');
        await createPaymentsAndSubscriptions();
      } catch (chatRoomErr) {
        console.error('❌ خطأ في إنشاء غرفة الدردشة:', chatRoomErr);
        return res.status(500).json({ message: 'تم حفظ العقد ولكن فشل إنشاء غرفة الدردشة' });
      }
    }
  } catch (err) {
    console.error('❌ PDF Analyze Error:', err.stack || err.message || err);
    res.status(500).json({
      message: 'فشل في تحليل الـ PDF',
      error: err.message || err.toString(),
    });
  }
});







////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get('/api/download-contract/:tenantId', verifyToken, async (req, res) => {
  const { tenantId } = req.params;

  try {
    // استعلام من قاعدة البيانات للحصول على رابط الملف
    const result = await query(
      'SELECT pdf_path FROM rental_contracts_details WHERE tenant_id = ? ORDER BY id DESC LIMIT 1',
      [tenantId]
    );

    if (!result.length || !result[0].pdf_path) {
      return res.status(404).json({ message: 'الملف غير موجود' });
    }

    // استخراج اسم الملف من الرابط
    const pdfPath = result[0].pdf_path;
    const filename = pdfPath.split('/').pop();

    const file = bucket.file(filename);

    // تحقق من وجود الملف
    const [exists] = await file.exists();
    if (!exists) {
      return res.status(404).json({ message: 'الملف غير موجود في السحابة' });
    }

    // إنشاء رابط مؤقت صالح لساعة
    const [signedUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + 60 * 60 * 1000,
    });

    res.json({ url: signedUrl });
  } catch (error) {
    console.error('❌ Download Error:', error);
    res.status(500).json({ message: 'خطأ أثناء إنشاء الرابط المؤقت' });
  }
});



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/api/profile/contract/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      contract_number, contract_type, contract_date, 
      contract_start, contract_end, contract_location
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-contract Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});


app.get('/api/profile/owner/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      owner_name, owner_nationality, owner_id_type, 
      owner_id_number, owner_email, owner_phone, owner_address
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-owner Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});




app.get('/api/profile/tenant/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      tenant_name, tenant_nationality, tenant_id_type, 
      tenant_id_number, tenant_email, tenant_phone, tenant_address
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);
    ``
    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-tenant Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});



app.get('/api/profile/property/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      property_national_address, property_building_type, property_usage,
      property_units_count, property_floors_count
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-property Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});





app.get('/api/profile/unit/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      unit_type, unit_number, unit_floor_number, unit_area,
      unit_furnishing_status, unit_ac_units_count, unit_ac_type
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-unit Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});



app.get('/api/profile/finance/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT 
      annual_rent, periodic_rent_payment, rent_payment_cycle, 
      rent_payments_count, total_contract_value
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-finance Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});



app.get('/api/profile/privacy/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT terms_conditions, privacy_policy
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch (err) {
    console.error('❌ Profile-privacy Error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.put('/api/payments/:paymentId', verifyToken, async (req, res) => {
  const { paymentId } = req.params;
  const { payment_status, paid_date, payment_note } = req.body;

  const sql = `
    UPDATE payments SET payment_status = ?, paid_date = ?, payment_note = ?
    WHERE id = ?
  `;

  try {
    await query(sql, [payment_status, paid_date, payment_note, paymentId]);
    res.json({ message: 'تم تحديث الدفعة بنجاح' });

  } catch (err) {
    console.error('❌ Payments-update Error:', err);
    res.status(500).json({ message: 'خطأ في تحديث الدفعة' });
  }
});



app.get('/api/payment-stats/:tenantId', verifyToken, async (req, res) => {
  const tenantId = req.params.tenantId;

  const sql = `
    SELECT p.payment_number, p.payment_amount, p.due_date, p.payment_status
    FROM payments p
    JOIN rental_contracts_details r ON p.contract_id = r.id
    WHERE r.tenant_id = (SELECT id FROM users WHERE user_id = ?)
    ORDER BY p.payment_number;
  `;

  try {
    const payments = await query(sql, [tenantId]);
    res.json({ payments });

  } catch (err) {
    console.error('❌ Payment-stats Error:', err);
    res.status(500).json({ message: 'خطأ في جلب بيانات الدفعات' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post('/api/messages/send', verifyToken, async (req, res) => {
  const { chatRoomId, senderId, receiverId, message } = req.body;

  const getContractSql = `SELECT contract_id FROM chat_rooms WHERE id = ?`;
  const insertMessageSql = `
    INSERT INTO messages (contract_id, chat_room_id, sender_id, receiver_id, message)
    VALUES (?, ?, ?, ?, ?)
  `;

  try {
    const results = await query(getContractSql, [chatRoomId]);

    if (results.length === 0) {
      console.error('خطأ في إيجاد العقد');
      return res.status(500).json({ message: 'خطأ في إيجاد العقد المرتبط بغرفة الدردشة' });
    }

    const contractId = results[0].contract_id;

    await query(insertMessageSql, [contractId, chatRoomId, senderId, receiverId, message]);
    res.status(200).json({ message: 'تم الإرسال بنجاح' });

  } catch (err) {
    console.error('❌ Send-message Error:', err);
    res.status(500).json({ message: 'خطأ في إرسال الرسالة' });
  }
});


// تعليم كل رسائل الطرف الآخر كمقروء في غرفة الشات
app.put('/api/messages/:chatRoomId/read', verifyToken, async (req, res) => {
  const { chatRoomId } = req.params;
  const userId = req.user.userId; // النصي
  const userDbId = req.user.id;   // الرقمي

  try {
    // علم كل الرسائل التي استقبلها المستخدم الحالي في هذه الغرفة كمقروء (نصي أو رقمي)
    const result = await query(
      `UPDATE messages SET is_read = 1 
       WHERE chat_room_id = ? AND (receiver_id = ? OR receiver_id = ?) AND is_read = 0`,
      [chatRoomId, userId, userDbId]
    );
    res.json({ message: 'تم التعليم كمقروء', affectedRows: result.affectedRows });
  } catch (err) {
    res.status(500).json({ message: 'خطأ', error: err });
  }
});


app.get('/api/messages/:chatRoomId', verifyToken, async (req, res) => {
  const { chatRoomId } = req.params;
  const userId = req.user.userId;



  const checkSql = `
    SELECT * FROM chat_rooms 
    WHERE id = ? AND (tenant_user_id = ? OR admin_user_id = ?)
  `;

  const messagesSql = `
    SELECT * FROM messages
    WHERE chat_room_id = ?
    ORDER BY timestamp ASC
  `;

  try {
    const checkResult = await query(checkSql, [chatRoomId, userId, userId]);

    if (checkResult.length === 0) {
      console.error('خطأ صلاحيات الوصول:', checkResult);
      return res.status(403).json({ message: 'لا يسمح لك بالوصول لهذه الرسائل' });
    }

    const messages = await query(messagesSql, [chatRoomId]);
    res.status(200).json({ messages });

  } catch (err) {
    console.error('❌ Get-messages Error:', err);
    res.status(500).json({ message: 'خطأ في جلب الرسائل' });
  }
});


app.put('/api/messages/read/:messageId', verifyToken, async (req, res) => {
  const { messageId } = req.params;

  const sql = `
    UPDATE messages SET is_read = TRUE WHERE id = ?
  `;

  try {
    await query(sql, [messageId]);
    res.status(200).json({ message: 'تم تحديث حالة الرسالة' });

  } catch (err) {
    console.error('❌ Update-message-read Error:', err);
    res.status(500).json({ message: 'خطأ في تحديث حالة القراءة' });
  }
});



// Endpoint لجلب بيانات غرفة الدردشة للمستأجر
app.get('/api/chat-room/tenant/:tenantId', verifyToken, async (req, res) => {
  const { tenantId } = req.params;

  const sql = `
    SELECT cr.id AS chat_room_id, cr.admin_user_id AS owner_user_id, u.name AS owner_name
    FROM chat_rooms cr
    JOIN users u ON cr.admin_user_id = u.user_id
    WHERE cr.tenant_user_id = ?
    LIMIT 1
  `;

  try {
    const results = await query(sql, [tenantId]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'لم يتم العثور على غرفة دردشة' });
    }

    res.status(200).json(results[0]);

  } catch (err) {
    console.error('❌ Chat-room-tenant Error:', err);
    res.status(500).json({ message: 'خطأ في جلب بيانات غرفة الدردشة' });
  }
});

// ✅ API جديدة لجلب غرف الدردشة النشطة للمستأجرين
app.get('/api/admin-active-chats/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT 
      rcd.tenant_id, 
      u.user_id AS tenant_user_id, 
      rcd.tenant_name, 
      rcd.contract_number, 
      cr.id AS chatRoomId,
      (
        SELECT COUNT(*) FROM messages m
        WHERE m.chat_room_id = cr.id AND m.receiver_id = ?
        AND m.is_read = 0
      ) AS unread_count
    FROM rental_contracts_details rcd
    INNER JOIN rental_contracts rc ON rc.tenant_id = rcd.tenant_id AND rc.status = 'active'
    INNER JOIN chat_rooms cr ON cr.contract_id = rcd.id
    INNER JOIN users u ON u.id = rcd.tenant_id
    INNER JOIN users admin ON admin.id = rcd.admin_id
    WHERE admin.user_id = ? -- ✅ هنا أصبحنا نستخدم user_id النصي
    ORDER BY rcd.created_at DESC
  `;

  try {
    const chats = await query(sql, [userId, userId]);
    res.status(200).json({ chats });
  } catch (err) {
    console.error('❌ Admin-active-chats Error:', err);
    res.status(500).json({ message: 'خطأ في جلب غرف الدردشة النشطة' });
  }
});




app.post('/api/chat/send-notification', verifyToken, async (req, res) => {
  const { receiverId, title, body, chatRoomId, senderId } = req.body;

  if (!receiverId || !title || !body || !chatRoomId || !senderId) {
    return res.status(400).json({ message: '❗ جميع الحقول مطلوبة' });
  }

  try {
    // جلب FCM Token للمستلم
    const [receiver] = await query('SELECT fcm_token FROM users WHERE user_id = ?', [receiverId]);
    if (!receiver || !receiver.fcm_token) {
      console.warn('🚫 لا يوجد FCM Token للمستلم:', receiverId);
      return res.status(404).json({ message: '❌ لا يوجد FCM Token للمستلم' });
    }

    const accessToken = await getAccessToken();
    const fcmMessage = {
      message: {
        token: receiver.fcm_token,
        notification: { title, body },
        data: {
          screen: 'chat',
          chatRoomId: String(chatRoomId),
          senderId: String(senderId),
        }
      }
    };

    // اطبع الـpayload قبل الإرسال
    console.log('🚀 سيتم إرسال إشعار FCM بهذا الشكل:');
    console.log(JSON.stringify(fcmMessage, null, 2));

    // أرسل الإشعار
    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(fcmMessage),
      }
    );

    // اطبع رد FCM
    const responseBody = await response.text();
    console.log('🔥 رد FCM:', responseBody);

    if (!response.ok) {
      console.error('❌ خطأ من FCM:', response.status, responseBody);
      return res.status(500).json({ message: 'فشل في إرسال إشعار الشات', fcmError: responseBody });
    }

    res.json({ message: '✅ تم إرسال إشعار الشات بنجاح', fcmPayload: fcmMessage, fcmResponse: responseBody });

  } catch (err) {
    console.error('❌ Chat-notification Error:', err);
    res.status(500).json({ message: 'فشل في إرسال إشعار الشات', error: err.message });
  }
});








////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 📁 index.js أو ملف routes المناسب
// 📁 index.js أو ملف routes المناسب
const { JWT } = require('google-auth-library');
const admin = require('firebase-admin');

const serviceAccount = JSON.parse(process.env.GOOGLE_CREDENTIALS);

// ✅ تهيئة Firebase Admin SDK للتحقق من OTP
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// ✅ كود JWT الحالي لإرسال FCM
async function getAccessToken() {
  const jwtClient = new JWT(
    serviceAccount.client_email,
    null,
    serviceAccount.private_key,
    ['https://www.googleapis.com/auth/firebase.messaging']
  );

  const tokens = await jwtClient.authorize();
  return tokens.access_token;
}


// ✅ API لإرسال إشعار عبر FCM V1
app.post('/api/send-notification', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { title, body, userId, userIds, targetType } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر أدمن يمكنه إرسال الإشعارات' });
  }

  if (!title || !body) {
    return res.status(400).json({ message: '❗ title و body مطلوبان' });
  }

  let tokens = [];

  // 📌 حالة فردية
  if (userId) {
    const sql = 'SELECT fcm_token FROM users WHERE user_id = ?';
    const result = await query(sql, [userId]);
    if (result.length && result[0].fcm_token) {
      tokens.push({ token: result[0].fcm_token, userId });
    }
  }

  // 📌 حالة متعددة محددة
  else if (Array.isArray(userIds)) {
    const placeholders = userIds.map(() => '?').join(',');
    const sql = `SELECT user_id, fcm_token FROM users WHERE user_id IN (${placeholders})`;
    const results = await query(sql, userIds);
    tokens = results.filter(row => row.fcm_token).map(row => ({ token: row.fcm_token, userId: row.user_id }));
  }

  // 📌 حالة حسب نوع المستخدم (admins أو users)
  else if (targetType) {
    const sql = `SELECT user_id, fcm_token FROM users WHERE user_type = ?`;
    const results = await query(sql, [targetType]);
    tokens = results.filter(row => row.fcm_token).map(row => ({ token: row.fcm_token, userId: row.user_id }));
  }

  if (!tokens.length) {
    return res.status(404).json({ message: '❌ لم يتم العثور على مستلمين صالحين' });
  }

  const accessToken = await getAccessToken();

  for (const { token, userId } of tokens) {
    const message = {
      message: {
        token,
        notification: { title, body },
        data: {
          screen: 'notifications',
          userId,
          userType: targetType || 'user', // ← يعتمد على targetType المُرسل من الواجهة
          senderType: 'super' // إضافة هذه المعلومة
        }
      }
    };

    try {
      await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });

      // حفظ الإشعار في قاعدة البيانات
      const insertNotificationSql = `
        INSERT INTO notifications (user_id, title, body)
        VALUES (?, ?, ?)
      `;
      await query(insertNotificationSql, [userId, title, body]);

    } catch (err) {
      console.error(`❌ فشل الإرسال لـ ${userId}`, err);
    }
  }

  res.json({ message: `✅ تم إرسال الإشعار إلى ${tokens.length} مستخدم` });
});


app.get('/api/user/all-notifications/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // إشعارات عامة
    const notifications = await query(
      `SELECT id, title, body, is_read, created_at, 'notification' as type
       FROM notifications WHERE user_id = ?`,
      [userId]
    );

    // إشعارات الصيانة
    const maintenance = await query(
      `SELECT id, category as title, description as body, is_read, created_at, 'maintenance' as type
       FROM maintenance_requests WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)`,
      [userId]
    );

    // إشعارات الإزعاج (تأكد أن جدول noise_complaints فيه عمود is_read)
    const noise = await query(
      `SELECT id, category as title, description as body, is_read, created_at, 'noise' as type
       FROM noise_complaints WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)`,
      [userId]
    );

    // إشعارات الدفعات المتأخرة
    const latePayments = await query(
      `SELECT 
        id, 
        'تنبيه دفعة متأخرة' as title, 
        CONCAT('لديك دفعة متأخرة، يرجى مراجعة تفاصيل الدفع.') as body, 
        is_read, 
        last_sent_date as created_at, 
        'late_payment' as type
       FROM late_payment_notifications
       WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
       ORDER BY last_sent_date DESC`,
      [userId]
    );

    // إشعارات الشات (آخر رسالة غير مقروءة لكل غرفة)
    const chat = await query(
      `SELECT 
        m.id, 
        'رسالة جديدة في الدردشة' as title, 
        m.message as body, 
        m.is_read, 
        m.timestamp as created_at, 
        'chat' as type,
        m.chat_room_id as chatRoomId,
        m.receiver_id as userId,
        m.sender_id as otherUserId,
        u2.name as otherUserName
      FROM messages m
      JOIN chat_rooms cr ON m.chat_room_id = cr.id
      JOIN users u1 ON m.receiver_id = u1.user_id OR m.receiver_id = u1.id
      JOIN users u2 ON m.sender_id = u2.user_id OR m.sender_id = u2.id
      WHERE (u1.user_id = ? OR u1.id = ?) AND m.receiver_id = u1.user_id AND m.is_read = 0
      ORDER BY m.timestamp DESC`,
      [userId, userId]
    );

    // دمج وترتيب حسب التاريخ
    const all = [
      ...notifications,
      ...maintenance,
      ...noise,
      ...latePayments,
      ...chat
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({ notifications: all });
  } catch (err) {
    console.error('❌ All-Notifications Error:', err);
    res.status(500).json({ message: 'خطأ داخلي في جلب الإشعارات', error: err });
  }
});


app.put('/api/late-payment-notifications/:id/read', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { userId, id: userDbId } = req.user;

  // تحقق أن الإشعار يخص المستخدم (يدعم id الرقمي أو user_id النصي)
  const checkSql = 'SELECT tenant_id FROM late_payment_notifications WHERE id = ?';
  const updateSql = 'UPDATE late_payment_notifications SET is_read = TRUE WHERE id = ?';

  try {
    const results = await query(checkSql, [id]);
    if (results.length === 0) {
      return res.status(404).json({ message: 'الإشعار غير موجود' });
    }
    const tenantId = results[0].tenant_id;

    // جلب بيانات المستخدم
    const userRow = await query('SELECT id, user_id FROM users WHERE user_id = ? OR id = ?', [userId, tenantId]);
    if (
      !userRow.length ||
      (userRow[0].id != tenantId && userRow[0].user_id != tenantId)
    ) {
      return res.status(403).json({ message: 'لا يمكنك تعديل هذا الإشعار' });
    }

    await query(updateSql, [id]);
    res.json({ message: 'تم التعليم كمقروء' });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في التعليم كمقروء', error: err });
  }
});




// ✅ API: جلب إشعارات مستخدم معين
app.get('/api/notifications/:userId', verifyToken, async (req, res) => {
  const { userType, userId: requesterId } = req.user;
  const { userId } = req.params;

  if (userId !== requesterId && userType !== 'super') {
    return res.status(403).json({ message: '❌ ليس لديك صلاحية لعرض هذه الإشعارات' });
  }

  const sql = `
    SELECT id, title, body, is_read, created_at
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
  `;

  try {
    const notifications = await query(sql, [userId]);
    res.json({ notifications });

  } catch (err) {
    console.error('❌ Notifications-fetch Error:', err);
    res.status(500).json({ message: 'خطأ في جلب الإشعارات' });
  }
});


// ✅ API: تعليم الإشعار كمقروء
app.put('/api/notifications/:id/read', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { userId } = req.user;

  const checkSql = 'SELECT user_id FROM notifications WHERE id = ?';
  const updateSql = 'UPDATE notifications SET is_read = TRUE WHERE id = ?';

  try {
    const results = await query(checkSql, [id]);

    if (results.length === 0 || results[0].user_id !== userId) {
      return res.status(403).json({ message: '❌ لا يمكن تعديل هذا الإشعار' });
    }

    await query(updateSql, [id]);
    res.json({ message: '✅ تم التعليم كمقروء' });

  } catch (err) {
    console.error('❌ Notifications-read Error:', err);
    res.status(500).json({ message: 'فشل التحديث' });
  }
});


// ✅ API: تفعيل اشتراك للمُلاك (admin) من السوبر فقط
app.post('/api/activate-subscription', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId, startDate, endDate } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه تفعيل الاشتراكات' });
  }

  if (!adminId || !startDate || !endDate) {
    return res.status(400).json({ message: 'يجب إرسال adminId و startDate و endDate' });
  }

  try {
    // تحقق أولًا من صلاحية الاشتراك الحالي
    const checkSql = `
      SELECT end_date FROM admin_subscriptions WHERE admin_id = ?
    `;
    const rows = await query(checkSql, [adminId]);

    if (rows.length > 0 && new Date(rows[0].end_date) >= new Date()) {
      return res.status(400).json({ message: '⚠️ الاشتراك الحالي ما زال فعّالًا ولا يحتاج لتحديث.' });
    }

    const sql = `
      INSERT INTO admin_subscriptions (admin_id, start_date, end_date)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE start_date = VALUES(start_date), end_date = VALUES(end_date)
    `;

    await query(sql, [adminId, startDate, endDate]);
    res.json({ message: '✅ تم تفعيل أو تحديث الاشتراك للمُـلك' });

  } catch (err) {
    console.error('❌ Subscription-activation Error:', err);
    res.status(500).json({ message: '❌ فشل في تفعيل الاشتراك' });
  }
});


// ✅ التحقق من صلاحية اشتراك المالك
app.get('/api/check-admin-subscription/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT end_date
    FROM admin_subscriptions
    WHERE admin_id = ?
  `;

  try {
    const rows = await query(sql, [adminId]);
    if (rows.length === 0) {
      return res.json({ isSubscribed: false });
    }

    const endDate = new Date(rows[0].end_date);
    const today = new Date();

    if (endDate >= today) {
      res.json({ isSubscribed: true, endDate });
    } else {
      res.json({ isSubscribed: false, endDate });
    }

  } catch (err) {
    console.error('❌ Check-subscription Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.post('/api/save-device-token', verifyToken, async (req, res) => {
  const { userId, deviceToken } = req.body;

  if (!userId || !deviceToken) {
    return res.status(400).json({ message: 'userId و deviceToken مطلوبين' });
  }

  const sql = `UPDATE users SET fcm_token = ? WHERE user_id = ?`;

  try {
    await query(sql, [deviceToken, userId]);
    res.json({ message: '✅ تم حفظ FCM Token بنجاح' });

  } catch (err) {
    console.error('❌ Save-device-token Error:', err);
    res.status(500).json({ message: 'فشل في حفظ التوكن' });
  }
});



app.get('/api/admin-properties-cleaned/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      TRIM(SUBSTRING_INDEX(rcd.property_national_address, ',', -1)) AS address_cleaned,
      COUNT(DISTINCT rcd.property_id) AS properties_count,
      MAX(rcd.property_units_count) AS units_count
    FROM rental_contracts_details rcd
    JOIN users u ON u.id = rcd.tenant_id
    WHERE rcd.admin_id = ?
      AND u.fcm_token IS NOT NULL
      AND u.fcm_token != ''
    GROUP BY address_cleaned
    ORDER BY address_cleaned ASC;
  `;

  try {
    const rows = await query(sql, [adminId]);
    res.json({ properties: rows });
  } catch (err) {
    console.error('❌ admin-properties-cleaned Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.get('/api/property-tenants/:cleanedAddress/:adminId', verifyToken, async (req, res) => {
  const { cleanedAddress, adminId } = req.params;

  const sql = `
    SELECT 
      u.user_id AS tenant_id,
      rcd.tenant_name,
      rcd.tenant_phone,
      rcd.tenant_email,
      rcd.unit_number,
      rcd.unit_floor_number,
      rcd.unit_area
    FROM rental_contracts_details rcd
    JOIN users u ON u.id = rcd.tenant_id
    WHERE rcd.admin_id = ?
      AND TRIM(SUBSTRING_INDEX(rcd.property_national_address, ',', -1)) = ?
      AND u.fcm_token IS NOT NULL
      AND u.fcm_token != ''
    GROUP BY u.user_id
  `;

  try {
    const tenants = await query(sql, [adminId, cleanedAddress]);
    res.json({ tenants });
  } catch (err) {
    console.error('❌ property-tenants Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


app.get('/api/tenants-by-admin/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
  u.user_id AS tenant_id,
  MAX(rcd.tenant_name) AS tenant_name,
  MAX(rcd.tenant_phone) AS tenant_phone
FROM rental_contracts_details rcd
JOIN users u ON u.id = rcd.tenant_id
WHERE rcd.admin_id = ?
  AND u.fcm_token IS NOT NULL
  AND u.fcm_token != ''
GROUP BY u.user_id
ORDER BY tenant_name ASC;

  `;

  try {
    const tenants = await query(sql, [adminId]);
    res.json({ tenants });
  } catch (err) {
    console.error('❌ tenants-by-admin Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ endpoint لإظهار الإشعارات التي أرسلها المالك للمستأجرين
app.get('/api/admin-sent-notifications/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  const { userType } = req.user;

  if (userType !== 'admin' && userType !== 'super') {
    return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول لهذه البيانات' });
  }

  const sql = `
    SELECT 
      n.id,
      n.title,
      n.body,
      n.created_at,
      u.name AS target_name
    FROM notifications n
    JOIN users u ON n.user_id = u.user_id
    WHERE n.sender_id = ?
    ORDER BY n.created_at DESC
  `;

  try {
    const rows = await query(sql, [adminId]);
    res.json({ notifications: rows });
  } catch (err) {
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ endpoint جديد لإظهار الإشعارات التي وصلت إلى المالك من السوبر أدمن
app.get('/api/admin-received-notifications/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  try {
    // إشعارات عامة لكل مستأجر مرتبط بالمالك
    const notifications = await query(
      `SELECT n.id, n.title, n.body, n.is_read, n.created_at, u.name as tenantName, 'notification' as type
       FROM notifications n
       JOIN users u ON n.user_id = u.user_id
       JOIN rental_contracts_details rcd ON u.id = rcd.tenant_id
       WHERE rcd.admin_id = ?
       GROUP BY n.id
       ORDER BY n.created_at DESC`,
      [adminId]
    );

    // إشعارات الصيانة
    const maintenance = await query(
      `SELECT m.id, CONCAT('طلب صيانة من ', u.name) as title, m.description as body, m.is_read, m.created_at, u.name as tenantName, 'maintenance' as type
       FROM maintenance_requests m
       JOIN users u ON m.tenant_id = u.id
       WHERE m.owner_id = ?
       ORDER BY m.created_at DESC`,
      [adminId]
    );
    // إشعارات الإزعاج
    const noise = await query(
      `SELECT n.id, CONCAT('بلاغ إزعاج من ', u.name) as title, n.description as body, n.is_read, n.created_at, u.name as tenantName, 'noise' as type
       FROM noise_complaints n
       JOIN users u ON n.tenant_id = u.id
       WHERE n.admin_id = ?
       ORDER BY n.created_at DESC`,
      [adminId]
    );

    // إشعارات الدفعات المتأخرة
    const latePayments = await query(
      `SELECT l.id, 'تنبيه دفعة متأخرة' as title, CONCAT('لدى المستأجر ', u.name, ' دفعة متأخرة.') as body, l.is_read, l.last_sent_date as created_at, u.name as tenantName, 'late_payment' as type
       FROM late_payment_notifications l
       JOIN users u ON l.tenant_id = u.id
       WHERE l.admin_id = ?
       ORDER BY l.last_sent_date DESC`,
      [adminId]
    );

    // دمج وترتيب حسب التاريخ
    const all = [
      ...notifications,
      ...maintenance,
      ...noise,
      ...latePayments
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({ notifications: all });
  } catch (err) {
    console.error('❌ Admin notifications error:', err);
    res.status(500).json({ message: 'خطأ في جلب إشعارات المالك', error: err });
  }
});



app.get('/api/super-received-notifications/:superId', verifyToken, async (req, res) => {
  const { superId } = req.params;

  try {
    // جلب كل الملاك (admins) الذين أنشأهم هذا السوبر
    const admins = await query(
      `SELECT id FROM users WHERE user_type = 'admin' AND created_by = ?`,
      [superId]
    );
    const adminIds = admins.map(a => a.id);

    // جلب كل المستأجرين المرتبطين بأي مالك أنشأه هذا السوبر
    let tenants = [];
    if (adminIds.length) {
      tenants = await query(
        `SELECT u.id, u.user_id, u.name
         FROM users u
         JOIN rental_contracts_details rcd ON u.id = rcd.tenant_id
         WHERE rcd.admin_id IN (${adminIds.map(() => '?').join(',')})`,
        adminIds
      );
    }

    // جلب كل المستأجرين المرتبطين مباشرة بالسوبر (لو كان السوبر نفسه مالك)
    const directTenants = await query(
      `SELECT u.id, u.user_id, u.name
       FROM users u
       JOIN rental_contracts_details rcd ON u.id = rcd.tenant_id
       WHERE rcd.admin_id = ?`,
      [superId]
    );

    // دمج كل المستأجرين بدون تكرار
    const allTenants = [...tenants, ...directTenants];
    const tenantIds = [...new Set(allTenants.map(t => t.id))];
    if (!tenantIds.length) return res.json({ notifications: [] });

    // إشعارات عامة
    const notifications = await query(
      `SELECT n.id, n.title, n.body, n.is_read, n.created_at, u.name as tenantName, 'notification' as type
       FROM notifications n
       JOIN users u ON n.user_id = u.user_id
       WHERE u.id IN (${tenantIds.map(() => '?').join(',')})
       GROUP BY n.id
       ORDER BY n.created_at DESC`,
      tenantIds
    );

    // إشعارات الصيانة
    const maintenance = await query(
      `SELECT m.id, CONCAT('طلب صيانة من ', u.name) as title, m.description as body, m.is_read, m.created_at, u.name as tenantName, 'maintenance' as type
       FROM maintenance_requests m
       JOIN users u ON m.tenant_id = u.id
       WHERE m.owner_id = ?
       ORDER BY m.created_at DESC`,
      [superId]
    );

    // إشعارات الإزعاج
    const noise = await query(
      `SELECT n.id, CONCAT('بلاغ إزعاج من ', u.name) as title, n.description as body, n.is_read, n.created_at, u.name as tenantName, 'noise' as type
       FROM noise_complaints n
       JOIN users u ON n.tenant_id = u.id
       WHERE n.admin_id = ?
       ORDER BY n.created_at DESC`,
      [superId]
    );

    // إشعارات الدفعات المتأخرة
    const latePayments = await query(
      `SELECT l.id, 'تنبيه دفعة متأخرة' as title, CONCAT('لدى المستأجر ', u.name, ' دفعة متأخرة.') as body, l.is_read, l.last_sent_date as created_at, u.name as tenantName, 'late_payment' as type
       FROM late_payment_notifications l
       JOIN users u ON l.tenant_id = u.id
       WHERE l.admin_id = ?
       ORDER BY l.last_sent_date DESC`,
      [superId]
    );
    let chat = [];

// دمج tenantIds والسوبر مباشرة معًا
const receiverIds = [...tenantIds, superId];

if (receiverIds.length) {
  chat = await query(
    `SELECT 
      m.id, 
      'رسالة جديدة في الدردشة' as title, 
      m.message as body, 
      m.is_read, 
      m.timestamp as created_at, 
      'chat' as type,
      m.chat_room_id as chatRoomId,
      m.receiver_id as userId,
      m.sender_id as otherUserId,
      u2.name as otherUserName
    FROM messages m
    JOIN chat_rooms cr ON m.chat_room_id = cr.id
    JOIN users u1 ON m.receiver_id = u1.user_id OR m.receiver_id = u1.id
    JOIN users u2 ON m.sender_id = u2.user_id OR m.sender_id = u2.id
    WHERE (u1.id IN (${receiverIds.map(() => '?').join(',')}))
      AND (m.receiver_id = u1.user_id OR m.receiver_id = u1.id)
      AND m.is_read = 0
    ORDER BY m.timestamp DESC`,
    receiverIds
  );
}



    // دمج وترتيب حسب التاريخ
    const all = [
      ...notifications,
      ...maintenance,
      ...noise,
      ...latePayments,
      ...chat
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({ notifications: all });
  } catch (err) {
    console.error('❌ Super notifications error:', err);
    res.status(500).json({ message: 'خطأ في جلب إشعارات السوبر', error: err });
  }
});






app.post('/api/admin/send-notification', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;
  const { title, body, userId, userIds } = req.body;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه استخدام هذا المسار' });
  }

  if (!title || !body) {
    return res.status(400).json({ message: '❗ العنوان والمحتوى مطلوبان' });
  }


  const [adminUser] = await query(
    'SELECT notifications_sent FROM users WHERE id = ?',
    [adminId]
  );

  if (adminUser.notifications_sent >= 100) {
    return res.status(403).json({
      message: '⚠️ لقد استخدمت الحد المجاني (100 إشعار). يرجى الاشتراك لتفعيل المزيد.',
    });
  }


  let tokens = [];

  // 📌 حالة فردية
  if (userId) {
    const sql = `
  SELECT u.user_id, u.fcm_token
  FROM users u
  JOIN rental_contracts_details rcd ON u.id = rcd.tenant_id
  WHERE u.user_id = ? 
    AND rcd.admin_id = ?
    AND u.fcm_token IS NOT NULL
    AND u.fcm_token != ''
  LIMIT 1
`;

    const result = await query(sql, [userId, adminId]);
    if (result.length && result[0].fcm_token) {
      tokens.push({ token: result[0].fcm_token, userId });
    }
  }

  // 📌 حالة متعددة
  else if (Array.isArray(userIds)) {
    const placeholders = userIds.map(() => '?').join(',');
    const sql = `
  SELECT u.user_id, u.fcm_token
  FROM users u
  JOIN rental_contracts_details rcd ON u.id = rcd.tenant_id
  WHERE u.user_id IN (${placeholders})
    AND rcd.admin_id = ?
    AND u.fcm_token IS NOT NULL  -- ✅ فقط من لديه FCM
  GROUP BY u.user_id
`;

    const results = await query(sql, [...userIds, adminId]);
    tokens = results.filter(row => row.fcm_token).map(row => ({
      token: row.fcm_token,
      userId: row.user_id
    }));
  }

  if (!tokens.length) {
    return res.status(404).json({ message: '❌ لا يوجد مستلمين صالحين' });
  }

  const accessToken = await getAccessToken();

  for (const { token, userId } of tokens) {
    const message = {
      message: {
        token,
        notification: { title, body },
        data: {
          screen: 'notifications',
          userId,
          userType: 'user',
          senderType: 'admin'  // ✅ ضروري لإظهار صفحة المستأجر مش المالك
        }
      }
    };


    try {
      await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });

      await query(`
  INSERT INTO notifications (user_id, title, body, sender_id)
  VALUES (?, ?, ?, ?)
`, [userId, title, body, adminId]);

      await query(
        'UPDATE users SET notifications_sent = notifications_sent + 1 WHERE id = ?',
        [adminId]
      );

    } catch (err) {
      console.error(`❌ فشل إرسال الإشعار لـ ${userId}:`, err);
    }
  }

  res.json({
    message: `✅ تم إرسال الإشعار إلى ${tokens.length} مستأجر`,
    sender_id: adminId
  });
});

app.get('/api/admin/late-payments-notifications/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      p.payment_number, p.payment_amount, p.due_date, p.payment_status,
      rcd.contract_number, rcd.tenant_name, u.id as tenant_id,
      CASE WHEN lpn.last_sent_date = CURDATE() THEN TRUE ELSE FALSE END AS notification_sent_today
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    JOIN users u ON rcd.tenant_id = u.id
    LEFT JOIN late_payment_notifications lpn ON lpn.tenant_id = u.id AND lpn.admin_id = ? AND lpn.last_sent_date = CURDATE()
    WHERE rcd.admin_id = ? 
      AND p.payment_status != 'مدفوعة' 
      AND p.due_date < CURDATE()
    ORDER BY p.due_date ASC
  `;

  try {
    const arrears = await query(sql, [adminId, adminId]);
    res.json({ arrears });

  } catch (err) {
    console.error('❌ Late payments notifications Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


app.post('/api/admin/send-late-payment-notification', verifyToken, async (req, res) => {
  const { adminId, tenantId, title, body } = req.body;

  if (!adminId || !tenantId || !title || !body) {
    return res.status(400).json({ message: '❗ جميع الحقول مطلوبة: adminId, tenantId, title, body.' });
  }

  try {
    // جلب بيانات المستأجر
    const tenantResult = await query('SELECT id, user_id, fcm_token, name FROM users WHERE user_id = ?', [tenantId]);
    if (!tenantResult.length) {
      console.warn(`🚫 المستأجر غير موجود: user_id=${tenantId}`);
      return res.status(404).json({ message: '❌ المستأجر غير موجود.' });
    }

    const { id: tenantDbId, user_id: userId, fcm_token: token, name: tenantName } = tenantResult[0];
    const accessToken = await getAccessToken();

    let fcmStatus = 'لم يتم الإرسال (لا يوجد FCM Token)';
    let fcmError = null;

    // إذا يوجد FCM Token أرسل الإشعار عبر FCM
    if (token) {
      const message = {
        message: {
          token,
          notification: { title, body },
          data: {
            screen: 'notifications',
            userId,
            userType: 'user',
            senderType: 'admin'
          }
        }
      };

      const response = await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(message)
        }
      );

      const responseBody = await response.text();
      if (response.ok) {
        fcmStatus = 'تم الإرسال بنجاح عبر FCM ✅';
        console.log(`✅ [FCM] تم إرسال إشعار للمستأجر (${tenantName} - ${userId})`);
      } else {
        // حاول قراءة تفاصيل الخطأ
        let errorDetail;
        try {
          errorDetail = JSON.parse(responseBody);
        } catch (e) {
          errorDetail = responseBody;
        }
        fcmStatus = 'فشل إرسال FCM ❌';
        fcmError = errorDetail;
        console.error(`❌ [FCM] خطأ أثناء إرسال الإشعار للمستأجر (${tenantName} - ${userId}):`, errorDetail);

        // إذا التوكن UNREGISTERED احذفه من قاعدة البيانات
        if (
          errorDetail &&
          errorDetail.error &&
          errorDetail.error.details &&
          Array.isArray(errorDetail.error.details)
        ) {
          const fcmErr = errorDetail.error.details.find(
            (d) => d.errorCode === 'UNREGISTERED'
          );
          if (fcmErr) {
            await query('UPDATE users SET fcm_token = NULL WHERE user_id = ?', [userId]);
            console.warn(`⚠️ تم حذف FCM Token غير صالح للمستأجر (${tenantName} - ${userId})`);
            fcmStatus += ' | تم حذف التوكن غير الصالح من قاعدة البيانات.';
          }
        }
      }
    } else {
      console.warn(`⚠️ لا يوجد FCM Token للمستأجر (${tenantName} - ${userId})`);
    }

    // تسجيل تاريخ إرسال الإشعار في قاعدة البيانات (حتى لو لم يوجد FCM)
    await query(`
  INSERT INTO late_payment_notifications (admin_id, tenant_id, last_sent_date, is_read)
  VALUES (?, ?, CURDATE(), 0)
  ON DUPLICATE KEY UPDATE last_sent_date = CURDATE(), is_read = 0
`, [adminId, tenantDbId]);

    // رسالة واضحة للمالك
    let clientMsg = '';
    if (token && fcmStatus.startsWith('تم الإرسال')) {
      clientMsg = `✅ تم إرسال الإشعار إلى "${tenantName}" (${userId}) بنجاح.`;
    } else if (token && fcmError) {
      clientMsg = `⚠️ لم يتم إرسال الإشعار عبر FCM بسبب مشكلة في التوكن. تم تسجيل العملية فقط.`;
    } else {
      clientMsg = `⚠️ لم يتم إرسال الإشعار لأن المستأجر "${tenantName}" لم يسجل دخول في التطبيق بعد أو حذف التطبيق. تم تسجيل العملية فقط.`;
    }

    res.json({
      message: clientMsg,
      fcmStatus,
      fcmError
    });

  } catch (err) {
    console.error('❌ Error sending late payment notification:', err);
    res.status(500).json({ message: '❌ خطأ في إرسال الإشعار', error: err });
  }
});


app.get('/api/admin-arrears-with-fcm/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      p.payment_number, p.payment_amount, p.due_date, p.payment_status,
      rcd.contract_number, rcd.tenant_name,
      u.user_id, u.fcm_token
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    JOIN users u ON rcd.tenant_id = u.id
    WHERE rcd.admin_id = ? 
      AND p.payment_status != 'مدفوعة'
      AND p.due_date < CURDATE()
      AND u.fcm_token IS NOT NULL
      AND u.fcm_token != ''
    ORDER BY p.due_date ASC
  `;

  try {
    const arrears = await query(sql, [adminId]);
    res.json({ arrears });

  } catch (err) {
    console.error('❌ Admin-arrears-with-fcm Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.post('/api/admin/set-default-late-notification', verifyToken, async (req, res) => {
  const { adminId, title, body } = req.body;

  // اطبع القيم المستلمة من الواجهة
  console.log('🔵 [set-default-late-notification] adminId:', adminId, 'title:', title, 'body:', body);

  if (!adminId || !title || !body) {
    return res.status(400).json({ message: 'adminId, title, body مطلوبة.' });
  }

  try {
    // التحقق من وجود adminId في جدول المستخدمين
    const adminExists = await query('SELECT id FROM users WHERE id = ?', [adminId]);
    console.log('🟢 [set-default-late-notification] adminExists:', adminExists);

    if (adminExists.length === 0) {
      return res.status(404).json({ message: '❌ هذا المالك غير موجود.' });
    }

    // حفظ أو تحديث الإشعار الافتراضي
    const result = await query(`
      INSERT INTO admin_default_notifications (admin_id, title, body)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE title = VALUES(title), body = VALUES(body)
    `, [adminId, title, body]);

    console.log('🟢 [set-default-late-notification] DB result:', result);

    res.json({ message: '✅ تم تحديث النص الافتراضي للإشعار.' });

  } catch (err) {
    console.error('❌ Error updating default notification:', err);
    res.status(500).json({ message: '❌ فشل تحديث النص الافتراضي.', error: err });
  }
});


app.get('/api/admin/get-default-late-notification/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  // القيم الافتراضية الدائمة
  const defaultNotification = {
    title: 'تنبيه بالدفعة المتأخرة',
    body: 'عزيزي المستأجر، لديك دفعة متأخرة. يرجى السداد في أقرب وقت.'
  };

  try {
    const results = await query(`
      SELECT title, body 
      FROM admin_default_notifications 
      WHERE admin_id = ?
    `, [adminId]);

    if (results.length > 0) {
      res.json({ notification: results[0] });
    } else {
      res.json({ notification: defaultNotification });
    }

  } catch (err) {
    console.error('❌ Error fetching default notification:', err);
    res.status(500).json({ message: '❌ فشل في جلب النص الافتراضي.', error: err });
  }
});



app.put('/api/maintenance-requests/:id/read', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { userType, id: userId } = req.user;

  try {
    // جلب الطلب
    const [request] = await query('SELECT tenant_id, owner_id FROM maintenance_requests WHERE id = ?', [id]);
    if (!request) return res.status(404).json({ message: 'غير موجود' });

    // فقط المستأجر أو المالك المرتبط يحق له التعليم كمقروء
    if (userType === 'user') {
      const [userRow] = await query('SELECT id FROM users WHERE user_id = ?', [req.user.userId]);
      if (!userRow || userRow.id !== request.tenant_id)
        return res.status(403).json({ message: 'غير مصرح' });
    } else if (userType === 'admin') {
      if (userId !== request.owner_id)
        return res.status(403).json({ message: 'غير مصرح' });
    } else {
      return res.status(403).json({ message: 'غير مصرح' });
    }

    await query('UPDATE maintenance_requests SET is_read = 1 WHERE id = ?', [id]);

    // ✅ جلب بيانات المستأجر لإرسال FCM
    const [tenant] = await query(`
      SELECT u.user_id, u.fcm_token 
      FROM maintenance_requests mr 
      JOIN users u ON mr.tenant_id = u.id 
      WHERE mr.id = ?`, [id]);

    // ✅ إرسال إشعار FCM للمستأجر
    if (tenant && tenant.fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: tenant.fcm_token,
          notification: {
            title: 'تحديث طلب الصيانة ✅',
            body: 'تم تحديث حالة طلب الصيانة الخاص بك.'
          },
          data: {
            screen: 'notifications',
            userId: tenant.user_id,
            userType: 'user',
            senderType: 'admin'
          }
        }
      };

      await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });
    }

    res.json({ message: 'تم التعليم كمقروء وإرسال إشعار للمستأجر' });

  } catch (err) {
    console.error('❌ Maintenance Request Read Error:', err);
    res.status(500).json({ message: 'خطأ داخلي', error: err });
  }
});



app.put('/api/noise-complaints/:id/read', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { userType, id: userId } = req.user;

  try {
    const [complaint] = await query('SELECT tenant_id, admin_id FROM noise_complaints WHERE id = ?', [id]);
    if (!complaint) return res.status(404).json({ message: 'غير موجود' });

    // فقط المستأجر أو المالك المرتبط يحق له التعليم كمقروء
    if (userType === 'user') {
      const [userRow] = await query('SELECT id FROM users WHERE user_id = ?', [req.user.userId]);
      if (!userRow || userRow.id !== complaint.tenant_id)
        return res.status(403).json({ message: 'غير مصرح' });
    } else if (userType === 'admin') {
      if (userId !== complaint.admin_id)
        return res.status(403).json({ message: 'غير مصرح' });
    } else {
      return res.status(403).json({ message: 'غير مصرح' });
    }

    await query('UPDATE noise_complaints SET is_read = 1 WHERE id = ?', [id]);

    // ✅ جلب بيانات المستأجر لإرسال FCM
    const [tenant] = await query(`
      SELECT u.user_id, u.fcm_token 
      FROM noise_complaints nc
      JOIN users u ON nc.tenant_id = u.id 
      WHERE nc.id = ?`, [id]);

    // ✅ إرسال إشعار FCM للمستأجر
    if (tenant && tenant.fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: tenant.fcm_token,
          notification: {
            title: 'تحديث شكوى الإزعاج ⚠️',
            body: 'تم تحديث حالة شكوى الإزعاج الخاصة بك.'
          },
          data: {
            screen: 'notifications',
            userId: tenant.user_id,
            userType: 'user',
            senderType: 'admin'
          }
        }
      };

      await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });
    }

    res.json({ message: 'تم التعليم كمقروء وإرسال إشعار للمستأجر' });
  } catch (err) {
    console.error('❌ Noise Complaint Read Error:', err);
    res.status(500).json({ message: 'خطأ داخلي', error: err });
  }
});



app.put('/api/messages/:id/read', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { userId } = req.user;
  try {
    // تحقق أن المستخدم هو المستقبل
    const check = await query('SELECT receiver_id FROM messages WHERE id = ?', [id]);
    if (!check.length) return res.status(404).json({ message: 'غير موجود' });
    if (check[0].receiver_id != userId)
      return res.status(403).json({ message: 'غير مصرح' });
    await query('UPDATE messages SET is_read = 1 WHERE id = ?', [id]);
    res.json({ message: 'تم التعليم كمقروء' });
  } catch (err) {
    res.status(500).json({ message: 'خطأ', error: err });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// إضافة محتوى جديد
app.post('/api/super/articles', verifyToken, async (req, res) => {
  const { title, content, type, image_url, start_date, end_date } = req.body;
  const created_by = req.user.id;

  try {
    await query(`
      INSERT INTO articles_offers_ads
      (title, content, type, image_url, start_date, end_date, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, content, type, image_url, start_date, end_date, created_by]
    );

    // بعد إضافة المحتوى، أرسل إشعار للجميع (مستأجرين وملاك)
    // جلب جميع المستخدمين الذين لديهم FCM Token
    const users = await query(
      `SELECT user_id, fcm_token FROM users WHERE fcm_token IS NOT NULL AND fcm_token != ''`
    );

    if (users.length > 0) {
      const accessToken = await getAccessToken();
      const sendAll = users.map(async (user) => {
        const message = {
          message: {
            token: user.fcm_token,
            notification: {
              title: 'محتوى جديد',
              body: title || 'تم نشر محتوى جديد في المنصة',
            },
            data: {
              screen: 'articles',
              userId: user.user_id,
              senderType: 'super',
              contentType: type 
            }
          }
        };

        try {
          await fetch(
            `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
            {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(message),
            }
          );
          // حفظ الإشعار في جدول notifications
          await query(
            `INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)`,
            [user.user_id, 'محتوى جديد', title || 'تم نشر محتوى جديد في المنصة']
          );
        } catch (err) {
          console.error(`❌ فشل إرسال إشعار للمستخدم ${user.user_id}:`, err);
        }
      });

      await Promise.all(sendAll);
    }

    res.status(201).json({ message: 'تم إنشاء المحتوى بنجاح وتم إرسال إشعار لجميع المستخدمين' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء المحتوى' });
  }
});

// جلب جميع المحتويات
app.get('/api/super/articles', verifyToken, async (req, res) => {
  try {
    const articles = await query('SELECT * FROM articles_offers_ads WHERE is_visible = TRUE ORDER BY id DESC');
    res.json(articles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب البيانات' });
  }
});

// جلب محتوى واحد
app.get('/api/super/articles/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [article] = await query(`SELECT * FROM articles_offers_ads WHERE id = ?`, [id]);
    res.json(article);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب المحتوى' });
  }
});

// تعديل محتوى
app.put('/api/super/articles/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, content, type, image_url, start_date, end_date, is_active, is_visible } = req.body;

  if (!['super', 'owner'].includes(req.user.user_type)) {
    return res.status(403).json({ message: 'غير مصرح لك بتنفيذ هذه العملية' });
  }

  try {
    await query(`
      UPDATE articles_offers_ads
      SET title=?, content=?, type=?, image_url=?, start_date=?, end_date=?, is_active=?, is_visible=?
      WHERE id=?`,
      [title, content, type, image_url, start_date, end_date, is_active, is_visible, id]
    );
    res.json({ message: 'تم تحديث المحتوى بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث المحتوى' });
  }
});

// إخفاء محتوى
app.delete('/api/super/articles/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  if (!['super', 'owner'].includes(req.user.user_type)) {
    return res.status(403).json({ message: 'غير مصرح لك بتنفيذ هذه العملية' });
  }

  try {
    await query(`UPDATE articles_offers_ads SET is_visible = FALSE WHERE id = ?`, [id]);
    res.json({ message: 'تم إخفاء المحتوى بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء إخفاء المحتوى' });
  }
});






// جلب جميع المحتويات الفعالة
app.get('/api/articles', verifyToken, async (req, res) => {
  try {
    const today = new Date();
    const articles = await query(`
      SELECT a.*, GROUP_CONCAT(pi.image_url) AS images
      FROM articles_offers_ads a
      LEFT JOIN property_images pi ON a.id = pi.article_id
      WHERE a.is_active = true
      AND (a.start_date IS NULL OR a.start_date <= ?)
      AND (a.end_date IS NULL OR a.end_date >= ?)
      GROUP BY a.id
      ORDER BY a.created_at DESC`,
      [today, today]
    );

    const formattedArticles = articles.map(article => ({
      ...article,
      images: article.images ? article.images.split(',') : []
    }));

    res.json(formattedArticles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب المحتويات' });
  }
});


// جلب محتوى واحد فعال
app.get('/api/articles/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const today = new Date();

  try {
    const [article] = await query(`
      SELECT a.*, GROUP_CONCAT(pi.image_url) AS images
      FROM articles_offers_ads a
      LEFT JOIN property_images pi ON a.id = pi.article_id
      WHERE a.id = ?
      AND a.is_active = true
      AND (a.start_date IS NULL OR a.start_date <= ?)
      AND (a.end_date IS NULL OR a.end_date >= ?)
      GROUP BY a.id`,
      [id, today, today]
    );

    if (!article) {
      return res.status(404).json({ message: 'المحتوى غير موجود أو غير فعال' });
    }

    article.images = article.images ? article.images.split(',') : [];

    res.json(article);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب المحتوى' });
  }
});










////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// ✅ API: إرسال طلب صيانة
app.post('/api/maintenance-request', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { category, description } = req.body;

  if (!category) {
    return res.status(400).json({ message: 'نوع الصيانة مطلوب' });
  }

  try {
    // 1. جلب tenant_id من جدول users
    const userSql = 'SELECT id FROM users WHERE user_id = ?';
    const userRows = await query(userSql, [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }
    const tenantId = userRows[0].id;

    // 2. جلب admin_id المرتبط بالمستأجر من آخر عقد
    const contractSql = `
      SELECT admin_id FROM rental_contracts_details 
      WHERE tenant_id = ? 
      ORDER BY created_at DESC LIMIT 1
    `;
    const contractRows = await query(contractSql, [tenantId]);
    if (contractRows.length === 0) {
      return res.status(404).json({ message: 'لا يوجد عقد مرتبط بهذا المستخدم' });
    }
    const ownerId = contractRows[0].admin_id;

    // 3. إنشاء الطلب
    const insertSql = `
      INSERT INTO maintenance_requests (tenant_id, owner_id, category, description) 
      VALUES (?, ?, ?, ?)
    `;
    await query(insertSql, [tenantId, ownerId, category, description || '']);

    // 4. جلب fcm_token للمالك
    const ownerSql = 'SELECT fcm_token FROM users WHERE id = ?';
    const ownerRows = await query(ownerSql, [ownerId]);

    if (ownerRows.length > 0 && ownerRows[0].fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: ownerRows[0].fcm_token,
          notification: {
            title: 'طلب صيانة جديد',
            body: `هناك بلاغ صيانة: ${category}`,
          },
          data: {
            screen: 'maintenance',
          },
        },
      };

      await fetch(`https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });
    }

    res.json({ message: '✅ تم إرسال طلب الصيانة بنجاح' });

  } catch (err) {
    console.error('❌ Maintenance Request Error:', err);
    res.status(500).json({ message: 'فشل في إرسال الطلب' });
  }
});





// ✅ API: سجل طلبات الصيانة للمستأجر
app.get('/api/maintenance-history/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // 1. جلب tenant_id من جدول users
    const userSql = 'SELECT id FROM users WHERE user_id = ?';
    const userRows = await query(userSql, [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }

    const tenantId = userRows[0].id;

    // 2. جلب سجل الطلبات لهذا المستأجر
    const historySql = `
      SELECT category, description, status, created_at
      FROM maintenance_requests
      WHERE tenant_id = ?
      ORDER BY created_at DESC
    `;
    const history = await query(historySql, [tenantId]);

    res.json({ history });

  } catch (err) {
    console.error('❌ Maintenance History Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب سجل الصيانة' });
  }
});



app.get('/api/last-maintenance-request', verifyToken, async (req, res) => {
  const { userId } = req.user;

  try {
    // جلب tenant_id من جدول users
    const userSql = 'SELECT id FROM users WHERE user_id = ?';
    const userRows = await query(userSql, [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }

    const tenantId = userRows[0].id;

    // جلب آخر طلب صيانة
    const requestSql = `
      SELECT category, description, status, created_at
      FROM maintenance_requests
      WHERE tenant_id = ?
      ORDER BY created_at DESC LIMIT 1
    `;
    const requestRows = await query(requestSql, [tenantId]);

    if (requestRows.length === 0) {
      return res.status(404).json({ message: 'لا يوجد طلبات' });
    }

    res.json(requestRows[0]);

  } catch (err) {
    console.error('❌ Last Maintenance Request Error:', err);
    res.status(500).json({ message: 'خطأ في استرجاع البيانات' });
  }
});


app.get('/api/maintenance-requests/admin', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه عرض هذه الطلبات' });
  }

  const sql = `
    SELECT mr.id, mr.category, mr.description, mr.status, mr.created_at,
           rcd.tenant_name, rcd.unit_number, rcd.tenant_phone
    FROM maintenance_requests mr
    JOIN rental_contracts_details rcd ON mr.tenant_id = rcd.tenant_id
    WHERE mr.owner_id = ?
    ORDER BY mr.created_at DESC
  `;

  try {
    const requests = await query(sql, [adminId]);
    res.json({ requests });

  } catch (err) {
    console.error('❌ Maintenance-requests-admin Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب الطلبات' });
  }
});



app.put('/api/maintenance-requests/:id/status', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;
  const requestId = req.params.id;
  const { status, admin_notes } = req.body;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه تحديث الحالة' });
  }

  if (!['جديد', 'قيد التنفيذ', 'تم التنفيذ'].includes(status)) {
    return res.status(400).json({ message: '❗ حالة غير صالحة' });
  }

  const updateSql = `
    UPDATE maintenance_requests 
    SET status = ?, admin_notes = ?
    WHERE id = ?
  `;

  try {
    await query(updateSql, [status, admin_notes || null, requestId]);

    // جلب بيانات الطلب
    const [request] = await query(
      `SELECT tenant_id, owner_id, category, description, admin_notes, created_at FROM maintenance_requests WHERE id = ?`,
      [requestId]
    );

    if (status === 'تم التنفيذ') {
      const archiveSql = `
        INSERT INTO archived_maintenance_requests (tenant_id, owner_id, category, description, status, admin_notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      await query(archiveSql, [
        request.tenant_id,
        request.owner_id,
        request.category,
        request.description,
        status,
        request.admin_notes,
        request.created_at,
      ]);

      // حذف الطلب الأصلي بعد الأرشفة
      await query(`DELETE FROM maintenance_requests WHERE id = ?`, [requestId]);
    }

    // جلب FCM Token و user_id للمستأجر
    const [tenant] = await query(
      `SELECT fcm_token, user_id FROM users WHERE id = ?`,
      [request.tenant_id]
    );

    // إرسال إشعار FCM وإضافة سجل في جدول الإشعارات
    if (tenant && tenant.fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: tenant.fcm_token,
          notification: {
            title: 'تحديث حالة طلب الصيانة 🛠️',
            body: `تم تحديث حالة طلب الصيانة (${request.category}) إلى: ${status}`,
          },
          data: {
            screen: 'notifications',
            userId: tenant.user_id,
            userType: 'user',
            senderType: userType,
            status,
          },
        },
      };

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        }
      );
    }

    // ✅ إضافة سجل دائم في جدول الإشعارات
    await query(`
      INSERT INTO notifications (user_id, title, body, sender_id)
      VALUES (?, ?, ?, ?)
    `, [
      tenant.user_id,
      'تحديث حالة طلب الصيانة 🛠️',
      `تم تحديث حالة طلب الصيانة (${request.category}) إلى: ${status}`,
      adminId
    ]);

    res.json({ message: '✅ تم تحديث حالة الطلب بنجاح' });

  } catch (err) {
    console.error('❌ Update-maintenance-request-status Error:', err);
    res.status(500).json({ message: '❌ فشل في تحديث الطلب' });
  }
});



app.get('/api/maintenance-requests/archived', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه الوصول إلى هذه البيانات' });
  }

  const sql = `
    SELECT id, tenant_id, owner_id, category, description, status, admin_notes, created_at, archived_at
    FROM archived_maintenance_requests 
    WHERE owner_id = ? 
    ORDER BY archived_at DESC
  `;

  try {
    const archivedRequests = await query(sql, [adminId]);
    res.json({ archivedRequests });

  } catch (err) {
    console.error('❌ Archived-Maintenance-Requests Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب البيانات المؤرشفة' });
  }
});


app.get('/api/noise-complaints/archived', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه الوصول إلى هذه البيانات' });
  }

  const sql = `
    SELECT id, tenant_id, admin_id, category, description, status, admin_notes, created_at, archived_at
    FROM archived_noise_complaints 
    WHERE admin_id = ? 
    ORDER BY archived_at DESC
  `;

  try {
    const archivedComplaints = await query(sql, [adminId]);
    res.json({ archivedComplaints });

  } catch (err) {
    console.error('❌ Archived-Noise-Complaints Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب البيانات المؤرشفة' });
  }
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post('/api/toggle-review-permission', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { adminId, enabled } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه تعديل صلاحيات المراجعات' });
  }

  const sql = `
    INSERT INTO review_permissions (admin_id, enabled)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)
  `;

  try {
    await query(sql, [adminId, enabled]);
    res.json({ message: '✅ تم تعديل الصلاحية بنجاح' });

  } catch (err) {
    console.error('❌ Toggle-review-permission Error:', err);
    res.status(500).json({ message: 'فشل في تعديل الصلاحية' });
  }
});



// ✅ API: إضافة تقييم من المستأجر + تسجيل نقاط
app.post('/api/reviews/add', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { rating, comment } = req.body;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'يرجى إرسال تقييم بين 1 و5' });
  }

  const insertReviewSql = `
    INSERT INTO reviews (user_id, rating, comment)
    VALUES (?, ?, ?)
  `;

  const insertPointsSql = `
    INSERT INTO review_points (user_id, points, source)
    VALUES (?, ?, ?)
  `;

  try {
    await query(insertReviewSql, [userId, rating, comment || '']);
    await query(insertPointsSql, [userId, 10, 'إرسال تقييم']);

    res.json({ message: '✅ تم تسجيل تقييمك وحصلت على 10 نقاط!' });

  } catch (err) {
    console.error('❌ Review-add Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إرسال التقييم' });
  }
});


app.post('/api/admin/reviews/add', verifyToken, async (req, res) => {
  const { id: adminId, userType } = req.user;
  const { rating, comment } = req.body;

  // تحقق أن المستخدم مالك (admin)
  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط الملاك يمكنهم إضافة تقييم.' });
  }

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'يرجى إرسال تقييم بين 1 و5' });
  }

  const insertReviewSql = `
    INSERT INTO admin_reviews (admin_id, rating, comment)
    VALUES (?, ?, ?)
  `;

  const insertPointsSql = `
    INSERT INTO admin_review_points (admin_id, points, source)
    VALUES (?, ?, ?)
  `;

  try {
    await query(insertReviewSql, [adminId, rating, comment || '']);
    await query(insertPointsSql, [adminId, 10, 'إرسال تقييم']);

    res.json({ message: '✅ تم تسجيل تقييمك وحصلت على 10 نقاط!' });

  } catch (err) {
    console.error('❌ Admin-Review-add Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إرسال التقييم' });
  }
});


app.get('/api/admin/reviews', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه رؤية تقييمات الملاك.' });
  }

  const statsSql = `
    SELECT 
      COUNT(*) AS total_reviews,
      AVG(rating) AS average_rating
    FROM admin_reviews;
  `;

  const recentReviewsSql = `
    SELECT ar.admin_id, u.name AS admin_name, ar.rating, ar.comment, ar.created_at
    FROM admin_reviews ar
    JOIN users u ON ar.admin_id = u.id
    ORDER BY ar.created_at DESC
    LIMIT 2;
  `;

  try {
    const [stats] = await query(statsSql);
    const recentReviews = await query(recentReviewsSql);

    res.json({
      total_reviews: stats.total_reviews,
      average_rating: parseFloat(stats.average_rating).toFixed(2),
      recent_reviews: recentReviews
    });

  } catch (err) {
    console.error('❌ Super-Admin-Reviews-fetch Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب تقييمات الملاك.' });
  }
});






// ✅ API: جلب التقييمات (للموقع أو للمالك لو عنده صلاحية)
app.get('/api/reviews-summary/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  const { userType } = req.user; // ⬅️ استخراج نوع المستخدم

  const permissionSql = `
    SELECT enabled FROM review_permissions WHERE admin_id = ?
  `;

  const statsSql = `
    SELECT 
      COUNT(*) AS total_reviews,
      AVG(rating) AS average_rating
    FROM reviews
    WHERE visible = TRUE
  `;

  const recentReviewsSql = `
    SELECT rating, comment, created_at 
    FROM reviews 
    WHERE visible = TRUE 
    ORDER BY created_at DESC
    LIMIT 2
  `;

  try {
    // إذا كان سوبر، تخطي التحقق من الصلاحيات
    if (userType !== 'super') {
      const permissionResults = await query(permissionSql, [adminId]);
      if (permissionResults.length === 0 || !permissionResults[0].enabled) {
        return res.status(403).json({ message: '❌ لا يملك المالك صلاحية عرض التقييمات' });
      }
    }

    const stats = await query(statsSql);
    const recentReviews = await query(recentReviewsSql);

    res.json({
      total_reviews: stats[0].total_reviews,
      average_rating: parseFloat(stats[0].average_rating).toFixed(2),
      recent_reviews: recentReviews
    });

  } catch (err) {
    console.error('❌ Reviews-summary Error:', err);
    res.status(500).json({ message: 'فشل في جلب بيانات التقييمات' });
  }
});


// ✅ API: جلب تقييمات المستخدمين (للمستخدم نفسه)



// ✅ API: ترتيب المستخدمين حسب النقاط (شارت المنافسة)
app.get('/api/review-stats', verifyToken, async (req, res) => {
  const sql = `
    SELECT u.user_id, u.name, SUM(rp.points) AS total_points
    FROM review_points rp
    JOIN users u ON u.user_id = rp.user_id
    GROUP BY rp.user_id
    ORDER BY total_points DESC
  `;

  try {
    const leaderboard = await query(sql);
    res.json({ leaderboard });

  } catch (err) {
    console.error('❌ Review-stats Error:', err);
    res.status(500).json({ message: 'فشل في جلب البيانات' });
  }
});


// ✅ API: تعديل النقاط يدويًا من لوحة الإدارة (فقط للسوبر أو المالك)
app.post('/api/admin/update-review-points', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { userId, points, source } = req.body;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ لا تملك صلاحية تعديل النقاط' });
  }

  if (!userId || !points || isNaN(points)) {
    return res.status(400).json({ message: '❗ البيانات غير مكتملة أو غير صالحة' });
  }

  const sql = `
    INSERT INTO review_points (user_id, points, source)
    VALUES (?, ?, ?)
  `;

  try {
    await query(sql, [userId, points, source || 'تعديل يدوي']);
    res.json({ message: '✅ تم تحديث النقاط للمستخدم بنجاح' });

  } catch (err) {
    console.error('❌ Admin-update-points Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث النقاط' });
  }
});




// ✅ API: ملخص تقييمات ونقاط مستخدم محدد
app.get('/api/user-review-summary/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  const pointsSql = `
    SELECT SUM(points) AS total_points FROM review_points WHERE user_id = ?
  `;

  const reviewsSql = `
    SELECT rating, comment, created_at FROM reviews 
    WHERE user_id = ? 
    ORDER BY created_at DESC
  `;

  try {
    const pointsResults = await query(pointsSql, [userId]);
    const reviews = await query(reviewsSql, [userId]);

    res.json({
      total_points: pointsResults[0].total_points || 0,
      reviews,
    });

  } catch (err) {
    console.error('❌ User-review-summary Error:', err);
    res.status(500).json({ message: 'فشل في جلب ملخص التقييمات' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get('/api/download-contract/:userId', verifyToken, async (req, res) => {
  const userId = req.params.userId;

  const sql = `
    SELECT pdf_path 
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    ORDER BY created_at DESC
    LIMIT 1;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'لم يتم العثور على ملف العقد' });
    }

    const pdfPath = path.join(__dirname, results[0].pdf_path);

    res.sendFile(pdfPath, (err) => {
      if (err) {
        console.error('❌ File Sending Error:', err);
        res.status(500).json({ message: 'حدث خطأ في تحميل الملف' });
      }
    });

  } catch (err) {
    console.error('❌ Download-contract Error:', err);
    res.status(500).json({ message: 'حدث خطأ في الخادم' });
  }
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ✅ 1. Get all services (for super admin)
app.get('/api/services', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: 'صلاحية مفقودة' });
  }

  const sql = 'SELECT * FROM dynamic_services';

  try {
    const results = await query(sql);
    res.json(results);

  } catch (err) {
    console.error('❌ Get-services Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ 2. Create new service (super only)
app.post('/api/services', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }

  const { title, icon, description } = req.body;
  const sql = `
    INSERT INTO dynamic_services (title, icon, description)
    VALUES (?, ?, ?)
  `;

  try {
    const result = await query(sql, [title, icon, description]);
    res.json({ message: 'تمت الإضافة بنجاح', id: result.insertId });

  } catch (err) {
    console.error('❌ Create-service Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ 3. Toggle service active (super only)
app.put('/api/services/:id/toggle', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }

  const id = req.params.id;
  const sql = `
    UPDATE dynamic_services SET is_active = NOT is_active WHERE id = ?
  `;

  try {
    await query(sql, [id]);
    res.json({ message: 'تم التحديث بنجاح' });

  } catch (err) {
    console.error('❌ Toggle-service Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ 4. Get admin's selected services
app.get('/api/admin-services/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT ds.*, COALESCE(av.is_enabled, 0) as is_enabled
    FROM dynamic_services ds
    LEFT JOIN admin_service_visibility av
    ON ds.id = av.service_id AND av.admin_id = ?
    WHERE ds.is_active = 1
  `;

  try {
    const results = await query(sql, [adminId]);
    res.json(results);

  } catch (err) {
    console.error('❌ Admin-services-fetch Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




// ✅ 5. Toggle service for admin
app.post('/api/admin-services/toggle', verifyToken, async (req, res) => {
  const { userType } = req.user;

  if (userType !== 'admin' && userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }

  const { adminId, serviceId } = req.body;

  const checkSql = `
    SELECT * FROM admin_service_visibility 
    WHERE admin_id = ? AND service_id = ?
  `;

  const toggleSql = `
    UPDATE admin_service_visibility 
    SET is_enabled = NOT is_enabled 
    WHERE admin_id = ? AND service_id = ?
  `;

  const insertSql = `
    INSERT INTO admin_service_visibility (admin_id, service_id, is_enabled) 
    VALUES (?, ?, 1)
  `;

  try {
    const existingRows = await query(checkSql, [adminId, serviceId]);

    if (existingRows.length) {
      await query(toggleSql, [adminId, serviceId]);
      res.json({ message: 'تم التحديث بنجاح' });
    } else {
      await query(insertSql, [adminId, serviceId]);
      res.json({ message: 'تم التفعيل بنجاح' });
    }

  } catch (err) {
    console.error('❌ Admin-services-toggle Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


// ✅ 6. Get services for tenant (final output for UI)
// ✅ خدمات المستأجر النهائية بعد التعديل
app.get('/api/services-for-tenant/:tenantUserId', verifyToken, async (req, res) => {
  const tenantUserId = req.params.tenantUserId;

  const getAdminSql = `
    SELECT rcd.admin_id
    FROM rental_contracts_details rcd
    JOIN users u ON rcd.tenant_id = u.id
    WHERE u.user_id = ?
    ORDER BY rcd.created_at DESC
    LIMIT 1
  `;

  const servicesSql = `
    SELECT ds.*
    FROM dynamic_services ds
    LEFT JOIN admin_service_visibility v ON v.service_id = ds.id AND v.admin_id = ?
    WHERE ds.is_active = 1 AND (
      (ds.is_default = 1 AND (v.is_enabled IS NULL OR v.is_enabled = 1))
      OR (ds.is_default = 0 AND v.is_enabled = 1)
    )
    ORDER BY ds.display_order ASC
  `;

  try {
    const adminResults = await query(getAdminSql, [tenantUserId]);

    if (adminResults.length === 0) {
      return res.status(404).json({ message: 'المالك غير موجود' });
    }

    const adminId = adminResults[0].admin_id;
    const results = await query(servicesSql, [adminId]);

    const services = results.map(service => {
      let route;
      switch (service.id) {
        case 1: route = 'internetService'; break;
        case 2: route = 'apartmentSecurity'; break;
        case 3: route = 'cleaningService'; break;
        case 4: route = 'urgentMaintenance'; break;
        case 5: route = 'reportProblem'; break;
        case 6: route = 'downloadContract'; break;
        case 7: route = 'waterDelivery'; break;
        case 8: route = 'paymentAlert'; break;
        case 9: route = 'supportContact'; break;
        case 21: route = 'cleaningServiceRequest'; break;
        case 22: route = 'changeLocksRequest'; break;
        case 23: route = 'noiseComplaintRequest'; break;
        case 24: route = 'apartmentSuppliesRequest'; break;
        default: route = null;
      }

      return { ...service, route };
    });

    res.json({ services });

  } catch (err) {
    console.error('❌ Services-for-tenant Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});






app.put('/api/services/:id/order', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const serviceId = req.params.id;
  const { display_order } = req.body;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ غير مصرح لك بتعديل الترتيب' });
  }

  if (!display_order || isNaN(display_order)) {
    return res.status(400).json({ message: '❗ display_order مطلوب ويجب أن يكون رقمًا صالحًا' });
  }

  const sql = `
    UPDATE dynamic_services 
    SET display_order = ? 
    WHERE id = ?
  `;

  try {
    await query(sql, [display_order, serviceId]);
    res.json({ message: '✅ تم تحديث ترتيب الخدمة بنجاح' });

  } catch (err) {
    console.error('❌ Update-service-order Error:', err);
    res.status(500).json({ message: 'فشل في تحديث الترتيب' });
  }
});


app.get('/api/super/finance-yearly', verifyToken, async (req, res) => {
  const { userType, id: superId } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه الوصول لهذه البيانات.' });
  }

  try {
    // جلب كل admin_id أنشأهم السوبر
    const admins = await query(
      `SELECT id FROM users WHERE user_type = 'admin' AND created_by = ?`,
      [superId]
    );
    const adminIds = admins.map(a => a.id);

    if (!adminIds.length) {
      return res.json({ yearly: [] });
    }

    const sql = `
      SELECT 
        years.year AS year,
        IFNULL(SUM(rcd.periodic_rent_payment) * 12, 0) AS yearly_expected_income,
        COUNT(DISTINCT rcd.id) AS contracts_count
      FROM (
        SELECT YEAR(CURDATE()) AS year
        UNION SELECT YEAR(CURDATE()) - 1
        UNION SELECT YEAR(CURDATE()) - 2
        UNION SELECT YEAR(CURDATE()) - 3
        UNION SELECT YEAR(CURDATE()) - 4
      ) AS years
      JOIN rental_contracts_details rcd 
        ON rcd.admin_id IN (${adminIds.map(() => '?').join(',')})
        AND (
          YEAR(rcd.contract_start) <= years.year 
          AND YEAR(rcd.contract_end) >= years.year
        )
        AND rcd.contract_end > CURDATE()
      GROUP BY years.year
      ORDER BY years.year DESC
    `;

    const yearly = await query(sql, adminIds);
    res.json({ yearly });

  } catch (err) {
    console.error('❌ Super-finance-yearly Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/noise-complaints', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { category, description } = req.body;

  if (userType !== 'user') {
    return res.status(403).json({ message: '❌ فقط المستأجر يمكنه تقديم بلاغ' });
  }

  const getAdminSql = `
    SELECT admin_id FROM rental_contracts_details 
    WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1
  `;

  const insertComplaintSql = `
    INSERT INTO noise_complaints (tenant_id, admin_id, category, description) 
    VALUES (?, ?, ?, ?)
  `;

  try {
    const adminRows = await query(getAdminSql, [userId]);

    if (adminRows.length === 0) {
      return res.status(404).json({ message: 'لا يوجد عقد مرتبط' });
    }

    await query(insertComplaintSql, [
      userId,
      adminRows[0].admin_id,
      category,
      description || '',
    ]);

    res.json({ message: '✅ تم إرسال البلاغ بنجاح' });

  } catch (err) {
    console.error('❌ Noise-complaint-create Error:', err);
    res.status(500).json({ message: '❌ خطأ في إرسال البلاغ' });
  }
});



app.get('/api/noise-complaints/tenant', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;

  if (userType !== 'user') {
    return res.status(403).json({ message: '❌ فقط المستأجر يملك هذه الصلاحية' });
  }

  const sql = `
    SELECT id, category, description, status, created_at
    FROM noise_complaints WHERE tenant_id = ? ORDER BY created_at DESC
  `;

  try {
    const complaints = await query(sql, [userId]);
    res.json({ complaints });

  } catch (err) {
    console.error('❌ Noise-complaints-tenant Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب البلاغات' });
  }
});


app.get('/api/noise-complaints/admin', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه عرض هذه البلاغات' });
  }

  const sql = `
    SELECT nc.id, nc.category, nc.description, nc.status, nc.created_at,
           rcd.tenant_name, rcd.unit_number, rcd.tenant_phone
    FROM noise_complaints nc
    JOIN rental_contracts_details rcd ON nc.tenant_id = rcd.tenant_id
    WHERE nc.admin_id = ?
    ORDER BY nc.created_at DESC
  `;

  try {
    const complaints = await query(sql, [adminId]);
    res.json({ complaints });

  } catch (err) {
    console.error('❌ Noise-complaints-admin Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب البلاغات' });
  }
});


app.put('/api/noise-complaints/:id/status', verifyToken, async (req, res) => {
  const { userType, id: senderId } = req.user;
  const complaintId = req.params.id;
  const { status } = req.body;

  if (!['admin', 'super'].includes(userType)) {
    return res.status(403).json({ message: '❌ غير مصرح' });
  }

  if (!['جديد', 'قيد المعالجة', 'تم الحل'].includes(status)) {
    return res.status(400).json({ message: '❗ حالة غير صالحة' });
  }

  const updateSql = `
    UPDATE noise_complaints SET status = ? WHERE id = ?
  `;

  try {
    await query(updateSql, [status, complaintId]);

    // جلب بيانات البلاغ
    const [complaint] = await query(
      `SELECT tenant_id, admin_id, category, description, admin_notes, created_at FROM noise_complaints WHERE id = ?`,
      [complaintId]
    );

    if (status === 'تم الحل') {
      const archiveSql = `
        INSERT INTO archived_noise_complaints (tenant_id, admin_id, category, description, status, admin_notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      await query(archiveSql, [
        complaint.tenant_id,
        complaint.admin_id,
        complaint.category,
        complaint.description,
        status,
        complaint.admin_notes,
        complaint.created_at,
      ]);

      // حذف البلاغ الأصلي بعد الأرشفة
      await query(`DELETE FROM noise_complaints WHERE id = ?`, [complaintId]);
    }

    // جلب FCM Token و user_id للمستأجر
    const [tenant] = await query(
      `SELECT fcm_token, user_id FROM users WHERE id = ?`,
      [complaint.tenant_id]
    );

    if (tenant && tenant.fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: tenant.fcm_token,
          notification: {
            title: 'تحديث حالة بلاغ الإزعاج ⚠️',
            body: `تم تحديث حالة بلاغ (${complaint.category}) إلى: ${status}`,
          },
          data: {
            screen: 'notifications',
            userId: tenant.user_id,
            userType: 'user',
            senderType: userType,
            status,
          },
        },
      };

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        }
      );
    }

    // ✅ إضافة سجل دائم في جدول الإشعارات
    await query(`
      INSERT INTO notifications (user_id, title, body, sender_id)
      VALUES (?, ?, ?, ?)
    `, [
      tenant.user_id,
      'تحديث حالة بلاغ الإزعاج ⚠️',
      `تم تحديث حالة بلاغ (${complaint.category}) إلى: ${status}`,
      senderId
    ]);

    res.json({ message: '✅ تم تحديث حالة البلاغ بنجاح' });

  } catch (err) {
    console.error('❌ Update-complaint-status Error:', err);
    res.status(500).json({ message: '❌ فشل في تحديث الحالة' });
  }
});



app.delete('/api/noise-complaints/:id', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { id } = req.params;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه الحذف' });
  }

  const sql = `
    DELETE FROM noise_complaints WHERE id = ?
  `;

  try {
    await query(sql, [id]);
    res.json({ message: '🗑️ تم حذف البلاغ بنجاح' });

  } catch (err) {
    console.error('❌ Delete-complaint Error:', err);
    res.status(500).json({ message: '❌ خطأ أثناء الحذف' });
  }
});




app.get('/api/noise-complaints/:id', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const complaintId = req.params.id;

  const sql = `
    SELECT * FROM noise_complaints WHERE id = ?
  `;

  try {
    const complaints = await query(sql, [complaintId]);

    if (complaints.length === 0) {
      return res.status(404).json({ message: 'البلاغ غير موجود' });
    }

    const complaint = complaints[0];

    if (userType === 'user' && complaint.tenant_id !== userId) {
      return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول لهذا البلاغ' });
    }

    if (userType === 'admin' && complaint.admin_id !== userId) {
      return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول لهذا البلاغ' });
    }

    res.json({ complaint });

  } catch (err) {
    console.error('❌ Get-complaint Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب البلاغ' });
  }
});


app.get('/api/admin/all-notifications/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  try {
    // جلب إشعارات الصيانة
    const maintenance = await query(
      `SELECT id, tenant_id, description, status, created_at 
       FROM maintenance_requests 
       WHERE admin_id = ? 
       ORDER BY created_at DESC`,
      [adminId]
    );

    // جلب بلاغات الإزعاج
    const noise = await query(
      `SELECT id, tenant_id, category, description, status, created_at 
       FROM noise_complaints 
       WHERE admin_id = ? 
       ORDER BY created_at DESC`,
      [adminId]
    );

    // دمج النتائج مع نوع الإشعار
    const notifications = [
      ...maintenance.map(item => ({
        type: 'maintenance',
        id: item.id,
        tenant_id: item.tenant_id,
        title: 'طلب صيانة',
        description: item.description,
        status: item.status,
        created_at: item.created_at,
      })),
      ...noise.map(item => ({
        type: 'noise',
        id: item.id,
        tenant_id: item.tenant_id,
        title: item.category || 'بلاغ إزعاج',
        description: item.description,
        status: item.status,
        created_at: item.created_at,
      })),
    ];

    // ترتيب حسب الأحدث
    notifications.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({ notifications });

  } catch (err) {
    console.error('❌ All-notifications Error:', err);
    res.status(500).json({ message: 'خطأ داخلي في جلب الإشعارات', error: err });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/api/payment-alert', verifyToken, async (req, res) => {
  const userId = req.user.id;

  const selectSql = `
    SELECT is_enabled, days_before FROM payment_alert_settings WHERE user_id = ?
  `;
  const insertSql = `
    INSERT INTO payment_alert_settings (user_id) VALUES (?)
  `;

  try {
    const existingRows = await query(selectSql, [userId]);

    if (existingRows.length) {
      return res.json({ ...existingRows[0] });
    }

    await query(insertSql, [userId]);

    res.json({ is_enabled: true, days_before: 3 });

  } catch (err) {
    console.error('❌ Get-payment-alert Error:', err);
    res.status(500).json({ message: 'خطأ في جلب الإعدادات' });
  }
});


app.put('/api/payment-alert', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { is_enabled, days_before } = req.body;

  if (typeof is_enabled !== 'boolean' || isNaN(days_before)) {
    return res.status(400).json({ message: '❗ البيانات غير صالحة' });
  }

  const sql = `
    INSERT INTO payment_alert_settings (user_id, is_enabled, days_before)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled), days_before = VALUES(days_before)
  `;

  try {
    await query(sql, [userId, is_enabled, days_before]);
    res.json({ message: '✅ تم حفظ الإعدادات بنجاح' });

  } catch (err) {
    console.error('❌ Update-payment-alert Error:', err);
    res.status(500).json({ message: 'فشل في تحديث الإعدادات' });
  }
});


app.get('/api/payment-alert/:targetUserId', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { targetUserId } = req.params;

  if (!['super', 'admin'].includes(userType)) {
    return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول' });
  }

  const getUserSql = 'SELECT id FROM users WHERE user_id = ? LIMIT 1';
  const selectSql = 'SELECT is_enabled, days_before FROM payment_alert_settings WHERE user_id = ?';
  const insertSql = 'INSERT INTO payment_alert_settings (user_id) VALUES (?)';

  try {
    const userRows = await query(getUserSql, [targetUserId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }

    const userRow = userRows[0];

    const existingRows = await query(selectSql, [userRow.id]);

    if (existingRows.length) {
      return res.json({ ...existingRows[0] });
    }

    await query(insertSql, [userRow.id]);

    res.json({ is_enabled: true, days_before: 3 });

  } catch (err) {
    console.error('❌ Get-user-payment-alert Error:', err);
    res.status(500).json({ message: '❌ خطأ في جلب الإعدادات' });
  }
});



app.put('/api/payment-alert/:targetUserId', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { targetUserId } = req.params;
  const { is_enabled, days_before } = req.body;

  if (!['super', 'admin'].includes(userType)) {
    return res.status(403).json({ message: '❌ لا تملك صلاحية التعديل' });
  }

  if (typeof is_enabled !== 'boolean' || isNaN(days_before)) {
    return res.status(400).json({ message: '❗ البيانات غير صالحة' });
  }

  const getUserSql = 'SELECT id FROM users WHERE user_id = ? LIMIT 1';

  const updateSql = `
    INSERT INTO payment_alert_settings (user_id, is_enabled, days_before)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled), days_before = VALUES(days_before)
  `;

  try {
    const userRows = await query(getUserSql, [targetUserId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }

    const userRow = userRows[0];

    await query(updateSql, [userRow.id, is_enabled, days_before]);
    res.json({ message: '✅ تم تحديث إعدادات المستخدم' });

  } catch (err) {
    console.error('❌ Update-user-payment-alert Error:', err);
    res.status(500).json({ message: '❌ فشل في تحديث الإعدادات' });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// جلب جميع المستأجرين للمالك الحالي
app.get('/api/admin-tenants/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  const { address, floor } = req.query;

  let sql = `
    SELECT 
      tenant_id, tenant_name, contract_number, contract_start, contract_end, contract_type,
      tenant_phone, tenant_email, tenant_address, unit_number, unit_floor_number, property_national_address
    FROM rental_contracts_details
    WHERE admin_id = ?
  `;
  const params = [adminId];

  if (address) {
    sql += ' AND property_national_address = ?';
    params.push(address);
  }

  if (floor) {
    sql += ' AND unit_floor_number = ?';
    params.push(floor);
  }

  sql += ' ORDER BY created_at DESC';

  try {
    const tenants = await query(sql, params);
    res.json({ tenants });

  } catch (err) {
    console.error('❌ Admin-tenants-fetch Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});






app.get('/api/admin-finance-summary/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const contractsSumSql = `
    SELECT 
      IFNULL(SUM(total_contract_value), 0) AS total_contracts,
      COUNT(*) AS contracts_count
    FROM rental_contracts_details
    WHERE admin_id = ? AND contract_end > CURDATE()
  `;

  const paymentsSumSql = `
    SELECT 
  IFNULL(SUM(p.paid_amount), 0) AS total_paid
FROM payments p
JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
WHERE rcd.admin_id = ? 
  AND p.payment_status IN ('مدفوعة', 'مدفوعة جزئياً') 
  AND rcd.contract_end > CURDATE()
  `;

  try {
    const contractsRows = await query(contractsSumSql, [adminId]);
    const paymentsRows = await query(paymentsSumSql, [adminId]);

    const total_contracts = contractsRows[0].total_contracts;
    const contracts_count = contractsRows[0].contracts_count;
    const total_paid = paymentsRows[0].total_paid;
    const total_remaining = total_contracts - total_paid;

    res.json({
      total_contracts,
      total_paid,
      total_remaining,
      contracts_count,
    });

  } catch (err) {
    console.error('❌ Admin-finance-summary Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-finance-monthly/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      DATE_FORMAT(date_range.month, '%Y-%m') AS month,
      IFNULL(SUM(rcd.periodic_rent_payment), 0) AS monthly_expected_income,
      COUNT(rcd.id) AS contracts_count
    FROM (
      SELECT CURDATE() - INTERVAL (a.a + (10 * b.a)) MONTH AS month
      FROM (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS a
      CROSS JOIN (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS b
    ) AS date_range
    JOIN rental_contracts_details rcd 
      ON rcd.admin_id = ? 
      AND date_range.month BETWEEN DATE_FORMAT(rcd.contract_start, '%Y-%m-01') AND DATE_FORMAT(rcd.contract_end, '%Y-%m-01')
      AND rcd.contract_end > CURDATE()
    GROUP BY month
    ORDER BY month DESC
  `;

  try {
    const monthly = await query(sql, [adminId]);
    res.json({ monthly });

  } catch (err) {
    console.error('❌ Admin-finance-monthly Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-finance-yearly/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      years.year AS year,
      IFNULL(SUM(rcd.periodic_rent_payment) * 12, 0) AS yearly_expected_income,
      COUNT(DISTINCT rcd.id) AS contracts_count
    FROM (
      SELECT YEAR(CURDATE()) AS year
      UNION SELECT YEAR(CURDATE()) - 1
      UNION SELECT YEAR(CURDATE()) - 2
      UNION SELECT YEAR(CURDATE()) - 3
      UNION SELECT YEAR(CURDATE()) - 4
    ) AS years
    JOIN rental_contracts_details rcd 
      ON rcd.admin_id = ?
      AND (
        YEAR(rcd.contract_start) <= years.year 
        AND YEAR(rcd.contract_end) >= years.year
      )
      AND rcd.contract_end > CURDATE()
    GROUP BY years.year
    ORDER BY years.year DESC
  `;

  try {
    const yearly = await query(sql, [adminId]);
    res.json({ yearly });

  } catch (err) {
    console.error('❌ Admin-finance-yearly Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.get('/api/admin-contracts-finance/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
  rcd.contract_number,
  rcd.tenant_name,
  rcd.total_contract_value,
  IFNULL(SUM(p.paid_amount), 0) AS paid,
  (rcd.total_contract_value - IFNULL(SUM(p.paid_amount), 0)) AS remaining
FROM rental_contracts_details rcd
LEFT JOIN payments p ON p.contract_id = rcd.id AND p.payment_status IN ('مدفوعة', 'مدفوعة جزئياً')
WHERE rcd.admin_id = ? AND rcd.contract_end > CURDATE()
GROUP BY rcd.id
ORDER BY rcd.contract_start DESC
  `;

  try {
    const contracts = await query(sql, [adminId]);
    res.json({ contracts });

  } catch (err) {
    console.error('❌ Admin-contracts-finance Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-expiring-contracts/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      contract_number, tenant_name, contract_end
    FROM rental_contracts_details
    WHERE admin_id = ? 
      AND contract_end >= CURDATE() 
      AND contract_end <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)
    ORDER BY contract_end ASC
  `;

  try {
    const expiring = await query(sql, [adminId]);
    res.json({ expiring });

  } catch (err) {
    console.error('❌ Admin-expiring-contracts Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-arrears/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      p.id, -- أضف هذا السطر
      p.payment_number, 
      p.payment_amount, 
      p.due_date, 
      p.remaining_amount,
      p.payment_status,
      rcd.contract_number, 
      rcd.tenant_name,
      rcd.tenant_id  -- ✅ تأكد من هذا العمود
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    WHERE rcd.admin_id = ? 
      AND p.payment_status != 'مدفوعة' 
      AND p.due_date < CURDATE()
      AND rcd.contract_end > CURDATE()
    ORDER BY p.due_date ASC
  `;

  try {
    const arrears = await query(sql, [adminId]);
    res.json({ arrears });
  } catch (err) {
    console.error('❌ Admin-arrears Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-contracts-growth/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      month,
      count,
      count - IFNULL(LAG(count) OVER (ORDER BY month), 0) AS growth
    FROM (
      SELECT DATE_FORMAT(created_at, '%Y-%m') AS month,
             COUNT(*) AS count
      FROM rental_contracts_details
      WHERE admin_id = ?
      GROUP BY month
    ) monthly_counts
    ORDER BY month DESC
    LIMIT 12
  `;

  try {
    const rows = await query(sql, [adminId]);
    res.json({ monthly_contracts_growth: rows });

  } catch (err) {
    console.error('❌ Admin-contracts-growth Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.get('/api/admin-finance-6months/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
  SELECT
    CONCAT(years.year, '-', LPAD(periods.start_month, 2, '0'), ' ~ ', LPAD(periods.end_month, 2, '0')) AS period,
    IFNULL(SUM(rcd.periodic_rent_payment) * 6, 0) AS six_months_expected_income,
    COUNT(DISTINCT rcd.id) AS contracts_count
  FROM (
    SELECT YEAR(CURDATE()) AS year UNION SELECT YEAR(CURDATE()) - 1
  ) AS years
  CROSS JOIN (
    SELECT 1 AS start_month, 6 AS end_month UNION ALL
    SELECT 7 AS start_month, 12 AS end_month
  ) AS periods
  JOIN rental_contracts_details rcd ON rcd.admin_id = ?
    AND (
      DATE(rcd.contract_start) <= LAST_DAY(CONCAT(years.year, '-', periods.end_month, '-01'))
      AND DATE(rcd.contract_end) >= DATE(CONCAT(years.year, '-', periods.start_month, '-01'))
      AND rcd.contract_end > CURDATE()
    )
  GROUP BY years.year, periods.start_month, periods.end_month
  ORDER BY years.year DESC, periods.start_month DESC
`;
  try {
    const rows = await query(sql, [adminId]);
    res.json({ six_months: rows });

  } catch (err) {
    console.error('❌ Admin-finance-6months Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.get('/api/admin-collection-rate/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      (
        (SELECT IFNULL(SUM(p.payment_amount),0) FROM payments p
         JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
         WHERE rcd.admin_id = ? AND p.payment_status = 'مدفوعة' AND rcd.contract_end > CURDATE())
        /
        (SELECT IFNULL(SUM(total_contract_value),0) FROM rental_contracts_details WHERE admin_id = ? AND contract_end > CURDATE())
      ) * 100 AS collection_rate
  `;

  try {
    const rows = await query(sql, [adminId, adminId]);
    res.json({ collection_rate: rows[0].collection_rate || 0 });

  } catch (err) {
    console.error('❌ Admin-collection-rate Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});




app.get('/api/admin-finance-period/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;
  const { from, to } = req.query;

  const sql = `
    SELECT 
      IFNULL(SUM(p.payment_amount), 0) AS paid_sum
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    WHERE rcd.admin_id = ? 
      AND p.payment_status = 'مدفوعة' 
      AND p.paid_date BETWEEN ? AND ?
  `;

  try {
    const rows = await query(sql, [adminId, from, to]);
    res.json({ paid_sum: rows[0].paid_sum || 0 });

  } catch (err) {
    console.error('❌ Admin-finance-period Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


app.get('/api/admin-properties-stats/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      property_units_count AS units_count,
      COUNT(DISTINCT property_id) AS properties_count
    FROM rental_contracts_details
    WHERE admin_id = ? AND contract_end > CURDATE()
    GROUP BY property_units_count
    ORDER BY property_units_count ASC;
  `;

  try {
    const rows = await query(sql, [adminId]);
    res.json({ properties_stats: rows });

  } catch (err) {
    console.error('❌ Admin-properties-stats Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});



app.post('/api/renew-contract', upload.single('pdf'), async (req, res) => {
  const contractId = req.body.contractId;
  const admin_id = req.user?.id || req.body.adminId;

  if (!req.file) {
    return res.status(400).json({ message: 'يجب رفع ملف PDF جديد لتجديد العقد' });
  }

  try {
    const tempPath = req.file.path;
    const gcsFileName = `${Date.now()}-${req.file.originalname}`;

    await bucket.upload(tempPath, {
      destination: gcsFileName,
      resumable: false,
      contentType: req.file.mimetype,
      metadata: {
        cacheControl: 'public, max-age=31536000',
      },
    });



    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${gcsFileName}`;
    const fileBuffer = fs.readFileSync(tempPath); // ⬅️ لتحليل المحتوى
    const pdfData = await pdfParse(fileBuffer);   // ⬅️ تحليل الملف
    const text = pdfData.text;                    // ⬅️ النص اللي راح تستخدمه
    const extract = (regex) => (text.match(regex) || [])[1]?.trim() || '';
    const toFloat = (v) => parseFloat(v) || 0;
    const toInt = (v) => parseInt(v) || 0;
    console.log('📄 Temp Path:', tempPath);
    console.log('📄 File Exists:', fs.existsSync(tempPath));
    console.log('📄 File Size:', fs.statSync(tempPath).size);



    const data = {
      contract_number: extract(/Contract No\.(.+?):العقد سجل رقم/),
      contract_type: extract(/Contract Type(.+?):العقد نوع/),
      contract_date: extract(/Contract Sealing Date(\d{4}-\d{2}-\d{2})/),
      contract_start: extract(/Tenancy Start Date(\d{4}-\d{2}-\d{2})/),
      contract_end: extract(/Tenancy End Date(\d{4}-\d{2}-\d{2})/),
      contract_location: extract(/Location\n(.+?):العقد إبرام مكان/),

      // Tenant Information
      tenant_name: (() => {
        let raw = '';
        let match = text.match(/Name\s*الاسم:?\s*(.+)/);
        if (match && match[1]) {
          raw = match[1].trim();
        } else {
          match = text.match(/Tenant Data[\s\S]*?Name(.+?):الاسم/);
          if (match && match[1]) raw = match[1].trim();
        }
        return !raw ? '' : raw.split(/\s+/).reverse().join(' ');
      })(),

      tenant_nationality: extract(/Tenant Data[\s\S]*?Nationality(.+?):الجنسي/),
      tenant_id_type: (() => {
        const raw = extract(/Tenant Data[\s\S]*?ID Type(.+?):الهوي/).trim();
        return !raw ? '' : raw.split(/\s+/).reverse().join(' ');
      })(),
      tenant_id_number: extract(/Tenant Data[\s\S]*?ID No\.(\d+):الهوي/),
      tenant_email: extract(/Tenant Data[\s\S]*?Email(.+?):الإلكتروني البريد/) || '-',
      tenant_phone: extract(/Tenant Data[\s\S]*?Mobile No\.(\+?\d+):الجو/),
      tenant_address: (() => {
        const raw = extract(/Tenant Data[\s\S]*?National Address(.+?):الوطني العنوان/).trim();
        if (!raw) return '';
        const parts = raw.split(/,\s*/);
        return parts.map(part => part.split(/\s+/).reverse().join(' ')).reverse().join(', ');
      })(),

      // Owner Information
      owner_name: extract(/Lessor Data[\s\S]*?Name(.+?):الاسم/).split(' ').reverse().join(' '),
      owner_nationality: (() => {
        const lines = text.split('\n');
        const i = lines.findIndex(line => line.includes('Nationality'));
        if (i !== -1 && lines[i + 1] && lines[i + 2]) {
          const raw = `${lines[i + 1].trim()} ${lines[i + 2].trim()}`;
          const words = raw.split(/\s+/);
          if (words.includes('السعودية') && words.includes('العربية') && words.includes('المملكة')) {
            return 'المملكة العربية السعودية';
          }
          return raw;
        }
        return (i !== -1 && lines[i + 1]) ? lines[i + 1].trim() : '';
      })(),
      owner_id_type: (() => {
        const lines = text.split('\n');
        const idx = lines.findIndex(line => line.includes('ID Type'));
        let result = '';
        if (idx !== -1) {
          const line = lines[idx];
          const match = line.match(/ID Type\s*([^\:]+):الهوي/);
          if (match && match[1]) result = match[1].trim();
          else {
            const start = line.indexOf('ID Type') + 'ID Type'.length;
            const end = line.indexOf(':الهوي');
            if (end > start) result = line.substring(start, end).trim();
          }
        }
        if (result) {
          const words = result.split(/\s+/);
          if (words.length === 2 && (words[0].endsWith('ية') || words[0].endsWith('يم'))) {
            return `${words[1]} ${words[0]}`;
          }
        }
        return result;
      })(),
      owner_id_number: extract(/Lessor Data[\s\S]*?ID No\.(\d+):الهوي/),
      owner_email: extract(/Lessor Data[\s\S]*?Email(.+?):الإلكتروني البريد/),
      owner_phone: extract(/Lessor Data[\s\S]*?Mobile No\.(\+?\d+):الجو/),
      owner_address: (() => {
        let addr = '';
        const match = text.match(/National Address\s*:?([^\n:]+):الوطني العنوان/);
        if (match && match[1]) addr = match[1].replace(/\s+/g, ' ').trim();
        else {
          const alt = text.match(/العنوان الوطني:\s*([^\n:]+)\s*Address National/);
          if (alt && alt[1]) addr = alt[1].replace(/\s+/g, ' ').trim();
        }
        return addr.split(/\s+/).reverse().join(' ');
      })(),

      // Financial Data
      annual_rent: toFloat(extract(/Annual Rent\s*(\d+\.\d+)/)),
      periodic_rent_payment: toFloat(extract(/Regular Rent Payment:\s*(\d+\.\d+)/)),
      rent_payment_cycle: extract(/Rent payment cycle\s*(\S+)/).replace(/الايجار.*/, '').trim(),
      rent_payments_count: toInt(extract(/Number of Rent\s*Payments:\s*(\d+)/)),
      total_contract_value: toFloat(extract(/Total Contract value\s*(\d+\.\d+)/)),

      // Property Information
      property_usage: (() => {
        const raw = extract(/Property Usage\s*(.+?)\s*استخدام/).trim();
        return !raw ? '' : raw.split(/,\s*/).map(part => part.split(/\s+/).reverse().join(' ')).join(', ');
      })(),
      property_building_type: extract(/Property Type(.+?):العقار بناء نوع/),
      property_units_count: toInt(extract(/Number of Units(\d+)/)),
      property_floors_count: toInt(extract(/Number of Floors(\d+)/)),
      property_national_address: extract(/Property Data[\s\S]*?National Address(.+?):الوطني العنوان/),

      // Unit Information
      unit_type: extract(/Unit Type(.+?):الوحدة نوع/),
      unit_number: extract(/Unit No\.(.+?):الوحدة رقم/),
      unit_floor_number: toInt(extract(/Floor No\.(\d+):الطابق رقم/)),
      unit_area: toFloat(extract(/Unit Area(\d+\.\d+):الوحدة مساحة/)),
      unit_furnishing_status: extract(/Furnishing Status\s*[-:]?\s*(.*?)\s*Number of AC units/),
      unit_ac_units_count: toInt(extract(/Number of AC units(\d+)/)),
      unit_ac_type: (() => {
        const raw = extract(/AC Type(.+?)التكييف نوع/).trim();
        return !raw ? '' : raw.split(/,\s*/).map(part => part.split(/\s+/).reverse().join(' ')).join(', ');
      })(),





      pdf_path: publicUrl,
      tenant_id: null, // بنعبيها بعدين
      admin_id: admin_id
    };


    const today = new Date();
    const contractEndDate = new Date(data.contract_end);

    if (contractEndDate <= today) {
      return res.status(400).json({
        message: '❌ لا يمكن تجديد العقد لأن تاريخ انتهاء العقد الجديد منتهي أو ينتهي اليوم.',
        contract_end: data.contract_end
      });
    }



    // تحقق من وجود العقار أو أنشئه
    let property_id;
    const [existingProperty] = await query(`
      SELECT property_id FROM properties
      WHERE property_national_address = ? AND admin_id = ?
      LIMIT 1
    `, [data.property_national_address, admin_id]);

    if (existingProperty) {
      property_id = existingProperty.property_id;
    } else {
      const insertResult = await query(`
        INSERT INTO properties (property_national_address, property_units_count, admin_id)
        VALUES (?, ?, ?)
      `, [data.property_national_address, data.property_units_count, admin_id]);

      property_id = insertResult.insertId;
    }

    data.property_id = property_id;

    // أرشفة العقد القديم
    const archiveSql = `
      INSERT INTO contracts_archive (
        contract_id, contract_number, contract_type, contract_date, contract_start, contract_end,
        contract_location, owner_name, owner_nationality, owner_id_type, owner_id_number, owner_email,
        owner_phone, owner_address, tenant_name, tenant_nationality, tenant_id_type, tenant_id_number,
        tenant_email, tenant_phone, tenant_address, property_national_address, property_building_type,
        property_usage, property_units_count, property_floors_count, unit_type, unit_number, unit_floor_number,
        unit_area, unit_furnishing_status, unit_ac_units_count, unit_ac_type, annual_rent,
        periodic_rent_payment, rent_payment_cycle, rent_payments_count, total_contract_value,
        terms_conditions, privacy_policy, pdf_path, tenant_id, admin_id, property_id, tenant_serial_number, archived_at
      )
      SELECT
        id, contract_number, contract_type, contract_date, contract_start, contract_end,
        contract_location, owner_name, owner_nationality, owner_id_type, owner_id_number, owner_email,
        owner_phone, owner_address, tenant_name, tenant_nationality, tenant_id_type, tenant_id_number,
        tenant_email, tenant_phone, tenant_address, property_national_address, property_building_type,
        property_usage, property_units_count, property_floors_count, unit_type, unit_number, unit_floor_number,
        unit_area, unit_furnishing_status, unit_ac_units_count, unit_ac_type, annual_rent,
        periodic_rent_payment, rent_payment_cycle, rent_payments_count, total_contract_value,
        terms_conditions, privacy_policy, pdf_path, tenant_id, admin_id, property_id, tenant_serial_number, NOW()
      FROM rental_contracts_details
      WHERE id = ?
    `;


    const [existingContract] = await query(`
  SELECT tenant_id FROM rental_contracts_details WHERE id = ?
`, [contractId]);

    if (!existingContract || !existingContract.tenant_id) {
      return res.status(400).json({ message: 'لم يتم العثور على معرف المستأجر للعقد القديم.' });
    }

    data.tenant_id = existingContract.tenant_id;

    await query(archiveSql, [contractId]);

    // تحديث العقد الجديد
    const updateFields = Object.keys(data)
      .filter(key => key !== 'tenant_id') // مستبعد tenant_id
      .map(key => `${key}=?`).join(', ');

    const updateValues = Object.keys(data)
      .filter(key => key !== 'tenant_id')
      .map(key => data[key]);

    updateValues.push(contractId);  // إضافة شرط الـ WHERE في نهاية المصفوفة

    const updateSql = `
  UPDATE rental_contracts_details SET ${updateFields} WHERE id=?
`;

    await query(updateSql, updateValues);

    res.json({
      message: '✅ تم تجديد العقد بنجاح وأرشفة النسخة القديمة.',
      contract_id: contractId,
      property_id: property_id,
      contract_start: data.contract_start,
      contract_end: data.contract_end
    });

  } catch (err) {
    console.error('❌ Renew-contract Error:', err);
    res.status(500).json({ message: 'خطأ في تجديد العقد', error: err });
  }
});


app.get('/api/contracts-archive', verifyToken, async (req, res) => {
  const sql = `
    SELECT 
      archive_id, tenant_name, contract_number, archived_at
    FROM contracts_archive
    ORDER BY archived_at DESC
  `;

  try {
    const rows = await query(sql);
    res.json({ archived_contracts: rows });
  } catch (err) {
    console.error('❌ Contracts-Archive List Error:', err);
    res.status(500).json({ message: 'فشل في جلب العقود المؤرشفة', error: err });
  }
});


app.get('/api/contracts-archive/:archiveId', verifyToken, async (req, res) => {
  const { archiveId } = req.params;

  const sql = `
    SELECT *
    FROM contracts_archive
    WHERE archive_id = ?
    LIMIT 1
  `;

  try {

    const [contract] = await query(sql, [archiveId]);

    if (!contract) {
      return res.status(404).json({ message: 'لم يتم العثور على العقد المؤرشف' });
    }

    res.json({ contract });
  } catch (err) {
    console.error('❌ Contract Archive Details Error:', err);
    res.status(500).json({ message: 'فشل في جلب تفاصيل العقد', error: err });
  }
});








app.get('/api/check-username/:username', verifyToken, async (req, res) => {
  const { username } = req.params;

  const sql = 'SELECT COUNT(*) AS count FROM users WHERE user_id = ?';
  try {
    const [result] = await query(sql, [username]);
    res.json({ exists: result.count > 0 });
  } catch (err) {
    console.error('Error checking username:', err);
    res.status(500).json({ message: 'DB Error' });
  }
});


app.get('/api/tenants-expiring/:adminId', verifyToken, async (req, res) => {
  const adminId = req.params.adminId;

  const sql = `
    SELECT id, tenant_name, unit_number, contract_end, contract_number
    FROM rental_contracts_details
    WHERE admin_id = ?
      AND (contract_end <= CURDATE() OR contract_end BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY))
    ORDER BY contract_end ASC
  `;

  try {
    const tenants = await query(sql, [adminId]);
    res.json({ tenants });
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// يجب أن يكون Firebase Admin SDK مُعد مسبقًا على backend

app.post('/api/verify-phone-login', async (req, res) => {
  const { idToken, phone_number } = req.body;

  if (!idToken || !phone_number) {
    return res.status(400).json({ message: 'بيانات الإدخال مطلوبة.' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const firebasePhone = decodedToken.phone_number;
    const formattedPhone = formatInternationalPhoneNumber(phone_number);

    if (firebasePhone !== formattedPhone) {
      return res.status(401).json({ message: '❌ الرقم غير مطابق لما تم التحقق منه.' });
    }

    const [user] = await query(
      'SELECT id, user_id, name, user_type FROM users WHERE phone_number = ? LIMIT 1', 
      [formattedPhone]
    );

    if (!user || !user.user_id || !user.name || !user.user_type) {
      return res.status(500).json({ message: '❌ بيانات المستخدم ناقصة أو غير صحيحة.' });
    }

    return sendLoginSuccess(res, user);

  } catch (err) {
    console.error('خطأ في التحقق من رقم الجوال:', err);
    res.status(500).json({ message: 'حدث خطأ داخلي.' });
  }
});





app.post('/api/check-phone-registered', async (req, res) => {
  const { phone_number } = req.body;

  if (!phone_number) {
    return res.status(400).json({ message: 'رقم الجوال مطلوب.' });
  }

  let formattedPhone;

  try {
    formattedPhone = formatInternationalPhoneNumber(phone_number);
  } catch (err) {
    return res.status(400).json({ message: '❌ صيغة رقم الجوال غير صحيحة.' });
  }

  try {
    const [user] = await query('SELECT id FROM users WHERE phone_number = ? LIMIT 1', [formattedPhone]);

    if (!user) {
      return res.status(404).json({ message: '❌ رقم الجوال غير مسجل.' });
    }

    res.json({ message: '✅ الرقم مسجل، يمكنك طلب OTP الآن.' });

  } catch (err) {
    console.error('خطأ في التحقق من رقم الجوال:', err);
    res.status(500).json({ message: 'حدث خطأ داخلي.' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const articlesBucket = storage.bucket('image50154');  

app.post('/api/upload-article-image', upload.single('image'), async (req, res) => {
  try {
    console.log('🔵 [رفع صورة] استقبلنا الطلب');
    if (!req.file) {
      console.warn('⚠️ لم يتم رفع صورة!');
      return res.status(400).json({ message: 'لم يتم رفع صورة' });
    }

    const tempPath = req.file.path;
    const gcsFileName = `articles/${Date.now()}-${req.file.originalname}`;
    console.log('🔵 tempPath:', tempPath);
    console.log('🔵 gcsFileName:', gcsFileName);

    await articlesBucket.upload(tempPath, {
      destination: gcsFileName,
      resumable: false,
      contentType: req.file.mimetype,
      metadata: { cacheControl: 'public, max-age=31536000' },
    });

    console.log('✅ تم رفع الصورة بنجاح:', gcsFileName);

    // أرجع اسم الملف فقط (وليس رابط)
    res.json({ imageFileName: gcsFileName });
  } catch (err) {
    console.error('❌ Image Upload Error:', err, err.stack);
    res.status(500).json({ message: 'فشل رفع الصورة', error: err.message });
  }
});

app.get('/api/article-image/:fileName', verifyToken, async (req, res) => {
  const { fileName } = req.params;
  try {
    console.log('🔵 [جلب رابط موقع] fileName:', fileName);
    const filePath = fileName.startsWith('articles/') ? fileName : `articles/${fileName}`;
    console.log('🔵 filePath المستخدم:', filePath);

    const file = articlesBucket.file(filePath);

    // تحقق من وجود الملف فعلياً
    const [exists] = await file.exists();
    console.log('🔵 هل الملف موجود في الباكيت؟', exists);
    if (!exists) {
      return res.status(404).json({ message: 'الصورة غير موجودة في التخزين' });
    }

    // رابط موقع صالح لأسبوع (7 أيام فقط)
    const [signedUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 أيام فقط
    });
    console.log('✅ تم توليد الرابط الموقع:', signedUrl);

    res.json({ url: signedUrl });
  } catch (err) {
    console.error('❌ Signed URL Error:', err, err.stack);
    res.status(500).json({ message: 'فشل في توليد الرابط المؤقت', error: err.message });
  }
});


app.post('/api/articles/:id/toggle-like', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const articleId = req.params.id;

  try {
    const [existingLike] = await query(
      `SELECT id FROM article_likes WHERE article_id=? AND user_id=?`,
      [articleId, userId]
    );

    if (existingLike) {
      // حذف الإعجاب الموجود
      await query(`DELETE FROM article_likes WHERE id=?`, [existingLike.id]);
      res.json({ message: 'تم إلغاء الإعجاب', liked: false });
    } else {
      // إضافة إعجاب جديد
      await query(
        `INSERT INTO article_likes (article_id, user_id) VALUES (?, ?)`,
        [articleId, userId]
      );
      res.json({ message: 'تم تسجيل الإعجاب', liked: true });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء تسجيل الإعجاب' });
  }
});


app.post('/api/articles/:id/mark-viewed', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const articleId = req.params.id;

  try {
    await query(
      `INSERT IGNORE INTO article_views (article_id, user_id) VALUES (?, ?)`,
      [articleId, userId]
    );
    res.json({ message: 'تم تسجيل المحتوى كمقروء' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء تسجيل المحتوى كمقروء' });
  }
});

app.get('/api/articles/:id/stats', verifyToken, async (req, res) => {
  const articleId = req.params.id;

  try {
    const [likesCount] = await query(
      `SELECT COUNT(*) AS total_likes FROM article_likes WHERE article_id=?`,
      [articleId]
    );

    const [viewsCount] = await query(
      `SELECT COUNT(*) AS total_views FROM article_views WHERE article_id=?`,
      [articleId]
    );

    res.json({
      likes: likesCount.total_likes,
      views: viewsCount.total_views,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب إحصائيات المحتوى' });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/rental-units/:id/publish-ad', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    // تحديد تاريخ بداية ونهاية الإعلان (7 أيام من اليوم)
    const today = new Date();
    const startDate = today;
    const endDate = new Date(today);
    endDate.setDate(today.getDate() + 7);

    // تحقق من وجود إعلان نشط لنفس الشقة خلال الفترة المحددة
    const [existingAd] = await query(`
      SELECT id FROM articles_offers_ads
      WHERE property_id = ?
        AND type = 'ad'
        AND is_active = 1
        AND is_visible = 1
        AND (
          (start_date <= ? AND end_date >= ?)
          OR (start_date BETWEEN ? AND ?)
          OR (end_date BETWEEN ? AND ?)
        )
    `, [
      id,
      endDate, startDate,
      startDate, endDate,
      startDate, endDate
    ]);

    if (existingAd) {
      return res.status(400).json({ message: 'يوجد إعلان نشط لهذه الوحدة في نفس الفترة بالفعل.' });
    }

    // جلب تفاصيل الوحدة
    const [unit] = await query('SELECT * FROM rental_units WHERE id = ?', [id]);
    if (!unit) {
      return res.status(404).json({ message: 'الوحدة غير موجودة' });
    }

    // إنشاء الإعلان الجديد
    const insertResult = await query(`
      INSERT INTO articles_offers_ads 
      (title, content, type, price, rooms, area, amenities, contact_info, property_id, start_date, end_date, created_by)
      VALUES (?, ?, 'ad', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      unit.title,
      unit.description,
      unit.price,
      unit.rooms,
      unit.area,
      unit.amenities,
      unit.contact_info,
      unit.id,
      startDate,
      endDate,
      req.user.id
    ]);

    const articleId = insertResult.insertId;

    // تحديث حالة الوحدة إلى "تم نشر إعلان"
    await query('UPDATE rental_units SET is_published_ad = 1 WHERE id = ?', [id]);

    // جلب توكنات FCM للمستخدمين
    const usersFCM = await query('SELECT id AS user_id, fcm_token FROM users WHERE user_type = ?', ['user']);
    const accessToken = await getAccessToken();

    for (const user of usersFCM) {
      if (!user.fcm_token) continue;

      const notificationMessage = {
        message: {
          token: user.fcm_token,
          notification: {
            title: 'إعلان جديد 🏠',
            body: `تم نشر إعلان جديد: ${unit.title}`,
          },
          data: {
            screen: 'articles',
            articleId: String(articleId),
            userId: String(user.user_id),
            userType: 'user',
            senderType: 'admin'
          }
        }
      };

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(notificationMessage),
        }
      );

      await query(`
        INSERT INTO notifications (user_id, title, body)
        VALUES (?, ?, ?)
      `, [user.user_id, 'إعلان جديد 🏠', `تم نشر إعلان جديد: ${unit.title}`]);
    }

    res.status(201).json({ message: 'تم نشر الإعلان بنجاح', articleId });

  } catch (err) {
    console.error('❌ خطأ في نشر الإعلان:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء نشر الإعلان' });
  }
});




// استيراد الـ pool من ملف database.js


app.post('/api/rental-units/create', verifyToken, async (req, res) => {
  const {
    title, description, price, rooms, area, amenities,
    contact_info, imageFileNames
  } = req.body;

  try {
    // إضافة الشقة
    const result = await query(`
      INSERT INTO rental_units 
      (title, description, price, rooms, area, amenities, contact_info, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        title,
        description,
        price || null,
        rooms || null,
        area || null,
        amenities || null,
        contact_info || null,
        req.user.id
      ]
    );

    const rentalUnitId = result.insertId;

    // ربط الصور إذا موجودة
   if (imageFileNames && imageFileNames.length > 0) {
  const imageInserts = imageFileNames.map(img => [rentalUnitId, img]);
  await pool.query(
    'INSERT INTO property_images (unit_id, image_url) VALUES ?',
    [imageInserts]
  );
}


    res.status(201).json({ 
      message: 'تم إضافة الشقة بنجاح', 
      rentalUnitId 
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء إضافة الشقة' });
  }
});



app.get('/api/rental-units', verifyToken, async (req, res) => {
  try {
    const units = await query(`
      SELECT id, title, description, rooms, area, price
      FROM rental_units
      WHERE is_published_ad = 0
      ORDER BY created_at DESC
    `);
    res.json(units);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الوحدات' });
  }
});


app.get('/api/rental-units/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [unit] = await query(`
      SELECT * FROM rental_units WHERE id = ?
    `, [id]);

    if (!unit) {
      return res.status(404).json({ message: 'الوحدة غير موجودة' });
    }

    const images = await query(`
      SELECT image_url FROM property_images WHERE unit_id = ?
    `, [id]);

    unit.images = images.map(img => img.image_url.replace(/^articles\//, '')); // في حال فيه مسار قديم

    res.json(unit);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب تفاصيل الوحدة' });
  }
});


app.put('/api/rental-units/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const {
    title, description, price, rooms, area, amenities,
    contact_info, imageFileNames
  } = req.body;

  try {
    await query(`
      UPDATE rental_units SET
        title = ?,
        description = ?,
        price = ?,
        rooms = ?,
        area = ?,
        amenities = ?,
        contact_info = ?,
        updated_at = NOW()
      WHERE id = ?`,
      [
        title,
        description,
        price || null,
        rooms || null,
        area || null,
        amenities || null,
        contact_info || null,
        id
      ]
    );

    // حذف الصور القديمة وإضافة الجديدة
    await query(`DELETE FROM property_images WHERE unit_id = ?`, [id]);

  if (imageFileNames && imageFileNames.length > 0) {
  const imageInserts = imageFileNames.map(img => [id, img]);
  await pool.query(
    'INSERT INTO property_images (unit_id, image_url) VALUES ?',
    [imageInserts]
  );
}
    // جلب بيانات الشقة المحدّثة
    const [unit] = await query(`SELECT * FROM rental_units WHERE id = ?`, [id]);
    const images = await query(`SELECT image_url FROM property_images WHERE unit_id = ?`, [id]);
    unit.images = images.map(img => img.image_url);

    // إذا منشور لها إعلان، جيب آخر إعلان
    let ad = null;
    if (unit.is_published_ad) {
      const [adRow] = await query(`
        SELECT * FROM articles_offers_ads 
        WHERE property_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
      `, [id]);
      ad = adRow || null;
    }

    res.json({
      message: 'تم تحديث بيانات الشقة بنجاح',
      unit,
      ad
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث الشقة' });
  }
});



app.delete('/api/ads/:adId', verifyToken, async (req, res) => {
  const { adId } = req.params;

  try {
    // 1. حذف مشاهدات وإعجابات الإعلان
    await query('DELETE FROM article_views WHERE article_id = ?', [adId]);
    await query('DELETE FROM article_likes WHERE article_id = ?', [adId]);

    // 2. تحديث حالة الإعلان ليصبح غير نشط وغير ظاهر
    await query('UPDATE articles_offers_ads SET is_active = 0, is_visible = 0 WHERE id = ?', [adId]);

    // 3. تحديث حالة الشقة المرتبطة ليصبح is_published_ad = 0
    await query(`
      UPDATE rental_units ru
      JOIN articles_offers_ads a ON ru.id = a.property_id
      SET ru.is_published_ad = 0
      WHERE a.id = ?
    `, [adId]);

    res.json({ message: 'تم إلغاء تفعيل الإعلان بنجاح' });
  } catch (err) {
     console.error('❌ Delete ad error:', err); // <-- اطبع الخطأ هنا
    res.status(500).json({ message: 'حدث خطأ أثناء حذف الإعلان' });
  }
});


// حذف فعلي كامل للإعلان وكل ما يتعلق به
// حذف فعلي كامل للشقة وكل ما يتعلق بها
app.delete('/api/rental-units/:unitId/permanent', verifyToken, async (req, res) => {
  const { unitId } = req.params;

  try {
    // 1. حذف الصور المرتبطة بالشقة
    await query('DELETE FROM property_images WHERE unit_id = ?', [unitId]);

    // 2. حذف كل الإعلانات المرتبطة بالشقة
    const ads = await query('SELECT id FROM articles_offers_ads WHERE property_id = ?', [unitId]);
    for (const ad of ads) {
      await query('DELETE FROM article_views WHERE article_id = ?', [ad.id]);
      await query('DELETE FROM article_likes WHERE article_id = ?', [ad.id]);
    }
    await query('DELETE FROM articles_offers_ads WHERE property_id = ?', [unitId]);

    // 3. حذف الشقة نفسها
    await query('DELETE FROM rental_units WHERE id = ?', [unitId]);

    res.json({ message: 'تم حذف الشقة وكل ما يتعلق بها نهائياً' });
  } catch (err) {
    console.error('❌ Permanent Delete unit error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء الحذف النهائي للشقة' });
  }
});




app.get('/api/active-ads', verifyToken, async (req, res) => {
  try {
    const today = new Date();
    const todayStr = today.toISOString().slice(0, 10);

    const ads = await query(`
      SELECT 
        a.id,
        a.title,
        a.content,
        a.type,
        a.price,
        a.rooms,
        a.area,
        a.amenities,
        a.contact_info,
        a.property_id,
        a.start_date,
        a.end_date,
        a.created_by,
        a.created_at,
        a.is_active,
        a.is_visible,
        ru.title AS unit_title,
        ru.description AS unit_description,
        ru.price AS unit_price,
        ru.rooms AS unit_rooms,
        ru.area AS unit_area,
        ru.amenities AS unit_amenities,
        ru.contact_info AS unit_contact_info,
        ru.id AS unit_id,
        GROUP_CONCAT(pi.image_url) AS images
      FROM articles_offers_ads a
      LEFT JOIN rental_units ru ON a.property_id = ru.id
      LEFT JOIN property_images pi ON pi.unit_id = ru.id
      WHERE a.type = 'ad'
        AND a.is_active = 1
        AND (a.is_visible IS NULL OR a.is_visible = 1)
        AND (a.start_date IS NULL OR a.start_date <= ?)
        AND (a.end_date IS NULL OR a.end_date >= ?)
      GROUP BY a.id
      ORDER BY a.created_at DESC
    `, [todayStr, todayStr]);

   const formatted = ads.map(ad => ({
  ...ad,
  images: ad.images
    ? ad.images.split(',').map(img => img.replace(/^articles\//, '')) // شيل 'articles/' من أول الاسم
    : []
}));

    res.json(formatted);
  } catch (err) {
    console.error('❌ /api/active-ads Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الإعلانات الفعالة' });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/admin/update-payment-status', verifyToken, async (req, res) => {
  const { payment_id, paid_amount, paid_date, reminder_date } = req.body;

  if (!payment_id || !paid_amount || !paid_date) {
    return res.status(400).json({ message: 'جميع الحقول مطلوبة: payment_id, paid_amount, paid_date' });
  }

  try {
    // جلب تفاصيل الدفعة والمستأجر
    const paymentDetails = await query(
      `SELECT payment_amount, paid_amount, tenant_id FROM payments 
       JOIN rental_contracts_details ON payments.contract_id = rental_contracts_details.id 
       WHERE payments.id = ?`,
      [payment_id]  
    );

    if (paymentDetails.length === 0) {
      return res.status(404).json({ message: 'الدفعة غير موجودة' });
    }

    const { payment_amount, paid_amount: previous_paid, tenant_id } = paymentDetails[0];

    const total_paid_amount = parseFloat(previous_paid || 0) + parseFloat(paid_amount);
    const remaining_amount = parseFloat(payment_amount) - total_paid_amount;

    let payment_status = '';

    if (remaining_amount > 0) {
      payment_status = 'مدفوعة جزئياً';
    } else if (remaining_amount <= 0) {
      payment_status = 'مدفوعة';
    }

    const payment_note =
      remaining_amount > 0
        ? `تم دفع مبلغ ${total_paid_amount} ريال، المتبقي ${remaining_amount} ريال`
        : 'دفعة مستلمة بالكامل';

    // تحديث بيانات الدفعة
    await query(
      `UPDATE payments SET payment_status = ?, paid_date = ?, paid_amount = ?, remaining_amount = ?, reminder_date = ?, payment_note = ? WHERE id = ?`,
      [payment_status, paid_date, total_paid_amount, remaining_amount, reminder_date || null, payment_note, payment_id]
    );

    // جلب FCM Token للمستأجر
    const tenantFCM = await query('SELECT user_id, fcm_token FROM users WHERE id = ?', [tenant_id]);
    const userId = tenantFCM.length > 0 ? tenantFCM[0].user_id : null;
    const fcmToken = tenantFCM.length > 0 ? tenantFCM[0].fcm_token : null;

    // إرسال إشعار FCM إذا متوفر
    if (fcmToken) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: fcmToken,
          notification: {
            title: 'تحديث في الدفعات 💳',
            body: payment_note,
          },
          data: {
            screen: 'notifications',
            userId: userId ? String(userId) : '',
            userType: 'user',
            senderType: 'admin'
          }
        }
      };

      await fetch(
        `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        }
      );
    }

    // إضافة سجل في جدول الإشعارات ليظهر في صفحة الإشعارات
    if (userId) {
      await query(
        `INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)`,
        [userId, 'تحديث في الدفعات 💳', payment_note]
      );
    }

    return res.json({
      success: true,
      message: remaining_amount > 0 ? 'تم تسجيل الدفعة الجزئية بنجاح' : 'تم تسجيل الدفعة بالكامل',
      remaining_amount,
      payment_status,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'خطأ في تحديث الدفعة' });
  }
});



app.get('/api/payments/active-tenants', verifyToken, async (req, res) => {
  const adminId = req.user.id;

  try {
    const tenants = await query(`
      SELECT 
        u.user_id AS tenant_id,
        MAX(rcd.tenant_name) AS name,
        MAX(rcd.unit_number) AS unit_number
      FROM rental_contracts_details rcd
      JOIN users u ON u.id = rcd.tenant_id
      WHERE rcd.admin_id = ? AND rcd.contract_end >= CURDATE()
      GROUP BY u.user_id
    `, [adminId]);

    res.json({ tenants });
  } catch (err) {
    console.error('❌ Error fetching active tenants:', err);
    res.status(500).json({ message: 'خطأ في جلب المستأجرين' });
  }
});


app.get('/api/payments/tenant/:tenantId', verifyToken, async (req, res) => {
  const { tenantId } = req.params;

  try {
    const payments = await query(`
      SELECT 
        p.id AS payment_id,
        p.payment_number,
        p.payment_amount,
        p.due_date,
        p.payment_status,
        p.paid_date,
        p.payment_note
      FROM payments p
      JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
      WHERE rcd.tenant_id = (SELECT id FROM users WHERE user_id = ?)
      ORDER BY p.due_date ASC
    `, [tenantId]);

    res.json({ payments });
  } catch (err) {
    console.error('❌ Error fetching tenant payments:', err);
    res.status(500).json({ message: 'خطأ في جلب الدفعات' });
  }
});


app.put('/api/payments/update/:paymentId', verifyToken, async (req, res) => {
  const { paymentId } = req.params;
  const { payment_status, paid_date, payment_note } = req.body;

  try {
    await query(`
      UPDATE payments 
      SET payment_status = ?, paid_date = ?, payment_note = ?
      WHERE id = ?
    `, [payment_status, paid_date, payment_note, paymentId]);

    res.json({ message: '✅ تم تحديث الدفعة بنجاح' });
  } catch (err) {
    console.error('❌ Error updating payment:', err);
    res.status(500).json({ message: 'خطأ في تحديث بيانات الدفعة' });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/api/admin/expenses/types/:adminId', verifyToken, async (req, res) => {
  const adminId = req.params.adminId;

  const sql = `
    SELECT et.id AS type_id,
           COALESCE(uet.custom_name, et.name) AS expense_name,
           IF(uet.user_id IS NULL, FALSE, TRUE) AS is_selected
    FROM expenses_types et
    LEFT JOIN user_expenses_types uet ON et.id = uet.type_id AND uet.user_id = ?
  `;

  try {
    const types = await query(sql, [adminId]);
    res.json({ types });
  } catch (err) {
    console.error('Error fetching expense types:', err);
    res.status(500).json({ message: 'خطأ في جلب أنواع المصروفات' });
  }
});


app.post('/api/admin/expenses/types', verifyToken, async (req, res) => {
  const { adminId, selectedTypes } = req.body; // selectedTypes = [{type_id, custom_name}]

  if (!adminId || !Array.isArray(selectedTypes)) {
    return res.status(400).json({ message: 'بيانات غير صحيحة' });
  }

  try {
    // حذف الاختيارات السابقة
    await query('DELETE FROM user_expenses_types WHERE user_id = ?', [adminId]);

    // إدخال الاختيارات الجديدة
    const insertPromises = selectedTypes.map(type =>
      query(
        'INSERT INTO user_expenses_types (user_id, type_id, custom_name) VALUES (?, ?, ?)',
        [adminId, type.type_id, type.custom_name || null]
      )
    );

    await Promise.all(insertPromises);
    res.json({ message: 'تم حفظ الاختيارات بنجاح' });
  } catch (err) {
    console.error('Error saving expense types:', err);
    res.status(500).json({ message: 'خطأ في حفظ أنواع المصروفات' });
  }
});


app.get('/api/admin/selected-expenses-types/:adminId', verifyToken, async (req, res) => {
  const adminId = req.params.adminId;

const sql = `
 SELECT 
  et.id AS type_id,
  COALESCE(uet.custom_name, et.name) AS expense_name,
  ee.frequency,
  ee.amount,
  ee.note
FROM expenses_types et
INNER JOIN user_expenses_types uet ON et.id = uet.type_id
LEFT JOIN (
  SELECT e1.type_id, e1.amount, e1.note, e1.frequency
  FROM expenses_entries e1
  INNER JOIN (
    SELECT type_id, MAX(id) AS max_id
    FROM expenses_entries
    WHERE user_id = ?
    GROUP BY type_id
  ) e2 ON e1.type_id = e2.type_id AND e1.id = e2.max_id
  WHERE e1.user_id = ?
) ee ON ee.type_id = uet.type_id
WHERE uet.user_id = ?;
`;

  try {
    const selectedTypes = await query(sql, [adminId, adminId, adminId]);
    console.log('🔵 [selected-expenses-types] selectedTypes:', selectedTypes); // <--- هنا
    res.json({ selectedTypes });
  } catch (err) {
    console.error('Error fetching selected expense types:', err);
    res.status(500).json({ message: 'خطأ في جلب الأنواع المختارة' });
  }
});

app.post('/api/admin/expenses-entries', verifyToken, async (req, res) => {
  const { userId, entries } = req.body;

  if (!userId || !Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ message: 'بيانات غير صحيحة.' });
  }

  try {
    console.log('🟡 [expenses-entries] Received entries:', entries); // <--- هنا
    const upsertPromises = entries.map(entry =>
      query(
        `INSERT INTO expenses_entries (user_id, type_id, amount, frequency, note)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE 
           amount = VALUES(amount),
           frequency = VALUES(frequency),
           note = VALUES(note)`,
        [userId, entry.type_id, entry.amount, entry.frequency, entry.note || null]
      )
    );

    await Promise.all(upsertPromises);
    const check = await query('SELECT * FROM expenses_entries WHERE user_id = ?', [userId]);
    console.log('🟢 [expenses-entries] DB after save:', check); // <--- هنا
    res.json({ message: 'تم حفظ الإدخالات بنجاح' });
  } catch (err) {
    console.error('Error saving expenses entries:', err);
    res.status(500).json({ message: 'خطأ في حفظ الإدخالات' });
  }
});







app.post('/api/admin/expenses', verifyToken, async (req, res) => {
  const { adminId, typeId, amount, expenseDate, notes } = req.body;

  if (!adminId || !typeId || !amount || !expenseDate) {
    return res.status(400).json({ message: 'كل الحقول مطلوبة ما عدا الملاحظات' });
  }

  const sql = `
    INSERT INTO expenses (user_id, type_id, amount, expense_date, notes)
    VALUES (?, ?, ?, ?, ?)
  `;

  try {
    await query(sql, [adminId, typeId, amount, expenseDate, notes || null]);
    res.json({ message: 'تمت إضافة المصروف بنجاح' });
  } catch (err) {
    console.error('Error adding expense:', err);
    res.status(500).json({ message: 'خطأ في إضافة المصروف' });
  }
});


app.put('/api/admin/expenses/:expenseId', verifyToken, async (req, res) => {
  const expenseId = req.params.expenseId;
  const { typeId, amount, expenseDate, notes } = req.body;

  if (!typeId || !amount || !expenseDate) {
    return res.status(400).json({ message: 'كل الحقول مطلوبة ما عدا الملاحظات' });
  }

  const sql = `
    UPDATE expenses
    SET type_id = ?, amount = ?, expense_date = ?, notes = ?
    WHERE id = ?
  `;

  try {
    await query(sql, [typeId, amount, expenseDate, notes || null, expenseId]);
    res.json({ message: 'تم تعديل المصروف بنجاح' });
  } catch (err) {
    console.error('Error updating expense:', err);
    res.status(500).json({ message: 'خطأ في تعديل المصروف' });
  }
});



app.delete('/api/admin/expenses/:expenseId', verifyToken, async (req, res) => {
  const expenseId = req.params.expenseId;

  try {
    await query('DELETE FROM expenses WHERE id = ?', [expenseId]);
    res.json({ message: 'تم حذف المصروف بنجاح' });
  } catch (err) {
    console.error('Error deleting expense:', err);
    res.status(500).json({ message: 'خطأ في حذف المصروف' });
  }
});


app.get('/api/admin/expenses-report/:adminId', verifyToken, async (req, res) => {
  const adminId = req.params.adminId;

  const sql = `
    SELECT et.id AS type_id,
           COALESCE(uet.custom_name, et.name) AS expense_name,
           SUM(e.amount) AS total_amount,
           COUNT(e.id) AS expense_count
    FROM expenses e
    JOIN expenses_types et ON e.type_id = et.id
    LEFT JOIN user_expenses_types uet ON uet.type_id = et.id AND uet.user_id = e.user_id
    WHERE e.user_id = ?
    GROUP BY e.type_id, expense_name
    ORDER BY total_amount DESC
  `;

  try {
    const report = await query(sql, [adminId]);
    res.json({ report });
  } catch (err) {
    console.error('Error generating report:', err);
    res.status(500).json({ message: 'خطأ في توليد التقرير' });
  }
});




app.get('/api/admin/expenses-stats/:adminId', verifyToken, async (req, res) => {
  const adminId = req.params.adminId;

  console.log('🔵 [expenses-stats] adminId:', adminId);

  const sql = `
SELECT
  et.id AS type_id,
  COALESCE(uet.custom_name, et.name) AS expense_name,
  ee.frequency,
  ee.amount,
  ee.note,
  DATE_FORMAT(ee.entry_date, '%Y-%m-%d') AS last_updated
FROM expenses_types et
INNER JOIN user_expenses_types uet ON et.id = uet.type_id
LEFT JOIN (
  SELECT e1.*
  FROM expenses_entries e1
  INNER JOIN (
    SELECT type_id, MAX(id) AS max_id
    FROM expenses_entries
    WHERE user_id = ?
    GROUP BY type_id
  ) e2 ON e1.type_id = e2.type_id AND e1.id = e2.max_id
  WHERE e1.user_id = ?
) ee ON ee.type_id = uet.type_id
WHERE uet.user_id = ?
ORDER BY ee.frequency;
  `;

  try {
    console.log('🟡 [expenses-stats] SQL:', sql);
    const results = await query(sql, [adminId, adminId, adminId]);
    console.log('🟢 [expenses-stats] Raw Results:', results);

    const stats = {
      daily: [],
      monthly: [],
      yearly: [],
    };

    results.forEach((row, idx) => {
      const formattedRow = {
        type_id: row.type_id,
        name: row.expense_name,
        amount: parseFloat(row.amount),
        note: row.note,
        last_updated: row.last_updated,
      };
      console.log(`🟠 [expenses-stats] Row #${idx}:`, row);
      console.log(`🔵 [expenses-stats] Formatted Row #${idx}:`, formattedRow);

      if (row.frequency === 'daily') stats.daily.push(formattedRow);
      else if (row.frequency === 'monthly') stats.monthly.push(formattedRow);
      else if (row.frequency === 'yearly') stats.yearly.push(formattedRow);
    });

    console.log('🟣 [expenses-stats] Final Stats:', stats);

    res.json(stats);
  } catch (err) {
    console.error('❌ Error fetching expense stats:', err);
    res.status(500).json({ message: 'خطأ في جلب إحصائيات المصروفات' });
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/subscriptions/renew/google-play', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { subscription_type, purchaseToken } = req.body;

  try {
    // ✅ الخطوة المهمة هنا: احصل على الـ id الصحيح للمستخدم من جدول users
    const [userRecord] = await query(`SELECT id, name, phone_number FROM users WHERE user_id = ?`, [userId]);

    if (!userRecord) {
      return res.status(404).json({ message: '❌ المستخدم غير موجود.' });
    }

    const realAdminId = userRecord.id;

    const [currentSub] = await query(
      `SELECT id, end_date FROM admin_subscriptions WHERE admin_id = ?`, 
      [realAdminId]
    );

    let currentEndDate = currentSub?.end_date ? new Date(currentSub.end_date) : new Date();

    if (currentEndDate < new Date()) {
      currentEndDate = new Date();
    }

    let newEndDate;

    if (subscription_type === 'monthly') {
      newEndDate = new Date(currentEndDate);
      newEndDate.setMonth(newEndDate.getMonth() + 1);
    } else if (subscription_type === 'yearly') {
      newEndDate = new Date(currentEndDate);
      newEndDate.setFullYear(newEndDate.getFullYear() + 1);
    } else {
      return res.status(400).json({ message: 'نوع الاشتراك غير صالح.' });
    }

    const formattedEndDate = newEndDate.toISOString().slice(0, 10);

    if (currentSub) {
      // تحديث الاشتراك الحالي
      await query(`
        UPDATE admin_subscriptions
        SET start_date = CURDATE(), end_date = ?, status = 'active', subscription_type = ?
        WHERE admin_id = ?
      `, [formattedEndDate, subscription_type, realAdminId]);

      // تحديث الوكلاء المرتبطين
      await query(`
        UPDATE admin_subscriptions
        SET start_date = CURDATE(), end_date = ?, status = 'active', subscription_type = ?
        WHERE linked_subscription_id = ?
      `, [formattedEndDate, subscription_type, currentSub.id]);

    } else {
      // إنشاء اشتراك جديد
      await query(`
        INSERT INTO admin_subscriptions (admin_id, start_date, end_date, subscription_type, status)
        VALUES (?, CURDATE(), ?, ?, 'active')
      `, [realAdminId, formattedEndDate, subscription_type]);
    }

    // إرسال رسالة الواتساب
    if (userRecord.phone_number) {
      const formattedPhone = userRecord.phone_number.replace('+', '');
      const whatsappMessage = `
      أهلاً ${userRecord.name} 👋،

      تم تجديد اشتراكك بنجاح 🎉

      نوع الاشتراك الجديد: ${subscription_type === 'monthly' ? 'شهري' : 'سنوي'}
      تاريخ الانتهاء الجديد: ${formattedEndDate}

      شكرًا لتجديد اشتراكك 🌟
      `.trim();

      await sendWhatsAppMessage(formattedPhone, whatsappMessage);
    }

    res.json({
      message: '✅ تم تجديد الاشتراك بنجاح عبر Google Play وإرسال الإشعار.',
      newEndDate: formattedEndDate
    });

  } catch (error) {
    console.error('❌ Error renewing subscription via Google Play:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تجديد الاشتراك.' });
  } 
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 🔹 إجمالي عدد المستأجرين للوكلاء المرتبطين بViewer معين
app.get('/api/viewers/:viewerId/total-tenants', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT COUNT(rc.id) AS total_tenants_count
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ?
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalTenantsCount: result.total_tenants_count || 0
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ في جلب عدد المستأجرين.', error });
  }
});


// 🔹 بيانات المستأجرين بشكل مختصر (تابعين لوكلاء Viewer محدد)
app.get('/api/viewers/:viewerId/tenants-summary', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      tenants.name AS tenantName,
      rc.property_name AS propertyName,
      rc.status AS contractStatus,
      agents.name AS agentName
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ?
    ORDER BY rc.created_at DESC
  `;

  try {
    const tenants = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalTenants: tenants.length,
      tenants
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ في جلب بيانات المستأجرين.', error });
  }
});


// 🔹 إجمالي عدد العقارات لوكلاء Viewer معين
app.get('/api/viewers/:viewerId/total-properties', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT COUNT(DISTINCT rc.property_name) AS total_properties_count
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ?
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalPropertiesCount: result.total_properties_count || 0
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ في جلب عدد العقارات.', error });
  }
});


// 🔹 إحصائية العقود الفعالة والمنتهية لوكلاء Viewer معين
app.get('/api/viewers/:viewerId/contracts-stats', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT
      SUM(CASE WHEN rc.status = 'active' THEN 1 ELSE 0 END) AS active_contracts_count,
      SUM(CASE WHEN rc.status IN ('expired', 'terminated') THEN 1 ELSE 0 END) AS expired_contracts_count
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ?
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      activeContractsCount: result.active_contracts_count || 0,
      expiredContractsCount: result.expired_contracts_count || 0,
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب إحصائية العقود.', error });
  }
});


// 🔹 إجمالي عدد الوكلاء المرتبطين ب Viewer معين
app.get('/api/viewers/:viewerId/agents-count', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT COUNT(*) AS total_agents
    FROM users
    WHERE viewer_id = ? AND user_type = 'admin'
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalAgentsCount: result.total_agents || 0
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب عدد الوكلاء.', error });
  }
});

// 🔹 جلب نوع اشتراك Viewer معين (شهري أو سنوي) وحالة الاشتراك
app.get('/api/viewers/:viewerId/subscription-type', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT subscription_type, status, start_date, end_date
    FROM admin_subscriptions
    WHERE admin_id = ?
    ORDER BY end_date DESC
    LIMIT 1
  `;

  try {
    const [subscription] = await query(sql, [viewerId]);

    if (!subscription) {
      return res.status(404).json({ message: '⚠️ لا يوجد اشتراك لهذا المتطلع.' });
    }

    res.json({
      viewerId: parseInt(viewerId),
      subscriptionType: subscription.subscription_type,
      subscriptionStatus: subscription.status,
      startDate: subscription.start_date,
      endDate: subscription.end_date
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب بيانات الاشتراك.', error });
  }
});

// 🔹 تفاصيل الوكلاء الكاملة لـ Viewer معين
app.get('/api/viewers/:viewerId/agents-details', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      u.id AS agentId,
      u.user_id AS agentUserId,
      u.name AS agentName,
      u.phone_number AS phoneNumber,
      s.subscription_type AS subscriptionType,
      s.status AS subscriptionStatus,
      s.start_date AS subscriptionStart,
      s.end_date AS subscriptionEnd,
      s.tenant_limit AS tenantLimit,
      (
        SELECT COUNT(*)
        FROM rental_contracts rc
        JOIN users tenants ON tenants.id = rc.tenant_id
        WHERE tenants.created_by = u.id AND rc.status = 'active'
      ) AS activeTenantsCount
    FROM users u
    LEFT JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.viewer_id = ? AND u.user_type = 'admin'
  `;

  try {
    const agents = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalAgents: agents.length,
      agents
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب تفاصيل الوكلاء.', error });
  }
});

// 🔹 تفاصيل العقود الفعالة لوكلاء Viewer معين
app.get('/api/viewers/:viewerId/active-contracts-details', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT
      rc.id AS contractId,
      rc.property_name AS propertyName,
      rc.contract_start AS contractStart,
      rc.contract_end AS contractEnd,
      tenants.name AS tenantName,
      tenants.phone_number AS tenantPhone,
      agents.name AS agentName,
      agents.phone_number AS agentPhone
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ? AND rc.status = 'active'
    ORDER BY rc.contract_end ASC
  `;

  try {
    const contracts = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalActiveContracts: contracts.length,
      contracts
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب تفاصيل العقود الفعالة.', error });
  }
});


// 🔹 تفاصيل العقود المنتهية لوكلاء Viewer معين
app.get('/api/viewers/:viewerId/expired-contracts-details', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 التحقق من صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT
      rc.id AS contractId,
      rc.property_name AS propertyName,
      rc.contract_start AS contractStart,
      rc.contract_end AS contractEnd,
      rc.status AS contractStatus,
      tenants.name AS tenantName,
      tenants.phone_number AS tenantPhone,
      agents.name AS agentName,
      agents.phone_number AS agentPhone
    FROM rental_contracts rc
    JOIN users tenants ON rc.tenant_id = tenants.id
    JOIN users agents ON tenants.created_by = agents.id
    WHERE agents.viewer_id = ? AND rc.status IN ('expired', 'terminated')
    ORDER BY rc.contract_end DESC
  `;

  try {
    const contracts = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      totalExpiredContracts: contracts.length,
      contracts
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب تفاصيل العقود المنتهية.', error });
  }
});


// 🔹 تفاصيل اشتراك الـ Viewer بشكل كامل
app.get('/api/viewers/:viewerId/subscription-details', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { viewerId } = req.params;

  // 🔐 صلاحية الوصول
  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      s.subscription_type AS subscriptionType,
      s.status AS subscriptionStatus,
      s.start_date AS subscriptionStart,
      s.end_date AS subscriptionEnd,
      u.max_agents AS maxAgents,
      u.tenant_limit_per_agent AS tenantLimitPerAgent
    FROM admin_subscriptions s
    JOIN users u ON u.id = s.admin_id
    WHERE s.admin_id = ?
    ORDER BY s.end_date DESC
    LIMIT 1
  `;

  try {
    const [subscription] = await query(sql, [viewerId]);

    if (!subscription) {
      return res.status(404).json({ message: '⚠️ لا يوجد اشتراك لهذا المتطلع.' });
    }

    res.json({
      viewerId: parseInt(viewerId),
      subscription
    });

  } catch (error) {
    console.error('❌ DB Error:', error);
    res.status(500).json({ message: 'حدث خطأ في جلب تفاصيل الاشتراك.', error });
  }
});

// 🔹 API لعرض الدخل الشهري الإجمالي والمختصر للفيور من جميع وكلائه
app.get('/api/viewer-monthly-income/:viewerId', verifyToken, async (req, res) => {
  const { viewerId } = req.params;
  const { userType, id: userId } = req.user;

  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      IFNULL(SUM(rcd.periodic_rent_payment), 0) AS total_monthly_income,
      COUNT(rcd.id) AS active_contracts_count
    FROM rental_contracts_details rcd
    JOIN rental_contracts rc ON rc.tenant_id = rcd.tenant_id
    WHERE rc.status = 'active'
      AND rcd.admin_id IN (SELECT id FROM users WHERE viewer_id = ?)
      AND CURDATE() BETWEEN rc.contract_start AND rc.contract_end
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      monthlyIncome: parseFloat(result.total_monthly_income).toFixed(2),
      activeContractsCount: result.active_contracts_count
    });

  } catch (err) {
    console.error('❌ Viewer-monthly-income Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الدخل الشهري.', error: err });
  }
});


app.get('/api/viewer-annual-income/:viewerId', verifyToken, async (req, res) => {
  const { viewerId } = req.params;
  const { userType, id: userId } = req.user;

  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT 
      IFNULL(SUM(rcd.periodic_rent_payment * 12), 0) AS total_annual_income,
      COUNT(rcd.id) AS active_contracts_count
    FROM rental_contracts_details rcd
    JOIN rental_contracts rc ON rc.tenant_id = rcd.tenant_id
    WHERE rc.status = 'active'
      AND rcd.admin_id IN (SELECT id FROM users WHERE viewer_id = ?)
      AND CURDATE() BETWEEN rc.contract_start AND rc.contract_end
  `;

  try {
    const [result] = await query(sql, [viewerId]);

    res.json({
      viewerId: parseInt(viewerId),
      annualIncome: parseFloat(result.total_annual_income).toFixed(2),
      activeContractsCount: result.active_contracts_count
    });

  } catch (err) {
    console.error('❌ Viewer-annual-income Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب الدخل السنوي.', error: err });
  }
});



app.get('/api/viewer/expenses-summary/:viewerId', verifyToken, async (req, res) => {
  const { viewerId } = req.params;
  const { userType, id: userId } = req.user;

  if (userType !== 'super' && (userType !== 'viewer' || parseInt(viewerId) !== userId)) {
    return res.status(403).json({ message: '❌ صلاحية مفقودة.' });
  }

  const sql = `
    SELECT ee.frequency, IFNULL(SUM(ee.amount), 0) AS total_amount FROM expenses_entries ee
    INNER JOIN (
      SELECT user_id, type_id, MAX(id) AS max_id
      FROM expenses_entries
      GROUP BY user_id, type_id
    ) last_entries ON ee.id = last_entries.max_id
    INNER JOIN users u ON ee.user_id = u.id
    WHERE u.viewer_id = ?
    GROUP BY ee.frequency
  `;

  try {
    const expensesResults = await query(sql, [viewerId]);

    const summary = { daily: 0, monthly: 0, yearly: 0 };

    expensesResults.forEach(row => {
      summary[row.frequency] = parseFloat(row.total_amount);
    });

    res.json({
      viewerId: parseInt(viewerId),
      expensesSummary: {
        daily: summary.daily.toFixed(2),
        monthly: summary.monthly.toFixed(2),
        yearly: summary.yearly.toFixed(2)
      }
    });

  } catch (err) {
    console.error('❌ Error fetching viewer expenses summary:', err);
    res.status(500).json({ message: 'خطأ في جلب إجمالي المصروفات' });
  }
});



app.post('/api/viewer/:viewerId/agents-salaries', verifyToken, async (req, res) => {
  const { viewerId } = req.params;
  const { salaries } = req.body; // [{agent_id, salary}, ...]

  if (!Array.isArray(salaries)) {
    return res.status(400).json({ message: 'بيانات الرواتب غير صحيحة.' });
  }

  try {
    for (const { agent_id, salary } of salaries) {
      await query(`
        INSERT INTO viewer_agents_salaries (viewer_id, agent_id, salary)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE salary = ?
      `, [viewerId, agent_id, salary, salary]);
    }

    res.json({ message: 'تم تحديث رواتب الوكلاء بنجاح.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في تحديث الرواتب.' });
  }
});



app.get('/api/viewer/:viewerId/annual-financial-summary', verifyToken, async (req, res) => {
  const { viewerId } = req.params;

  try {
    // إجمالي دخل العقود السنوي
    const [incomeResult] = await query(`
      SELECT IFNULL(SUM(rcd.periodic_rent_payment * rent_payments_count), 0) AS annual_income
      FROM rental_contracts_details rcd
      WHERE rcd.admin_id IN (SELECT id FROM users WHERE viewer_id = ?) 
        AND rcd.contract_end > CURDATE()
    `, [viewerId]);

    // إجمالي المصروفات (اليومي، الشهري، السنوي)
const expensesResults = await query(`
  SELECT ee.frequency, IFNULL(SUM(ee.amount), 0) AS total_amount
  FROM expenses_entries ee
  INNER JOIN (
    SELECT user_id, type_id, MAX(id) AS max_id
    FROM expenses_entries
    GROUP BY user_id, type_id
  ) last_entries ON ee.id = last_entries.max_id
  INNER JOIN users u ON ee.user_id = u.id
  INNER JOIN user_expenses_types uet ON ee.type_id = uet.type_id AND ee.user_id = uet.user_id
  WHERE u.viewer_id = ?
  GROUP BY ee.frequency
`, [viewerId]);

    let daily = 0, monthly = 0, yearly = 0;
    expensesResults.forEach(row => {
      if (row.frequency === 'daily') daily = parseFloat(row.total_amount);
      if (row.frequency === 'monthly') monthly = parseFloat(row.total_amount);
      if (row.frequency === 'yearly') yearly = parseFloat(row.total_amount);
    });

    const totalExpenses = (daily * 30 * 12) + (monthly * 12) + yearly;

    // إجمالي رواتب الوكلاء
    const [salariesResult] = await query(`
      SELECT IFNULL(SUM(salary), 0) AS total_salaries
      FROM viewer_agents_salaries
      WHERE viewer_id = ?
    `, [viewerId]);

    const annualIncome = parseFloat(incomeResult.annual_income);
    const totalSalaries = parseFloat(salariesResult.total_salaries);
    const netProfit = annualIncome - totalExpenses - totalSalaries;

    res.json({
      viewerId: parseInt(viewerId),
      financialSummary: {
        annualIncome: annualIncome.toFixed(2),
        totalExpenses: totalExpenses.toFixed(2),
        totalAgentsSalaries: totalSalaries.toFixed(2),
        netProfit: netProfit.toFixed(2)
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في استعلام الملخص المالي.' });
  }
});



app.get('/api/viewer/:viewerId/name', verifyToken, async (req, res) => {
  const { viewerId } = req.params;

  try {
    const [viewer] = await query(`SELECT name FROM users WHERE id = ? AND user_type = 'viewer'`, [viewerId]);

    if (!viewer) {
      return res.status(404).json({ message: 'لم يتم العثور على الفيور.' });
    }

    res.json({ 
      viewerId: parseInt(viewerId), 
      viewerName: viewer.name 
    });

  } catch (err) {
    console.error('❌ Error fetching viewer name:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب اسم الفيور.' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// ✅ API: جلب المستأجرين مجمّعين حسب عنوان العقار ثم رقم الدور
// ✅ API: جلب المستأجرين مجمّعين حسب عنوان العقار ثم رقم الدور (حسب adminId في الباراميتر)
// ✅ API: إحصائيات المستأجرين حسب العنوان والدور
// ✅ API: إحصائيات المستأجرين حسب العنوان والدور + أرقام الوحدات
app.get('/api/admin/tenant-stats/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  try {
    const rows = await query(`
      SELECT 
        p.property_national_address,
        d.unit_floor_number,
        d.unit_number,
        rc.status
      FROM rental_contracts_details d
      JOIN properties p ON d.property_id = p.property_id
      JOIN rental_contracts rc ON rc.tenant_id = d.tenant_id
      WHERE d.admin_id = ?
      ORDER BY p.property_national_address, d.unit_floor_number, d.unit_number
    `, [adminId]);

    // تشكيل الإحصائيات مجمعة
    const stats = {};

    rows.forEach(row => {
      const address = row.property_national_address;
      const floor = row.unit_floor_number || 'دور غير معروف';

      if (!stats[address]) stats[address] = {};
      if (!stats[address][floor]) {
        stats[address][floor] = {
          tenant_count: 0,
          active_contracts: 0,
          expired_contracts: 0,
          unit_numbers: []
        };
      }

      stats[address][floor].tenant_count++;
      if (row.status === 'active') stats[address][floor].active_contracts++;
      if (row.status === 'expired') stats[address][floor].expired_contracts++;

      stats[address][floor].unit_numbers.push(row.unit_number);
    });

    res.json({ tenant_stats: stats });
  } catch (err) {
    console.error('❌ Error fetching tenant stats:', err);
    res.status(500).json({ message: 'خطأ في جلب إحصائيات المستأجرين' });
  }
});





app.post('/api/admin/save-address-label', verifyToken, async (req, res) => {
  const { id: adminId } = req.user;
  const { address, customLabel } = req.body;

  if (!address || !customLabel) {
    return res.status(400).json({ message: '❗ العنوان والتسمية مطلوبة.' });
  }

  try {
    await query(`
      INSERT INTO custom_address_labels (admin_id, original_address, custom_label)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE custom_label = VALUES(custom_label)
    `, [adminId, address, customLabel]);

    res.json({ message: '✅ تم حفظ التسمية المخصصة بنجاح.' });
  } catch (err) {
    console.error('❌ Save Address Label Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء حفظ التسمية.' });
  }
});

// ✅ 3. API لجلب جميع التسميات المخصصة للمالك أو الوكيل فقط
app.get('/api/admin/address-labels/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  try {
    const labels = await query(`
      SELECT original_address, custom_label
      FROM custom_address_labels
      WHERE admin_id = ?
    `, [adminId]);

    const labelMap = {};
    labels.forEach(row => {
      labelMap[row.original_address] = row.custom_label;
    });

    res.json({ labels: labelMap });
  } catch (err) {
    console.error('❌ Fetch Address Labels Error:', err);
    res.status(500).json({ message: 'فشل في جلب التسميات.' });
  }
});



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API تعمل على المنفذ ${PORT}`);
});
