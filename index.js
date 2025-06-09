const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();
const fetch = require('node-fetch');
const pdfParse = require('pdf-parse');




const { query } = require('./database');

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
    SELECT u.user_id, u.name, u.user_type
    FROM users u
    INNER JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.id = ?;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    res.json({ admin: results[0] });

  } catch (err) {
    console.error('❌ Get-admin-details Error:', err);
    res.status(500).json({ message: 'خطأ داخلي في الخادم' });
  }
});

app.post('/api/get-user-details', verifyToken, async (req, res) => {
  const { userId } = req.body;

  const sql = `
    SELECT u.user_id, u.name, u.email, r.contract_start, r.contract_end
    FROM users u
    INNER JOIN rental_contracts r ON u.id = r.tenant_id
    WHERE u.user_id = ?;
  `;

  try {
    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: results[0] });
  } catch (err) {
    console.error('❌ Get-user-details Error:', err);
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



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/create-admin', verifyToken, async (req, res) => {
  const { userType, id: created_by } = req.user;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إنشاء مالك.' });
  }

  const { user_id, name, permissions = {} } = req.body;

  if (!user_id || !name) {
    return res.status(400).json({ message: '❗ user_id و name مطلوبة.' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  const insertUserSql = `
    INSERT INTO users (user_id, name, user_type, token, created_at)
    VALUES (?, ?, 'admin', ?, NOW())
  `;

  const insertTokenSql = `
    INSERT INTO admin_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

  try {
    // إدخال بيانات المستخدم (admin)
    const userResult = await query(insertUserSql, [user_id, name, token]);

    // إدخال التوكن والصلاحيات
    await query(insertTokenSql, [token, JSON.stringify(permissions), created_by]);

    res.json({
      message: '✅ تم إنشاء المالك والتوكن بنجاح.',
      adminId: userResult.insertId,
      token
    });

  } catch (err) {
    console.error('❌ Create-admin Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء المالك أو التوكن.' });
  }
});



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









////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const axios = require('axios');

const instance_id = 'instance124299';
const token = 'hk7g25xetv3t58r5';

async function sendWhatsAppMessage(to, message) {
  try {
    const response = await axios.post(`https://api.ultramsg.com/${instance_id}/messages/chat`, {
      token: token,
      to: to,
      body: message
    });

    console.log('✅ WhatsApp sent:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ WhatsApp sending error:', error);
    throw error;
  }
}


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

    // 👇 شرط ذكي لإضافة المستخدم إذا العقد ما زال ساريًا
    if (contractEndDate <= today) {
      return res.status(400).json({
        message: '❌ لا يمكن إنشاء مستخدم لأن العقد منتهي أو ينتهي اليوم.',
        contract_end: data.contract_end
      });
    }
    // 👇 شرط ذكي لإضافة المستخدم إذا العقد ما زال ساريًا


    if (!user_id) {
      return res.status(400).json({ message: '❌ تعذّر استخراج رقم الهوية من الملف.' });
    }

    const userCheckSql = 'SELECT id FROM users WHERE user_id = ? LIMIT 1';
    const tenant_name_from_pdf = data.tenant_name || '---';

    try {
      const existing = await query(userCheckSql, [user_id]);

  

// ✅ عرّف الدالة بشكل واضح أولًا في الأعلى


// ✅ ثم بقية الكود بشكل واضح ومنظم
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
  `;

  const userResult = await query(insertUserSql, [
    user_id,
    tenant_name_from_pdf,
    token,
    formattedPhone,
    admin_id
  ]);

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

// حذف محتوى
app.delete('/api/super/articles/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  
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
      SELECT * FROM articles_offers_ads
      WHERE is_active = true
      AND (start_date IS NULL OR start_date <= ?)
      AND (end_date IS NULL OR end_date >= ?)
      ORDER BY created_at DESC`,
      [today, today]
    );
    res.json(articles);
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
      SELECT * FROM articles_offers_ads
      WHERE id = ?
      AND is_active = true
      AND (start_date IS NULL OR start_date <= ?)
      AND (end_date IS NULL OR end_date >= ?)`,
      [id, today, today]
    );
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



// ✅ API: جلب التقييمات (للموقع أو للمالك لو عنده صلاحية)
app.get('/api/reviews/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const permissionSql = `
    SELECT enabled FROM review_permissions WHERE admin_id = ?
  `;

  const reviewsSql = `
    SELECT rating, comment, created_at FROM reviews 
    WHERE visible = TRUE 
    ORDER BY created_at DESC
  `;

  try {
    const permissionResults = await query(permissionSql, [adminId]);

    if (permissionResults.length === 0 || !permissionResults[0].enabled) {
      return res.status(403).json({ message: '❌ لا يملك المالك صلاحية عرض التقييمات' });
    }

    const reviews = await query(reviewsSql);
    res.json({ reviews });

  } catch (err) {
    console.error('❌ Fetch-reviews Error:', err);
    res.status(500).json({ message: 'فشل في جلب التقييمات' });
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

  const sql = `
    SELECT 
      tenant_id, tenant_name, contract_number, contract_start, contract_end, contract_type,
      tenant_phone, tenant_email, tenant_address
    FROM rental_contracts_details
    WHERE admin_id = ?
    ORDER BY created_at DESC
  `;

  try {
    const tenants = await query(sql, [adminId]);
    res.json({ tenants });

  } catch (err) {
    console.error('❌ Admin-tenants-fetch Error:', err);
    res.status(500).json({ message: 'DB Error', error: err });
  }
});


app.get('/api/admin-tenants/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  const sql = `
    SELECT 
      tenant_id, tenant_name, contract_number, contract_start, contract_end, contract_type,
      tenant_phone, tenant_email, tenant_address
    FROM rental_contracts_details
    WHERE admin_id = ?
    ORDER BY created_at DESC
  `;

  try {
    const tenants = await query(sql, [adminId]);
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
      IFNULL(SUM(p.payment_amount), 0) AS total_paid
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    WHERE rcd.admin_id = ? AND p.payment_status = 'مدفوعة' AND rcd.contract_end > CURDATE()
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
      IFNULL(SUM(p.payment_amount), 0) AS paid,
      (rcd.total_contract_value - IFNULL(SUM(p.payment_amount), 0)) AS remaining
    FROM rental_contracts_details rcd
    LEFT JOIN payments p ON p.contract_id = rcd.id AND p.payment_status = 'مدفوعة'
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
      p.payment_number, p.payment_amount, p.due_date, p.payment_status,
      rcd.contract_number, rcd.tenant_name
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
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API تعمل على المنفذ ${PORT}`);
});
