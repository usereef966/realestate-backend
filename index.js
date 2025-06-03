const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();
const fetch = require('node-fetch');



const { query } = require('./database');

const app = express();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
app.use(express.json());
app.use(cors());


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




app.post('/api/generate-admin-token', verifyToken, async (req, res) => {
  const { permissions, created_by } = req.body;

  const token = crypto.randomBytes(32).toString('hex');

  const sql = `
    INSERT INTO admin_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
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

  const token = crypto.randomBytes(32).toString('hex');

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


  const user_id = req.body.tenantId;
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

    // === 1. تحقق/أنشئ المستأجر والتوكن ===
    const userCheckSql = 'SELECT id FROM users WHERE user_id = ? LIMIT 1';
    const tenant_name_from_pdf = data.tenant_name || '---';
    try {
      const existing = await query(userCheckSql, [user_id]);
      if (existing.length === 0) {
        token = crypto.randomBytes(32).toString('hex');
        const insertUserSql = `
          INSERT INTO users (user_id, name, user_type, token, created_at, created_by)
          VALUES (?, ?, 'user', ?, NOW(), ?)
        `;
        const userResult = await query(insertUserSql, [
          user_id,
          tenant_name_from_pdf,
          token,
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
      } else {
        tenantDbId = existing[0].id;
        // تحديث الاسم من PDF لو فاضي
        await query('UPDATE users SET name = ? WHERE id = ?', [tenant_name_from_pdf, tenantDbId]);
      }
    } catch (err) {
      console.error('❌ User Creation Error:', err);
      return res.status(500).json({ message: 'فشل في إنشاء أو التحقق من المستأجر' });
    }
    data.tenant_id = tenantDbId;


    

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

    if(results.length === 0) 
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch(err) {
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

    if(results.length === 0) 
      return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);

  } catch(err) {
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

  } catch(err) {
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

  } catch(err) {
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

  } catch(err) {
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







////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 📁 index.js أو ملف routes المناسب
// 📁 index.js أو ملف routes المناسب
const { JWT } = require('google-auth-library');
const serviceAccount = JSON.parse(process.env.GOOGLE_CREDENTIALS);

// دالة لجلب التوكن من Google
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
        data: { screen: 'notifications', userId }
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

  const sql = `
    INSERT INTO admin_subscriptions (admin_id, start_date, end_date)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE start_date = VALUES(start_date), end_date = VALUES(end_date)
  `;

  try {
    await query(sql, [adminId, startDate, endDate]);
    res.json({ message: '✅ تم تفعيل أو تحديث الاشتراك للمُـلك' });

  } catch (err) {
    console.error('❌ Subscription-activation Error:', err);
    res.status(500).json({ message: '❌ فشل في تفعيل الاشتراك' });
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




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
    SELECT id, category, description, status, created_at
    FROM noise_complaints WHERE admin_id = ? ORDER BY created_at DESC
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
  const { userType } = req.user;
  const complaintId = req.params.id;
  const { status } = req.body;

  if (!['admin', 'super'].includes(userType)) {
    return res.status(403).json({ message: '❌ غير مصرح' });
  }

  if (!['جديد', 'قيد المعالجة', 'تم الحل'].includes(status)) {
    return res.status(400).json({ message: '❗ حالة غير صالحة' });
  }

  const sql = `
    UPDATE noise_complaints SET status = ? WHERE id = ?
  `;

  try {
    await query(sql, [status, complaintId]);
    res.json({ message: '✅ تم تحديث حالة البلاغ' });

  } catch (err) {
    console.error('❌ Update-complaint-status Error:', err);
    res.status(500).json({ message: '❌ فشل في التحديث' });
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
    WHERE admin_id = ?
  `;

  const paymentsSumSql = `
    SELECT 
      IFNULL(SUM(p.payment_amount), 0) AS total_paid
    FROM payments p
    JOIN rental_contracts_details rcd ON p.contract_id = rcd.id
    WHERE rcd.admin_id = ? AND p.payment_status = 'مدفوعة'
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
    WHERE rcd.admin_id = ?
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
    WHERE rcd.admin_id = ? AND p.payment_status != 'مدفوعة' AND p.due_date < CURDATE()
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
      )
    GROUP BY years.year, periods.start_month
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
         WHERE rcd.admin_id = ? AND p.payment_status = 'مدفوعة')
        /
        (SELECT IFNULL(SUM(total_contract_value),0) FROM rental_contracts_details WHERE admin_id = ?)
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
    WHERE admin_id = ?
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

  pdf_path: `https://storage.googleapis.com/rental-contracts-pdfs/${req.file.filename}`,
      tenant_id: null, // بنعبيها بعدين
      admin_id: admin_id
    };


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
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API تعمل على المنفذ ${PORT}`);
});
