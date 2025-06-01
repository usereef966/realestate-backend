const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();
const fetch = require('node-fetch');





const app = express();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
app.use(express.json());
app.use(cors());


const db = mysql.createConnection({
  host:     process.env.MYSQLHOST,
  port:     process.env.MYSQLPORT,
  user:     process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
});

db.connect((err) => {
  if (err) {
    console.error('DB Connection Failed:', err);
  } else {
    console.log('DB Connected Successfully!');
  }
});


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
app.post('/api/login', (req, res) => {
  const { userId, token } = req.body;

  const query = 'SELECT id, user_id, name, user_type FROM users WHERE user_id = ? AND token = ?';

  db.query(query, [userId, token], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'بيانات الدخول غير صحيحة' });
    }

    const user = results[0];

    // تحقق من نوع المستخدم
    if (user.user_type === 'admin') {
      // تحقق من اشتراك المالك
      const adminSubQuery = `
        SELECT 1 FROM admin_subscriptions 
        WHERE admin_id = ? AND end_date >= CURDATE()
        LIMIT 1
      `;
      db.query(adminSubQuery, [user.id], (err, subResults) => {
        if (err || subResults.length === 0) {
          return res.status(403).json({ message: 'انتهى اشتراك المالك أو غير موجود' });
        }
        // اشتراك فعّال، أكمل تسجيل الدخول
        return sendLoginSuccess(res, user);
      });
    } else if (user.user_type === 'user') {
      // تحقق من عقد المستأجر
      const userContractQuery = `
        SELECT 1 FROM rental_contracts 
        WHERE tenant_id = ? AND contract_end >= CURDATE()
        LIMIT 1
      `;
      db.query(userContractQuery, [user.id], (err, contractResults) => {
        if (err || contractResults.length === 0) {
          return res.status(403).json({ message: 'انتهى عقد المستأجر أو غير موجود' });
        }
        // عقد فعّال، أكمل تسجيل الدخول
        return sendLoginSuccess(res, user);
      });
    } else if (user.user_type === 'super') {
      // سوبر أدمن، لا تحقق من اشتراك
      return sendLoginSuccess(res, user);
    } else {
      return res.status(403).json({ message: 'نوع مستخدم غير مدعوم' });
    }
  });
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
    },
  });
}










// جميع ما يلي محمي بـ JWT
app.post('/api/validate-admin', verifyToken, (req, res) => {
  const { userId } = req.body;

  const query = `
    SELECT u.user_id, s.end_date 
    FROM users u
    INNER JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.user_id = ? AND s.end_date >= CURDATE();
  `;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.json({ valid: false });
    }
    res.json({ valid: true });
  });
});


app.post('/api/validate-session', verifyToken, (req, res) => {
  const { userId } = req.body;

  const query = `SELECT user_id FROM users WHERE user_id = ? AND user_type='super' LIMIT 1`;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.json({ valid: false });
    }
    res.json({ valid: true });
  });
});




app.post('/api/validate-user', verifyToken, (req, res) => {
  const { userId } = req.body;

  const query = `
    SELECT u.user_id, r.contract_end
    FROM users u
    INNER JOIN rental_contracts r ON u.id = r.tenant_id
    WHERE u.user_id = ? AND r.contract_end >= CURDATE();
  `;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.json({ valid: false });
    }
    res.json({ valid: true });
  });
});

app.post('/api/get-admin-details', verifyToken, (req, res) => {
  const { userId } = req.body;

  const query = `
    SELECT u.user_id, u.name, u.email, u.user_type
    FROM users u
    INNER JOIN admin_subscriptions s ON u.id = s.admin_id
    WHERE u.user_id = ?;
  `;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    res.json({ admin: results[0] });
  });
});

app.post('/api/get-user-details', verifyToken, (req, res) => {
  const { userId } = req.body;

  const query = `
    SELECT u.user_id, u.name, u.email, r.contract_start, r.contract_end
    FROM users u
    INNER JOIN rental_contracts r ON u.id = r.tenant_id
    WHERE u.user_id = ?;
  `;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user: results[0] });
  });
});

app.post('/api/generate-admin-token', verifyToken, (req, res) => {
  const { permissions, created_by } = req.body;

  const token = crypto.randomBytes(32).toString('hex');

  const query = `
    INSERT INTO admin_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

  db.query(query, [token, JSON.stringify(permissions), created_by], (err, result) => {
    if (err) return res.status(500).json({ error: 'فشل في إنشاء توكن المالك' });
    res.json({ token, permissions });
  });
});

app.post('/api/generate-user-token', verifyToken, (req, res) => {
  const { permissions, created_by } = req.body;

  const token = crypto.randomBytes(32).toString('hex');

  const query = `
    INSERT INTO user_tokens (token, permissions, created_by)
    VALUES (?, ?, ?)
  `;

  db.query(query, [token, JSON.stringify(permissions), created_by], (err, result) => {
    if (err) return res.status(500).json({ error: 'فشل في إنشاء توكن المستأجر' });
    res.json({ token, permissions });
  });
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/create-admin', verifyToken, (req, res) => {
  const { userType, id: created_by } = req.user; // تأكد هنا id رقم السوبر وليس userId
  
  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر يمكنه إنشاء مالك.' });
  }

  const { user_id, name, permissions = {} } = req.body;

  if (!user_id || !name) {
    return res.status(400).json({ message: '❗ user_id و name مطلوبة.' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  const insertUserQuery = `
    INSERT INTO users (user_id, name, user_type, token, created_at)
    VALUES (?, ?, 'admin', ?, NOW())
  `;

  db.query(insertUserQuery, [user_id, name, token], (err, userResult) => {
    if (err) {
      console.error('❌ خطأ في إنشاء مالك:', err);
      return res.status(500).json({ message: 'حدث خطأ أثناء إنشاء مالك جديد.' });
    }

    const insertTokenQuery = `
      INSERT INTO admin_tokens (token, permissions, created_by)
      VALUES (?, ?, ?)
    `;

    // هنا created_by رقم السوبر (id) وليس userId
    db.query(insertTokenQuery, [token, JSON.stringify(permissions), created_by], (err) => {
      if (err) {
        console.error('❌ خطأ في إنشاء توكن المالك:', err);
        return res.status(500).json({ message: 'تم إنشاء المالك، ولكن فشل في إنشاء التوكن.' });
      }

      res.json({
        message: '✅ تم إنشاء المالك والتوكن بنجاح.',
        adminId: userResult.insertId,
        token
      });
    });
  });
});


app.post('/api/create-tenant', verifyToken, (req, res) => {
  const { userType, id: creatorId } = req.user;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ صلاحية مفقودة: فقط السوبر أو المالك يمكنه إنشاء مستأجر.' });
  }

  const { user_id, name, permissions = {} } = req.body;

  if (!user_id || !name) {
    return res.status(400).json({ message: '❗ user_id و name مطلوبة.' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  const insertUserQuery = `
    INSERT INTO users (user_id, name, user_type, token, created_at, created_by)
    VALUES (?, ?, 'user', ?, NOW(), ?)
  `;

  db.query(insertUserQuery, [user_id, name, token, creatorId], (err, userResult) => {
    if (err) {
      console.error('❌ خطأ في إنشاء مستأجر:', err);
      return res.status(500).json({ message: 'حدث خطأ أثناء إنشاء مستأجر جديد.' });
    }

    const insertTokenQuery = `
      INSERT INTO user_tokens (token, permissions, created_by)
      VALUES (?, ?, ?)
    `;

    db.query(insertTokenQuery, [token, JSON.stringify(permissions), creatorId], (err) => {
      if (err) {
        console.error('❌ خطأ في إنشاء توكن المستأجر:', err);
        return res.status(500).json({ message: 'تم إنشاء المستأجر، ولكن فشل في إنشاء التوكن.' });
      }

      res.json({
        message: '✅ تم إنشاء المستأجر والتوكن بنجاح.',
        tenantId: userResult.insertId,
        token
      });
    });
  });
});





////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////












const pdfParse = require('pdf-parse');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}.pdf`;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });




// ... الإعدادات السابقة كما هي

app.post('/api/analyze-local-pdf', upload.single('pdf'), async (req, res) => {
  console.log("Current working directory:", process.cwd());
console.log("File saved at:", req.file.path);
  try {
    const fileBuffer = fs.readFileSync(req.file.path);
    const pdfData = await pdfParse(fileBuffer);
    const text = pdfData.text;
    
    const cleanText = (txt) =>
  txt
    .replace(/[^\p{L}\p{N}\s,.-]/gu, '') // يشيل الرموز الغريبة، ويحافظ عالنصوص والفواصل
    .replace(/\s+/g, ' ')                // يصغر كل المسافات لمفردة
    .trim();

    

    const extract = (regex) => (text.match(regex) || [])[1]?.trim() || '';
    const toFloat = (v) => parseFloat(v) || 0;
    const toInt = (v) => parseInt(v) || 0;
    

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

  pdf_path: '/' + req.file.path.replace(/\\/g, '/'),
tenant_id: req.body.tenantId,
admin_id: req.body.adminId,
};


   const insertQuery = `INSERT INTO rental_contracts_details SET ?`;

// إدخال بيانات العقد
db.query(insertQuery, data, (err, contractResult) => {
  if (err) {
    console.error('❌ DB Error:', err);
    return res.status(500).json({ message: 'فشل في حفظ بيانات العقد' });
  }

  const contractId = contractResult.insertId;

  const tenantId = data.tenant_id; // من البيانات التي أرسلتها
  const adminId = data.admin_id; // من البيانات التي أرسلتها

  // جلب tenant_user_id و admin_user_id بشكل صحيح (ضروري جدًا)
  const getUsersQuery = `
    SELECT 
      (SELECT user_id FROM users WHERE id = ?) AS tenantUserId,
      (SELECT user_id FROM users WHERE id = ?) AS adminUserId
  `;

  db.query(getUsersQuery, [tenantId, adminId], (userErr, userResults) => {
    if (userErr || userResults.length === 0) {
      console.error('❌ خطأ في جلب بيانات المستخدمين:', userErr);
      return res.status(500).json({ message: 'خطأ في جلب بيانات المستخدمين' });
    }

    const { tenantUserId, adminUserId } = userResults[0];

    // التحقق من وجود غرفة دردشة سابقة بين نفس المالك والمستأجر
    const checkChatRoomQuery = `
      SELECT id FROM chat_rooms WHERE tenant_user_id = ? AND admin_user_id = ? LIMIT 1
    `;

    db.query(checkChatRoomQuery, [tenantUserId, adminUserId], (checkErr, checkResults) => {
      if (checkErr) {
        console.error('❌ خطأ في التحقق من غرفة الدردشة:', checkErr);
        return res.status(500).json({ message: 'خطأ في التحقق من غرفة الدردشة' });
      }

      const createPaymentsAndSubscriptions = () => {
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
          VALUES ?
        `;

        db.query(paymentsQuery, [payments], (paymentsErr) => {
          if (paymentsErr) {
            console.error('❌ Payments DB Error:', paymentsErr);
            return res.status(500).json({ message: 'تم حفظ العقد، لكن فشل في إنشاء الدفعات' });
          }

          // تحديث الاشتراك إذا موجود مسبقًا
          const updateSubscriptionQuery = `
            UPDATE rental_contracts
            SET contract_start = ?, contract_end = ?, status = 'active', created_at = NOW()
            WHERE tenant_id = ?
          `;

          db.query(updateSubscriptionQuery, [
            data.contract_start,
            data.contract_end,
            tenantId
          ], (updateErr, updateResult) => {
            if (updateErr) {
              console.error('❌ فشل في تحديث الاشتراك:', updateErr);
              return res.status(500).json({ message: 'تم حفظ العقد، لكن فشل تحديث الاشتراك' });
            }

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

              const subscriptionQuery = 'INSERT INTO rental_contracts SET ?';

              db.query(subscriptionQuery, subscriptionData, (insertSubErr) => {
                if (insertSubErr) {
                  console.error('❌ Subscription DB Error:', insertSubErr);
                  return res.status(500).json({ message: 'تم حفظ العقد لكن فشل في إنشاء الاشتراك' });
                }

                // نجاح الإدخال مع إنشاء اشتراك جديد
                res.json({
                  message: '✅ تم تحليل وتخزين العقد وإنشاء الاشتراك بنجاح',
                  contract_number: data.contract_number
                });
              });

            } else {
              // نجاح التحديث
              res.json({
                message: '✅ تم تحليل وتخزين العقد وتحديث الاشتراك بنجاح',
                contract_number: data.contract_number
              });
            }
          });
        });
      };

      if (checkResults.length > 0) {
        console.log('🔵 غرفة الدردشة موجودة مسبقًا.');
        createPaymentsAndSubscriptions(); // تابع العمليات
      } else {
        // إدخال غرفة دردشة جديدة
        const chatRoomQuery = `
          INSERT INTO chat_rooms (contract_id, tenant_user_id, admin_user_id)
          VALUES (?, ?, ?)
        `;

        db.query(chatRoomQuery, [
          contractId,
          tenantUserId,
          adminUserId
        ], (chatRoomErr) => {
          if (chatRoomErr) {
            console.error('❌ خطأ في إنشاء غرفة الدردشة:', chatRoomErr);
            return res.status(500).json({ message: 'تم حفظ العقد ولكن فشل إنشاء غرفة الدردشة' });
          }

          console.log('✅ تم إنشاء غرفة الدردشة بنجاح.');
          createPaymentsAndSubscriptions(); // تابع العمليات
        });
      }
    });
  });
});

  
  } catch (err) {
    console.error('❌ PDF Analyze Error:', err);
    res.status(500).json({ message: 'فشل في تحليل الـ PDF' });
  }
  
  });


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/api/profile/contract/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      contract_number, contract_type, contract_date, 
      contract_start, contract_end, contract_location
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});


app.get('/api/profile/owner/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      owner_name, owner_nationality, owner_id_type, 
      owner_id_number, owner_email, owner_phone, owner_address
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});



app.get('/api/profile/tenant/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      tenant_name, tenant_nationality, tenant_id_type, 
      tenant_id_number, tenant_email, tenant_phone, tenant_address
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});


app.get('/api/profile/property/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      property_national_address, property_building_type, property_usage,
      property_units_count, property_floors_count
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});


app.get('/api/profile/unit/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      unit_type, unit_number, unit_floor_number, unit_area,
      unit_furnishing_status, unit_ac_units_count, unit_ac_type
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});



app.get('/api/profile/finance/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      annual_rent, periodic_rent_payment, rent_payment_cycle, 
      rent_payments_count, total_contract_value
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});



app.get('/api/profile/privacy/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT terms_conditions, privacy_policy
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    LIMIT 1;
  `;
  
  db.query(query, [userId], (err, results) => {
    if(err) return res.status(500).json({ message: 'خطأ في الخادم' });
    if(results.length === 0) return res.status(404).json({ message: 'لا توجد بيانات' });

    res.json(results[0]);
  });
});









////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.put('/api/payments/:paymentId', verifyToken, (req, res) => {
  const { paymentId } = req.params;
  const { payment_status, paid_date, payment_note } = req.body;

  const updateQuery = `
    UPDATE payments SET payment_status = ?, paid_date = ?, payment_note = ?
    WHERE id = ?
  `;

  db.query(updateQuery, [payment_status, paid_date, payment_note, paymentId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'خطأ في تحديث الدفعة' });
    }

    res.json({ message: 'تم تحديث الدفعة بنجاح' });
  });
});



app.get('/api/payment-stats/:tenantId', verifyToken, (req, res) => {
  const tenantId = req.params.tenantId;

  const query = `
    SELECT p.payment_number, p.payment_amount, p.due_date, p.payment_status
    FROM payments p
    JOIN rental_contracts_details r ON p.contract_id = r.id
    WHERE r.tenant_id = (SELECT id FROM users WHERE user_id = ?)
    ORDER BY p.payment_number;
  `;

  db.query(query, [tenantId], (err, payments) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'خطأ في جلب بيانات الدفعات' });
    }

    res.json({ payments });
  });
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post('/api/messages/send', verifyToken, (req, res) => {
  const { chatRoomId, senderId, receiverId, message } = req.body;

  // جلب contract_id من جدول chat_rooms
  const getContractQuery = `SELECT contract_id FROM chat_rooms WHERE id = ?`;

  db.query(getContractQuery, [chatRoomId], (err, results) => {
    if (err || results.length === 0) {
      console.error('خطأ في إيجاد العقد', err);
      return res.status(500).json({ message: 'خطأ في إيجاد العقد المرتبط بغرفة الدردشة' });
    }

    const contractId = results[0].contract_id;

    const query = `
      INSERT INTO messages (contract_id, chat_room_id, sender_id, receiver_id, message)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(query, [contractId, chatRoomId, senderId, receiverId, message], (err) => {
      if (err) {
        console.error('خطأ في إرسال الرسالة:', err);
        return res.status(500).json({ message: 'خطأ في إرسال الرسالة' });
      }

      res.status(200).json({ message: 'تم الإرسال بنجاح' });
    });
  });
});



app.get('/api/messages/:chatRoomId', verifyToken, (req, res) => {
  const { chatRoomId } = req.params;
  const userId = req.user.userId; // 👈 استخدم هذا المفتاح فقط.

  console.log('القيم التي يتم التحقق منها:', { chatRoomId, userId });

  const checkQuery = `
    SELECT * FROM chat_rooms 
    WHERE id = ? AND (tenant_user_id = ? OR admin_user_id = ?)
  `;

  db.query(checkQuery, [chatRoomId, userId, userId], (checkErr, checkResult) => {
    if (checkErr || checkResult.length === 0) {
      console.error('خطأ صلاحيات الوصول:', checkErr, checkResult);
      return res.status(403).json({ message: 'لا يسمح لك بالوصول لهذه الرسائل' });
    }

    const query = `
      SELECT * FROM messages
      WHERE chat_room_id = ?
      ORDER BY timestamp ASC
    `;

    db.query(query, [chatRoomId], (err, messages) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'خطأ في جلب الرسائل' });
      }

      res.status(200).json({ messages });
    });
  });
});




app.put('/api/messages/read/:messageId', verifyToken, (req, res) => {
  const { messageId } = req.params;

  const query = `
    UPDATE messages SET is_read = TRUE WHERE id = ?
  `;

  db.query(query, [messageId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'خطأ في تحديث حالة القراءة' });
    }

    res.status(200).json({ message: 'تم تحديث حالة الرسالة' });
  });
});




// Endpoint لجلب بيانات غرفة الدردشة للمستأجر
app.get('/api/chat-room/tenant/:tenantId', verifyToken, (req, res) => {
  const { tenantId } = req.params;

  const query = `
    SELECT cr.id AS chat_room_id, cr.admin_user_id AS owner_user_id, u.name AS owner_name
    FROM chat_rooms cr
    JOIN users u ON cr.admin_user_id = u.user_id
    WHERE cr.tenant_user_id = ?
    LIMIT 1
  `;

  db.query(query, [tenantId], (err, results) => {
    if (err || results.length === 0) {
      console.error(err);
      return res.status(404).json({ message: 'لم يتم العثور على غرفة دردشة' });
    }

    res.status(200).json(results[0]);
  });
});



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 📁 index.js أو ملف routes المناسب
// 📁 index.js أو ملف routes المناسب
const { JWT } = require('google-auth-library');

const serviceAccount = require('./firebase/firebase-service-account.json'); // مسار ملف JSON من Firebase

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
// إعدادات Firebase Admin SDK

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
    const query = 'SELECT fcm_token FROM users WHERE user_id = ?';
    const [result] = await db.promise().query(query, [userId]);
    if (result.length && result[0].fcm_token) {
      tokens.push({ token: result[0].fcm_token, userId });
    }
  }

  // 📌 حالة متعددة محددة
  else if (Array.isArray(userIds)) {
    const placeholders = userIds.map(() => '?').join(',');
    const query = `SELECT user_id, fcm_token FROM users WHERE user_id IN (${placeholders})`;
    const [results] = await db.promise().query(query, userIds);
    tokens = results.filter(row => row.fcm_token).map(row => ({ token: row.fcm_token, userId: row.user_id }));
  }

  // 📌 حالة حسب نوع المستخدم (admins أو users)
  else if (targetType) {
    const query = `SELECT user_id, fcm_token FROM users WHERE user_type = ?`;
    const [results] = await db.promise().query(query, [targetType]);
    tokens = results.filter(row => row.fcm_token).map(row => ({ token: row.fcm_token, userId: row.user_id }));
  }

  if (!tokens.length) {
    return res.status(404).json({ message: '❌ لم يتم العثور على مستلمين صالحين' });
  }

  // إرسال لكل واحد
  const accessToken = await getAccessToken();
  for (const { token, userId } of tokens) {
    const message = {
  message: {
    token,
    notification: {
      title,
      body,
    },
    data: {
      screen: 'notifications',
      userId: userId
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

      // حفظ الإشعار
      await db.promise().query(
        'INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)',
        [userId, title, body]
      );
    } catch (err) {
      console.error(`فشل الإرسال لـ ${userId}`, err);
    }
  }

  res.json({ message: `✅ تم إرسال الإشعار إلى ${tokens.length} مستخدم` });
});





// ✅ API: جلب إشعارات مستخدم معين
app.get('/api/notifications/:userId', verifyToken, (req, res) => {
  const { userType, userId: requesterId } = req.user;
  const { userId } = req.params;

  // فقط السوبر أو نفس المستخدم يقدر يشوف إشعاراته
  if (userId !== requesterId && userType !== 'super') {
    return res.status(403).json({ message: '❌ ليس لديك صلاحية لعرض هذه الإشعارات' });
  }

  const query = `
    SELECT id, title, body, is_read, created_at
    FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ message: 'خطأ في جلب الإشعارات' });
    res.json({ notifications: results });
  });
});

// ✅ API: تعليم الإشعار كمقروء
app.put('/api/notifications/:id/read', verifyToken, (req, res) => {
  const { id } = req.params;
  const { userId } = req.user;

  const checkQuery = 'SELECT user_id FROM notifications WHERE id = ?';

  db.query(checkQuery, [id], (err, results) => {
    if (err || results.length === 0 || results[0].user_id !== userId) {
      return res.status(403).json({ message: '❌ لا يمكن تعديل هذا الإشعار' });
    }

    const updateQuery = 'UPDATE notifications SET is_read = TRUE WHERE id = ?';
    db.query(updateQuery, [id], (updateErr) => {
      if (updateErr) return res.status(500).json({ message: 'فشل التحديث' });
      res.json({ message: '✅ تم التعليم كمقروء' });
    });
  });
});

// ✅ API: تفعيل اشتراك للمُلاك (admin) من السوبر فقط
app.post('/api/activate-subscription', verifyToken, (req, res) => {
  const { userType } = req.user;
  const { adminId, startDate, endDate } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه تفعيل الاشتراكات' });
  }

  if (!adminId || !startDate || !endDate) {
    return res.status(400).json({ message: 'يجب إرسال adminId و startDate و endDate' });
  }

  const insertQuery = `
    INSERT INTO admin_subscriptions (admin_id, start_date, end_date)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE start_date = VALUES(start_date), end_date = VALUES(end_date)
  `;

  db.query(insertQuery, [adminId, startDate, endDate], (err) => {
    if (err) return res.status(500).json({ message: '❌ فشل في تفعيل الاشتراك' });
    res.json({ message: '✅ تم تفعيل أو تحديث الاشتراك للمُـلك' });
  });
});



app.post('/api/save-device-token', verifyToken, (req, res) => {
  const { userId, deviceToken } = req.body;
  if (!userId || !deviceToken) {
    return res.status(400).json({ message: 'userId و deviceToken مطلوبين' });
  }

  const query = `UPDATE users SET fcm_token = ? WHERE user_id = ?`;
  db.query(query, [deviceToken, userId], (err) => {
    if (err) return res.status(500).json({ message: 'فشل في حفظ التوكن' });
    res.json({ message: '✅ تم حفظ FCM Token بنجاح' });
  });
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
    const [[userRow]] = await db.promise().query(
      'SELECT id FROM users WHERE user_id = ?',
      [userId]
    );
    if (!userRow) return res.status(404).json({ message: 'المستخدم غير موجود' });
    const tenantId = userRow.id;

    // 2. جلب admin_id المرتبط بالمستأجر من آخر عقد
    const [[contractRow]] = await db.promise().query(
      'SELECT admin_id FROM rental_contracts_details WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1',
      [tenantId]
    );
    if (!contractRow) return res.status(404).json({ message: 'لا يوجد عقد مرتبط بهذا المستخدم' });
    const ownerId = contractRow.admin_id;

    // 3. إنشاء الطلب
    await db.promise().query(
      'INSERT INTO maintenance_requests (tenant_id, owner_id, category, description) VALUES (?, ?, ?, ?)',
      [tenantId, ownerId, category, description || '']
    );

    // 4. جلب fcm_token للمالك
    const [[ownerRow]] = await db.promise().query(
      'SELECT fcm_token FROM users WHERE id = ?',
      [ownerId]
    );
    if (ownerRow && ownerRow.fcm_token) {
      const accessToken = await getAccessToken();
      const message = {
        message: {
          token: ownerRow.fcm_token,
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
    const [[userRow]] = await db.promise().query(
      'SELECT id FROM users WHERE user_id = ?',
      [userId]
    );
    if (!userRow) return res.status(404).json({ message: 'المستخدم غير موجود' });

    // 2. جلب سجل الطلبات لهذا المستأجر
    const [history] = await db.promise().query(
      `SELECT category, description, status, created_at
       FROM maintenance_requests
       WHERE tenant_id = ?
       ORDER BY created_at DESC`,
      [userRow.id]
    );

    res.json({ history });
  } catch (err) {
    console.error('❌ Maintenance History Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء جلب سجل الصيانة' });
  }
});



app.get('/api/last-maintenance-request', verifyToken, async (req, res) => {
  const { userId } = req.user;

  try {
    const [[userRow]] = await db.promise().query(
      'SELECT id FROM users WHERE user_id = ?',
      [userId]
    );
    if (!userRow) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const tenantId = userRow.id;

    const [[requestRow]] = await db.promise().query(
      `SELECT category, description, status, created_at
       FROM maintenance_requests
       WHERE tenant_id = ?
       ORDER BY created_at DESC LIMIT 1`,
      [tenantId]
    );

    if (!requestRow) return res.status(404).json({ message: 'لا يوجد طلبات' });

    res.json(requestRow);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'خطأ في استرجاع البيانات' });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post('/api/toggle-review-permission', verifyToken, (req, res) => {
  const { userType } = req.user;
  const { adminId, enabled } = req.body;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه تعديل صلاحيات المراجعات' });
  }

  const query = `
    INSERT INTO review_permissions (admin_id, enabled)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)
  `;

  db.query(query, [adminId, enabled], (err) => {
    if (err) return res.status(500).json({ message: 'فشل في تعديل الصلاحية' });
    res.json({ message: '✅ تم تعديل الصلاحية بنجاح' });
  });
});




// ✅ API: إضافة تقييم من المستأجر + تسجيل نقاط
app.post('/api/reviews/add', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { rating, comment } = req.body;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'يرجى إرسال تقييم بين 1 و5' });
  }

  try {
    await db.promise().query(
      'INSERT INTO reviews (user_id, rating, comment) VALUES (?, ?, ?)',
      [userId, rating, comment || '']
    );

    await db.promise().query(
      'INSERT INTO review_points (user_id, points, source) VALUES (?, ?, ?)',
      [userId, 10, 'إرسال تقييم']
    );

    res.json({ message: '✅ تم تسجيل تقييمك وحصلت على 10 نقاط!' });
  } catch (err) {
    console.error('❌ Review Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء إرسال التقييم' });
  }
});



// ✅ API: جلب التقييمات (للموقع أو للمالك لو عنده صلاحية)
app.get('/api/reviews/:adminId', verifyToken, async (req, res) => {
  const { adminId } = req.params;

  try {
    const [[permission]] = await db.promise().query(
      'SELECT enabled FROM review_permissions WHERE admin_id = ?',
      [adminId]
    );

    if (!permission || !permission.enabled) {
      return res.status(403).json({ message: '❌ لا يملك المالك صلاحية عرض التقييمات' });
    }

    const [reviews] = await db.promise().query(
      'SELECT rating, comment, created_at FROM reviews WHERE visible = TRUE ORDER BY created_at DESC'
    );

    res.json({ reviews });
  } catch (err) {
    console.error('❌ Fetch Reviews Error:', err);
    res.status(500).json({ message: 'فشل في جلب التقييمات' });
  }
});




// ✅ API: ترتيب المستخدمين حسب النقاط (شارت المنافسة)
app.get('/api/review-stats', verifyToken, async (req, res) => {
  try {
    const [results] = await db.promise().query(`
      SELECT u.user_id, u.name, SUM(rp.points) AS total_points
      FROM review_points rp
      JOIN users u ON u.user_id = rp.user_id
      GROUP BY rp.user_id
      ORDER BY total_points DESC
    `);

    res.json({ leaderboard: results });
  } catch (err) {
    console.error('❌ Review Stats Error:', err);
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

  try {
    await db.promise().query(
      'INSERT INTO review_points (user_id, points, source) VALUES (?, ?, ?)',
      [userId, points, source || 'تعديل يدوي']
    );

    res.json({ message: '✅ تم تحديث النقاط للمستخدم بنجاح' });
  } catch (err) {
    console.error('❌ Admin Points Update Error:', err);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث النقاط' });
  }
});



// ✅ API: ملخص تقييمات ونقاط مستخدم محدد
app.get('/api/user-review-summary/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    const [[pointsRow]] = await db.promise().query(
      'SELECT SUM(points) AS total_points FROM review_points WHERE user_id = ?',
      [userId]
    );

    const [reviews] = await db.promise().query(
      'SELECT rating, comment, created_at FROM reviews WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      total_points: pointsRow.total_points || 0,
      reviews,
    });
  } catch (err) {
    console.error('❌ User Review Summary Error:', err);
    res.status(500).json({ message: 'فشل في جلب ملخص التقييمات' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get('/api/download-contract/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT pdf_path 
    FROM rental_contracts_details 
    WHERE tenant_id = (SELECT id FROM users WHERE user_id = ?)
    ORDER BY created_at DESC
    LIMIT 1;
  `;

  db.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: 'لم يتم العثور على ملف العقد' });
    }

    const pdfPath = path.join(__dirname, results[0].pdf_path);

    res.sendFile(pdfPath, (err) => {
      if (err) {
        console.error('❌ File Sending Error:', err);
        res.status(500).json({ message: 'حدث خطأ في تحميل الملف' });
      }
    });
  });
});



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ✅ 1. Get all services (for super admin)
app.get('/api/services', verifyToken, (req, res) => {
  const { userType } = req.user;
  
  if (userType !== 'super') {
    return res.status(403).json({ message: 'صلاحية مفقودة' });
  }
  db.query('SELECT * FROM dynamic_services', (err, results) => {
    if (err) return res.status(500).json({ message: 'DB Error', err });
    res.json(results);
  });
});

// ✅ 2. Create new service (super only)
app.post('/api/services', verifyToken, (req, res) => {
  const { userType } = req.user;
  if (userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }
  const { title, icon, description } = req.body;
  const query = 'INSERT INTO dynamic_services (title, icon, description) VALUES (?, ?, ?)';
  db.query(query, [title, icon, description], (err, result) => {
    if (err) return res.status(500).json({ message: 'DB Error', err });
    res.json({ message: 'تمت الإضافة بنجاح', id: result.insertId });
  });
});

// ✅ 3. Toggle service active (super only)
app.put('/api/services/:id/toggle', verifyToken, (req, res) => {
  const { userType } = req.user;
  if (userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }
  const id = req.params.id;
  const query = 'UPDATE dynamic_services SET is_active = NOT is_active WHERE id = ?';
  db.query(query, [id], (err) => {
    if (err) return res.status(500).json({ message: 'DB Error', err });
    res.json({ message: 'تم التحديث بنجاح' });
  });
});

// ✅ 4. Get admin's selected services
app.get('/api/admin-services/:adminId', verifyToken, (req, res) => {
  const { adminId } = req.params;
  const query = `
    SELECT ds.*, COALESCE(av.is_enabled, 0) as is_enabled
    FROM dynamic_services ds
    LEFT JOIN admin_service_visibility av
    ON ds.id = av.service_id AND av.admin_id = ?
    WHERE ds.is_active = 1
  `;
  db.query(query, [adminId], (err, results) => {
    if (err) return res.status(500).json({ message: 'DB Error', err });
    res.json(results);
  });
});

// ✅ 5. Toggle service for admin
app.post('/api/admin-services/toggle', verifyToken, (req, res) => {
  const { userType } = req.user;
  if (userType !== 'admin' && userType !== 'super') {
    return res.status(403).json({ message: 'غير مصرح' });
  }
  const { adminId, serviceId } = req.body;
  const checkQuery = 'SELECT * FROM admin_service_visibility WHERE admin_id = ? AND service_id = ?';
  db.query(checkQuery, [adminId, serviceId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'DB Error', err });
    if (rows.length) {
      const toggleQuery = 'UPDATE admin_service_visibility SET is_enabled = NOT is_enabled WHERE admin_id = ? AND service_id = ?';
      db.query(toggleQuery, [adminId, serviceId], (err) => {
        if (err) return res.status(500).json({ message: 'DB Error', err });
        res.json({ message: 'تم التحديث بنجاح' });
      });
    } else {
      const insertQuery = 'INSERT INTO admin_service_visibility (admin_id, service_id, is_enabled) VALUES (?, ?, 1)';
      db.query(insertQuery, [adminId, serviceId], (err) => {
        if (err) return res.status(500).json({ message: 'DB Error', err });
        res.json({ message: 'تم التفعيل بنجاح' });
      });
    }
  });
});

// ✅ 6. Get services for tenant (final output for UI)
// ✅ خدمات المستأجر النهائية بعد التعديل
app.get('/api/services-for-tenant/:tenantUserId', verifyToken, (req, res) => {
  const tenantUserId = req.params.tenantUserId;

  const getAdminQuery = `
    SELECT rcd.admin_id
    FROM rental_contracts_details rcd
    JOIN users u ON rcd.tenant_id = u.id
    WHERE u.user_id = ?
    ORDER BY rcd.created_at DESC
    LIMIT 1
  `;

  db.query(getAdminQuery, [tenantUserId], (adminErr, adminResults) => {
    if (adminErr) return res.status(500).json({ message: 'DB Error', error: adminErr });

    if (!adminResults.length) return res.status(404).json({ message: 'المالك غير موجود' });

    const adminId = adminResults[0].admin_id;

    const servicesQuery = `
  SELECT ds.*
  FROM dynamic_services ds
  LEFT JOIN admin_service_visibility v ON v.service_id = ds.id AND v.admin_id = ?
  WHERE ds.is_active = 1 AND (
    (ds.is_default = 1 AND (v.is_enabled IS NULL OR v.is_enabled = 1))
    OR (ds.is_default = 0 AND v.is_enabled = 1)
  )
  ORDER BY ds.display_order ASC
`;

    db.query(servicesQuery, [adminId], (err, results) => {
      if (err) return res.status(500).json({ message: 'DB Error', err });

     // داخل الكود الحالي للـ API، عدّل:
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
  case 21: route = 'cleaningServiceRequest'; break;        // 🧹 طلب خدمة تنظيف متخصصة
  case 22: route = 'changeLocksRequest'; break;            // 🔐 طلب تغيير الأقفال
  case 23: route = 'noiseComplaintRequest'; break;         // 🚨 بلاغ إزعاج
  case 24: route = 'apartmentSuppliesRequest'; break;      // 📦 طلب مستلزمات الشقة
  default: route = null;
}


  return {
    ...service,
    route: route
  };
});



      res.json({ services });
    });
  });
});






app.put('/api/services/:id/order', verifyToken, (req, res) => {
  const { userType } = req.user;
  const serviceId = req.params.id;
  const { display_order } = req.body;

  if (userType !== 'super' && userType !== 'admin') {
    return res.status(403).json({ message: '❌ غير مصرح لك بتعديل الترتيب' });
  }

  if (!display_order || isNaN(display_order)) {
    return res.status(400).json({ message: '❗ display_order مطلوب ويجب أن يكون رقمًا صالحًا' });
  }

  const query = 'UPDATE dynamic_services SET display_order = ? WHERE id = ?';

  db.query(query, [display_order, serviceId], (err) => {
    if (err) {
      console.error('❌ DB Error:', err);
      return res.status(500).json({ message: 'فشل في تحديث الترتيب' });
    }

    res.json({ message: '✅ تم تحديث ترتيب الخدمة بنجاح' });
  });
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/api/noise-complaints', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const { category, description } = req.body;

  if (userType !== 'user') {
    return res.status(403).json({ message: '❌ فقط المستأجر يمكنه تقديم بلاغ' });
  }

  try {
    // جلب admin_id من آخر عقد للمستأجر
    const [[row]] = await db.promise().query(
      `SELECT admin_id FROM rental_contracts_details 
       WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );

    if (!row) return res.status(404).json({ message: 'لا يوجد عقد مرتبط' });

    await db.promise().query(
      `INSERT INTO noise_complaints (tenant_id, admin_id, category, description) 
       VALUES (?, ?, ?, ?)`,
      [userId, row.admin_id, category, description || '']
    );

    res.json({ message: '✅ تم إرسال البلاغ بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ خطأ في إرسال البلاغ' });
  }
});


app.get('/api/noise-complaints/tenant', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;

  if (userType !== 'user') {
    return res.status(403).json({ message: '❌ فقط المستأجر يملك هذه الصلاحية' });
  }

  try {
    const [complaints] = await db.promise().query(
      `SELECT id, category, description, status, created_at
       FROM noise_complaints WHERE tenant_id = ? ORDER BY created_at DESC`,
      [userId]
    );

    res.json({ complaints });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ خطأ في جلب البلاغات' });
  }
});


app.get('/api/noise-complaints/admin', verifyToken, async (req, res) => {
  const { userType, id: adminId } = req.user;

  if (userType !== 'admin') {
    return res.status(403).json({ message: '❌ فقط المالك يمكنه عرض هذه البلاغات' });
  }

  try {
    const [complaints] = await db.promise().query(
      `SELECT id, category, description, status, created_at
       FROM noise_complaints WHERE admin_id = ? ORDER BY created_at DESC`,
      [adminId]
    );

    res.json({ complaints });
  } catch (err) {
    console.error(err);
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

  try {
    await db.promise().query(
      `UPDATE noise_complaints SET status = ? WHERE id = ?`,
      [status, complaintId]
    );

    res.json({ message: '✅ تم تحديث حالة البلاغ' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ فشل في التحديث' });
  }
});


app.delete('/api/noise-complaints/:id', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { id } = req.params;

  if (userType !== 'super') {
    return res.status(403).json({ message: '❌ فقط السوبر يمكنه الحذف' });
  }

  try {
    await db.promise().query(
      `DELETE FROM noise_complaints WHERE id = ?`,
      [id]
    );
    res.json({ message: '🗑️ تم حذف البلاغ بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ خطأ أثناء الحذف' });
  }
});




app.get('/api/noise-complaints/:id', verifyToken, async (req, res) => {
  const { userType, id: userId } = req.user;
  const complaintId = req.params.id;

  try {
    const [[complaint]] = await db.promise().query(
      `SELECT * FROM noise_complaints WHERE id = ?`,
      [complaintId]
    );

    if (!complaint) {
      return res.status(404).json({ message: 'البلاغ غير موجود' });
    }

    if (userType === 'user' && complaint.tenant_id !== userId) {
      return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول لهذا البلاغ' });
    }

    if (userType === 'admin' && complaint.admin_id !== userId) {
      return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول لهذا البلاغ' });
    }

    res.json({ complaint });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ خطأ في جلب البلاغ' });
  }
});




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/api/payment-alert', verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [[existing]] = await db.promise().query(
      'SELECT is_enabled, days_before FROM payment_alert_settings WHERE user_id = ?',
      [userId]
    );

    if (existing) {
      return res.json({ ...existing });
    }

    // لا يوجد إعداد سابق، إنشاء افتراضي
    await db.promise().query(
      'INSERT INTO payment_alert_settings (user_id) VALUES (?)',
      [userId]
    );

    return res.json({ is_enabled: true, days_before: 3 });
  } catch (err) {
    console.error('❌ Error fetching payment alert settings:', err);
    res.status(500).json({ message: 'خطأ في جلب الإعدادات' });
  }
});


app.put('/api/payment-alert', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { is_enabled, days_before } = req.body;

  if (typeof is_enabled !== 'boolean' || isNaN(days_before)) {
    return res.status(400).json({ message: '❗ البيانات غير صالحة' });
  }

  try {
    await db.promise().query(
      `INSERT INTO payment_alert_settings (user_id, is_enabled, days_before)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled), days_before = VALUES(days_before)`,
      [userId, is_enabled, days_before]
    );

    res.json({ message: '✅ تم حفظ الإعدادات بنجاح' });
  } catch (err) {
    console.error('❌ Error updating payment alert settings:', err);
    res.status(500).json({ message: 'فشل في تحديث الإعدادات' });
  }
});


app.get('/api/payment-alert/:targetUserId', verifyToken, async (req, res) => {
  const { userType } = req.user;
  const { targetUserId } = req.params;

  if (!['super', 'admin'].includes(userType)) {
    return res.status(403).json({ message: '❌ لا تملك صلاحية الوصول' });
  }

  try {
    const [[userRow]] = await db.promise().query(
      'SELECT id FROM users WHERE user_id = ? LIMIT 1',
      [targetUserId]
    );
    if (!userRow) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const [[existing]] = await db.promise().query(
      'SELECT is_enabled, days_before FROM payment_alert_settings WHERE user_id = ?',
      [userRow.id]
    );

    if (existing) {
      return res.json({ ...existing });
    }

    await db.promise().query(
      'INSERT INTO payment_alert_settings (user_id) VALUES (?)',
      [userRow.id]
    );

    return res.json({ is_enabled: true, days_before: 3 });
  } catch (err) {
    console.error(err);
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

  try {
    const [[userRow]] = await db.promise().query(
      'SELECT id FROM users WHERE user_id = ? LIMIT 1',
      [targetUserId]
    );
    if (!userRow) return res.status(404).json({ message: 'المستخدم غير موجود' });

    await db.promise().query(
      `INSERT INTO payment_alert_settings (user_id, is_enabled, days_before)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled), days_before = VALUES(days_before)`,
      [userRow.id, is_enabled, days_before]
    );

    res.json({ message: '✅ تم تحديث إعدادات المستخدم' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '❌ فشل في تحديث الإعدادات' });
  }
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API تعمل على المنفذ ${PORT}`);
});
