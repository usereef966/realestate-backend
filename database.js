const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

async function query(sql, params) {
  const [results] = await pool.execute(sql, params);
  return results;
}

setInterval(async () => {
  try {
    await query('SELECT 1');
    console.log('✅ DB Ping successful');
  } catch (err) {
    console.error('❌ DB Ping failed:', err);
  }
}, 60000);

// تعديل SQL Mode لمطابقة القاعدة المحلية
query("SET SESSION sql_mode = REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', '')")
  .then(() => console.log('⚙️ SQL mode adjusted: STRICT_TRANS_TABLES removed'))
  .catch((err) => console.error('❌ Failed to adjust SQL mode:', err));


module.exports = { query };
