const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// الاتصال بـ PostgreSQL عبر DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDatabase() {
  const client = await pool.connect();
  try {
    // إنشاء جدول المستخدمين
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // إنشاء جدول التسجيل اليومي
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_prayers (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        prayer_date DATE NOT NULL,
        sunnah_fajr INTEGER DEFAULT 0,
        fajr_jamaah INTEGER DEFAULT 0,
        fajr_ontime INTEGER DEFAULT 0,
        total_points INTEGER DEFAULT 0,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, prayer_date)
      )
    `);

    // إنشاء فهارس
    await client.query(`CREATE INDEX IF NOT EXISTS idx_daily_prayers_date ON daily_prayers(prayer_date)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_daily_prayers_user ON daily_prayers(user_id)`);

    // إضافة حساب الادمن
    const adminPassword = bcrypt.hashSync('admin123', 10);
    await client.query(`
      INSERT INTO users (username, password_hash, full_name, is_admin)
      VALUES ($1, $2, $3, 1)
      ON CONFLICT (username) DO NOTHING
    `, ['admin', adminPassword, 'المشرف']);

    console.log('✅ قاعدة البيانات جاهزة!');
    console.log('📝 Username: admin');
    console.log('📝 Password: admin123');
  } finally {
    client.release();
  }
}

// تهيئة قاعدة البيانات عند الاتصال
initDatabase().catch(err => {
  console.error('❌ خطأ في تهيئة قاعدة البيانات:', err);
});

module.exports = pool;