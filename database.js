const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// إنشاء/فتح قاعدة البيانات
const db = new sqlite3.Database('fursan.db', (err) => {
  if (err) {
    console.error('خطأ في فتح قاعدة البيانات:', err);
  } else {
    console.log('✅ تم الاتصال بقاعدة البيانات');
    initDatabase();
  }
});

function initDatabase() {
  // إنشاء الجداول
  db.serialize(() => {
    // جدول المستخدمين
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول التسجيل اليومي
    db.run(`
      CREATE TABLE IF NOT EXISTS daily_prayers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        prayer_date DATE NOT NULL,
        sunnah_fajr INTEGER DEFAULT 0,
        fajr_jamaah INTEGER DEFAULT 0,
        fajr_ontime INTEGER DEFAULT 0,
        total_points INTEGER DEFAULT 0,
        recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, prayer_date)
      )
    `);

    // إنشاء فهارس
    db.run(`CREATE INDEX IF NOT EXISTS idx_daily_prayers_date ON daily_prayers(prayer_date)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_daily_prayers_user ON daily_prayers(user_id)`);

    // إضافة حساب الادمن
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(
      `INSERT OR IGNORE INTO users (username, password_hash, full_name, is_admin) VALUES (?, ?, ?, 1)`,
      ['admin', adminPassword, 'المشرف'],
      (err) => {
        if (!err) {
          console.log('✅ حساب الادمن جاهز');
          console.log('📝 Username: admin');
          console.log('📝 Password: admin123');
          console.log('');
          console.log('📊 نظام النقاط:');
          console.log('   - سنة الفجر: 1 نقطة');
          console.log('   - الفجر جماعة في المسجد: 3 نقاط');
          console.log('   - الفجر في وقتها: 1 نقطة');
          console.log('   - أقصى نقاط يومياً: 4 نقاط');
        }
      }
    );
  });
}

module.exports = db;