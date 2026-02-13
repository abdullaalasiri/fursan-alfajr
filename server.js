const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./database');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'fursan-alfajr-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Helper: التاريخ بتوقيت البحرين
function getBahrainDate() {
  const now = new Date();
  const bahrainTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Bahrain' }));
  return bahrainTime.toISOString().split('T')[0];
}

// Middleware: التحقق من تسجيل الدخول
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next();
}

// Middleware: التحقق من صلاحيات الادمن
function requireAdmin(req, res, next) {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.status(403).json({ error: 'غير مصرح' });
  }
  next();
}

// ============ API Routes ============

// تسجيل حساب جديد
app.post('/api/register', (req, res) => {
  const { username, password, fullName } = req.body;

  if (!username || !password || !fullName) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  
  db.run(
    'INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)',
    [username, passwordHash, fullName],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
        }
        return res.status(500).json({ error: 'خطأ في السيرفر' });
      }

      req.session.userId = this.lastID;
      req.session.username = username;
      req.session.isAdmin = false;

      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    }
  );
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبة' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }

    if (!user) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });
    }

    const validPassword = bcrypt.compareSync(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = user.is_admin === 1;

    res.json({
      success: true,
      isAdmin: user.is_admin === 1,
      message: 'تم تسجيل الدخول بنجاح'
    });
  });
});

// تسجيل خروج
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// الحصول على بيانات المستخدم الحالي
app.get('/api/me', requireAuth, (req, res) => {
  db.get('SELECT id, username, full_name, is_admin FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }

    const today = getBahrainDate();
    db.get('SELECT * FROM daily_prayers WHERE user_id = ? AND prayer_date = ?', [req.session.userId, today], (err, todayRecord) => {
      res.json({
        user,
        todayRecord: todayRecord || null
      });
    });
  });
});

// تسجيل الصلاة اليومية
app.post('/api/record-prayer', requireAuth, (req, res) => {
  const { sunnahFajr, fajrPrayer } = req.body;
  const today = getBahrainDate();
  const userId = req.session.userId;

  if (typeof sunnahFajr !== 'boolean' || typeof fajrPrayer !== 'boolean') {
    return res.status(400).json({ error: 'بيانات غير صحيحة' });
  }

  const sunnahPoints = sunnahFajr ? 1 : 0;
  const fajrPoints = fajrPrayer ? 1 : 0;
  const totalPoints = sunnahPoints + fajrPoints;

  // التحقق من عدم وجود تسجيل
  db.get('SELECT id FROM daily_prayers WHERE user_id = ? AND prayer_date = ?', [userId, today], (err, existing) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }

    if (existing) {
      return res.status(400).json({ error: 'تم التسجيل مسبقاً لهذا اليوم' });
    }

    // إضافة التسجيل
    db.run(
      'INSERT INTO daily_prayers (user_id, prayer_date, sunnah_fajr, fajr_prayer, total_points) VALUES (?, ?, ?, ?, ?)',
      [userId, today, sunnahPoints, fajrPoints, totalPoints],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'خطأ في حفظ البيانات' });
        }
        res.json({ success: true, message: 'تم حفظ التسجيل بنجاح', points: totalPoints });
      }
    );
  });
});

// الحصول على نقاط وترتيب الطالب
app.get('/api/my-stats', requireAuth, (req, res) => {
  const userId = req.session.userId;

  db.get('SELECT COALESCE(SUM(total_points), 0) as total FROM daily_prayers WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }

    const totalPoints = result.total;

    db.all('SELECT user_id, SUM(total_points) as total FROM daily_prayers GROUP BY user_id ORDER BY total DESC', [], (err, leaderboard) => {
      const rank = leaderboard.findIndex(item => item.user_id === userId) + 1;
      res.json({
        totalPoints,
        rank,
        totalStudents: leaderboard.length
      });
    });
  });
});

// لوحة الصدارة
app.get('/api/leaderboard', requireAuth, (req, res) => {
  db.all(`
    SELECT 
      u.id,
      u.full_name,
      COALESCE(SUM(dp.total_points), 0) as total_points,
      COUNT(dp.id) as days_count
    FROM users u
    LEFT JOIN daily_prayers dp ON u.id = dp.user_id
    WHERE u.is_admin = 0
    GROUP BY u.id
    ORDER BY total_points DESC, days_count DESC
  `, [], (err, leaderboard) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }
    res.json(leaderboard);
  });
});

// لوحة الادمن
app.get('/api/admin/students', requireAdmin, (req, res) => {
  db.all(`
    SELECT 
      u.id,
      u.username,
      u.full_name,
      u.created_at,
      COALESCE(SUM(dp.total_points), 0) as total_points,
      COUNT(dp.id) as days_count
    FROM users u
    LEFT JOIN daily_prayers dp ON u.id = dp.user_id
    WHERE u.is_admin = 0
    GROUP BY u.id
    ORDER BY total_points DESC, days_count DESC
  `, [], (err, students) => {
    if (err) {
      return res.status(500).json({ error: 'خطأ في السيرفر' });
    }

    const studentsWithRank = students.map((student, index) => ({
      ...student,
      rank: index + 1
    }));

    res.json(studentsWithRank);
  });
});

// الصفحة الرئيسية
app.get('/', (req, res) => {
  if (req.session.userId) {
    if (req.session.isAdmin) {
      res.redirect('/admin.html');
    } else {
      res.redirect('/student.html');
    }
  } else {
    res.redirect('/login.html');
  }
});

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║       🌙 فرسان الفجر 🌙              ║
  ╠════════════════════════════════════════╣
  ║  السيرفر يعمل على: http://localhost:${PORT} ║
  ╚════════════════════════════════════════╝
  `);
});
