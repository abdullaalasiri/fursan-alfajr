const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const pool = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Trust proxy - important for Render
app.set('trust proxy', 1);

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  secret: 'fursan-alfajr-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    secure: true, // Always secure on Render
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Helper: التاريخ بتوقيت البحرين
function getBahrainDate() {
  const now = new Date();
  const bahrainTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Bahrain' }));
  const y = bahrainTime.getFullYear();
  const m = String(bahrainTime.getMonth() + 1).padStart(2, '0');
  const d = String(bahrainTime.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// Middleware: التحقق من تسجيل الدخول
function requireAuth(req, res, next) {
  console.log('Session check:', { 
    sessionID: req.sessionID,
    userId: req.session?.userId,
    isAdmin: req.session?.isAdmin 
  });
  
  if (!req.session.userId) {
    console.log('❌ No session userId - redirecting to login');
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
app.post('/api/register', async (req, res) => {
  const { username, password, fullName, category, branch } = req.body;

  if (!username || !password || !fullName || !category || !branch) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
  }

  try {
    // التحقق من حالة التسجيل
    const settingResult = await pool.query(
      'SELECT value FROM settings WHERE key = $1',
      ['registration_open']
    );
    
    const isOpen = settingResult.rows[0]?.value === 'true';
    
    if (!isOpen) {
      return res.status(403).json({ error: 'التسجيل مغلق حالياً. يرجى التواصل مع الإدارة.' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, full_name, category, branch) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [username, passwordHash, fullName, category, branch]
    );

    req.session.userId = result.rows[0].id;
    req.session.username = username;
    req.session.isAdmin = false;

    res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
    } else {
      console.error(error);
      res.status(500).json({ error: 'خطأ في السيرفر' });
    }
  }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبة' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

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

    // Force session save
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'خطأ في حفظ الجلسة' });
      }
      
      console.log('✅ Login successful:', {
        userId: user.id,
        username: user.username,
        sessionID: req.sessionID
      });

      res.json({
        success: true,
        isAdmin: user.is_admin === 1,
        message: 'تم تسجيل الدخول بنجاح'
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// تسجيل خروج
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// الحصول على بيانات المستخدم الحالي
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, username, full_name, is_admin FROM users WHERE id = $1',
      [req.session.userId]
    );

    const today = getBahrainDate();
    const recordResult = await pool.query(
      'SELECT * FROM daily_prayers WHERE user_id = $1 AND prayer_date = $2',
      [req.session.userId, today]
    );

    res.json({
      user: userResult.rows[0],
      todayRecord: recordResult.rows[0] || null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// تسجيل الصلاة اليومية
app.post('/api/record-prayer', requireAuth, async (req, res) => {
  const { sunnahFajr, fajrJamaah, fajrOntime } = req.body;
  const today = getBahrainDate();
  const userId = req.session.userId;

  if (typeof sunnahFajr !== 'boolean' || typeof fajrJamaah !== 'boolean' || typeof fajrOntime !== 'boolean') {
    return res.status(400).json({ error: 'بيانات غير صحيحة' });
  }

  const sunnahPoints = sunnahFajr ? 1 : 0;
  const jamaahPoints = fajrJamaah ? 3 : 0;
  const ontimePoints = fajrOntime ? 1 : 0;
  const totalPoints = sunnahPoints + jamaahPoints + ontimePoints;

  try {
    // التحقق من عدم وجود تسجيل
    const existing = await pool.query(
      'SELECT id FROM daily_prayers WHERE user_id = $1 AND prayer_date = $2',
      [userId, today]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'تم التسجيل مسبقاً لهذا اليوم' });
    }

    await pool.query(
      'INSERT INTO daily_prayers (user_id, prayer_date, sunnah_fajr, fajr_jamaah, fajr_ontime, total_points) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, today, sunnahPoints, jamaahPoints, ontimePoints, totalPoints]
    );

    res.json({ success: true, message: 'تم حفظ التسجيل بنجاح', points: totalPoints });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في حفظ البيانات' });
  }
});

// الحصول على نقاط وترتيب الطالب
app.get('/api/my-stats', requireAuth, async (req, res) => {
  const userId = req.session.userId;

  try {
    // جلب معلومات الطالب مع فئته
    const userInfo = await pool.query(
      'SELECT category FROM users WHERE id = $1',
      [userId]
    );
    const userCategory = userInfo.rows[0]?.category;

    const totalResult = await pool.query(
      'SELECT COALESCE(SUM(total_points), 0) as total FROM daily_prayers WHERE user_id = $1',
      [userId]
    );

    // ترتيب داخل نفس الفئة فقط
    const leaderboard = await pool.query(`
      SELECT u.id as user_id, COALESCE(SUM(dp.total_points), 0) as total 
      FROM users u
      LEFT JOIN daily_prayers dp ON u.id = dp.user_id
      WHERE u.is_admin = 0 AND u.category = $1
      GROUP BY u.id
      ORDER BY total DESC
    `, [userCategory]);

    const rank = leaderboard.rows.findIndex(item => item.user_id === userId) + 1;

    res.json({
      totalPoints: parseInt(totalResult.rows[0].total),
      rank: rank > 0 ? rank : '-',
      totalStudents: leaderboard.rows.length,
      category: userCategory
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// لوحة الصدارة
app.get('/api/leaderboard', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.full_name,
        COALESCE(SUM(dp.total_points), 0) as total_points,
        COUNT(dp.id) as days_count
      FROM users u
      LEFT JOIN daily_prayers dp ON u.id = dp.user_id
      WHERE u.is_admin = 0
      GROUP BY u.id
      ORDER BY total_points DESC, days_count DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// لوحة الادمن
app.get('/api/admin/students', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.full_name, u.category, u.branch, u.created_at,
        COALESCE(SUM(dp.total_points), 0) as total_points,
        COUNT(dp.id) as days_count
      FROM users u
      LEFT JOIN daily_prayers dp ON u.id = dp.user_id
      WHERE u.is_admin = 0
      GROUP BY u.id
      ORDER BY total_points DESC, days_count DESC
    `);

    const studentsWithRank = result.rows.map((student, index) => ({
      ...student,
      rank: index + 1
    }));

    res.json(studentsWithRank);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// تفاصيل تقدم الطالب
app.get('/api/admin/student/:id/progress', requireAdmin, async (req, res) => {
  const studentId = req.params.id;

  try {
    const studentResult = await pool.query(
      'SELECT id, username, full_name FROM users WHERE id = $1 AND is_admin = 0',
      [studentId]
    );

    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود' });
    }

    const recordsResult = await pool.query(`
      SELECT prayer_date, sunnah_fajr, fajr_jamaah, fajr_ontime, total_points
      FROM daily_prayers
      WHERE user_id = $1
      ORDER BY prayer_date ASC
    `, [studentId]);

    // تحويل prayer_date لـ string بدون timezone مشاكل
    const records = recordsResult.rows.map(r => ({
      ...r,
      prayer_date: r.prayer_date instanceof Date
        ? r.prayer_date.toISOString().split('T')[0]
        : r.prayer_date
    }));

    res.json({ student: studentResult.rows[0], records });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// 🗑️ حذف طالب - للمشرف فقط
app.delete('/api/admin/user/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  
  try {
    // حذف سجلات الصلاة أولاً
    await pool.query('DELETE FROM daily_prayers WHERE user_id = $1', [userId]);
    
    // حذف المستخدم (التأكد أنه ليس مشرف)
    const result = await pool.query('DELETE FROM users WHERE id = $1 AND is_admin = 0 RETURNING id', [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود أو لا يمكن حذفه' });
    }
    
    res.json({ success: true, message: 'تم حذف الطالب بنجاح' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'فشل في حذف الطالب' });
  }
});

// 🔑 إعادة تعيين كلمة المرور - للمشرف فقط
app.post('/api/admin/reset-password/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  
  try {
    // التحقق أن المستخدم موجود وليس مشرف
    const userResult = await pool.query(
      'SELECT id, username, full_name FROM users WHERE id = $1 AND is_admin = 0',
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود' });
    }
    
    // توليد كلمة مرور جديدة (6 أرقام عشوائية)
    const newPassword = Math.floor(100000 + Math.random() * 900000).toString();
    const passwordHash = bcrypt.hashSync(newPassword, 10);
    
    // تحديث كلمة المرور
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [passwordHash, userId]
    );
    
    res.json({
      success: true,
      username: userResult.rows[0].username,
      fullName: userResult.rows[0].full_name,
      newPassword: newPassword
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'فشل في إعادة تعيين كلمة المرور' });
  }
});

// 🔐 التحقق من حالة التسجيل
app.get('/api/registration-status', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT value FROM settings WHERE key = $1',
      ['registration_open']
    );
    
    const isOpen = result.rows[0]?.value === 'true';
    res.json({ isOpen });
  } catch (error) {
    console.error(error);
    res.json({ isOpen: true }); // Default to open if error
  }
});

// 🔐 تبديل حالة التسجيل - للمشرف فقط
app.post('/api/admin/toggle-registration', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT value FROM settings WHERE key = $1',
      ['registration_open']
    );
    
    const currentValue = result.rows[0]?.value === 'true';
    const newValue = !currentValue;
    
    await pool.query(
      'UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2',
      [newValue.toString(), 'registration_open']
    );
    
    res.json({
      success: true,
      isOpen: newValue,
      message: newValue ? 'تم فتح التسجيل' : 'تم إغلاق التسجيل'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'فشل في تغيير حالة التسجيل' });
  }
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