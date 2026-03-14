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
    // Trim username to handle spaces
    const trimmedUsername = username.trim();
    
    console.log('🔍 Login attempt:', {
      originalUsername: username,
      trimmedUsername: trimmedUsername,
      usernameLength: username.length,
      trimmedLength: trimmedUsername.length,
      hasSpaces: username !== trimmedUsername
    });
    
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [trimmedUsername]);
    const user = result.rows[0];

    if (!user) {
      console.log('❌ User not found:', trimmedUsername);
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });
    }

    const validPassword = bcrypt.compareSync(password, user.password_hash);

    if (!validPassword) {
      console.log('❌ Invalid password for user:', trimmedUsername);
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
      'SELECT id, username, full_name, is_admin, branch, last_ten_score FROM users WHERE id = $1',
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

  const sunnahPoints = sunnahFajr ? 2 : 0;
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

    // تحدي العشر الأواخر (10 مارس - 19 مارس 2026)
    const lastTenStart = '2026-03-10';
    const lastTenEnd = '2026-03-19';
    
    if (today >= lastTenStart && today <= lastTenEnd) {
      // التحقق: سنة + جماعة معاً
      if (sunnahFajr && fajrJamaah) {
        await pool.query(
          'UPDATE users SET last_ten_score = last_ten_score + 1 WHERE id = $1 AND last_ten_score < 10',
          [userId]
        );
      }
    }

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

    // حساب أطول سلسلة
    const recordsResult = await pool.query(
      'SELECT prayer_date FROM daily_prayers WHERE user_id = $1 ORDER BY prayer_date ASC',
      [userId]
    );
    
    let longestStreak = 0;
    let currentStreak = 0;
    let previousDate = null;
    
    recordsResult.rows.forEach(row => {
      const currentDate = new Date(row.prayer_date);
      
      if (previousDate) {
        const diffDays = Math.floor((currentDate - previousDate) / (1000 * 60 * 60 * 24));
        
        if (diffDays === 1) {
          currentStreak++;
        } else {
          longestStreak = Math.max(longestStreak, currentStreak);
          currentStreak = 1;
        }
      } else {
        currentStreak = 1;
      }
      
      previousDate = currentDate;
    });
    
    longestStreak = Math.max(longestStreak, currentStreak);

    res.json({
      totalPoints: parseInt(totalResult.rows[0].total),
      rank: rank > 0 ? rank : '-',
      totalStudents: leaderboard.rows.length,
      category: userCategory,
      longestStreak: longestStreak
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
    const adminId = req.session.userId;
    
    // جلب معلومات الادمن
    const adminResult = await pool.query(
      'SELECT branch FROM users WHERE id = $1',
      [adminId]
    );
    
    const adminBranch = adminResult.rows[0]?.branch;
    
    // إذا الادمن له فرع محدد، يعرض فقط طلاب فرعه
    let query = `
      SELECT u.id, u.username, u.full_name, u.category, u.branch, u.created_at,
        COALESCE(SUM(dp.total_points), 0) as total_points,
        COUNT(dp.id) as days_count
      FROM users u
      LEFT JOIN daily_prayers dp ON u.id = dp.user_id
      WHERE u.is_admin = 0
    `;
    
    const params = [];
    
    if (adminBranch) {
      query += ' AND u.branch = $1';
      params.push(adminBranch);
    }
    
    query += `
      GROUP BY u.id
      ORDER BY total_points DESC, days_count DESC
    `;
    
    const result = await pool.query(query, params);

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
  const adminId = req.session.userId;

  try {
    // جلب فرع الادمن
    const adminResult = await pool.query(
      'SELECT branch FROM users WHERE id = $1',
      [adminId]
    );
    const adminBranch = adminResult.rows[0]?.branch;

    // جلب معلومات الطالب مع التحقق من الفرع
    let studentQuery = 'SELECT id, username, full_name, branch FROM users WHERE id = $1 AND is_admin = 0';
    const studentParams = [studentId];
    
    if (adminBranch) {
      studentQuery += ' AND branch = $2';
      studentParams.push(adminBranch);
    }
    
    const studentResult = await pool.query(studentQuery, studentParams);

    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود أو لا يمكن الوصول إليه' });
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
  const adminId = req.session.userId;
  
  try {
    // جلب فرع الادمن
    const adminResult = await pool.query(
      'SELECT branch FROM users WHERE id = $1',
      [adminId]
    );
    const adminBranch = adminResult.rows[0]?.branch;

    // التحقق من الطالب والفرع
    let checkQuery = 'SELECT id FROM users WHERE id = $1 AND is_admin = 0';
    const checkParams = [userId];
    
    if (adminBranch) {
      checkQuery += ' AND branch = $2';
      checkParams.push(adminBranch);
    }
    
    const checkResult = await pool.query(checkQuery, checkParams);
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود أو لا يمكن حذفه' });
    }
    
    // حذف سجلات الصلاة أولاً
    await pool.query('DELETE FROM daily_prayers WHERE user_id = $1', [userId]);
    
    // حذف المستخدم
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    
    res.json({ success: true, message: 'تم حذف الطالب بنجاح' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'فشل في حذف الطالب' });
  }
});

// 🔑 إعادة تعيين كلمة المرور - للمشرف فقط
app.post('/api/admin/reset-password/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const adminId = req.session.userId;
  
  try {
    // جلب فرع الادمن
    const adminResult = await pool.query(
      'SELECT branch FROM users WHERE id = $1',
      [adminId]
    );
    const adminBranch = adminResult.rows[0]?.branch;

    // التحقق أن المستخدم موجود وليس مشرف والفرع صحيح
    let userQuery = 'SELECT id, username, full_name FROM users WHERE id = $1 AND is_admin = 0';
    const userParams = [userId];
    
    if (adminBranch) {
      userQuery += ' AND branch = $2';
      userParams.push(adminBranch);
    }
    
    const userResult = await pool.query(userQuery, userParams);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'الطالب غير موجود أو لا يمكن الوصول إليه' });
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

// 📝 تسجيل صلاة بتاريخ سابق
app.post('/api/record-prayer-past', requireAuth, async (req, res) => {
  const { date, sunnahFajr, fajrJamaah, fajrOntime } = req.body;
  const userId = req.session.userId;
  const today = getBahrainDate();
  const ramadanStart = '2026-02-18'; // رمضان 1

  try {
    // التحقق: التاريخ ليس في المستقبل
    if (date > today) {
      return res.status(400).json({ error: 'لا يمكن التسجيل لتاريخ مستقبلي' });
    }
    
    // التحقق: التاريخ ليس قبل رمضان 1
    if (date < ramadanStart) {
      return res.status(400).json({ error: 'لا يمكن التسجيل قبل رمضان' });
    }
    
    // التحقق من عدم وجود تسجيل سابق
    const existing = await pool.query(
      'SELECT id FROM daily_prayers WHERE user_id = $1 AND prayer_date = $2',
      [userId, date]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'تم التسجيل مسبقاً لهذا اليوم' });
    }

    // حساب النقاط
    const sunnahPoints = sunnahFajr ? 2 : 0;
    const jamaahPoints = fajrJamaah ? 3 : 0;
    const ontimePoints = fajrOntime ? 1 : 0;
    const totalPoints = sunnahPoints + jamaahPoints + ontimePoints;

    // حفظ السجل
    await pool.query(
      'INSERT INTO daily_prayers (user_id, prayer_date, sunnah_fajr, fajr_jamaah, fajr_ontime, total_points) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, date, sunnahPoints, jamaahPoints, ontimePoints, totalPoints]
    );

    // تحدي العشر الأواخر (10 مارس - 19 مارس 2026)
    const lastTenStart = '2026-03-10';
    const lastTenEnd = '2026-03-19';
    
    if (date >= lastTenStart && date <= lastTenEnd) {
      // التحقق: سنة + جماعة معاً
      if (sunnahFajr && fajrJamaah) {
        await pool.query(
          'UPDATE users SET last_ten_score = last_ten_score + 1 WHERE id = $1 AND last_ten_score < 10',
          [userId]
        );
      }
    }

    res.json({ 
      success: true, 
      message: 'تم حفظ التسجيل بنجاح', 
      points: totalPoints 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في حفظ البيانات' });
  }
});

// 🔍 Debug: فحص تفاصيل مستخدم - للمشرف فقط
app.get('/api/admin/debug-user/:username', requireAdmin, async (req, res) => {
  const username = req.params.username;
  
  try {
    const result = await pool.query(
      `SELECT id, username, full_name, category, branch, is_admin, created_at,
       LENGTH(username) as username_length,
       LENGTH(password_hash) as password_hash_length
       FROM users WHERE username = $1`,
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.json({ 
        found: false,
        message: 'المستخدم غير موجود',
        searchedUsername: username,
        usernameLength: username.length
      });
    }
    
    const user = result.rows[0];
    
    // فحص إضافي للمسافات والأحرف الخاصة
    const hasSpaces = username.includes(' ');
    const hasTabs = username.includes('\t');
    const hasNewlines = username.includes('\n');
    const trimmedUsername = username.trim();
    const isTrimmed = username === trimmedUsername;
    
    res.json({
      found: true,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        category: user.category,
        branch: user.branch,
        is_admin: user.is_admin,
        created_at: user.created_at
      },
      debug: {
        username_length: user.username_length,
        password_hash_length: user.password_hash_length,
        has_spaces: hasSpaces,
        has_tabs: hasTabs,
        has_newlines: hasNewlines,
        is_trimmed: isTrimmed,
        username_bytes: Buffer.from(username).toString('hex')
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// 🔍 البحث عن مستخدم بالاسم الكامل - للمشرف فقط
app.get('/api/admin/find-user/:fullname', requireAdmin, async (req, res) => {
  const fullname = req.params.fullname;
  
  try {
    const result = await pool.query(
      `SELECT id, username, full_name, category, branch 
       FROM users 
       WHERE full_name ILIKE $1 
       ORDER BY id DESC 
       LIMIT 10`,
      [`%${fullname}%`]
    );
    
    res.json({
      found: result.rows.length > 0,
      count: result.rows.length,
      users: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// 🏆 ترتيب تحدي العشر الأواخر - للمشرف فقط
app.get('/api/admin/last-ten-leaderboard', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, full_name, username, category, branch, last_ten_score
      FROM users
      WHERE is_admin = 0 AND last_ten_score > 0
      ORDER BY last_ten_score DESC, full_name ASC
      LIMIT 50
    `);
    
    res.json({
      success: true,
      leaderboard: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// 📅 الحصول على الأيام المسجلة للطالب
app.get('/api/my-recorded-days', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  
  try {
    const result = await pool.query(
      'SELECT prayer_date FROM daily_prayers WHERE user_id = $1 ORDER BY prayer_date',
      [userId]
    );
    
    // تحويل التواريخ إلى strings
    const recordedDates = result.rows.map(row => 
      row.prayer_date.toISOString().split('T')[0]
    );
    
    res.json({
      success: true,
      recordedDates: recordedDates
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// ✏️ تعديل سجل يوم معين - للمشرف فقط
app.post('/api/admin/update-day-record', requireAdmin, async (req, res) => {
  const { userId, date, sunnahFajr, fajrJamaah, fajrOntime } = req.body;
  const adminBranch = req.session.adminBranch;

  try {
    // التحقق من صلاحيات المشرف (إذا كان مشرف فرع)
    if (adminBranch) {
      const userCheck = await pool.query(
        'SELECT branch FROM users WHERE id = $1',
        [userId]
      );
      
      if (userCheck.rows.length === 0) {
        return res.status(404).json({ error: 'الطالب غير موجود' });
      }
      
      if (userCheck.rows[0].branch !== adminBranch) {
        return res.status(403).json({ error: 'لا يمكنك تعديل طلاب من فرع آخر' });
      }
    }

    // حساب النقاط الجديدة
    const sunnahPoints = sunnahFajr ? 2 : 0;
    const jamaahPoints = fajrJamaah ? 3 : 0;
    const ontimePoints = fajrOntime ? 1 : 0;
    const totalPoints = sunnahPoints + jamaahPoints + ontimePoints;

    // تحديث السجل
    const result = await pool.query(
      `UPDATE daily_prayers 
       SET sunnah_fajr = $1, fajr_jamaah = $2, fajr_ontime = $3, total_points = $4
       WHERE user_id = $5 AND prayer_date = $6
       RETURNING *`,
      [sunnahPoints, jamaahPoints, ontimePoints, totalPoints, userId, date]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'السجل غير موجود' });
    }

    // إعادة حساب last_ten_score
    const lastTenStart = '2026-03-10';
    const lastTenEnd = '2026-03-19';
    
    if (date >= lastTenStart && date <= lastTenEnd) {
      // حساب عدد الأيام اللي فيها سنة + جماعة
      const countResult = await pool.query(
        `SELECT COUNT(*) as count 
         FROM daily_prayers 
         WHERE user_id = $1 
         AND prayer_date >= $2 
         AND prayer_date <= $3
         AND sunnah_fajr > 0 
         AND fajr_jamaah > 0`,
        [userId, lastTenStart, lastTenEnd]
      );
      
      const newScore = Math.min(parseInt(countResult.rows[0].count), 10);
      
      await pool.query(
        'UPDATE users SET last_ten_score = $1 WHERE id = $2',
        [newScore, userId]
      );
    }

    res.json({
      success: true,
      message: 'تم التحديث بنجاح',
      newPoints: totalPoints
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'خطأ في السيرفر' });
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