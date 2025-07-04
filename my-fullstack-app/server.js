const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 数据库连接 ---
// 通过环境变量获取数据库连接URL，这是在云平台部署的最佳实践
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // 在某些云平台上需要此配置
  }
});

// --- 中间件 ---
app.use(express.json()); // 解析请求体中的JSON数据
app.use(express.static('public')); // 托管前端静态文件（public文件夹）

// --- 数据库初始化 ---
// 应用启动时，自动检查并创建users表
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(100) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('数据库 "users" 表已准备就绪。');
  } catch (err) {
    console.error('数据库初始化失败:', err);
  } finally {
    client.release();
  }
}

// --- API 路由 ---

// 注册接口
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: '用户名和密码不能为空' });
  }

  try {
    // 使用 bcrypt 对密码进行哈希加密，10是加密强度
    const passwordHash = await bcrypt.hash(password, 10);
    
    // 将新用户信息存入数据库
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, passwordHash]
    );

    res.status(201).json({ message: '注册成功', user: result.rows[0] });
  } catch (err) {
    // 捕获因用户名重复（UNIQUE约束）等原因造成的错误
    if (err.code === '23505') {
      return res.status(409).json({ message: '用户名已存在' });
    }
    console.error(err);
    res.status(500).json({ message: '服务器内部错误' });
  }
});

// 登录接口
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: '用户名和密码不能为空' });
  }

  try {
    // 从数据库中查找用户
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: '用户名或密码错误' });
    }

    // 使用 bcrypt.compare 比较用户输入的密码和数据库中存储的哈希密码
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (isMatch) {
      res.status(200).json({ message: '登录成功' }); // 实际项目中会返回一个JWT Token
    } else {
      res.status(401).json({ message: '用户名或密码错误' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '服务器内部错误' });
  }
});


// --- 启动服务器 ---
app.listen(PORT, () => {
  console.log(`服务器正在端口 ${PORT} 上运行...`);
  initializeDatabase(); // 启动时初始化数据库
});