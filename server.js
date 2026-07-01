const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'maido-oa-secret-2026-' + crypto.randomBytes(8).toString('hex');

// ============ Simple JWT implementation (no jsonwebtoken dependency) ============
function base64url(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}
function createJWT(payload, expiresIn) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const exp = Date.now() + parseExpiry(expiresIn);
  const body = base64url(JSON.stringify({ ...payload, exp }));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return header + '.' + body + '.' + sig;
}
function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(parts[0] + '.' + parts[1]).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (sig !== parts[2]) return null;
    const payload = JSON.parse(base64urlDecode(parts[1]));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) { return null; }
}
function parseExpiry(str) {
  if (str.endsWith('d')) return parseInt(str) * 86400000;
  if (str.endsWith('h')) return parseInt(str) * 3600000;
  return 86400000 * 30; // default 30 days
}

// ============ Simple bcrypt-like hash (using crypto.pbkdf2) ============
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === check;
}

// ============ Middleware ============
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ============ File Storage Helpers ============
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

function readJSON(filepath, fallback) {
  try {
    if (fs.existsSync(filepath)) return JSON.parse(fs.readFileSync(filepath, 'utf8'));
  } catch (e) { console.error('Read error:', filepath, e.message); }
  return fallback;
}
function writeJSON(filepath, data) {
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf8');
}

// ============ Database files ============
const usersFile = path.join(dataDir, 'users.json');
const appDataFile = path.join(dataDir, 'appdata.json');
const knowledgeFile = path.join(dataDir, 'knowledge.json');
const reportsFile = path.join(dataDir, 'reports.json');

// Initialize users
let users = readJSON(usersFile, null);
if (!users) {
  users = {
    admin: { password: hashPassword('admin123'), role: 'master', parent: null, created_at: new Date().toISOString() }
  };
  writeJSON(usersFile, users);
  console.log('✅ Created default master account: admin / admin123');
}

// Initialize app data
let appData = readJSON(appDataFile, null);
if (!appData) {
  appData = {
    tasks: [
      { id: 1, name: "每日站会组织", content: "组织团队每日站会，同步工作进展", frequency: "每日", category: "团队管理" },
      { id: 2, name: "日报提交", content: "提交当日工作日报", frequency: "每日", category: "日常管理" },
      { id: 3, name: "客户数据更新", content: "更新客户跟进数据和状态", frequency: "每日", category: "客户管理" },
      { id: 4, name: "周报撰写", content: "撰写本周工作总结和下周计划", frequency: "每周", category: "日常管理" },
      { id: 5, name: "项目进度同步", content: "与项目经理同步项目进度", frequency: "每周", category: "项目对接" },
      { id: 6, name: "月度数据分析", content: "分析本月业务数据，产出分析报告", frequency: "每月", category: "数据管理" },
      { id: 7, name: "月度培训计划", content: "制定并执行月度培训计划", frequency: "每月", category: "团队建设" },
      { id: 8, name: "季度绩效评估", content: "完成团队成员季度绩效评估", frequency: "季度", category: "团队管理" },
      { id: 9, name: "季度业务复盘", content: "复盘季度业务目标达成情况", frequency: "季度", category: "项目管理" },
      { id: 10, name: "年度工作总结", content: "撰写年度工作总结和来年规划", frequency: "年度", category: "日常管理" },
      { id: 11, name: "每日邮件处理", content: "处理当日重要邮件和消息", frequency: "每日", category: "日常管理" },
      { id: 12, name: "客户需求跟进", content: "跟进客户新需求和反馈", frequency: "每日", category: "客户管理" },
      { id: 13, name: "周报汇总", content: "汇总组员周报，提交上级", frequency: "每周", category: "团队管理" },
      { id: 14, name: "跨部门协调会", content: "参加跨部门协调会议", frequency: "每周", category: "项目对接" },
      { id: 15, name: "月度预算审核", content: "审核部门月度预算执行情况", frequency: "每月", category: "数据管理" },
      { id: 16, name: "周初计划制定", content: "每周初制定本周工作计划", frequency: "周初", category: "日常管理" },
      { id: 17, name: "月初排班计划制定", content: "每月初制定组内排班计划", frequency: "月初", category: "团队管理" },
      { id: 18, name: "月度工作总结与计划", content: "每月底总结本月工作，制定下月计划", frequency: "月底", category: "日常管理" },
      { id: 19, name: "月度培训组织", content: "每月至少组织一次组内培训", frequency: "每月", category: "团队建设" },
      { id: 20, name: "月度团队氛围建设", content: "每月至少一次团队活动或关怀", frequency: "每月", category: "团队建设" }
    ],
    categories: ["客户管理", "数据管理", "项目对接", "团队建设", "日常运营"],
    completions: {},
    qcColumns: ["日期", "项目", "客服", "在线时长", "接待量", "转化率", "备注"],
    qcData: [],
    qcProjects: ["项目A", "项目B", "项目C"],
    assignedTasks: [],
    exemptions: {},
    selfTasks: [],
    leaderCreatedTasks: [],
    completionImages: {},
    knowledgeBase: [],
    reports: []
  };
  writeJSON(appDataFile, appData);
  console.log('✅ Initialized default app data');
}

// Initialize knowledge and reports
let knowledgeFiles = readJSON(knowledgeFile, []);
let reports = readJSON(reportsFile, []);

// ============ Simple multipart parser ============
function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('multipart/form-data')) return resolve(null);

    const boundary = contentType.split('boundary=')[1];
    if (!boundary) return resolve(null);

    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const boundaryBuf = Buffer.from('--' + boundary);
      const parts = [];
      let start = 0;

      while (true) {
        const idx = buf.indexOf(boundaryBuf, start);
        if (idx === -1) break;
        if (start > 0) {
          const partData = buf.slice(start, idx);
          const headerEnd = partData.indexOf('\r\n\r\n');
          if (headerEnd !== -1) {
            const headers = partData.slice(0, headerEnd).toString('utf8');
            let body = partData.slice(headerEnd + 4);
            if (body.length >= 2 && body[body.length - 2] === 13 && body[body.length - 1] === 10) {
              body = body.slice(0, -2);
            }
            const nameMatch = headers.match(/name="([^"]+)"/);
            const filenameMatch = headers.match(/filename="([^"]+)"/);
            const ctMatch = headers.match(/Content-Type:\s*(.+)/i);
            parts.push({
              name: nameMatch ? nameMatch[1] : '',
              filename: filenameMatch ? filenameMatch[1] : null,
              contentType: ctMatch ? ctMatch[1].trim() : null,
              data: body
            });
          }
        }
        start = idx + boundaryBuf.length;
        if (buf.slice(start, start + 2).toString() === '--') break;
        if (buf[start] === 13) start++;
        if (buf[start] === 10) start++;
      }
      resolve(parts);
    });
    req.on('error', reject);
  });
}

// ============ Auth Middleware ============
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: '未授权，请先登录' });

  const token = authHeader.replace('Bearer ', '');
  const decoded = verifyJWT(token);
  if (!decoded) return res.status(401).json({ error: '登录已过期，请重新登录' });

  req.user = decoded;
  next();
}

// ============ Serve Frontend ============
const htmlPath = path.join(__dirname, 'management_system_v9.html');
app.get('/', (req, res) => {
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.status(404).send('Frontend not found. Please ensure management_system_v9.html exists in the same directory.');
  }
});

// Serve uploaded files
app.use('/uploads', express.static(uploadsDir));

// ============ Auth Routes ============
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });

  const user = users[username];
  if (!user) return res.status(401).json({ error: '用户不存在，请联系管理员创建账号' });

  if (!verifyPassword(password, user.password)) {
    return res.status(401).json({ error: '密码错误' });
  }

  const token = createJWT({ username, role: user.role }, '30d');
  res.json({ token, user: { username, role: user.role, parent: user.parent } });
});

app.post('/api/auth/register', authMiddleware, (req, res) => {
  const { username, password, role, parent } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

  if (role === 'master') return res.status(403).json({ error: '不能创建主账号' });
  if (role === 'manager' && req.user.role !== 'master') {
    return res.status(403).json({ error: '只有主账号可以创建主管账号' });
  }

  if (users[username]) return res.status(400).json({ error: '用户名已存在' });

  users[username] = {
    password: hashPassword(password),
    role: role || 'leader',
    parent: parent || null,
    created_at: new Date().toISOString()
  };
  writeJSON(usersFile, users);
  res.json({ success: true, message: '用户 ' + username + ' 创建成功' });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = users[req.user.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({
    username: req.user.username,
    role: user.role,
    parent: user.parent,
    created_at: user.created_at
  });
});

// ============ User Management ============
app.get('/api/users', authMiddleware, (req, res) => {
  const result = {};
  for (const [uname, info] of Object.entries(users)) {
    result[uname] = { password: '', role: info.role, parent: info.parent, created_at: info.created_at };
  }
  res.json(result);
});

app.post('/api/users', authMiddleware, (req, res) => {
  const { username, password, role, parent } = req.body;
  if (req.user.role !== 'master' && req.user.role !== 'manager') {
    return res.status(403).json({ error: '权限不足' });
  }

  if (users[username]) {
    // Update
    if (password) users[username].password = hashPassword(password);
    if (role) users[username].role = role;
    if (parent !== undefined) users[username].parent = parent;
    writeJSON(usersFile, users);
    res.json({ success: true, message: '用户 ' + username + ' 已更新' });
  } else {
    // Create
    if (!password) return res.status(400).json({ error: '新用户必须设置密码' });
    if (role === 'master') return res.status(403).json({ error: '不能创建主账号' });
    if (role === 'manager' && req.user.role !== 'master') {
      return res.status(403).json({ error: '只有主账号可以创建主管账号' });
    }
    users[username] = {
      password: hashPassword(password),
      role: role || 'leader',
      parent: parent || null,
      created_at: new Date().toISOString()
    };
    writeJSON(usersFile, users);
    res.json({ success: true, message: '用户 ' + username + ' 创建成功' });
  }
});

app.delete('/api/users/:username', authMiddleware, (req, res) => {
  const { username } = req.params;
  if (username === req.user.username) return res.status(400).json({ error: '不能删除自己' });
  if (username === 'admin') return res.status(403).json({ error: '不能删除默认管理员' });
  if (!users[username]) return res.status(404).json({ error: '用户不存在' });

  delete users[username];
  writeJSON(usersFile, users);
  res.json({ success: true, message: '用户 ' + username + ' 已删除' });
});

// ============ App Data ============
app.get('/api/data', authMiddleware, (req, res) => {
  res.json(appData);
});

app.put('/api/data', authMiddleware, (req, res) => {
  appData = req.body;
  writeJSON(appDataFile, appData);
  res.json({ success: true });
});

// ============ Knowledge Base ============
app.get('/api/knowledge', authMiddleware, (req, res) => {
  res.json(knowledgeFiles);
});

app.post('/api/knowledge/upload', authMiddleware, async (req, res) => {
  try {
    const parts = await parseMultipart(req);
    if (!parts || parts.length === 0) return res.status(400).json({ error: '未选择文件' });

    const filePart = parts.find(p => p.filename);
    if (!filePart) return res.status(400).json({ error: '未选择文件' });

    const id = 'kb_' + crypto.randomUUID().replace(/-/g, '').substring(0, 12);
    const ext = path.extname(filePart.filename).replace('.', '').toLowerCase();
    const storedName = id + (ext ? '.' + ext : '');

    fs.writeFileSync(path.join(uploadsDir, storedName), filePart.data);

    const fileInfo = {
      id,
      name: filePart.filename,
      size: filePart.data.length,
      type: ext,
      filepath: storedName,
      uploaded_by: req.user.username,
      uploaded_at: new Date().toISOString()
    };

    knowledgeFiles.push(fileInfo);
    writeJSON(knowledgeFile, knowledgeFiles);
    res.json(fileInfo);
  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ error: '上传失败: ' + e.message });
  }
});

app.get('/api/knowledge/:id/download', authMiddleware, (req, res) => {
  const file = knowledgeFiles.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: '文件不存在' });

  const filepath = path.join(uploadsDir, file.filepath);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: '文件已丢失' });

  res.download(filepath, file.name);
});

app.delete('/api/knowledge/:id', authMiddleware, (req, res) => {
  const idx = knowledgeFiles.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: '文件不存在' });

  const file = knowledgeFiles[idx];
  const filepath = path.join(uploadsDir, file.filepath);
  if (fs.existsSync(filepath)) fs.unlinkSync(filepath);

  knowledgeFiles.splice(idx, 1);
  writeJSON(knowledgeFile, knowledgeFiles);
  res.json({ success: true });
});

app.put('/api/knowledge/:id/content', authMiddleware, async (req, res) => {
  try {
    const file = knowledgeFiles.find(f => f.id === req.params.id);
    if (!file) return res.status(404).json({ error: '文件不存在' });

    const parts = await parseMultipart(req);
    if (!parts || !parts.find(p => p.filename)) return res.status(400).json({ error: '未上传文件' });

    const filePart = parts.find(p => p.filename);
    const ext = path.extname(filePart.filename).replace('.', '').toLowerCase();

    // Delete old file
    const oldPath = path.join(uploadsDir, file.filepath);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);

    // Save new file
    const storedName = file.id + (ext ? '.' + ext : '');
    fs.writeFileSync(path.join(uploadsDir, storedName), filePart.data);

    file.filepath = storedName;
    file.name = filePart.filename;
    file.size = filePart.data.length;
    file.uploaded_at = new Date().toISOString();
    writeJSON(knowledgeFile, knowledgeFiles);

    res.json({ success: true });
  } catch (e) {
    console.error('Update error:', e);
    res.status(500).json({ error: '更新失败: ' + e.message });
  }
});

// ============ Reports ============
app.get('/api/reports', authMiddleware, (req, res) => {
  res.json(reports);
});

app.post('/api/reports', authMiddleware, (req, res) => {
  const { type, title, content } = req.body;
  if (!type || !title) return res.status(400).json({ error: '类型和标题不能为空' });

  const id = 'rpt_' + crypto.randomUUID().replace(/-/g, '').substring(0, 12);
  const report = {
    id, type, title,
    content: content || '',
    author: req.user.username,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    sent_to: []
  };

  reports.push(report);
  writeJSON(reportsFile, reports);
  res.json(report);
});

app.put('/api/reports/:id', authMiddleware, (req, res) => {
  const report = reports.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: '报表不存在' });

  const { title, content, sent_to } = req.body;
  if (title) report.title = title;
  if (content !== undefined) report.content = content;
  if (sent_to) report.sent_to = sent_to;
  report.updated_at = new Date().toISOString();

  writeJSON(reportsFile, reports);
  res.json({ success: true });
});

app.delete('/api/reports/:id', authMiddleware, (req, res) => {
  const idx = reports.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: '报表不存在' });

  reports.splice(idx, 1);
  writeJSON(reportsFile, reports);
  res.json({ success: true });
});

// ============ Data Migration ============
app.post('/api/migrate', authMiddleware, (req, res) => {
  const { users: migUsers, data: migData } = req.body;

  if (migUsers) {
    for (const [uname, info] of Object.entries(migUsers)) {
      if (users[uname]) continue; // skip existing
      if (typeof info === 'string') {
        users[uname] = { password: hashPassword(info), role: 'leader', parent: null, created_at: new Date().toISOString() };
      } else {
        users[uname] = {
          password: hashPassword(info.password || 'default123'),
          role: info.role || 'leader',
          parent: info.parent || null,
          created_at: new Date().toISOString()
        };
      }
    }
    writeJSON(usersFile, users);
  }

  if (migData) {
    appData = migData;
    writeJSON(appDataFile, appData);
  }

  res.json({ success: true, message: '数据迁移完成' });
});

// ============ Health Check ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), version: 'v9.1-pure' });
});

// ============ Start Server ============
app.listen(PORT, () => {
  console.log('');
  console.log('========================================');
  console.log('  麦多OA管理系统 v9.1 (纯JS后端版)');
  console.log('========================================');
  console.log('  访问地址: http://localhost:' + PORT);
  console.log('  API地址:  http://localhost:' + PORT + '/api');
  console.log('  默认账号: admin / admin123');
  console.log('========================================');
  console.log('  数据存储: ' + dataDir);
  console.log('  文件上传: ' + uploadsDir);
  console.log('========================================');
  console.log('');
});
