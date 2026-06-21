const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const pool = require('../db/pool');
const { requireAdmin } = require('../middleware/auth');

router.use(requireAdmin);

// GET /admin
router.get('/', async (req, res) => {
  try {
    const [usersR, projectsR, tasksR, membersR] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM projects'),
      pool.query('SELECT COUNT(*) FROM tasks'),
      pool.query('SELECT COUNT(*) FROM project_members WHERE status = $1', ['active'])
    ]);
    const stats = {
      users: parseInt(usersR.rows[0].count),
      projects: parseInt(projectsR.rows[0].count),
      tasks: parseInt(tasksR.rows[0].count),
      members: parseInt(membersR.rows[0].count)
    };
    const users = await pool.query(
      'SELECT id, username, display_name, email, role, is_active, avatar_color, plan, created_at FROM users ORDER BY created_at DESC'
    );
    const projects = await pool.query(
      `SELECT p.*, u.display_name AS owner_name, 
       (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = p.id AND pm.status = 'active') AS member_count
       FROM projects p LEFT JOIN users u ON u.id = p.owner_id ORDER BY p.created_at DESC LIMIT 20`
    );
    res.render('admin/index', {
      title: 'Quản trị hệ thống',
      stats,
      users: users.rows,
      projects: projects.rows,
      flash: req.query.flash || null,
      flashType: req.query.type || 'success'
    });
  } catch (err) {
    console.error(err);
    res.render('error', { title: 'Lỗi', message: err.message, code: 500 });
  }
});

// POST /admin/users/:id/toggle - Toggle user active status
router.post('/users/:id/toggle', async (req, res) => {
  const uid = parseInt(req.params.id);
  if (uid === req.session.userId) return res.redirect('/admin?flash=Không+thể+vô+hiệu+hóa+chính+mình&type=error');
  await pool.query('UPDATE users SET is_active = NOT is_active WHERE id = $1', [uid]);
  res.redirect('/admin?flash=Cập+nhật+trạng+thái+thành+công&type=success');
});

// POST /admin/users/:id/toggle-plan - Toggle user plan free/pro
router.post('/users/:id/toggle-plan', async (req, res) => {
  const uid = parseInt(req.params.id);
  const cur = await pool.query('SELECT plan FROM users WHERE id=$1', [uid]);
  const newPlan = cur.rows[0]?.plan === 'pro' ? 'free' : 'pro';
  await pool.query('UPDATE users SET plan=$1 WHERE id=$2', [newPlan, uid]);
  res.redirect('/admin?flash=Đã+cập+nhật+gói+người+dùng&type=success');
});

// POST /admin/users/:id/delete - Delete user
router.post('/users/:id/delete', async (req, res) => {
  const uid = parseInt(req.params.id);
  if (uid === req.session.userId) return res.redirect('/admin?flash=Không+thể+xóa+chính+mình&type=error');
  await pool.query('DELETE FROM users WHERE id = $1 AND role != $2', [uid, 'admin']);
  res.redirect('/admin?flash=Đã+xóa+người+dùng&type=success');
});

// POST /admin/users/create - Create user directly
router.post('/users/create', async (req, res) => {
  const { username, password, display_name, role } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, display_name, role) VALUES ($1, $2, $3, $4)',
      [username.trim(), hash, display_name.trim(), role || 'user']
    );
    res.redirect('/admin?flash=Tạo+tài+khoản+thành+công&type=success');
  } catch (err) {
    res.redirect('/admin?flash=Lỗi+tạo+tài+khoản&type=error');
  }
});

// POST /admin/projects/:id/delete
router.post('/projects/:id/delete', async (req, res) => {
  await pool.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
  res.redirect('/admin?flash=Đã+xóa+dự+án&type=success');
});

// POST /admin/users/:id/change-password - Admin đổi mật khẩu cho tài khoản bất kỳ
router.post('/users/:id/change-password', async (req, res) => {
  const uid = parseInt(req.params.id);
  const { new_password, confirm_new_password } = req.body;
  if (!new_password || new_password.length < 6) {
    return res.redirect('/admin?flash=Mật+khẩu+phải+có+ít+nhất+6+ký+tự&type=error');
  }
  if (new_password !== confirm_new_password) {
    return res.redirect('/admin?flash=Mật+khẩu+xác+nhận+không+khớp&type=error');
  }
  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, uid]);
    res.redirect('/admin?flash=Đã+đổi+mật+khẩu+thành+công&type=success');
  } catch (err) {
    console.error(err);
    res.redirect('/admin?flash=Lỗi+server&type=error');
  }
});

module.exports = router;
