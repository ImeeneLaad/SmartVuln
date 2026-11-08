// Test cases for smartvuln-raw-sql-interpolation (semgrep --test format)
function vulnerable (req: any, models: any, db: any, pool: any) {
  // ruleid: smartvuln-raw-sql-interpolation
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
  // ruleid: smartvuln-raw-sql-interpolation
  sequelize.query("SELECT * FROM Products WHERE name LIKE '%" + req.query.q + "%'")
  // ruleid: smartvuln-raw-sql-interpolation
  db.prepare(`SELECT id, name FROM products WHERE name LIKE '%${req.query.q}%'`).all()
  // ruleid: smartvuln-raw-sql-interpolation
  pool.query('DELETE FROM sessions WHERE id = ' + req.params.id)
}

function safe (req: any, models: any, db: any, elastic: any) {
  // ok: smartvuln-raw-sql-interpolation
  models.sequelize.query('SELECT * FROM Users WHERE email = :email', { replacements: { email: req.body.email } })
  // ok: smartvuln-raw-sql-interpolation
  db.prepare('SELECT id, name FROM products WHERE name LIKE ?').all(`%${req.query.q}%`)
  // ok: smartvuln-raw-sql-interpolation
  models.sequelize.query('SELECT sql FROM sqlite_master')
  // ok: smartvuln-raw-sql-interpolation
  elastic.query(`match ${req.query.q}`)
}
