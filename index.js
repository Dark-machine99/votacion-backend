import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { pool } from "./db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecreto";

// ================================================
//                   MIDDLEWARES
// ================================================
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json());

// ================================================
//                   HELPERS
// ================================================
function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "Token requerido" });

  const token = authHeader.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "No autorizado" });
  }
  next();
}

async function logAudit(userId, action, description) {
  try {
    await pool.query(
      "INSERT INTO audit_log (user_id, action, description, created_at) VALUES (?, ?, ?, NOW())",
      [userId || null, action, description]
    );
  } catch (err) {
    console.error("Audit log error:", err);
  }
}

// ================================================
//                       RUTAS
// ================================================
app.get("/", (req, res) => {
  res.json({ message: "API Sistema de Votación funcionando" });
});

/* =====================================================
                      AUTH
===================================================== */

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash, role, active FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    if (rows.length === 0)
      return res.status(400).json({ message: "Credenciales incorrectas" });

    const user = rows[0];

    if (!user.active)
      return res.status(403).json({ message: "Usuario inactivo" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(400).json({ message: "Credenciales incorrectas" });

    const token = createToken(user);
    await logAudit(user.id, "LOGIN", `Inicio de sesión de ${user.email}`);

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// REGISTRO VOTANTE
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const [exist] = await pool.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    if (exist.length > 0)
      return res.status(400).json({ message: "El correo ya está registrado" });

    const hash = await bcrypt.hash(password, 12);

    const [result] = await pool.query(
      "INSERT INTO users (name, email, password_hash, role, active, created_at) VALUES (?, ?, ?, 'voter', 1, NOW())",
      [name, email, hash]
    );

    await logAudit(result.insertId, "USUARIO_CREADO", `Nuevo votante: ${email}`);

    res.json({ message: "Usuario creado correctamente" });
  } catch (err) {
    console.error("Error registrando usuario:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// CREAR ADMIN
app.post("/api/admin/create-admin", authRequired, adminOnly, async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const [exist] = await pool.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    if (exist.length > 0)
      return res.status(400).json({ message: "El correo ya existe" });

    const hash = await bcrypt.hash(password, 12);

    const [result] = await pool.query(
      "INSERT INTO users (name, email, password_hash, role, active, created_at) VALUES (?, ?, ?, 'admin', 1, NOW())",
      [name, email, hash]
    );

    await logAudit(req.user.id, "ADMIN_CREADO", `Admin creado: ${email}`);

    res.json({ message: "Administrador creado", id: result.insertId });
  } catch (err) {
    console.error("Error creando admin:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

/* =====================================================
                    VOTANTE
===================================================== */

// LISTA DE ELECCIONES
app.get("/api/voter/elections", authRequired, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, title, description, start_date, end_date, status 
       FROM elections ORDER BY start_date ASC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// DETALLE ELECCIÓN
app.get("/api/voter/elections/:id", authRequired, async (req, res) => {
  const { id } = req.params;

  try {
    const [[election]] = await pool.query(
      "SELECT * FROM elections WHERE id = ?",
      [id]
    );

    if (!election)
      return res.status(404).json({ message: "Elección no encontrada" });

    const [candidates] = await pool.query(
      "SELECT * FROM candidates WHERE election_id = ?",
      [id]
    );

    res.json({ election, candidates });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// VOTAR
app.post("/api/voter/elections/:id/vote", authRequired, async (req, res) => {
  const { id } = req.params;          // election_id
  const { candidateId } = req.body;
  const userId = req.user.id;

  try {
    // Evitar doble voto
    const [exists] = await pool.query(
      "SELECT id FROM votes WHERE user_id = ? AND election_id = ?",
      [userId, id]
    );

    if (exists.length > 0)
      return res.status(400).json({ message: "Ya votaste en esta elección" });

    await pool.query(
      "INSERT INTO votes (user_id, election_id, candidate_id, created_at) VALUES (?, ?, ?, NOW())",
      [userId, id, candidateId]
    );

    await logAudit(userId, "VOTO_EMITIDO", `Voto en elección ${id}`);

    res.json({ message: "Voto registrado correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// HISTORIAL
app.get("/api/voter/history", authRequired, async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await pool.query(
      `SELECT 
        v.id, e.title, e.description, v.created_at, c.name AS candidate
       FROM votes v
       JOIN elections e ON v.election_id = e.id
       JOIN candidates c ON v.candidate_id = c.id
       WHERE v.user_id = ?
       ORDER BY v.created_at DESC`,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

/* =====================================================
                    ADMINISTRADOR
===================================================== */

// DASHBOARD
app.get("/api/admin/dashboard", authRequired, adminOnly, async (_req, res) => {
  try {
    const [[users]] = await pool.query("SELECT COUNT(*) AS total_users FROM users");
    const [[elections]] = await pool.query("SELECT COUNT(*) AS total_elections FROM elections");
    const [[votes]] = await pool.query("SELECT COUNT(*) AS total_votes FROM votes");

    const [[participation]] = await pool.query(
      `SELECT 
       (SELECT COUNT(DISTINCT user_id) FROM votes) /
       GREATEST((SELECT COUNT(*) FROM users WHERE role='voter'),1) * 100 AS participation`
    );

    res.json({
      totalUsers: users.total_users,
      totalElections: elections.total_elections,
      totalVotes: votes.total_votes,
      participation: participation.participation || 0,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// LISTAR ELECCIONES
app.get("/api/admin/elections", authRequired, adminOnly, async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM elections ORDER BY start_date DESC");
    res.json(rows);
  } catch (err) {
    console.error(err);
  }
});

// CREAR ELECCIÓN
app.post("/api/admin/elections/create", authRequired, adminOnly, async (req, res) => {
  try {
    const { title, description, start_date, end_date, status } = req.body;

    const allowed = ["Activa", "Programada", "Finalizada"];
    if (!allowed.includes(status))
      return res.status(400).json({ message: "Estado inválido" });

    const [result] = await pool.query(
      "INSERT INTO elections (title, description, start_date, end_date, status, created_at) VALUES (?, ?, ?, ?, ?, NOW())",
      [title, description, start_date, end_date, status]
    );

    await logAudit(req.user.id, "ELECTION_CREATE", `Elección ${title}`);

    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// COMPATIBILIDAD
app.post("/api/admin/elections", authRequired, adminOnly, (req, res, next) => {
  req.url = "/api/admin/elections/create";
  next();
});

// EDITAR ELECCIÓN
app.put("/api/admin/elections/update/:id", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;

  const { title, description, start_date, end_date, status } = req.body;

  const allowed = ["Activa", "Programada", "Finalizada"];

  if (status && !allowed.includes(status))
    return res.status(400).json({ message: "Estado inválido" });

  try {
    await pool.query(
      "UPDATE elections SET title=?, description=?, start_date=?, end_date=?, status=? WHERE id=?",
      [title, description, start_date, end_date, status, id]
    );

    await logAudit(req.user.id, "ELECTION_UPDATE", `Elección #${id}`);

    res.json({ message: "Actualizado correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ELIMINAR ELECCIÓN
app.delete("/api/admin/elections/delete/:id", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM elections WHERE id=?", [id]);

    await logAudit(req.user.id, "ELECTION_DELETE", `Elección eliminada #${id}`);

    res.json({ message: "Elección eliminada" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// LISTAR CANDIDATOS
app.get("/api/admin/candidates", authRequired, adminOnly, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.*, e.title AS election_title
       FROM candidates c
       LEFT JOIN elections e ON c.election_id = e.id
       ORDER BY c.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
  }
});

// CREAR CANDIDATO
app.post("/api/admin/candidates/create", authRequired, adminOnly, async (req, res) => {
  const { election_id, name, party, bio, photo_url } = req.body;

  try {
    const [result] = await pool.query(
      "INSERT INTO candidates (election_id, name, party, bio, photo_url, created_at) VALUES (?, ?, ?, ?, ?, NOW())",
      [election_id, name, party, bio, photo_url]
    );

    await logAudit(req.user.id, "CANDIDATE_CREATE", `Candidato ${name}`);

    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// EDITAR CANDIDATO
app.put("/api/admin/candidates/update/:id", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { election_id, name, party, bio, photo_url } = req.body;

  try {
    await pool.query(
      "UPDATE candidates SET election_id=?, name=?, party=?, bio=?, photo_url=? WHERE id=?",
      [election_id, name, party, bio, photo_url, id]
    );

    await logAudit(req.user.id, "CANDIDATE_UPDATE", `Candidato #${id}`);

    res.json({ message: "Candidato actualizado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ELIMINAR CANDIDATO
app.delete("/api/admin/candidates/delete/:id", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM candidates WHERE id=?", [id]);

    await logAudit(req.user.id, "CANDIDATE_DELETE", `Candidato eliminado #${id}`);

    res.json({ message: "Eliminado correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// LISTA DE USUARIOS
app.get("/api/admin/users", authRequired, adminOnly, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, role, active FROM users"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
  }
});

// ACTIVAR / DESACTIVAR USER
app.patch("/api/admin/users/:id/status", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  try {
    await pool.query("UPDATE users SET active=? WHERE id=?", [
      active ? 1 : 0,
      id,
    ]);

    await logAudit(
      req.user.id,
      "USER_STATUS",
      `Usuario #${id} -> ${active ? "Activo" : "Inactivo"}`
    );

    res.json({ message: "Estado actualizado" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// AUDITORÍA
app.get("/api/admin/audit", authRequired, adminOnly, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT a.id, a.action, a.description, a.created_at, u.name AS user_name
       FROM audit_log a
       LEFT JOIN users u ON a.user_id = u.id
       ORDER BY a.created_at DESC
       LIMIT 200`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
  }
});

// ================================================
//                   SERVER START
// ================================================
app.listen(PORT, () => {
  console.log(`Servidor backend escuchando en http://localhost:${PORT}`);
});
