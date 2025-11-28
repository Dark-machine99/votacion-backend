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

// Middlewares
app.use(cors({
  origin: "http://localhost:5173", // Vite por defecto
  credentials: true,
}));
app.use(express.json());

// Utilidad: crear token
function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

// Middleware de auth
function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Token requerido" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Token inválido" });
  }
}

// Middleware para admins
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "No autorizado" });
  }
  next();
}

// ================== RUTAS ==================

// Ping
app.get("/", (req, res) => {
  res.json({ message: "API Sistema de Votación funcionando" });
});

// ---------- Auth ----------
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash, role, active FROM users WHERE email = ? LIMIT 1",
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: "Credenciales incorrectas" });
    }

    const user = rows[0];

    if (!user.active) {
      return res.status(403).json({ message: "Usuario inactivo" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: "Credenciales incorrectas" });
    }

    const token = createToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ---------- Votante: elecciones disponibles ----------
app.get("/api/voter/elections", authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT e.id, e.title, e.description, e.start_date, e.end_date, e.status
       FROM elections e
       ORDER BY e.start_date ASC`
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo elecciones:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Detalle de una elección + candidatos
app.get("/api/voter/elections/:id", authRequired, async (req, res) => {
  const { id } = req.params;
  try {
    const [[election]] = await pool.query(
      "SELECT * FROM elections WHERE id = ?",
      [id]
    );
    if (!election) {
      return res.status(404).json({ message: "Elección no encontrada" });
    }

    const [candidates] = await pool.query(
      "SELECT * FROM candidates WHERE election_id = ?",
      [id]
    );

    res.json({ election, candidates });
  } catch (err) {
    console.error("Error obteniendo elección:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Emitir voto
app.post("/api/voter/elections/:id/vote", authRequired, async (req, res) => {
  const { id } = req.params; // election_id
  const { candidateId } = req.body;
  const userId = req.user.id;

  try {
    // comprobar si ya votó en esa elección
    const [existing] = await pool.query(
      "SELECT id FROM votes WHERE user_id = ? AND election_id = ?",
      [userId, id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ message: "Ya has votado en esta elección" });
    }

    await pool.query(
      "INSERT INTO votes (user_id, election_id, candidate_id, created_at) VALUES (?, ?, ?, NOW())",
      [userId, id, candidateId]
    );

    await pool.query(
      "INSERT INTO audit_log (user_id, action, description, created_at) VALUES (?, ?, ?, NOW())",
      [userId, "VOTO_EMITIDO", `Voto emitido en elección ${id}`]
    );

    res.json({ message: "Voto registrado correctamente" });
  } catch (err) {
    console.error("Error registrando voto:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Historial de votaciones del usuario
app.get("/api/voter/history", authRequired, async (req, res) => {
  const userId = req.user.id;
  try {
    const [rows] = await pool.query(
      `SELECT v.id, e.title, e.description, v.created_at, c.name AS candidate
       FROM votes v
       JOIN elections e ON v.election_id = e.id
       JOIN candidates c ON v.candidate_id = c.id
       WHERE v.user_id = ?
       ORDER BY v.created_at DESC`,
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo historial:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Lugares de votación
app.get("/api/voter/places", authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, address, capacity FROM polling_places"
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo lugares:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ---------- Admin: dashboard ----------
app.get("/api/admin/dashboard", authRequired, adminOnly, async (req, res) => {
  try {
    const [[usersCount]] = await pool.query(
      "SELECT COUNT(*) AS total_users FROM users"
    );
    const [[electionsCount]] = await pool.query(
      "SELECT COUNT(*) AS total_elections FROM elections"
    );
    const [[votesCount]] = await pool.query(
      "SELECT COUNT(*) AS total_votes FROM votes"
    );
    const [[participation]] = await pool.query(
      `SELECT 
         (SELECT COUNT(DISTINCT user_id) FROM votes) / 
         GREATEST((SELECT COUNT(*) FROM users WHERE role = 'voter'), 1) * 100 
         AS participation`
    );

    res.json({
      totalUsers: usersCount.total_users,
      totalElections: electionsCount.total_elections,
      totalVotes: votesCount.total_votes,
      participation: participation.participation || 0,
    });
  } catch (err) {
    console.error("Error en dashboard admin:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Lista de elecciones (admin)
app.get("/api/admin/elections", authRequired, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM elections ORDER BY start_date DESC");
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo elecciones:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Crear elección
app.post("/api/admin/elections", authRequired, adminOnly, async (req, res) => {
  const { title, description, startDate, endDate, status } = req.body;
  try {
    const [result] = await pool.query(
      "INSERT INTO elections (title, description, start_date, end_date, status) VALUES (?, ?, ?, ?, ?)",
      [title, description, startDate, endDate, status]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error("Error creando elección:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Candidatos (lista)
app.get("/api/admin/candidates", authRequired, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.*, e.title AS election_title
       FROM candidates c
       LEFT JOIN elections e ON c.election_id = e.id`
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo candidatos:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Usuarios
app.get("/api/admin/users", authRequired, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, role, active FROM users"
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo usuarios:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Cambiar estado de usuario (activo/inactivo)
app.patch("/api/admin/users/:id/status", authRequired, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;
  try {
    await pool.query("UPDATE users SET active = ? WHERE id = ?", [active ? 1 : 0, id]);
    res.json({ message: "Estado actualizado" });
  } catch (err) {
    console.error("Error actualizando estado:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Registro de auditoría
app.get("/api/admin/audit", authRequired, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT a.id, a.action, a.description, a.created_at, u.name AS user_name
       FROM audit_log a
       LEFT JOIN users u ON a.user_id = u.id
       ORDER BY a.created_at DESC
       LIMIT 100`
    );
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo auditoría:", err);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// ===================================
app.listen(PORT, () => {
  console.log(`Servidor backend escuchando en http://localhost:${PORT}`);
});
