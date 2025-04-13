const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const allowedOrigins = [
  'https://front-p-final-1ds7.vercel.app',
  'https://front-p-final-chi.vercel.app',
  'https://front-p-final-l0liz.vercel.app',
  'http://localhost:3000'
];

const { SECRET_KEY } = process.env;
const PORT = process.env.PORT || 5001;

// Configuración de Firebase
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  admin.app();
}

const server = express();
const db = admin.firestore();

server.use(bodyParser.json());
server.use(bodyParser.urlencoded({ extended: true }));

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`Intento de acceso desde origen no permitido: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

server.use(cors(corsOptions));
server.options('*', cors(corsOptions));

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" })
  ],
});

// Modifica el middleware de logging de la siguiente manera:

server.use(async (req, res, next) => {
  const startTime = Date.now();
  const logData = {
    ip: req.ip || req.connection.remoteAddress,
    method: req.method,
    responseTime: endTime - startTime,
    server: 1,
    status: res.statusCode,
    timestamp: new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' }),
    url: req.url,
    userAgent: req.get("User-Agent")
  };

  // Guardamos una copia de la función original de res.json
  const originalJson = res.json.bind(res);

  // Sobrescribimos res.json para interceptar la respuesta
  res.json = async (body) => {
    // Primero completamos el logData con la información de la respuesta
    logData.status = res.statusCode;
    logData.responseTime = Date.now() - startTime;
    logData.responseBody = body;
    logData.corsHeaders = {
      'access-control-allow-origin': res.getHeader('access-control-allow-origin'),
      'access-control-allow-credentials': res.getHeader('access-control-allow-credentials')
    };

    try {
      // Guardamos en Winston
      if (res.statusCode >= 400) {
        logger.error(logData);
      } else {
        logger.info(logData);
      }

      // Guardamos en Firebase
      await db.collection("logs").add(logData);
    } catch (error) {
      console.error("Error al guardar logs:", error);
      // No detenemos el flujo por un error en el logging
    }

    // Llamamos a la función original
    return originalJson(body);
  };

  next();
});

// LOGIN
server.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email y contraseña son requeridos" });
    }

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    res.json({ requiresMFA: true, userId: userDoc.id });

  } catch (error) {
    logger.error("Error en login:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// OTP VERIFICATION
server.post("/verify-otp", async (req, res) => {
  try {
    const { email, token } = req.body;

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userSnapshot.docs[0].data();
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    res.json({ success: verified });

  } catch (error) {
    logger.error("Error en verificación OTP:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// NUEVA RECUPERACIÓN SIN CORREO
server.post("/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email es requerido" });
    }

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(200).json({ 
        message: "Si el email existe, podrás usar el código para restablecer tu contraseña",
        success: false 
      });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();

    const resetToken = jwt.sign({ userId: userDoc.id }, SECRET_KEY, { expiresIn: '15m' });

    res.status(200).json({ 
      message: "Usa el código del autenticador para continuar.",
      resetToken,
      mfaSecret: user.mfaSecret,
      success: true
    });

  } catch (error) {
    console.error("Error en request-password-reset:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// RESTABLECER CONTRASEÑA
server.post("/reset-password", async (req, res) => {
  try {
    const { resetToken, mfaCode, newPassword } = req.body;

    if (!resetToken || !mfaCode || !newPassword) {
      return res.status(400).json({ message: "Todos los campos son requeridos" });
    }

    const decoded = jwt.verify(resetToken, SECRET_KEY);
    const userDoc = await db.collection("users").doc(decoded.userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userDoc.data();

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: mfaCode,
      window: 1
    });

    if (!verified) {
      return res.status(401).json({ message: "Código MFA inválido" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection("users").doc(decoded.userId).update({ password: hashedPassword });

    res.json({ message: "Contraseña actualizada correctamente" });

  } catch (error) {
    logger.error("Error en reset-password:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// INFO DE USUARIO
server.get("/getInfo", async (req, res) => {
  try {
    const { idUs } = req.query;

    if (!idUs) {
      return res.status(400).json({ message: "ID de usuario es requerido" });
    }

    const userDoc = await db.collection("users").doc(idUs).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    res.json({
      statusCode: 200,
      message: "Usuario encontrado",
      user: userDoc.data()
    });

  } catch (error) {
    logger.error("Error en getInfo:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// LOGS DEL SERVIDOR
server.get("/getServer", async (req, res) => {
  try {
    const logsSnapshot = await db.collection("logs").get();
    const logs = logsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.json({
      statusCode: 200,
      message: "Logs obtenidos",
      logs
    });

  } catch (error) {
    logger.error("Error en getServer:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// ERROR CORS
server.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ 
      statusCode: 403,
      message: 'Origen no permitido',
      allowedOrigins,
      yourOrigin: req.headers.origin
    });
  } else {
    next(err);
  }
});

// INICIAR SERVIDOR
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log('Orígenes permitidos:', allowedOrigins);
});

module.exports = server;
