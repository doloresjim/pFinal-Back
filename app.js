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

// Middleware mejorado para logs
server.use(async (req, res, next) => {
  const startTime = Date.now();
  const serverInstance = 1; // Identificador del servidor (1 para este servidor)

  res.on("finish", async () => {
    try {
      const logData = {
        timestamp: admin.firestore.FieldValue.serverTimestamp(), // Usa timestamp de Firestore
        method: req.method,
        url: req.url,
        status: res.statusCode,
        responseTime: Date.now() - startTime,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get("User-Agent"),
        origin: req.headers.origin,
        server: serverInstance, // Añadido campo server
        corsHeaders: {
          'access-control-allow-origin': res.getHeader('access-control-allow-origin'),
          'access-control-allow-credentials': res.getHeader('access-control-allow-credentials')
        }
      };

      // Log a archivos locales
      if (res.statusCode >= 400) {
        logger.error(logData);
      } else {
        logger.info(logData);
      }

      // Log a Firestore
      await db.collection("logs").add(logData);
      console.log("Log registrado en Firestore:", logData); // Log de depuración

    } catch (error) {
      console.error("Error al guardar log:", error);
      logger.error("Error al guardar log:", error);
    }
  });

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
    const logsSnapshot = await db.collection("logs")
      .orderBy("timestamp", "desc") // Ordenar por timestamp descendente
      .limit(1000) // Límite para no sobrecargar
      .get();

    const logs = logsSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        // Asegurar que el timestamp sea accesible
        timestamp: data.timestamp ? data.timestamp.toDate() : new Date()
      };
    });

    res.json({
      statusCode: 200,
      message: "Logs obtenidos",
      logs,
      count: logs.length
    });

  } catch (error) {
    console.error("Error en getServer:", error);
    res.status(500).json({ 
      message: "Error interno del servidor",
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});


// Endpoint de prueba para Firestore
server.get("/test-firebase", async (req, res) => {
  try {
    const testDoc = await db.collection("test").add({
      message: "Test connection",
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      server: 1
    });
    res.json({ 
      success: true, 
      id: testDoc.id,
      message: "Conexión a Firestore verificada correctamente"
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message,
      details: "Verifica las credenciales de Firebase y los permisos de Firestore"
    });
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
