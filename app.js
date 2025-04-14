const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const bcrypt = require("bcryptjs");
require("dotenv").config();

// Configuración de orígenes permitidos
const allowedOrigins = [
  'https://front-p-final-iand.vercel.app',
  'https://front-p-final-chi.vercel.app',
  'https://front-p-final-l0liz.vercel.app',
  'http://localhost:3000'
];

const { SECRET_KEY } = process.env;
const PORT = process.env.PORT || 5001;

// Configuración de Firebase
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
} catch (error) {
  console.error('Error parsing FIREBASE_CREDENTIALS:', error);
  process.exit(1);
}

// Inicialización de Firebase
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin inicializado correctamente');
  } catch (firebaseError) {
    console.error('Error inicializando Firebase Admin:', firebaseError);
    process.exit(1);
  }
}

const server = express();
const db = admin.firestore();

// Configuración de middlewares
server.use(bodyParser.json());
server.use(bodyParser.urlencoded({ extended: true }));

// Configuración CORS mejorada
const corsOptionsDelegate = (req, callback) => {
  const origin = req.header('Origin');
  const corsOptions = {
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-action-type'],
    exposedHeaders: ['Content-Length', 'X-Kuma-Revision'],
    maxAge: 86400
  };

  // Permitir solicitudes sin origen (como apps móviles o Postman)
  if (!origin) {
    corsOptions.origin = false;
    return callback(null, corsOptions);
  }

  // Verificar si el origen está permitido
  if (allowedOrigins.includes(origin)) {
    corsOptions.origin = origin;
    return callback(null, corsOptions);
  }

  // Origen no permitido
  console.warn(`Intento de acceso desde origen no permitido: ${origin}`);
  return callback(new Error('Not allowed by CORS'), corsOptions);
};

// Aplicar CORS con la configuración personalizada
server.use(cors(corsOptionsDelegate));

// Manejar explícitamente las peticiones OPTIONS
server.options('*', cors(corsOptionsDelegate));

// Configuración de logging
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

// Middleware de logging mejorado
server.use((req, res, next) => {
  if (req.method === 'OPTIONS') return next();

  const startTime = Date.now();
  const shouldLog = ['GET', 'POST', 'PUT', 'DELETE'].includes(req.method);

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);

  const logResponse = async (body, methodUsed) => {
    const logData = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      status: res.statusCode,
      responseTime: Date.now() - startTime,
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      server: 1,
      origin: req.get('Origin') || 'none'
    };

    try {
      if (shouldLog) {
        await db.collection("logs").add(logData);
        logger[res.statusCode >= 400 ? 'error' : 'info'](logData);
      }
    } catch (error) {
      console.error("Error al guardar logs:", error);
    }

    return methodUsed(body);
  };

  res.json = (body) => logResponse(body, originalJson);
  res.send = (body) => logResponse(body, originalSend);

  next();
});

// Endpoint de prueba CORS
server.get('/api/cors-test', (req, res) => {
  res.json({
    message: 'CORS test successful',
    origin: req.get('Origin'),
    allowedOrigins: allowedOrigins,
    headers: req.headers
  });
});

// Rutas de autenticación
server.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email y contraseña son requeridos" });
    }

    // Verificar si el usuario ya existe
    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ message: "El email ya está registrado" });
    }

    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generar secreto MFA
    const mfaSecret = speakeasy.generateSecret({ length: 20 }).base32;

    // Crear nuevo usuario
    const newUser = {
      email,
      password: hashedPassword,
      mfaSecret,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const userRef = await db.collection("users").add(newUser);

    res.status(201).json({ 
      message: "Usuario registrado exitosamente",
      userId: userRef.id,
      requiresMFA: true
    });

  } catch (error) {
    logger.error("Error en registro:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

server.post("/api/login", async (req, res) => {
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

    res.json({ 
      requiresMFA: true, 
      userId: userDoc.id,
      mfaSecret: user.mfaSecret
    });

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

// NUEVA RECUPERACIÓN CON CODIGO
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

// Manejador de errores general
server.use((err, req, res, next) => {
  logger.error("Error no manejado:", err);
  res.status(500).json({ message: "Error interno del servidor" });
});

// Iniciar servidor
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log('Orígenes permitidos:', allowedOrigins);
});

module.exports = server;

