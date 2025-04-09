const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const { SECRET_KEY } = process.env;
const PORT = process.env.PORT || 5001;

// 🔥 Leer las credenciales de Firebase desde variables de entorno
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  admin.app();
}

const routes = require("./routes");
const server = express();
const db = admin.firestore();
 
// Middleware CORS manual (100% efectivo)
server.use((req, res, next) => {
  const allowedOrigins = [
    'https://front-p-final-1ds7.vercel.app',
    'https://front-p-final-chi.vercel.app',
    'http://localhost:3000'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

server.use(bodyParser.json());

// Configuración de winston para logs
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/all.log", level: "info" }),
    new winston.transports.File({ filename: "logs/combined.log" }),
  ],
});

// Middleware de logging mejorado
server.use(async (req, res, next) => {
  console.log(`📡 [${req.method}] ${req.url} - Origin: ${req.headers.origin} - Body:`, req.body);
  const startTime = Date.now();

  res.on("finish", async () => {
    const logData = {
      timestamp: new Date(),
      method: req.method,
      url: req.url,
      status: res.statusCode,
      responseTime: Date.now() - startTime,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get("User-Agent"),
      origin: req.headers.origin,
      server: 1,
      corsHeaders: {
        'access-control-allow-origin': res.getHeader('access-control-allow-origin'),
        'access-control-allow-credentials': res.getHeader('access-control-allow-credentials')
      }
    };

    if(res.statusCode >= 400) {
      logger.error(logData);
    } else {
      logger.info(logData);
    }

    try {
      await db.collection("logs").add(logData);
    } catch (error) {
      logger.error("Error al guardar log en Firebase: ", error);
    }
  });

  next();
});

// Rutas de la API
server.use("/api", routes);

// 🔑 Endpoint de login
server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  try {
    const userDoc = await db.collection("users").where("email", "==", email).get();

    if (userDoc.empty) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const doc = userDoc.docs[0];
    const user = doc.data();
    const userId = doc.id;

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    // Retorna si se requiere MFA
    res.json({ requiresMFA: true, userId });

  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// 🔑 Endpoint de verificación de OTP
server.post("/verify-otp", async (req, res) => {
  const { email, token } = req.body; 

  try {
    const userDoc = await db.collection("users").where("email", "==", email).get();
    if (userDoc.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    
    const user = userDoc.docs[0].data(); 

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    }); 

    if (verified) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (error) {
    console.error("Error en OTP:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// 🔑 Endpoint de alumno
server.get("/getInfo", async (req, res) => {
  const { idUs } = req.query;
  try {
    const userDoc = await db.collection('users').doc(idUs).get();

    if (!userDoc.exists) {
      return res.status(401).json({ message: "Usuario no encontrado" });
    }

    const userData = userDoc.data(); 
    return res.status(200).json({
      statusCode: 200,
      message: "Usuario encontrado exitosamente.",
      user: userData
    }); 
  } catch (error) {
    console.error("Error en getInfo:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// 🔑 Endpoint de servidor
server.get("/getServer", async (req, res) => { 
  try {
    const logCollection = await db.collection("logs").get();

    if (logCollection.empty) {
      return res.status(404).json({ message: "No se encontraron logs" });
    }
    
    const logs = logCollection.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    return res.status(200).json({
      statusCode: 200,
      message: "Logs obtenidos exitosamente.",
      logs
    });
  } catch (error) {
    console.error("Error en getServer:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Middleware para manejar errores CORS explícitamente
server.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ 
      statusCode: 403,
      message: 'Origen no permitido por CORS',
      allowedOrigins: allowedOrigins,
      yourOrigin: req.headers.origin
    });
  } else {
    next(err);
  }
});

// 🔥 Iniciar servidor
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log(`Orígenes permitidos: ${allowedOrigins.join(', ')}`);
});