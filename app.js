const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const nodemailer = require('nodemailer');

// Configuración global de orígenes permitidos
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

const routes = require("./routes");
const server = express();
const db = admin.firestore();

// Middleware CORS manual mejorado
server.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

server.use(bodyParser.json());

// Configuración de logs con Winston
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
server.use(async (req, res, next) => {
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
      corsHeaders: {
        'access-control-allow-origin': res.getHeader('access-control-allow-origin'),
        'access-control-allow-credentials': res.getHeader('access-control-allow-credentials')
      }
    };

    if (res.statusCode >= 400) {
      logger.error(logData);
    } else {
      logger.info(logData);
    }

    try {
      await db.collection("logs").add(logData);
    } catch (error) {
      logger.error("Error al guardar log en Firebase:", error);
    }
  });

  next();
});

// Rutas principales
server.use("/api", routes);

// Endpoint de login
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

    res.json({ 
      requiresMFA: true, 
      userId: userDoc.id 
    });

  } catch (error) {
    logger.error("Error en login:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Endpoint de verificación OTP
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

// Endpoint para solicitar recuperación de contraseña
server.post("/request-password-reset", async (req, res) => {
  try {
    console.log("Solicitud recibida:", req.body); // Log de la solicitud entrante
    
    const { email } = req.body;
    
    // Validación mejorada
    if (!email) {
      console.log("Email no proporcionado");
      return res.status(400).json({ message: "Email es requerido" });
    }

    console.log("Buscando usuario con email:", email);
    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    
    if (userSnapshot.empty) {
      console.log("No se encontró usuario con email:", email);
      return res.status(200).json({ 
        message: "Si el email existe, recibirás instrucciones para restablecer tu contraseña",
        success: false 
      });
    }

    console.log("Usuario encontrado, preparando email...");
    const userDoc = userSnapshot.docs[0];
    const resetLink = `https://front-p-final-chi.vercel.app/reset-password?userId=${userDoc.id}`;
    
    console.log("Configurando transporte de email...");
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    console.log("Preparando opciones de email...");
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `...` // tu plantilla de email
    };
     
    console.log("Intentando enviar email...");
    await transporter.sendMail(mailOptions);
    console.log("Email enviado exitosamente");
    
    res.status(200).json({ 
      message: "Si el email existe, recibirás instrucciones para restablecer tu contraseña",
      success: true
    });

  } catch (error) {
    console.error("ERROR EN request-password-reset:", {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    res.status(500).json({ 
      message: "Error interno del servidor",
      error: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});

// Endpoint para restablecer contraseña (después de verificar MFA)
server.post("/reset-password", async (req, res) => {
  try {
    const { userId, token, newPassword } = req.body;
    
    if (!userId || !token || !newPassword) {
      return res.status(400).json({ 
        message: "ID de usuario, token y nueva contraseña son requeridos" 
      });
    } 
    
    const userDoc = await db.collection("users").doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userDoc.data();
     
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ message: "Código de verificación inválido" });
    }
 
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Actualizar contraseña
    await db.collection("users").doc(userId).update({
      password: hashedPassword
    });

    res.json({ 
      success: true,
      message: "Contraseña actualizada correctamente" 
    });

  } catch (error) {
    logger.error("Error en reset-password:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Endpoint para obtener información de usuario
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

// Endpoint para obtener logs del servidor
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

// Middleware para manejar errores CORS explícitamente
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

// Iniciar servidor
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log('Orígenes permitidos:', allowedOrigins);
});

// Exportar para testing
module.exports = server;