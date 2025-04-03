const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const speakeasy = require('speakeasy');

const router = express.Router();
const db = admin.firestore();

router.post("/register", async (req, res) => { 
    try {
        const { email, username, nombre, app, apm , grupo, password } = req.body;
        if (!email || !password || !username || !nombre || !app || !apm || !grupo) {
            return res.status(400).json({ message: "Missing fields" });
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generar secreto para 2FA
        const secret = speakeasy.generateSecret({ length: 20 });
        
        // Guardar usuario en Firestore
        await db.collection("users").add({
            nombre,
            app,
            apm,
            email,
            username,
            grupo,
            password: hashedPassword,
            mfaSecret: secret.base32,  
        });

        // Log antes de responder
        console.log("mfaSecret del usuario:", secret.base32);

        // Respuesta correcta
        return res.status(201).json({ 
            message: "User registered",
            mfaSecret: secret.base32
        });

    } catch (error) {
        console.error("Error registering user:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});


module.exports = router;
