const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Importations pour Socket.io
const http = require('http');
const { Server } = require("socket.io");

// --- CONFIGURATION ---
const app = express();
app.use(cors());
app.use(express.json());

// Création du serveur HTTP et de l'instance Socket.io
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "*", // En production, restreignez ceci à l'URL de votre front-end
        methods: ["GET", "POST"]
    }
});

// LECTURE DES VARIABLES D'ENVIRONNEMENT
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- CONFIGURATION DE NODEMAILER (BREVO) ---
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    // Si le port est 465, on met secure à true, sinon false (pour 587 ou 2525)
    secure: parseInt(process.env.SMTP_PORT) === 465,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Vérification de la connexion SMTP au démarrage
transporter.verify(function (error, success) {
    if (error) {
        console.error("❌ Erreur de configuration SMTP (Brevo) :", error);
    } else {
        console.log("✅ Serveur SMTP prêt à envoyer des emails via Brevo");
    }
});


// --- MODÈLES DE DONNÉES (SCHEMAS) ---

// Schéma pour les Organisations (Plan Centre)
const organisationSchema = new mongoose.Schema({
    name: { type: String, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Le 'Propriétaire'
    plan: { type: String, default: 'centre', enum: ['centre'] },
    licences_max: { type: Number, default: 50 }, // Le nombre de formateurs (sièges)

    // Pour le paiement sur devis
    quote_url: { type: String, default: null }, // Le lien de paiement Stripe
    quote_price: { type: String, default: null }, // Le texte "2000€/an"
    is_active: { type: Boolean, default: false } // Devient 'true' après le paiement
});
const Organisation = mongoose.model('Organisation', organisationSchema);

// Schéma pour les invitations de Formateurs
const invitationSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, index: true },
    organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', required: true },
    token: { type: String, required: true, unique: true },
    expires_at: { type: Date, default: () => Date.now() + 7 * 24 * 60 * 60 * 1000 } // Expire dans 7 jours
});
const Invitation = mongoose.model('Invitation', invitationSchema);


// Schéma Utilisateur (gestion des rôles et de l'organisation)
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true, sparse: true }, // Pour formateurs/owners
    login: { type: String, unique: true, lowercase: true, sparse: true }, // Pour étudiants

    passwordHash: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    confirmationCode: { type: String },

    // RÔLES
    role: {
        type: String,
        enum: ['user', 'formateur', 'owner', 'etudiant'], // user = standard, owner = admin du centre, formateur = invité du centre
        required: true
    },

    // Plan personnel (pour 'user')
    subscription: {
        type: String,
        enum: ['free', 'independant', 'promo'],
        default: 'free'
    },

    // --- LIENS ---

    // Si role='etudiant', ceci est l'ID du formateur/owner qui l'a créé
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    // Si role='formateur' ou 'owner', ceci est l'ID de leur organisation
    organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', default: null },

    // Pour différencier le payeur des invités dans une organisation
    is_owner: { type: Boolean, default: false },

    // --- Données spécifiques aux étudiants ---
    permissions: { type: mongoose.Schema.Types.Mixed, default: {} },
    allowedRooms: { type: [String], default: [] },

    // --- Champs pour le changement d'e-mail ---
    newEmail: { type: String, lowercase: true, default: null },
    newEmailToken: { type: String, default: null },
    newEmailTokenExpires: { type: Date, default: null }
});
const User = mongoose.model('User', userSchema);

// --- SCHÉMA PATIENT ---
const patientSchema = new mongoose.Schema({
    patientId: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} },
    is_public: { type: Boolean, default: false }
});
const Patient = mongoose.model('Patient', patientSchema);

// --- MIDDLEWARE D'AUTHENTIFICATION ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-passwordHash');

            if (!req.user) {
                return res.status(401).json({ error: 'Utilisateur non trouvé' });
            }

            // Calculer resourceId et effectivePlan
            if (req.user.role === 'etudiant') {
                req.user.resourceId = req.user.createdBy;
                const owner = await User.findById(req.user.createdBy);
                req.user.effectivePlan = owner ? owner.subscription : 'free';
            } else if (req.user.role === 'formateur' && req.user.organisation) {
                req.user.resourceId = req.user._id;
                req.user.effectivePlan = 'centre';
            } else {
                req.user.resourceId = req.user._id;
                req.user.effectivePlan = req.user.subscription;
            }

            next();
        } catch (error) {
            res.status(401).json({ error: 'Non autorisé, token invalide' });
        }
    } else {
        res.status(401).json({ error: 'Non autorisé, pas de token' });
    }
};

// --- ROUTES AUTH (MINIMALES) ---
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (user && (await bcrypt.compare(password, user.passwordHash))) {
            const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
            res.json({
                _id: user._id,
                email: user.email,
                role: user.role,
                subscription: user.subscription,
                token
            });
        } else {
            res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ROUTES PATIENTS ---
app.get('/api/patients', protect, async (req, res) => {
    try {
        const query = {
            $or: [
                { user: req.user.resourceId },
                { is_public: true }
            ]
        };

        if (req.user.role === 'etudiant') {
            query.$or = [
                { user: req.user.resourceId, patientId: { $in: req.user.allowedRooms } },
                { is_public: true }
            ];
        }

        const patients = await Patient.find(query, 'patientId sidebar_patient_name is_public user');
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/patients/save', protect, async (req, res) => {
    try {
        const { patientId, dossierData, sidebar_patient_name, is_public } = req.body;

        let finalIsPublic = false;
        if (is_public === true) {
            if (req.user.email === 'lucas.seraudie@gmail.com') {
                finalIsPublic = true;
            }
        }

        if (!finalIsPublic) {
            if (req.user.effectivePlan === 'free') {
                const count = await Patient.countDocuments({ user: req.user.resourceId, is_public: false });
                if (count >= 3) {
                    const existing = await Patient.findOne({ patientId, user: req.user.resourceId });
                    if (!existing) return res.status(403).json({ error: "Limite de plan atteinte (Free)" });
                }
            }
        }

        let patient = await Patient.findOne({ patientId, user: req.user.resourceId });

        if (!patient) {
            const publicPatient = await Patient.findOne({ patientId, is_public: true });
            if (publicPatient) {
                if (req.user.email !== 'lucas.seraudie@gmail.com') {
                    return res.status(403).json({ error: "Vous ne pouvez pas modifier un dossier public." });
                }
                patient = publicPatient;
            }
        }

        if (patient) {
            patient.dossierData = dossierData;
            patient.sidebar_patient_name = sidebar_patient_name;
            if (req.user.email === 'lucas.seraudie@gmail.com') {
                patient.is_public = finalIsPublic;
            }
            await patient.save();
        } else {
            patient = await Patient.create({
                patientId,
                user: req.user.resourceId,
                sidebar_patient_name,
                dossierData,
                is_public: finalIsPublic
            });
        }

        res.json(patient);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        const patient = await Patient.findOne({
            patientId: req.params.patientId,
            $or: [
                { user: req.user.resourceId },
                { is_public: true }
            ]
        });

        if (!patient) return res.status(404).json({ error: 'Patient non trouvé' });
        res.json(patient);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/patients/:patientId', protect, async (req, res) => {
    try {
        const patient = await Patient.findOne({ patientId: req.params.patientId });
        if (!patient) return res.status(404).json({ error: 'Patient non trouvé' });

        if (patient.is_public) {
            if (req.user.email !== 'lucas.seraudie@gmail.com') {
                return res.status(403).json({ error: "Seul l'administrateur peut supprimer un dossier public." });
            }
        } else {
            if (patient.user.toString() !== req.user.resourceId.toString()) {
                return res.status(403).json({ error: "Non autorisé" });
            }
        }

        await patient.deleteOne();
        res.json({ message: 'Patient supprimé' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Webhook simulation
app.post('/api/webhook/payment-received', express.raw({ type: 'application/json' }), async (req, res) => {
    console.log("Webhook reçu !");
    res.json({ received: true });
});

// --- DÉMARRAGE DU SERVEUR ---
mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('✅ Connecté avec succès à MongoDB !');
        httpServer.listen(PORT, () => {
            console.log(`🚀 Serveur backend (Express + Socket.io) démarré sur le port ${PORT}`);
        });
    })
    .catch((err) => {
        console.error('❌ Erreur de connexion à MongoDB :', err);
        process.exit(1);
    });