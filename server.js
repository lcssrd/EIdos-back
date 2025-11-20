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


const patientSchema = new mongoose.Schema({
    patientId: { type: String, required: true },
    // Ce 'user' est maintenant l'ID du "propriétaire des ressources"
    // (le 'resourceId' défini dans le middleware protect)
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} }
});
patientSchema.index({ patientId: 1, user: 1 }, { unique: true });
const Patient = mongoose.model('Patient', patientSchema);


// --- Middleware de sécurité ---
const protect = async (req, res, next) => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Non autorisé (pas de token)' });
    }

    const token = header.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // On "populate" l'organisation si elle existe
        const user = await User.findById(decoded.id).populate('organisation');

        if (!user) {
            return res.status(401).json({ error: 'Utilisateur non trouvé' });
        }

        req.user = user; // Le 'user' complet est attaché à la requête

        // --- Définition de l'ID des ressources (qui possède les patients/étudiants ?) ---
        if (user.role === 'etudiant') {
            // Un étudiant accède aux ressources de son créateur (le formateur OU le propriétaire)
            req.user.resourceId = user.createdBy;
        } else {
            // MODIFIÉ : Tout formateur (qu'il soit owner, invité, ou indépendant) 
            // est maintenant propriétaire de ses propres ressources (étudiants/patients).
            req.user.resourceId = user._id;
        }

        // --- Définition du Plan effectif ---
        if ((user.role === 'formateur' || user.role === 'owner') && user.organisation && user.organisation.is_active) {
            // S'il fait partie d'une organisation active, son plan est celui de l'organisation
            req.user.effectivePlan = user.organisation.plan;
        } else if (user.role === 'etudiant') {
            // L'étudiant n'a pas de plan, mais on lui donne un statut pour l'API
            req.user.effectivePlan = 'student';
        } else {
            // Sinon, c'est son plan personnel
            req.user.effectivePlan = user.subscription;
        }

        next();
    } catch (err) {
        console.error("Erreur Middleware Protect:", err);
        res.status(401).json({ error: 'Non autorisé (token invalide)' });
    }
};

// --- Middleware d'authentification Socket.io ---
io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error('Authentification échouée (pas de token)'));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).populate('organisation');

        if (!user) {
            return next(new Error('Utilisateur non trouvé'));
        }

        // --- Logique copiée du middleware 'protect' ---
        let resourceId;
        if (user.role === 'etudiant') {
            resourceId = user.createdBy;
        } else {
            // MODIFIÉ : Le formateur invité utilise son propre ID pour ses salles/sockets
            resourceId = user._id;
        }

        // Attache les infos vitales au socket
        socket.user = user;
        socket.resourceId = resourceId;

        next();
    } catch (err) {
        return next(new Error('Authentification échouée (token invalide)'));
    }
});

// --- Gestion des connexions Socket.io ---
io.on('connection', (socket) => {
    console.log(`Un utilisateur s'est connecté : ${socket.id} (Utilisateur: ${socket.user._id}, Ressource: ${socket.resourceId})`);

    // L'utilisateur rejoint une "room" basée sur l'ID de ses ressources
    const roomName = `room_${socket.resourceId}`;
    socket.join(roomName);
    console.log(`Socket ${socket.id} a rejoint la room ${roomName}`);

    socket.on('disconnect', () => {
        console.log(`Utilisateur déconnecté : ${socket.id}`);
    });
});


// --- ROUTES D'AUTHENTIFICATION ---

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, plan, token } = req.body; // 'token' pour l'invitation

        if (!email || !password) {
            return res.status(400).json({ error: 'Email et mot de passe requis' });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();

        let newUser;

        if (token) {
            // --- Logique d'invitation (MODIFIÉ POUR RETOURNER VERIFIED: TRUE) ---
            const invitation = await Invitation.findOne({ token: token, email: email.toLowerCase() }).populate('organisation');

            if (!invitation || invitation.expires_at < Date.now()) {
                return res.status(400).json({ error: "Token d'invitation invalide ou expiré." });
            }

            // Compter les licences
            const formateurCount = await User.countDocuments({
                organisation: invitation.organisation._id,
                role: 'formateur'
            });

            if (formateurCount >= invitation.organisation.licences_max) {
                return res.status(403).json({ error: "Le nombre maximum de formateurs pour ce centre a été atteint." });
            }

            newUser = new User({
                email: email.toLowerCase(),
                passwordHash,
                isVerified: true, // L'invitation par e-mail vaut vérification
                role: 'formateur',
                subscription: 'promo', // MODIFIÉ : 'promo' au lieu de 'free'
                organisation: invitation.organisation._id,
                is_owner: false
            });

            await newUser.save();
            await Invitation.deleteOne({ _id: invitation._id }); // Supprime le token

            // Retourne une réponse spécifique indiquant que la vérification est déjà faite
            return res.status(201).json({
                success: true,
                message: 'Compte formateur créé avec succès.',
                verified: true // Flag pour le frontend
            });

        } else {
            // --- Logique d'inscription standard ---
            const validPlans = ['free', 'independant', 'promo', 'centre'];
            let finalSubscription = 'free';
            if (plan && validPlans.includes(plan)) {
                finalSubscription = plan;
            }

            if (finalSubscription === 'centre') {
                // Plan Centre (owner)
                newUser = new User({
                    email: email.toLowerCase(),
                    passwordHash,
                    confirmationCode,
                    isVerified: false,
                    role: 'owner',
                    subscription: 'free',
                    is_owner: true
                });
                await newUser.save();

                // Crée l'organisation
                const newOrganisation = new Organisation({
                    name: `Centre de ${email}`,
                    owner: newUser._id,
                    is_active: false, // Inactif jusqu'au paiement
                    quote_url: "https://votre-site.com/lien-admin-a-remplir",
                    quote_price: "Devis en attente"
                });
                await newOrganisation.save();

                // Lie l'organisation à l'utilisateur
                newUser.organisation = newOrganisation._id;
                await newUser.save();

            } else {
                // Inscription standard
                newUser = new User({
                    email: email.toLowerCase(),
                    passwordHash,
                    confirmationCode,
                    isVerified: false,
                    role: 'user',
                    subscription: finalSubscription
                });
                await newUser.save();
            }

            // --- ENVOI DE L'EMAIL DE VÉRIFICATION (Seulement ici) ---
            try {
                await transporter.sendMail({
                    from: `"EIdos" <${process.env.EMAIL_FROM}>`,
                    to: email,
                    subject: 'Vérifiez votre compte EIdos',
                    html: `
                        <h3>Bienvenue sur EIdos !</h3>
                        <p>Votre code de vérification est :</p>
                        <h2 style="color:#0d9488; letter-spacing: 5px;">${confirmationCode}</h2>
                        <p>Saisissez ce code sur la page de vérification pour activer votre compte.</p>
                    `
                });
                console.log(`Email de vérification envoyé à ${email}`);
            } catch (emailError) {
                console.error("Erreur envoi email inscription:", emailError);
            }

            // Réponse standard avec demande de vérification
            return res.status(201).json({
                success: true,
                message: 'Utilisateur créé. Veuillez vérifier votre email.',
                verified: false
            });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// POST /auth/resend-code
app.post('/auth/resend-code', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email requis' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }
        if (user.isVerified) {
            return res.status(400).json({ error: 'Ce compte est déjà vérifié.' });
        }

        // Générer un nouveau code
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.confirmationCode = confirmationCode;
        await user.save();

        // Envoyer l'email
        await transporter.sendMail({
            from: `"EIdos" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Nouveau code de vérification EIdos',
            html: `
                <h3>Nouveau code demandé</h3>
                <p>Votre code de vérification est :</p>
                <h2 style="color:#0d9488; letter-spacing: 5px;">${confirmationCode}</h2>
                <p>Saisissez ce code sur la page de vérification pour activer votre compte.</p>
            `
        });

        res.json({ success: true, message: 'Nouveau code envoyé.' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erreur lors de l'envoi de l'email." });
    }
});


// POST /auth/verify
app.post('/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) {
            return res.status(400).json({ error: 'Email et code requis' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(400).json({ error: 'Utilisateur non trouvé' });
        }
        if (user.isVerified) {
            return res.status(400).json({ error: 'Email déjà vérifié' });
        }
        if (user.confirmationCode !== code) {
            return res.status(400).json({ error: 'Code de vérification invalide' });
        }

        user.isVerified = true;
        user.confirmationCode = undefined;
        await user.save();

        res.json({ success: true, message: 'Email vérifié avec succès !' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// POST /auth/login
app.post('/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        let user;
        const anID = identifier.toLowerCase();

        if (anID.includes('@')) {
            user = await User.findOne({ email: anID });
        } else {
            user = await User.findOne({ login: anID });
        }

        if (!user) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        if ((user.role === 'user' || user.role === 'owner') && !user.isVerified) {
            return res.status(401).json({ error: 'Veuillez d\'abord vérifier votre email.' });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token: token });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/auth/me
app.get('/api/auth/me', protect, async (req, res) => {
    res.json({
        ...req.user.toObject(),
        effectivePlan: req.user.effectivePlan
    });
});

// --- ROUTES DE GESTION DE COMPTE ---

// GET /api/account/details
app.get('/api/account/details', protect, async (req, res) => {
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        // MODIFIÉ : On cherche les étudiants créés par l'utilisateur (resourceId = user._id)
        const students = await User.find(
            { createdBy: req.user.resourceId },
            'login permissions allowedRooms'
        );

        let organisationData = null;
        if (req.user.is_owner && req.user.organisation) {
            const formateurs = await User.find(
                { organisation: req.user.organisation._id, is_owner: false },
                'email'
            );

            organisationData = {
                ...req.user.organisation.toObject(),
                formateurs: formateurs,
                licences_utilisees: formateurs.length + 1
            };
        }

        res.json({
            email: req.user.email,
            plan: req.user.effectivePlan,
            role: req.user.role,
            is_owner: req.user.is_owner,
            students: students,
            organisation: organisationData
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/change-password
app.post('/api/account/change-password', protect, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const isMatch = await bcrypt.compare(currentPassword, req.user.passwordHash);

        if (!isMatch) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        }

        req.user.passwordHash = await bcrypt.hash(newPassword, 10);

        await req.user.save();

        res.json({ success: true, message: 'Mot de passe mis à jour.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// POST /api/account/request-change-email
app.post('/api/account/request-change-email', protect, async (req, res) => {
    try {
        const { newEmail, password } = req.body;
        const user = req.user;

        // 1. Vérifier le mot de passe
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        }

        // 2. Vérifier si le nouvel email est déjà pris
        const existingUser = await User.findOne({ email: newEmail.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Cette adresse e-mail est déjà utilisée.' });
        }

        // 3. Générer un token de vérification
        const token = crypto.randomBytes(32).toString('hex');

        user.newEmail = newEmail.toLowerCase();
        user.newEmailToken = token;
        user.newEmailTokenExpires = Date.now() + 3600000; // Valide 1 heure
        await user.save();

        // 4. Envoyer l'email de vérification avec Brevo
        // Nous utilisons process.env.FRONTEND_URL ou une URL construite pour le lien de vérification
        const verifyLink = `${req.protocol}://${req.get('host')}/api/account/verify-change-email?token=${token}`;

        // ENVOI RÉEL
        await transporter.sendMail({
            from: `"EIdos" <${process.env.EMAIL_FROM}>`, // Utilise le postmaster
            to: newEmail,
            subject: 'Confirmez votre nouvelle adresse e-mail EIdos',
            html: `
                <h3>Bonjour,</h3>
                <p>Vous avez demandé à changer votre adresse e-mail pour <strong>${newEmail}</strong>.</p>
                <p>Veuillez confirmer ce changement en cliquant sur le lien ci-dessous :</p>
                <a href="${verifyLink}" style="background-color:#0d9488;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Confirmer ma nouvelle adresse</a>
                <p><small>Ce lien expirera dans 1 heure.</small></p>
            `
        });

        res.json({ success: true, message: `Un e-mail de vérification a été envoyé à ${newEmail}.` });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/account/verify-change-email
app.get('/api/account/verify-change-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) {
            return res.status(400).send('Token manquant.');
        }

        const user = await User.findOne({
            newEmailToken: token,
            newEmailTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('<h1>Erreur</h1><p>Ce lien est invalide ou a expiré.</p>');
        }

        user.email = user.newEmail;
        user.newEmail = null;
        user.newEmailToken = null;
        user.newEmailTokenExpires = null;
        await user.save();

        res.send('<h1>Succès !</h1><p>Votre adresse e-mail a été mise à jour. Vous pouvez fermer cet onglet et vous reconnecter.</p>');

    } catch (err) {
        res.status(500).send('<h1>Erreur</h1><p>Une erreur est survenue.</p>');
    }
});


// DELETE /api/account/delete
app.delete('/api/account/delete', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Supprime les patients
        await Patient.deleteMany({ user: req.user.resourceId });
        // Supprime les étudiants
        await User.deleteMany({ createdBy: userId });

        if (req.user.is_owner && req.user.organisation) {
            const orgId = req.user.organisation._id;
            // Détache les formateurs
            await User.updateMany(
                { organisation: orgId },
                { $set: { organisation: null, role: 'user', subscription: 'free' } }
            );
            // Supprime l'organisation
            await Organisation.deleteOne({ _id: orgId });
        }

        // Supprime l'utilisateur
        await User.deleteOne({ _id: userId });

        res.json({ success: true, message: 'Compte supprimé avec succès.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/invite (Création étudiant)
app.post('/api/account/invite', protect, async (req, res) => {
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    if (req.user.effectivePlan === 'free') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const studentCount = await User.countDocuments({ createdBy: req.user.resourceId });

        if (req.user.effectivePlan === 'independant' && studentCount >= 5) {
            return res.status(403).json({ error: 'Limite de 5 étudiants atteinte pour le plan Indépendant.' });
        }
        if (req.user.effectivePlan === 'promo' && studentCount >= 40) {
            return res.status(403).json({ error: 'Limite de 40 étudiants atteinte pour le plan Promo.' });
        }

        const { login, password } = req.body;

        const existingStudent = await User.findOne({ login: login.toLowerCase() });
        if (existingStudent) {
            return res.status(400).json({ error: 'Ce login est déjà utilisé.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const defaultPermissions = {
            header: true, admin: true, vie: true, observations: true,
            comptesRendus: true,
            prescriptions_add: true, prescriptions_delete: true, prescriptions_validate: true,
            transmissions: true, pancarte: true, diagramme: true, biologie: true
        };

        const defaultRooms = Array.from({ length: 10 }, (_, i) => `chambre_${101 + i}`);

        const newStudent = new User({
            login: login.toLowerCase(),
            passwordHash: passwordHash,
            role: 'etudiant',
            subscription: 'free',
            createdBy: req.user.resourceId,
            isVerified: true,
            permissions: defaultPermissions,
            allowedRooms: defaultRooms
        });

        await newStudent.save();
        res.status(201).json({ success: true, message: 'Compte étudiant créé.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/account/permissions
app.put('/api/account/permissions', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { login, permission, value } = req.body;

        const student = await User.findOne({
            login: login.toLowerCase(),
            createdBy: req.user.resourceId
        });

        if (!student) {
            return res.status(404).json({ error: 'Étudiant non trouvé' });
        }

        if (!student.permissions) {
            student.permissions = {};
        }

        student.permissions[permission] = value;
        student.markModified('permissions');
        await student.save();

        res.json({ success: true, message: 'Permission mise à jour.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/account/student/rooms
app.put('/api/account/student/rooms', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { login, rooms } = req.body;

        const student = await User.findOne({
            login: login.toLowerCase(),
            createdBy: req.user.resourceId
        });

        if (!student) {
            return res.status(404).json({ error: 'Étudiant non trouvé' });
        }

        if (!Array.isArray(rooms)) {
            return res.status(400).json({ error: 'Format de chambres non valide.' });
        }

        student.allowedRooms = rooms;
        await student.save();

        res.json({ success: true, message: 'Chambres autorisées mises à jour.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/account/student
app.delete('/api/account/student', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { login } = req.body;

        const result = await User.deleteOne({
            login: login.toLowerCase(),
            createdBy: req.user.resourceId
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Étudiant non trouvé' });
        }

        res.json({ success: true, message: 'Compte étudiant supprimé.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/change-subscription
app.post('/api/account/change-subscription', protect, async (req, res) => {
    try {
        const { newPlan } = req.body;
        const validPlans = ['free', 'independant', 'promo', 'centre'];
        if (!newPlan || !validPlans.includes(newPlan)) {
            return res.status(400).json({ error: 'Plan non valide.' });
        }

        if (req.user.role === 'etudiant') {
            return res.status(403).json({ error: 'Non autorisé.' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouvé.' });
        }

        if (newPlan === 'centre') {
            if (user.organisation) {
                return res.status(400).json({ error: "Vous êtes déjà rattaché à un centre." });
            }

            user.role = 'owner';
            user.is_owner = true;

            const newOrganisation = new Organisation({
                name: `Centre de ${user.email}`,
                owner: user._id,
                is_active: false,
                quote_url: "https://votre-site.com/lien-admin-a-remplir",
                quote_price: "Devis en attente"
            });
            await newOrganisation.save();

            user.organisation = newOrganisation._id;

        } else {
            user.subscription = newPlan;
            user.role = 'user';
            user.is_owner = false;
            user.organisation = null;
        }

        await user.save();
        res.json({ success: true, message: 'Abonnement mis à jour.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- ROUTES ORGANISATION ---

// POST /api/organisation/invite (Invitation FORMATEUR)
app.post('/api/organisation/invite', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) {
        return res.status(403).json({ error: 'Non autorisé (réservé aux propriétaires de centre).' });
    }

    try {
        const { email } = req.body;
        const organisation = req.user.organisation;

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Un utilisateur avec cet e-mail existe déjà.' });
        }

        const formateurCount = await User.countDocuments({ organisation: organisation._id, role: 'formateur' });
        if (formateurCount >= organisation.licences_max) {
            return res.status(403).json({ error: "La limite de formateurs pour votre centre a été atteinte." });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const invitation = new Invitation({
            email: email.toLowerCase(),
            organisation: organisation._id,
            token: token
        });
        await invitation.save();

        const baseUrl = process.env.FRONTEND_URL || `http://localhost:${PORT}`;
        const inviteLink = `${baseUrl}/auth.html?invitation_token=${token}`;

        // ENVOI RÉEL
        await transporter.sendMail({
            from: `"EIdos" <${process.env.EMAIL_FROM}>`, // Utilise le postmaster
            to: email,
            subject: `Vous avez été invité à rejoindre ${organisation.name} sur EIdos`,
            html: `
                <h3>Bonjour,</h3>
                <p>Vous avez été invité par ${req.user.email} à rejoindre l'espace formateur de "<strong>${organisation.name}</strong>" sur EIdos.</p>
                <p>Cliquez sur le bouton ci-dessous pour créer votre compte :</p>
                <a href="${inviteLink}" style="background-color:#0d9488;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Créer mon compte formateur</a>
                <p><small>Ce lien expirera dans 7 jours.</small></p>
            `
        });

        res.status(200).json({ success: true, message: `Invitation envoyée à ${email}.` });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/organisation/remove
app.post('/api/organisation/remove', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { email } = req.body;

        const formateur = await User.findOne({
            email: email.toLowerCase(),
            organisation: req.user.organisation._id,
            is_owner: false
        });

        if (!formateur) {
            return res.status(404).json({ error: 'Formateur non trouvé dans votre organisation.' });
        }

        formateur.organisation = null;
        formateur.role = 'user';
        formateur.subscription = 'free';
        await formateur.save();

        res.status(200).json({ success: true, message: `${email} a été retiré de votre centre.` });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- ROUTES API (Patients) ---

// GET /api/patients
app.get('/api/patients', protect, async (req, res) => {
    try {
        const query = { user: req.user.resourceId };

        if (req.user.role === 'etudiant') {
            query.patientId = { $in: req.user.allowedRooms };
        }

        const patients = await Patient.find(
            query,
            'patientId sidebar_patient_name'
        );
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/patients/save
app.post('/api/patients/save', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { dossierData, sidebar_patient_name } = req.body;

        if (!sidebar_patient_name || sidebar_patient_name.startsWith('Chambre ')) {
            return res.status(400).json({ error: 'Veuillez donner un nom au patient dans l\'en-tête avant de sauvegarder.' });
        }

        const existingSave = await Patient.findOne({
            user: req.user.resourceId,
            sidebar_patient_name: sidebar_patient_name,
            patientId: { $regex: /^save_/ }
        });

        if (existingSave) {
            await Patient.updateOne(
                { _id: existingSave._id },
                { dossierData: dossierData }
            );
            res.json({ success: true, message: 'Sauvegarde mise à jour.' });
        } else {
            const plan = req.user.effectivePlan;

            if (plan === 'independant' || plan === 'promo') {
                const saveCount = await Patient.countDocuments({
                    user: req.user.resourceId,
                    patientId: { $regex: /^save_/ }
                });

                let limit = 0;
                if (plan === 'independant') limit = 20;
                if (plan === 'promo') limit = 50;

                if (saveCount >= limit) {
                    return res.status(403).json({
                        error: `Limite de ${limit} archives atteinte pour le plan ${plan}.`
                    });
                }
            }

            const newPatientId = `save_${new mongoose.Types.ObjectId()}`;
            const newPatient = new Patient({
                patientId: newPatientId,
                user: req.user.resourceId,
                dossierData: dossierData,
                sidebar_patient_name: sidebar_patient_name
            });
            await newPatient.save();
            res.status(201).json({ success: true, message: 'Dossier sauvegardé.' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// GET /api/patients/:patientId
app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        let patient = await Patient.findOne({
            patientId: req.params.patientId,
            user: req.user.resourceId
        });

        if (!patient && req.params.patientId.startsWith('chambre_')) {
            patient = new Patient({
                patientId: req.params.patientId,
                user: req.user.resourceId,
                sidebar_patient_name: `Chambre ${req.params.patientId.split('_')[1]}`
            });
            await patient.save();
        } else if (!patient) {
            return res.status(404).json({ error: 'Dossier non trouvé' });
        }

        res.json(patient.dossierData || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/patients/:patientId (Mise à jour temps réel)
app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        if (req.user.effectivePlan === 'free' && req.user.role !== 'etudiant') {
            return res.status(403).json({ error: 'Le plan Free ne permet pas la sauvegarde.' });
        }

        if (!req.params.patientId.startsWith('chambre_')) {
            return res.status(400).json({ error: 'Cette route est réservée à la mise à jour des chambres.' });
        }

        const { dossierData, sidebar_patient_name } = req.body;
        const userIdToSave = req.user.resourceId;
        let finalDossierData = dossierData;
        let sidebarUpdate = {};

        // Fusion pour les étudiants
        if (req.user.role === 'etudiant') {
            const permissions = req.user.permissions;
            const existingPatient = await Patient.findOne({
                patientId: req.params.patientId,
                user: userIdToSave
            });
            const existingData = existingPatient ? existingPatient.dossierData : {};
            const mergedData = { ...existingData };

            if (permissions.header) {
                ['patient-nom-usage', 'patient-prenom', 'patient-dob', 'patient-motif', 'patient-entry-date'].forEach(k => {
                    if (dossierData[k] !== undefined) mergedData[k] = dossierData[k];
                });

                const adminFieldsToSync = ['admin-nom-usage', 'admin-prenom', 'admin-dob'];
                adminFieldsToSync.forEach(adminKey => {
                    const patientKey = adminKey.replace('admin-', 'patient-');
                    if (dossierData[patientKey] !== undefined) {
                        mergedData[adminKey] = dossierData[patientKey];
                    }
                });
                sidebarUpdate = { sidebar_patient_name: sidebar_patient_name };
            }

            if (permissions.admin) {
                const adminFieldsToSync = ['admin-nom-usage', 'admin-prenom', 'admin-dob'];
                Object.keys(dossierData).filter(k => k.startsWith('admin-') && !adminFieldsToSync.includes(k))
                    .forEach(k => mergedData[k] = dossierData[k]);
            }
            if (permissions.vie) {
                Object.keys(dossierData).filter(k => k.startsWith('vie-') || k.startsWith('atcd-')).forEach(k => mergedData[k] = dossierData[k]);
            }
            if (permissions.observations) mergedData['observations'] = dossierData['observations'];
            if (permissions.prescriptions_add || permissions.prescriptions_delete || permissions.prescriptions_validate) mergedData['prescriptions'] = dossierData['prescriptions'];
            if (permissions.transmissions) mergedData['transmissions'] = dossierData['transmissions'];
            if (permissions.comptesRendus) mergedData['comptesRendus'] = dossierData['comptesRendus'];
            if (permissions.pancarte) {
                mergedData['pancarte'] = dossierData['pancarte'];
                mergedData['glycemie'] = dossierData['glycemie'];
            }
            if (permissions.diagramme) {
                mergedData['care-diagram-tbody_html'] = dossierData['care-diagram-tbody_html'];
                mergedData['careDiagramCheckboxes'] = dossierData['careDiagramCheckboxes'];
            }
            if (permissions.biologie) mergedData['biologie'] = dossierData['biologie'];

            finalDossierData = mergedData;
        } else {
            sidebarUpdate = { sidebar_patient_name: sidebar_patient_name };
        }

        await Patient.findOneAndUpdate(
            { patientId: req.params.patientId, user: userIdToSave },
            {
                dossierData: finalDossierData,
                ...sidebarUpdate,
                user: userIdToSave
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        // Émission Socket.io
        try {
            const senderSocketId = req.headers['x-socket-id'];
            const roomName = `room_${req.user.resourceId}`;
            const sockets = await io.in(roomName).fetchSockets();
            const senderSocket = sockets.find(s => s.id === senderSocketId);

            const eventData = {
                patientId: req.params.patientId,
                dossierData: finalDossierData,
                sender: senderSocketId
            };

            if (senderSocket) {
                senderSocket.to(roomName).emit('patient_updated', eventData);
            } else {
                io.to(roomName).emit('patient_updated', eventData);
            }

        } catch (socketError) {
            console.error("Erreur socket :", socketError);
        }

        res.json({ success: true, message: 'Dossier de chambre mis à jour.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/patients/:patientId
app.delete('/api/patients/:patientId', protect, async (req, res) => {

    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const patientId = req.params.patientId;
        const userId = req.user.resourceId;

        if (patientId.startsWith('chambre_')) {
            await Patient.findOneAndUpdate(
                { patientId: patientId, user: userId },
                {
                    dossierData: {},
                    sidebar_patient_name: `Chambre ${patientId.split('_')[1]}`
                },
                { upsert: true, new: true }
            );

            // Socket.io clear
            try {
                const roomName = `room_${req.user.resourceId}`;
                const eventData = { patientId: patientId, dossierData: {} };
                io.to(roomName).emit('patient_updated', eventData);
            } catch (socketError) { console.error("Erreur socket (clear):", socketError); }

            res.json({ success: true, message: 'Chambre réinitialisée.' });

        } else if (patientId.startsWith('save_')) {
            await Patient.deleteOne({ patientId: patientId, user: userId });
            res.json({ success: true, message: 'Sauvegarde supprimée.' });
        } else {
            res.status(400).json({ error: 'ID patient invalide.' });
        }
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