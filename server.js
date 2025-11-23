const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

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
    secure: parseInt(process.env.SMTP_PORT) === 465,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

transporter.verify(function (error, success) {
    if (error) {
        console.error("❌ Erreur de configuration SMTP (Brevo) :", error);
    } else {
        console.log("✅ Serveur SMTP prêt à envoyer des emails via Brevo");
    }
});


// --- MODÈLES DE DONNÉES (SCHEMAS) ---

const organisationSchema = new mongoose.Schema({
    name: { type: String, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: String, default: 'centre', enum: ['centre'] },
    licences_max: { type: Number, default: 50 },
    quote_url: { type: String, default: null },
    quote_price: { type: String, default: null },
    is_active: { type: Boolean, default: false }
});
const Organisation = mongoose.model('Organisation', organisationSchema);

const invitationSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, index: true },
    organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', required: true },
    token: { type: String, required: true, unique: true },
    expires_at: { type: Date, default: () => Date.now() + 7 * 24 * 60 * 60 * 1000 }
});
const Invitation = mongoose.model('Invitation', invitationSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true, sparse: true },
    login: { type: String, unique: true, lowercase: true, sparse: true },
    passwordHash: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    confirmationCode: { type: String },
    role: {
        type: String,
        enum: ['user', 'formateur', 'owner', 'etudiant'],
        required: true
    },
    subscription: {
        type: String,
        enum: ['free', 'independant', 'promo'],
        default: 'free'
    },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', default: null },
    is_owner: { type: Boolean, default: false },
    permissions: { type: mongoose.Schema.Types.Mixed, default: {} },
    allowedRooms: { type: [String], default: [] },
    newEmail: { type: String, lowercase: true, default: null },
    newEmailToken: { type: String, default: null },
    newEmailTokenExpires: { type: Date, default: null }
});
const User = mongoose.model('User', userSchema);

const patientSchema = new mongoose.Schema({
    patientId: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} },
    is_public: { type: Boolean, default: false }
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
        const user = await User.findById(decoded.id).populate('organisation');

        if (!user) {
            return res.status(401).json({ error: 'Utilisateur non trouvé' });
        }

        req.user = user;

        if (user.role === 'etudiant') {
            req.user.resourceId = user.createdBy;
        } else {
            req.user.resourceId = user._id;
        }

        if ((user.role === 'formateur' || user.role === 'owner') && user.organisation && user.organisation.is_active) {
            req.user.effectivePlan = user.organisation.plan;
        } else if (user.role === 'etudiant') {
            req.user.effectivePlan = 'student';
        } else {
            req.user.effectivePlan = user.subscription;
        }

        next();
    } catch (err) {
        console.error("Erreur Middleware Protect:", err);
        res.status(401).json({ error: 'Non autorisé (token invalide)' });
    }
};

// --- Middleware Admin ---
const adminProtect = (req, res, next) => {
    if (req.user && req.user.email === 'lucas.seraudie@gmail.com') {
        next();
    } else {
        return res.status(403).json({ error: 'Accès refusé. Réservé à l\'administrateur.' });
    }
};

// --- Middleware Socket.io ---
io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentification échouée (pas de token)'));

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).populate('organisation');
        if (!user) return next(new Error('Utilisateur non trouvé'));

        let resourceId;
        if (user.role === 'etudiant') {
            resourceId = user.createdBy;
        } else {
            resourceId = user._id;
        }

        socket.user = user;
        socket.resourceId = resourceId;
        next();
    } catch (err) {
        return next(new Error('Authentification échouée (token invalide)'));
    }
});

io.on('connection', (socket) => {
    const roomName = `room_${socket.resourceId}`;
    socket.join(roomName);
    socket.on('disconnect', () => {});
});


// --- ROUTES D'AUTHENTIFICATION ---

app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, plan, token } = req.body;

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
            const invitation = await Invitation.findOne({ token: token, email: email.toLowerCase() }).populate('organisation');
            if (!invitation || invitation.expires_at < Date.now()) {
                return res.status(400).json({ error: "L'adresse email ne correspond pas à celle de l'invitation ou le lien a expiré." });
            }

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
                isVerified: true,
                role: 'formateur',
                subscription: 'promo',
                organisation: invitation.organisation._id,
                is_owner: false
            });

            await newUser.save();
            await Invitation.deleteOne({ _id: invitation._id });

            return res.status(201).json({
                success: true,
                message: 'Compte formateur créé avec succès.',
                verified: true
            });

        } else {
            const validPlans = ['free', 'independant', 'promo', 'centre'];
            let finalSubscription = 'free';
            if (plan && validPlans.includes(plan)) {
                finalSubscription = plan;
            }

            if (finalSubscription === 'centre') {
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

                const newOrganisation = new Organisation({
                    name: `Centre de ${email}`,
                    owner: newUser._id,
                    is_active: false,
                    quote_url: "https://votre-site.com/lien-admin-a-remplir",
                    quote_price: "Devis en attente"
                });
                await newOrganisation.save();

                newUser.organisation = newOrganisation._id;
                await newUser.save();

            } else {
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
            } catch (emailError) {
                console.error("Erreur envoi email inscription:", emailError);
            }

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

app.post('/auth/resend-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email requis' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
        if (user.isVerified) return res.status(400).json({ error: 'Ce compte est déjà vérifié.' });

        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.confirmationCode = confirmationCode;
        await user.save();

        await transporter.sendMail({
            from: `"EIdos" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Nouveau code de vérification EIdos',
            html: `<h3>Nouveau code demandé</h3><p>Code : <b>${confirmationCode}</b></p>`
        });

        res.json({ success: true, message: 'Nouveau code envoyé.' });
    } catch (err) {
        res.status(500).json({ error: "Erreur lors de l'envoi de l'email." });
    }
});

app.post('/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'Email et code requis' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(400).json({ error: 'Utilisateur non trouvé' });
        if (user.isVerified) return res.status(400).json({ error: 'Email déjà vérifié' });
        if (user.confirmationCode !== code) return res.status(400).json({ error: 'Code invalide' });

        user.isVerified = true;
        user.confirmationCode = undefined;
        await user.save();

        res.json({ success: true, message: 'Email vérifié avec succès !' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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

        if (!user) return res.status(401).json({ error: 'Identifiants invalides' });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(401).json({ error: 'Identifiants invalides' });

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

app.get('/api/auth/me', protect, async (req, res) => {
    res.json({
        ...req.user.toObject(),
        effectivePlan: req.user.effectivePlan
    });
});


// --- ROUTES ADMIN ---

app.get('/api/admin/stats', protect, adminProtect, async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const patientCount = await Patient.countDocuments({ patientId: { $regex: /^save_/ } });
        const orgCount = await Organisation.countDocuments();
        const studentCount = await User.countDocuments({ role: 'etudiant' });
        const formateurCount = await User.countDocuments({ role: { $in: ['formateur', 'user', 'owner'] } });

        res.json({ userCount, patientCount, orgCount, studentCount, formateurCount });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/data', protect, adminProtect, async (req, res) => {
    try {
        const users = await User.find().select('-passwordHash').populate('organisation').populate('createdBy', 'email');
        const organisations = await Organisation.find().populate('owner', 'email');
        const scenarios = await Patient.find({ patientId: { $regex: /^save_/ } }).populate('user', 'email').select('patientId sidebar_patient_name is_public user');
        res.json({ users, organisations, scenarios });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:id', protect, adminProtect, async (req, res) => {
    try {
        const userId = req.params.id;
        await Patient.deleteMany({ user: userId });
        await User.deleteMany({ createdBy: userId });
        const user = await User.findById(userId);
        if (user && user.is_owner) {
             await Organisation.deleteOne({ owner: userId });
             await User.updateMany({ organisation: user.organisation }, { $set: { organisation: null, role: 'user', subscription: 'free' } });
        }
        await User.deleteOne({ _id: userId });
        res.json({ success: true, message: 'Utilisateur supprimé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- NOUVEAU : Route Admin pour supprimer un scénario ---
app.delete('/api/admin/scenarios/:id', protect, adminProtect, async (req, res) => {
    try {
        const result = await Patient.deleteOne({ patientId: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Scénario non trouvé.' });
        }
        res.json({ success: true, message: 'Scénario supprimé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/scenarios/:id/toggle-public', protect, adminProtect, async (req, res) => {
    try {
        const scenario = await Patient.findOne({ patientId: req.params.id });
        if(!scenario) return res.status(404).json({error: 'Scénario non trouvé'});
        scenario.is_public = !scenario.is_public;
        await scenario.save();
        res.json({ success: true, is_public: scenario.is_public });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- ROUTES COMPTE & API --- (Idem précédent)

app.get('/api/account/details', protect, async (req, res) => {
    if (req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const students = await User.find({ createdBy: req.user.resourceId }, 'login permissions allowedRooms');
        let organisationData = null;
        if (req.user.is_owner && req.user.organisation) {
            const formateurs = await User.find({ organisation: req.user.organisation._id, is_owner: false }, 'email');
            organisationData = { ...req.user.organisation.toObject(), formateurs: formateurs, licences_utilisees: formateurs.length + 1 };
        }
        res.json({ email: req.user.email, plan: req.user.effectivePlan, role: req.user.role, is_owner: req.user.is_owner, students: students, organisation: organisationData });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/account/change-password', protect, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const isMatch = await bcrypt.compare(currentPassword, req.user.passwordHash);
        if (!isMatch) return res.status(400).json({ error: 'Mot de passe incorrect.' });
        req.user.passwordHash = await bcrypt.hash(newPassword, 10);
        await req.user.save();
        res.json({ success: true, message: 'Mot de passe mis à jour.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/account/request-change-email', protect, async (req, res) => {
    try {
        const { newEmail, password } = req.body;
        const isMatch = await bcrypt.compare(password, req.user.passwordHash);
        if (!isMatch) return res.status(400).json({ error: 'Mot de passe incorrect.' });
        if (await User.findOne({ email: newEmail.toLowerCase() })) return res.status(400).json({ error: 'Email déjà utilisé.' });

        const token = crypto.randomBytes(32).toString('hex');
        req.user.newEmail = newEmail.toLowerCase();
        req.user.newEmailToken = token;
        req.user.newEmailTokenExpires = Date.now() + 3600000;
        await req.user.save();

        const verifyLink = `${req.protocol}://${req.get('host')}/api/account/verify-change-email?token=${token}`;
        await transporter.sendMail({
            from: `"EIdos" <${process.env.EMAIL_FROM}>`,
            to: newEmail,
            subject: 'Confirmez votre nouvelle adresse e-mail EIdos',
            html: `<h3>Bonjour,</h3><p>Cliquez ici pour confirmer : <a href="${verifyLink}">Confirmer</a></p>`
        });
        res.json({ success: true, message: `Email de vérification envoyé à ${newEmail}.` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/account/verify-change-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).send('Token manquant.');
        const user = await User.findOne({ newEmailToken: token, newEmailTokenExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).send('Lien invalide.');
        user.email = user.newEmail;
        user.newEmail = null;
        user.newEmailToken = null;
        user.newEmailTokenExpires = null;
        await user.save();
        res.send('<h1>Succès !</h1><p>Email mis à jour.</p>');
    } catch (err) { res.status(500).send('Erreur'); }
});

app.delete('/api/account/delete', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        await Patient.deleteMany({ user: req.user.resourceId });
        await User.deleteMany({ createdBy: userId });
        if (req.user.is_owner && req.user.organisation) {
            const orgId = req.user.organisation._id;
            await User.updateMany({ organisation: orgId }, { $set: { organisation: null, role: 'user', subscription: 'free' } });
            await Organisation.deleteOne({ _id: orgId });
        }
        await User.deleteOne({ _id: userId });
        res.json({ success: true, message: 'Compte supprimé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/account/invite', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login, password } = req.body;
        if (await User.findOne({ login: login.toLowerCase() })) return res.status(400).json({ error: 'Login utilisé.' });
        const studentCount = await User.countDocuments({ createdBy: req.user.resourceId });
        const limit = req.user.effectivePlan === 'independant' ? 5 : (req.user.effectivePlan === 'promo' ? 40 : 999);
        if (studentCount >= limit) return res.status(403).json({ error: 'Limite atteinte.' });

        const passwordHash = await bcrypt.hash(password, 10);
        const newStudent = new User({
            login: login.toLowerCase(),
            passwordHash,
            role: 'etudiant',
            subscription: 'free',
            createdBy: req.user.resourceId,
            isVerified: true,
            permissions: { header: true, admin: true, vie: true, observations: true, comptesRendus: true, prescriptions_add: true, prescriptions_delete: true, prescriptions_validate: true, transmissions: true, pancarte: true, diagramme: true, biologie: true },
            allowedRooms: Array.from({ length: 10 }, (_, i) => `chambre_${101 + i}`)
        });
        await newStudent.save();
        res.status(201).json({ success: true, message: 'Étudiant créé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/account/permissions', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login, permission, value } = req.body;
        const student = await User.findOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (!student) return res.status(404).json({ error: 'Non trouvé.' });
        if (!student.permissions) student.permissions = {};
        student.permissions[permission] = value;
        student.markModified('permissions');
        await student.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/account/student/rooms', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login, rooms } = req.body;
        const student = await User.findOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (!student) return res.status(404).json({ error: 'Non trouvé.' });
        student.allowedRooms = rooms;
        await student.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/account/student', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login } = req.body;
        const resDel = await User.deleteOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (resDel.deletedCount === 0) return res.status(404).json({ error: 'Non trouvé.' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/account/change-subscription', protect, async (req, res) => {
    try {
        const { newPlan } = req.body;
        const user = await User.findById(req.user._id);
        if (newPlan === 'centre') {
            if (user.organisation) return res.status(400).json({ error: "Déjà rattaché." });
            user.role = 'owner'; user.is_owner = true;
            const org = new Organisation({ name: `Centre de ${user.email}`, owner: user._id });
            await org.save();
            user.organisation = org._id;
        } else {
            user.subscription = newPlan; user.role = 'user'; user.is_owner = false; user.organisation = null;
        }
        await user.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/organisation/invite', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { email } = req.body;
        if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ error: 'Email existe.' });
        const count = await User.countDocuments({ organisation: req.user.organisation._id, role: 'formateur' });
        if (count >= req.user.organisation.licences_max) return res.status(403).json({ error: "Limite atteinte." });

        const token = crypto.randomBytes(32).toString('hex');
        const inv = new Invitation({ email: email.toLowerCase(), organisation: req.user.organisation._id, token: token });
        await inv.save();
        const link = `${process.env.FRONTEND_URL || `http://localhost:${PORT}`}/auth.html?invitation_token=${token}&email=${encodeURIComponent(email)}`;
        await transporter.sendMail({ from: `"EIdos" <${process.env.EMAIL_FROM}>`, to: email, subject: 'Invitation EIdos', html: `<a href="${link}">Rejoindre</a>` });
        res.status(200).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/organisation/remove', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { email } = req.body;
        const f = await User.findOne({ email: email.toLowerCase(), organisation: req.user.organisation._id, is_owner: false });
        if (!f) return res.status(404).json({ error: 'Non trouvé.' });
        f.organisation = null; f.role = 'user'; f.subscription = 'free';
        await f.save();
        res.status(200).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/patients', protect, async (req, res) => {
    try {
        if (req.user.role === 'etudiant') {
            const p = await Patient.find({ user: req.user.resourceId, patientId: { $in: req.user.allowedRooms } }, 'patientId sidebar_patient_name');
            return res.json(p);
        }
        const p = await Patient.find({ $or: [{ user: req.user.resourceId }, { is_public: true }] }, 'patientId sidebar_patient_name is_public');
        res.json(p);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patients/save', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { dossierData, sidebar_patient_name } = req.body;
        if (!sidebar_patient_name) return res.status(400).json({ error: 'Nom requis.' });

        const existing = await Patient.findOne({ user: req.user.resourceId, sidebar_patient_name: sidebar_patient_name, patientId: { $regex: /^save_/ } });
        if (existing) {
            await Patient.updateOne({ _id: existing._id }, { dossierData: dossierData });
            return res.json({ success: true });
        }
        
        const plan = req.user.effectivePlan;
        if (plan === 'independant' || plan === 'promo') {
            const count = await Patient.countDocuments({ user: req.user.resourceId, patientId: { $regex: /^save_/ }, is_public: { $ne: true } });
            const limit = plan === 'independant' ? 20 : 50;
            if (count >= limit) return res.status(403).json({ error: 'Limite atteinte.' });
        }

        const np = new Patient({ patientId: `save_${new mongoose.Types.ObjectId()}`, user: req.user.resourceId, dossierData: dossierData, sidebar_patient_name: sidebar_patient_name, is_public: false });
        await np.save();
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        let p = await Patient.findOne({ patientId: req.params.patientId, user: req.user.resourceId });
        if (!p && req.params.patientId.startsWith('save_')) p = await Patient.findOne({ patientId: req.params.patientId, is_public: true });
        if (!p && req.params.patientId.startsWith('chambre_')) {
            p = new Patient({ patientId: req.params.patientId, user: req.user.resourceId, sidebar_patient_name: `Chambre ${req.params.patientId.split('_')[1]}` });
            await p.save();
        } else if (!p) return res.status(404).json({ error: 'Non trouvé' });
        res.json(p.dossierData || {});
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        if (req.user.effectivePlan === 'free' && req.user.role !== 'etudiant') return res.status(403).json({ error: 'Plan Free.' });
        if (!req.params.patientId.startsWith('chambre_')) return res.status(400).json({ error: 'Chambres uniquement.' });

        const { dossierData, sidebar_patient_name } = req.body;
        const userId = req.user.resourceId;
        let finalData = dossierData;
        let updates = { sidebar_patient_name };

        if (req.user.role === 'etudiant') {
            const perms = req.user.permissions;
            const existing = await Patient.findOne({ patientId: req.params.patientId, user: userId });
            const merged = { ...(existing ? existing.dossierData : {}) };
            if (perms.header) {
                ['patient-nom-usage', 'patient-prenom', 'patient-dob', 'patient-motif', 'patient-entry-date'].forEach(k => { if (dossierData[k] !== undefined) merged[k] = dossierData[k]; });
                ['admin-nom-usage', 'admin-prenom', 'admin-dob'].forEach(ak => { const pk = ak.replace('admin-', 'patient-'); if (dossierData[pk] !== undefined) merged[ak] = dossierData[pk]; });
            }
            if (perms.admin) Object.keys(dossierData).filter(k => k.startsWith('admin-')).forEach(k => merged[k] = dossierData[k]);
            if (perms.vie) Object.keys(dossierData).filter(k => k.startsWith('vie-') || k.startsWith('atcd-')).forEach(k => merged[k] = dossierData[k]);
            ['observations', 'prescriptions', 'transmissions', 'comptesRendus', 'biologie'].forEach(k => { if (perms[k] || (k === 'prescriptions' && (perms.prescriptions_add || perms.prescriptions_delete || perms.prescriptions_validate))) merged[k] = dossierData[k]; });
            if (perms.pancarte) { merged.pancarte = dossierData.pancarte; merged.glycemie = dossierData.glycemie; }
            if (perms.diagramme) { merged['care-diagram-tbody_html'] = dossierData['care-diagram-tbody_html']; merged.careDiagramCheckboxes = dossierData.careDiagramCheckboxes; }
            finalData = merged;
        }

        await Patient.findOneAndUpdate({ patientId: req.params.patientId, user: userId }, { dossierData: finalData, ...updates, user: userId }, { upsert: true, new: true, setDefaultsOnInsert: true });
        
        try {
            const sender = req.headers['x-socket-id'];
            const room = `room_${userId}`;
            const sockets = await io.in(room).fetchSockets();
            const s = sockets.find(s => s.id === sender);
            const evt = { patientId: req.params.patientId, dossierData: finalData, sender };
            if (s) s.to(room).emit('patient_updated', evt); else io.to(room).emit('patient_updated', evt);
        } catch (e) {}
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/patients/:patientId', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const pid = req.params.patientId;
        const uid = req.user.resourceId;
        if (pid.startsWith('chambre_')) {
            await Patient.findOneAndUpdate({ patientId: pid, user: uid }, { dossierData: {}, sidebar_patient_name: `Chambre ${pid.split('_')[1]}` }, { upsert: true });
            io.to(`room_${uid}`).emit('patient_updated', { patientId: pid, dossierData: {} });
            res.json({ success: true });
        } else if (pid.startsWith('save_')) {
            await Patient.deleteOne({ patientId: pid, user: uid });
            res.json({ success: true });
        } else res.status(400).json({ error: 'ID invalide.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/webhook/payment-received', express.raw({ type: 'application/json' }), async (req, res) => { res.json({ received: true }); });

mongoose.connect(MONGO_URI).then(() => { console.log('✅ MongoDB connecté'); httpServer.listen(PORT, () => console.log(`🚀 Port ${PORT}`)); }).catch(e => console.error(e));