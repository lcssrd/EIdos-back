const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet'); // NOUVEAU : Import Helmet
const rateLimit = require('express-rate-limit'); // NOUVEAU : Import Rate Limit

// Importations pour Socket.io
const http = require('http');
const { Server } = require("socket.io");

// --- CONFIGURATION ---
const app = express();

// NOUVEAU : Sécurisation des en-têtes HTTP avec Helmet
app.use(helmet());

// Render (et d'autres load balancers) ajoute le header 'x-forwarded-proto'
app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'http') {
        // Si la requête est en HTTP, on redirige vers HTTPS
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    // Sinon (HTTPS ou localhost), on continue
    next();
});

// LISTE DES ORIGINES AUTORISÉES (Whitelist)
const allowedOrigins = [
    'https://eidos-simul.fr',       // Votre production OVH
    'https://www.eidos-simul.fr',   // Variante www
    'https://eidos-app.vercel.app',   // Variante site
    'https://eidos-simul.pages.dev', // Variante Pages
    'https://eidos-simul.onrender.com', // Variante Render
];

// Configuration CORS pour Express (API REST)
app.use(cors({
    origin: function (origin, callback) {
        // Autoriser les requêtes sans origine (ex: Postman, mobile apps) ou si dans la liste
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Non autorisé par CORS'));
        }
    },
    credentials: true // Important si vous utilisez des cookies ou headers sécurisés
}));

// NOUVEAU : Limitation de la taille du payload JSON à 1mb (Protection DoS)
app.use(express.json({ limit: '1mb' }));

// NOUVEAU : Configuration du Rate Limiting (Limitation de débit)

// 1. Limiteur strict pour l'authentification (Login/Signup/Verify)
// Pour éviter le brute-force sur les mots de passe ou l'envoi massif d'emails
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limite chaque IP à 20 requêtes par fenêtre de 15 min
    standardHeaders: true, // Retourne les infos de limite dans les headers `RateLimit-*`
    legacyHeaders: false, // Désactive les headers `X-RateLimit-*`
    message: { error: "Trop de tentatives de connexion, veuillez réessayer dans 15 minutes." }
});

// 2. Limiteur global pour l'API
// Pour protéger les ressources serveur
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // Limite chaque IP à 300 requêtes par fenêtre (environ 1 requête toutes les 3 sec en moyenne)
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Trop de requêtes à l'API, veuillez ralentir." }
});

// Application des limiteurs aux routes spécifiques
// On applique le limiteur AVANT la définition des routes
app.use('/auth', authLimiter);
app.use('/api', apiLimiter);


// Création du serveur HTTP et de l'instance Socket.io
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
    cors: {
        // Configuration CORS spécifique pour les WebSockets
        origin: allowedOrigins,
        methods: ["GET", "POST"],
        credentials: true
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
    is_super_admin: { type: Boolean, default: false },
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
    newEmailTokenExpires: { type: Date, default: null },
    // NOUVEAU : Champs pour la récupération de mot de passe
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null }
});
const User = mongoose.model('User', userSchema);

const patientSchema = new mongoose.Schema({
    patientId: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Créateur
    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} },
    isPublic: { type: Boolean, default: false }
});
patientSchema.index({ patientId: 1, user: 1 }, { unique: true });
const Patient = mongoose.model('Patient', patientSchema);


// --- MIDDLEWARES ---

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

        // Auto-correction du rôle pour les anciens comptes
        if (user.role === 'user' && (user.subscription === 'independant' || user.subscription === 'promo')) {
            console.log(`Auto-correction rôle pour ${user.email}: user -> formateur`);
            user.role = 'formateur';
            await user.save();
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

const checkAdmin = (req, res, next) => {
    if (req.user && req.user.is_super_admin === true) {
        next();
    } else {
        res.status(403).json({ error: 'Accès refusé. Réservé au Super Administrateur.' });
    }
};

// --- SOCKET.IO ---
io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentification échouée'));
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
        return next(new Error('Authentification échouée'));
    }
});

io.on('connection', (socket) => {
    const roomName = `room_${socket.resourceId}`;
    socket.join(roomName);
    socket.on('disconnect', () => { });
});


// --- ROUTES API ---

app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, plan, token } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Requis' });
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: 'Email pris' });
        const passwordHash = await bcrypt.hash(password, 10);
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();

        if (token) {
            const invitation = await Invitation.findOne({ token: token, email: email.toLowerCase() }).populate('organisation');
            if (!invitation || invitation.expires_at < Date.now()) return res.status(400).json({ error: "Invitation invalide" });
            const formateurCount = await User.countDocuments({ organisation: invitation.organisation._id, role: 'formateur' });
            if (formateurCount >= invitation.organisation.licences_max) return res.status(403).json({ error: "Max atteint" });

            const newUser = new User({ email: email.toLowerCase(), passwordHash, isVerified: true, role: 'formateur', subscription: 'promo', organisation: invitation.organisation._id, is_owner: false });
            await newUser.save();
            await Invitation.deleteOne({ _id: invitation._id });
            return res.status(201).json({ success: true, verified: true });
        } else {
            let newUser;
            const validPlans = ['free', 'independant', 'promo', 'centre'];
            let finalSubscription = plan && validPlans.includes(plan) ? plan : 'free';

            if (finalSubscription === 'centre') {
                newUser = new User({ email: email.toLowerCase(), passwordHash, confirmationCode, role: 'owner', subscription: 'free', is_owner: true });
                await newUser.save();
                const newOrg = new Organisation({ name: `Centre de ${email}`, owner: newUser._id, quote_url: "https://stripe.com", quote_price: "Devis", is_active: false });
                await newOrg.save();
                newUser.organisation = newOrg._id;
                await newUser.save();
            } else {
                let role = 'user';
                if (finalSubscription === 'independant' || finalSubscription === 'promo') {
                    role = 'formateur';
                }
                newUser = new User({ email: email.toLowerCase(), passwordHash, confirmationCode, role: role, subscription: finalSubscription });
                await newUser.save();
            }
            try {
                await transporter.sendMail({ from: `"EIdos-simul" <${process.env.EMAIL_FROM}>`, to: email, subject: 'Vérification EIdos-simul', html: `Code: <b>${confirmationCode}</b>` });
            } catch (e) { console.error(e); }
            return res.status(201).json({ success: true, verified: false });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/resend-code', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.confirmationCode = confirmationCode;
        await user.save();
        await transporter.sendMail({ from: `"EIdos-simul" <${process.env.EMAIL_FROM}>`, to: email, subject: 'Nouveau code', html: `Code: <b>${confirmationCode}</b>` });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || user.confirmationCode !== code) return res.status(400).json({ error: 'Code invalide' });

        // Validation de l'utilisateur
        user.isVerified = true;
        user.confirmationCode = undefined;
        await user.save();

        // GÉNÉRATION DU TOKEN (Connexion automatique)
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

        // On renvoie le token au frontend
        res.json({ success: true, token });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        let user;
        const anID = identifier.toLowerCase();
        if (anID.includes('@')) user = await User.findOne({ email: anID });
        else user = await User.findOne({ login: anID });
        if (!user || !await bcrypt.compare(password, user.passwordHash)) return res.status(401).json({ error: 'Invalide' });
        if ((user.role === 'user' || user.role === 'owner' || user.role === 'formateur') && !user.isVerified) return res.status(401).json({ error: 'Non vérifié' });
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- NOUVEAU : ROUTES MOT DE PASSE OUBLIÉ ---

app.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email requis' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });

        // Générer un code simple à 6 chiffres
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetPasswordToken = code;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 heure
        await user.save();

        // Envoyer l'email
        await transporter.sendMail({
            from: `"EIdos-simul" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Réinitialisation de mot de passe EIdos-simul',
            html: `
                <h3>Réinitialisation de mot de passe</h3>
                <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
                <p>Votre code de vérification est : <b>${code}</b></p>
                <p>Ce code expire dans 1 heure.</p>
                <p>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
            `
        });

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erreur lors de l'envoi de l'email." });
    }
});

app.post('/auth/reset-password', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        if (!email || !code || !newPassword) return res.status(400).json({ error: 'Tous les champs sont requis' });

        const user = await User.findOne({
            email: email.toLowerCase(),
            resetPasswordToken: code,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ error: 'Code invalide ou expiré' });

        user.passwordHash = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;
        await user.save();

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------------------------------------------

app.get('/api/auth/me', protect, async (req, res) => {
    res.json({ ...req.user.toObject(), effectivePlan: req.user.effectivePlan });
});

// --- ROUTES ACCOUNT ---
app.get('/api/account/details', protect, async (req, res) => {
    if (req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });

    const students = await User.find({ createdBy: req.user.resourceId }, 'login permissions allowedRooms');
    let organisationData = null;

    if (req.user.is_owner && req.user.organisation) {
        const formateurs = await User.find({ organisation: req.user.organisation._id, is_owner: false }, 'email');
        const invitations = await Invitation.find({ organisation: req.user.organisation._id });

        organisationData = {
            ...req.user.organisation.toObject(),
            formateurs,
            invitations,
            licences_utilisees: formateurs.length + 1
        };
    }

    res.json({
        email: req.user.email,
        plan: req.user.effectivePlan,
        role: req.user.role,
        is_owner: req.user.is_owner,
        is_super_admin: req.user.is_super_admin,
        students,
        organisation: organisationData
    });
});

app.post('/api/account/change-password', protect, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!await bcrypt.compare(currentPassword, req.user.passwordHash)) return res.status(400).json({ error: 'Mot de passe incorrect' });
    req.user.passwordHash = await bcrypt.hash(newPassword, 10); await req.user.save();
    res.json({ success: true });
});

app.post('/api/account/request-change-email', protect, async (req, res) => {
    const { newEmail, password } = req.body;
    if (!await bcrypt.compare(password, req.user.passwordHash)) return res.status(400).json({ error: 'Incorrect' });
    const token = crypto.randomBytes(32).toString('hex');
    req.user.newEmail = newEmail.toLowerCase(); req.user.newEmailToken = token; req.user.newEmailTokenExpires = Date.now() + 3600000;
    await req.user.save();
    const verifyLink = `${req.protocol}://${req.get('host')}/api/account/verify-change-email?token=${token}`;
    await transporter.sendMail({ from: `"EIdos-simul" <${process.env.EMAIL_FROM}>`, to: newEmail, subject: 'Confirmer email', html: `<a href="${verifyLink}">Confirmer</a>` });
    res.json({ success: true });
});

app.get('/api/account/verify-change-email', async (req, res) => {
    const { token } = req.query;
    const user = await User.findOne({ newEmailToken: token, newEmailTokenExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).send('Invalide');
    user.email = user.newEmail; user.newEmail = null; await user.save();
    res.send('Email changé.');
});

app.delete('/api/account/delete', protect, async (req, res) => {
    await Patient.deleteMany({ user: req.user.resourceId });
    await User.deleteMany({ createdBy: req.user._id });
    if (req.user.is_owner && req.user.organisation) {
        await User.updateMany({ organisation: req.user.organisation._id }, { $set: { organisation: null, role: 'user', subscription: 'free' } });
        await Organisation.deleteOne({ _id: req.user.organisation._id });
    }
    await User.deleteOne({ _id: req.user._id });
    res.json({ success: true });
});

app.post('/api/account/invite', protect, async (req, res) => {
    const { login, password } = req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ login: login.toLowerCase(), passwordHash, role: 'etudiant', subscription: 'free', createdBy: req.user.resourceId, isVerified: true, permissions: {}, allowedRooms: [] });
    await newUser.save();
    res.status(201).json({ success: true });
});

app.put('/api/account/permissions', protect, async (req, res) => {
    const { login, permission, value } = req.body;
    await User.updateOne({ login: login.toLowerCase(), createdBy: req.user.resourceId }, { [`permissions.${permission}`]: value });
    res.json({ success: true });
});

app.put('/api/account/student/rooms', protect, async (req, res) => {
    const { login, rooms } = req.body;
    await User.updateOne({ login: login.toLowerCase(), createdBy: req.user.resourceId }, { allowedRooms: rooms });
    res.json({ success: true });
});

app.delete('/api/account/student', protect, async (req, res) => {
    await User.deleteOne({ login: req.body.login.toLowerCase(), createdBy: req.user.resourceId });
    res.json({ success: true });
});

app.post('/api/account/change-subscription', protect, async (req, res) => {
    const newPlan = req.body.newPlan;
    req.user.subscription = newPlan;
    req.user.organisation = null;

    if (newPlan === 'independant' || newPlan === 'promo') {
        req.user.role = 'formateur';
    } else {
        req.user.role = 'user';
    }

    await req.user.save();
    res.json({ success: true });
});

app.post('/api/organisation/invite', protect, async (req, res) => {
    try {
        const token = crypto.randomBytes(32).toString('hex');
        const email = req.body.email.toLowerCase();
        await new Invitation({ email: email, organisation: req.user.organisation._id, token }).save();

        const baseUrl = 'https://eidos-simul.fr';
        const inviteLink = `${baseUrl}/auth.html?invitation_token=${token}&email=${email}`;

        await transporter.sendMail({
            from: `"EIdos-simul" <${process.env.EMAIL_FROM}>`,
            to: email,
            subject: 'Invitation à rejoindre EIdos-simul',
            html: `
                <h3>Bonjour,</h3>
                <p>Vous avez été invité à rejoindre un centre de formation sur EIdos-simul.</p>
                <p>Pour accepter l'invitation et finaliser votre inscription, cliquez sur le lien ci-dessous :</p>
                <p><a href="${inviteLink}">Accepter l'invitation</a></p>
                <p>Ce lien est valable 7 jours.</p>
            `
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Erreur envoi invitation:", err);
        res.status(500).json({ error: "Erreur lors de l'envoi de l'invitation." });
    }
});

app.delete('/api/organisation/invite/:id', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) return res.status(403).json({ error: 'Non autorisé' });
    try {
        const invitationId = req.params.id;
        const result = await Invitation.deleteOne({ _id: invitationId, organisation: req.user.organisation._id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Invitation introuvable ou déjà supprimée." });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/organisation/remove', protect, async (req, res) => {
    await User.updateOne({ email: req.body.email.toLowerCase(), organisation: req.user.organisation._id }, { organisation: null, role: 'user', subscription: 'free' });
    res.json({ success: true });
});


// --- ROUTES ADMIN ---

app.get('/api/admin/structure', protect, checkAdmin, async (req, res) => {
    try {
        const organisations = await Organisation.find({}, 'name plan licences_max licences_utilisees owner');
        const independants = await User.find({
            role: { $in: ['user', 'formateur'] },
            organisation: null,
            is_owner: false,
            role: { $ne: 'etudiant' }
        }, 'email subscription isVerified');

        res.json({ organisations, independants });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/centre/:orgId/formateurs', protect, checkAdmin, async (req, res) => {
    try {
        const formateurs = await User.find({ organisation: req.params.orgId }, 'email role is_owner subscription');
        res.json(formateurs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/creator/:creatorId/students', protect, checkAdmin, async (req, res) => {
    try {
        const students = await User.find({ createdBy: req.params.creatorId, role: 'etudiant' }, 'login permissions allowedRooms');
        res.json(students);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/user/:userId', protect, checkAdmin, async (req, res) => {
    try {
        const targetUser = await User.findById(req.params.userId);
        if (!targetUser) return res.status(404).json({ error: "Utilisateur non trouvé" });

        if (targetUser.is_owner && targetUser.organisation) {
            await Organisation.deleteOne({ _id: targetUser.organisation });
            await User.updateMany({ organisation: targetUser.organisation }, { organisation: null, role: 'user', subscription: 'free' });
        }

        await Patient.deleteMany({ user: targetUser._id });
        await User.deleteMany({ createdBy: targetUser._id });
        await User.deleteOne({ _id: targetUser._id });

        res.json({ success: true, message: "Utilisateur et données associées supprimés." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/patients', protect, checkAdmin, async (req, res) => {
    try {
        const patients = await Patient.find({ patientId: { $regex: /^save_/ } })
            .populate('user', 'email login')
            .select('patientId sidebar_patient_name isPublic user');
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/patients/:id/public', protect, checkAdmin, async (req, res) => {
    try {
        const patient = await Patient.findOne({ patientId: req.params.id });
        if (!patient) return res.status(404).json({ error: "Dossier non trouvé" });

        patient.isPublic = !patient.isPublic;
        await patient.save();
        res.json({ success: true, isPublic: patient.isPublic });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/patients/:id', protect, checkAdmin, async (req, res) => {
    try {
        await Patient.deleteOne({ patientId: req.params.id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- ROUTES PATIENTS ---

app.get('/api/patients', protect, async (req, res) => {
    try {
        const baseQuery = { user: req.user.resourceId };
        if (req.user.role === 'etudiant') {
            baseQuery.patientId = { $in: req.user.allowedRooms };
        }
        const publicQuery = { isPublic: true, patientId: { $regex: /^save_/ } };

        const patients = await Patient.find(
            { $or: [baseQuery, publicQuery] },
            'patientId sidebar_patient_name isPublic user'
        ).populate('user', 'email');

        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/patients/save', protect, async (req, res) => {
    // Sauvegarde archive : Interdit aux 'user' (Free) et 'etudiant'
    if (req.user.role === 'etudiant' || req.user.role === 'user') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    try {
        const { dossierData, sidebar_patient_name } = req.body;
        if (!sidebar_patient_name || sidebar_patient_name.startsWith('Chambre ')) return res.status(400).json({ error: 'Nom requis' });

        const existingSave = await Patient.findOne({
            user: req.user.resourceId,
            sidebar_patient_name: sidebar_patient_name,
            patientId: { $regex: /^save_/ }
        });

        if (existingSave) {
            await Patient.updateOne({ _id: existingSave._id }, { dossierData: dossierData });
            res.json({ success: true, message: 'Mise à jour OK.' });
        } else {
            const plan = req.user.effectivePlan;

            if (plan === 'independant' || plan === 'promo') {
                const saveCount = await Patient.countDocuments({
                    user: req.user.resourceId,
                    patientId: { $regex: /^save_/ },
                    isPublic: false
                });
                let limit = (plan === 'independant') ? 20 : 50;
                if (saveCount >= limit) return res.status(403).json({ error: `Limite atteinte (${limit}).` });
            }

            const newPatientId = `save_${new mongoose.Types.ObjectId()}`;
            const newPatient = new Patient({
                patientId: newPatientId,
                user: req.user.resourceId,
                dossierData: dossierData,
                sidebar_patient_name: sidebar_patient_name,
                isPublic: false
            });
            await newPatient.save();
            res.status(201).json({ success: true, message: 'Sauvegardé.' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/patients/:patientId', protect, async (req, res) => {
    // Suppression : Interdit aux 'user' (Free) et 'etudiant'
    if (req.user.role === 'etudiant' || req.user.role === 'user') return res.status(403).json({ error: 'Non autorisé' });

    try {
        const patientId = req.params.patientId;

        if (patientId.startsWith('chambre_')) {
            await Patient.findOneAndUpdate({ patientId: patientId, user: req.user.resourceId }, { dossierData: {}, sidebar_patient_name: `Chambre ${patientId.split('_')[1]}` }, { upsert: true });
            try { io.to(`room_${req.user.resourceId}`).emit('patient_updated', { patientId, dossierData: {} }); } catch (e) { }
            res.json({ success: true });
        } else if (patientId.startsWith('save_')) {

            const patient = await Patient.findOne({ patientId: patientId });
            if (!patient) return res.status(404).json({ error: "Introuvable" });

            if (patient.isPublic && req.user.is_super_admin !== true) {
                return res.status(403).json({ error: "Impossible de supprimer un dossier Public." });
            }

            if (patient.user.toString() !== req.user.resourceId.toString() && req.user.is_super_admin !== true) {
                return res.status(403).json({ error: "Ce dossier ne vous appartient pas." });
            }

            await Patient.deleteOne({ _id: patient._id });
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'ID invalide' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        const patientId = req.params.patientId;
        const userId = req.user.resourceId;

        // --- CORRECTION CRITIQUE : RECHERCHE SCOPÉE ---
        // 1. On cherche d'abord si CE patient appartient à l'utilisateur
        let patient = await Patient.findOne({ patientId: patientId, user: userId });

        // 2. Si non trouvé et que c'est une sauvegarde, on regarde si c'est un dossier public
        if (!patient && patientId.startsWith('save_')) {
            patient = await Patient.findOne({ patientId: patientId, isPublic: true });
        }

        // 3. Si trouvé (soit à l'user, soit public), on le renvoie
        if (patient) {
            // Vérification redondante mais sécurisante (au cas où le findOne changerait)
            const belongsToUser = (patient.user.toString() === userId.toString());
            const isPublic = patient.isPublic;
            if (!belongsToUser && !isPublic && req.user.is_super_admin !== true) {
                return res.status(403).json({ error: 'Accès refusé' });
            }
        }

        // 4. Auto-création pour les chambres si non trouvé
        if (!patient && patientId.startsWith('chambre_')) {
            patient = new Patient({
                patientId: patientId,
                user: userId,
                sidebar_patient_name: `Chambre ${patientId.split('_')[1]}`
            });
            await patient.save();
        } else if (!patient) {
            return res.status(404).json({ error: 'Dossier non trouvé' });
        }

        res.json(patient.dossierData || {});
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        if (!req.params.patientId.startsWith('chambre_')) return res.status(400).json({ error: 'Chambres uniquement' });

        if (req.user.role === 'user') {
            return res.status(403).json({ error: "Modification interdite pour le plan gratuit." });
        }

        const { dossierData, sidebar_patient_name } = req.body;
        const userIdToSave = req.user.resourceId;
        let finalDossierData = dossierData;
        let sidebarUpdate = {};
        if (req.user.role === 'etudiant') {
            const permissions = req.user.permissions;
            const existing = await Patient.findOne({ patientId: req.params.patientId, user: userIdToSave });
            const merged = { ...(existing ? existing.dossierData : {}) };
            finalDossierData = dossierData;
            if (permissions.header) { sidebarUpdate = { sidebar_patient_name }; }
        } else {
            sidebarUpdate = { sidebar_patient_name };
        }

        await Patient.findOneAndUpdate({ patientId: req.params.patientId, user: userIdToSave }, { dossierData: finalDossierData, ...sidebarUpdate, user: userIdToSave }, { upsert: true, new: true });

        try {
            const sId = req.headers['x-socket-id'];
            const room = `room_${userIdToSave}`;
            const socks = await io.in(room).fetchSockets();
            const sender = socks.find(s => s.id === sId);
            if (sender) sender.to(room).emit('patient_updated', { patientId: req.params.patientId, dossierData: finalDossierData, sender: sId });
            else io.to(room).emit('patient_updated', { patientId: req.params.patientId, dossierData: finalDossierData, sender: sId });
        } catch (e) { }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/webhook/payment-received', express.raw({ type: 'application/json' }), async (req, res) => { res.json({ received: true }); });

mongoose.connect(MONGO_URI).then(() => { console.log('✅ MongoDB Connecté'); httpServer.listen(PORT, () => console.log(`🚀 Serveur sur port ${PORT}`)); }).catch(e => console.error(e));