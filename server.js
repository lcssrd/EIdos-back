const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const http = require('http'); // AJOUTÉ : Nécessaire pour Socket.io
const { Server } = require("socket.io"); // AJOUTÉ : Import de Socket.io

// --- CONFIGURATION ---
const app = express();
const server = http.createServer(app); // AJOUTÉ : Création du serveur HTTP
const io = new Server(server, { // AJOUTÉ : Initialisation de Socket.io
    cors: {
        origin: "*", // Autorise toutes les origines, comme votre app.use(cors())
        methods: ["GET", "POST"]
    }
});

app.use(cors()); 
app.use(express.json());

// LECTURE DES VARIABLES D'ENVIRONNEMENT
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI; 
const JWT_SECRET = process.env.JWT_SECRET; 

// --- CONFIGURATION SIMULÉE DE NODEMAILER ---
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'reyna.vonrueden@ethereal.email',
        pass: 'JqXN2AMJ9xnmZ2N4Gg'
    }
});
console.log("Pour voir les e-mails de test, allez sur : https://ethereal.email/login");

// --- MODÈLES DE DONNÉES (SCHEMAS) ---
// ... (Organisation, Invitation Schemas - Inchangés)
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
    expires_at: { type: Date, default: () => Date.now() + 7*24*60*60*1000 }
});
const Invitation = mongoose.model('Invitation', invitationSchema);

// ... (User Schema - Inchangé par rapport à la modif précédente)
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
        enum: ['free', 'independant', 'promo', null], 
        default: null 
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

// ... (Patient Schema - Inchangé)
const patientSchema = new mongoose.Schema({
    patientId: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} }
});
patientSchema.index({ patientId: 1, user: 1 }, { unique: true });
const Patient = mongoose.model('Patient', patientSchema);


// --- Middleware de sécurité (Inchangé) ---
const protect = async (req, res, next) => {
    // ... (Logique du middleware 'protect' inchangée)
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
        } else if (user.role === 'formateur' && user.organisation) {
            req.user.resourceId = user.organisation.owner;
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

// --- ROUTES D'AUTHENTIFICATION (Inchangées) ---
// ... (POST /auth/signup)
// ... (POST /auth/verify)
// ... (POST /auth/login)
// ... (GET /api/auth/me)
app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, plan, token } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        const passwordHash = await bcrypt.hash(password, 10);
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();
        let newUser;
        if (token) {
            const invitation = await Invitation.findOne({ token: token, email: email.toLowerCase() }).populate('organisation');
            if (!invitation || invitation.expires_at < Date.now()) return res.status(400).json({ error: "Token d'invitation invalide ou expiré." });
            const formateurCount = await User.countDocuments({ organisation: invitation.organisation._id, role: 'formateur' });
            if (formateurCount >= invitation.organisation.licences_max) return res.status(403).json({ error: "Le nombre maximum de formateurs pour ce centre a été atteint." });
            newUser = new User({ email: email.toLowerCase(), passwordHash, isVerified: true, role: 'formateur', subscription: null, organisation: invitation.organisation._id, is_owner: false });
            await newUser.save();
            await Invitation.deleteOne({ _id: invitation._id });
        } else {
            const validPlans = ['free', 'independant', 'promo', 'centre'];
            let finalSubscription = 'free';
            if (plan && validPlans.includes(plan)) finalSubscription = plan;
            if (finalSubscription === 'centre') {
                newUser = new User({ email: email.toLowerCase(), passwordHash, confirmationCode, isVerified: false, role: 'owner', subscription: null, is_owner: true });
                await newUser.save();
                const newOrganisation = new Organisation({ name: `Centre de ${email}`, owner: newUser._id, is_active: false, quote_url: "https://votre-site.com/lien-admin-a-remplir", quote_price: "Devis en attente" });
                await newOrganisation.save();
                newUser.organisation = newOrganisation._id;
                await newUser.save();
            } else {
                newUser = new User({ email: email.toLowerCase(), passwordHash, confirmationCode, isVerified: false, role: 'user', subscription: finalSubscription });
                await newUser.save();
            }
        }
        if (!token) console.log(`CODE DE VÉRIFICATION pour ${email}: ${confirmationCode}`);
        res.status(201).json({ success: true, message: 'Utilisateur créé. Veuillez vérifier votre email.', _test_code: token ? null : confirmationCode });
    } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});
app.post('/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'Email et code requis' });
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(400).json({ error: 'Utilisateur non trouvé' });
        if (user.isVerified) return res.status(400).json({ error: 'Email déjà vérifié' });
        if (user.confirmationCode !== code) return res.status(400).json({ error: 'Code de vérification invalide' });
        user.isVerified = true;
        user.confirmationCode = undefined;
        await user.save();
        res.json({ success: true, message: 'Email vérifié avec succès !' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        let user;
        const anID = identifier.toLowerCase();
        if (anID.includes('@')) user = await User.findOne({ email: anID });
        else user = await User.findOne({ login: anID });
        if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(401).json({ error: 'Identifiants invalides' });
        if ((user.role === 'user' || user.role === 'owner') && !user.isVerified) return res.status(401).json({ error: 'Veuillez d\'abord vérifier votre email.' });
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token: token });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/auth/me', protect, async (req, res) => {
    res.json({ ...req.user.toObject(), effectivePlan: req.user.effectivePlan });
});

// --- ROUTES DE GESTION DE COMPTE (Inchangées) ---
// ... (GET /api/account/details)
// ... (POST /api/account/change-password)
// ... (POST /api/account/request-change-email)
// ... (GET /api/account/verify-change-email)
// ... (DELETE /api/account/delete)
// ... (POST /api/account/invite)
// ... (PUT /api/account/permissions)
// ... (PUT /api/account/student/rooms)
// ... (DELETE /api/account/student)
// ... (POST /api/account/change-subscription)
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
        if (!isMatch) return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        req.user.passwordHash = await bcrypt.hash(newPassword, 10);
        await req.user.save();
        res.json({ success: true, message: 'Mot de passe mis à jour.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/account/request-change-email', protect, async (req, res) => {
    try {
        const { newEmail, password } = req.body;
        const user = req.user;
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        const existingUser = await User.findOne({ email: newEmail.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: 'Cette adresse e-mail est déjà utilisée.' });
        const token = crypto.randomBytes(32).toString('hex');
        user.newEmail = newEmail.toLowerCase();
        user.newEmailToken = token;
        user.newEmailTokenExpires = Date.now() + 3600000;
        await user.save();
        const verifyLink = `http://localhost:${PORT}/api/account/verify-change-email?token=${token}`;
        console.log('--- SIMULATION D\'ENVOI D\'EMAIL DE CHANGEMENT ---');
        console.log(`À: ${newEmail}`);
        console.log(`Sujet: Confirmez votre nouvelle adresse e-mail EIdos`);
        console.log(`Corps: ... cliquez sur ce lien pour confirmer : ${verifyLink}`);
        console.log('-----------------------------------');
        res.json({ success: true, message: `Un e-mail de vérification a été envoyé à ${newEmail}.` });
    } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});
app.get('/api/account/verify-change-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).send('Token manquant.');
        const user = await User.findOne({ newEmailToken: token, newEmailTokenExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).send('<h1>Erreur</h1><p>Ce lien est invalide ou a expiré.</p>');
        user.email = user.newEmail;
        user.newEmail = null;
        user.newEmailToken = null;
        user.newEmailTokenExpires = null;
        await user.save();
        res.send('<h1>Succès !</h1><p>Votre adresse e-mail a été mise à jour. Vous pouvez fermer cet onglet et vous reconnecter.</p>');
    } catch (err) { res.status(500).send('<h1>Erreur</h1><p>Une erreur est survenue.</p>'); }
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
        res.json({ success: true, message: 'Compte supprimé avec succès.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/account/invite', protect, async (req, res) => {
    if (req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    if (req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const studentCount = await User.countDocuments({ createdBy: req.user.resourceId });
        if (req.user.effectivePlan === 'independant' && studentCount >= 5) return res.status(403).json({ error: 'Limite de 5 étudiants atteinte pour le plan Indépendant.' });
        if (req.user.effectivePlan === 'promo' && studentCount >= 40) return res.status(403).json({ error: 'Limite de 40 étudiants atteinte pour le plan Promo.' });
        const { login, password } = req.body;
        const existingStudent = await User.findOne({ login: login.toLowerCase() });
        if (existingStudent) return res.status(400).json({ error: 'Ce login est déjà utilisé.' });
        const passwordHash = await bcrypt.hash(password, 10);
        const defaultPermissions = { header: true, admin: true, vie: true, observations: true, comptesRendus: true, prescriptions_add: true, prescriptions_delete: true, prescriptions_validate: true, transmissions: true, pancarte: true, diagramme: true, biologie: true };
        const defaultRooms = Array.from({ length: 10 }, (_, i) => `chambre_${101 + i}`);
        const newStudent = new User({ login: login.toLowerCase(), passwordHash: passwordHash, role: 'etudiant', subscription: null, createdBy: req.user.resourceId, isVerified: true, permissions: defaultPermissions, allowedRooms: defaultRooms });
        await newStudent.save();
        res.status(201).json({ success: true, message: 'Compte étudiant créé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/account/permissions', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login, permission, value } = req.body;
        const student = await User.findOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (!student) return res.status(404).json({ error: 'Étudiant non trouvé' });
        if (!student.permissions) student.permissions = {};
        student.permissions[permission] = value;
        student.markModified('permissions');
        await student.save();
        res.json({ success: true, message: 'Permission mise à jour.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/account/student/rooms', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login, rooms } = req.body;
        const student = await User.findOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (!student) return res.status(404).json({ error: 'Étudiant non trouvé' });
        if (!Array.isArray(rooms) || !rooms.every(r => typeof r === 'string' && r.startsWith('chambre_'))) return res.status(400).json({ error: 'Format de chambres non valide.' });
        student.allowedRooms = rooms;
        await student.save();
        res.json({ success: true, message: 'Chambres autorisées mises à jour.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/account/student', protect, async (req, res) => {
    if (req.user.effectivePlan === 'free' || req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { login } = req.body;
        const result = await User.deleteOne({ login: login.toLowerCase(), createdBy: req.user.resourceId });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Étudiant non trouvé' });
        res.json({ success: true, message: 'Compte étudiant supprimé.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/account/change-subscription', protect, async (req, res) => {
    try {
        const { newPlan } = req.body;
        const validPlans = ['free', 'independant', 'promo', 'centre'];
        if (!newPlan || !validPlans.includes(newPlan)) return res.status(400).json({ error: 'Plan non valide.' });
        if (req.user.role === 'etudiant') return res.status(403).json({ error: 'Non autorisé.' });
        const user = await User.findById(req.user._id);
        if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé.' });
        if (newPlan === 'centre') {
            if (user.organisation) return res.status(400).json({ error: "Vous êtes déjà rattaché à un centre." });
            user.role = 'owner';
            user.is_owner = true;
            const newOrganisation = new Organisation({ name: `Centre de ${user.email}`, owner: user._id, is_active: false, quote_url: "https://votre-site.com/lien-admin-a-remplir", quote_price: "Devis en attente" });
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- ROUTES D'ORGANISATION (Inchangées) ---
// ... (POST /api/organisation/invite)
// ... (POST /api/organisation/remove)
app.post('/api/organisation/invite', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) return res.status(403).json({ error: 'Non autorisé (réservé aux propriétaires de centre).' });
    try {
        const { email } = req.body;
        const organisation = req.user.organisation;
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: 'Un utilisateur avec cet e-mail existe déjà.' });
        const formateurCount = await User.countDocuments({ organisation: organisation._id, role: 'formateur' });
        if (formateurCount >= organisation.licences_max) return res.status(403).json({ error: "La limite de formateurs pour votre centre a été atteinte." });
        const token = crypto.randomBytes(32).toString('hex');
        const invitation = new Invitation({ email: email.toLowerCase(), organisation: organisation._id, token: token });
        await invitation.save();
        const inviteLink = `http://localhost:${PORT}/auth.html?invitation_token=${token}`;
        console.log('--- SIMULATION D\'ENVOI D\'EMAIL ---');
        console.log(`À: ${email}`);
        console.log(`De: EIdos <ne-pas-repondre@eidos.fr>`);
        console.log(`Sujet: Vous avez été invité à rejoindre ${organisation.name} sur EIdos`);
        console.log(`Corps: ... cliquez sur ce lien pour créer votre compte formateur : ${inviteLink}`);
        console.log('-----------------------------------');
        res.status(200).json({ success: true, message: `Invitation envoyée à ${email}.` });
    } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});
app.post('/api/organisation/remove', protect, async (req, res) => {
    if (!req.user.is_owner || !req.user.organisation) return res.status(403).json({ error: 'Non autorisé (réservé aux propriétaires de centre).' });
    try {
        const { email } = req.body;
        const formateur = await User.findOne({ email: email.toLowerCase(), organisation: req.user.organisation._id, is_owner: false });
        if (!formateur) return res.status(404).json({ error: 'Formateur non trouvé dans votre organisation.' });
        formateur.organisation = null;
        formateur.role = 'user';
        formateur.subscription = 'free';
        await formateur.save();
        res.status(200).json({ success: true, message: `${email} a été retiré de votre centre.` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- ROUTES DE L'API (PATIENTS) ---

// GET /api/patients (Inchangé)
app.get('/api/patients', protect, async (req, res) => {
    try {
        const query = { user: req.user.resourceId };
        if (req.user.role === 'etudiant') {
            query.patientId = { $in: req.user.allowedRooms };
        }
        const patients = await Patient.find(query, 'patientId sidebar_patient_name');
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/patients/save (Inchangé)
app.post('/api/patients/save', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const { dossierData, sidebar_patient_name } = req.body;
        if (!sidebar_patient_name || sidebar_patient_name.startsWith('Chambre ')) return res.status(400).json({ error: 'Veuillez donner un nom au patient dans l\'en-tête avant de sauvegarder.' });
        const existingSave = await Patient.findOne({ user: req.user.resourceId, sidebar_patient_name: sidebar_patient_name, patientId: { $regex: /^save_/ } });
        if (existingSave) {
            await Patient.updateOne({ _id: existingSave._id }, { dossierData: dossierData });
            res.json({ success: true, message: 'Sauvegarde mise à jour.' });
        } else {
            const plan = req.user.effectivePlan;
            if (plan === 'independant' || plan === 'promo') {
                const saveCount = await Patient.countDocuments({ user: req.user.resourceId, patientId: { $regex: /^save_/ } });
                let limit = 0;
                if (plan === 'independant') limit = 20;
                if (plan === 'promo') limit = 50;
                if (saveCount >= limit) return res.status(403).json({ error: `Limite de ${limit} archives atteinte pour le plan ${plan}.` });
            }
            const newPatientId = `save_${new mongoose.Types.ObjectId()}`;
            const newPatient = new Patient({ patientId: newPatientId, user: req.user.resourceId, dossierData: dossierData, sidebar_patient_name: sidebar_patient_name });
            await newPatient.save();
            res.status(201).json({ success: true, message: 'Dossier sauvegardé.' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/patients/:patientId (Inchangé)
app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        let patient = await Patient.findOne({ patientId: req.params.patientId, user: req.user.resourceId });
        if (!patient && req.params.patientId.startsWith('chambre_')) {
            patient = new Patient({ patientId: req.params.patientId, user: req.user.resourceId, sidebar_patient_name: `Chambre ${req.params.patientId.split('_')[1]}` });
            await patient.save();
        } else if (!patient) {
            return res.status(404).json({ error: 'Dossier non trouvé' });
        }
        res.json(patient.dossierData || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// NOUVEAU : Fonction de sauvegarde réutilisable
async function savePatientData(user, patientId, dossierData, sidebar_patient_name) {
    // 1. Vérifier les permissions (copié de la route POST)
    if (user.effectivePlan === 'free') {
         throw new Error('Le plan Free ne permet pas la sauvegarde.');
    }
    if (!patientId.startsWith('chambre_')) {
        throw new Error('Cette route est réservée à la mise à jour des chambres.');
    }

    const userIdToSave = user.resourceId;
    let finalDossierData = dossierData;

    // 2. Logique de fusion pour les étudiants (copié de la route POST)
    if (user.role === 'etudiant') {
        const permissions = user.permissions;
        
        const existingPatient = await Patient.findOne({ 
            patientId: patientId, 
            user: userIdToSave 
        });
        const existingData = existingPatient ? existingPatient.dossierData : {};
        
        const mergedData = { ...existingData };

        if (permissions.header) ['patient-nom-usage', 'patient-prenom', 'patient-dob', 'patient-motif', 'patient-entry-date'].forEach(k => { if (dossierData[k] !== undefined) mergedData[k] = dossierData[k]; });
        if (permissions.admin) Object.keys(dossierData).filter(k => k.startsWith('admin-')).forEach(k => mergedData[k] = dossierData[k]);
        if (permissions.vie) Object.keys(dossierData).filter(k => k.startsWith('vie-') || k.startsWith('atcd-')).forEach(k => mergedData[k] = dossierData[k]);
        if (permissions.observations) mergedData['observations'] = dossierData['observations'];
        if (permissions.prescriptions_add || permissions.prescriptions_delete || permissions.prescriptions_validate) mergedData['prescriptions'] = dossierData['prescriptions'];
        if (permissions.transmissions) mergedData['transmissions'] = dossierData['transmissions'];
        if (permissions.comptesRendus) mergedData['comptesRendus'] = dossierData['comptesRendus'];
        if (permissions.pancarte) { mergedData['pancarte'] = dossierData['pancarte']; mergedData['glycemie'] = dossierData['glycemie']; }
        if (permissions.diagramme) { mergedData['care-diagram-tbody_html'] = dossierData['care-diagram-tbody_html']; mergedData['careDiagramCheckboxes'] = dossierData['careDiagramCheckboxes']; }
        if (permissions.biologie) mergedData['biologie'] = dossierData['biologie'];
        
        finalDossierData = mergedData;
    }

    // 3. Sauvegarde en base de données (copié de la route POST)
    await Patient.findOneAndUpdate(
        { patientId: patientId, user: userIdToSave }, 
        { 
            dossierData: finalDossierData, 
            ...(user.role !== 'etudiant' && { sidebar_patient_name: sidebar_patient_name }),
            user: userIdToSave 
        }, 
        { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    
    // 4. Renvoyer les données sauvegardées (important pour le broadcast)
    return finalDossierData;
}

// POST /api/patients/:patientId (MODIFIÉ : utilise la nouvelle fonction)
app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        const { dossierData, sidebar_patient_name } = req.body;
        
        // Appelle la nouvelle fonction réutilisable
        await savePatientData(req.user, req.params.patientId, dossierData, sidebar_patient_name);
        
        res.json({ success: true, message: 'Dossier de chambre mis à jour.' });
    } catch (err) {
        // La fonction savePatientData renvoie des erreurs
        res.status(403).json({ error: err.message });
    }
});


// DELETE /api/patients/:patientId (Inchangé)
app.delete('/api/patients/:patientId', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.effectivePlan === 'free') return res.status(403).json({ error: 'Non autorisé' });
    try {
        const patientId = req.params.patientId;
        const userId = req.user.resourceId;
        if (patientId.startsWith('chambre_')) {
            await Patient.findOneAndUpdate({ patientId: patientId, user: userId }, { dossierData: {}, sidebar_patient_name: `Chambre ${patientId.split('_')[1]}` }, { upsert: true, new: true });
            res.json({ success: true, message: 'Chambre réinitialisée.' });
        } else if (patientId.startsWith('save_')) {
            await Patient.deleteOne({ patientId: patientId, user: userId });
            res.json({ success: true, message: 'Sauvegarde supprimée.' });
        } else {
            res.status(400).json({ error: 'ID patient invalide pour la suppression.' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// NOUVEAU : Webhook (Inchangé)
app.post('/api/webhook/payment-received', express.raw({type: 'application/json'}), async (req, res) => {
    console.log("Événement Webhook reçu (Simulation) !");
    try {
        res.json({ received: true });
    } catch (err) {
        console.error("Erreur Webhook:", err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});


// --- NOUVEAU : LOGIQUE SOCKET.IO ---

// Middleware d'authentification pour Socket.io (adapté de 'protect')
io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Non autorisé (pas de token)'));
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Important : 'populate' l'organisation ici aussi
        const user = await User.findById(decoded.id).populate('organisation');
        if (!user) {
            return next(new Error('Utilisateur non trouvé'));
        }
        
        // Attache les mêmes données que 'protect' à l'objet socket
        socket.user = user;
        
        if (user.role === 'etudiant') {
            socket.user.resourceId = user.createdBy;
        } else if (user.role === 'formateur' && user.organisation) {
            socket.user.resourceId = user.organisation.owner;
        } else {
            socket.user.resourceId = user._id;
        }
        
        if ((user.role === 'formateur' || user.role === 'owner') && user.organisation && user.organisation.is_active) {
            socket.user.effectivePlan = user.organisation.plan; 
        } else if (user.role === 'etudiant') {
            socket.user.effectivePlan = 'student';
        } else {
            socket.user.effectivePlan = user.subscription;
        }
        
        next();
    } catch (err) {
        return next(new Error('Non autorisé (token invalide)'));
    }
});

// Logique de connexion Socket.io
io.on('connection', (socket) => {
    console.log(`✅ [Socket] Utilisateur connecté: ${socket.user.email} (ID: ${socket.id})`);

    // Événement pour rejoindre une "room" de patient
    socket.on('client:joinRoom', (patientId) => {
        const roomName = `dossier:${socket.user.resourceId}:${patientId}`;

        // Quitter les autres rooms de dossier
        socket.rooms.forEach(room => {
            if (room.startsWith('dossier:') && room !== roomName) {
                socket.leave(room);
            }
        });

        // Rejoindre la nouvelle room
        socket.join(roomName);
        console.log(`[Socket] ${socket.user.email} a rejoint la room: ${roomName}`);
    });

    // Événement de mise à jour du patient
    socket.on('client:updatePatient', async (data, callback) => {
        try {
            const { patientId, dossierData, sidebar_patient_name } = data;
            
            // Utilise la même fonction de sauvegarde que la route POST
            const savedData = await savePatientData(socket.user, patientId, dossierData, sidebar_patient_name);

            // Définit la room
            const roomName = `dossier:${socket.user.resourceId}:${patientId}`;

            // 1. Confirmer à l'émetteur que c'est sauvegardé
            callback({ success: true });
            
            // 2. Envoyer les données mises à jour à TOUS LES AUTRES dans la room
            socket.to(roomName).emit('server:patientUpdated', savedData);

        } catch (err) {
            // En cas d'erreur (ex: permissions), renvoyer l'erreur à l'émetteur
            console.error(`[Socket] Erreur de sauvegarde: ${err.message}`);
            callback({ error: err.message });
        }
    });

    // Gérer la déconnexion
    socket.on('disconnect', () => {
        console.log(`🔌 [Socket] Utilisateur déconnecté: ${socket.user.email || socket.id}`);
    });
});


// --- DÉMARRAGE DU SERVEUR (MODIFIÉ) ---
mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('✅ Connecté avec succès à MongoDB !');
        // MODIFIÉ : Utilise server.listen au lieu de app.listen
        server.listen(PORT, () => {
            console.log(`🚀 Serveur backend et Socket.io démarrés sur http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('❌ Erreur de connexion à MongoDB :', err);
        process.exit(1);
    });