const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const path = require('path'); // SUPPRIMÉ

// --- CONFIGURATION ---
const app = express();
app.use(cors()); 
app.use(express.json());

// SUPPRIMÉ : Le app.use(express.static(...)) a été retiré

// MODIFIÉ : Utiliser le port de Render, ou 3000 par défaut
const PORT = process.env.PORT || 3000;
const MONGO_URI = "mongodb+srv://lucasseraudie_db_user:9AnBALAG30WhZ3Ce@eidos.lelleaw.mongodb.net/?appName=EIdos";
const JWT_SECRET = "mettez_une_phrase_secrete_tres_longue_ici";

// --- MODÈLES DE DONNÉES (SCHEMAS) ---

// --- MODIFIÉ : Schéma Utilisateur (Ajout du statut 'student') ---
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true, sparse: true }, // Pour les formateurs
    login: { type: String, unique: true, lowercase: true, sparse: true }, // Pour les étudiants

    passwordHash: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    confirmationCode: { type: String },
    
    // Rôle simplifié
    role: { type: String, enum: ['formateur', 'etudiant'], required: true },
    
    // Nouveaux plans (avec 'student' ajouté)
    subscription: { type: String, enum: ['free', 'independant', 'promo', 'centre', 'student'], default: 'free' },

    // Pour les étudiants
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    permissions: { type: mongoose.Schema.Types.Mixed, default: {} },
    allowedRooms: { type: [String], default: [] } 
});
const User = mongoose.model('User', userSchema);
// --- FIN MODIFICATION ---


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
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Non autorisé (pas de token)' });
    }
    
    const token = header.split(' ')[1]; 

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ error: 'Utilisateur non trouvé' });
        }
        
        req.user = user; 

        if (user.role === 'etudiant') {
            req.user.resourceId = user.createdBy;
        } else {
            req.user.resourceId = user._id;
        }
        
        next(); 
    } catch (err) {
        res.status(401).json({ error: 'Non autorisé (token invalide)' });
    }
};


// --- ROUTES D'AUTHENTIFICATION (MODIFIÉES) ---
// Note : Les routes API commencent par /auth ou /api, elles ne
// seront PAS confondues avec les fichiers statiques.

// POST /auth/signup (Inchangé, gère l'inscription du formateur)
app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, plan } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email et mot de passe requis' });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }
        
        const passwordHash = await bcrypt.hash(password, 10);
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();

        const validPlans = ['free', 'independant', 'promo', 'centre'];
        let finalSubscription = 'free';
        if (plan && validPlans.includes(plan)) {
            finalSubscription = plan;
        }

        const newUser = new User({ 
            email: email.toLowerCase(), 
            passwordHash,
            confirmationCode,
            isVerified: false,
            role: 'formateur', 
            subscription: finalSubscription 
        });
        
        await newUser.save();
        
        console.log(`CODE DE VÉRIFICATION pour ${email}: ${confirmationCode}`);

        res.status(201).json({ 
            success: true, 
            message: 'Utilisateur créé. Veuillez vérifier votre email.',
            _test_code: confirmationCode 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// POST /auth/verify (Inchangé)
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


// POST /auth/login (Inchangé)
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
        
        if (user.role === 'formateur' && !user.isVerified) {
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

// GET /api/auth/me (MODIFIÉ : Logique d'héritage supprimée, renvoie juste les infos)
app.get('/api/auth/me', protect, (req, res) => {
    // Le middleware 'protect' a déjà récupéré 'req.user'
    // L'abonnement de l'utilisateur (ex: 'student') est maintenant correct
    res.json({
        id: req.user._id,
        role: req.user.role,
        email: req.user.email,
        login: req.user.login,
        permissions: req.user.permissions,
        subscription: req.user.subscription, // Renvoie 'student' pour les étudiants
        allowedRooms: req.user.allowedRooms
    });
});

// --- NOUVEAU : ROUTES DE GESTION DE COMPTE ---

// GET /api/account/details (Inchangé)
app.get('/api/account/details', protect, async (req, res) => {
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const students = await User.find(
            { createdBy: req.user._id },
            'login permissions allowedRooms' 
        );
        
        res.json({
            plan: req.user.subscription,
            students: students
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/change-password (Inchangé)
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

// NOUVEAU : POST /api/account/change-email
app.post('/api/account/change-email', protect, async (req, res) => {
    // Les étudiants ne peuvent pas changer leur email (seulement leur formateur)
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { newEmail, password } = req.body;

        // 1. Vérifier le mot de passe actuel
        const isMatch = await bcrypt.compare(password, req.user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        }

        // 2. Vérifier si le nouvel email est déjà pris
        const existingUser = await User.findOne({ email: newEmail.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Cette adresse email est déjà utilisée.' });
        }

        // 3. Mettre à jour l'email
        req.user.email = newEmail.toLowerCase();
        await req.user.save();
        
        res.json({ success: true, message: 'Adresse email mise à jour.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/account/delete (Inchangé)
app.delete('/api/account/delete', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        await Patient.deleteMany({ user: userId });
        await User.deleteMany({ createdBy: userId });
        await User.deleteOne({ _id: userId });
        
        res.json({ success: true, message: 'Compte supprimé avec succès.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/invite (MODIFIÉ : Définit subscription: 'student')
app.post('/api/account/invite', protect, async (req, res) => {
    if (req.user.subscription === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    try {
        const studentCount = await User.countDocuments({ createdBy: req.user._id });

        if (req.user.subscription === 'independant' && studentCount >= 5) {
            return res.status(403).json({ error: 'Limite de 5 étudiants atteinte pour le plan Indépendant.' });
        }
        if (req.user.subscription === 'promo' && studentCount >= 40) {
            return res.status(403).json({ error: 'Limite de 40 étudiants atteinte pour le plan Promo.' });
        }
        
        const { login, password } = req.body;
        
        const existingStudent = await User.findOne({ login: login.toLowerCase() });
        if (existingStudent) {
            return res.status(400).json({ error: 'Ce login est déjà utilisé.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        const defaultPermissions = {
            header: true, 
            admin: true, 
            vie: true, 
            observations: true,
            prescriptions_add: true,
            prescriptions_delete: true,
            prescriptions_validate: true,
            transmissions: true, 
            pancarte: true, 
            diagramme: true, 
            biologie: true
        };

        const defaultRooms = Array.from({ length: 10 }, (_, i) => `chambre_${101 + i}`);

        const newStudent = new User({
            login: login.toLowerCase(),
            passwordHash: passwordHash,
            role: 'etudiant', // Rôle correct
            subscription: 'student', // MODIFIÉ : Statut explicite 'student'
            createdBy: req.user._id,
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
// --- FIN MODIFICATION ---

// PUT /api/account/permissions (Inchangé)
app.put('/api/account/permissions', protect, async (req, res) => {
    if (req.user.subscription === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    try {
        const { login, permission, value } = req.body;
        
        const student = await User.findOne({
            login: login.toLowerCase(),
            createdBy: req.user._id
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

// PUT /api/account/student/rooms (Inchangé)
app.put('/api/account/student/rooms', protect, async (req, res) => {
    if (req.user.subscription === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    try {
        const { login, rooms } = req.body;
        
        const student = await User.findOne({
            login: login.toLowerCase(),
            createdBy: req.user._id
        });

        if (!student) {
            return res.status(404).json({ error: 'Étudiant non trouvé' });
        }
        
        if (!Array.isArray(rooms) || !rooms.every(r => typeof r === 'string' && r.startsWith('chambre_'))) {
             return res.status(400).json({ error: 'Format de chambres non valide.' });
        }

        student.allowedRooms = rooms;
        await student.save();
        
        res.json({ success: true, message: 'Chambres autorisées mises à jour.' });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/account/student (Inchangé)
app.delete('/api/account/student', protect, async (req, res) => {
    if (req.user.subscription === 'free' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    try {
        const { login } = req.body;
        
        const result = await User.deleteOne({
            login: login.toLowerCase(),
            createdBy: req.user._id
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Étudiant non trouvé' });
        }
        
        res.json({ success: true, message: 'Compte étudiant supprimé.' });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/change-subscription (Inchangé)
app.post('/api/account/change-subscription', protect, async (req, res) => {
    try {
        const { newPlan } = req.body;
        const validPlans = ['free', 'independant', 'promo', 'centre']; // Ne contient pas 'student'
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

        user.subscription = newPlan;
        user.role = 'formateur';

        await user.save();
        
        res.json({ 
            success: true, 
            message: 'Abonnement mis à jour.',
            subscription: user.subscription,
            role: user.role
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- ROUTES DE L'API (Protégées) ---

// GET /api/patients (Inchangé)
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

// POST /api/patients/save (MODIFIÉ : Ajout de la limite de sauvegarde)
app.post('/api/patients/save', protect, async (req, res) => {
    if (req.user.role === 'etudiant' || req.user.subscription === 'free') {
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
            // L'utilisateur met à jour une sauvegarde existante, pas de vérification de limite.
            await Patient.updateOne(
                { _id: existingSave._id },
                { dossierData: dossierData }
            );
            res.json({ success: true, message: 'Sauvegarde mise à jour.' });
        } else {
            // =================================================================
            // DÉBUT DE LA MODIFICATION : Vérification de la limite de sauvegarde
            // =================================================================
            const subscription = req.user.subscription;
            
            // Le plan 'centre' n'a pas de limite
            if (subscription === 'independant' || subscription === 'promo') {
                
                const saveCount = await Patient.countDocuments({
                    user: req.user.resourceId,
                    patientId: { $regex: /^save_/ }
                });

                let limit = 0;
                if (subscription === 'independant') limit = 20;
                if (subscription === 'promo') limit = 50;

                if (saveCount >= limit) {
                    return res.status(403).json({ 
                        error: `Limite de ${limit} archives atteinte pour le plan ${subscription}.` 
                    });
                }
            }
            // =================================================================
            // FIN DE LA MODIFICATION
            // =================================================================

            // Si la limite n'est pas atteinte (ou si c'est 'centre'), on crée la sauvegarde.
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


// GET /api/patients/:patientId (MODIFIÉ : Simplification, suppression de la vérification 'free' ici)
app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        // La logique 'free' sera gérée par le frontend (app.js)
        
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

// POST /api/patients/:patientId (MODIFIÉ : Simplification, suppression de la vérification 'free' ici)
app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        // La logique 'free' sera gérée par le frontend (app.js)
        
        if (!req.params.patientId.startsWith('chambre_')) {
            return res.status(400).json({ error: 'Cette route est réservée à la mise à jour des chambres.' });
        }

        const { dossierData, sidebar_patient_name } = req.body;
        const userIdToSave = req.user.resourceId;
        let finalDossierData = dossierData;

        if (req.user.role === 'etudiant') {
            const permissions = req.user.permissions;
            
            const existingPatient = await Patient.findOne({ 
                patientId: req.params.patientId, 
                user: userIdToSave 
            });
            const existingData = existingPatient ? existingPatient.dossierData : {};
            
            const mergedData = { ...existingData };

            if (permissions.header) {
                Object.keys(dossierData).forEach(key => {
                    if (key.startsWith('patient-') || key === 'admin-nom-usage' || key === 'admin-prenom' || key === 'admin-dob') {
                        mergedData[key] = dossierData[key];
                    }
                });
            }
            if (permissions.admin) {
                Object.keys(dossierData).forEach(key => {
                    if (key.startsWith('admin-')) {
                        mergedData[key] = dossierData[key];
                    }
                });
            }
            if (permissions.vie) {
                Object.keys(dossierData).forEach(key => {
                    if (key.startsWith('vie-') || key.startsWith('atcd-')) {
                        mergedData[key] = dossierData[key];
                    }
                });
            }
            if (permissions.observations) {
                mergedData['observations-list_html'] = dossierData['observations-list_html'];
            }
            
            if (permissions.prescriptions_add || permissions.prescriptions_delete || permissions.prescriptions_validate) {
                mergedData['prescriptions'] = dossierData['prescriptions'];
            }
            
            if (permissions.transmissions) {
                mergedData['transmissions-list-ide_html'] = dossierData['transmissions-list-ide_html'];
            }
            if (permissions.pancarte) {
                mergedData['pancarte'] = dossierData['pancarte'];
            }
            if (permissions.diagramme) {
                mergedData['care-diagram-tbody_html'] = dossierData['care-diagram-tbody_html'];
                mergedData['careDiagramCheckboxes'] = dossierData['careDiagramCheckboxes'];
            }
            if (permissions.biologie) {
                mergedData['biologie'] = dossierData['biologie'];
            }
            
            finalDossierData = mergedData;
        }


        await Patient.findOneAndUpdate(
            { patientId: req.params.patientId, user: userIdToSave }, 
            { 
                dossierData: finalDossierData, 
                ...(req.user.role !== 'etudiant' && { sidebar_patient_name: sidebar_patient_name }),
                user: userIdToSave 
            }, 
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
        
        res.json({ success: true, message: 'Dossier de chambre mis à jour.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/patients/:patientId (MODIFIÉ : Simplification, suppression de la vérification 'free' ici)
app.delete('/api/patients/:patientId', protect, async (req, res) => {
    // La logique 'free' sera gérée par le frontend (app.js)
    
    if (req.user.role === 'etudiant') {
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
            res.json({ success: true, message: 'Chambre réinitialisée.' });

        } else if (patientId.startsWith('save_')) {
            await Patient.deleteOne({ 
                patientId: patientId, 
                user: userId 
            });
            res.json({ success: true, message: 'Sauvegarde supprimée.' });
        } else {
            res.status(400).json({ error: 'ID patient invalide pour la suppression.' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SUPPRIMÉ : La route "Catch-all" app.get('/*') a été retirée

// --- DÉMARRAGE DU SERVEUR ---
mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('✅ Connecté avec succès à MongoDB !');
        app.listen(PORT, () => {
            console.log(`🚀 Serveur backend démarré sur http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('❌ Erreur de connexion à MongoDB :', err);
        process.exit(1);
    });
