// server.js (Modifié)

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const nodemailer = require('nodemailer'); // Nécessaire pour un VRAI envoi d'email

// --- CONFIGURATION ---
const app = express();

app.use((req, res, next) => {
    console.log(`REQ ORIGIN: ${req.headers.origin}`);
    next();
});

// MODIFIÉ : Configuration CORS
const whitelist = [
    'https://lcssrd.github.io', // <--- C'EST LA LIGNE CORRIGÉE
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];
const corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            console.error(`CORS Rejeté : Origine ${origin} non autorisée.`); // Ajout d'un log d'erreur
            callback(new Error('Non autorisé par CORS'));
        }
    }
};
app.use(cors(corsOptions));
// FIN DE LA MODIFICATION
app.use(express.json());

const PORT = 3000;
const MONGO_URI = "mongodb+srv://lucasseraudie_db_user:9AnBALAG30WhZ3Ce@eidos.lelleaw.mongodb.net/?appName=EIdos";
const JWT_SECRET = "mettez_une_phrase_secrete_tres_longue_ici";

// --- MODÈLES DE DONNÉES (SCHEMAS) ---

// --- MODIFIÉ : Schéma Utilisateur (retour au hachage pour tous) ---
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true, sparse: true },
    isVerified: { type: Boolean, default: false },
    confirmationCode: { type: String },
    subscription: { type: String, enum: ['solo', 'pro', 'organisation'], default: 'solo' },

    login: { type: String, unique: true, lowercase: true, sparse: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    permissions: { type: mongoose.Schema.Types.Mixed, default: {} },

    passwordHash: { type: String, required: true }, // Stocke TOUJOURS un hash
    role: { type: String, enum: ['solo', 'pro', 'organisation', 'etudiant'], required: true }
});
const User = mongoose.model('User', userSchema);

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

// POST /auth/signup (Inchangé, hache déjà le mdp)
app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email et mot de passe requis' });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }
        
        const passwordHash = await bcrypt.hash(password, 10);
        const confirmationCode = Math.floor(100000 + Math.random() * 900000).toString();

        const newUser = new User({ 
            email: email.toLowerCase(), 
            passwordHash, // Haché
            confirmationCode,
            isVerified: false,
            role: 'solo',
            subscription: 'solo'
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


// POST /auth/login (MODIFIÉ)
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

        // --- MODIFIÉ : La vérification par HASH s'applique à TOUS les rôles ---
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        // --- Fin de la modification ---

        if (!isMatch) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }
        
        if (user.role !== 'etudiant' && !user.isVerified) {
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

// NOUVEAU : Route pour récupérer les infos de l'utilisateur (permissions)
app.get('/api/auth/me', protect, (req, res) => {
    // Le middleware 'protect' a déjà récupéré 'req.user'
    res.json({
        id: req.user._id,
        role: req.user.role,
        email: req.user.email,
        login: req.user.login,
        permissions: req.user.permissions
    });
});

// --- NOUVEAU : ROUTES DE GESTION DE COMPTE ---

// GET /api/account/details (MODIFIÉ)
app.get('/api/account/details', protect, async (req, res) => {
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        // MODIFIÉ : On ne renvoie PAS le hash du mot de passe
        const students = await User.find(
            { createdBy: req.user._id },
            'login permissions' // On sélectionne login et permissions
        );
        
        res.json({
            plan: req.user.subscription,
            students: students // On envoie la liste
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/change-password (MODIFIÉ)
app.post('/api/account/change-password', protect, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // --- MODIFIÉ : La vérification par HASH s'applique à TOUS les rôles ---
        const isMatch = await bcrypt.compare(currentPassword, req.user.passwordHash);

        if (!isMatch) {
            return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
        }
        
        // --- MODIFIÉ : On HACHE toujours le nouveau mot de passe ---
        req.user.passwordHash = await bcrypt.hash(newPassword, 10); // Toujours haché

        await req.user.save();
        
        res.json({ success: true, message: 'Mot de passe mis à jour.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/account/delete
app.delete('/api/account/delete', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // 1. Supprimer tous les patients (chambres et sauvegardes) de l'utilisateur
        await Patient.deleteMany({ user: userId });
        
        // 2. Supprimer tous les comptes étudiants créés par cet utilisateur
        await User.deleteMany({ createdBy: userId });
        
        // 3. Supprimer l'utilisateur lui-même
        await User.deleteOne({ _id: userId });
        
        res.json({ success: true, message: 'Compte supprimé avec succès.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/account/invite (Créer un étudiant) (MODIFIÉ)
app.post('/api/account/invite', protect, async (req, res) => {
    if (req.user.role === 'solo' || req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    try {
        const { login, password } = req.body;
        
        const existingStudent = await User.findOne({ login: login.toLowerCase() });
        if (existingStudent) {
            return res.status(400).json({ error: 'Ce login est déjà utilisé.' });
        }

        // MODIFIÉ : On HACHE le mot de passe de l'étudiant
        const passwordHash = await bcrypt.hash(password, 10);
        
        // MODIFIÉ : Droits par défaut granulaires
        const defaultPermissions = {
            header: true, 
            admin: true, 
            vie: true, 
            observations: true,
            prescriptions_add: true, // NOUVEAU
            prescriptions_delete: true, // NOUVEAU
            prescriptions_validate: true, // NOUVEAU
            transmissions: true, 
            pancarte: true, 
            diagramme: true, 
            biologie: true
        };

        const newStudent = new User({
            login: login.toLowerCase(),
            passwordHash: passwordHash, // On stocke le HASH
            role: 'etudiant',
            createdBy: req.user._id,
            isVerified: true,
            permissions: defaultPermissions
        });

        await newStudent.save();
        res.status(201).json({ success: true, message: 'Compte étudiant créé.' });
        
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PUT /api/account/permissions (Mettre à jour les droits d'un étudiant)
app.put('/api/account/permissions', protect, async (req, res) => {
    if (req.user.role === 'solo' || req.user.role === 'etudiant') {
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
        
        // NOUVEAU : S'assurer que l'objet permissions existe
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

// DELETE /api/account/student (Supprimer un étudiant)
app.delete('/api/account/student', protect, async (req, res) => {
    if (req.user.role === 'solo' || req.user.role === 'etudiant') {
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


// --- ROUTES DE L'API (Protégées et MODIFIÉES) ---

// GET /api/patients (MODIFIÉ)
app.get('/api/patients', protect, async (req, res) => {
    try {
        // MODIFIÉ : Utilise 'resourceId' (l'ID du formateur)
        const patients = await Patient.find(
            { user: req.user.resourceId }, 
            'patientId sidebar_patient_name'
        );
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/patients/save (MODIFIÉ)
app.post('/api/patients/save', protect, async (req, res) => {
    // MODIFIÉ : Les étudiants ne peuvent pas sauvegarder de "cas"
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const { dossierData, sidebar_patient_name } = req.body;

        if (!sidebar_patient_name || sidebar_patient_name.startsWith('Chambre ')) {
            return res.status(400).json({ error: 'Veuillez donner un nom au patient dans l\'en-tête avant de sauvegarder.' });
        }

        // MODIFIÉ : Utilise 'resourceId' (l'ID du formateur, qui est son propre ID ici)
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

// GET /api/patients/:patientId (MODIFIÉ)
app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        // MODIFIÉ : Utilise 'resourceId' (l'ID du formateur)
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

// POST /api/patients/:patientId (MODIFIÉ)
app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        if (!req.params.patientId.startsWith('chambre_')) {
            return res.status(400).json({ error: 'Cette route est réservée à la mise à jour des chambres.' });
        }

        const { dossierData, sidebar_patient_name } = req.body;
        const userIdToSave = req.user.resourceId; // ID du formateur
        let finalDossierData = dossierData;

        // NOUVEAU : Si c'est un étudiant, filtrer les données à sauvegarder
        if (req.user.role === 'etudiant') {
            const permissions = req.user.permissions;
            
            const existingPatient = await Patient.findOne({ 
                patientId: req.params.patientId, 
                user: userIdToSave 
            });
            const existingData = existingPatient ? existingPatient.dossierData : {};
            
            const mergedData = { ...existingData };

            // Écraser *uniquement* les champs autorisés
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
            
            // MODIFIÉ : Utilisation des permissions granulaires
            if (permissions.prescriptions_add || permissions.prescriptions_delete || permissions.prescriptions_validate) {
                // Le front-end (app.js) est censé n'envoyer que les modifications autorisées.
                // Ici, on accepte le bloc 'prescriptions' si *n'importe quelle* permission est vraie.
                // La logique fine est gérée côté client.
                mergedData['prescriptions'] = dossierData['prescriptions'];
            }
            // FIN DE LA MODIFICATION
            
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

// DELETE /api/patients/:patientId (MODIFIÉ)
app.delete('/api/patients/:patientId', protect, async (req, res) => {
    if (req.user.role === 'etudiant') {
        return res.status(403).json({ error: 'Non autorisé' });
    }

    try {
        const patientId = req.params.patientId;
        const userId = req.user.resourceId; // Son propre ID

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


