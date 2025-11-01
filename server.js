const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // --- NOUVEAU ---
const jwt = require('jsonwebtoken'); // --- NOUVEAU ---

// --- CONFIGURATION ---
const app = express();
app.use(cors()); 
app.use(express.json());

const PORT = 3000;
const MONGO_URI = "mongodb+srv://lucasseraudie_db_user:zGTjEgLUXfv4xmvw@eidos.lelleaw.mongodb.net/?appName=EIdos";
const JWT_SECRET = "mettez_une_phrase_secrete_tres_longue_ici"; // --- NOUVEAU ---

// --- MODÈLES DE DONNÉES (SCHEMAS) ---

// --- NOUVEAU : Schéma pour les Utilisateurs ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// --- MODIFIÉ : Le patient appartient maintenant à un utilisateur ---
const patientSchema = new mongoose.Schema({
    // L'ID du patient (ex: "chambre_101")
    patientId: { type: String, required: true },
    
    // --- NOUVEAU : Lien vers l'utilisateur propriétaire ---
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

    sidebar_patient_name: { type: String, default: '' },
    dossierData: { type: mongoose.Schema.Types.Mixed, default: {} }
});
// Index pour garantir qu'un patientId est unique PAR utilisateur
patientSchema.index({ patientId: 1, user: 1 }, { unique: true });
const Patient = mongoose.model('Patient', patientSchema);


// --- NOUVEAU : Middleware de sécurité (le "gardien") ---
const protect = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Non autorisé (pas de token)' });
    }
    
    const token = header.split(' ')[1]; // Récupère le token après "Bearer "

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Ajoute les infos de l'utilisateur à la requête
        req.user = decoded; // 'decoded' contient { id: '...' }
        next(); // Passe à la route suivante
    } catch (err) {
        res.status(401).json({ error: 'Non autorisé (token invalide)' });
    }
};


// --- ROUTES D'AUTHENTIFICATION (Non protégées) ---

// POST /auth/signup (Inscription)
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
        const newUser = new User({ email: email.toLowerCase(), passwordHash });
        await newUser.save();

        res.status(201).json({ success: true, message: 'Utilisateur créé' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /auth/login (Connexion)
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }

        // --- Création du "Pass" (Token) ---
        const token = jwt.sign(
            { id: user._id }, // Le "payload" : ce qu'on stocke dans le token
            JWT_SECRET,        // La clé secrète
            { expiresIn: '7d' } // Durée de validité
        );

        res.json({ success: true, token: token });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- ROUTES DE L'API (Toutes protégées par le "gardien") ---

// GET /api/patients
// MODIFIÉ : Renvoie les patients UNIQUEMENT pour l'utilisateur connecté
app.get('/api/patients', protect, async (req, res) => {
    try {
        const patients = await Patient.find(
            { user: req.user.id }, // Ne trouve que les patients de cet utilisateur
            'patientId sidebar_patient_name'
        );
        res.json(patients);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/patients/:patientId
// MODIFIÉ : Renvoie UN patient, s'il appartient à l'utilisateur
app.get('/api/patients/:patientId', protect, async (req, res) => {
    try {
        let patient = await Patient.findOne({ 
            patientId: req.params.patientId,
            user: req.user.id // Vérification de propriété
        });
        
        if (!patient) {
            // Si le patient n'existe pas, on le crée pour cet utilisateur
            patient = new Patient({ 
                patientId: req.params.patientId, 
                user: req.user.id, // On assigne le propriétaire
                sidebar_patient_name: `Chambre ${req.params.patientId.split('_')[1]}` 
            });
            await patient.save();
        }
        
        res.json(patient.dossierData || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/patients/:patientId
// MODIFIÉ : Sauvegarde UN patient, en l'assignant à l'utilisateur
app.post('/api/patients/:patientId', protect, async (req, res) => {
    try {
        const { dossierData, sidebar_patient_name } = req.body;

        await Patient.findOneAndUpdate(
            { patientId: req.params.patientId, user: req.user.id }, // La condition
            { dossierData, sidebar_patient_name, user: req.user.id }, // Les données
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
        
        res.json({ success: true, message: 'Dossier sauvegardé.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/patients/:patientId
// MODIFIÉ : Efface UN patient, s'il appartient à l'utilisateur
app.delete('/api/patients/:patientId', protect, async (req, res) => {
    try {
        await Patient.findOneAndUpdate(
            { patientId: req.params.patientId, user: req.user.id },
            { 
                dossierData: {}, 
                sidebar_patient_name: `Chambre ${req.params.patientId.split('_')[1]}` 
            },
            { upsert: true, new: true } // 'upsert' garantit que l'entrée existe
        );
        res.json({ success: true, message: 'Dossier effacé.' });
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