const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Étape 1: Importer les modules bcrypt et jsonwebtoken
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Étape 2: Créer un fichier auth.js dans le dossier middleware et importer les modules requis
const userModel = require('./chemin/vers/userModel');
const jwt = require('jsonwebtoken');

// Étape 3: Implémenter la fonction de hachage avec bcrypt
const motDePasse = 'monMotDePasse';
const saltRounds = 10;

bcrypt.hash(motDePasse, saltRounds, (erreur, hash) => {
  if (erreur) {
    console.error('Erreur lors du hachage du mot de passe :', erreur);
    return;
  }

  console.log('Mot de passe haché :', hash);
});

// Étape 4: Utiliser bcrypt pour comparer les mots de passe
const motDePasseSaisi = 'monMotDePasse';
const motDePasseHashé = '$2b$10$A5v3qLJmZkX9QWUjIfHtCOsIi/dYEmJdHdklZoRDzr.7TGy1e7g8u';

bcrypt.compare(motDePasseSaisi, motDePasseHashé, (erreur, correspond) => {
  if (erreur) {
    console.error('Erreur lors de la comparaison des mots de passe :', erreur);
    return;
  }

  if (correspond) {
    console.log('Le mot de passe correspond.');
  } else {
    console.log('Le mot de passe ne correspond pas.');
  }
});

// Étape 5: Utiliser jsonwebtoken pour générer et vérifier les jetons d'authentification
const utilisateurId = '123456';
const secret = 'monSecret';

const token = jwt.sign({ utilisateurId }, secret, { expiresIn: '1h' });
console.log('Jeton d\'authentification généré :', token);

try {
  const decoded = jwt.verify(token, secret);
  console.log('Jeton d\'authentification vérifié. Utilisateur ID:', decoded.utilisateurId);
} catch (erreur) {
  console.error('Erreur lors de la vérification du jeton d\'authentification :', erreur);
}

//Étape 6: Un middleware d'authentification qui vérifie si un jeton d'authentification est présent dans l'en-tête de la demande, puis authentifie l'utilisateur en conséquence 


const secretKey = 'cléSecrètePourSignatureJWT';

function authMiddleware(req, res, next) {
  // Vérifier si le jeton d'authentification est présent dans l'en-tête de la demande
  const token = req.headers.authorization;

  if (!token) {
    // Jeton non fourni, renvoyer une réponse d'erreur
    return res.status(401).json({ message: 'Jeton d\'authentification non fourni' });
  }

  try {
    // Vérifier et décoder le jeton d'authentification
    const decoded = jwt.verify(token, secretKey);

    // Ajouter les données d'authentification à l'objet de demande pour une utilisation ultérieure
    req.user = decoded;

    // Passer le contrôle au middleware ou à la fonction de rappel suivante
    next();
  } catch (error) {
    // Erreur lors de la vérification du jeton, renvoyer une réponse d'erreur
    return res.status(401).json({ message: 'Jeton d\'authentification invalide' });
  }
}

// Exemple d'utilisation du middleware d'authentification dans une route
app.get('/api/private', authMiddleware, (req, res) => {
  // Le middleware d'authentification a été passé avec succès, l'utilisateur est authentifié
  // Effectuer des opérations privilégiées ici

  res.json({ message: 'Accès autorisé à la ressource privée' });
});


// Étape 7: Implémenter le middleware d'authentification

async function authMiddleware(req, res, next) {
  try {
    // Vérifier si le jeton d'authentification est présent dans les cookies de la requête
    const token = req.cookies.token;

    if (!token) {
      // Jeton non fourni, renvoyer une réponse d'erreur
      return res.status(401).json({ message: 'Jeton d\'authentification manquant' });
    }

    // Vérifier la validité et décoder le jeton d'authentification de manière asynchrone
    const decoded = await jwt.verify(token, process.env.JWT_SECRET);

    // Récupérer l'utilisateur associé à l'ID du jeton vérifié
    const user = await userModel.findById(decoded.userId);

    if (!user) {
      // Utilisateur introuvable, renvoyer une réponse d'erreur
      return res.status(401).json({ message: 'Utilisateur introuvable' });
    }

    // Ajouter l'utilisateur à l'objet de demande pour une utilisation ultérieure
    req.user = user;

    // Passer le contrôle au middleware ou à la fonction de rappel suivante
    next();
  } catch (error) {
    // Gérer les erreurs en les envoyant à next()
    next(error);
  }
}


// Étape 8: Exporter le middleware d'authentification
module.exports = authMiddleware;

// Utilisation du middleware dans votre application
const authMiddleware = require('./chemin/vers/middleware/auth');
app.use(authMiddleware);
app.listen(3000, () => {
  console.log('Serveur en écoute sur le port 3000');
});