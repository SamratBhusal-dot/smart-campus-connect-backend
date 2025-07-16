const express = require('express');
const bcrypt = require('bcryptjs'); // For password hashing
const cors = require('cors'); // For handling Cross-Origin Resource Sharing
const jwt = require('jsonwebtoken'); // For JWT token generation
const admin = require('firebase-admin'); // Firebase Admin SDK

const app = express();
const PORT = 5003; // Ensure this matches the port in your frontend JavaScript files
const SECRET_KEY = 'your_super_secret_key_for_jwt_signing_change_this_in_production_!'; // IMPORTANT: Use a strong, unique key!

// --- Firebase Admin SDK Initialization ---
// This block initializes the Firebase Admin SDK using your service account key.
// It allows your Node.js backend to securely interact with Firebase services like Firestore.
try {
    // Attempt to load the service account key from the local file.
    // In a production environment, you would typically load this from an environment variable
    // for better security (e.g., process.env.FIREBASE_SERVICE_ACCOUNT_JSON).
    const serviceAccount = require('./serviceAccountKey.json'); // Make sure this path is correct

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin SDK initialized successfully.');
} catch (error) {
    console.error('Failed to initialize Firebase Admin SDK.');
    console.error('Please ensure "serviceAccountKey.json" is in your backend directory and is valid.');
    console.error('Error details:', error.message);
    // Exit the process if Firebase initialization fails, as the server won't function correctly.
    process.exit(1);
}

const db = admin.firestore(); // Get a Firestore instance to interact with your database

// Middleware to parse JSON bodies from incoming requests
app.use(express.json());
// Enable CORS for all origins. This is crucial for local development where your frontend
// and backend might be on different ports/origins. Restrict this in production.
app.use(cors());

// --- Authentication Routes ---

// Registration Route: Handles new user sign-ups
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Basic validation to ensure all required fields are provided
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        // Check if username already exists in the Firestore 'users' collection
        const usersRef = db.collection('users');
        const usernameQuery = await usersRef.where('username', '==', username).get();
        if (!usernameQuery.empty) {
            return res.status(409).json({ error: 'Username already exists.' });
        }

        // Check if email already exists in the Firestore 'users' collection
        const emailQuery = await usersRef.where('email', '==', email).get();
        if (!emailQuery.empty) {
            return res.status(409).json({ error: 'Email already registered.' });
        }

        // Hash the user's password using bcrypt for security
        // The '10' represents the salt rounds, determining the complexity of the hash.
        const hashedPassword = await bcrypt.hash(password, 10);

        // Add the new user's data to the 'users' collection in Firestore
        // 'role' is set to 'student' by default.
        // 'createdAt' uses a server timestamp for accurate creation time.
        const newUserRef = await usersRef.add({
            username,
            email,
            hashedPassword,
            role: 'student', // Default role for new registrations
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log('New user registered successfully with Firestore ID:', newUserRef.id);
        res.status(201).json({ message: 'User registered successfully!', userId: newUserRef.id });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Login Route: Handles user authentication
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username in the Firestore 'users' collection
        // .limit(1) ensures we only fetch one document even if multiple exist (though usernames should be unique)
        const usersRef = db.collection('users');
        const userQuery = await usersRef.where('username', '==', username).limit(1).get();

        // If no user document is found with the given username
        if (userQuery.empty) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Get the user data from the first (and only) document found
        const userDoc = userQuery.docs[0];
        const user = userDoc.data(); // This contains username, email, hashedPassword, role, etc.

        // Compare the provided plain password with the stored hashed password using bcrypt
        const isMatch = await bcrypt.compare(password, user.hashedPassword);

        // If passwords do not match
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // If credentials are valid, generate a JSON Web Token (JWT)
        // The token includes user ID, username, and role.
        // It's signed with a SECRET_KEY and set to expire in 1 hour.
        const token = jwt.sign(
            { id: userDoc.id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        console.log('User logged in successfully:', user.username);
        // Send back a success message, the JWT token, and basic user info (excluding password hash)
        res.status(200).json({ message: 'Login successful!', token, user: { id: userDoc.id, username: user.username, email: user.email, role: user.role } });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});

// --- Example Protected Route ---
// This route demonstrates how to protect an endpoint using JWT verification.
app.get('/api/protected', (req, res) => {
    // Get the authorization header from the request
    const authHeader = req.headers['authorization'];
    // Extract the token (Bearer <token>)
    const token = authHeader && authHeader.split(' ')[1];

    // If no token is provided, deny access
    if (!token) {
        return res.status(401).json({ message: 'Access Denied: No token provided!' });
    }

    try {
        // Verify the token using the SECRET_KEY
        const verified = jwt.verify(token, SECRET_KEY);
        // If verification is successful, attach the decoded user payload to the request object
        req.user = verified;
        // Send a success response with the protected data and user info
        res.json({ message: 'Welcome to the protected route!', user: req.user });
    } catch (error) {
        // If token verification fails (e.g., invalid, expired), deny access
        res.status(403).json({ message: 'Access Denied: Invalid token!' });
    }
});

// --- Server Start ---
// Start the Express server and listen for incoming requests on the specified PORT.
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
