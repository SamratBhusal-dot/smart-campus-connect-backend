const express = require('express');
const bcrypt = require('bcryptjs'); // For password hashing
const cors = require('cors'); // For handling Cross-Origin Resource Sharing
const jwt = require('jsonwebtoken'); // For JWT token generation
const admin = require('firebase-admin'); // Firebase Admin SDK

const app = express();
const PORT = 5001; // Ensure this matches the port in your frontend JavaScript files
const SECRET_KEY = 'your_super_secret_key_for_jwt_signing_change_this_in_production_!'; // IMPORTANT: Use a strong, unique key!

// --- Firebase Admin SDK Initialization ---
try {
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_JSON;

    if (!serviceAccountJson) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_KEY_JSON environment variable is not set or is empty.');
    }

    const serviceAccount = JSON.parse(serviceAccountJson);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin SDK initialized successfully.');
} catch (error) {
    console.error('Failed to initialize Firebase Admin SDK.');
    console.error('Please ensure FIREBASE_SERVICE_ACCOUNT_KEY_JSON environment variable is set on Render and contains a valid JSON string.');
    console.error('Error details:', error.message);
    process.exit(1);
}

const db = admin.firestore(); // Get a Firestore instance

// Middleware to parse JSON bodies
app.use(express.json());
// Enable CORS for all origins (for development, restrict in production)
app.use(cors());

// --- JWT Authentication Middleware ---
// This middleware will verify the JWT token for protected routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ message: 'Access Denied: No token provided!' });
    }

    try {
        // Verify the token using the SECRET_KEY
        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified; // Attach user payload (id, username, role) to the request object
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        // If token verification fails (e.g., invalid, expired)
        return res.status(403).json({ message: 'Access Denied: Invalid token!' });
    }
};

// --- Authentication Routes ---

// Registration Route
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const usersRef = db.collection('users');
        const usernameQuery = await usersRef.where('username', '==', username).get();
        if (!usernameQuery.empty) {
            return res.status(409).json({ error: 'Username already exists.' });
        }

        const emailQuery = await usersRef.where('email', '==', email).get();
        if (!emailQuery.empty) {
            return res.status(409).json({ error: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUserRef = await usersRef.add({
            username,
            email,
            hashedPassword,
            role: 'student',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log('New user registered with ID:', newUserRef.id);
        res.status(201).json({ message: 'User registered successfully!', userId: newUserRef.id });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const usersRef = db.collection('users');
        const userQuery = await usersRef.where('username', '==', username).limit(1).get();

        if (userQuery.empty) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        const userDoc = userQuery.docs[0];
        const user = userDoc.data();

        const isMatch = await bcrypt.compare(password, user.hashedPassword);

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: userDoc.id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        console.log('User logged in:', user.username);
        res.status(200).json({ message: 'Login successful!', token, user: { id: userDoc.id, username: user.username, email: user.email, role: user.role } });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});

// --- Marketplace Routes (Protected by authenticateToken middleware) ---

// POST /api/listings: Create a new listing
app.post('/api/listings', authenticateToken, async (req, res) => {
    const { title, description, price, category } = req.body;
    const sellerId = req.user.id; // Get seller ID from authenticated token
    const sellerUsername = req.user.username; // Get seller username from authenticated token

    if (!title || !description || !price || !category) {
        return res.status(400).json({ error: 'All fields (title, description, price, category) are required.' });
    }
    if (isNaN(price) || parseFloat(price) <= 0) {
        return res.status(400).json({ error: 'Price must be a positive number.' });
    }

    try {
        const listingsRef = db.collection('listings');
        const newListingRef = await listingsRef.add({
            title,
            description,
            price: parseFloat(price), // Store price as a number
            category,
            sellerId,
            sellerUsername, // Store username for easier display on frontend
            status: 'available', // Default status
            postedAt: admin.firestore.FieldValue.serverTimestamp() // Timestamp
        });

        console.log('New listing created with ID:', newListingRef.id);
        res.status(201).json({ message: 'Listing created successfully!', listingId: newListingRef.id });

    } catch (error) {
        console.error('Error creating listing:', error);
        res.status(500).json({ error: 'Server error during listing creation.' });
    }
});

// GET /api/listings: Fetch all listings with optional search and filters
app.get('/api/listings', authenticateToken, async (req, res) => {
    const { search, category, minPrice, maxPrice } = req.query;

    try {
        let listingsRef = db.collection('listings');
        let query = listingsRef;

        // Apply filters based on query parameters
        if (category && category !== 'All') {
            query = query.where('category', '==', category);
        }
        if (minPrice) {
            query = query.where('price', '>=', parseFloat(minPrice));
        }
        if (maxPrice) {
            query = query.where('price', '<=', parseFloat(maxPrice));
        }

        const snapshot = await query.get();
        let listings = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        // Manual search filtering for title/description (Firestore doesn't support full-text search directly)
        if (search) {
            const searchTermLower = search.toLowerCase();
            listings = listings.filter(listing =>
                listing.title.toLowerCase().includes(searchTermLower) ||
                listing.description.toLowerCase().includes(searchTermLower)
            );
        }

        // Sort by postedAt, newest first (optional, can be done client-side if needed)
        listings.sort((a, b) => b.postedAt.toDate() - a.postedAt.toDate());


        res.status(200).json({ listings });

    } catch (error) {
        console.error('Error fetching listings:', error);
        res.status(500).json({ error: 'Server error during fetching listings.' });
    }
});


// Example protected route (requires token) - kept for demonstration
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Welcome to the protected route!', user: req.user });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
