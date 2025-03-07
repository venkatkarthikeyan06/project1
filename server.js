require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 5000;


// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// Define MongoDB Schema and Models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const scoreSchema = new mongoose.Schema({
    score: { type: Number, required: true },
    date: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Score = mongoose.model('Score', scoreSchema);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));



// Rate-Limiting Middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
});
app.use(limiter);

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ error: 'Authorization token is required' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

app.post('/api/personalization', authenticateJWT, async (req, res) => {
    console.log("Request received at /api/personalization");

    const { personalizationData } = req.body;

    if (!personalizationData) {
        return res.status(400).json({ error: 'Personalization data is required' });
    }
    try {
        // Example: Process the data without saving to DB
        console.log('Received personalization data:', personalizationData);

        res.status(201).json({ message: 'Personalization data received successfully' });
    } catch (error) {
        console.error('Error handling personalization data:', error);
        res.status(500).json({ error: 'Failed to process personalization data' });
    }
});

// Routes
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, name: user.name });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to log in' });
    }
});

app.get('/api/user', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('name');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ name: user.name });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

app.post('/api/score', authenticateJWT, async (req, res) => {
    const { score } = req.body;
    if (score === undefined) {
        return res.status(400).json({ error: 'Score is required' });
    }
    try {
        const newScore = new Score({ score });
        await newScore.save();
        res.status(201).json({ message: 'Score saved successfully' });
    } catch (error) {
        console.error('Error saving score:', error);
        res.status(500).json({ error: 'Failed to save score' });
    }
});

app.get('/api/scores', authenticateJWT, async (req, res) => {
    try {
        const scores = await Score.find().sort({ date: -1 }).limit(10);
        res.json(scores.map(s => ({ score: s.score, date: s.date })));
    } catch (error) {
        console.error('Error fetching scores:', error);
        res.status(500).json({ error: 'Failed to fetch scores' });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
