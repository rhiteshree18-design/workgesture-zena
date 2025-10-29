const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// ✅ CORS: Allow frontend to connect (Render + localhost)
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://127.0.0.1:5500',
        'https://your-render-app-name.onrender.com' // add your Render domain here later
    ],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

// ✅ Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || 'Hetu1812',
    database: process.env.DB_NAME || 'zena'
});

db.connect(err => {
    if (err) {
        console.error('❌ Database connection failed:', err.stack);
        return;
    }
    console.log('✅ Connected to MySQL database.');
});

// ✅ Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword)
        return res.status(400).send('All fields are required.');

    if (password !== confirmPassword)
        return res.status(400).send('Passwords do not match.');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)';

        db.query(query, [name, email, hashedPassword], (err) => {
            if (err) {
                console.error('❌ Signup DB Error:', err);
                if (err.code === 'ER_DUP_ENTRY')
                    return res.status(409).send('Email already exists.');
                return res.status(500).send('Database error.');
            }
            res.status(201).send('User registered successfully.');
        });
    } catch (err) {
        console.error('❌ Signup Server Error:', err);
        res.status(500).send('Server error.');
    }
});

// ✅ Login Route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).send('Email and password are required.');

    const query = 'SELECT email, password_hash FROM users WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('❌ Login DB Error:', err);
            return res.status(500).send('Database error.');
        }

        console.log('✅ Query results:', results);

        if (results.length === 0)
            return res.status(401).send('Invalid email or password.');

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch)
            return res.status(401).send('Invalid email or password.');

        res.status(200).send('Login successful.');
    });
});

// ✅ Start Server
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});
