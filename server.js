const session = require('express-session');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
}));

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'secure_storage',
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database!');
});

// Default route: Always redirect to login page
app.get('/', (req, res) => {
    res.redirect('/login.html'); // Redirect directly to login.html
});

// Serve static files after defining other routes
app.use(express.static('public')); // This will serve static files like index.html, login.html, etc.

// Middleware to check authentication
function checkAuth(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login.html');
}

// Routes for signup and login
app.post('/signup', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error hashing password.');

        const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(query, [username, hashedPassword], (err) => {
            if (err) {
                console.error('Error creating user:', err);
                return res.status(500).send('Error creating user.');
            }
            res.redirect('/login.html');
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).send('Error checking user.');

        if (results.length === 0) {
            return res.status(401).send('Invalid credentials.');
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Error comparing passwords.');

            if (!isMatch) {
                return res.status(401).send('Invalid credentials.');
            }

            // Save user session
            req.session.userId = user.id;
            res.redirect('/index.html');
        });
    });
});

app.use('/index.html', checkAuth);
app.use('/files.html', checkAuth);

// Configure file upload
const upload = multer({ dest: 'uploads/' });

// In-memory file database
const fileDatabase = {};

// Route: Upload File
app.post('/upload', upload.single('file'), (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).send('No file uploaded.');

    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);

    const input = fs.createReadStream(file.path);
    const encryptedPath = `${file.path}.enc`;
    const output = fs.createWriteStream(encryptedPath);

    input.pipe(cipher).pipe(output).on('finish', () => {
        const publicKey = fs.readFileSync('keys/public.pem', 'utf8');
        const encryptedAesKey = crypto.publicEncrypt(publicKey, aesKey).toString('base64');

        const fileId = uuidv4();
        fileDatabase[fileId] = {
            originalName: file.originalname,
            filePath: encryptedPath,
            mimeType: file.mimetype, // Save the original MIME type
            iv: iv.toString('hex'),
            encryptedAesKey,
        };

        fs.unlinkSync(file.path);

        res.json({
            message: 'File uploaded successfully!',
            fileId,
            encryptedAesKey,
        });
    }).on('error', (err) => {
        console.error('Error during encryption:', err);
        res.status(500).send('Error during file encryption.');
    });
});

// Route: Download File
app.post('/download', (req, res) => {
    const { fileId, encryptedAesKey } = req.body;

    if (!fileId || !encryptedAesKey) return res.status(400).send('File ID and encryption key are required.');

    const fileData = fileDatabase[fileId];
    if (!fileData) return res.status(404).send('File not found.');

    const privateKey = fs.readFileSync('keys/private.pem', 'utf8');
    let aesKey;
    try {
        aesKey = crypto.privateDecrypt(privateKey, Buffer.from(encryptedAesKey, 'base64'));
    } catch (err) {
        console.error('Error decrypting AES key:', err);
        return res.status(403).send('Invalid encryption key.');
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(fileData.iv, 'hex'));

    const input = fs.createReadStream(fileData.filePath);
    const outputPath = path.resolve(`${fileData.filePath}.dec`);
    const output = fs.createWriteStream(outputPath);

    input.pipe(decipher).pipe(output).on('finish', () => {
        // Set correct headers for file download
        res.setHeader('Content-Disposition', `attachment; filename="${fileData.originalName}"`);
        res.setHeader('Content-Type', fileData.mimeType);

        // Use path.resolve to ensure an absolute path
        res.sendFile(outputPath, (err) => {
            if (!err) fs.unlinkSync(outputPath); // Delete decrypted file after sending
        });
    }).on('error', (err) => {
        console.error('Decryption error:', err);
        res.status(500).send('Error during file decryption.');
    });
});

// Route: View All Files
app.get('/files', (req, res) => {
    const files = Object.entries(fileDatabase).map(([id, data]) => ({
        fileId: id,
        originalName: data.originalName,
    }));
    res.json(files);
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));
