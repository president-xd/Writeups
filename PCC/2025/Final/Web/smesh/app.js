const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 3600000
    }
}));

const users = new Map();
const posts = new Map();
const analytics = new Map();

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = crypto.randomBytes(32).toString('hex');

users.set(ADMIN_USERNAME, {
    username: ADMIN_USERNAME,
    password: ADMIN_PASSWORD,
    role: 'admin',
    credits: 1000000
});

function formatUsername(input) {
    return input.normalize('NFKC').toLowerCase();
}

function isAdmin(req) {
    return req.session.user && req.session.user.role === 'admin';
}

function checkPremium(req) {
    return req.session.user && (req.session.user.premium === true || req.session.user.role === 'admin');
}

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.render('login', { error: 'Please provide both username and password' });
    }

    const name = formatUsername(username);
    const user = users.get(name);
    
    if (!user || user.password !== password) {
        return res.render('login', { error: 'Invalid credentials' });
    }

    req.session.user = {
        username: user.username,
        credits: user.credits,
    };

    res.redirect('/dashboard');
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, success: null });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.render('register', { error: 'Please provide both username and password', success: null });
    }

    if (password.length < 6) {
        return res.render('register', { error: 'Password must be at least 6 characters', success: null });
    }

    const name = formatUsername(username);
    
    if (name === 'admin') {
        return res.render('register', { error: 'This username is reserved', success: null });
    }

    if (users.has(name)) {
        return res.render('register', { error: 'Username already exists', success: null });
    }

    const newUser = {
        username: name,
        password: password,
        role: 'user',
        credits: 100,
        premium: false
    };

    users.set(name, newUser);
    res.render('register', { error: null, success: 'Account created! You can now login.' });
});

app.get('/dashboard', requireAuth, (req, res) => {
    const userPosts = Array.from(posts.values()).filter(p => p.author === req.session.user.username);
    res.render('dashboard', { 
        user: req.session.user, 
        posts: userPosts,
        isAdmin: isAdmin(req)
    });
});

app.get('/create-post', requireAuth, (req, res) => {
    res.render('create-post', { user: req.session.user, error: null });
});

app.post('/create-post', requireAuth, (req, res) => {
    const { title, content, scheduled } = req.body;
    
    if (!title || !content) {
        return res.render('create-post', { user: req.session.user, error: 'Title and content are required' });
    }

    if (req.session.user.credits < 5 && !isAdmin(req)) {
        return res.render('create-post', { user: req.session.user, error: 'Insufficient credits. You need 5 credits to post.' });
    }

    const postId = crypto.randomUUID();
    const post = {
        id: postId,
        title,
        content,
        author: req.session.user.username,
        scheduled: scheduled || false,
        createdAt: Date.now()
    };

    posts.set(postId, post);

    if (!isAdmin(req)) {
        req.session.user.credits -= 5;
        const user = users.get(req.session.user.username);
        if (user) {
            user.credits = req.session.user.credits;
        }
    }

    res.redirect('/dashboard');
});

function merge(target, source) {
    for (let key in source) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) {
                target[key] = {};
            }
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function validate(data) {
    const result = {};
    for (let key in data) {
        result[key] = (key === "theme" || key === "language") ? data[key].toString() : data[key];
    }
    return result;
}

app.post('/api/settings', requireAuth, (req, res) => {
    try {
        const { theme, language, notifications } = req.body;
        
        if (!theme || !language) {
            return res.json({ success: false, error: 'Theme and language are required' });
        }

        if (typeof theme !== 'string' || typeof language !== 'string') {
            return res.json({ success: false, error: 'Invalid settings format' });
        }

        const config = validate(JSON.parse(`{"theme": "${theme}", "language": "${language}", "notifications": false}`));

        if (!req.session.user.settings) {
            req.session.user.settings = {};
        }

        merge(req.session.user.settings, validate(config));
        res.json({ success: true, message: 'Settings updated successfully' });
    } catch (error) {
        res.json({ success: false, error: 'Invalid settings data' });
    }
});

app.get('/analytics', requireAuth, (req, res) => {
    if (!checkPremium(req)) {
        return res.render('analytics', { 
            user: req.session.user, 
            error: 'This feature requires premium membership',
            analytics: null 
        });
    }

    const userPosts = Array.from(posts.values()).filter(p => p.author === req.session.user.username);
    const data = {
        totalPosts: userPosts.length,
        totalViews: userPosts.reduce((sum, p) => sum + (analytics.get(p.id)?.views || 0), 0),
        avgEngagement: userPosts.length > 0 ? Math.random() * 100 : 0
    };

    res.render('analytics', { 
        user: req.session.user, 
        error: null,
        analytics: data 
    });
});

let locks = new Map();

app.post('/api/buy-credits', requireAuth, async (req, res) => {
    const { amount } = req.body;
    
    if (!amount || isNaN(amount) || amount <= 0) {
        return res.json({ success: false, error: 'Invalid amount' });
    }

    const username = req.session.user.username;
    const cost = Math.floor(amount / 10);

    if (req.session.user.credits < cost) {
        return res.json({ success: false, error: 'Insufficient funds for this purchase' });
    }

    const user = users.get(username);
    
    if (!user) {
        return res.json({ success: false, error: 'User not found' });
    }

    await new Promise(resolve => setTimeout(resolve, 100));

    if (user.credits < cost) {
        return res.json({ success: false, error: 'Insufficient funds' });
    }

    user.credits -= cost;
    user.credits += amount;
    req.session.user.credits = user.credits;

    res.json({ success: true, credits: user.credits });
});

app.get('/admin', requireAuth, (req, res) => {
    if (!isAdmin(req)) {
        return res.status(403).send('Access Denied: Admin privileges required');
    }

    let flag = 'PCC{FAKE_FLAG_FOR_TESTING}';
    try {
        flag = fs.readFileSync('/flag.txt', 'utf8').trim();
    } catch (error) {
        console.error('Error reading flag:', error);
    }

    res.render('admin', { 
        user: req.session.user,
        flag: flag,
        totalUsers: users.size,
        totalPosts: posts.size
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

app.listen(PORT, () => {
    console.log(`[*] Smesh Social Media Dashboard running on port ${PORT}`);
    console.log(`[*] Admin credentials: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}`);
});
