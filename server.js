
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();


app.use(express.json({
    limit: '100kb'
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGIN?.split(',') || ['http://localhost:3000']
}));

app.use(express.static(path.join(__dirname, 'public')));
const API_KEY =process.env.BRAWL_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const msgLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: {
        error: 'Слишком много запросов'
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        error: 'Слишком много попыток входа'
    }
});

let posts = [];
let reports = [];
let users = [];
let messages = [];

function auth(req, res, next) {
    const header = req.headers.authorization;

    if (!header) {
        return res.status(401).json({
            error: 'Нет токена'
        });
    }

    try {
        const token = header.split(' ')[1];

        req.user = jwt.verify(
            token,
            JWT_SECRET
        );

        next();
    } catch {
        return res.status(401).json({
            error: 'Недействительный токен'
        });
    }
}

function sanitize(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// --- API: АВТОРИЗАЦИЯ ---
app.post('/api/register', authLimiter, async (req, res) => {
    const username = sanitize(req.body.username).trim();
    const password = req.body.password;

    if (
        !username ||
        username.length < 3 ||
        username.length > 30
    ) {
        return res.status(400).json({
            error: 'Логин должен быть от 3 до 30 символов'
        });
    }

    if (
        !password ||
        password.length < 8
    ) {
        return res.status(400).json({
            error: 'Пароль минимум 8 символов'
        });
    }

    if (
        users.find(
            u =>
                u.username.toLowerCase() ===
                username.toLowerCase()
        )
    ) {
        return res.status(400).json({
            error: 'Этот никнейм уже занят'
        });
    }

    const passwordHash =
        await bcrypt.hash(password, 12);

    users.push({
        username,
        passwordHash
    });

    res.json({
        success: true
    });
});

app.post('/api/login', authLimiter, async (req, res) => {
    const username = sanitize(req.body.username).trim();
    const password = req.body.password;

    const user = users.find(
        u =>
            u.username.toLowerCase() ===
            username.toLowerCase()
    );

    if (!user) {
        return res.status(401).json({
            error: 'Неверный логин или пароль'
        });
    }

    const validPassword =
        await bcrypt.compare(
            password,
            user.passwordHash
        );

    if (!validPassword) {
        return res.status(401).json({
            error: 'Неверный логин или пароль'
        });
    }

    const token = jwt.sign(
        {
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: '7d'
        }
    );

    res.json({
        username: user.username,
        token
    });
});

// --- API: ЧАТ ---
app.get('/api/messages', (req, res) => res.json(messages));

app.post('/api/messages', msgLimiter, (req, res) => {
    const { username, text } = req.body;
    if (!username || !text || text.trim() === "") return res.status(400).send("Bad request");

    const newMessage = {
        username: sanitize(username),
        text: sanitize(text),
        time: new Date().toLocaleTimeString()
    };
    messages.push(newMessage);
    if (messages.length > 50) messages.shift();

    res.json(newMessage);
});

// --- API: BRAWL STARS ---

app.get('/api/player/:tag', async (req, res) => {
    try {
        if (!API_KEY) {
            return res.status(500).json({
                error: 'BRAWL_API_KEY не найден в .env'
            });
        }

        let tag = req.params.tag.toUpperCase();

        if (tag.startsWith('#')) {
            tag = tag.substring(1);
        }

        tag = `%23${tag}`;

        const response = await axios.get(
            `https://api.brawlstars.com/v1/players/${tag}`,
            {
                headers: {
                    Authorization: `Bearer ${API_KEY}`
                },
                timeout: 10000
            }
        );

        res.json(response.data);

    } catch (e) {
        console.error('=== BRAWL API ERROR ===');
        console.error('Status:', e.response?.status);
        console.error('Data:', e.response?.data);
        console.error('Message:', e.message);

        res.status(e.response?.status || 500).json({
            error: e.response?.data?.reason || e.message
        });
    }
});
// --- API: ПОСТЫ ---
app.get('/api/posts', (req, res) => res.json(posts));

app.post('/api/posts', msgLimiter, (req, res) => {
    const name = sanitize(req.body.name);
    const tag = sanitize(req.body.tag);
    const contact = sanitize(req.body.contact);
    const mode = sanitize(req.body.mode);
    const bio = sanitize(req.body.bio || "Игрок не оставил описания."); // Новое поле "О себе"

    if(!name || !tag || !mode) return res.status(400).json({ error: "Заполните обязательные поля!" });

    const newPost = { id: Date.now(), name, tag, contact, mode, bio };
    posts.push(newPost);
    res.status(201).json(newPost);
});

// --- API: ЖАЛОБЫ ---
app.post('/api/reports', (req, res) => {
    const reporter = sanitize(req.body.reporter || "Аноним");
    const targetTag = sanitize(req.body.targetTag);
    const targetName = sanitize(req.body.targetName);
    const reason = sanitize(req.body.reason);

    const report = { id: Date.now(), reporter, targetTag, targetName, reason };
    reports.push(report);
    console.log(`⚠️ ЖАЛОБА от ${reporter} на игрока ${targetName} (${targetTag}): "${reason}"`);
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('==========================================');
    console.log(`СЕРВЕР ЗАПУЩЕН НА PORT: ${PORT}`);
    console.log('==========================================');
});
