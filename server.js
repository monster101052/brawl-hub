require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const API_KEY = process.env.BRAWL_API_KEY;

const msgLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 30,
    message: { error: "Слишком много запросов. Пожалуйста, подождите немного." }
});

let posts = [];
let reports = [];
let users = [];
let messages = [];

function sanitize(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// --- API: АВТОРИЗАЦИЯ ---
app.post('/api/register', (req, res) => {
    const username = sanitize(req.body.username).trim();
    const password = req.body.password;

    if (!username || !password || username.length < 3 || password.length < 4) {
        return res.status(400).json({ error: "Логин (мин. 3 симв.) и пароль (мин. 4 симв.) обязательны!" });
    }

    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: "Этот никнейм уже занят!" });
    }

    users.push({
        username,
        passwordHash: hashPassword(password)
    });
    res.json({ success: true });
});

app.post('/api/login', (req, res) => {
    const username = sanitize(req.body.username).trim();
    const password = req.body.password;

    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user || user.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: "Неверный логин или пароль!" });
    }

    res.json({ username: user.username });
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
});// --- API: BRAWL STARS ---
app.get('/api/player/:tag', async (req, res) => {
    try {
        let tag = req.params.tag;
        if (!tag.startsWith('%23')) {
            tag = `%23${tag.replace('#', '')}`;
        }
        const response = await axios.get(`https://api.brawlstars.com/v1/players/${tag}`, {
            headers: { 'Authorization': `Bearer ${API_KEY}` }
        });
        res.json(response.data);
    } catch (e) {
        res.status(500).json({ error: "Ошибка при получении профиля. Проверьте тег." });
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