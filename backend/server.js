'use strict';

/**
 * ============================================================
 * LOKI LIVE / MIROTALK C2C SERVER
 * ============================================================
 *
 * يحتوي هذا الملف على:
 *
 * 1. WebRTC rooms
 * 2. Socket.IO signaling
 * 3. Basic Authentication
 * 4. OIDC
 * 5. CORS
 * 6. Swagger API
 * 7. STUN / TURN
 * 8. Ngrok
 * 9. Mattermost
 * 10. Global Public Chat
 *
 * ============================================================
 *
 * GLOBAL PUBLIC CHAT
 *
 * الدردشة العامة ليست مرتبطة بالغرف.
 *
 * Events:
 *
 * client -> server:
 *
 *   globalChatSend
 *
 * server -> client:
 *
 *   globalChatHistory
 *   globalChatMessage
 *   globalChatSystem
 *
 * ============================================================
 */

require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const {
    auth,
    requiresAuth,
} = require('express-openid-connect');

const {
    Server,
} = require('socket.io');

const httpolyglot =
    require('httpolyglot');

const compression =
    require('compression');

const express =
    require('express');

const cors =
    require('cors');

const helmet =
    require('helmet');

const checkXSS =
    require('./xss.js');

const ngrok =
    require('@ngrok/ngrok');

const logs =
    require('./logs');

const ServerApi =
    require('./api');

const mattermostCli =
    require('./mattermost');

const sentry =
    require('./sentry');

const {
    applyEmbedHeaders,
    embedAllowedOrigins,
    embedCsp,
} = require('./embedHeaders');

const yaml =
    require('js-yaml');

const swaggerUi =
    require('swagger-ui-express');

const nodemailer =
    require('./lib/nodemailer');

const app =
    express();

const log =
    new logs('server');

/* ============================================================
   SENTRY
============================================================ */

sentry.start();

/* ============================================================
   SWAGGER
============================================================ */

const swaggerDocument =
    yaml.load(
        fs.readFileSync(
            path.join(
                __dirname,
                '/api/swagger.yaml'
            ),
            'utf8'
        )
    );

/* ============================================================
   CONSTANTS
============================================================ */

const queryJoin =
    '/join?room=test&name=test';

const queryRoom =
    '/?room=test';

const packageJson =
    require('../package.json');

/* ============================================================
   SSL
============================================================ */

const keyPath =
    path.join(
        __dirname,
        'ssl/key.pem'
    );

const certPath =
    path.join(
        __dirname,
        'ssl/cert.pem'
    );

let sslOptions = null;

try {
    sslOptions = {
        key:
            fs.readFileSync(
                keyPath,
                'utf8'
            ),

        cert:
            fs.readFileSync(
                certPath,
                'utf8'
            ),
    };
} catch (error) {
    log.warn(
        'SSL certificate files could not be loaded.',
        error.message
    );

    /*
     * Render/proxies may terminate HTTPS
     * before reaching Node.
     */
    sslOptions = null;
}

/* ============================================================
   HTTP / HTTPS SERVER
============================================================ */

const server =
    sslOptions
        ? httpolyglot.createServer(
              sslOptions,
              app
          )
        : require('http').createServer(
              app
          );

/* ============================================================
   BASIC AUTH
============================================================ */

const BASIC_AUTH_ENABLED =
    getEnvBoolean(
        process.env.BASIC_AUTH_ENABLED
    );

const BASIC_AUTH_USERNAME =
    process.env.BASIC_AUTH_USERNAME ||
    '';

const BASIC_AUTH_PASSWORD =
    process.env.BASIC_AUTH_PASSWORD ||
    '';

const BASIC_AUTH_SECRET =
    process.env.BASIC_AUTH_SECRET ||
    'CHANGE_THIS_SECRET_IN_RENDER';

const BASIC_AUTH_COOKIE =
    'loki_live_auth';

const MAX_LOGIN_ATTEMPTS =
    10;

const BASIC_AUTH_BLOCK_DURATION_MS =
    Number(
        process.env.BASIC_AUTH_BLOCK_DURATION_MS ||
        86400000
    );

const BASIC_AUTH_SESSION_MS =
    Number(
        process.env.BASIC_AUTH_SESSION_MS ||
        86400000
    );

const loginSecurity =
    new Map();

if (
    BASIC_AUTH_ENABLED &&
    (
        !BASIC_AUTH_USERNAME ||
        !BASIC_AUTH_PASSWORD
    )
) {
    log.error(
        'BASIC_AUTH_ENABLED=true but BASIC_AUTH_USERNAME or BASIC_AUTH_PASSWORD is missing'
    );

    process.exit(1);
}

if (
    BASIC_AUTH_ENABLED &&
    BASIC_AUTH_SECRET ===
        'CHANGE_THIS_SECRET_IN_RENDER'
) {
    log.warn(
        'WARNING: BASIC_AUTH_SECRET is using the default value. Change it in Render!'
    );
}

/* ============================================================
   GLOBAL PUBLIC CHAT
   ============================================================ */

/*
 * عدد الرسائل التي نحفظها.
 */
const GLOBAL_CHAT_MAX_MESSAGES =
    Math.max(
        10,
        Number(
            process.env.GLOBAL_CHAT_MAX_MESSAGES ||
            100
        )
    );

/*
 * الحد الأقصى لطول الاسم.
 */
const GLOBAL_CHAT_MAX_NAME_LENGTH =
    Math.max(
        3,
        Math.min(
            50,
            Number(
                process.env.GLOBAL_CHAT_MAX_NAME_LENGTH ||
                36
            )
        )
    );

/*
 * الحد الأقصى لطول الرسالة.
 */
const GLOBAL_CHAT_MAX_MESSAGE_LENGTH =
    Math.max(
        50,
        Math.min(
            2000,
            Number(
                process.env.GLOBAL_CHAT_MAX_MESSAGE_LENGTH ||
                500
            )
        )
    );

/*
 * ملف حفظ الدردشة العامة.
 */
const globalChatFile =
    path.join(
        __dirname,
        'global-chat.json'
    );

/*
 * تخزين الرسائل في الذاكرة.
 */
let globalChatMessages = [];

/*
 * إنشاء ملف الدردشة إذا لم يكن موجوداً.
 */
function ensureGlobalChatFile() {
    try {
        const dir =
            path.dirname(
                globalChatFile
            );

        if (
            !fs.existsSync(dir)
        ) {
            fs.mkdirSync(
                dir,
                {
                    recursive: true,
                }
            );
        }

        if (
            !fs.existsSync(
                globalChatFile
            )
        ) {
            fs.writeFileSync(
                globalChatFile,
                '[]',
                'utf8'
            );
        }
    } catch (error) {
        log.error(
            'Unable to create global chat file',
            error
        );
    }
}

/*
 * تحميل الرسائل القديمة.
 */
function loadGlobalChat() {
    ensureGlobalChatFile();

    try {
        const raw =
            fs.readFileSync(
                globalChatFile,
                'utf8'
            );

        const parsed =
            JSON.parse(raw);

        if (
            Array.isArray(parsed)
        ) {
            globalChatMessages =
                parsed
                    .filter(
                        isValidChatMessage
                    )
                    .slice(
                        -GLOBAL_CHAT_MAX_MESSAGES
                    );
        } else {
            globalChatMessages = [];
        }

        log.info(
            `Global chat loaded: ${globalChatMessages.length} messages`
        );
    } catch (error) {
        globalChatMessages = [];

        log.warn(
            'Could not load global chat history',
            error.message
        );
    }
}

/*
 * فحص رسالة محفوظة.
 */
function isValidChatMessage(
    message
) {
    if (
        !message ||
        typeof message !==
            'object'
    ) {
        return false;
    }

    return (
        typeof message.id ===
            'string' &&
        typeof message.name ===
            'string' &&
        typeof message.message ===
            'string' &&
        typeof message.timestamp ===
            'number'
    );
}

/*
 * حفظ الدردشة.
 */
function saveGlobalChat() {
    try {
        ensureGlobalChatFile();

        fs.writeFileSync(
            globalChatFile,
            JSON.stringify(
                globalChatMessages,
                null,
                2
            ),
            'utf8'
        );
    } catch (error) {
        log.error(
            'Could not save global chat',
            error
        );
    }
}

/*
 * تنظيف اسم المستخدم.
 */
function sanitizeChatName(
    value
) {
    let name =
        typeof value ===
            'string'
            ? value
            : '';

    name =
        name
            .replace(
                /\s+/g,
                ' '
            )
            .trim();

    name =
        checkXSS(name);

    if (
        !name
    ) {
        name =
            'زائر';
    }

    return name.substring(
        0,
        GLOBAL_CHAT_MAX_NAME_LENGTH
    );
}

/*
 * تنظيف الرسالة.
 */
function sanitizeChatMessage(
    value
) {
    let message =
        typeof value ===
            'string'
            ? value
            : '';

    /*
     * إزالة null characters.
     */
    message =
        message.replace(
            /\0/g,
            ''
        );

    /*
     * توحيد الأسطر.
     */
    message =
        message.replace(
            /\r\n/g,
            '\n'
        );

    message =
        message.trim();

    /*
     * XSS filter.
     */
    message =
        checkXSS(message);

    /*
     * منع HTML الناتج.
     */
    message =
        message
            .replace(
                /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
                ''
            );

    return message.substring(
        0,
        GLOBAL_CHAT_MAX_MESSAGE_LENGTH
    );
}

/*
 * إنشاء ID للرسالة.
 */
function createChatMessageId() {
    return (
        Date.now().toString(36) +
        '-' +
        crypto
            .randomBytes(8)
            .toString('hex')
    );
}

/*
 * إضافة رسالة للدردشة.
 */
function addGlobalChatMessage(
    name,
    message
) {
    const chatMessage = {
        id:
            createChatMessageId(),

        name:
            sanitizeChatName(
                name
            ),

        message:
            sanitizeChatMessage(
                message
            ),

        timestamp:
            Date.now(),
    };

    if (
        !chatMessage.message
    ) {
        return null;
    }

    globalChatMessages.push(
        chatMessage
    );

    if (
        globalChatMessages.length >
        GLOBAL_CHAT_MAX_MESSAGES
    ) {
        globalChatMessages =
            globalChatMessages.slice(
                -GLOBAL_CHAT_MAX_MESSAGES
            );
    }

    saveGlobalChat();

    return chatMessage;
}

/*
 * تحميل الدردشة عند تشغيل السيرفر.
 */
loadGlobalChat();

/* ============================================================
   CLIENT IP
============================================================ */

function getClientIp(
    req
) {
    const forwarded =
        req.headers[
            'x-forwarded-for'
        ];

    if (
        forwarded
    ) {
        const firstIp =
            String(
                forwarded
            )
                .split(',')[0]
                .trim();

        if (
            firstIp
        ) {
            return firstIp;
        }
    }

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        'unknown'
    );
}

/* ============================================================
   SOCKET CLIENT IP
============================================================ */

function getSocketIp(
    socket
) {
    const headers =
        socket.handshake
            ?.headers || {};

    const forwarded =
        headers[
            'x-forwarded-for'
        ];

    if (
        forwarded
    ) {
        return String(
            forwarded
        )
            .split(',')[0]
            .trim();
    }

    return (
        socket.handshake?.address ||
        'unknown'
    );
}

/* ============================================================
   SECURITY STORE
============================================================ */

function getSecurityRecord(
    ip
) {
    let record =
        loginSecurity.get(
            ip
        );

    if (
        !record
    ) {
        record = {
            attempts: 0,
            blockedUntil: 0,
        };

        loginSecurity.set(
            ip,
            record
        );
    }

    return record;
}

function isIpBlocked(
    ip
) {
    const record =
        loginSecurity.get(
            ip
        );

    if (
        !record
    ) {
        return false;
    }

    if (
        record.blockedUntil &&
        Date.now() <
            record.blockedUntil
    ) {
        return true;
    }

    if (
        record.blockedUntil &&
        Date.now() >=
            record.blockedUntil
    ) {
        loginSecurity.delete(
            ip
        );

        return false;
    }

    return false;
}

function registerFailedLogin(
    ip
) {
    const record =
        getSecurityRecord(
            ip
        );

    record.attempts += 1;

    if (
        record.attempts >=
        MAX_LOGIN_ATTEMPTS
    ) {
        record.blockedUntil =
            Date.now() +
            BASIC_AUTH_BLOCK_DURATION_MS;

        loginSecurity.set(
            ip,
            record
        );

        log.warn(
            'IP BLOCKED AFTER 10 FAILED LOGIN ATTEMPTS',
            {
                ip,
                attempts:
                    record.attempts,
                blockedUntil:
                    new Date(
                        record.blockedUntil
                    ).toISOString(),
            }
        );

        return {
            blocked: true,
            attempts:
                record.attempts,
        };
    }

    loginSecurity.set(
        ip,
        record
    );

    return {
        blocked: false,
        attempts:
            record.attempts,
    };
}

function resetLoginAttempts(
    ip
) {
    loginSecurity.delete(
        ip
    );
}

/* ============================================================
   AUTH SIGNATURE
============================================================ */

function createAuthSignature(
    timestamp
) {
    return crypto
        .createHmac(
            'sha256',
            BASIC_AUTH_SECRET
        )
        .update(
            String(timestamp)
        )
        .digest('hex');
}

/* ============================================================
   AUTH COOKIE
============================================================ */

function createAuthCookie() {
    const timestamp =
        Date.now();

    const signature =
        createAuthSignature(
            timestamp
        );

    return (
        `${timestamp}.${signature}`
    );
}

function verifyAuthCookie(
    cookieValue
) {
    if (
        !cookieValue
    ) {
        return false;
    }

    const parts =
        String(
            cookieValue
        ).split('.');

    if (
        parts.length !== 2
    ) {
        return false;
    }

    const timestamp =
        Number(
            parts[0]
        );

    const signature =
        parts[1];

    if (
        !Number.isFinite(
            timestamp
        ) ||
        !signature
    ) {
        return false;
    }

    const age =
        Date.now() -
        timestamp;

    if (
        age >
            BASIC_AUTH_SESSION_MS ||
        age < 0
    ) {
        return false;
    }

    const expectedSignature =
        createAuthSignature(
            timestamp
        );

    try {
        const signatureBuffer =
            Buffer.from(
                signature
            );

        const expectedBuffer =
            Buffer.from(
                expectedSignature
            );

        if (
            signatureBuffer.length !==
            expectedBuffer.length
        ) {
            return false;
        }

        return crypto.timingSafeEqual(
            signatureBuffer,
            expectedBuffer
        );
    } catch {
        return false;
    }
}

/* ============================================================
   COOKIE READER
============================================================ */

function getCookie(
    req,
    cookieName
) {
    const cookieHeader =
        req.headers.cookie;

    if (
        !cookieHeader
    ) {
        return null;
    }

    const cookies =
        cookieHeader.split(';');

    for (
        const cookie of cookies
    ) {
        const separator =
            cookie.indexOf('=');

        if (
            separator === -1
        ) {
            continue;
        }

        const name =
            cookie
                .substring(
                    0,
                    separator
                )
                .trim();

        const value =
            cookie
                .substring(
                    separator + 1
                )
                .trim();

        if (
            name ===
            cookieName
        ) {
            try {
                return decodeURIComponent(
                    value
                );
            } catch {
                return value;
            }
        }
    }

    return null;
}

/* ============================================================
   PASSWORD COMPARISON
============================================================ */

function safeStringEqual(
    a,
    b
) {
    if (
        typeof a !== 'string' ||
        typeof b !== 'string'
    ) {
        return false;
    }

    const aBuffer =
        Buffer.from(a);

    const bBuffer =
        Buffer.from(b);

    if (
        aBuffer.length !==
        bBuffer.length
    ) {
        return false;
    }

    try {
        return crypto.timingSafeEqual(
            aBuffer,
            bBuffer
        );
    } catch {
        return false;
    }
}

function checkLoginCredentials(
    username,
    password
) {
    return (
        safeStringEqual(
            username,
            BASIC_AUTH_USERNAME
        ) &&
        safeStringEqual(
            password,
            BASIC_AUTH_PASSWORD
        )
    );
}

/* ============================================================
   HTTP AUTH CHECK
============================================================ */

function isHttpAuthenticated(
    req
) {
    if (
        !BASIC_AUTH_ENABLED
    ) {
        return true;
    }

    const cookie =
        getCookie(
            req,
            BASIC_AUTH_COOKIE
        );

    return verifyAuthCookie(
        cookie
    );
}

/* ============================================================
   AUTH COOKIE
============================================================ */

function setAuthCookie(
    res,
    req
) {
    const value =
        createAuthCookie();

    const isHttps =
        req.secure ||
        req.headers[
            'x-forwarded-proto'
        ] === 'https';

    const secure =
        isHttps
            ? '; Secure'
            : '';

    res.setHeader(
        'Set-Cookie',
        `${BASIC_AUTH_COOKIE}=${encodeURIComponent(
            value
        )}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(
            BASIC_AUTH_SESSION_MS / 1000
        )}${secure}`
    );
}

function clearAuthCookie(
    res,
    req
) {
    const isHttps =
        req.secure ||
        req.headers[
            'x-forwarded-proto'
        ] === 'https';

    const secure =
        isHttps
            ? '; Secure'
            : '';

    res.setHeader(
        'Set-Cookie',
        `${BASIC_AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
    );
}

/* ============================================================
   HTML ESCAPE
============================================================ */

function escapeHtml(
    value
) {
    return String(value)
        .replace(
            /&/g,
            '&amp;'
        )
        .replace(
            /</g,
            '&lt;'
        )
        .replace(
            />/g,
            '&gt;'
        )
        .replace(
            /"/g,
            '&quot;'
        )
        .replace(
            /'/g,
            '&#039;'
        );
}

/* ============================================================
   LOGIN PAGE
============================================================ */

function sendLoginPage(
    res,
    message = ''
) {
    const safeMessage =
        escapeHtml(
            message
        );

    return res
        .status(200)
        .send(
            `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Loki Live - Login</title>
<style>
* {
    box-sizing:border-box;
}

html,
body {
    margin:0;
    padding:0;
    min-height:100%;
    font-family:Arial,Helvetica,sans-serif;
    background:linear-gradient(
        135deg,
        #0d0f14,
        #171a21
    );
    color:#fff;
}

body {
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
}

.login-box {
    width:100%;
    max-width:400px;
    padding:32px;
    border-radius:20px;
    background:#1a1d23;
    border:1px solid rgba(255,255,255,.09);
    box-shadow:0 25px 70px rgba(0,0,0,.5);
}

.logo {
    width:78px;
    height:78px;
    margin:0 auto 18px;
    border-radius:50%;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#fff;
    color:#111318;
    font-size:40px;
}

h1 {
    text-align:center;
    margin:0 0 8px;
    font-size:28px;
}

.subtitle {
    text-align:center;
    color:#9da3ad;
    margin:0 0 26px;
    font-size:14px;
}

.error {
    background:rgba(220,38,38,.12);
    border:1px solid rgba(220,38,38,.30);
    color:#ff9696;
    border-radius:10px;
    padding:12px;
    margin-bottom:18px;
    font-size:14px;
    text-align:center;
}

label {
    display:block;
    margin:0 0 7px;
    font-size:14px;
}

input {
    width:100%;
    height:50px;
    border:1px solid #343944;
    border-radius:10px;
    background:#101217;
    color:#fff;
    padding:0 14px;
    outline:none;
    margin-bottom:18px;
    font-size:16px;
}

button {
    width:100%;
    height:50px;
    border:0;
    border-radius:10px;
    background:#fff;
    color:#111318;
    font-size:16px;
    font-weight:700;
    cursor:pointer;
}

.footer {
    text-align:center;
    color:#686f7b;
    margin-top:20px;
    font-size:12px;
}
</style>
</head>

<body>

<div class="login-box">

<div class="logo">🥕</div>

<h1>The rabbit in the hole</h1>

<p class="subtitle">
Sign in to continue
</p>

${
    safeMessage
        ? `<div class="error">${safeMessage}</div>`
        : ''
}

<form
    method="POST"
    action="/auth/login"
    autocomplete="on"
>

<label for="username">
Username
</label>

<input
    id="username"
    name="username"
    type="text"
    autocomplete="username"
    required
    autofocus
>

<label for="password">
Password
</label>

<input
    id="password"
    name="password"
    type="password"
    autocomplete="current-password"
    required
>

<button type="submit">
Login
</button>

</form>

<div class="footer">
https://live-six-hole.onrender.com
</div>

</div>

</body>
</html>`
        );
}

/* ============================================================
   BLOCKED PAGE
============================================================ */

function sendBlockedPage(
    res
) {
    return res
        .status(403)
        .send(
            `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Loki Live - Access Blocked</title>
<style>
body {
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#111318;
    color:#fff;
    font-family:Arial,sans-serif;
    padding:20px;
}
.box {
    max-width:430px;
    text-align:center;
    background:#1a1d23;
    padding:36px;
    border-radius:18px;
}
p {
    color:#a8adb7;
    line-height:1.6;
}
</style>
</head>
<body>
<div class="box">
<h1>Access Blocked</h1>
<p>
Too many failed login attempts were detected.
</p>
<p>
Please try again later.
</p>
</div>
</body>
</html>`
        );
}

/* ============================================================
   BASIC AUTH MIDDLEWARE
============================================================ */

function basicAuth(
    req,
    res,
    next
) {
    if (
        !BASIC_AUTH_ENABLED
    ) {
        return next();
    }

    if (
        req.path === '/login' ||
        req.path === '/auth/login'
    ) {
        return next();
    }

    if (
        req.path === '/favicon.ico'
    ) {
        return next();
    }

    const ip =
        getClientIp(req);

    if (
        isIpBlocked(ip)
    ) {
        return sendBlockedPage(
            res
        );
    }

    if (
        isHttpAuthenticated(req)
    ) {
        return next();
    }

    if (
        req.method === 'GET' ||
        req.method === 'HEAD'
    ) {
        return res.redirect(
            302,
            '/login'
        );
    }

    return res
        .status(401)
        .json({
            error:
                'Authentication required',

            login:
                '/login',
        });
}

/* ============================================================
   LOGIN ROUTES
============================================================ */

app.get(
    '/login',
    (
        req,
        res
    ) => {
        if (
            !BASIC_AUTH_ENABLED
        ) {
            return res.redirect(
                '/'
            );
        }

        const ip =
            getClientIp(req);

        if (
            isIpBlocked(ip)
        ) {
            return sendBlockedPage(
                res
            );
        }

        if (
            isHttpAuthenticated(req)
        ) {
            return res.redirect(
                '/'
            );
        }

        return sendLoginPage(
            res
        );
    }
);

app.post(
    '/auth/login',
    express.urlencoded({
        extended:false,
    }),
    (
        req,
        res
    ) => {
        if (
            !BASIC_AUTH_ENABLED
        ) {
            return res.redirect(
                '/'
            );
        }

        const ip =
            getClientIp(req);

        if (
            isIpBlocked(ip)
        ) {
            return sendBlockedPage(
                res
            );
        }

        const username =
            typeof req.body.username ===
            'string'
                ? req.body.username
                : '';

        const password =
            typeof req.body.password ===
            'string'
                ? req.body.password
                : '';

        if (
            checkLoginCredentials(
                username,
                password
            )
        ) {
            resetLoginAttempts(
                ip
            );

            setAuthCookie(
                res,
                req
            );

            log.info(
                'Successful Loki Live login',
                {
                    ip,
                    username,
                }
            );

            return res.redirect(
                303,
                '/'
            );
        }

        const result =
            registerFailedLogin(
                ip
            );

        if (
            result.blocked
        ) {
            return sendBlockedPage(
                res
            );
        }

        const remaining =
            MAX_LOGIN_ATTEMPTS -
            result.attempts;

        return sendLoginPage(
            res,
            `Invalid username or password. ${remaining} attempt${
                remaining === 1
                    ? ''
                    : 's'
            } remaining.`
        );
    }
);

app.get(
    '/auth/logout',
    (
        req,
        res
    ) => {
        clearAuthCookie(
            res,
            req
        );

        res.redirect(
            '/login'
        );
    }
);

/* ============================================================
   SERVER SETTINGS
============================================================ */

const trustProxy =
    !!getEnvBoolean(
        process.env.TRUST_PROXY
    );

const port =
    process.env.PORT ||
    8080;

const host =
    process.env.HOST ||
    `http://localhost:${port}`;

const apiKeySecret =
    process.env.API_KEY_SECRET ||
    'mirotalkc2c_default_secret';

const apiBasePath =
    '/api/v1';

const apiDocs =
    host +
    apiBasePath +
    '/docs';

/* ============================================================
   CORS
============================================================ */

const cors_origin =
    process.env.CORS_ORIGIN;

const cors_methods =
    process.env.CORS_METHODS;

let corsOrigin = '*';

let corsMethods = [
    'GET',
    'POST',
];

if (
    cors_origin &&
    cors_origin !== '*'
) {
    try {
        corsOrigin =
            JSON.parse(
                cors_origin
            );
    } catch (error) {
        log.error(
            'Error parsing CORS_ORIGIN',
            error.message
        );
    }
}

if (
    cors_methods &&
    cors_methods !== ''
) {
    try {
        corsMethods =
            JSON.parse(
                cors_methods
            );
    } catch (error) {
        log.error(
            'Error parsing CORS_METHODS',
            error.message
        );
    }
}

const corsOptions = {
    origin:
        corsOrigin,

    methods:
        corsMethods,

    credentials:
        true,
};

/* ============================================================
   SOCKET.IO
============================================================ */

const io =
    new Server(
        server,
        {
            maxHttpBufferSize:
                1e7,

            transports: [
                'websocket',
                'polling',
            ],

            cors:
                corsOptions,
        }
    );

/* ============================================================
   SOCKET AUTH
============================================================ */

io.use(
    (
        socket,
        next
    ) => {
        if (
            !BASIC_AUTH_ENABLED
        ) {
            return next();
        }

        const headers =
            socket.handshake
                ?.headers || {};

        const cookieHeader =
            headers.cookie || '';

        let authCookie =
            null;

        const cookies =
            cookieHeader.split(';');

        for (
            const cookie of cookies
        ) {
            const separator =
                cookie.indexOf('=');

            if (
                separator === -1
            ) {
                continue;
            }

            const name =
                cookie
                    .substring(
                        0,
                        separator
                    )
                    .trim();

            const value =
                cookie
                    .substring(
                        separator + 1
                    )
                    .trim();

            if (
                name ===
                BASIC_AUTH_COOKIE
            ) {
                try {
                    authCookie =
                        decodeURIComponent(
                            value
                        );
                } catch {
                    authCookie =
                        value;
                }

                break;
            }
        }

        if (
            verifyAuthCookie(
                authCookie
            )
        ) {
            return next();
        }

        return next(
            new Error(
                'Authentication required'
            )
        );
    }
);

/* ============================================================
   NGROK
============================================================ */

const ngrokEnabled =
    getEnvBoolean(
        process.env.NGROK_ENABLED
    );

const ngrokAuthToken =
    process.env.NGROK_AUTH_TOKEN;

/* ============================================================
   ICE SERVERS
============================================================ */

const iceServers = [];

const stunServerUrl =
    process.env.STUN_SERVER_URL;

const turnServerUrl =
    process.env.TURN_SERVER_URL;

const turnServerUsername =
    process.env.TURN_SERVER_USERNAME;

const turnServerCredential =
    process.env.TURN_SERVER_CREDENTIAL;

const stunServerEnabled =
    getEnvBoolean(
        process.env.STUN_SERVER_ENABLED
    );

const turnServerEnabled =
    getEnvBoolean(
        process.env.TURN_SERVER_ENABLED
    );

if (
    stunServerEnabled &&
    stunServerUrl
) {
    iceServers.push({
        urls:
            stunServerUrl,
    });
}

if (
    turnServerEnabled &&
    turnServerUrl &&
    turnServerUsername &&
    turnServerCredential
) {
    iceServers.push({
        urls:
            turnServerUrl,

        username:
            turnServerUsername,

        credential:
            turnServerCredential,
    });
}

/* ============================================================
   MATTERMOST
============================================================ */

const mattermostCfg = {
    enabled:
        getEnvBoolean(
            process.env.MATTERMOST_ENABLED
        ),

    server_url:
        process.env.MATTERMOST_SERVER_URL,

    username:
        process.env.MATTERMOST_USERNAME,

    password:
        process.env.MATTERMOST_PASSWORD,

    token:
        process.env.MATTERMOST_TOKEN,
};

const surveyURL =
    process.env.SURVEY_URL ||
    false;

const redirectURL =
    process.env.REDIRECT_URL ||
    false;

/* ============================================================
   OIDC
============================================================ */

const OIDC = {
    enabled:
        process.env.OIDC_ENABLED
            ? getEnvBoolean(
                  process.env.OIDC_ENABLED
              )
            : false,

    baseUrlDynamic:
        process.env.OIDC_BASE_URL_DYNAMIC
            ? getEnvBoolean(
                  process.env.OIDC_BASE_URL_DYNAMIC
              )
            : false,

    allowedDynamicBaseURLs:
        process.env.OIDC_ALLOWED_DYNAMIC_BASE_URLS
            ? process.env.OIDC_ALLOWED_DYNAMIC_BASE_URLS
                  .split(',')
                  .map(
                      u =>
                          u.trim()
                  )
                  .filter(Boolean)
            : [],

    config: {
        issuerBaseURL:
            process.env.OIDC_ISSUER_BASE_URL,

        clientID:
            process.env.OIDC_CLIENT_ID,

        clientSecret:
            process.env.OIDC_CLIENT_SECRET,

        baseURL:
            process.env.OIDC_BASE_URL,

        secret:
            process.env.SESSION_SECRET,

        authorizationParams: {
            response_type:
                'code',

            scope:
                'openid profile email',
        },

        authRequired:
            process.env.OIDC_AUTH_REQUIRED
                ? getEnvBoolean(
                      process.env.OIDC_AUTH_REQUIRED
                  )
                : false,

        auth0Logout:
            process.env.OIDC_AUTH_LOGOUT
                ? getEnvBoolean(
                      process.env.OIDC_AUTH_LOGOUT
                  )
                : true,

        routes: {
            callback:
                '/auth/callback',

            login:
                false,

            logout:
                '/logout',
        },
    },
};

const OIDCAuth =
    function (
        req,
        res,
        next
    ) {
        if (
            OIDC.enabled
        ) {
            if (
                req.oidc &&
                req.oidc.isAuthenticated()
            ) {
                return next();
            }

            return requiresAuth()(
                req,
                res,
                next
            );
        }

        return next();
    };

/* ============================================================
   FRONTEND
============================================================ */

const frontendDir =
    path.join(
        __dirname,
        '../',
        'frontend'
    );

const htmlClient =
    path.join(
        __dirname,
        '../',
        'frontend/html/client.html'
    );

const htmlHome =
    path.join(
        __dirname,
        '../',
        'frontend/html/home.html'
    );

const htmlPrivacy =
    path.join(
        __dirname,
        '../',
        'frontend/html/privacy.html'
    );

/* ============================================================
   ROOM STORAGE
============================================================ */

const channels = {};
const sockets = {};
const peers = {};

/* ============================================================
   RABBIT ADMIN CONTROL
   Must be loaded before the global Basic Auth middleware so
   /rabbit-control can use its own admin/admin session.
============================================================ */

const adminControl =
    require('./admin-control');

/* ============================================================
   EXPRESS
============================================================ */

app.set(
    'trust proxy',
    trustProxy
);

app.use(
    helmet.noSniff()
);

/*
 * Parse request bodies before the admin controller.
 * The admin login sends JSON to /rabbit-control/api/login.
 */
app.use(
    express.json({
        limit:
            '1mb',
    })
);

app.use(
    express.urlencoded({
        extended:false,
        limit:
            '1mb',
    })
);

/*
 * Rabbit Control is intentionally mounted BEFORE the global
 * Basic Auth middleware. It has its own admin session.
 */
app.use(
    adminControl
);

/*
 * Authentication before protected
 * frontend/API routes.
 */
app.use(
    basicAuth
);

app.use(
    applyEmbedHeaders
);

app.use(
    express.static(
        frontendDir
    )
);

app.use(
    cors(
        corsOptions
    )
);

app.use(
    compression()
);

app.use(
    apiBasePath +
        '/docs',
    swaggerUi.serve,
    swaggerUi.setup(
        swaggerDocument
    )
);

/* ============================================================
   REQUEST LOGGING
============================================================ */

app.use(
    (
        req,
        res,
        next
    ) => {
        log.debug(
            'New request:',
            {
                method:
                    req.method,

                path:
                    req.originalUrl,
            }
        );

        next();
    }
);

/* ============================================================
   MATTERMOST
============================================================ */

const mattermost =
    new mattermostCli(
        app,
        mattermostCfg
    );

/* ============================================================
   ERROR HANDLER
============================================================ */

app.use(
    (
        err,
        req,
        res,
        next
    ) => {
        if (
            err instanceof
                SyntaxError ||
            err.status === 400 ||
            'body' in err
        ) {
            log.error(
                'Request Error',
                {
                    error:
                        err.message,
                }
            );

            return res
                .status(400)
                .send({
                    status:
                        400,

                    message:
                        err.message,
                });
        }

        if (
            req.path.substr(
                -1
            ) === '/' &&
            req.path.length > 1
        ) {
            const query =
                req.url.slice(
                    req.path.length
                );

            return res.redirect(
                301,
                req.path.slice(
                    0,
                    -1
                ) + query
            );
        }

        return next();
    }
);

/* ============================================================
   OIDC
============================================================ */

if (
    OIDC.enabled
) {
    const configuredAllowlist =
        Array.isArray(
            OIDC.allowedDynamicBaseURLs
        )
            ? OIDC.allowedDynamicBaseURLs
            : [];

    const allowedOrigins =
        new Set(
            [
                OIDC.config?.baseURL,
                ...configuredAllowlist,
            ]
                .filter(Boolean)
                .map(
                    u => {
                        try {
                            return new URL(
                                u
                            ).origin;
                        } catch {
                            return null;
                        }
                    }
                )
                .filter(Boolean)
        );

    const authMiddlewareCache =
        new Map();

    const getAuthMiddleware =
        (
            incomingHost,
            protocol
        ) => {
            if (
                !OIDC.baseUrlDynamic
            ) {
                if (
                    !authMiddlewareCache.has(
                        'static'
                    )
                ) {
                    authMiddlewareCache.set(
                        'static',
                        auth(
                            OIDC.config
                        )
                    );
                }

                return authMiddlewareCache.get(
                    'static'
                );
            }

            const key =
                `${protocol}://${incomingHost}`;

            if (
                !authMiddlewareCache.has(
                    key
                )
            ) {
                const config = {
                    ...OIDC.config,
                    baseURL:
                        key,
                };

                authMiddlewareCache.set(
                    key,
                    auth(config)
                );
            }

            return authMiddlewareCache.get(
                key
            );
        };

    app.use(
        (
            req,
            res,
            next
        ) => {
            const incomingHost =
                req.headers.host;

            const protocol =
                req.protocol ===
                'https'
                    ? 'https'
                    : 'http';

            const cacheKey =
                `${protocol}://${incomingHost}`;

            if (
                OIDC.baseUrlDynamic &&
                !allowedOrigins.has(
                    cacheKey
                )
            ) {
                return res
                    .status(400)
                    .send(
                        'Bad Request: invalid Host header'
                    );
            }

            try {
                return getAuthMiddleware(
                    incomingHost,
                    protocol
                )(
                    req,
                    res,
                    next
                );
            } catch (error) {
                log.error(
                    'OIDC Auth Middleware Error',
                    error
                );

                process.exit(1);
            }
        }
    );
}

/* ============================================================
   PROFILE
============================================================ */

app.get(
    '/profile',
    OIDCAuth,
    (
        req,
        res
    ) => {
        if (
            OIDC.enabled
        ) {
            return res.json(
                req.oidc.user
            );
        }

        return res.json({
            profile:
                false,
        });
    }
);

/* ============================================================
   OIDC CALLBACK
============================================================ */

app.get(
    '/auth/callback',
    (
        req,
        res,
        next
    ) => {
        next();
    }
);

/* ============================================================
   LOGOUT
============================================================ */

app.get(
    '/logout',
    (
        req,
        res
    ) => {
        if (
            OIDC.enabled &&
            req.logout
        ) {
            req.logout();
        }

        clearAuthCookie(
            res,
            req
        );

        res.redirect(
            '/login'
        );
    }
);

/* ============================================================
   HOME OIDC AUTH
============================================================ */

const HomeOIDCAuth =
    (
        req,
        res,
        next
    ) => {
        if (
            OIDC.enabled &&
            !OIDC.config.authRequired &&
            req.oidc &&
            !req.oidc.isAuthenticated()
        ) {
            const query =
                checkXSS(
                    req.query ||
                        {}
                );

            const room =
                query &&
                query.room;

            if (
                room &&
                room in peers
            ) {
                return next();
            }
        }

        return OIDCAuth(
            req,
            res,
            next
        );
    };

/* ============================================================
   HOME
============================================================ */

app.get(
    '/',
    HomeOIDCAuth,
    (
        req,
        res
    ) => {
        return res.sendFile(
            htmlHome
        );
    }
);

/* ============================================================
   PRIVACY
============================================================ */

app.get(
    '/privacy',
    (
        req,
        res
    ) => {
        return res.sendFile(
            htmlPrivacy
        );
    }
);

/* ============================================================
   JOIN
============================================================ */

app.get(
    '/join/',
    (
        req,
        res,
        next
    ) => {
        if (
            Object.keys(
                req.query
            ).length === 0
        ) {
            return notFound(
                res
            );
        }

        const {
            room,
            name,
        } =
            checkXSS(
                req.query
            );

        if (
            !room ||
            !name
        ) {
            return notFound(
                res
            );
        }

        if (
            OIDC.enabled &&
            OIDC.config.authRequired &&
            (
                !req.oidc ||
                !req.oidc.isAuthenticated()
            )
        ) {
            return OIDCAuth(
                req,
                res,
                next
            );
        }

        if (
            OIDC.enabled &&
            (
                !req.oidc ||
                !req.oidc.isAuthenticated()
            )
        ) {
            const roomExist =
                room in peers;

            if (
                !roomExist
            ) {
                return notFound(
                    res
                );
            }
        }

        return res.sendFile(
            htmlClient
        );
    }
);

/* ============================================================
   API MEETING
============================================================ */

app.post(
    `${apiBasePath}/meeting`,
    (
        req,
        res
    ) => {
        const {
            host,
            authorization,
        } =
            req.headers;

        const api =
            new ServerApi(
                host,
                authorization,
                apiKeySecret
            );

        if (
            !api.isAuthorized()
        ) {
            return res
                .status(403)
                .json({
                    error:
                        'Unauthorized!',
                });
        }

        const meetingURL =
            api.getMeetingURL();

        return res.json({
            meeting:
                meetingURL,
        });
    }
);

/* ============================================================
   API JOIN
============================================================ */

app.post(
    `${apiBasePath}/join`,
    (
        req,
        res
    ) => {
        const {
            host,
            authorization,
        } =
            req.headers;

        const api =
            new ServerApi(
                host,
                authorization,
                apiKeySecret
            );

        if (
            !api.isAuthorized()
        ) {
            return res
                .status(403)
                .json({
                    error:
                        'Unauthorized!',
                });
        }

        const joinURL =
            api.getJoinURL(
                req.body
            );

        return res.json({
            join:
                joinURL,
        });
    }
);

/* ============================================================
   404
============================================================ */

app.use(
    (
        req,
        res
    ) => {
        return notFound(
            res
        );
    }
);

function notFound(
    res
) {
    return res
        .status(404)
        .json({
            data:
                '404 not found',
        });
}

/* ============================================================
   ENV BOOLEAN
============================================================ */

function getEnvBoolean(
    key,
    force_true_if_undefined = false
) {
    if (
        key == undefined &&
        force_true_if_undefined
    ) {
        return true;
    }

    return key === 'true';
}

/* ============================================================
   SERVER CONFIG
============================================================ */

function getServerConfig(
    tunnelHttps = false
) {
    const serverConfig = {
        home:
            host,

        room:
            host +
            queryRoom,

        join:
            host +
            queryJoin,
    };

    const serverTunnel =
        tunnelHttps
            ? {
                  ngrokHome:
                      tunnelHttps,

                  ngrokRoom:
                      tunnelHttps +
                      queryRoom,

                  ngrokJoin:
                      tunnelHttps +
                      queryJoin,

                  ngrokToken:
                      ngrokAuthToken,
              }
            : false;

    return {
        server:
            serverConfig,

        serverTunnel:
            serverTunnel,

        trustProxy:
            trustProxy,

        oidc:
            OIDC.enabled
                ? OIDC
                : false,

        iceServers:
            iceServers,

        cors:
            corsOptions,

        embed: {
            allowedOrigins:
                embedAllowedOrigins.length
                    ? embedAllowedOrigins
                    : 'any',

            csp:
                embedCsp
                    ? embedCsp.csp
                    : 'not set',
        },

        apiDocs:
            apiDocs,

        basicAuth: {
            enabled:
                BASIC_AUTH_ENABLED,

            maxAttempts:
                MAX_LOGIN_ATTEMPTS,

            blockDuration:
                BASIC_AUTH_BLOCK_DURATION_MS,

            sessionDuration:
                BASIC_AUTH_SESSION_MS,
        },

        globalChat: {
            enabled:
                true,

            maxMessages:
                GLOBAL_CHAT_MAX_MESSAGES,

            maxNameLength:
                GLOBAL_CHAT_MAX_NAME_LENGTH,

            maxMessageLength:
                GLOBAL_CHAT_MAX_MESSAGE_LENGTH,
        },

        apiKeySecret:
            apiKeySecret,

        mattermost:
            mattermostCfg.enabled
                ? mattermostCfg
                : false,

        redirectURL:
            redirectURL,

        environment:
            process.env.NODE_ENV ||
            'development',

        app_version:
            packageJson.version,

        nodeVersion:
            process.versions.node,
    };
}

/* ============================================================
   NGROK
============================================================ */

async function ngrokStart() {
    try {
        await ngrok.authtoken(
            ngrokAuthToken
        );

        const listener =
            await ngrok.forward({
                addr:
                    port,
            });

        const tunnelUrl =
            listener.url();

        log.info(
            'Server config',
            getServerConfig(
                tunnelUrl
            )
        );
    } catch (error) {
        log.warn(
            'Ngrok Start error',
            error
        );

        try {
            await ngrok.kill();
        } catch (
            killError
        ) {
            log.warn(
                'Ngrok kill error',
                killError
            );
        }

        process.exit(1);
    }
}

/* ============================================================
   SERVER START
============================================================ */

server.listen(
    port,
    null,
    () => {
        if (
            ngrokEnabled &&
            ngrokAuthToken
        ) {
            ngrokStart();
        } else {
            log.debug(
                'settings',
                getServerConfig()
            );
        }

        log.info(
            `Loki Live server started on port ${port}`
        );

        log.info(
            'GLOBAL PUBLIC CHAT ENABLED'
        );
    }
);

/* ============================================================
   CLIENT ERROR
============================================================ */

server.on(
    'clientError',
    (
        err,
        socket
    ) => {
        log.warn(
            'Client connection error',
            {
                error:
                    err.message,

                code:
                    err.code,
            }
        );

        if (
            socket &&
            !socket.destroyed
        ) {
            socket.end(
                'HTTP/1.1 400 Bad Request\r\n\r\n'
            );
        }
    }
);

/* ============================================================
   SOCKET.IO ERROR
============================================================ */

io.on(
    'error',
    error => {
        log.error(
            'Socket.IO error:',
            error
        );
    }
);

/* ============================================================
   SOCKET.IO CONNECTION
============================================================ */

io.on(
    'connection',
    socket => {

        log.debug(
            `[${socket.id}] connection accepted`
        );

        socket.channels = {};

        sockets[
            socket.id
        ] = socket;

        /* ====================================================
           GLOBAL PUBLIC CHAT
        ==================================================== */

        /*
         * عند دخول أي مستخدم للموقع،
         * أرسل له سجل الدردشة العامة.
         */
        socket.emit(
            'globalChatHistory',
            globalChatMessages
        );

        /*
         * إرسال معلومات عدد المتصلين بالدردشة.
         */
        io.emit(
            'globalChatOnline',
            io.engine.clientsCount
        );

        /*
         * استقبال رسالة الدردشة العامة.
         *
         * لا نتحقق من room هنا.
         *
         * لذلك الدردشة مستقلة تماماً
         * عن غرف الفيديو.
         */
        socket.on(
            'globalChatSend',
            data => {

                try {

                    if (
                        !data ||
                        typeof data !==
                            'object'
                    ) {
                        return;
                    }

                    /*
                     * يمكن للواجهة إرسال:
                     *
                     * {
                     *   name: "Ahmed",
                     *   message: "مرحبا"
                     * }
                     */
                    const name =
                        sanitizeChatName(
                            data.name
                        );

                    const message =
                        sanitizeChatMessage(
                            data.message
                        );

                    if (
                        !message
                    ) {
                        return socket.emit(
                            'globalChatSystem',
                            {
                                type:
                                    'error',

                                message:
                                    'الرسالة فارغة.',
                            }
                        );
                    }

                    /*
                     * منع الرسائل الطويلة.
                     */
                    if (
                        String(
                            data.message ||
                                ''
                        ).length >
                        GLOBAL_CHAT_MAX_MESSAGE_LENGTH
                    ) {
                        return socket.emit(
                            'globalChatSystem',
                            {
                                type:
                                    'error',

                                message:
                                    `الحد الأقصى للرسالة ${GLOBAL_CHAT_MAX_MESSAGE_LENGTH} حرف.`,
                            }
                        );
                    }

                    const chatMessage =
                        addGlobalChatMessage(
                            name,
                            message
                        );

                    if (
                        !chatMessage
                    ) {
                        return;
                    }

                    /*
                     * إرسال الرسالة للجميع.
                     *
                     * هذا هو الجزء الذي يجعل
                     * الدردشة عامة خارج الغرفة.
                     */
                    io.emit(
                        'globalChatMessage',
                        chatMessage
                    );

                    /*
                     * تحديث عدد المتصلين.
                     */
                    io.emit(
                        'globalChatOnline',
                        io.engine.clientsCount
                    );

                    log.info(
                        '[GLOBAL CHAT]',
                        {
                            socketId:
                                socket.id,

                            name:
                                chatMessage.name,

                            messageLength:
                                chatMessage.message.length,
                        }
                    );

                } catch (error) {

                    log.error(
                        'Global chat message error',
                        error
                    );

                    socket.emit(
                        'globalChatSystem',
                        {
                            type:
                                'error',

                            message:
                                'حدث خطأ أثناء إرسال الرسالة.',
                        }
                    );
                }
            }
        );

        /*
         * إشعار الكتابة.
         *
         * لا نحفظه في الملف.
         */
        socket.on(
            'globalChatTyping',
            data => {

                const name =
                    sanitizeChatName(
                        data?.name
                    );

                socket.broadcast.emit(
                    'globalChatTyping',
                    {
                        name:
                            name,

                        typing:
                            Boolean(
                                data?.typing
                            ),
                    }
                );
            }
        );

        /* ====================================================
           VIDEO JOIN
        ==================================================== */

        socket.on(
            'join',
            cfg => {

                const config =
                    checkXSS(
                        cfg
                    );

                const channel =
                    config.channel;

                if (
                    !channel
                ) {
                    return log.warn(
                        `[${socket.id}] join rejected: missing channel`
                    );
                }

                if (
                    channel in
                    socket.channels
                ) {
                    return;
                }

                if (
                    !(
                        channel in
                        channels
                    )
                ) {
                    channels[
                        channel
                    ] = {};
                }

                if (
                    !(
                        channel in
                        peers
                    )
                ) {
                    peers[
                        channel
                    ] = {};
                }

                peers[
                    channel
                ][
                    socket.id
                ] =
                    config.peerInfo;

                addPeerTo(
                    channel
                );

                channels[
                    channel
                ][
                    socket.id
                ] = socket;

                socket.channels[
                    channel
                ] = channel;

                const peerCounts =
                    Object.keys(
                        peers[
                            channel
                        ]
                    ).length;

                sendToPeer(
                    socket.id,
                    sockets,
                    'serverInfo',
                    {
                        roomPeersCount:
                            peerCounts,

                        redirectURL:
                            redirectURL,

                        surveyURL:
                            surveyURL,
                    }
                );

                if (
                    peerCounts ===
                    1
                ) {
                    const peerInfo =
                        config.peerInfo ||
                        {};

                    const {
                        peerName,
                        osName,
                        osVersion,
                        browserName,
                        browserVersion,
                    } =
                        peerInfo;

                    nodemailer.sendEmailAlert(
                        'join',
                        {
                            room_id:
                                channel,

                            peer_name:
                                peerName,

                            domain:
                                socket
                                    .handshake
                                    .headers
                                    .host
                                    ?.split(
                                        ':'
                                    )[0] ||
                                '',

                            os:
                                osName
                                    ? `${osName} ${osVersion}`
                                    : '',

                            browser:
                                browserName
                                    ? `${browserName} ${browserVersion}`
                                    : '',
                        }
                    );
                }
            }
        );

        /* ====================================================
           SHARED ROOM
        ==================================================== */

        function peersShareRoom(
            peerId
        ) {
            if (
                typeof peerId !==
                    'string' ||
                !peerId
            ) {
                return false;
            }

            for (
                const channel in
                socket.channels
            ) {
                if (
                    channels[
                        channel
                    ] &&
                    channels[
                        channel
                    ][
                        peerId
                    ]
                ) {
                    return true;
                }
            }

            return false;
        }

        /* ====================================================
           RELAY SDP
        ==================================================== */

        socket.on(
            'relaySDP',
            config => {

                if (
                    !config
                ) {
                    return;
                }

                const {
                    peerId,
                    sessionDescription,
                } =
                    config;

                if (
                    !peersShareRoom(
                        peerId
                    )
                ) {
                    return;
                }

                sendToPeer(
                    peerId,
                    sockets,
                    'sessionDescription',
                    {
                        peerId:
                            socket.id,

                        sessionDescription:
                            sessionDescription,
                    }
                );
            }
        );

        /* ====================================================
           RELAY ICE
        ==================================================== */

        socket.on(
            'relayICE',
            config => {

                if (
                    !config
                ) {
                    return;
                }

                const {
                    peerId,
                    iceCandidate,
                } =
                    config;

                if (
                    !peersShareRoom(
                        peerId
                    )
                ) {
                    return;
                }

                sendToPeer(
                    peerId,
                    sockets,
                    'iceCandidate',
                    {
                        peerId:
                            socket.id,

                        iceCandidate:
                            iceCandidate,
                    }
                );
            }
        );

        /* ====================================================
           PEER STATUS
        ==================================================== */

        socket.on(
            'peerStatus',
            cfg => {

                const config =
                    checkXSS(
                        cfg
                    );

                const {
                    roomId,
                    peerName,
                    element,
                    active,
                } =
                    config;

                if (
                    peers[
                        roomId
                    ]
                ) {
                    for (
                        const peerId in
                        peers[
                            roomId
                        ]
                    ) {

                        const peer =
                            peers[
                                roomId
                            ][
                                peerId
                            ];

                        if (
                            peer &&
                            peer.peerName ===
                                peerName
                        ) {

                            switch (
                                element
                            ) {

                                case 'video':

                                    peer.peerVideo =
                                        active;

                                    break;

                                case 'audio':

                                    peer.peerAudio =
                                        active;

                                    break;

                                case 'screen':

                                    peer.peerScreen =
                                        active;

                                    break;
                            }
                        }
                    }
                }

                sendToRoom(
                    roomId,
                    socket.id,
                    'peerStatus',
                    {
                        peerId:
                            socket.id,

                        peerName:
                            peerName,

                        element:
                            element,

                        active:
                            active,
                    }
                );
            }
        );

        /* ====================================================
           DISCONNECT
        ==================================================== */

        socket.on(
            'disconnect',
            reason => {

                const joinedChannels =
                    Object.keys(
                        socket.channels ||
                            {}
                    );

                for (
                    const channel of
                        joinedChannels
                ) {
                    removePeerFrom(
                        channel
                    );
                }

                for (
                    const channel in
                    channels
                ) {
                    if (
                        channels[
                            channel
                        ] &&
                        channels[
                            channel
                        ][
                            socket.id
                        ]
                    ) {
                        delete channels[
                            channel
                        ][
                            socket.id
                        ];
                    }
                }

                for (
                    const channel in
                    peers
                ) {
                    if (
                        peers[
                            channel
                        ] &&
                        peers[
                            channel
                        ][
                            socket.id
                        ]
                    ) {
                        delete peers[
                            channel
                        ][
                            socket.id
                        ];
                    }
                }

                delete sockets[
                    socket.id
                ];

                /*
                 * تحديث عدد المتصلين
                 * بالدردشة العامة.
                 */
                io.emit(
                    'globalChatOnline',
                    io.engine.clientsCount
                );

                log.debug(
                    `[${socket.id}] disconnected`,
                    {
                        reason:
                            reason,
                    }
                );
            }
        );

        /* ====================================================
           ADD PEER
        ==================================================== */

        async function addPeerTo(
            channel
        ) {
            try {

                if (
                    !channels[
                        channel
                    ] ||
                    !peers[
                        channel
                    ]
                ) {
                    return;
                }

                for (
                    const id in
                    channels[
                        channel
                    ]
                ) {

                    const peerSocket =
                        channels[
                            channel
                        ][
                            id
                        ];

                    if (
                        !peerSocket ||
                        typeof peerSocket.emit !==
                            'function'
                    ) {
                        continue;
                    }

                    await peerSocket.emit(
                        'addPeer',
                        {
                            peerId:
                                socket.id,

                            peers:
                                peers[
                                    channel
                                ],

                            shouldCreateOffer:
                                false,

                            iceServers:
                                iceServers,
                        }
                    );

                    socket.emit(
                        'addPeer',
                        {
                            peerId:
                                id,

                            peers:
                                peers[
                                    channel
                                ],

                            shouldCreateOffer:
                                true,

                            iceServers:
                                iceServers,
                        }
                    );
                }

            } catch (error) {

                log.error(
                    'Error in addPeerTo',
                    error
                );
            }
        }

        /* ====================================================
           REMOVE PEER
        ==================================================== */

        async function removePeerFrom(
            channel
        ) {

            if (
                !(
                    channel in
                    socket.channels
                )
            ) {
                return;
            }

            try {

                const channelSockets =
                    channels[
                        channel
                    ]
                        ? {
                              ...channels[
                                  channel
                              ],
                          }
                        : {};

                delete socket.channels[
                    channel
                ];

                if (
                    channels[
                        channel
                    ]
                ) {
                    delete channels[
                        channel
                    ][
                        socket.id
                    ];
                }

                if (
                    peers[
                        channel
                    ]
                ) {
                    delete peers[
                        channel
                    ][
                        socket.id
                    ];
                }

                for (
                    const id in
                    channelSockets
                ) {

                    if (
                        id ===
                        socket.id
                    ) {
                        continue;
                    }

                    const peerSocket =
                        channelSockets[
                            id
                        ];

                    if (
                        peerSocket &&
                        typeof peerSocket.emit ===
                            'function'
                    ) {
                        await peerSocket.emit(
                            'removePeer',
                            {
                                peerId:
                                    socket.id,
                            }
                        );
                    }

                    if (
                        !socket.disconnected
                    ) {
                        socket.emit(
                            'removePeer',
                            {
                                peerId:
                                    id,
                            }
                        );
                    }
                }

                if (
                    peers[
                        channel
                    ] &&
                    Object.keys(
                        peers[
                            channel
                        ]
                    ).length ===
                        0
                ) {

                    delete peers[
                        channel
                    ];

                    delete channels[
                        channel
                    ];
                }

            } catch (error) {

                log.error(
                    'Error in removePeerFrom',
                    error
                );
            }
        }

        /* ====================================================
           SEND TO ROOM
        ==================================================== */

        async function sendToRoom(
            roomId,
            socketId,
            msg,
            config = {}
        ) {

            if (
                !channels[
                    roomId
                ]
            ) {
                return;
            }

            for (
                const peerId in
                channels[
                    roomId
                ]
            ) {

                if (
                    peerId !=
                    socketId
                ) {

                    try {

                        const peerSocket =
                            channels[
                                roomId
                            ][
                                peerId
                            ];

                        if (
                            peerSocket
                        ) {
                            await peerSocket.emit(
                                msg,
                                config
                            );
                        }

                    } catch (error) {

                        log.warn(
                            'Error sending message to room peer',
                            {
                                roomId,
                                peerId,
                                msg,
                                error:
                                    error.message,
                            }
                        );
                    }
                }
            }
        }

        /* ====================================================
           SEND TO PEER
        ==================================================== */

        async function sendToPeer(
            peerId,
            socketsMap,
            msg,
            config = {}
        ) {

            if (
                peerId in
                socketsMap
            ) {

                try {

                    await socketsMap[
                        peerId
                    ].emit(
                        msg,
                        config
                    );

                } catch (error) {

                    log.warn(
                        'Error sending message to peer',
                        {
                            peerId,
                            msg,
                            error:
                                error.message,
                        }
                    );
                }
            }
        }

        /* ====================================================
           ACTIVE ROOMS
        ==================================================== */

        function getActiveRooms() {

            const roomPeersArray =
                [];

            for (
                const roomId in
                peers
            ) {

                if (
                    Object.prototype.hasOwnProperty.call(
                        peers,
                        roomId
                    )
                ) {

                    const peersCount =
                        Object.keys(
                            peers[
                                roomId
                            ]
                        ).length;

                    roomPeersArray.push(
                        {
                            roomId:
                                roomId,

                            peersCount:
                                peersCount,
                        }
                    );
                }
            }

            return roomPeersArray;
        }
    }
);

/* ============================================================
   PERIODIC CLEANUP
============================================================ */

/*
 * تنظيف سجلات محاولات الدخول القديمة
 * حتى لا تكبر الـ Map بلا حدود.
 */
setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                ip,
                record,
            ] of loginSecurity
        ) {

            if (
                !record.blockedUntil &&
                record.attempts === 0
            ) {
                loginSecurity.delete(
                    ip
                );

                continue;
            }

            if (
                record.blockedUntil &&
                now >=
                    record.blockedUntil
            ) {
                loginSecurity.delete(
                    ip
                );
            }
        }

    },
    60 * 60 * 1000
);

/* ============================================================
   GLOBAL ERROR HANDLING
============================================================ */

process.on(
    'uncaughtException',
    error => {

        log.error(
            'UNCAUGHT EXCEPTION',
            error
        );
    }
);

process.on(
    'unhandledRejection',
    error => {

        log.error(
            'UNHANDLED REJECTION',
            error
        );
    }
);

/* ============================================================
   END
============================================================ */
