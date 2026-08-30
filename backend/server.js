'use strict';

/**
 * MiroTalk C2C - Server component
 *
 * Loki Live Authentication
 *
 * BASIC_AUTH_ENABLED=true
 * BASIC_AUTH_USERNAME=Loki
 * BASIC_AUTH_PASSWORD=your_password
 * BASIC_AUTH_SECRET=your_long_random_secret
 * BASIC_AUTH_BLOCK_DURATION_MS=86400000
 */

require('dotenv').config();

const crypto = require('crypto');
const { auth, requiresAuth } = require('express-openid-connect');
const { Server } = require('socket.io');
const httpolyglot = require('httpolyglot');
const compression = require('compression');
const express = require('express');
const cors = require('cors');
const checkXSS = require('./xss.js');
const path = require('path');
const ngrok = require('@ngrok/ngrok');
const app = express();
const helmet = require('helmet');
const fs = require('fs');
const logs = require('./logs');
const log = new logs('server');
const ServerApi = require('./api');
const mattermostCli = require('./mattermost');
const sentry = require('./sentry');

const {
    applyEmbedHeaders,
    embedAllowedOrigins,
    embedCsp,
} = require('./embedHeaders');

const yaml = require('js-yaml');
const swaggerUi = require('swagger-ui-express');

const swaggerDocument = yaml.load(
    fs.readFileSync(
        path.join(__dirname, '/api/swagger.yaml'),
        'utf8'
    )
);

const queryJoin = '/join?room=test&name=test';
const queryRoom = '/?room=test';

const packageJson = require('../package.json');
const nodemailer = require('./lib/nodemailer');

sentry.start();

// ============================================================
// SSL
// ============================================================

const keyPath = path.join(
    __dirname,
    'ssl/key.pem'
);

const certPath = path.join(
    __dirname,
    'ssl/cert.pem'
);

const options = {
    key: fs.readFileSync(
        keyPath,
        'utf-8'
    ),
    cert: fs.readFileSync(
        certPath,
        'utf-8'
    ),
};

// ============================================================
// HTTP / HTTPS SERVER
// ============================================================

const server =
    httpolyglot.createServer(
        options,
        app
    );

// ============================================================
// BASIC AUTH / LOKI LIVE AUTHENTICATION
// ============================================================

const BASIC_AUTH_ENABLED =
    getEnvBoolean(
        process.env.BASIC_AUTH_ENABLED
    );

const BASIC_AUTH_USERNAME =
    process.env.BASIC_AUTH_USERNAME || '';

const BASIC_AUTH_PASSWORD =
    process.env.BASIC_AUTH_PASSWORD || '';

const BASIC_AUTH_SECRET =
    process.env.BASIC_AUTH_SECRET ||
    'CHANGE_THIS_SECRET_IN_RENDER';

const BASIC_AUTH_COOKIE =
    'loki_live_auth';

const MAX_LOGIN_ATTEMPTS = 10;

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

const loginSecurity = new Map();

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

// ============================================================
// CLIENT IP
// ============================================================

function getClientIp(req) {
    const forwarded =
        req.headers[
            'x-forwarded-for'
        ];

    if (forwarded) {
        const firstIp =
            String(forwarded)
                .split(',')[0]
                .trim();

        if (firstIp) {
            return firstIp;
        }
    }

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        'unknown'
    );
}

// ============================================================
// SECURITY STORE
// ============================================================

function getSecurityRecord(ip) {
    let record =
        loginSecurity.get(ip);

    if (!record) {
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

function isIpBlocked(ip) {
    const record =
        loginSecurity.get(ip);

    if (!record) {
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
        loginSecurity.delete(ip);
        return false;
    }

    return false;
}

function registerFailedLogin(ip) {
    const record =
        getSecurityRecord(ip);

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

function resetLoginAttempts(ip) {
    loginSecurity.delete(ip);
}

// ============================================================
// AUTH SIGNATURE
// ============================================================

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

// ============================================================
// AUTH COOKIE
// ============================================================

function createAuthCookie() {
    const timestamp =
        Date.now();

    const signature =
        createAuthSignature(
            timestamp
        );

    return `${timestamp}.${signature}`;
}

function verifyAuthCookie(
    cookieValue
) {
    if (!cookieValue) {
        return false;
    }

    const parts =
        String(cookieValue)
            .split('.');

    if (
        parts.length !== 2
    ) {
        return false;
    }

    const timestamp =
        Number(parts[0]);

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
        age > BASIC_AUTH_SESSION_MS ||
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

// ============================================================
// COOKIE READER
// ============================================================

function getCookie(req, cookieName) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === cookieName) return value;
    }
    return null;
}

function getEnvBoolean(val) {
    return val === 'true' || val === true;
}

// ============================================================
// 🌟 كود تشغيل غرف الدردشة العامة المحلية للموقع (تلقائي وبدون وسيط)
// ============================================================
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

io.on('connection', (socket) => {
    socket.on('join-public-chat', (data) => {
        socket.join(data.room);
    });

    socket.on('send-public-msg', (data) => {
        const shortName = "زائر_" + socket.id.substring(0, 4);
        io.to(data.room).emit('receive-public-msg', {
            id: socket.id,
            user: shortName,
            text: data.text
        });
    });
});
// ============================================================
