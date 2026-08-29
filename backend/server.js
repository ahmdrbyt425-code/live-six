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

function getCookie(
    req,
    cookieName
) {
    const cookieHeader =
        req.headers.cookie;

    if (!cookieHeader) {
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
            name === cookieName
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

// ============================================================
// PASSWORD COMPARISON
// ============================================================

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

// ============================================================
// LOGIN CREDENTIALS
// ============================================================

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

// ============================================================
// HTTP AUTH CHECK
// ============================================================

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

// ============================================================
// SET AUTH COOKIE
// ============================================================

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

// ============================================================
// CLEAR AUTH COOKIE
// ============================================================

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

// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHtml(value) {
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

// ============================================================
// LOGIN PAGE
// ============================================================

function sendLoginPage(
    res,
    message = ''
) {
    const safeMessage =
        escapeHtml(message);

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
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    padding: 0;
    width: 100%;
    min-height: 100%;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background:
        linear-gradient(
            135deg,
            #0d0f14,
            #171a21
        );
    color: #fff;
}

body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
}

.login-box {
    width: 100%;
    max-width: 400px;
    padding: 32px;
    border-radius: 20px;
    background: #1a1d23;
    border: 1px solid
        rgba(255,255,255,.09);
    box-shadow:
        0 25px 70px
        rgba(0,0,0,.5);
}

.logo {
    width: 78px;
    height: 78px;
    margin:
        0 auto 18px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #fff;
    color: #111318;
    font-size: 40px;
    box-shadow:
        0 8px 30px
        rgba(0,0,0,.25);
}

h1 {
    text-align: center;
    margin:
        0 0 8px;
    font-size: 28px;
    font-weight: 700;
}

.subtitle {
    text-align: center;
    color: #9da3ad;
    margin:
        0 0 26px;
    font-size: 14px;
}

.error {
    background:
        rgba(220,38,38,.12);
    border:
        1px solid
        rgba(220,38,38,.30);
    color: #ff9696;
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 18px;
    font-size: 14px;
    text-align: center;
}

label {
    display: block;
    margin:
        0 0 7px;
    font-size: 14px;
    color: #d8dbe0;
}

input {
    width: 100%;
    height: 50px;
    border:
        1px solid #343944;
    border-radius: 10px;
    background: #101217;
    color: #fff;
    padding:
        0 14px;
    outline: none;
    margin-bottom: 18px;
    font-size: 16px;
}

input:focus {
    border-color:
        #8b929e;
    box-shadow:
        0 0 0 3px
        rgba(255,255,255,.05);
}

button {
    width: 100%;
    height: 50px;
    border: 0;
    border-radius: 10px;
    background: #fff;
    color: #111318;
    font-size: 16px;
    font-weight: 700;
    cursor: pointer;
    transition:
        opacity .2s,
        transform .1s;
}

button:hover {
    opacity: .92;
}

button:active {
    transform: scale(.99);
}

button:disabled {
    opacity: .55;
    cursor: wait;
}

.footer {
    text-align: center;
    color: #686f7b;
    margin-top: 20px;
    font-size: 12px;
}
</style>
</head>

<body>

<div class="login-box">

    <div class="logo">
        😈
    </div>

    <h1>
        Welcome to burrow
    </h1>

    <p class="subtitle">
        Sign in to continue
    </p>

    ${
        safeMessage
            ? `<div class="error">${safeMessage}</div>`
            : ''
    }

    <form
        id="loginForm"
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

        <button
            id="loginButton"
            type="submit"
        >
            Login
        </button>

    </form>

    <div class="footer">
        The rabbit in the hole
    </div>

</div>

<script>
const form =
    document.getElementById(
        'loginForm'
    );

const button =
    document.getElementById(
        'loginButton'
    );

form.addEventListener(
    'submit',
    function () {
        button.disabled = true;
        button.textContent =
            'Checking...';
    }
);
</script>

</body>
</html>`
        );
}

// ============================================================
// ACCESS BLOCKED PAGE
// ============================================================

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
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #111318;
    color: #fff;
    font-family: Arial, sans-serif;
    padding: 20px;
}
.box {
    max-width: 430px;
    text-align: center;
    background: #1a1d23;
    padding: 36px;
    border-radius: 18px;
    border: 1px solid
        rgba(255,255,255,.08);
}
h1 {
    margin-top: 0;
}
p {
    color: #a8adb7;
    line-height: 1.6;
}
</style>
</head>
<body>
<div class="box">
<h1>Access Blocked</h1>
<p>
Too many failed login attempts were detected from this IP address.
</p>
<p>
Please try again later.
</p>
</div>
</body>
</html>`
        );
}

// ============================================================
// BASIC AUTH MIDDLEWARE
// ============================================================

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

    /*
     * Public authentication routes.
     */
    if (
        req.path === '/login' ||
        req.path === '/auth/login'
    ) {
        return next();
    }

    /*
     * Favicon is allowed.
     */
    if (
        req.path === '/favicon.ico'
    ) {
        return next();
    }

    const ip =
        getClientIp(req);

    /*
     * Blocked IP.
     */
    if (
        isIpBlocked(ip)
    ) {
        return sendBlockedPage(
            res
        );
    }

    /*
     * Valid authentication cookie.
     */
    if (
        isHttpAuthenticated(req)
    ) {
        return next();
    }

    /*
     * No WWW-Authenticate header.
     *
     * This intentionally prevents
     * the browser's native Basic Auth popup.
     */
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

// ============================================================
// LOGIN GET
// ============================================================

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

// ============================================================
// LOGIN POST
// ============================================================

app.post(
    '/auth/login',
    express.urlencoded({
        extended: false,
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

        log.warn(
            'Failed Loki Live login',
            {
                ip,
                username,
                attempts:
                    result.attempts,
            }
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

// ============================================================
// AUTH LOGOUT
// ============================================================

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

// ============================================================
// SERVER SETTINGS
// ============================================================

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

// ============================================================
// CORS
// ============================================================

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
};

// ============================================================
// SOCKET.IO
// ============================================================

const io =
    new Server({
        maxHttpBufferSize:
            1e7,

        transports: [
            'websocket',
        ],

        cors:
            corsOptions,
    }).listen(
        server
    );

// ============================================================
// SOCKET.IO AUTHENTICATION
// ============================================================

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
                .headers || {};

        const cookieHeader =
            headers.cookie || '';

        let authCookie =
            null;

        const cookies =
            cookieHeader.split(
                ';'
            );

        for (
            const cookie of cookies
        ) {
            const separator =
                cookie.indexOf(
                    '='
                );

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

        log.warn(
            'Socket.IO authentication failed',
            {
                ip:
                    socket.handshake
                        .address,
            }
        );

        return next(
            new Error(
                'Authentication required'
            )
        );
    }
);

// ============================================================
// NGROK
// ============================================================

const ngrokEnabled =
    getEnvBoolean(
        process.env.NGROK_ENABLED
    );

const ngrokAuthToken =
    process.env.NGROK_AUTH_TOKEN;

// ============================================================
// ICE SERVERS
// ============================================================

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

// ============================================================
// MATTERMOST
// ============================================================

const mattermostCfg = {
    enabled:
        getEnvBoolean(
            process.env
                .MATTERMOST_ENABLED
        ),

    server_url:
        process.env
            .MATTERMOST_SERVER_URL,

    username:
        process.env
            .MATTERMOST_USERNAME,

    password:
        process.env
            .MATTERMOST_PASSWORD,

    token:
        process.env
            .MATTERMOST_TOKEN,
};

const surveyURL =
    process.env.SURVEY_URL ||
    false;

const redirectURL =
    process.env.REDIRECT_URL ||
    false;

// ============================================================
// OIDC
// ============================================================

const OIDC = {
    enabled:
        process.env.OIDC_ENABLED
            ? getEnvBoolean(
                  process.env
                      .OIDC_ENABLED
              )
            : false,

    baseUrlDynamic:
        process.env
            .OIDC_BASE_URL_DYNAMIC
            ? getEnvBoolean(
                  process.env
                      .OIDC_BASE_URL_DYNAMIC
              )
            : false,

    allowedDynamicBaseURLs:
        process.env
            .OIDC_ALLOWED_DYNAMIC_BASE_URLS
            ? process.env
                  .OIDC_ALLOWED_DYNAMIC_BASE_URLS
                  .split(',')
                  .map(
                      (u) =>
                          u.trim()
                  )
                  .filter(Boolean)
            : [],

    config: {
        issuerBaseURL:
            process.env
                .OIDC_ISSUER_BASE_URL,

        clientID:
            process.env
                .OIDC_CLIENT_ID,

        clientSecret:
            process.env
                .OIDC_CLIENT_SECRET,

        baseURL:
            process.env
                .OIDC_BASE_URL,

        secret:
            process.env
                .SESSION_SECRET,

        authorizationParams: {
            response_type:
                'code',

            scope:
                'openid profile email',
        },

        authRequired:
            process.env
                .OIDC_AUTH_REQUIRED
                ? getEnvBoolean(
                      process.env
                          .OIDC_AUTH_REQUIRED
                  )
                : false,

        auth0Logout:
            process.env
                .OIDC_AUTH_LOGOUT
                ? getEnvBoolean(
                      process.env
                          .OIDC_AUTH_LOGOUT
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
                log.debug(
                    'OIDC ------> User already Authenticated'
                );

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

// ============================================================
// FRONTEND
// ============================================================

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

// ============================================================
// ROOM STORAGE
// ============================================================

const channels = {};
const sockets = {};
const peers = {};

// ============================================================
// EXPRESS SETTINGS
// ============================================================

app.set(
    'trust proxy',
    trustProxy
);

app.use(
    helmet.noSniff()
);

/*
 * IMPORTANT:
 * Authentication comes before
 * frontend/API/Swagger.
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
    express.json()
);

app.use(
    express.urlencoded({
        extended: false,
    })
);

app.use(
    apiBasePath +
        '/docs',
    swaggerUi.serve,
    swaggerUi.setup(
        swaggerDocument
    )
);

// ============================================================
// REQUEST LOGGING
// ============================================================

app.use(
    (
        req,
        res,
        next
    ) => {
        log.debug(
            'New request:',
            {
                body:
                    req.body,

                method:
                    req.method,

                path:
                    req.originalUrl,
            }
        );

        next();
    }
);

// ============================================================
// MATTERMOST
// ============================================================

const mattermost =
    new mattermostCli(
        app,
        mattermostCfg
    );

// ============================================================
// ERROR HANDLER
// ============================================================

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
                    header:
                        req.headers,

                    body:
                        req.body,

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

// ============================================================
// OIDC
// ============================================================

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
                    (u) => {
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
                    log.debug(
                        'OIDC baseURL',
                        OIDC
                            .config
                            .baseURL
                    );

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

                log.debug(
                    'OIDC baseURL',
                    config.baseURL
                );

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
                log.warn(
                    'OIDC Host header not in allowlist - rejecting request',
                    {
                        host:
                            incomingHost,

                        origin:
                            cacheKey,

                        allowed: [
                            ...allowedOrigins,
                        ],
                    }
                );

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
            } catch (
                err
            ) {
                log.error(
                    'OIDC Auth Middleware Error',
                    err
                );

                process.exit(1);
            }
        }
    );
}

// ============================================================
// PROFILE
// ============================================================

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
            log.debug(
                'OIDC User profile requested',
                req.oidc.user
            );

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

// ============================================================
// OIDC CALLBACK
// ============================================================

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

// ============================================================
// LOGOUT
// ============================================================

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

// ============================================================
// HOME OIDC AUTH
// ============================================================

const HomeOIDCAuth =
    (
        req,
        res,
        next
    ) => {
        if (
            OIDC.enabled &&
            !OIDC.config
                .authRequired &&
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
                log.debug(
                    'OIDC ------> Guest allowed on home for existing room',
                    {
                        room,
                    }
                );

                return next();
            }
        }

        return OIDCAuth(
            req,
            res,
            next
        );
    };

// ============================================================
// HOME
// ============================================================

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

// ============================================================
// PRIVACY
// ============================================================

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

// ============================================================
// JOIN
// ============================================================

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

        log.debug(
            '[' +
                req.headers.host +
                ']' +
                ' request query',
            req.query
        );

        const {
            room,
            name,
        } = checkXSS(
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
            OIDC.config
                .authRequired &&
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
    },
    (
        req,
        res
    ) => {
        return res.sendFile(
            htmlClient
        );
    }
);

// ============================================================
// API - MEETING
// ============================================================

app.post(
    `${apiBasePath}/meeting`,
    (
        req,
        res
    ) => {
        const {
            host,
            authorization,
        } = req.headers;

        const api =
            new ServerApi(
                host,
                authorization,
                apiKeySecret
            );

        if (
            !api.isAuthorized()
        ) {
            log.debug(
                'MiroTalk get meeting - Unauthorized',
                {
                    header:
                        req.headers,

                    body:
                        req.body,
                }
            );

            return res
                .status(403)
                .json({
                    error:
                        'Unauthorized!',
                });
        }

        const meetingURL =
            api.getMeetingURL();

        res.json({
            meeting:
                meetingURL,
        });

        log.debug(
            'MiroTalk get meeting - Authorized',
            {
                header:
                    req.headers,

                body:
                    req.body,

                meeting:
                    meetingURL,
            }
        );
    }
);

// ============================================================
// API - JOIN
// ============================================================

app.post(
    `${apiBasePath}/join`,
    (
        req,
        res
    ) => {
        const {
            host,
            authorization,
        } = req.headers;

        const api =
            new ServerApi(
                host,
                authorization,
                apiKeySecret
            );

        if (
            !api.isAuthorized()
        ) {
            log.debug(
                'MiroTalk get join - Unauthorized',
                {
                    header:
                        req.headers,

                    body:
                        req.body,
                }
            );

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

        res.json({
            join:
                joinURL,
        });

        log.debug(
            'MiroTalk get join - Authorized',
            {
                header:
                    req.headers,

                body:
                    req.body,

                join:
                    joinURL,
            }
        );
    }
);

// ============================================================
// 404
// ============================================================

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

// ============================================================
// ENV BOOLEAN
// ============================================================

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

// ============================================================
// SERVER CONFIG
// ============================================================

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
                    : 'not set (embedding allowed from any origin)',
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

// ============================================================
// NGROK
// ============================================================

async function ngrokStart() {
    try {
        await ngrok.authtoken(
            ngrokAuthToken
        );

        const listener =
            await ngrok.forward({
                addr: port,
            });

        const tunnelUrl =
            listener.url();

        log.info(
            'Server config',
            getServerConfig(
                tunnelUrl
            )
        );
    } catch (
        err
    ) {
        log.warn(
            'Ngrok Start error',
            err
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

// ============================================================
// SERVER START
// ============================================================

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
    }
);

// ============================================================
// CLIENT ERROR
// ============================================================

server.on(
    'clientError',
    (
        err,
        socket
    ) => {
        if (
            err.code ===
                'HPE_HEADER_OVERFLOW' ||
            err.message ===
                'Parse Error'
        ) {
            log.warn(
                'Client HTTP parse error',
                {
                    error:
                        err.message,

                    code:
                        err.code,
                }
            );
        } else {
            log.warn(
                'Client connection error',
                {
                    error:
                        err.message,

                    code:
                        err.code,
                }
            );
        }

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

// ============================================================
// SOCKET.IO ERROR
// ============================================================

io.on(
    'error',
    (
        error
    ) => {
        log.error(
            'Socket.IO error:',
            error
        );
    }
);

// ============================================================
// SOCKET.IO CONNECTION
// ============================================================

io.sockets.on(
    'connect',
    (
        socket
    ) => {
        log.debug(
            '[' +
                socket.id +
                '] connection accepted'
        );

        socket.channels = {};

        sockets[
            socket.id
        ] = socket;

        // ====================================================
        // JOIN
        // ====================================================

        socket.on(
            'join',
            (
                cfg
            ) => {
                const config =
                    checkXSS(
                        cfg
                    );

                log.debug(
                    '[' +
                        socket.id +
                        '] join ',
                    config
                );

                const channel =
                    config.channel;

                if (
                    !channel
                ) {
                    return log.warn(
                        '[' +
                            socket.id +
                            '] join rejected: missing channel'
                    );
                }

                if (
                    channel in
                    socket.channels
                ) {
                    return log.debug(
                        '[' +
                            socket.id +
                            '] [Warning] already joined',
                        channel
                    );
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

                const activeRooms =
                    getActiveRooms();

                log.info(
                    '[Join] - active rooms and peers count',
                    activeRooms
                );

                log.debug(
                    '[Join] - connected peers grp by roomId',
                    peers
                );

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

        // ====================================================
        // SHARED ROOM
        // ====================================================

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

        // ====================================================
        // RELAY SDP
        // ====================================================

        socket.on(
            'relaySDP',
            (
                config
            ) => {
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
                    return log.warn(
                        '[' +
                            socket.id +
                            '] relaySDP blocked: no shared room with [' +
                            peerId +
                            ']'
                    );
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

                log.debug(
                    '[' +
                        socket.id +
                        '] relay SessionDescription to [' +
                        peerId +
                        ']',
                    {
                        type:
                            sessionDescription
                                ?.type,
                    }
                );
            }
        );

        // ====================================================
        // RELAY ICE
        // ====================================================

        socket.on(
            'relayICE',
            (
                config
            ) => {
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
                    return log.warn(
                        '[' +
                            socket.id +
                            '] relayICE blocked: no shared room with [' +
                            peerId +
                            ']'
                    );
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

        // ====================================================
        // DISCONNECT
        // ====================================================

        socket.on(
            'disconnect',
            (
                reason
            ) => {
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

                log.debug(
                    '[' +
                        socket.id +
                        '] disconnected',
                    {
                        reason:
                            reason,
                    }
                );

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
            }
        );

        // ====================================================
        // PEER STATUS
        // ====================================================

        socket.on(
            'peerStatus',
            (
                cfg
            ) => {
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
                        if (
                            peers[
                                roomId
                            ][
                                peerId
                            ] &&
                            peers[
                                roomId
                            ][
                                peerId
                            ].peerName ===
                                peerName
                        ) {
                            switch (
                                element
                            ) {
                                case 'video':
                                    peers[
                                        roomId
                                    ][
                                        peerId
                                    ].peerVideo =
                                        active;
                                    break;

                                case 'audio':
                                    peers[
                                        roomId
                                    ][
                                        peerId
                                    ].peerAudio =
                                        active;
                                    break;

                                case 'screen':
                                    peers[
                                        roomId
                                    ][
                                        peerId
                                    ].peerScreen =
                                        active;
                                    break;
                            }
                        }
                    }
                }

                const data = {
                    peerId:
                        socket.id,

                    peerName:
                        peerName,

                    element:
                        element,

                    active:
                        active,
                };

                sendToRoom(
                    roomId,
                    socket.id,
                    'peerStatus',
                    data
                );

                log.debug(
                    '[' +
                        socket.id +
                        '] emit peerStatus to [roomId: ' +
                        roomId +
                        ']',
                    data
                );
            }
        );

        // ====================================================
        // ADD PEER
        // ====================================================

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
                    await channels[
                        channel
                    ][
                        id
                    ].emit(
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

                    log.debug(
                        '[' +
                            socket.id +
                            '] emit addPeer [' +
                            id +
                            ']'
                    );
                }
            } catch (
                error
            ) {
                log.error(
                    '[' +
                        socket.id +
                        '] Error in addPeerTo',
                    error
                );
            }
        }

        // ====================================================
        // REMOVE PEER
        // ====================================================

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

                    if (
                        channelSockets[
                            id
                        ] &&
                        typeof channelSockets[
                            id
                        ].emit ===
                            'function'
                    ) {
                        await channelSockets[
                            id
                        ].emit(
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

                    log.debug(
                        '[' +
                            socket.id +
                            '] emit removePeer [' +
                            id +
                            ']'
                    );
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

                    log.debug(
                        '[' +
                            socket.id +
                            '] Channel [' +
                            channel +
                            '] is now empty and removed'
                    );
                }

                const activeRooms =
                    getActiveRooms();

                log.info(
                    '[RemovePeer] - active rooms and peers count',
                    activeRooms
                );

                log.debug(
                    '[RemovePeer] - connected peers grp by roomId',
                    peers
                );
            } catch (
                error
            ) {
                log.error(
                    '[' +
                        socket.id +
                        '] Error in removePeerFrom',
                    error
                );
            }
        }

        // ====================================================
        // SEND TO ROOM
        // ====================================================

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
                        await channels[
                            roomId
                        ][
                            peerId
                        ].emit(
                            msg,
                            config
                        );
                    } catch (
                        error
                    ) {
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

        // ====================================================
        // SEND TO PEER
        // ====================================================

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
                } catch (
                    error
                ) {
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

        // ====================================================
        // ACTIVE ROOMS
        // ====================================================

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
