'use strict';

/**
 * MiroTalk C2C - Server component
 *
 * Basic Authentication added:
 * - HTTP pages
 * - Frontend files
 * - Join
 * - Profile
 * - Logout
 * - API
 * - Swagger
 * - Socket.IO / WebSocket
 *
 * Credentials are loaded from environment variables:
 * BASIC_AUTH_ENABLED=true
 * BASIC_AUTH_USERNAME=your_username
 * BASIC_AUTH_PASSWORD=your_password
 * BASIC_AUTH_SECRET=random_long_secret
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

// Email alerts and notifications
const nodemailer = require('./lib/nodemailer');

// Sentry
sentry.start();

// ============================================================
// SSL
// ============================================================

const keyPath = path.join(__dirname, 'ssl/key.pem');
const certPath = path.join(__dirname, 'ssl/cert.pem');

const options = {
    key: fs.readFileSync(keyPath, 'utf-8'),
    cert: fs.readFileSync(certPath, 'utf-8'),
};

// ============================================================
// HTTP / HTTPS SERVER
// ============================================================

const server = httpolyglot.createServer(options, app);

// ============================================================
// BASIC AUTHENTICATION
// ============================================================

const BASIC_AUTH_ENABLED = getEnvBoolean(
    process.env.BASIC_AUTH_ENABLED
);

const BASIC_AUTH_USERNAME =
    process.env.BASIC_AUTH_USERNAME || '';

const BASIC_AUTH_PASSWORD =
    process.env.BASIC_AUTH_PASSWORD || '';

const BASIC_AUTH_SECRET =
    process.env.BASIC_AUTH_SECRET ||
    'CHANGE_THIS_SECRET_IN_RENDER';

const BASIC_AUTH_COOKIE = 'mirotalk_c2c_auth';

if (
    BASIC_AUTH_ENABLED &&
    (!BASIC_AUTH_USERNAME || !BASIC_AUTH_PASSWORD)
) {
    log.error(
        'BASIC_AUTH_ENABLED=true but BASIC_AUTH_USERNAME or BASIC_AUTH_PASSWORD is missing'
    );

    process.exit(1);
}

if (
    BASIC_AUTH_ENABLED &&
    BASIC_AUTH_SECRET === 'CHANGE_THIS_SECRET_IN_RENDER'
) {
    log.warn(
        'WARNING: BASIC_AUTH_SECRET is using the default value. Change it in Render!'
    );
}

/**
 * Create HMAC signature for authentication cookie.
 */
function createAuthSignature(timestamp) {
    return crypto
        .createHmac('sha256', BASIC_AUTH_SECRET)
        .update(String(timestamp))
        .digest('hex');
}

/**
 * Create authentication cookie value.
 */
function createAuthCookie() {
    const timestamp = Date.now();

    const signature = createAuthSignature(timestamp);

    return `${timestamp}.${signature}`;
}

/**
 * Verify authentication cookie.
 */
function verifyAuthCookie(cookieValue) {
    if (!cookieValue) {
        return false;
    }

    const parts = cookieValue.split('.');

    if (parts.length !== 2) {
        return false;
    }

    const timestamp = Number(parts[0]);
    const signature = parts[1];

    if (!Number.isFinite(timestamp) || !signature) {
        return false;
    }

    // Session lifetime: 24 hours
    const maxAge = 24 * 60 * 60 * 1000;

    if (Date.now() - timestamp > maxAge) {
        return false;
    }

    if (Date.now() - timestamp < 0) {
        return false;
    }

    const expectedSignature =
        createAuthSignature(timestamp);

    try {
        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expectedSignature)
        );
    } catch {
        return false;
    }
}

/**
 * Read cookies manually without requiring another npm package.
 */
function getCookie(req, cookieName) {
    const cookieHeader = req.headers.cookie;

    if (!cookieHeader) {
        return null;
    }

    const cookies = cookieHeader.split(';');

    for (const cookie of cookies) {
        const separator = cookie.indexOf('=');

        if (separator === -1) {
            continue;
        }

        const name = cookie
            .substring(0, separator)
            .trim();

        const value = cookie
            .substring(separator + 1)
            .trim();

        if (name === cookieName) {
            return decodeURIComponent(value);
        }
    }

    return null;
}

/**
 * Check HTTP Basic Authentication header.
 */
function checkBasicAuthorization(authorization) {
    if (
        !authorization ||
        !authorization.startsWith('Basic ')
    ) {
        return false;
    }

    try {
        const encoded = authorization.substring(6);

        const decoded = Buffer
            .from(encoded, 'base64')
            .toString('utf8');

        const separator = decoded.indexOf(':');

        if (separator === -1) {
            return false;
        }

        const username =
            decoded.substring(0, separator);

        const password =
            decoded.substring(separator + 1);

        return (
            username === BASIC_AUTH_USERNAME &&
            password === BASIC_AUTH_PASSWORD
        );
    } catch (error) {
        log.warn(
            'Basic authentication decode error',
            error.message
        );

        return false;
    }
}

/**
 * Check whether HTTP request is authenticated.
 *
 * Authentication succeeds when:
 * 1. Valid authentication cookie exists
 * OR
 * 2. Valid Basic Authorization header exists
 */
function isHttpAuthenticated(req) {
    if (!BASIC_AUTH_ENABLED) {
        return true;
    }

    const cookie = getCookie(
        req,
        BASIC_AUTH_COOKIE
    );

    if (verifyAuthCookie(cookie)) {
        return true;
    }

    return checkBasicAuthorization(
        req.headers.authorization
    );
}

/**
 * Set authentication cookie.
 */
function setAuthCookie(res, req) {
    const value = createAuthCookie();

    const isHttps =
        req.secure ||
        req.headers['x-forwarded-proto'] === 'https';

    /*
     * Render uses HTTPS in production.
     *
     * SameSite=None is useful if MiroTalk is embedded
     * inside another HTTPS website.
     */
    const sameSite = isHttps ? 'None' : 'Lax';

    const secure = isHttps ? '; Secure' : '';

    res.setHeader(
        'Set-Cookie',
        `${BASIC_AUTH_COOKIE}=${encodeURIComponent(
            value
        )}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=86400${secure}`
    );
}

/**
 * Clear authentication cookie.
 */
function clearAuthCookie(res, req) {
    const isHttps =
        req.secure ||
        req.headers['x-forwarded-proto'] === 'https';

    const secure = isHttps ? '; Secure' : '';

    res.setHeader(
        'Set-Cookie',
        `${BASIC_AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
    );
}

/**
 * Main HTTP authentication middleware.
 */
function basicAuth(req, res, next) {
    if (!BASIC_AUTH_ENABLED) {
        return next();
    }

    if (isHttpAuthenticated(req)) {
        /*
         * If the user authenticated with Basic Auth,
         * create a session cookie so WebSocket/Socket.IO
         * can authenticate automatically.
         */
        const cookie = getCookie(
            req,
            BASIC_AUTH_COOKIE
        );

        if (!verifyAuthCookie(cookie)) {
            setAuthCookie(res, req);
        }

        return next();
    }

    res.setHeader(
        'WWW-Authenticate',
        'Basic realm="MiroTalk C2C", charset="UTF-8"'
    );

    return res
        .status(401)
        .send(`
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>MiroTalk C2C - Authentication Required</title>
            </head>
            <body>
                <h2>MiroTalk C2C</h2>
                <p>Authentication required.</p>
            </body>
            </html>
        `);
}

// ============================================================
// SERVER SETTINGS
// ============================================================

const trustProxy =
    !!getEnvBoolean(process.env.TRUST_PROXY);

const port =
    process.env.PORT || 8080;

const host =
    process.env.HOST ||
    `http://localhost:${port}`;

const apiKeySecret =
    process.env.API_KEY_SECRET ||
    'mirotalkc2c_default_secret';

const apiBasePath = '/api/v1';

const apiDocs =
    host + apiBasePath + '/docs';

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
            JSON.parse(cors_origin);
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
            JSON.parse(cors_methods);
    } catch (error) {
        log.error(
            'Error parsing CORS_METHODS',
            error.message
        );
    }
}

const corsOptions = {
    origin: corsOrigin,
    methods: corsMethods,
};

// ============================================================
// SOCKET.IO
// ============================================================

const io = new Server({
    maxHttpBufferSize: 1e7,

    transports: [
        'websocket',
    ],

    cors: corsOptions,
}).listen(server);

/**
 * Socket.IO authentication.
 *
 * Authentication is accepted through:
 *
 * 1. Authentication cookie
 * 2. Basic Authorization header
 *
 * The browser automatically sends the authentication
 * cookie during the WebSocket handshake.
 */
io.use((socket, next) => {
    if (!BASIC_AUTH_ENABLED) {
        return next();
    }

    const headers =
        socket.handshake.headers || {};

    const cookieHeader =
        headers.cookie || '';

    let authCookie = null;

    const cookies =
        cookieHeader.split(';');

    for (const cookie of cookies) {
        const separator =
            cookie.indexOf('=');

        if (separator === -1) {
            continue;
        }

        const name =
            cookie
                .substring(0, separator)
                .trim();

        const value =
            cookie
                .substring(separator + 1)
                .trim();

        if (
            name === BASIC_AUTH_COOKIE
        ) {
            try {
                authCookie =
                    decodeURIComponent(value);
            } catch {
                authCookie = value;
            }

            break;
        }
    }

    if (
        verifyAuthCookie(authCookie)
    ) {
        return next();
    }

    /*
     * Also support Authorization header
     * for non-browser Socket.IO clients.
     */
    if (
        checkBasicAuthorization(
            headers.authorization
        )
    ) {
        return next();
    }

    log.warn(
        'Socket.IO authentication failed',
        {
            ip:
                socket.handshake.address,
        }
    );

    return next(
        new Error(
            'أكيد. هذه نسخة إنجليزية لصفحة **18+**، بدون وصف جنسي صريح:

# The Jumping Rabbit 🐰

## 18+ Adult Content Warning

Welcome to **The Jumping Rabbit**, a website intended exclusively for adults aged **18 and over**.

This website may contain adult-oriented live streams and material that is not suitable for minors.

By entering this website, you confirm that you are at least **18 years old** and legally permitted to access adult content in your location.

If you are under 18, please leave this website immediately.

Please respect the privacy of streamers and other visitors at all times.

Do not share personal information, passwords, financial details, or private documents with other users.

Be careful when communicating with people you do not personally know.

Do not click suspicious links or download unknown files.

Never send money to someone simply because they request it through a live chat.

Use the reporting and blocking features whenever you encounter suspicious or inappropriate behavior.

Do not record, copy, or redistribute live-stream content without the appropriate permission.

Respect copyright, privacy, and applicable laws.

The Jumping Rabbit is intended for responsible adult use only.

You are responsible for following the laws and regulations applicable in your country.

If adult content is restricted or prohibited where you live, do not enter the website.

Please use the service responsibly and respect other members of the community.

Your continued use of this website means that you acknowledge this age warning.

### Before You Continue

**Are you 18 years old or older?**

**YES, I AM 18+**

**NO, EXIT**

By selecting **YES, I AM 18+**, you confirm that you meet the minimum age requirement and agree to use the website responsibly.

**The Jumping Rabbit — Live Streaming for Adults 18+**
'
        )
    );
});

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
        urls: stunServerUrl,
    });
}

if (
    turnServerEnabled &&
    turnServerUrl &&
    turnServerUsername &&
    turnServerCredential
) {
    iceServers.push({
        urls: turnServerUrl,
        username: turnServerUsername,
        credential:
            turnServerCredential,
    });
}

// ============================================================
// MATTERMOST
// ============================================================

const mattermostCfg = {
    enabled: getEnvBoolean(
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
    process.env.SURVEY_URL || false;

const redirectURL =
    process.env.REDIRECT_URL || false;

// ============================================================
// OIDC
// ============================================================

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
                  process.env
                      .OIDC_BASE_URL_DYNAMIC
              )
            : false,

    allowedDynamicBaseURLs:
        process.env.OIDC_ALLOWED_DYNAMIC_BASE_URLS
            ? process.env
                  .OIDC_ALLOWED_DYNAMIC_BASE_URLS
                  .split(',')
                  .map((u) => u.trim())
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
            response_type: 'code',
            scope:
                'openid profile email',
        },

        authRequired:
            process.env.OIDC_AUTH_REQUIRED
                ? getEnvBoolean(
                      process.env
                          .OIDC_AUTH_REQUIRED
                  )
                : false,

        auth0Logout:
            process.env.OIDC_AUTH_LOGOUT
                ? getEnvBoolean(
                      process.env
                          .OIDC_AUTH_LOGOUT
                  )
                : true,

        routes: {
            callback:
                '/auth/callback',

            login: false,

            logout:
                '/logout',
        },
    },
};

const OIDCAuth =
    function (req, res, next) {
        if (OIDC.enabled) {
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

        next();
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
// EXPRESS MIDDLEWARE
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
 * Basic authentication is installed before
 * static files, pages, API and Swagger.
 *
 * Therefore everything is protected.
 */
app.use(basicAuth);

app.use(
    applyEmbedHeaders
);

app.use(
    express.static(
        frontendDir
    )
);

app.use(
    cors(corsOptions)
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
    apiBasePath + '/docs',
    swaggerUi.serve,
    swaggerUi.setup(
        swaggerDocument
    )
);

// ============================================================
// REQUEST LOGGING
// ============================================================

app.use(
    (req, res, next) => {
        log.debug(
            'New request:',
            {
                body: req.body,
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
    (err, req, res, next) => {
        if (
            err instanceof SyntaxError ||
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
                    status: 404,
                    message:
                        err.message,
                });
        }

        if (
            req.path.substr(-1) === '/' &&
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

        next();
    }
);

// ============================================================
// OIDC
// ============================================================

if (OIDC.enabled) {
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
                .map((u) => {
                    try {
                        return new URL(
                            u
                        ).origin;
                    } catch {
                        return null;
                    }
                })
                .filter(Boolean)
        );

    const authMiddlewareCache =
        new Map();

    const getAuthMiddleware =
        (
            host,
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
                        OIDC.config
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
                `${protocol}://${host}`;

            if (
                !authMiddlewareCache.has(
                    key
                )
            ) {
                const config = {
                    ...OIDC.config,
                    baseURL: key,
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
        (req, res, next) => {
            const host =
                req.headers.host;

            const protocol =
                req.protocol ===
                'https'
                    ? 'https'
                    : 'http';

            const cacheKey =
                `${protocol}://${host}`;

            if (
                OIDC.baseUrlDynamic &&
                !allowedOrigins.has(
                    cacheKey
                )
            ) {
                log.warn(
                    'OIDC Host header not in allowlist - rejecting request',
                    {
                        host,
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
                    host,
                    protocol
                )(
                    req,
                    res,
                    next
                );
            } catch (err) {
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
    (req, res) => {
        if (OIDC.enabled) {
            log.debug(
                'OIDC User profile requested',
                req.oidc.user
            );

            return res.json(
                req.oidc.user
            );
        }

        return res.json({
            profile: false,
        });
    }
);

// ============================================================
// OIDC CALLBACK
// ============================================================

app.get(
    '/auth/callback',
    (req, res, next) => {
        next();
    }
);

// ============================================================
// LOGOUT
// ============================================================

app.get(
    '/logout',
    (req, res) => {
        if (OIDC.enabled) {
            req.logout();
        }

        clearAuthCookie(
            res,
            req
        );

        res.redirect('/');
    }
);

// ============================================================
// HOME OIDC AUTH
// ============================================================

const HomeOIDCAuth =
    (req, res, next) => {
        if (
            OIDC.enabled &&
            !OIDC.config.authRequired &&
            req.oidc &&
            !req.oidc.isAuthenticated()
        ) {
            const query =
                checkXSS(
                    req.query || {}
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
    (req, res) => {
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
    (req, res) => {
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
    (req, res, next) => {
        if (
            Object.keys(
                req.query
            ).length === 0
        ) {
            return notFound(res);
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

        if (!room || !name) {
            return notFound(res);
        }

        if (
            OIDC.enabled &&
            OIDC.config.authRequired &&
            (!req.oidc ||
                !req.oidc.isAuthenticated())
        ) {
            return OIDCAuth(
                req,
                res,
                next
            );
        }

        if (
            OIDC.enabled &&
            (!req.oidc ||
                !req.oidc.isAuthenticated())
        ) {
            const roomExist =
                room in peers;

            if (!roomExist) {
                return notFound(
                    res
                );
            }
        }

        return res.sendFile(
            htmlClient
        );
    },
    (req, res) => {
        return res.sendFile(
            htmlClient
        );
    }
);

// ============================================================
// API - MEETING
// ============================================================

app.post(
    [
        `${apiBasePath}/meeting`,
    ],
    basicAuth,
    (req, res) => {
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
    [
        `${apiBasePath}/join`,
    ],
    basicAuth,
    (req, res) => {
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
    (req, res) => {
        return notFound(
            res
        );
    }
);

function notFound(res) {
    res.json({
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
    const server = {
        home: host,
        room:
            host +
            queryRoom,
        join:
            host +
            queryJoin,
    };

    const server_tunnel =
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
            server,

        serverTunnel:
            server_tunnel,

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

        /*
         * Do NOT expose BASIC_AUTH_PASSWORD
         * or BASIC_AUTH_SECRET here.
         */
        basicAuth: {
            enabled:
                BASIC_AUTH_ENABLED,

            username:
                BASIC_AUTH_ENABLED
                    ? BASIC_AUTH_USERNAME
                    : false,
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
    } catch (err) {
        log.warn(
            'Ngrok Start error',
            err
        );

        await ngrok.kill();

        process.exit(1);
    }
}

// ============================================================
// START SERVER
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
            'MiroTalk C2C server started'
        );

        log.info(
            'Basic Authentication:',
            BASIC_AUTH_ENABLED
                ? 'ENABLED'
                : 'DISABLED'
        );
    }
);

// ============================================================
// CLIENT ERRORS
// ============================================================

server.on(
    'clientError',
    (err, socket) => {
        err.code ===
            'HPE_HEADER_OVERFLOW' ||
        err.message ===
            'Parse Error'
            ? log.warn(
                  'Client HTTP parse error',
                  {
                      error:
                          err.message,
                      code:
                          err.code,
                  }
              )
            : log.warn(
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

// ============================================================
// SOCKET.IO ERRORS
// ============================================================

io.on(
    'error',
    (error) => {
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
    (socket) => {
        log.debug(
            '[' +
                socket.id +
                '] connection accepted'
        );

        socket.channels = {};

        sockets[socket.id] =
            socket;

        // ====================================================
        // JOIN
        // ====================================================

        socket.on(
            'join',
            (cfg) => {
                const config =
                    checkXSS(cfg);

                log.debug(
                    '[' +
                        socket.id +
                        '] join ',
                    config
                );

                const channel =
                    config.channel;

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
                ] =
                    socket;

                socket.channels[
                    channel
                ] =
                    channel;

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

                // Email alert
                if (
                    peerCounts === 1
                ) {
                    const {
                        peerName,
                        osName,
                        osVersion,
                        browserName,
                        browserVersion,
                    } =
                        config.peerInfo;

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
                                    .split(
                                        ':'
                                    )[0],

                            os: osName
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
        // CHECK SHARED ROOM
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

            for (const channel in socket.channels) {
                if (
                    channels[
                        channel
                    ] &&
                    channels[
                        channel
                    ][peerId]
                ) {
                    return true;
                }
            }

            return false;
        }

        // ====================================================
        // SDP
        // ====================================================

        socket.on(
            'relaySDP',
            (config) => {
                const {
                    peerId,
                    sessionDescription,
                } = config;

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
                        '] ',
                    {
                        type:
                            sessionDescription.type,
                    }
                );
            }
        );

        // ====================================================
        // ICE
        // ====================================================

        socket.on(
            'relayICE',
            (config) => {
                const {
                    peerId,
                    iceCandidate,
                } = config;

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
            (reason) => {
                for (
                    let channel in
                    socket.channels
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

                // Extra cleanup
                for (
                    let channel in
                    channels
                ) {
                    if (
                        channels[
                            channel
                        ] &&
                        channels[
                            channel
                        ][socket.id]
                    ) {
                        delete channels[
                            channel
                        ][
                            socket.id
                        ];

                        log.debug(
                            '[' +
                                socket.id +
                                '] cleaned up from channel [' +
                                channel +
                                ']'
                        );
                    }
                }

                for (
                    let channel in
                    peers
                ) {
                    if (
                        peers[
                            channel
                        ] &&
                        peers[
                            channel
                        ][socket.id]
                    ) {
                        delete peers[
                            channel
                        ][
                            socket.id
                        ];

                        log.debug(
                            '[' +
                                socket.id +
                                '] cleaned up from peers [' +
                                channel +
                                ']'
                        );
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
            (cfg) => {
                const config =
                    checkXSS(cfg);

                const {
                    roomId,
                    peerName,
                    element,
                    active,
                } = config;

                if (
                    peers[roomId]
                ) {
                    for (
                        let peerId in
                        peers[roomId]
                    ) {
                        if (
                            peers[
                                roomId
                            ][peerId] &&
                            peers[
                                roomId
                            ][peerId][
                                'peerName'
                            ] ==
                                peerName
                        ) {
                            switch (
                                element
                            ) {
                                case 'video':
                                    peers[
                                        roomId
                                    ][peerId][
                                        'peerVideo'
                                    ] =
                                        active;
                                    break;

                                case 'audio':
                                    peers[
                                        roomId
                                    ][peerId][
                                        'peerAudio'
                                    ] =
                                        active;
                                    break;

                                case 'screen':
                                    peers[
                                        roomId
                                    ][peerId][
                                        'peerScreen'
                                    ] =
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
                for (
                    let id in
                    channels[
                        channel
                    ]
                ) {
                    await channels[
                        channel
                    ][id].emit(
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
            } catch (error) {
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
                log.debug(
                    '[' +
                        socket.id +
                        '] [Warning] not in ',
                    channel
                );

                return;
            }

            try {
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
                    ][socket.id];
                }

                if (
                    peers[
                        channel
                    ]
                ) {
                    delete peers[
                        channel
                    ][socket.id];
                }

                // Clean up empty channel
                if (
                    peers[
                        channel
                    ] &&
                    Object.keys(
                        peers[
                            channel
                        ]
                    ).length === 0
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

                    return;
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

                if (
                    channels[
                        channel
                    ]
                ) {
                    for (
                        let id in
                        channels[
                            channel
                        ]
                    ) {
                        await channels[
                            channel
                        ][id].emit(
                            'removePeer',
                            {
                                peerId:
                                    socket.id,
                            }
                        );

                        socket.emit(
                            'removePeer',
                            {
                                peerId:
                                    id,
                            }
                        );

                        log.debug(
                            '[' +
                                socket.id +
                                '] emit removePeer [' +
                                id +
                                ']'
                        );
                    }
                }
            } catch (error) {
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
                let peerId in
                channels[
                    roomId
                ]
            ) {
                if (
                    peerId !=
                    socketId
                ) {
                    await channels[
                        roomId
                    ][peerId].emit(
                        msg,
                        config
                    );
                }
            }
        }

        // ====================================================
        // SEND TO PEER
        // ====================================================

        async function sendToPeer(
            peerId,
            sockets,
            msg,
            config = {}
        ) {
            if (
                peerId in
                sockets
            ) {
                await sockets[
                    peerId
                ].emit(
                    msg,
                    config
                );
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
