'use strict';

/*
============================================================
 THE RABBIT IN THE HOLE
 MASTER ADMIN CONTROL
============================================================

ملف واحد فقط للتحكم في الموقع.

المزايا:
- لوحة تحكم عصرية
- لا يحتاج admin.html
- لا يحتاج admin.css
- لا يحتاج admin.js
- لا يحتاج settings.json
- حماية باستخدام Basic Auth الموجود في المشروع
- تغيير اسم الموقع
- تغيير عنوان الصفحة
- تغيير الوصف
- تغيير الألوان
- تغيير الخلفية
- صورة / فيديو / WebM
- CSS مخصص
- JavaScript مخصص
- HTML إضافي
- إخفاء عناصر
- تغيير الخط
- تغيير اتجاه الصفحة
- إضافة كود قبل </head>
- إضافة كود بعد <body>
- إضافة كود قبل </body>
- التحكم في عنوان الصفحة
- التحكم في favicon
- التحكم في الـmeta
- تعطيل بعض العناصر بصريًا
- معاينة مباشرة
- استعادة الإعدادات
- كل شيء داخل هذا الملف

ملاحظة:
الإعدادات الحالية محفوظة في الذاكرة.
على Render قد تعود للوضع الافتراضي بعد إعادة تشغيل
الخدمة. لا يتم تعديل ملفات المشروع الأصلية تلقائيًا.
============================================================
*/


const fs = require('fs');
const path = require('path');
const crypto = require('crypto');


/*
============================================================
 SETTINGS
============================================================
*/

const CONFIG = {

    /*
    عنوان لوحة الإدارة
    */
    adminPath:
        '/rabbit-control',

    /*
    اسم لوحة الإدارة
    */
    adminName:
        'Rabbit Control',

    /*
    لون اللوحة
    */
    accent:
        '#a3ff12',

    /*
    بيانات الدخول:
    الأفضل استخدام Environment Variables في Render.
    */

    username: 'admin',

    password: 'admin',

    secret:
        process.env.ADMIN_CONTROL_SECRET ||
        process.env.BASIC_AUTH_SECRET ||
        'CHANGE_ADMIN_CONTROL_SECRET',

};


/*
============================================================
 DEFAULT SITE CONFIGURATION
============================================================
*/

const DEFAULTS = {

    siteName:
        'The rabbit in the hole',

    title:
        'The rabbit in the hole',

    description:
        '',

    favicon:
        '',

    language:
        'en',

    direction:
        'ltr',


    /*
    ========================================================
    COLORS
    ========================================================
    */

    primaryColor:
        '#a3ff12',

    secondaryColor:
        '#7cff00',

    backgroundColor:
        '#090b0d',

    textColor:
        '#ffffff',


    /*
    ========================================================
    BACKGROUND
    ========================================================
    */

    backgroundEnabled:
        true,

    backgroundType:
        'image',

    backgroundUrl:
        '',

    backgroundSize:
        'cover',

    backgroundPosition:
        'center',

    backgroundRepeat:
        'no-repeat',

    backgroundAttachment:
        'fixed',

    backgroundOverlay:
        '0.15',


    /*
    ========================================================
    TYPOGRAPHY
    ========================================================
    */

    fontFamily:
        'Arial, Helvetica, sans-serif',

    fontSize:
        '',


    /*
    ========================================================
    INTERFACE
    ========================================================
    */

    hideLogo:
        false,

    hideSiteName:
        false,

    hideFooter:
        false,

    hideHomeButton:
        false,

    hideChat:
        false,

    hideVideo:
        false,


    /*
    ========================================================
    CUSTOM CODE
    ========================================================
    */

    customCSS:
        '',

    customJS:
        '',

    headHTML:
        '',

    bodyStartHTML:
        '',

    bodyEndHTML:
        '',


    /*
    ========================================================
    META
    ========================================================
    */

    robots:
        'index,follow',

    themeColor:
        '#090b0d',

};


/*
============================================================
 LIVE CONFIG
============================================================
*/

let SITE = {
    ...DEFAULTS,
};


/*
============================================================
 UTILITIES
============================================================
*/

function escapeHtml(value) {

    return String(
        value === undefined ||
        value === null
            ? ''
            : value
    )
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


function safeString(
    value,
    max = 50000
) {

    if (
        typeof value !==
        'string'
    ) {
        return '';
    }

    return value.substring(
        0,
        max
    );
}


function safeColor(
    value,
    fallback
) {

    if (
        typeof value !==
        'string'
    ) {
        return fallback;
    }

    if (
        /^#[0-9a-fA-F]{3,8}$/
            .test(value)
    ) {
        return value;
    }

    if (
        /^rgba?\([^)]+\)$/
            .test(value)
    ) {
        return value;
    }

    return fallback;
}


function getCookies(req) {

    const header =
        req.headers.cookie || '';

    const result = {};

    header
        .split(';')
        .forEach(
            item => {

                const index =
                    item.indexOf('=');

                if (
                    index === -1
                ) {
                    return;
                }

                const name =
                    item
                        .substring(
                            0,
                            index
                        )
                        .trim();

                const value =
                    item
                        .substring(
                            index + 1
                        )
                        .trim();

                result[name] =
                    decodeURIComponent(
                        value
                    );
            }
        );

    return result;
}


/*
============================================================
 ADMIN SESSION
============================================================
*/

const ADMIN_COOKIE =
    'rabbit_control_session';


const sessions =
    new Map();


function createSession() {

    const token =
        crypto
            .randomBytes(48)
            .toString('hex');

    sessions.set(
        token,
        Date.now() +
            24 * 60 * 60 * 1000
    );

    return token;
}


function isAuthenticated(req) {

    const cookies =
        getCookies(req);

    const token =
        cookies[
            ADMIN_COOKIE
        ];

    if (!token) {
        return false;
    }

    const expires =
        sessions.get(token);

    if (!expires) {
        return false;
    }

    if (
        Date.now() >
        expires
    ) {
        sessions.delete(
            token
        );

        return false;
    }

    return true;
}


function requireAdmin(
    req,
    res,
    next
) {

    if (
        isAuthenticated(req)
    ) {
        return next();
    }

    return res
        .status(401)
        .json({
            error:
                'Administrator authentication required.',
        });
}


/*
============================================================
 LOGIN
============================================================
*/

function verifyLogin(
    username,
    password
) {

    if (
        !CONFIG.username ||
        !CONFIG.password
    ) {
        return false;
    }

    return (
        crypto.timingSafeEqual(
            Buffer.from(
                String(username)
            ),
            Buffer.from(
                String(
                    CONFIG.username
                )
            )
        ) &&
        crypto.timingSafeEqual(
            Buffer.from(
                String(password)
            ),
            Buffer.from(
                String(
                    CONFIG.password
                )
            )
        )
    );
}


/*
============================================================
 GENERATE ADMIN PAGE
============================================================
*/

function adminPage() {

    return `<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<meta
    name="robots"
    content="noindex,nofollow"
>

<title>Rabbit Control</title>

<style>

* {
    box-sizing:border-box;
}

html,
body {
    margin:0;
    min-height:100%;
    background:#07090b;
    color:#fff;
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

body {
    min-height:100vh;
}

button,
input,
textarea,
select {
    font:inherit;
}

button {
    cursor:pointer;
}

.hidden {
    display:none!important;
}


/* LOGIN */

#login {

    min-height:100vh;

    display:flex;

    align-items:center;

    justify-content:center;

    padding:25px;

    background:

        radial-gradient(
            circle at 20% 20%,
            rgba(163,255,18,.10),
            transparent 35%
        ),

        radial-gradient(
            circle at 80% 80%,
            rgba(124,255,0,.08),
            transparent 35%
        ),

        #07090b;
}

.login-card {

    width:100%;

    max-width:430px;

    padding:42px;

    border-radius:28px;

    background:
        rgba(20,23,27,.82);

    border:
        1px solid
        rgba(255,255,255,.09);

    box-shadow:
        0 40px 120px
        rgba(0,0,0,.55);

    backdrop-filter:
        blur(30px);
}

.rabbit {

    width:76px;

    height:76px;

    margin:
        0 auto 24px;

    display:flex;

    align-items:center;

    justify-content:center;

    border-radius:24px;

    background:
        linear-gradient(
            135deg,
            #a3ff12,
            #68d000
        );

    color:#050700;

    font-size:38px;

    box-shadow:
        0 15px 50px
        rgba(163,255,18,.22);
}

.login-card h1 {

    margin:0;

    text-align:center;

    font-size:28px;

    letter-spacing:-.7px;
}

.login-card p {

    margin:
        9px 0 30px;

    text-align:center;

    color:#8d949f;
}

.field {

    margin-bottom:17px;
}

.field label {

    display:block;

    margin-bottom:8px;

    color:#aeb4bd;

    font-size:13px;
}

.field input {

    width:100%;

    height:52px;

    padding:0 15px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:14px;

    outline:none;

    background:#0d1014;

    color:#fff;

    transition:.2s;
}

.field input:focus {

    border-color:
        rgba(163,255,18,.65);

    box-shadow:
        0 0 0 4px
        rgba(163,255,18,.08);
}

.login-button {

    width:100%;

    height:54px;

    border:0;

    border-radius:15px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #72dc00
        );

    color:#071000;

    font-weight:800;

    margin-top:5px;

    box-shadow:
        0 15px 40px
        rgba(163,255,18,.15);
}

.login-error {

    margin-top:15px;

    padding:12px;

    border-radius:12px;

    background:
        rgba(255,60,80,.10);

    color:#ff8793;

    font-size:13px;

    text-align:center;
}


/* APP */

#app {

    min-height:100vh;

    display:flex;

    background:#07090b;
}


/* SIDEBAR */

.sidebar {

    width:270px;

    min-height:100vh;

    padding:22px 16px;

    position:fixed;

    left:0;

    top:0;

    bottom:0;

    z-index:20;

    background:
        rgba(13,16,20,.88);

    border-right:
        1px solid
        rgba(255,255,255,.07);

    backdrop-filter:
        blur(28px);
}

.brand {

    display:flex;

    align-items:center;

    gap:12px;

    padding:
        8px 10px 26px;

    margin-bottom:8px;
}

.brand-icon {

    width:42px;

    height:42px;

    display:flex;

    align-items:center;

    justify-content:center;

    border-radius:13px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #70d900
        );

    color:#071000;

    font-size:22px;
}

.brand strong {

    display:block;

    font-size:15px;
}

.brand span {

    display:block;

    margin-top:3px;

    color:#747c87;

    font-size:11px;
}

.nav {

    display:flex;

    flex-direction:column;

    gap:5px;
}

.nav button {

    width:100%;

    min-height:46px;

    padding:0 13px;

    border:0;

    border-radius:13px;

    background:transparent;

    color:#8f96a1;

    text-align:left;

    transition:.2s;
}

.nav button:hover {

    color:#fff;

    background:
        rgba(255,255,255,.045);
}

.nav button.active {

    color:#b8ff4b;

    background:
        rgba(163,255,18,.09);

    box-shadow:
        inset 3px 0 0
        #a3ff12;
}

.sidebar-bottom {

    position:absolute;

    left:16px;

    right:16px;

    bottom:20px;
}

.logout {

    width:100%;

    height:45px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:13px;

    background:#101318;

    color:#969da8;
}


/* CONTENT */

.content {

    margin-left:270px;

    width:
        calc(100% - 270px);

    padding:28px;

    min-height:100vh;
}

.topbar {

    display:flex;

    align-items:center;

    justify-content:space-between;

    margin-bottom:28px;
}

.topbar h1 {

    margin:0;

    font-size:28px;

    letter-spacing:-.8px;
}

.topbar p {

    margin:6px 0 0;

    color:#747c87;

    font-size:13px;
}

.save {

    height:45px;

    padding:
        0 18px;

    border:0;

    border-radius:13px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #71d800
        );

    color:#071000;

    font-weight:800;
}


/* SECTIONS */

.section {
    display:none;
}

.section.active {
    display:block;
}


/* DASHBOARD */

.hero {

    padding:30px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:24px;

    background:

        radial-gradient(
            circle at 90% 20%,
            rgba(163,255,18,.10),
            transparent 35%
        ),

        linear-gradient(
            135deg,
            #13171c,
            #0d1014
        );

    margin-bottom:18px;
}

.hero h2 {

    margin:0 0 8px;

    font-size:24px;
}

.hero p {

    margin:0;

    color:#858d98;
}

.grid {

    display:grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                190px,
                1fr
            )
        );

    gap:14px;
}

.stat {

    padding:22px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:19px;

    background:#111419;
}

.stat-icon {

    font-size:24px;

    margin-bottom:15px;
}

.stat strong {

    display:block;

    font-size:20px;
}

.stat span {

    display:block;

    margin-top:4px;

    color:#747c87;

    font-size:12px;
}


/* SETTINGS */

.card {

    max-width:1000px;

    padding:25px;

    margin-bottom:18px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:22px;

    background:#111419;
}

.card h2 {

    margin:
        0 0 5px;

    font-size:18px;
}

.card .sub {

    margin:
        0 0 22px;

    color:#727a85;

    font-size:12px;
}

.form-grid {

    display:grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                250px,
                1fr
            )
        );

    gap:16px;
}

.control {

    margin-bottom:5px;
}

.control.full {

    grid-column:
        1 / -1;
}

.control label {

    display:block;

    margin-bottom:8px;

    color:#aeb5bf;

    font-size:12px;
}

.control input,
.control select,
.control textarea {

    width:100%;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:12px;

    background:#0b0e12;

    color:#fff;

    outline:none;

    padding:
        12px 13px;

    transition:.2s;
}

.control input,
.control select {

    height:46px;
}

.control textarea {

    min-height:140px;

    resize:vertical;

    line-height:1.5;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

    font-size:12px;
}

.control input:focus,
.control select:focus,
.control textarea:focus {

    border-color:
        rgba(163,255,18,.55);

    box-shadow:
        0 0 0 4px
        rgba(163,255,18,.06);
}

.color {

    display:flex;

    gap:8px;
}

.color input[type=color] {

    width:58px;

    padding:3px;

    cursor:pointer;
}

.switch {

    display:flex;

    align-items:center;

    justify-content:space-between;

    padding:14px;

    margin-bottom:8px;

    border:
        1px solid
        rgba(255,255,255,.06);

    border-radius:13px;

    background:#0d1014;
}

.switch span {

    color:#b8bec7;

    font-size:13px;
}

.switch input {

    width:19px;

    height:19px;

    accent-color:#a3ff12;
}


/* TOAST */

.toast {

    position:fixed;

    right:25px;

    bottom:25px;

    z-index:100;

    padding:
        13px 17px;

    border:
        1px solid
        rgba(163,255,18,.25);

    border-radius:13px;

    background:
        rgba(18,23,19,.95);

    color:#b9ff55;

    box-shadow:
        0 20px 60px
        rgba(0,0,0,.45);

    transform:
        translateY(20px);

    opacity:0;

    pointer-events:none;

    transition:.25s;
}

.toast.show {

    transform:
        translateY(0);

    opacity:1;
}


/* MOBILE */

@media(max-width:800px) {

    .sidebar {

        width:74px;

        padding:
            16px 10px;
    }

    .brand {

        justify-content:center;

        padding-bottom:18px;
    }

    .brand div:last-child,
    .nav button span,
    .sidebar-bottom button span {

        display:none;
    }

    .nav button {

        text-align:center;

        padding:0;

        font-size:19px;
    }

    .content {

        margin-left:74px;

        width:
            calc(100% - 74px);

        padding:18px;
    }

}

@media(max-width:520px) {

    .content {

        padding:12px;
    }

    .topbar {

        gap:12px;
    }

    .topbar h1 {

        font-size:22px;
    }

    .save {

        padding:
            0 12px;
    }

    .card {

        padding:18px;
    }

}

</style>

</head>


<body>


<!-- LOGIN -->

<div id="login">

    <div class="login-card">

        <div class="rabbit">
            🥕
        </div>

        <h1>
            Rabbit Control
        </h1>

        <p>
            Master control center
        </p>

        <form id="loginForm">

            <div class="field">

                <label>
                    Administrator
                </label>

                <input
                    id="username"
                    autocomplete="username"
                    required
                >

            </div>

            <div class="field">

                <label>
                    Password
                </label>

                <input
                    id="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >

            </div>

            <button
                class="login-button"
                type="submit"
            >
                Enter Control Center
            </button>

            <div
                id="loginError"
                class="login-error hidden"
            ></div>

        </form>

    </div>

</div>


<!-- APP -->

<div
    id="app"
    class="hidden"
>


<aside class="sidebar">

    <div class="brand">

        <div class="brand-icon">
            🥕
        </div>

        <div>

            <strong>
                Rabbit Control
            </strong>

            <span>
                Master Panel
            </span>

        </div>

    </div>


    <nav class="nav">

        <button
            class="active"
            data-page="dashboard"
        >
            🏠
            <span>
                Dashboard
            </span>
        </button>

        <button
            data-page="site"
        >
            🌐
            <span>
                Website
            </span>
        </button>

        <button
            data-page="background"
        >
            🖼️
            <span>
                Background
            </span>
        </button>

        <button
            data-page="appearance"
        >
            🎨
            <span>
                Appearance
            </span>
        </button>

        <button
            data-page="interface"
        >
            🧩
            <span>
                Interface
            </span>
        </button>

        <button
            data-page="code"
        >
            </ >
            <span>
                Custom Code
            </span>
        </button>

        <button
            data-page="advanced"
        >
            ⚡
            <span>
                Advanced
            </span>
        </button>

    </nav>


    <div class="sidebar-bottom">

        <button
            class="logout"
            id="logout"
        >
            🚪
            <span>
                Logout
            </span>
        </button>

    </div>

</aside>


<main class="content">


<header class="topbar">

    <div>

        <h1 id="pageTitle">
            Dashboard
        </h1>

        <p>
            The rabbit in the hole
        </p>

    </div>

    <button
        class="save"
        id="save"
    >
        Save Changes
    </button>

</header>


<!-- DASHBOARD -->

<section
    id="dashboard"
    class="section active"
>

    <div class="hero">

        <h2>
            Master Control Center
        </h2>

        <p>
            Control the visual and functional layer
            of your website from one place.
        </p>

    </div>


    <div class="grid">

        <div class="stat">

            <div class="stat-icon">
                🌐
            </div>

            <strong>
                Website
            </strong>

            <span>
                Identity and metadata
            </span>

        </div>


        <div class="stat">

            <div class="stat-icon">
                🖼️
            </div>

            <strong>
                Background
            </strong>

            <span>
                Image, video or WebM
            </span>

        </div>


        <div class="stat">

            <div class="stat-icon">
                🎨
            </div>

            <strong>
                Appearance
            </strong>

            <span>
                Colors and typography
            </span>

        </div>


        <div class="stat">

            <div class="stat-icon">
                ⚡
            </div>

            <strong>
                Live Control
            </strong>

            <span>
                Custom CSS and JavaScript
            </span>

        </div>

    </div>

</section>


<!-- WEBSITE -->

<section
    id="site"
    class="section"
>

<div class="card">

    <h2>
        Website Identity
    </h2>

    <p class="sub">
        Change the public identity without editing
        the original HTML files.
    </p>

    <div class="form-grid">

        <div class="control">

            <label>
                Website name
            </label>

            <input
                data-key="siteName"
            >

        </div>


        <div class="control">

            <label>
                Browser title
            </label>

            <input
                data-key="title"
            >

        </div>


        <div class="control full">

            <label>
                Description
            </label>

            <textarea
                data-key="description"
            ></textarea>

        </div>


        <div class="control">

            <label>
                Language
            </label>

            <select
                data-key="language"
            >

                <option value="en">
                    English
                </option>

                <option value="ar">
                    Arabic
                </option>

                <option value="pt">
                    Portuguese
                </option>

            </select>

        </div>


        <div class="control">

            <label>
                Direction
            </label>

            <select
                data-key="direction"
            >

                <option value="ltr">
                    Left to right
                </option>

                <option value="rtl">
                    Right to left
                </option>

            </select>

        </div>


        <div class="control full">

            <label>
                Favicon URL
            </label>

            <input
                data-key="favicon"
                placeholder="/images/logo.svg"
            >

        </div>

    </div>

</div>

</section>


<!-- BACKGROUND -->

<section
    id="background"
    class="section"
>

<div class="card">

    <h2>
        Background Engine
    </h2>

    <p class="sub">
        Supports normal images, animated images,
        videos and WebM files.
    </p>


    <div class="switch">

        <span>
            Enable background
        </span>

        <input
            type="checkbox"
            data-key="backgroundEnabled"
        >

    </div>


    <div class="form-grid">

        <div class="control">

            <label>
                Type
            </label>

            <select
                data-key="backgroundType"
            >

                <option value="image">
                    Image
                </option>

                <option value="video">
                    Video
                </option>

                <option value="webm">
                    WebM
                </option>

                <option value="none">
                    None
                </option>

            </select>

        </div>


        <div class="control">

            <label>
                Background URL
            </label>

            <input
                data-key="backgroundUrl"
                placeholder="/images/background.webp"
            >

        </div>


        <div class="control">

            <label>
                Size
            </label>

            <select
                data-key="backgroundSize"
            >

                <option value="cover">
                    Cover
                </option>

                <option value="contain">
                    Contain
                </option>

                <option value="100% 100%">
                    Stretch
                </option>

                <option value="auto">
                    Original
                </option>

            </select>

        </div>


        <div class="control">

            <label>
                Position
            </label>

            <select
                data-key="backgroundPosition"
            >

                <option value="center">
                    Center
                </option>

                <option value="top">
                    Top
                </option>

                <option value="bottom">
                    Bottom
                </option>

                <option value="left">
                    Left
                </option>

                <option value="right">
                    Right
                </option>

            </select>

        </div>


        <div class="control">

            <label>
                Overlay
            </label>

            <input
                data-key="backgroundOverlay"
                placeholder="0.15"
            >

        </div>

    </div>

</div>

</section>


<!-- APPEARANCE -->

<section
    id="appearance"
    class="section"
>

<div class="card">

    <h2>
        Visual System
    </h2>

    <p class="sub">
        Global colors and typography.
    </p>


    <div class="form-grid">

        <div class="control">

            <label>
                Primary color
            </label>

            <div class="color">

                <input
                    type="color"
                    id="primaryPicker"
                >

                <input
                    data-key="primaryColor"
                >

            </div>

        </div>


        <div class="control">

            <label>
                Secondary color
            </label>

            <div class="color">

                <input
                    type="color"
                    id="secondaryPicker"
                >

                <input
                    data-key="secondaryColor"
                >

            </div>

        </div>


        <div class="control">

            <label>
                Background color
            </label>

            <div class="color">

                <input
                    type="color"
                    id="backgroundPicker"
                >

                <input
                    data-key="backgroundColor"
                >

            </div>

        </div>


        <div class="control">

            <label>
                Text color
            </label>

            <div class="color">

                <input
                    type="color"
                    id="textPicker"
                >

                <input
                    data-key="textColor"
                >

            </div>

        </div>


        <div class="control full">

            <label>
                Font family
            </label>

            <input
                data-key="fontFamily"
                placeholder="Arial, sans-serif"
            >

        </div>

    </div>

</div>

</section>


<!-- INTERFACE -->

<section
    id="interface"
    class="section"
>

<div class="card">

    <h2>
        Interface Control
    </h2>

    <p class="sub">
        Hide or restore common interface elements.
    </p>


    <div class="switch">

        <span>
            Hide logo
        </span>

        <input
            type="checkbox"
            data-key="hideLogo"
        >

    </div>


    <div class="switch">

        <span>
            Hide website name
        </span>

        <input
            type="checkbox"
            data-key="hideSiteName"
        >

    </div>


    <div class="switch">

        <span>
            Hide footer
        </span>

        <input
            type="checkbox"
            data-key="hideFooter"
        >

    </div>


    <div class="switch">

        <span>
            Hide home button
        </span>

        <input
            type="checkbox"
            data-key="hideHomeButton"
        >

    </div>


    <div class="switch">

        <span>
            Hide chat
        </span>

        <input
            type="checkbox"
            data-key="hideChat"
        >

    </div>


    <div class="switch">

        <span>
            Hide video
        </span>

        <input
            type="checkbox"
            data-key="hideVideo"
        >

    </div>

</div>

</section>


<!-- CUSTOM CODE -->

<section
    id="code"
    class="section"
>

<div class="card">

    <h2>
        Custom Code
    </h2>

    <p class="sub">
        This is the most powerful part of the panel.
        Inject your own design and behavior without
        modifying the original frontend files.
    </p>


    <div class="control full">

        <label>
            Custom CSS
        </label>

        <textarea
            data-key="customCSS"
            placeholder="/* Your CSS */"
        ></textarea>

    </div>


    <div class="control full">

        <label>
            Custom JavaScript
        </label>

        <textarea
            data-key="customJS"
            placeholder="// Your JavaScript"
        ></textarea>

    </div>


    <div class="control full">

        <label>
            HTML inside &lt;head&gt;
        </label>

        <textarea
            data-key="headHTML"
            placeholder="<!-- Custom head HTML -->"
        ></textarea>

    </div>


    <div class="control full">

        <label>
            HTML after &lt;body&gt;
        </label>

        <textarea
            data-key="bodyStartHTML"
            placeholder="<!-- Custom body content -->"
        ></textarea>

    </div>


    <div class="control full">

        <label>
            HTML before &lt;/body&gt;
        </label>

        <textarea
            data-key="bodyEndHTML"
            placeholder="<!-- Custom footer content -->"
        ></textarea>

    </div>

</div>

</section>


<!-- ADVANCED -->

<section
    id="advanced"
    class="section"
>

<div class="card">

    <h2>
        Advanced Control
    </h2>

    <p class="sub">
        Advanced website-level settings.
    </p>


    <div class="form-grid">

        <div class="control">

            <label>
                Robots
            </label>

            <select
                data-key="robots"
            >

                <option value="index,follow">
                    Index / Follow
                </option>

                <option value="noindex,nofollow">
                    No Index
                </option>

                <option value="index,nofollow">
                    Index / No Follow
                </option>

            </select>

        </div>


        <div class="control">

            <label>
                Theme color
            </label>

            <input
                data-key="themeColor"
            >

        </div>

    </div>

</div>


<div class="card">

    <h2>
        Reset
    </h2>

    <p class="sub">
        Restore all control settings to their
        default values.
    </p>

    <button
        class="save"
        id="reset"
    >
        Reset Everything
    </button>

</div>

</section>


</main>

</div>


<div
    id="toast"
    class="toast"
>
    Saved
</div>


<script>

const state =
    ${JSON.stringify(SITE)};


const $ =
    selector =>
        document.querySelector(
            selector
        );


const $$ =
    selector =>
        document.querySelectorAll(
            selector
        );


function showToast(
    message
) {

    const toast =
        $('#toast');

    toast.textContent =
        message;

    toast.classList
        .add('show');

    setTimeout(
        () =>
            toast.classList
                .remove('show'),
        2500
    );
}


/*
============================================================
 LOGIN
============================================================
*/

$('#loginForm')
    .addEventListener(
        'submit',
        async event => {

            event.preventDefault();

            const username =
                $('#username').value;

            const password =
                $('#password').value;

            try {

                const response =
                    await fetch(
                        '${CONFIG.adminPath}/api/login',
                        {
                            method:
                                'POST',

                            headers: {
                                'Content-Type':
                                    'application/json',
                            },

                            credentials:
                                'same-origin',

                            body:
                                JSON.stringify({
                                    username,
                                    password,
                                }),
                        }
                    );

                const data =
                    await response
                        .json();

                if (
                    !response.ok
                ) {
                    throw new Error(
                        data.error ||
                        'Login failed'
                    );
                }

                $('#login')
                    .classList
                    .add('hidden');

                $('#app')
                    .classList
                    .remove('hidden');

            } catch (error) {

                $('#loginError')
                    .textContent =
                        error.message;

                $('#loginError')
                    .classList
                    .remove('hidden');
            }

        }
    );


/*
============================================================
 NAVIGATION
============================================================
*/

$$('.nav button')
    .forEach(
        button => {

            button
                .addEventListener(
                    'click',
                    () => {

                        $$('.nav button')
                            .forEach(
                                item =>
                                    item
                                        .classList
                                        .remove(
                                            'active'
                                        )
                            );

                        button
                            .classList
                            .add('active');

                        $$('.section')
                            .forEach(
                                section =>
                                    section
                                        .classList
                                        .remove(
                                            'active'
                                        )
                            );

                        const page =
                            button.dataset.page;

                        const section =
                            document.getElementById(
                                page
                            );

                        if (
                            section
                        ) {
                            section
                                .classList
                                .add(
                                    'active'
                                );
                        }

                        $('#pageTitle')
                            .textContent =
                            button
                                .innerText
                                .trim();

                    }
                );

        }
    );


/*
============================================================
 LOAD STATE INTO FORM
============================================================
*/

$$('[data-key]')
    .forEach(
        input => {

            const key =
                input.dataset.key;

            if (
                !(key in state)
            ) {
                return;
            }

            if (
                input.type ===
                'checkbox'
            ) {

                input.checked =
                    Boolean(
                        state[key]
                    );

            } else {

                input.value =
                    state[key] ?? '';

            }

        }
    );


/*
============================================================
 COLORS
============================================================
*/

const colorMap = {

    primaryPicker:
        'primaryColor',

    secondaryPicker:
        'secondaryColor',

    backgroundPicker:
        'backgroundColor',

    textPicker:
        'textColor',

};


Object.entries(
    colorMap
)
.forEach(
    ([pickerId, key]) => {

        const picker =
            document.getElementById(
                pickerId
            );

        const input =
            document.querySelector(
                '[data-key="' +
                key +
                '"]'
            );

        if (!picker || !input) {
            return;
        }

        picker.value =
            /^#[0-9a-f]{6}$/i
                .test(
                    state[key]
                )
                ? state[key]
                : '#ffffff';

        picker
            .addEventListener(
                'input',
                () => {
                    input.value =
                        picker.value;
                }
            );

        input
            .addEventListener(
                'input',
                () => {

                    if (
                        /^#[0-9a-f]{6}$/i
                            .test(
                                input.value
                            )
                    ) {
                        picker.value =
                            input.value;
                    }

                }
            );

    }
);


/*
============================================================
 SAVE
============================================================
*/

$('#save')
    .addEventListener(
        'click',
        async () => {

            const data = {};

            $$('[data-key]')
                .forEach(
                    input => {

                        const key =
                            input.dataset.key;

                        if (
                            input.type ===
                            'checkbox'
                        ) {

                            data[key] =
                                input.checked;

                        } else {

                            data[key] =
                                input.value;

                        }

                    }
                );

            try {

                const response =
                    await fetch(
                        '${CONFIG.adminPath}/api/save',
                        {
                            method:
                                'POST',

                            credentials:
                                'same-origin',

                            headers: {
                                'Content-Type':
                                    'application/json',
                            },

                            body:
                                JSON.stringify(
                                    data
                                ),
                        }
                    );

                const result =
                    await response
                        .json();

                if (
                    !response.ok
                ) {
                    throw new Error(
                        result.error ||
                        'Save failed'
                    );
                }

                showToast(
                    'Changes applied successfully'
                );

            } catch (error) {

                showToast(
                    error.message
                );

            }

        }
    );


/*
============================================================
 LOGOUT
============================================================
*/

$('#logout')
    .addEventListener(
        'click',
        async () => {

            await fetch(
                '${CONFIG.adminPath}/api/logout',
                {
                    method:
                        'POST',

                    credentials:
                        'same-origin',
                }
            );

            location.reload();

        }
    );


/*
============================================================
 RESET
============================================================
*/

$('#reset')
    .addEventListener(
        'click',
        async () => {

            if (
                !confirm(
                    'Reset all control settings?'
                )
            ) {
                return;
            }

            await fetch(
                '${CONFIG.adminPath}/api/reset',
                {
                    method:
                        'POST',

                    credentials:
                        'same-origin',
                }
            );

            location.reload();

        }
    );

</script>

</body>

</html>`;
}


/*
============================================================
 HTML MODIFIER
============================================================
*/

function modifyHTML(
    html
) {

    let output =
        String(html);


    /*
    ========================================================
    TITLE
    ========================================================
    */

    if (
        SITE.title
    ) {

        output =
            output.replace(
                /<title[^>]*>[\s\S]*?<\/title>/i,

                `<title>${escapeHtml(
                    SITE.title
                )}</title>`
            );

    }


    /*
    ========================================================
    HTML LANGUAGE
    ========================================================
    */

    output =
        output.replace(
            /<html([^>]*)>/i,

            `<html$1 lang="${escapeHtml(
                SITE.language
            )}" dir="${escapeHtml(
                SITE.direction
            )}">`
        );


    /*
    ========================================================
    META DESCRIPTION
    ========================================================
    */

    if (
        SITE.description
    ) {

        if (
            /<meta[^>]+name=["']description["'][^>]*>/i
                .test(output)
        ) {

            output =
                output.replace(
                    /<meta[^>]+name=["']description["'][^>]*>/i,

                    `<meta name="description" content="${escapeHtml(
                        SITE.description
                    )}">`
                );

        } else {

            output =
                output.replace(
                    /<\/head>/i,

                    `<meta name="description" content="${escapeHtml(
                        SITE.description
                    )}">\n</head>`
                );

        }

    }


    /*
    ========================================================
    ROBOTS
    ========================================================
    */

    output =
        output.replace(
            /<meta[^>]+name=["']robots["'][^>]*>/i,

            `<meta name="robots" content="${escapeHtml(
                SITE.robots
            )}">`
        );


    /*
    ========================================================
    THEME COLOR
    ========================================================
    */

    output =
        output.replace(
            /<\/head>/i,

            `<meta name="theme-color" content="${escapeHtml(
                SITE.themeColor
            )}">\n</head>`
        );


    /*
    ========================================================
    FAVICON
    ========================================================
    */

    if (
        SITE.favicon
    ) {

        output =
            output.replace(
                /<\/head>/i,

                `<link rel="icon" href="${escapeHtml(
                    SITE.favicon
                )}">\n</head>`
            );

    }


    /*
    ========================================================
    MASTER CSS
    ========================================================
    */

    const background =
        SITE.backgroundEnabled &&
        SITE.backgroundUrl
            ? `
body::before {

    content:"";

    position:fixed;

    inset:0;

    z-index:-2;

    background-image:
        url("${SITE.backgroundUrl}");

    background-size:
        ${SITE.backgroundSize};

    background-position:
        ${SITE.backgroundPosition};

    background-repeat:
        ${SITE.backgroundRepeat};

    background-attachment:
        ${SITE.backgroundAttachment};
}

body::after {

    content:"";

    position:fixed;

    inset:0;

    z-index:-1;

    pointer-events:none;

    background:
        rgba(
            0,
            0,
            0,
            ${SITE.backgroundOverlay}
        );
}
`
            : '';


    const hideRules = `

${
    SITE.hideLogo
        ? `
img[src*="logo"],
.logo,
#logo,
[class*="logo"] {
    display:none!important;
}
`
        : ''
}

${
    SITE.hideSiteName
        ? `
.site-name,
#site-name,
.brand-name,
[class*="site-name"] {
    display:none!important;
}
`
        : ''
}

${
    SITE.hideFooter
        ? `
footer,
.footer,
#footer {
    display:none!important;
}
`
        : ''
}

${
    SITE.hideHomeButton
        ? `
.home,
#home,
.home-button,
[class*="home-button"] {
    display:none!important;
}
`
        : ''
}

${
    SITE.hideChat
        ? `
.chat,
#chat,
.chat-container,
[class*="chat"] {
    display:none!important;
}
`
        : ''
}

${
    SITE.hideVideo
        ? `
video,
.video,
.video-container {
    display:none!important;
}
`
        : ''
}
`;


    const masterCSS = `

<style
    id="rabbit-master-control"
>

:root {

    --rabbit-primary:
        ${safeColor(
            SITE.primaryColor,
            '#a3ff12'
        )};

    --rabbit-secondary:
        ${safeColor(
            SITE.secondaryColor,
            '#7cff00'
        )};

    --rabbit-background:
        ${safeColor(
            SITE.backgroundColor,
            '#090b0d'
        )};

    --rabbit-text:
        ${safeColor(
            SITE.textColor,
            '#ffffff'
        )};
}

html,
body {

    background:
        ${SITE.backgroundColor}!important;

    color:
        ${SITE.textColor};
}

body {

    font-family:
        ${SITE.fontFamily}!important;

    ${SITE.fontSize
        ? `font-size:${SITE.fontSize}!important;`
        : ''}
}

button,
.btn,
.button {

    --primary:
        ${SITE.primaryColor};

}

${background}

${hideRules}

${SITE.customCSS}

</style>
`;


    /*
    ========================================================
    HEAD
    ========================================================
    */

    output =
        output.replace(
            /<\/head>/i,

            masterCSS +
            '\n' +
            SITE.headHTML +
            '\n</head>'
        );


    /*
    ========================================================
    BODY START
    ========================================================
    */

    if (
        SITE.bodyStartHTML
    ) {

        output =
            output.replace(
                /<body([^>]*)>/i,

                `<body$1>
${SITE.bodyStartHTML}`
            );

    }


    /*
    ========================================================
    BODY END
    ========================================================
    */

    const customJS =
        SITE.customJS
            ? `
<script
    id="rabbit-master-control-js"
>
${SITE.customJS}
</script>
`
            : '';


    output =
        output.replace(
            /<\/body>/i,

            SITE.bodyEndHTML +
            customJS +
            '\n</body>'
        );


    return output;
}


/*
============================================================
 MIDDLEWARE
============================================================
*/

function middleware(
    req,
    res,
    next
) {


    /*
    ========================================================
    ADMIN PAGE
    ========================================================
    */

    if (
        req.path ===
        CONFIG.adminPath
    ) {

        if (
            !isAuthenticated(req)
        ) {

            return res
                .status(200)
                .send(
                    adminPage()
                );

        }

        return res
            .status(200)
            .send(
                adminPage()
            );

    }


    /*
    ========================================================
    LOGIN API
    ========================================================
    */

    if (
        req.path ===
        CONFIG.adminPath +
        '/api/login'
        &&
        req.method ===
        'POST'
    ) {

        return loginAPI(
            req,
            res
        );

    }


    /*
    ========================================================
    LOGOUT API
    ========================================================
    */

    if (
        req.path ===
        CONFIG.adminPath +
        '/api/logout'
        &&
        req.method ===
        'POST'
    ) {

        const cookies =
            getCookies(req);

        const token =
            cookies[
                ADMIN_COOKIE
            ];

        if (token) {
            sessions.delete(
                token
            );
        }

        res.setHeader(
            'Set-Cookie',
            `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
        );

        return res.json({
            success:true,
        });

    }


    /*
    ========================================================
    SAVE API
    ========================================================
    */

    if (
        req.path ===
        CONFIG.adminPath +
        '/api/save'
        &&
        req.method ===
        'POST'
    ) {

        if (
            !isAuthenticated(req)
        ) {

            return res
                .status(401)
                .json({
                    error:
                        'Authentication required',
                });

        }

        return saveAPI(
            req,
            res
        );

    }


    /*
    ========================================================
    RESET
    ========================================================
    */

    if (
        req.path ===
        CONFIG.adminPath +
        '/api/reset'
        &&
        req.method ===
        'POST'
    ) {

        if (
            !isAuthenticated(req)
        ) {

            return res
                .status(401)
                .json({
                    error:
                        'Authentication required',
                });

        }

        SITE = {
            ...DEFAULTS,
        };

        return res.json({
            success:true,
        });

    }


    /*
    ========================================================
    HTML INJECTION
    ========================================================
    */

    if (
        req.method ===
        'GET'
        &&
        isHTMLRequest(req)
    ) {

        return interceptHTML(
            req,
            res,
            next
        );

    }


    next();
}


/*
============================================================
 LOGIN API
============================================================
*/

function loginAPI(
    req,
    res
) {

    let body =
        req.body;

    if (
        typeof body !==
        'object'
    ) {

        body = {};

    }

    const username =
        safeString(
            body.username,
            200
        );

    const password =
        safeString(
            body.password,
            500
        );


    if (
        !verifyLogin(
            username,
            password
        )
    ) {

        return res
            .status(401)
            .json({
                error:
                    'Invalid administrator credentials.',
            });

    }


    const token =
        createSession();


    res.setHeader(
        'Set-Cookie',
        `${ADMIN_COOKIE}=${encodeURIComponent(
            token
        )}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`
    );


    return res.json({
        success:true,
    });

}


/*
============================================================
 SAVE API
============================================================
*/

function saveAPI(
    req,
    res
) {

    const input =
        req.body || {};


    Object.keys(
        DEFAULTS
    )
    .forEach(
        key => {

            if (
                Object.prototype
                    .hasOwnProperty
                    .call(
                        input,
                        key
                    )
            ) {

                const value =
                    input[key];


                if (
                    typeof
                    DEFAULTS[key] ===
                    'boolean'
                ) {

                    SITE[key] =
                        Boolean(
                            value
                        );

                } else {

                    SITE[key] =
                        safeString(
                            value,
                            100000
                        );

                }

            }

        }
    );


    SITE.primaryColor =
        safeColor(
            SITE.primaryColor,
            DEFAULTS.primaryColor
        );

    SITE.secondaryColor =
        safeColor(
            SITE.secondaryColor,
            DEFAULTS.secondaryColor
        );

    SITE.backgroundColor =
        safeColor(
            SITE.backgroundColor,
            DEFAULTS.backgroundColor
        );

    SITE.textColor =
        safeColor(
            SITE.textColor,
            DEFAULTS.textColor
        );


    return res.json({
        success:true,
    });

}


/*
============================================================
 DETECT HTML
============================================================
*/

function isHTMLRequest(
    req
) {

    const pathname =
        req.path || '';


    if (
        pathname ===
        CONFIG.adminPath
    ) {
        return false;
    }


    if (
        pathname.startsWith(
            CONFIG.adminPath +
            '/'
        )
    ) {
        return false;
    }


    if (
        pathname.startsWith(
            '/api/'
        )
    ) {
        return false;
    }


    if (
        /\.(css|js|png|jpg|jpeg|gif|webp|svg|ico|webm|mp4|mp3|wav|woff|woff2|ttf|json)$/i
            .test(
                pathname
            )
    ) {
        return false;
    }


    return true;
}


/*
============================================================
 HTML INTERCEPTOR
============================================================
*/

function interceptHTML(
    req,
    res,
    next
) {

    let chunks = [];

    const originalWrite =
        res.write.bind(res);

    const originalEnd =
        res.end.bind(res);


    res.write =
        function(
            chunk,
            encoding
        ) {

            if (
                chunk
            ) {

                chunks.push(
                    Buffer.isBuffer(
                        chunk
                    )
                        ? chunk
                        : Buffer.from(
                            chunk,
                            encoding
                        )
                );

            }

            return true;
        };


    res.end =
        function(
            chunk,
            encoding
        ) {

            if (
                chunk
            ) {

                chunks.push(
                    Buffer.isBuffer(
                        chunk
                    )
                        ? chunk
                        : Buffer.from(
                            chunk,
                            encoding
                        )
                );

            }


            const buffer =
                Buffer.concat(
                    chunks
                );


            const content =
                buffer.toString(
                    'utf8'
                );


            /*
            فقط HTML
            */

            if (
                /<!doctype\s+html|<html[\s>]/i
                    .test(
                        content
                    )
            ) {

                const modified =
                    modifyHTML(
                        content
                    );

                res.setHeader(
                    'Content-Length',
                    Buffer.byteLength(
                        modified,
                        'utf8'
                    )
                );

                return originalEnd(
                    modified,
                    'utf8'
                );

            }


            return originalEnd(
                buffer
            );

        };


    next();

}


/*
============================================================
 EXPORT
============================================================
*/

module.exports =
    middleware;
