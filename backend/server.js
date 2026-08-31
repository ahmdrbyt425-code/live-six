'use strict';

/*
============================================================
 THE RABBIT IN THE HOLE
 MASTER ADMIN CONTROL
============================================================

 Default login:
 Username: admin
 Password: admin

 Optional environment variables:
 ADMIN_CONTROL_USERNAME
 ADMIN_CONTROL_PASSWORD
 ADMIN_CONTROL_SECRET

 This file does NOT require:
 - admin.html
 - admin.css
 - admin.js
 - settings.json
============================================================
*/

const crypto = require('crypto');


/*
============================================================
 CONFIGURATION
============================================================
*/

const CONFIG = {

    adminPath:
        '/rabbit-control',

    username:
        process.env.ADMIN_CONTROL_USERNAME ||
        'admin',

    password:
        process.env.ADMIN_CONTROL_PASSWORD ||
        'admin',

    secret:
        process.env.ADMIN_CONTROL_SECRET ||
        'rabbit-control-secret-change-this',

};


/*
============================================================
 DEFAULT SITE SETTINGS
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
    COLORS
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
    BACKGROUND
    */

    backgroundEnabled:
        true,

    backgroundType:
        'auto',

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
    TYPOGRAPHY
    */

    fontFamily:
        'Arial, Helvetica, sans-serif',

    fontSize:
        '',


    /*
    INTERFACE
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
    CUSTOM CODE
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
    META
    */

    robots:
        'index,follow',

    themeColor:
        '#090b0d',

};


/*
============================================================
 LIVE SITE CONFIGURATION
============================================================
*/

let SITE = {
    ...DEFAULTS,
};


/*
============================================================
 SESSION STORAGE
============================================================
*/

const ADMIN_COOKIE =
    'rabbit_control_session';


const sessions =
    new Map();


/*
============================================================
 UTILITY FUNCTIONS
============================================================
*/

function safeString(
    value,
    max = 100000
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


function escapeHtml(
    value
) {

    return String(
        value === undefined ||
        value === null
            ? ''
            : value
    )
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


function getCookies(
    req
) {

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

                try {

                    result[name] =
                        decodeURIComponent(
                            value
                        );

                } catch {

                    result[name] =
                        value;

                }

            }
        );

    return result;
}


/*
============================================================
 SAFE TIMING COMPARISON
============================================================
*/

function safeCompare(
    a,
    b
) {

    const A =
        Buffer.from(
            String(a)
        );

    const B =
        Buffer.from(
            String(b)
        );

    if (
        A.length !==
        B.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        A,
        B
    );
}


/*
============================================================
 LOGIN VERIFICATION
============================================================
*/

function verifyLogin(
    username,
    password
) {

    return (
        safeCompare(
            username,
            CONFIG.username
        ) &&
        safeCompare(
            password,
            CONFIG.password
        )
    );

}


/*
============================================================
 SESSION
============================================================
*/

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


function isAuthenticated(
    req
) {

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


/*
============================================================
 LOGIN PAGE
============================================================
*/

function loginPage() {

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

    width:100%;

    min-height:100%;

    background:#07090b;

    color:#fff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

body {

    min-height:100vh;

    display:flex;

    align-items:center;

    justify-content:center;

    padding:20px;
}

.card {

    width:100%;

    max-width:430px;

    padding:38px;

    border-radius:26px;

    background:
        rgba(18,22,26,.94);

    border:
        1px solid
        rgba(255,255,255,.08);

    box-shadow:
        0 30px 100px
        rgba(0,0,0,.55);
}

.logo {

    width:78px;

    height:78px;

    margin:
        0 auto 22px;

    border-radius:22px;

    display:flex;

    align-items:center;

    justify-content:center;

    font-size:40px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #72d800
        );

    box-shadow:
        0 15px 45px
        rgba(163,255,18,.2);
}

h1 {

    margin:0;

    text-align:center;

    font-size:27px;
}

p {

    margin:
        8px 0 28px;

    text-align:center;

    color:#858d98;
}

label {

    display:block;

    margin:
        0 0 8px;

    color:#aeb5bf;

    font-size:13px;
}

input {

    width:100%;

    height:52px;

    padding:
        0 15px;

    margin-bottom:17px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:14px;

    outline:none;

    background:#0b0e12;

    color:#fff;
}

input:focus {

    border-color:
        rgba(163,255,18,.6);

    box-shadow:
        0 0 0 4px
        rgba(163,255,18,.08);
}

button {

    width:100%;

    height:54px;

    border:0;

    border-radius:15px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #70d800
        );

    color:#071000;

    font-weight:800;

    cursor:pointer;
}

.error {

    display:none;

    margin-top:15px;

    padding:12px;

    border-radius:12px;

    background:
        rgba(255,60,80,.1);

    color:#ff8995;

    text-align:center;

    font-size:13px;
}

</style>

</head>

<body>

<div class="card">

    <div class="logo">
        🥕
    </div>

    <h1>
        Rabbit Control
    </h1>

    <p>
        Master Control Center
    </p>

    <form id="form">

        <label>
            Administrator
        </label>

        <input
            id="username"
            autocomplete="username"
            required
        >

        <label>
            Password
        </label>

        <input
            id="password"
            type="password"
            autocomplete="current-password"
            required
        >

        <button type="submit">
            Enter Control Center
        </button>

        <div
            id="error"
            class="error"
        ></div>

    </form>

</div>

<script>

document
    .getElementById('form')
    .addEventListener(
        'submit',
        async function(event) {

            event.preventDefault();

            const username =
                document
                    .getElementById(
                        'username'
                    )
                    .value;

            const password =
                document
                    .getElementById(
                        'password'
                    )
                    .value;

            const error =
                document
                    .getElementById(
                        'error'
                    );

            error.style.display =
                'none';

            try {

                const response =
                    await fetch(
                        '${CONFIG.adminPath}/api/login',
                        {
                            method:
                                'POST',

                            credentials:
                                'same-origin',

                            headers: {
                                'Content-Type':
                                    'application/json'
                            },

                            body:
                                JSON.stringify({
                                    username:
                                        username,

                                    password:
                                        password
                                })
                        }
                    );

                const data =
                    await response.json();

                if (
                    !response.ok
                ) {

                    throw new Error(
                        data.error ||
                        'Login failed'
                    );

                }

                window.location.href =
                    '${CONFIG.adminPath}';

            } catch (err) {

                error.textContent =
                    err.message;

                error.style.display =
                    'block';

            }

        }
    );

</script>

</body>

</html>`;
}


/*
============================================================
 ADMIN APPLICATION
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
        Arial,
        Helvetica,
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


/*
SIDEBAR
*/

.sidebar {

    position:fixed;

    left:0;

    top:0;

    bottom:0;

    width:250px;

    padding:20px;

    background:
        rgba(13,16,20,.96);

    border-right:
        1px solid
        rgba(255,255,255,.07);
}

.brand {

    display:flex;

    align-items:center;

    gap:12px;

    margin-bottom:25px;
}

.brand-icon {

    width:44px;

    height:44px;

    display:flex;

    align-items:center;

    justify-content:center;

    border-radius:13px;

    background:
        linear-gradient(
            135deg,
            #b5ff38,
            #70d800
        );

    color:#071000;

    font-size:23px;
}

.brand strong {

    display:block;

    font-size:15px;
}

.brand small {

    color:#737b86;

    font-size:11px;
}

.nav {

    display:flex;

    flex-direction:column;

    gap:6px;
}

.nav button {

    width:100%;

    min-height:46px;

    padding:
        0 13px;

    border:0;

    border-radius:13px;

    background:transparent;

    color:#8f97a2;

    text-align:left;
}

.nav button:hover {

    background:
        rgba(255,255,255,.05);

    color:#fff;
}

.nav button.active {

    color:#b9ff55;

    background:
        rgba(163,255,18,.09);

    box-shadow:
        inset 3px 0 0
        #a3ff12;
}

.logout {

    position:absolute;

    left:20px;

    right:20px;

    bottom:20px;

    height:45px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:13px;

    background:#101318;

    color:#999fa8;
}


/*
CONTENT
*/

.content {

    margin-left:250px;

    padding:28px;

    min-height:100vh;
}

.topbar {

    display:flex;

    align-items:center;

    justify-content:space-between;

    margin-bottom:25px;
}

.topbar h1 {

    margin:0;

    font-size:27px;
}

.topbar p {

    margin:6px 0 0;

    color:#737b86;

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
            #70d800
        );

    color:#071000;

    font-weight:800;
}


/*
SECTIONS
*/

.section {

    display:none;
}

.section.active {

    display:block;
}


/*
DASHBOARD
*/

.hero {

    padding:30px;

    border-radius:23px;

    margin-bottom:18px;

    background:
        radial-gradient(
            circle at 90% 20%,
            rgba(163,255,18,.1),
            transparent 35%
        ),
        linear-gradient(
            135deg,
            #13171c,
            #0d1014
        );

    border:
        1px solid
        rgba(255,255,255,.07);
}

.hero h2 {

    margin:0 0 8px;

    font-size:23px;
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

    border-radius:19px;

    background:#111419;

    border:
        1px solid
        rgba(255,255,255,.07);
}

.stat strong {

    display:block;

    margin-top:10px;

    font-size:18px;
}

.stat span {

    display:block;

    margin-top:5px;

    color:#737b86;

    font-size:12px;
}


/*
CARDS
*/

.card {

    max-width:1050px;

    padding:24px;

    margin-bottom:18px;

    border-radius:21px;

    background:#111419;

    border:
        1px solid
        rgba(255,255,255,.07);
}

.card h2 {

    margin:
        0 0 6px;

    font-size:18px;
}

.sub {

    margin:
        0 0 22px;

    color:#737b86;

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

    color:#adb4bd;

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
        monospace;

    font-size:12px;
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

.color {

    display:flex;

    gap:8px;
}

.color input[type=color] {

    width:58px;

    padding:3px;

    cursor:pointer;
}

.toast {

    position:fixed;

    right:22px;

    bottom:22px;

    padding:
        13px 17px;

    border-radius:13px;

    background:
        rgba(18,23,19,.96);

    border:
        1px solid
        rgba(163,255,18,.25);

    color:#b9ff55;

    opacity:0;

    transform:
        translateY(15px);

    pointer-events:none;

    transition:.25s;
}

.toast.show {

    opacity:1;

    transform:
        translateY(0);
}


@media(max-width:800px) {

    .sidebar {

        width:70px;

        padding:
            15px 10px;
    }

    .brand {

        justify-content:center;
    }

    .brand > div:last-child {

        display:none;
    }

    .nav button {

        text-align:center;

        padding:0;
    }

    .nav button span {

        display:none;
    }

    .logout {

        left:10px;

        right:10px;
    }

    .logout span {

        display:none;
    }

    .content {

        margin-left:70px;

        padding:17px;
    }

}

</style>

</head>

<body>

<aside class="sidebar">

    <div class="brand">

        <div class="brand-icon">
            🥕
        </div>

        <div>

            <strong>
                Rabbit Control
            </strong>

            <small>
                Master Panel
            </small>

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
            &lt;/&gt;
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


    <button
        class="logout"
        id="logout"
    >
        🚪
        <span>
            Logout
        </span>
    </button>

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


<section
    id="dashboard"
    class="section active"
>

    <div class="hero">

        <h2>
            Master Control Center
        </h2>

        <p>
            Control your website from one place.
        </p>

    </div>


    <div class="grid">

        <div class="stat">

            <div>
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

            <div>
                🖼️
            </div>

            <strong>
                Background
            </strong>

            <span>
                Images and videos
            </span>

        </div>

        <div class="stat">

            <div>
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

            <div>
                ⚡
            </div>

            <strong>
                Custom Code
            </strong>

            <span>
                CSS, JS and HTML
            </span>

        </div>

    </div>

</section>


<section
    id="site"
    class="section"
>

<div class="card">

<h2>
    Website Identity
</h2>

<p class="sub">
    Change website identity.
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


<section
    id="background"
    class="section"
>

<div class="card">

<h2>
    Background Engine
</h2>

<p class="sub">
    Image, GIF, WebP, SVG, AVIF, MP4 or WebM.
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

<option value="auto">
    Auto
</option>

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
    placeholder="/backgrounds/background.webp"
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


<section
    id="appearance"
    class="section"
>

<div class="card">

<h2>
    Visual System
</h2>

<p class="sub">
    Colors and typography.
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


<section
    id="interface"
    class="section"
>

<div class="card">

<h2>
    Interface Control
</h2>

<p class="sub">
    Hide or show website elements.
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


<section
    id="code"
    class="section"
>

<div class="card">

<h2>
    Custom Code
</h2>

<p class="sub">
    Add your own CSS, JavaScript and HTML.
</p>


<div class="control">

<label>
    Custom CSS
</label>

<textarea
    data-key="customCSS"
    placeholder="/* Your CSS */"
></textarea>

</div>


<br>


<div class="control">

<label>
    Custom JavaScript
</label>

<textarea
    data-key="customJS"
    placeholder="// Your JavaScript"
></textarea>

</div>


<br>


<div class="control">

<label>
    HTML inside HEAD
</label>

<textarea
    data-key="headHTML"
></textarea>

</div>


<br>


<div class="control">

<label>
    HTML after BODY
</label>

<textarea
    data-key="bodyStartHTML"
></textarea>

</div>


<br>


<div class="control">

<label>
    HTML before BODY END
</label>

<textarea
    data-key="bodyEndHTML"
></textarea>

</div>

</div>

</section>


<section
    id="advanced"
    class="section"
>

<div class="card">

<h2>
    Advanced
</h2>

<p class="sub">
    Metadata and reset.
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
    Restore default settings.
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


<div
    class="toast"
    id="toast"
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

    toast.classList.add(
        'show'
    );

    setTimeout(
        () =>
            toast.classList.remove(
                'show'
            ),
        2500
    );

}


/*
============================================================
 NAVIGATION
============================================================
*/

$$('.nav button')
.forEach(
    button => {

        button.addEventListener(
            'click',
            function() {

                $$('.nav button')
                    .forEach(
                        item =>
                            item.classList.remove(
                                'active'
                            )
                    );

                this.classList.add(
                    'active'
                );

                $$('.section')
                    .forEach(
                        section =>
                            section.classList.remove(
                                'active'
                            )
                    );

                const page =
                    this.dataset.page;

                const section =
                    document.getElementById(
                        page
                    );

                if (section) {

                    section.classList.add(
                        'active'
                    );

                }

                $('#pageTitle')
                    .textContent =
                    this.innerText.trim();

            }
        );

    }
);


/*
============================================================
 LOAD FORM
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

        if (
            !picker ||
            !input
        ) {
            return;
        }

        if (
            /^#[0-9a-f]{6}$/i
                .test(
                    state[key]
                )
        ) {

            picker.value =
                state[key];

        } else {

            picker.value =
                '#ffffff';

        }

        picker.addEventListener(
            'input',
            function() {

                input.value =
                    picker.value;

            }
        );

        input.addEventListener(
            'input',
            function() {

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
    async function() {

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
                                'application/json'
                        },

                        body:
                            JSON.stringify(
                                data
                            )

                    }
                );

            const result =
                await response.json();

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
    async function() {

        await fetch(
            '${CONFIG.adminPath}/api/logout',
            {

                method:
                    'POST',

                credentials:
                    'same-origin'

            }
        );

        window.location.href =
            '${CONFIG.adminPath}';

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
    async function() {

        if (
            !confirm(
                'Reset all control settings?'
            )
        ) {
            return;
        }

        const response =
            await fetch(
                '${CONFIG.adminPath}/api/reset',
                {

                    method:
                        'POST',

                    credentials:
                        'same-origin'

                }
            );

        if (
            response.ok
        ) {

            location.reload();

        }

    }
);

</script>

</body>

</html>`;
}


/*
============================================================
 MODIFY HTML
============================================================
*/

function modifyHTML(
    html
) {

    let output =
        String(html);


    /*
    TITLE
    */

    if (
        SITE.title
    ) {

        output =
            output.replace(
                /<title[^>]*>[\s\S]*?<\/title>/i,

                '<title>' +
                escapeHtml(
                    SITE.title
                ) +
                '</title>'
            );

    }


    /*
    LANGUAGE / DIRECTION
    */

    output =
        output.replace(
            /<html([^>]*)>/i,

            '<html$1 lang="' +
            escapeHtml(
                SITE.language
            ) +
            '" dir="' +
            escapeHtml(
                SITE.direction
            ) +
            '">'
        );


    /*
    DESCRIPTION
    */

    if (
        SITE.description
    ) {

        const meta =
            '<meta name="description" content="' +
            escapeHtml(
                SITE.description
            ) +
            '">';

        if (
            /<meta[^>]+name=["']description["'][^>]*>/i
                .test(output)
        ) {

            output =
                output.replace(
                    /<meta[^>]+name=["']description["'][^>]*>/i,
                    meta
                );

        } else {

            output =
                output.replace(
                    /<\/head>/i,
                    meta +
                    '\n</head>'
                );

        }

    }


    /*
    ROBOTS
    */

    const robots =
        '<meta name="robots" content="' +
        escapeHtml(
            SITE.robots
        ) +
        '">';

    if (
        /<meta[^>]+name=["']robots["'][^>]*>/i
            .test(output)
    ) {

        output =
            output.replace(
                /<meta[^>]+name=["']robots["'][^>]*>/i,
                robots
            );

    } else {

        output =
            output.replace(
                /<\/head>/i,
                robots +
                '\n</head>'
            );

    }


    /*
    THEME COLOR
    */

    output =
        output.replace(
            /<\/head>/i,

            '<meta name="theme-color" content="' +
            escapeHtml(
                SITE.themeColor
            ) +
            '">' +
            '\n</head>'
        );


    /*
    FAVICON
    */

    if (
        SITE.favicon
    ) {

        output =
            output.replace(
                /<\/head>/i,

                '<link rel="icon" href="' +
                escapeHtml(
                    SITE.favicon
                ) +
                '">' +
                '\n</head>'
            );

    }


    /*
    BACKGROUND
    */

    let backgroundCSS =
        '';

    if (
        SITE.backgroundEnabled &&
        SITE.backgroundUrl &&
        SITE.backgroundType !==
            'none'
    ) {

        const url =
            String(
                SITE.backgroundUrl
            )
            .replace(
                /"/g,
                '\\"'
            );


        const type =
            String(
                SITE.backgroundType
            )
            .toLowerCase();


        const isVideo =
            type === 'video' ||
            type === 'webm' ||
            /\.(mp4|webm|ogv|ogg|m4v|mov)(\?.*)?$/i
                .test(
                    url
                );


        if (!isVideo) {

            backgroundCSS = `

#rabbit-background {

    position:fixed;

    inset:0;

    z-index:-10;

    pointer-events:none;

    background-image:
        url("${url}");

    background-size:
        ${safeString(
            SITE.backgroundSize,
            100
        )};

    background-position:
        ${safeString(
            SITE.backgroundPosition,
            100
        )};

    background-repeat:
        ${safeString(
            SITE.backgroundRepeat,
            100
        )};

    background-attachment:
        ${safeString(
            SITE.backgroundAttachment,
            100
        )};
}

#rabbit-background-overlay {

    position:fixed;

    inset:0;

    z-index:-9;

    pointer-events:none;

    background:
        rgba(
            0,
            0,
            0,
            ${Math.max(
                0,
                Math.min(
                    1,
                    Number(
                        SITE.backgroundOverlay
                    ) || 0
                )
            )}
        );
}

`;

        }

    }


    /*
    VIDEO BACKGROUND
    */

    const videoType =
        String(
            SITE.backgroundType
        )
        .toLowerCase();

    const videoUrl =
        String(
            SITE.backgroundUrl ||
            ''
        );


    const videoBackground =
        SITE.backgroundEnabled &&
        videoUrl &&
        (
            videoType === 'video' ||
            videoType === 'webm' ||
            /\.(mp4|webm|ogv|ogg|m4v|mov)(\?.*)?$/i
                .test(
                    videoUrl
                )
        )
        ? `

<video
    id="rabbit-background-video"
    autoplay
    muted
    loop
    playsinline
>

<source
    src="${escapeHtml(
        videoUrl
    )}"
>

</video>

<div
    id="rabbit-background-video-overlay"
></div>

`
        : '';


    /*
    HIDE RULES
    */

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
video:not(#rabbit-background-video),
.video,
.video-container {
    display:none!important;
}
`
        : ''
}

`;


    /*
    MASTER CSS
    */

    const masterCSS = `

<style id="rabbit-master-control">

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
        ${safeColor(
            SITE.backgroundColor,
            '#090b0d'
        )}!important;

    color:
        ${safeColor(
            SITE.textColor,
            '#ffffff'
        )};
}

body {

    font-family:
        ${safeString(
            SITE.fontFamily,
            500
        )}!important;

    ${
        SITE.fontSize
            ? 'font-size:' +
              safeString(
                  SITE.fontSize,
                  100
              ) +
              '!important;'
            : ''
    }

}

${backgroundCSS}

#rabbit-background-video {

    position:fixed;

    inset:0;

    width:100%;

    height:100%;

    z-index:-10;

    object-fit:
        ${safeString(
            SITE.backgroundSize,
            100
        )};

    object-position:
        ${safeString(
            SITE.backgroundPosition,
            100
        )};

    pointer-events:none;
}

#rabbit-background-video-overlay {

    position:fixed;

    inset:0;

    z-index:-9;

    background:
        rgba(
            0,
            0,
            0,
            ${Math.max(
                0,
                Math.min(
                    1,
                    Number(
                        SITE.backgroundOverlay
                    ) || 0
                )
            )}
        );

    pointer-events:none;
}

${hideRules}

${safeString(
    SITE.customCSS,
    100000
)}

</style>

`;


    /*
    INSERT BACKGROUND
    */

    if (
        backgroundCSS
    ) {

        output =
            output.replace(
                /<body([^>]*)>/i,

                '<body$1>' +
                '<div id="rabbit-background"></div>' +
                '<div id="rabbit-background-overlay"></div>'
            );

    }


    if (
        videoBackground
    ) {

        output =
            output.replace(
                /<body([^>]*)>/i,

                '<body$1>' +
                videoBackground
            );

    }


    /*
    INSERT HEAD
    */

    output =
        output.replace(
            /<\/head>/i,

            masterCSS +
            '\n' +
            safeString(
                SITE.headHTML,
                100000
            ) +
            '\n</head>'
        );


    /*
    BODY START
    */

    if (
        SITE.bodyStartHTML
    ) {

        output =
            output.replace(
                /<body([^>]*)>/i,

                '<body$1>\n' +
                safeString(
                    SITE.bodyStartHTML,
                    100000
                )
            );

    }


    /*
    BODY END
    */

    const customJS =
        SITE.customJS
            ? `

<script id="rabbit-master-control-js">

${safeString(
    SITE.customJS,
    100000
)}

</script>

`
            : '';


    output =
        output.replace(
            /<\/body>/i,

            safeString(
                SITE.bodyEndHTML,
                100000
            ) +
            customJS +
            '\n</body>'
        );


    return output;
}


/*
============================================================
 DETECT HTML REQUEST
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
        /\.(css|js|mjs|png|jpg|jpeg|gif|webp|avif|svg|ico|webm|mp4|m4v|mov|ogv|ogg|mp3|wav|woff|woff2|ttf|json|map)$/i
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

    const chunks =
        [];

    const originalWrite =
        res.write.bind(
            res
        );

    const originalEnd =
        res.end.bind(
            res
        );


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
 MAIN MIDDLEWARE
============================================================
*/

function middleware(
    req,
    res,
    next
) {

    /*
    ADMIN PAGE
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
                    loginPage()
                );

        }

        return res
            .status(200)
            .send(
                adminPage()
            );

    }


    /*
    LOGIN
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
    LOGOUT
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
            getCookies(
                req
            );

        const token =
            cookies[
                ADMIN_COOKIE
            ];

        if (
            token
        ) {

            sessions.delete(
                token
            );

        }


        res.setHeader(
            'Set-Cookie',

            ADMIN_COOKIE +
            '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
        );


        return res.json({
            success:true
        });

    }


    /*
    SAVE
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
                        'Authentication required'
                });

        }

        return saveAPI(
            req,
            res
        );

    }


    /*
    RESET
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
                        'Authentication required'
                });

        }


        SITE = {
            ...DEFAULTS
        };


        return res.json({
            success:true
        });

    }


    /*
    HTML
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

    const body =
        req.body &&
        typeof req.body ===
            'object'
        ? req.body
        : {};


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
                    'Invalid administrator credentials.'
            });

    }


    const token =
        createSession();


    res.setHeader(
        'Set-Cookie',

        ADMIN_COOKIE +
        '=' +
        encodeURIComponent(
            token
        ) +
        '; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400'
    );


    return res.json({
        success:true
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
        req.body &&
        typeof req.body ===
            'object'
        ? req.body
        : {};


    Object.keys(
        DEFAULTS
    )
    .forEach(
        key => {

            if (
                !Object.prototype
                    .hasOwnProperty
                    .call(
                        input,
                        key
                    )
            ) {

                return;

            }


            const value =
                input[key];


            if (
                typeof DEFAULTS[key] ===
                'boolean'
            ) {

                SITE[key] =
                    value === true ||
                    value === 'true';

            } else {

                SITE[key] =
                    safeString(
                        value,
                        100000
                    );

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
        success:true
    });

}


/*
============================================================
 EXPORT
============================================================
*/

module.exports =
    middleware;
