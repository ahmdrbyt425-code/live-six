'use strict';

/* ============================================================
   HOME PAGE
   ============================================================ */

console.log('Location', window.location);
console.log('LocalStorage', window.localStorage);

/* ============================================================
   ROOM / USER
   ============================================================ */

const roomId =
    filterXSS(
        new URLSearchParams(
            window.location.search
        ).get('room') || ''
    );

const roomIdIn =
    document.getElementById(
        'roomIdInput'
    );

const userNameIn =
    document.getElementById(
        'userNameInput'
    );

const randomRoomBtn =
    document.getElementById(
        'randomRoomBtn'
    );

const randomUserBtn =
    document.getElementById(
        'randomUserBtn'
    );

const initAudioBtn =
    document.getElementById(
        'initAudioBtn'
    );

const initVideoBtn =
    document.getElementById(
        'initVideoBtn'
    );

const joinBtn =
    document.getElementById(
        'joinBtn'
    );

const supportBtn =
    document.getElementById(
        'supportBtn'
    );

const LS =
    new LocalStorage();

const localStorageConfig =
    LS.getConfig();

/* ============================================================
   MEDIA ICONS
   ============================================================ */

const mediaIcons = {
    audioOn:
        'fas fa-microphone',

    audioOff:
        'fas fa-microphone-slash',

    videoOn:
        'fas fa-video',

    videoOff:
        'fas fa-video-slash',
};

/* ============================================================
   CONFIG
   ============================================================ */

const config = {
    support: true,
};

/* ============================================================
   GLOBAL CHAT ELEMENTS
   ============================================================ */

const publicChatButton =
    document.getElementById(
        'publicChatButton'
    );

const publicChat =
    document.getElementById(
        'publicChat'
    );

const publicChatMessages =
    document.getElementById(
        'publicChatMessages'
    );

const publicChatInput =
    document.getElementById(
        'publicChatInput'
    );

const publicChatSend =
    document.getElementById(
        'publicChatSend'
    );

const publicChatOnline =
    document.getElementById(
        'publicChatOnline'
    );

const publicChatBadge =
    document.getElementById(
        'publicChatBadge'
    );

const publicChatMinimize =
    document.getElementById(
        'publicChatMinimize'
    );

const publicChatExpand =
    document.getElementById(
        'publicChatExpand'
    );

const publicChatClose =
    document.getElementById(
        'publicChatClose'
    );

/* ============================================================
   SOCKET.IO
   ============================================================ */

/*
 * home.html يقوم بتحميل:
 *
 * /socket.io/socket.io.js
 *
 * لذلك io() متاح هنا.
 */

let globalChatSocket = null;

/*
 * منع تكرار الرسائل عند إعادة التهيئة.
 */
let globalChatInitialized = false;

/*
 * عدد الرسائل الجديدة أثناء إغلاق الشات.
 */
let unreadGlobalChatMessages = 0;

/* ============================================================
   DOM READY
   ============================================================ */

document.addEventListener(
    'DOMContentLoaded',
    function () {
        initHome();
        initGlobalChat();
    }
);

/* ============================================================
   HOME INIT
   ============================================================ */

async function initHome() {

    /*
     * Room
     */
    if (roomIdIn) {
        roomIdIn.value =
            roomId
                ? roomId
                : filterXSS(
                      window.localStorage.room ||
                          ''
                  );
    }

    /*
     * User name
     */
    const getUserName =
        async () => {

            try {

                const response =
                    await axios.get(
                        '/profile',
                        {
                            timeout: 5000,
                        }
                    );

                const profile =
                    response.data;

                if (
                    profile &&
                    profile.name
                ) {

                    console.log(
                        'AXIOS GET OIDC Profile retrieved successfully',
                        profile
                    );

                    window.localStorage.name =
                        profile.name;
                }

            } catch (error) {

                console.error(
                    'AXIOS OIDC Error fetching profile',
                    error.message ||
                        error
                );
            }

            return (
                window.localStorage.name ||
                ''
            );
        };

    if (userNameIn) {

        userNameIn.value =
            filterXSS(
                await getUserName()
            );
    }

    /* ========================================================
       RANDOM ROOM
       ======================================================== */

    if (randomRoomBtn) {

        randomRoomBtn.onclick =
            () => {

                const finalValue =
                    (
                        [
                            1e7,
                        ] +
                        -1e3 +
                        -4e3 +
                        -8e3 +
                        -1e11
                    ).replace(
                        /[018]/g,
                        c =>
                            (
                                c ^
                                (
                                    crypto.getRandomValues(
                                        new Uint8Array(
                                            1
                                        )
                                    )[0] &
                                    (
                                        15 >>
                                        (
                                            c /
                                            4
                                        )
                                    )
                                )
                            ).toString(
                                16
                            )
                    );

                shuffleText(
                    roomIdIn,
                    finalValue
                );
            };
    }

    /* ========================================================
       RANDOM USER
       ======================================================== */

    if (randomUserBtn) {

        randomUserBtn.onclick =
            () => {

                const finalValue =
                    'User_' +
                    Math.floor(
                        Math.random() *
                            1000000
                    );

                shuffleText(
                    userNameIn,
                    finalValue
                );
            };
    }

    /* ========================================================
       MEDIA
       ======================================================== */

    if (
        initAudioBtn &&
        localStorageConfig &&
        localStorageConfig.audio &&
        localStorageConfig.audio.init
    ) {

        updateMediaToggle(
            initAudioBtn,
            'audio',
            localStorageConfig.audio
                .init.active
        );
    }

    if (
        initVideoBtn &&
        localStorageConfig &&
        localStorageConfig.video &&
        localStorageConfig.video.init
    ) {

        updateMediaToggle(
            initVideoBtn,
            'video',
            localStorageConfig.video
                .init.active
        );
    }

    if (initAudioBtn) {

        initAudioBtn.onclick =
            () => {

                const active =
                    !localStorageConfig
                        .audio
                        .init
                        .active;

                localStorageConfig
                    .audio
                    .init
                    .active =
                    active;

                LS.setConfig(
                    localStorageConfig
                );

                updateMediaToggle(
                    initAudioBtn,
                    'audio',
                    active
                );
            };
    }

    if (initVideoBtn) {

        initVideoBtn.onclick =
            () => {

                const active =
                    !localStorageConfig
                        .video
                        .init
                        .active;

                localStorageConfig
                    .video
                    .init
                    .active =
                    active;

                LS.setConfig(
                    localStorageConfig
                );

                updateMediaToggle(
                    initVideoBtn,
                    'video',
                    active
                );
            };
    }

    /* ========================================================
       JOIN
       ======================================================== */

    if (joinBtn) {

        joinBtn.onclick =
            event => {

                /*
                 * مهم:
                 * الزر موجود داخل <form> وهو submit.
                 * نمنع إعادة تحميل الصفحة.
                 */
                if (event) {
                    event.preventDefault();
                }

                if (
                    roomIdIn &&
                    userNameIn &&
                    roomIdIn.value.trim() &&
                    userNameIn.value.trim()
                ) {

                    const room =
                        roomIdIn.value.trim();

                    const name =
                        userNameIn.value.trim();

                    const joinURL =
                        window.location.origin +
                        '/join?room=' +
                        encodeURIComponent(
                            room
                        ) +
                        '&name=' +
                        encodeURIComponent(
                            name
                        );

                    window.history.pushState(
                        {
                            url: joinURL,
                        },
                        room,
                        joinURL
                    );

                    window.localStorage.room =
                        room;

                    window.localStorage.name =
                        name;

                    /*
                     * إذا كانت الصفحة تعتمد على
                     * pushState فقط، اترك السلوك
                     * كما هو في المشروع.
                     */
                }
            };
    }

    /* ========================================================
       SUPPORT
       ======================================================== */

    if (supportBtn) {

        supportBtn.onclick =
            () => {

                window.open(
                    'https://docs.mirotalk.com/about',
                    '_blank'
                );
            };
    }

    if (
        !config.support &&
        supportBtn
    ) {

        elementDisplay(
            supportBtn,
            false
        );
    }
}

/* ============================================================
   GLOBAL PUBLIC CHAT
   ============================================================ */

function initGlobalChat() {

    /*
     * منع تشغيل الشات أكثر من مرة.
     */
    if (globalChatInitialized) {
        return;
    }

    globalChatInitialized = true;

    /*
     * نتأكد أن عناصر الشات موجودة.
     */
    if (
        !publicChatButton ||
        !publicChat ||
        !publicChatMessages ||
        !publicChatInput ||
        !publicChatSend
    ) {

        console.warn(
            '[GLOBAL CHAT] Chat elements not found.'
        );

        return;
    }

    /*
     * نتأكد أن Socket.IO موجود.
     */
    if (
        typeof io !==
        'function'
    ) {

        console.error(
            '[GLOBAL CHAT] Socket.IO is not loaded.'
        );

        addSystemMessage(
            'تعذر الاتصال بخدمة الدردشة.'
        );

        return;
    }

    /* ========================================================
       CONNECT SOCKET
       ======================================================== */

    try {

        /*
         * الاتصال بنفس السيرفر الذي جاءت منه الصفحة.
         *
         * لا نضع URL ثابت.
         *
         * هذا مهم جدًا عند استخدام Render
         * أو HTTPS.
         */
        globalChatSocket =
            io(
                window.location.origin,
                {
                    transports: [
                        'websocket',
                        'polling',
                    ],
                    reconnection: true,
                    reconnectionAttempts:
                        Infinity,
                    reconnectionDelay: 1000,
                    reconnectionDelayMax:
                        5000,
                }
            );

    } catch (error) {

        console.error(
            '[GLOBAL CHAT] Socket initialization error:',
            error
        );

        addSystemMessage(
            'تعذر تشغيل الدردشة العامة.'
        );

        return;
    }

    /* ========================================================
       SOCKET CONNECT
       ======================================================== */

    globalChatSocket.on(
        'connect',
        () => {

            console.log(
                '[GLOBAL CHAT] Connected:',
                globalChatSocket.id
            );

            setChatOnlineStatus(
                publicChatOnline
                    ? publicChatOnline.textContent
                    : ''
            );

            /*
             * لا نعرض رسالة اتصال في كل إعادة اتصال
             * حتى لا تمتلئ الدردشة برسائل النظام.
             */
        }
    );

    /* ========================================================
       SOCKET DISCONNECT
       ======================================================== */

    globalChatSocket.on(
        'disconnect',
        reason => {

            console.warn(
                '[GLOBAL CHAT] Disconnected:',
                reason
            );

            if (publicChatOnline) {

                publicChatOnline.textContent =
                    'غير متصل';
            }
        }
    );

    /* ========================================================
       SOCKET CONNECT ERROR
       ======================================================== */

    globalChatSocket.on(
        'connect_error',
        error => {

            console.error(
                '[GLOBAL CHAT] Connection error:',
                error
            );

            if (publicChatOnline) {

                publicChatOnline.textContent =
                    'جاري الاتصال...';
            }
        }
    );

    /* ========================================================
       CHAT HISTORY
       ======================================================== */

    globalChatSocket.on(
        'globalChatHistory',
        messages => {

            console.log(
                '[GLOBAL CHAT] History received:',
                messages
            );

            renderGlobalChatHistory(
                messages
            );
        }
    );

    /* ========================================================
       NEW CHAT MESSAGE
       ======================================================== */

    globalChatSocket.on(
        'globalChatMessage',
        message => {

            console.log(
                '[GLOBAL CHAT] Message received:',
                message
            );

            appendGlobalChatMessage(
                message
            );

            /*
             * إذا كانت الدردشة مغلقة،
             * نزيد العداد.
             */
            if (
                publicChat.classList.contains(
                    'hidden'
                )
            ) {

                unreadGlobalChatMessages++;

                updateChatBadge();
            }
        }
    );

    /* ========================================================
       SYSTEM MESSAGE
       ======================================================== */

    globalChatSocket.on(
        'globalChatSystem',
        data => {

            console.log(
                '[GLOBAL CHAT] System:',
                data
            );

            if (
                data &&
                data.message
            ) {

                addSystemMessage(
                    data.message
                );
            }
        }
    );

    /* ========================================================
       ONLINE USERS
       ======================================================== */

    globalChatSocket.on(
        'globalChatOnline',
        count => {

            console.log(
                '[GLOBAL CHAT] Online:',
                count
            );

            updateOnlineCount(
                count
            );
        }
    );

    /* ========================================================
       OPEN CHAT
       ======================================================== */

    publicChatButton.onclick =
        () => {

            openPublicChat();

            /*
             * عند فتح الشات نعتبر
             * الرسائل الجديدة مقروءة.
             */
            unreadGlobalChatMessages =
                0;

            updateChatBadge();

            setTimeout(
                () => {

                    publicChatInput.focus();

                },
                100
            );
        };

    /* ========================================================
       CLOSE CHAT
       ======================================================== */

    if (publicChatClose) {

        publicChatClose.onclick =
            () => {

                closePublicChat();
            };
    }

    /* ========================================================
       MINIMIZE
       ======================================================== */

    if (publicChatMinimize) {

        publicChatMinimize.onclick =
            () => {

                publicChat.classList.toggle(
                    'minimized'
                );
            };
    }

    /* ========================================================
       EXPAND
       ======================================================== */

    if (publicChatExpand) {

        publicChatExpand.onclick =
            () => {

                publicChat.classList.toggle(
                    'expanded'
                );

                /*
                 * تغيير الأيقونة.
                 */
                const icon =
                    publicChatExpand.querySelector(
                        'i'
                    );

                if (icon) {

                    const expanded =
                        publicChat.classList.contains(
                            'expanded'
                        );

                    icon.className =
                        expanded
                            ? 'fas fa-compress'
                            : 'fas fa-expand';
                }
            };
    }

    /* ========================================================
       SEND BUTTON
       ======================================================== */

    publicChatSend.onclick =
        () => {

            sendGlobalChatMessage();
        };

    /* ========================================================
       ENTER TO SEND
       ======================================================== */

    publicChatInput.addEventListener(
        'keydown',
        event => {

            /*
             * Enter بدون Shift = إرسال.
             *
             * Shift + Enter = سطر جديد
             * رغم أن input لا يدعم السطر الجديد،
             * لذلك هنا نرسل مباشرة.
             */
            if (
                event.key ===
                    'Enter' &&
                !event.shiftKey
            ) {

                event.preventDefault();

                sendGlobalChatMessage();
            }
        }
    );

    /* ========================================================
       ESCAPE = CLOSE
       ======================================================== */

    document.addEventListener(
        'keydown',
        event => {

            if (
                event.key ===
                    'Escape' &&
                !publicChat.classList.contains(
                    'hidden'
                )
            ) {

                closePublicChat();
            }
        }
    );

    /*
     * تحديث أولي للعداد.
     */
    updateChatBadge();
}

/* ============================================================
   SEND GLOBAL CHAT MESSAGE
   ============================================================ */

function sendGlobalChatMessage() {

    if (
        !globalChatSocket
    ) {

        addSystemMessage(
            'الاتصال بالخادم غير متاح.'
        );

        return;
    }

    if (
        !globalChatSocket.connected
    ) {

        addSystemMessage(
            'جاري الاتصال بالخادم، حاول مرة أخرى.'
        );

        return;
    }

    const message =
        publicChatInput
            .value
            .trim();

    if (!message) {
        return;
    }

    /*
     * الحد الموجود في home.html هو 500.
     * والسيرفر يسمح حتى 500 افتراضيًا.
     */
    if (
        message.length >
        500
    ) {

        addSystemMessage(
            'الحد الأقصى للرسالة 500 حرف.'
        );

        return;
    }

    /*
     * اسم المستخدم الحالي.
     *
     * نأخذه من input أولًا،
     * ثم LocalStorage كاحتياط.
     */
    let name =
        userNameIn &&
        userNameIn.value
            ? userNameIn.value.trim()
            : '';

    if (!name) {

        name =
            window.localStorage.name ||
            '';
    }

    /*
     * إذا لم يكن هناك اسم،
     * نستخدم اسمًا تلقائيًا.
     */
    if (!name) {

        name =
            'User_' +
            Math.floor(
                Math.random() *
                    1000000
            );

        window.localStorage.name =
            name;

        if (userNameIn) {
            userNameIn.value =
                name;
        }
    }

    /*
     * تنظيف الاسم من HTML.
     */
    name =
        sanitizeClientText(
            name
        );

    /*
     * تنظيف الرسالة من HTML.
     *
     * السيرفر يقوم بالتنظيف أيضًا،
     * وهذا التنظيف هنا طبقة إضافية.
     */
    const safeMessage =
        sanitizeClientText(
            message
        );

    if (!safeMessage) {
        return;
    }

    console.log(
        '[GLOBAL CHAT] Sending:',
        {
            name,
            message:
                safeMessage,
        }
    );

    /*
     * هذا هو الحدث الذي ينتظره
     * backend/server.js:
     *
     * globalChatSend
     */
    globalChatSocket.emit(
        'globalChatSend',
        {
            name:
                name,

            message:
                safeMessage,
        }
    );

    /*
     * نمسح حقل الكتابة فورًا.
     *
     * الرسالة نفسها ستعود من السيرفر
     * عبر globalChatMessage.
     */
    publicChatInput.value = '';

    publicChatInput.focus();
}

/* ============================================================
   RENDER HISTORY
   ============================================================ */

function renderGlobalChatHistory(
    messages
) {

    if (!publicChatMessages) {
        return;
    }

    publicChatMessages.innerHTML =
        '';

    if (
        !Array.isArray(
            messages
        ) ||
        messages.length === 0
    ) {

        addSystemMessage(
            'لا توجد رسائل بعد. كن أول من يكتب!'
        );

        return;
    }

    messages.forEach(
        message => {

            appendGlobalChatMessage(
                message,
                false
            );
        }
    );

    scrollChatToBottom();
}

/* ============================================================
   APPEND CHAT MESSAGE
   ============================================================ */

function appendGlobalChatMessage(
    message,
    autoScroll = true
) {

    if (
        !publicChatMessages ||
        !message
    ) {
        return;
    }

    /*
     * منع عناصر غير صحيحة.
     */
    if (
        typeof message !==
            'object'
    ) {
        return;
    }

    const wrapper =
        document.createElement(
            'div'
        );

    wrapper.className =
        'public-chat-message';

    /*
     * تحديد رسائل المستخدم الحالي.
     */
    const currentName =
        sanitizeClientText(
            (
                userNameIn &&
                userNameIn.value
            ) ||
                window.localStorage.name ||
                ''
        );

    const messageName =
        sanitizeClientText(
            message.name ||
                'User'
        );

    if (
        currentName &&
        messageName ===
            currentName
    ) {

        wrapper.classList.add(
            'me'
        );
    }

    /* ========================================================
       NAME
       ======================================================== */

    const nameElement =
        document.createElement(
            'div'
        );

    nameElement.className =
        'public-chat-name';

    nameElement.textContent =
        messageName;

    wrapper.appendChild(
        nameElement
    );

    /* ========================================================
       MESSAGE
       ======================================================== */

    const textElement =
        document.createElement(
            'div'
        );

    textElement.className =
        'public-chat-text';

    textElement.textContent =
        sanitizeClientText(
            message.message ||
                ''
        );

    wrapper.appendChild(
        textElement
    );

    /* ========================================================
       TIME
       ======================================================== */

    const timeElement =
        document.createElement(
            'div'
        );

    timeElement.className =
        'public-chat-time';

    timeElement.textContent =
        formatChatTime(
            message.createdAt ||
                message.timestamp ||
                message.time
        );

    wrapper.appendChild(
        timeElement
    );

    publicChatMessages.appendChild(
        wrapper
    );

    if (autoScroll) {

        scrollChatToBottom();
    }
}

/* ============================================================
   SYSTEM MESSAGE
   ============================================================ */

function addSystemMessage(
    text
) {

    if (!publicChatMessages) {
        return;
    }

    const element =
        document.createElement(
            'div'
        );

    element.className =
        'public-chat-system';

    element.textContent =
        sanitizeClientText(
            text
        );

    publicChatMessages.appendChild(
        element
    );

    scrollChatToBottom();
}

/* ============================================================
   ONLINE COUNT
   ============================================================ */

function updateOnlineCount(
    count
) {

    if (!publicChatOnline) {
        return;
    }

    const online =
        Number(count);

    if (
        !Number.isFinite(
            online
        )
    ) {
        return;
    }

    publicChatOnline.textContent =
        online +
        ' متصل';
}

/* ============================================================
   CHAT BADGE
   ============================================================ */

function updateChatBadge() {

    if (!publicChatBadge) {
        return;
    }

    const count =
        Number(
            unreadGlobalChatMessages
        );

    if (
        !Number.isFinite(
            count
        ) ||
        count <= 0
    ) {

        publicChatBadge.textContent =
            '0';

        publicChatBadge.style.display =
            'none';

        return;
    }

    publicChatBadge.style.display =
        'flex';

    publicChatBadge.textContent =
        count > 99
            ? '99+'
            : String(count);
}

/* ============================================================
   OPEN CHAT
   ============================================================ */

function openPublicChat() {

    if (!publicChat) {
        return;
    }

    publicChat.classList.remove(
        'hidden'
    );

    /*
     * إزالة التصغير عند الفتح.
     */
    publicChat.classList.remove(
        'minimized'
    );

    unreadGlobalChatMessages =
        0;

    updateChatBadge();

    scrollChatToBottom();
}

/* ============================================================
   CLOSE CHAT
   ============================================================ */

function closePublicChat() {

    if (!publicChat) {
        return;
    }

    publicChat.classList.add(
        'hidden'
    );
}

/* ============================================================
   SCROLL
   ============================================================ */

function scrollChatToBottom() {

    if (!publicChatMessages) {
        return;
    }

    /*
     * requestAnimationFrame يجعل التمرير
     * بعد إضافة العنصر إلى DOM.
     */
    requestAnimationFrame(
        () => {

            publicChatMessages.scrollTop =
                publicChatMessages.scrollHeight;
        }
    );
}

/* ============================================================
   CHAT TIME
   ============================================================ */

function formatChatTime(
    value
) {

    if (!value) {
        return '';
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return '';
    }

    try {

        return date.toLocaleTimeString(
            'ar',
            {
                hour: '2-digit',
                minute: '2-digit',
            }
        );

    } catch (
        error
    ) {

        return date.toLocaleTimeString();
    }
}

/* ============================================================
   CLIENT TEXT SANITIZER
   ============================================================ */

function sanitizeClientText(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return '';
    }

    let text =
        String(value);

    /*
     * الحد الأقصى للنص في الواجهة.
     */
    text =
        text.substring(
            0,
            2000
        );

    /*
     * استخدام filterXSS إذا كانت مكتبة XSS
     * متاحة في الصفحة.
     */
    if (
        typeof filterXSS ===
        'function'
    ) {

        try {

            return filterXSS(
                text
            );

        } catch (
            error
        ) {

            console.warn(
                '[GLOBAL CHAT] XSS filter error:',
                error
            );
        }
    }

    /*
     * Fallback بسيط.
     */
    const element =
        document.createElement(
            'div'
        );

    element.textContent =
        text;

    return element.textContent;
}

/* ============================================================
   MEDIA TOGGLE
   ============================================================ */

function updateMediaToggle(
    btn,
    kind,
    active
) {

    if (!btn) {
        return;
    }

    const icon =
        btn.querySelector(
            'i'
        );

    if (icon) {

        icon.className =
            active
                ? mediaIcons[
                      kind +
                          'On'
                  ]
                : mediaIcons[
                      kind +
                          'Off'
                  ];
    }

    btn.classList.toggle(
        'off',
        !active
    );

    btn.setAttribute(
        'aria-pressed',
        String(active)
    );
}

/* ============================================================
   ELEMENT DISPLAY
   ============================================================ */

function elementDisplay(
    elem,
    display
) {

    if (!elem) {
        return;
    }

    elem.style.display =
        display
            ? 'block'
            : 'none';
}

/* ============================================================
   SHUFFLE TEXT
   ============================================================ */

function shuffleText(
    input,
    finalValue,
    duration = 600
) {

    if (!input) {
        return;
    }

    const chars =
        'abcdefghijklmnopqrstuvwxyz0123456789';

    const steps = 10;

    const interval =
        duration / steps;

    let step = 0;

    input.classList.add(
        'shuffle-active'
    );

    const timer =
        setInterval(
            () => {

                step++;

                const progress =
                    step /
                    steps;

                let display =
                    '';

                for (
                    let i = 0;
                    i <
                    finalValue.length;
                    i++
                ) {

                    if (
                        i <
                        finalValue.length *
                            progress
                    ) {

                        display +=
                            finalValue[
                                i
                            ];

                    } else {

                        display +=
                            chars[
                                Math.floor(
                                    Math.random() *
                                        chars.length
                                )
                            ];
                    }
                }

                input.value =
                    display;

                if (
                    step >=
                    steps
                ) {

                    clearInterval(
                        timer
                    );

                    input.value =
                        finalValue;

                    setTimeout(
                        () => {

                            input.classList.remove(
                                'shuffle-active'
                            );

                        },
                        300
                    );
                }

            },
            interval
        );
}
