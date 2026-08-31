'use strict';

/*
 * LIVE-SIX
 * Home page + Public Chat + Automatic Invite Join
 */

document.addEventListener('DOMContentLoaded', () => {
    initHome();
    initPublicChat();
});

/* =========================================================
   HOME
========================================================= */

async function initHome() {
    const roomIdIn = document.getElementById('roomIdInput');
    const userNameIn = document.getElementById('userNameInput');

    const randomRoomBtn = document.getElementById('randomRoomBtn');
    const randomUserBtn = document.getElementById('randomUserBtn');

    const initAudioBtn = document.getElementById('initAudioBtn');
    const initVideoBtn = document.getElementById('initVideoBtn');

    const joinBtn = document.getElementById('joinBtn');
    const joinForm = document.getElementById('joinForm');

    const supportBtn = document.getElementById('supportBtn');

    if (!roomIdIn || !userNameIn) {
        console.warn('[HOME] Required elements not found.');
        return;
    }

    /* ---------------------------------------------------------
       URL
    --------------------------------------------------------- */

    const params = new URLSearchParams(
        window.location.search
    );

    const inviteRoom = (
        params.get('room') || ''
    ).trim();

    const savedRoom =
        window.localStorage.getItem('room') || '';

    /* ---------------------------------------------------------
       LocalStorage config
    --------------------------------------------------------- */

    let storageConfig;

    try {
        const LS = new LocalStorage();

        storageConfig = LS.getConfig();
    } catch (error) {
        console.warn(
            '[HOME] LocalStorage config unavailable:',
            error
        );

        storageConfig = {
            audio: {
                init: {
                    active: true
                }
            },
            video: {
                init: {
                    active: true
                }
            }
        };
    }

    /* ---------------------------------------------------------
       Room
    --------------------------------------------------------- */

    roomIdIn.value =
        inviteRoom ||
        savedRoom ||
        '';

    /* ---------------------------------------------------------
       User name
    --------------------------------------------------------- */

    let userName =
        window.localStorage.getItem('name') || '';

    /*
     * Try profile first.
     */
    try {
        if (
            typeof axios !== 'undefined'
        ) {
            const response =
                await axios.get(
                    '/profile',
                    {
                        timeout: 5000
                    }
                );

            if (
                response &&
                response.data &&
                response.data.name
            ) {
                userName =
                    String(
                        response.data.name
                    ).trim();

                window.localStorage.setItem(
                    'name',
                    userName
                );
            }
        }
    } catch (error) {
        /*
         * Not logged in is fine.
         */
    }

    /*
     * If there is no name, generate one.
     */
    if (!userName) {
        userName =
            generateRandomUserName();

        window.localStorage.setItem(
            'name',
            userName
        );
    }

    userNameIn.value =
        cleanText(userName);

    /* ---------------------------------------------------------
       Random room
    --------------------------------------------------------- */

    if (randomRoomBtn) {
        randomRoomBtn.addEventListener(
            'click',
            () => {
                roomIdIn.value =
                    generateRoomId();

                roomIdIn.focus();
            }
        );
    }

    /* ---------------------------------------------------------
       Random user
    --------------------------------------------------------- */

    if (randomUserBtn) {
        randomUserBtn.addEventListener(
            'click',
            () => {
                const name =
                    generateRandomUserName();

                userNameIn.value =
                    name;

                window.localStorage.setItem(
                    'name',
                    name
                );

                userNameIn.focus();
            }
        );
    }

    /* ---------------------------------------------------------
       Audio
    --------------------------------------------------------- */

    if (initAudioBtn) {
        const active =
            getMediaState(
                'audio',
                storageConfig
            );

        updateMediaButton(
            initAudioBtn,
            'audio',
            active
        );

        initAudioBtn.addEventListener(
            'click',
            () => {
                const current =
                    getMediaState(
                        'audio',
                        storageConfig
                    );

                const next =
                    !current;

                setMediaState(
                    'audio',
                    next,
                    storageConfig
                );

                updateMediaButton(
                    initAudioBtn,
                    'audio',
                    next
                );
            }
        );
    }

    /* ---------------------------------------------------------
       Video
    --------------------------------------------------------- */

    if (initVideoBtn) {
        const active =
            getMediaState(
                'video',
                storageConfig
            );

        updateMediaButton(
            initVideoBtn,
            'video',
            active
        );

        initVideoBtn.addEventListener(
            'click',
            () => {
                const current =
                    getMediaState(
                        'video',
                        storageConfig
                    );

                const next =
                    !current;

                setMediaState(
                    'video',
                    next,
                    storageConfig
                );

                updateMediaButton(
                    initVideoBtn,
                    'video',
                    next
                );
            }
        );
    }

    /* ---------------------------------------------------------
       Normal join
    --------------------------------------------------------- */

    const join = (event) => {
        if (event) {
            event.preventDefault();
        }

        joinRoom(
            roomIdIn.value,
            userNameIn.value
        );
    };

    if (joinForm) {
        joinForm.addEventListener(
            'submit',
            join
        );
    }

    if (joinBtn) {
        joinBtn.addEventListener(
            'click',
            join
        );
    }

    /* ---------------------------------------------------------
       Support
    --------------------------------------------------------- */

    if (supportBtn) {
        supportBtn.addEventListener(
            'click',
            () => {
                window.open(
                    'https://docs.mirotalk.com/about',
                    '_blank',
                    'noopener,noreferrer'
                );
            }
        );
    }

    /* =========================================================
       AUTOMATIC INVITE JOIN
       
       IMPORTANT:
       Only happens when URL contains:
       
       ?room=ROOM_ID
       
       Normal homepage without room parameter
       remains unchanged.
    ========================================================= */

    if (inviteRoom) {
        /*
         * Give the browser a moment to finish
         * rendering the home page.
         */
        setTimeout(
            () => {
                const name =
                    userNameIn.value.trim() ||
                    generateRandomUserName();

                /*
                 * Save invite data.
                 */
                window.localStorage.setItem(
                    'room',
                    inviteRoom
                );

                window.localStorage.setItem(
                    'name',
                    name
                );

                /*
                 * Automatically enter the room.
                 */
                joinRoom(
                    inviteRoom,
                    name
                );
            },
            150
        );
    }
}

/* =========================================================
   JOIN ROOM
========================================================= */

function joinRoom(
    room,
    name
) {
    room =
        String(room || '').trim();

    name =
        String(name || '').trim();

    if (!room) {
        const input =
            document.getElementById(
                'roomIdInput'
            );

        if (input) {
            input.focus();
        }

        return;
    }

    if (!name) {
        name =
            generateRandomUserName();

        const input =
            document.getElementById(
                'userNameInput'
            );

        if (input) {
            input.value = name;
        }
    }

    /*
     * Save information.
     */
    window.localStorage.setItem(
        'room',
        room
    );

    window.localStorage.setItem(
        'name',
        name
    );

    /*
     * Go to the existing join route.
     */
    const url =
        '/join/?room=' +
        encodeURIComponent(room) +
        '&name=' +
        encodeURIComponent(name);

    window.location.assign(url);
}

/* =========================================================
   RANDOM USERNAME
========================================================= */

function generateRandomUserName() {
    const adjectives = [
        'Cool',
        'Happy',
        'Fast',
        'Smart',
        'Lucky',
        'Blue',
        'Red',
        'Silent',
        'Brave',
        'Funny',
        'Crazy',
        'Bright',
        'Wild',
        'Quick',
        'Nice'
    ];

    const animals = [
        'Lion',
        'Wolf',
        'Tiger',
        'Fox',
        'Eagle',
        'Bear',
        'Hawk',
        'Shark',
        'Panda',
        'Falcon',
        'Dragon',
        'Rabbit',
        'Dolphin',
        'Cobra',
        'Panther'
    ];

    const adjective =
        adjectives[
            Math.floor(
                Math.random() *
                adjectives.length
            )
        ];

    const animal =
        animals[
            Math.floor(
                Math.random() *
                animals.length
            )
        ];

    const number =
        Math.floor(
            100 +
            Math.random() *
            900
        );

    return (
        adjective +
        animal +
        number
    );
}

/* =========================================================
   RANDOM ROOM
========================================================= */

function generateRoomId() {
    if (
        window.crypto &&
        typeof window.crypto.randomUUID ===
            'function'
    ) {
        return window.crypto
            .randomUUID()
            .replace(/-/g, '')
            .substring(0, 12);
    }

    return (
        Math.random()
            .toString(36)
            .substring(2, 14) +
        Date.now()
            .toString(36)
            .substring(0, 4)
    );
}

/* =========================================================
   PUBLIC CHAT
========================================================= */

function initPublicChat() {
    const chatButton =
        document.getElementById(
            'publicChatButton'
        );

    const chat =
        document.getElementById(
            'publicChat'
        );

    const messages =
        document.getElementById(
            'publicChatMessages'
        );

    const input =
        document.getElementById(
            'publicChatInput'
        );

    const sendButton =
        document.getElementById(
            'publicChatSend'
        );

    const closeButton =
        document.getElementById(
            'publicChatClose'
        );

    const minimizeButton =
        document.getElementById(
            'publicChatMinimize'
        );

    const expandButton =
        document.getElementById(
            'publicChatExpand'
        );

    const badge =
        document.getElementById(
            'publicChatBadge'
        );

    const online =
        document.getElementById(
            'publicChatOnline'
        );

    if (
        !chatButton ||
        !chat ||
        !messages ||
        !input ||
        !sendButton
    ) {
        console.warn(
            '[PUBLIC CHAT] Elements not found.'
        );

        return;
    }

    if (
        typeof window.io !==
        'function'
    ) {
        console.error(
            '[PUBLIC CHAT] Socket.IO is not loaded.'
        );

        return;
    }

    let socket;

    try {
        socket =
            window.io(
                window.location.origin,
                {
                    transports: [
                        'websocket',
                        'polling'
                    ],
                    reconnection: true
                }
            );
    } catch (error) {
        console.error(
            '[PUBLIC CHAT]',
            error
        );

        return;
    }

    let unread = 0;

    /* ---------------------------------------------------------
       User
    --------------------------------------------------------- */

    const getUserName = () => {
        const userInput =
            document.getElementById(
                'userNameInput'
            );

        let name = '';

        if (
            userInput &&
            userInput.value
        ) {
            name =
                userInput.value.trim();
        }

        if (!name) {
            name =
                window.localStorage.getItem(
                    'name'
                ) || '';
        }

        if (!name) {
            name =
                generateRandomUserName();

            window.localStorage.setItem(
                'name',
                name
            );
        }

        return name.substring(
            0,
            50
        );
    };

    /* ---------------------------------------------------------
       Badge
    --------------------------------------------------------- */

    const updateBadge = () => {
        if (!badge) {
            return;
        }

        if (unread <= 0) {
            badge.textContent = '';
            badge.style.display =
                'none';
        } else {
            badge.textContent =
                unread > 99
                    ? '99+'
                    : String(unread);

            badge.style.display =
                'flex';
        }
    };

    /* ---------------------------------------------------------
       Scroll
    --------------------------------------------------------- */

    const scrollBottom = () => {
        requestAnimationFrame(
            () => {
                messages.scrollTop =
                    messages.scrollHeight;
            }
        );
    };

    /* ---------------------------------------------------------
       Time
    --------------------------------------------------------- */

    const formatTime = (
        timestamp
    ) => {
        if (!timestamp) {
            return '';
        }

        const date =
            new Date(timestamp);

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return '';
        }

        return date.toLocaleTimeString(
            [],
            {
                hour: '2-digit',
                minute: '2-digit'
            }
        );
    };

    /* ---------------------------------------------------------
       System message
    --------------------------------------------------------- */

    const addSystemMessage = (
        text
    ) => {
        if (!text) {
            return;
        }

        const element =
            document.createElement(
                'div'
            );

        element.className =
            'public-chat-system';

        element.textContent =
            String(text);

        messages.appendChild(
            element
        );

        scrollBottom();
    };

    /* ---------------------------------------------------------
       Chat message
    --------------------------------------------------------- */

    const addMessage = (
        data
    ) => {
        if (
            !data ||
            typeof data !==
                'object'
        ) {
            return;
        }

        const name =
            typeof data.name ===
            'string'
                ? data.name
                : 'Guest';

        const text =
            typeof data.message ===
            'string'
                ? data.message
                : '';

        if (!text.trim()) {
            return;
        }

        const wrapper =
            document.createElement(
                'div'
            );

        wrapper.className =
            'public-chat-message';

        if (
            name.trim() ===
            getUserName().trim()
        ) {
            wrapper.classList.add(
                'me'
            );
        }

        const nameElement =
            document.createElement(
                'div'
            );

        nameElement.className =
            'public-chat-name';

        nameElement.textContent =
            name;

        const textElement =
            document.createElement(
                'div'
            );

        textElement.className =
            'public-chat-text';

        textElement.textContent =
            text;

        const timeElement =
            document.createElement(
                'div'
            );

        timeElement.className =
            'public-chat-time';

        timeElement.textContent =
            formatTime(
                data.timestamp
            );

        wrapper.appendChild(
            nameElement
        );

        wrapper.appendChild(
            textElement
        );

        wrapper.appendChild(
            timeElement
        );

        messages.appendChild(
            wrapper
        );

        /*
         * Count unread messages.
         */
        if (
            chat.classList.contains(
                'hidden'
            )
        ) {
            unread++;
            updateBadge();
        }

        scrollBottom();
    };

    /* ---------------------------------------------------------
       History
    --------------------------------------------------------- */

    const renderHistory = (
        history
    ) => {
        messages.innerHTML = '';

        if (
            !Array.isArray(history)
        ) {
            return;
        }

        history.forEach(
            (message) => {
                addMessage(
                    message
                );
            }
        );

        scrollBottom();
    };

    /* ---------------------------------------------------------
       Send message
    --------------------------------------------------------- */

    const sendMessage = () => {
        const text =
            input.value.trim();

        if (!text) {
            return;
        }

        if (
            !socket.connected
        ) {
            addSystemMessage(
                'غير متصل بالخادم.'
            );

            return;
        }

        const name =
            getUserName();

        window.localStorage.setItem(
            'name',
            name
        );

        socket.emit(
            'globalChatSend',
            {
                name: name,
                message:
                    text.substring(
                        0,
                        1000
                    )
            }
        );

        input.value = '';

        input.focus();
    };

    /* ---------------------------------------------------------
       Open
    --------------------------------------------------------- */

    chatButton.addEventListener(
        'click',
        () => {
            chat.classList.remove(
                'hidden'
            );

            unread = 0;

            updateBadge();

            scrollBottom();

            setTimeout(
                () => input.focus(),
                100
            );
        }
    );

    /* ---------------------------------------------------------
       Close
    --------------------------------------------------------- */

    if (closeButton) {
        closeButton.addEventListener(
            'click',
            () => {
                chat.classList.add(
                    'hidden'
                );
            }
        );
    }

    /* ---------------------------------------------------------
       Minimize
    --------------------------------------------------------- */

    if (minimizeButton) {
        minimizeButton.addEventListener(
            'click',
            () => {
                chat.classList.toggle(
                    'minimized'
                );
            }
        );
    }

    /* ---------------------------------------------------------
       Expand
    --------------------------------------------------------- */

    if (expandButton) {
        expandButton.addEventListener(
            'click',
            () => {
                chat.classList.toggle(
                    'expanded'
                );

                const icon =
                    expandButton.querySelector(
                        'i'
                    );

                if (icon) {
                    icon.className =
                        chat.classList.contains(
                            'expanded'
                        )
                            ? 'fas fa-compress'
                            : 'fas fa-expand';
                }

                scrollBottom();
            }
        );
    }

    /* ---------------------------------------------------------
       Send
    --------------------------------------------------------- */

    sendButton.addEventListener(
        'click',
        sendMessage
    );

    input.addEventListener(
        'keydown',
        (event) => {
            if (
                event.key ===
                    'Enter' &&
                !event.shiftKey
            ) {
                event.preventDefault();

                sendMessage();
            }
        }
    );

    /* ---------------------------------------------------------
       Socket events
    --------------------------------------------------------- */

    socket.on(
        'connect',
        () => {
            console.log(
                '[PUBLIC CHAT] Connected:',
                socket.id
            );
        }
    );

    socket.on(
        'disconnect',
        (reason) => {
            console.log(
                '[PUBLIC CHAT] Disconnected:',
                reason
            );
        }
    );

    socket.on(
        'connect_error',
        (error) => {
            console.error(
                '[PUBLIC CHAT] Connection error:',
                error
            );
        }
    );

    socket.on(
        'globalChatHistory',
        (history) => {
            renderHistory(
                history
            );
        }
    );

    socket.on(
        'globalChatMessage',
        (message) => {
            addMessage(
                message
            );
        }
    );

    socket.on(
        'globalChatOnline',
        (count) => {
            if (!online) {
                return;
            }

            const value =
                Number(count);

            if (
                Number.isFinite(
                    value
                )
            ) {
                online.textContent =
                    value +
                    ' متصل';
            }
        }
    );

    socket.on(
        'globalChatSystem',
        (data) => {
            if (!data) {
                return;
            }

            if (
                typeof data ===
                'string'
            ) {
                addSystemMessage(
                    data
                );

                return;
            }

            if (
                data.message
            ) {
                addSystemMessage(
                    data.message
                );
            }
        }
    );
}

/* =========================================================
   MEDIA
========================================================= */

function getMediaState(
    type,
    config
) {
    if (
        !config ||
        !config[type] ||
        !config[type].init
    ) {
        return true;
    }

    return !!config[type]
        .init.active;
}

function setMediaState(
    type,
    active,
    config
) {
    if (
        !config ||
        !config[type] ||
        !config[type].init
    ) {
        return;
    }

    config[type]
        .init
        .active = !!active;

    try {
        const LS =
            new LocalStorage();

        LS.setConfig(
            config
        );
    } catch (error) {
        console.warn(
            '[HOME] Cannot save media config:',
            error
        );
    }
}

function updateMediaButton(
    button,
    type,
    active
) {
    if (!button) {
        return;
    }

    const icon =
        button.querySelector(
            'i'
        );

    if (icon) {
        if (type === 'audio') {
            icon.className =
                active
                    ? 'fas fa-microphone'
                    : 'fas fa-microphone-slash';
        }

        if (type === 'video') {
            icon.className =
                active
                    ? 'fas fa-video'
                    : 'fas fa-video-slash';
        }
    }

    button.classList.toggle(
        'off',
        !active
    );

    button.setAttribute(
        'aria-pressed',
        String(active)
    );
}

/* =========================================================
   CLEAN TEXT
========================================================= */

function cleanText(
    value
) {
    if (
        typeof value !==
        'string'
    ) {
        return '';
    }

    if (
        typeof window.filterXSS ===
        'function'
    ) {
        try {
            return window.filterXSS(
                value
            );
        } catch (error) {
            return value;
        }
    }

    return value;
}
