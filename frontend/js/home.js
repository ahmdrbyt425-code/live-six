'use strict';

/*
 * LIVE-SIX - HOME.JS
 * Home page + Public Global Chat
 */

document.addEventListener('DOMContentLoaded', () => {
    initHome();
    initPublicChat();
});

/* =========================================================
   HOME PAGE
   ========================================================= */

async function initHome() {
    const roomIdIn = document.getElementById('roomIdInput');
    const userNameIn = document.getElementById('userNameInput');

    const randomRoomBtn = document.getElementById('randomRoomBtn');
    const randomUserBtn = document.getElementById('randomUserBtn');

    const initAudioBtn = document.getElementById('initAudioBtn');
    const initVideoBtn = document.getElementById('initVideoBtn');

    const joinBtn = document.getElementById('joinBtn');
    const supportBtn = document.getElementById('supportBtn');

    if (!roomIdIn || !userNameIn) {
        console.warn('[HOME] Required home elements not found.');
        return;
    }

    /*
     * LocalStorage
     */
    let storageConfig = null;

    try {
        const LS = new LocalStorage();
        storageConfig = LS.getConfig();
    } catch (error) {
        console.warn('[HOME] Could not load LocalStorage config:', error);

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

    /*
     * Room from URL
     */
    const params = new URLSearchParams(window.location.search);

    const urlRoom = params.get('room');

    const savedRoom = window.localStorage.getItem('room') || '';

    roomIdIn.value = urlRoom || savedRoom || '';

    /*
     * Get user name
     */
    let userName = window.localStorage.getItem('name') || '';

    try {
        if (typeof axios !== 'undefined') {
            const response = await axios.get('/profile', {
                timeout: 5000
            });

            if (
                response &&
                response.data &&
                response.data.name
            ) {
                userName = response.data.name;

                window.localStorage.setItem(
                    'name',
                    userName
                );
            }
        }
    } catch (error) {
        console.log(
            '[HOME] Profile not available, using local name.'
        );
    }

    userNameIn.value = cleanText(userName);

    /*
     * Random room
     */
    if (randomRoomBtn) {
        randomRoomBtn.addEventListener('click', () => {
            const randomRoom = generateRoomId();

            roomIdIn.value = randomRoom;
            roomIdIn.focus();
        });
    }

    /*
     * Random username
     */
    if (randomUserBtn) {
        randomUserBtn.addEventListener('click', () => {
            const randomName =
                'User_' +
                Math.floor(
                    100000 +
                    Math.random() * 900000
                );

            userNameIn.value = randomName;
            userNameIn.focus();
        });
    }

    /*
     * Audio
     */
    if (initAudioBtn) {
        const audioActive =
            !!(
                storageConfig &&
                storageConfig.audio &&
                storageConfig.audio.init &&
                storageConfig.audio.init.active
            );

        updateMediaButton(
            initAudioBtn,
            'audio',
            audioActive
        );

        initAudioBtn.addEventListener(
            'click',
            () => {
                const current =
                    getMediaState(
                        'audio',
                        storageConfig
                    );

                const next = !current;

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

    /*
     * Video
     */
    if (initVideoBtn) {
        const videoActive =
            !!(
                storageConfig &&
                storageConfig.video &&
                storageConfig.video.init &&
                storageConfig.video.init.active
            );

        updateMediaButton(
            initVideoBtn,
            'video',
            videoActive
        );

        initVideoBtn.addEventListener(
            'click',
            () => {
                const current =
                    getMediaState(
                        'video',
                        storageConfig
                    );

                const next = !current;

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

    /*
     * Join
     */
    const join = (event) => {
        if (event) {
            event.preventDefault();
        }

        const room =
            roomIdIn.value.trim();

        const name =
            userNameIn.value.trim();

        if (!room) {
            roomIdIn.focus();
            return;
        }

        if (!name) {
            userNameIn.focus();
            return;
        }

        window.localStorage.setItem(
            'room',
            room
        );

        window.localStorage.setItem(
            'name',
            name
        );

        const joinURL =
            '/join/?room=' +
            encodeURIComponent(room) +
            '&name=' +
            encodeURIComponent(name);

        window.location.href = joinURL;
    };

    const joinForm =
        document.getElementById('joinForm');

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

    /*
     * Support
     */
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

    /*
     * Chat elements are not present.
     */
    if (
        !chatButton ||
        !chat ||
        !messages ||
        !input ||
        !sendButton
    ) {
        console.warn(
            '[PUBLIC CHAT] Chat HTML elements not found.'
        );

        return;
    }

    /*
     * Socket.IO
     */
    if (
        typeof window.io !== 'function'
    ) {
        console.error(
            '[PUBLIC CHAT] Socket.IO is not loaded.'
        );

        return;
    }

    let socket;

    try {
        socket = window.io(
            window.location.origin,
            {
                transports: [
                    'websocket',
                    'polling'
                ],
                reconnection: true,
                reconnectionAttempts: Infinity,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000
            }
        );
    } catch (error) {
        console.error(
            '[PUBLIC CHAT] Socket.IO error:',
            error
        );

        return;
    }

    let unread = 0;

    /*
     * Get username
     */
    const getUserName = () => {
        const userInput =
            document.getElementById(
                'userNameInput'
            );

        const name =
            userInput &&
            userInput.value
                ? userInput.value.trim()
                : '';

        if (name) {
            return name.substring(0, 50);
        }

        const saved =
            window.localStorage.getItem(
                'name'
            );

        if (saved) {
            return saved.substring(0, 50);
        }

        return 'Guest';
    };

    /*
     * Open chat
     */
    const openChat = () => {
        chat.classList.remove(
            'hidden'
        );

        chat.style.display = '';

        unread = 0;
        updateBadge();

        scrollBottom();

        setTimeout(() => {
            input.focus();
        }, 100);
    };

    /*
     * Close chat
     */
    const closeChat = () => {
        chat.classList.add(
            'hidden'
        );
    };

    /*
     * Badge
     */
    const updateBadge = () => {
        if (!badge) {
            return;
        }

        if (unread <= 0) {
            badge.textContent = '';
            badge.style.display = 'none';
        } else {
            badge.textContent =
                unread > 99
                    ? '99+'
                    : String(unread);

            badge.style.display = 'flex';
        }
    };

    /*
     * Scroll
     */
    const scrollBottom = () => {
        requestAnimationFrame(() => {
            messages.scrollTop =
                messages.scrollHeight;
        });
    };

    /*
     * Time
     */
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

    /*
     * Add system message
     */
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

    /*
     * Add chat message
     *
     * IMPORTANT:
     * textContent is used to prevent
     * HTML / JavaScript injection.
     */
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

        const currentName =
            getUserName();

        if (
            name.trim() ===
            currentName.trim()
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

        const messageElement =
            document.createElement(
                'div'
            );

        messageElement.className =
            'public-chat-text';

        messageElement.textContent =
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
            messageElement
        );

        wrapper.appendChild(
            timeElement
        );

        messages.appendChild(
            wrapper
        );

        /*
         * New message while closed.
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

    /*
     * History
     */
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

    /*
     * Send
     */
    const sendMessage = () => {
        const text =
            input.value.trim();

        if (!text) {
            return;
        }

        if (
            !socket ||
            !socket.connected
        ) {
            addSystemMessage(
                'غير متصل بالخادم. حاول مرة أخرى.'
            );

            return;
        }

        const name =
            getUserName();

        if (name) {
            window.localStorage.setItem(
                'name',
                name
            );
        }

        /*
         * Limit message length.
         */
        const message =
            text.substring(
                0,
                1000
            );

        socket.emit(
            'globalChatSend',
            {
                name: name,
                message: message
            }
        );

        input.value = '';
        input.focus();
    };

    /*
     * Button events
     */
    chatButton.addEventListener(
        'click',
        openChat
    );

    if (closeButton) {
        closeButton.addEventListener(
            'click',
            closeChat
        );
    }

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

    sendButton.addEventListener(
        'click',
        sendMessage
    );

    /*
     * Enter sends message.
     */
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

    /*
     * Socket connected
     */
    socket.on(
        'connect',
        () => {
            console.log(
                '[PUBLIC CHAT] Connected:',
                socket.id
            );
        }
    );

    /*
     * Socket disconnected
     */
    socket.on(
        'disconnect',
        (reason) => {
            console.warn(
                '[PUBLIC CHAT] Disconnected:',
                reason
            );
        }
    );

    /*
     * Connection error
     */
    socket.on(
        'connect_error',
        (error) => {
            console.error(
                '[PUBLIC CHAT] Connection error:',
                error
            );
        }
    );

    /*
     * Chat history
     */
    socket.on(
        'globalChatHistory',
        (history) => {
            renderHistory(
                history
            );
        }
    );

    /*
     * New message
     */
    socket.on(
        'globalChatMessage',
        (message) => {
            addMessage(
                message
            );
        }
    );

    /*
     * Online users
     */
    socket.on(
        'globalChatOnline',
        (count) => {
            if (!online) {
                return;
            }

            const number =
                Number(count);

            if (
                Number.isFinite(
                    number
                )
            ) {
                online.textContent =
                    number +
                    ' متصل';
            } else {
                online.textContent =
                    '';
            }
        }
    );

    /*
     * System message
     */
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
   HELPERS
   ========================================================= */

function cleanText(value) {
    if (
        typeof value !==
        'string'
    ) {
        return '';
    }

    /*
     * If filterXSS exists in the project,
     * use it. Otherwise safely return
     * the text for input.value.
     */
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

function generateRoomId() {
    if (
        window.crypto &&
        window.crypto.randomUUID
    ) {
        return window.crypto
            .randomUUID()
            .replace(
                /-/g,
                ''
            )
            .substring(
                0,
                12
            );
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

    return !!config[type].init.active;
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

    config[type].init.active =
        !!active;

    try {
        const LS =
            new LocalStorage();

        LS.setConfig(config);
    } catch (error) {
        console.warn(
            '[HOME] Could not save media config:',
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
