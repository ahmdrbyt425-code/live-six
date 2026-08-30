'use strict';

const roomId = filterXSS(
    new URLSearchParams(window.location.search).get('room') || ''
);

const roomIdIn = document.getElementById('roomIdInput');
const userNameIn = document.getElementById('userNameInput');
const randomRoomBtn = document.getElementById('randomRoomBtn');
const randomUserBtn = document.getElementById('randomUserBtn');
const initAudioBtn = document.getElementById('initAudioBtn');
const initVideoBtn = document.getElementById('initVideoBtn');
const joinBtn = document.getElementById('joinBtn');
const supportBtn = document.getElementById('supportBtn');

const LS = new LocalStorage();
const localStorageConfig = LS.getConfig();

const mediaIcons = {
    audioOn: 'fas fa-microphone',
    audioOff: 'fas fa-microphone-slash',
    videoOn: 'fas fa-video',
    videoOff: 'fas fa-video-slash',
};

const config = {
    support: true,
    //...
};

document.addEventListener('DOMContentLoaded', function () {
    initHome();
});

async function initHome() {
    // Restore room ID
    roomIdIn.value = roomId
        ? roomId
        : filterXSS(window.localStorage.room || '');

    // Get username
    const getUserName = async () => {
        try {
            const { data: profile } = await axios.get('/profile', {
                timeout: 5000,
            });

            if (profile && profile.name) {
                window.localStorage.name = profile.name;
            }
        } catch (error) {
            console.error(
                'AXIOS OIDC Error fetching profile',
                error.message || error
            );
        }

        return window.localStorage.name || '';
    };

    userNameIn.value = filterXSS(await getUserName());

    // Random room
    randomRoomBtn.onclick = () => {
        const finalValue = ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(
            /[018]/g,
            (c) =>
                (
                    c ^
                    (crypto.getRandomValues(new Uint8Array(1))[0] &
                        (15 >> (c / 4)))
                ).toString(16)
        );

        shuffleText(roomIdIn, finalValue);
    };

    // Random username
    randomUserBtn.onclick = () => {
        const finalValue = 'User_' + Math.floor(Math.random() * 1000000);

        shuffleText(userNameIn, finalValue);
    };

    // Initial media state
    updateMediaToggle(
        initAudioBtn,
        'audio',
        localStorageConfig.audio.init.active
    );

    updateMediaToggle(
        initVideoBtn,
        'video',
        localStorageConfig.video.init.active
    );

    // Audio toggle
    initAudioBtn.onclick = () => {
        const active = !localStorageConfig.audio.init.active;

        localStorageConfig.audio.init.active = active;

        LS.setConfig(localStorageConfig);

        updateMediaToggle(initAudioBtn, 'audio', active);
    };

    // Video toggle
    initVideoBtn.onclick = () => {
        const active = !localStorageConfig.video.init.active;

        localStorageConfig.video.init.active = active;

        LS.setConfig(localStorageConfig);

        updateMediaToggle(initVideoBtn, 'video', active);
    };

    // Join room
    joinBtn.onclick = () => {
        const room = roomIdIn.value.trim();
        const name = userNameIn.value.trim();

        // Do not continue if required fields are empty
        if (!room || !name) {
            return;
        }

        // Save values locally
        window.localStorage.room = room;
        window.localStorage.name = name;

        // Build a safe URL
        const params = new URLSearchParams({
            room: room,
            name: name,
        });

        const joinURL =
            window.location.origin + '/join?' + params.toString();

        /*
         * IMPORTANT:
         *
         * Do NOT use history.pushState() here.
         * pushState() changes the URL only and does not
         * actually navigate to /join.
         *
         * location.assign() performs a real navigation,
         * so the /join page is loaded immediately.
         */
        window.location.assign(joinURL);
    };

    // Support
    supportBtn.onclick = () => {
        window.open(
            'https://docs.mirotalk.com/about',
            '_blank',
            'noopener,noreferrer'
        );
    };

    // Show/hide support button
    !config.support && elementDisplay(supportBtn, false);
}

function shuffleText(input, finalValue, duration = 600) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const steps = 10;
    const interval = duration / steps;
    let step = 0;

    input.classList.add('shuffle-active');

    const timer = setInterval(() => {
        step++;

        const progress = step / steps;

        let display = '';

        for (let i = 0; i < finalValue.length; i++) {
            if (i < finalValue.length * progress) {
                display += finalValue[i];
            } else {
                display += chars[Math.floor(Math.random() * chars.length)];
            }
        }

        input.value = display;

        if (step >= steps) {
            clearInterval(timer);

            input.value = finalValue;

            setTimeout(() => {
                input.classList.remove('shuffle-active');
            }, 300);
        }
    }, interval);
}

function updateMediaToggle(btn, kind, active) {
    const icon = btn.querySelector('i');

    if (icon) {
        icon.className = active
            ? mediaIcons[kind + 'On']
            : mediaIcons[kind + 'Off'];
    }

    btn.classList.toggle('off', !active);

    btn.setAttribute('aria-pressed', String(active));
}

function elementDisplay(elem, display) {
    elem.style.display = display ? 'block' : 'none';
}
