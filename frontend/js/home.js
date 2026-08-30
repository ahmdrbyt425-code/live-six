'use strict';

console.log('Location', window.location);
console.log('LocalStorage', window.localStorage);

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
    roomIdIn.value = roomId
        ? roomId
        : filterXSS(window.localStorage.room) || '';

    const getUserName = async () => {
        try {
            const { data: profile } = await axios.get('/profile', {
                timeout: 5000,
            });

            if (profile && profile.name) {
                console.log(
                    'AXIOS GET OIDC Profile retrieved successfully',
                    profile
                );

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

    randomUserBtn.onclick = () => {
        const finalValue =
            'User_' + Math.floor(Math.random() * 1000000);

        shuffleText(userNameIn, finalValue);
    };

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

    initAudioBtn.onclick = () => {
        const active =
            !localStorageConfig.audio.init.active;

        localStorageConfig.audio.init.active = active;

        LS.setConfig(localStorageConfig);

        updateMediaToggle(
            initAudioBtn,
            'audio',
            active
        );
    };

    initVideoBtn.onclick = () => {
        const active =
            !localStorageConfig.video.init.active;

        localStorageConfig.video.init.active = active;

        LS.setConfig(localStorageConfig);

        updateMediaToggle(
            initVideoBtn,
            'video',
            active
        );
    };

    /*
     * JOIN ROOM
     *
     * The join button is type="submit" and is inside
     * #joinForm in home.html.
     *
     * We must handle the form submit itself.
     *
     * history.pushState() only changes the URL and does
     * not load /join/.
     *
     * The client page needs to actually load so that
     * client.js can read room/name and start WebRTC.
     */

    const joinForm = document.getElementById('joinForm');

    if (joinForm) {
        joinForm.addEventListener('submit', (event) => {
            event.preventDefault();

            const room = roomIdIn.value.trim();
            const name = userNameIn.value.trim();

            if (!room || !name) {
                return;
            }

            window.localStorage.room = room;
            window.localStorage.name = name;

            const params = new URLSearchParams();

            params.set('room', room);
            params.set('name', name);

            /*
             * IMPORTANT:
             *
             * The backend route is /join/.
             * We perform a real navigation instead of
             * history.pushState().
             */

            const joinURL =
                window.location.origin +
                '/join/?' +
                params.toString();

            window.location.assign(joinURL);
        });
    } else {
        /*
         * Fallback in case #joinForm is not available.
         */
        joinBtn.onclick = (event) => {
            if (event) {
                event.preventDefault();
            }

            const room = roomIdIn.value.trim();
            const name = userNameIn.value.trim();

            if (!room || !name) {
                return;
            }

            window.localStorage.room = room;
            window.localStorage.name = name;

            const params = new URLSearchParams();

            params.set('room', room);
            params.set('name', name);

            const joinURL =
                window.location.origin +
                '/join/?' +
                params.toString();

            window.location.assign(joinURL);
        };
    }

    supportBtn.onclick = () => {
        window.open(
            'https://docs.mirotalk.com/about',
            '_blank'
        );
    };

    !config.support &&
        elementDisplay(supportBtn, false);
}

function shuffleText(
    input,
    finalValue,
    duration = 600
) {
    const chars =
        'abcdefghijklmnopqrstuvwxyz0123456789';

    const steps = 10;
    const interval = duration / steps;

    let step = 0;

    input.classList.add(
        'shuffle-active'
    );

    const timer = setInterval(() => {
        step++;

        const progress =
            step / steps;

        let display = '';

        for (
            let i = 0;
            i < finalValue.length;
            i++
        ) {
            if (
                i <
                finalValue.length *
                    progress
            ) {
                display +=
                    finalValue[i];
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

        input.value = display;

        if (step >= steps) {
            clearInterval(timer);

            input.value = finalValue;

            setTimeout(
                () =>
                    input.classList.remove(
                        'shuffle-active'
                    ),
                300
            );
        }
    }, interval);
}

function updateMediaToggle(
    btn,
    kind,
    active
) {
    const icon =
        btn.querySelector('i');

    if (icon) {
        icon.className = active
            ? mediaIcons[
                  kind + 'On'
              ]
            : mediaIcons[
                  kind + 'Off'
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

function elementDisplay(
    elem,
    display
) {
    elem.style.display =
        display
            ? 'block'
            : 'none';
}
