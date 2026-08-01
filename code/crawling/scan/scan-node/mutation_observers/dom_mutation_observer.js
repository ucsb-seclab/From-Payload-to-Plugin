window.__MONITORING_SCRIPT_ACTIVE__ = true;

const __originalConsoleLog__ = console.log.bind(console);

let __inHook__ = false;

function __shouldSkipLogging__() {
    return __inHook__;
}

function __safeLog__(logFn) {
    if (__inHook__) return;
    __inHook__ = true;
    try {
        logFn();
    } catch (e) {
        try {
            __safeLog__(() => {
                __originalConsoleLog__('[Hook Error]', e.message);
            });
        } catch (ignored) {}
    } finally {
        __inHook__ = false;
    }
}

__safeLog__(() => {
    __originalConsoleLog__(JSON.stringify({
        type: 'Monitoring Started',
        timestamp: Date.now(),
        note: 'This marker should appear FIRST in console logs, before any page scripts'
    }));
});

window.addEventListener('storage', (e) => {
    __safeLog__(() => {
        const registrationStack = new Error().stack;
        __originalConsoleLog__(JSON.stringify({
            type: 'Storage Event',
            key: e.key,
            newValue: e.newValue,
            oldValue: e.oldValue,
            url: e.url,
            registrationStack: registrationStack
        }));
    });
});

if (navigator.sendBeacon) {
    const originalSendBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (url, data) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Beacon API Call',
            url: url,
            data: safeStringify(data),
            registrationStack: registrationStack
            }));
        });
        return originalSendBeacon.apply(this, arguments);
    };
}

if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = function (constraints) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'getUserMedia Call',
            constraints: safeStringify(constraints),
            registrationStack: registrationStack
            }));
        });
        return originalGetUserMedia(constraints);
    };
}

if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
    navigator.mediaDevices.enumerateDevices = function () {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'enumerateDevices Call',
            registrationStack: registrationStack
            }));
        });
        return originalEnumerateDevices();
    };
}

if (window.indexedDB) {
    const originalIndexedDBOpen = indexedDB.open.bind(indexedDB);
    indexedDB.open = function (name, version) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'IndexedDB Open',
            name: name,
            version: version,
            registrationStack: registrationStack
            }));
        });
        return originalIndexedDBOpen(name, version);
    };
}

if (window.caches) {
    const originalCachesOpen = caches.open.bind(caches);
    caches.open = function (cacheName) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Cache API Open',
            cacheName: cacheName,
            registrationStack: registrationStack
            }));
        });
        return originalCachesOpen(cacheName);
    };

    const originalCachesMatch = caches.match.bind(caches);
    caches.match = function (request, options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Cache API Match',
            request: safeStringify(request),
            options: safeStringify(options),
            registrationStack: registrationStack
            }));
        });
        return originalCachesMatch(request, options);
    };
}

if (window.PushManager) {
    const originalSubscribe = PushManager.prototype.subscribe;
    PushManager.prototype.subscribe = function (options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'PushManager Subscribe',
            options: safeStringify(options),
            registrationStack: registrationStack
            }));
        });
        return originalSubscribe.apply(this, arguments);
    };
}

if (window.Notification) {
    const originalRequestPermission = Notification.requestPermission;
    Notification.requestPermission = function (callback) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Notification Request Permission',
            registrationStack: registrationStack
            }));
        });
        return originalRequestPermission.call(this, callback);
    };
}

const originalGetContext = HTMLCanvasElement.prototype.getContext;
HTMLCanvasElement.prototype.getContext = function (type, ...args) {
    const registrationStack = new Error().stack;
    if (type === 'webgl' || type === 'experimental-webgl') {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'WebGL Context Creation',
            contextType: type,
            registrationStack: registrationStack
            }));
        });
    }
    return originalGetContext.apply(this, [type, ...args]);
};

const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function (...args) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Canvas toDataURL',
        tagName: this.tagName,
        registrationStack: registrationStack
        }));
    });
    return originalToDataURL.apply(this, args);
};

function safeStringify(value, maxDepth = 2, currentDepth = 0, maxLength = 1000, seen = new WeakSet()) {
    if (currentDepth >= maxDepth) return '[max depth]';

    try {
        if (value === null) return null;
        if (value === undefined) return undefined;
        if (typeof value === 'string') {
            return value.length > maxLength ? value.substring(0, maxLength) + '...[truncated]' : value;
        }
        if (typeof value === 'number' || typeof value === 'boolean') return value;
        if (typeof value === 'function') return '[Function]';

        if (value instanceof Date) return value.toISOString();
        if (value instanceof RegExp) return value.toString();
        if (value instanceof Error) return `[Error: ${value.message}]`;
        if (value instanceof HTMLElement) return `<${value.tagName}>`;
        if (value instanceof Node) return '[Node]';

        if (typeof value === 'object' && value !== null) {
            if (seen.has(value)) {
                return '[Circular]';
            }
            seen.add(value);
        }

        if (Array.isArray(value)) {
            if (value.length === 0) return [];
            if (currentDepth >= maxDepth - 1) return `[Array(${value.length})]`;
            const items = value.slice(0, 3).map(item => {
                try {
                    return safeStringify(item, maxDepth, currentDepth + 1, maxLength, seen);
                } catch (e) {
                    return '[Error]';
                }
            });
            if (value.length > 3) items.push(`...[${value.length - 3} more]`);
            return items;
        }

        if (typeof value === 'object') {
            if (currentDepth >= maxDepth - 1) return '[Object]';

            const keys = Object.keys(value).slice(0, 5);
            const obj = {};
            for (let key of keys) {
                try {
                    obj[key] = safeStringify(value[key], maxDepth, currentDepth + 1, maxLength, seen);
                } catch (e) {
                    obj[key] = '[Error]';
                }
            }
            if (Object.keys(value).length > 5) {
                obj._more = `${Object.keys(value).length - 5} more keys`;
            }
            return obj;
        }

        return '[Unknown]';
    } catch (e) {
        return '[Error]';
    }
}

function createPropertyInterceptor(obj, prop, objectName) {
    try {
        const descriptor = Object.getOwnPropertyDescriptor(obj, prop);

        if (!descriptor) {
             __safeLog__(() => {
                 __originalConsoleLog__(`[Interceptor] Property "${prop}" not found on ${objectName}.`);
             });
             return;
        }

        if (!descriptor.configurable) {
            __safeLog__(() => {
                __originalConsoleLog__(`[Interceptor] Property "${prop}" on ${objectName} is not configurable.`);
            });
            return;
        }

        const originalGetter = descriptor.get;
        const originalSetter = descriptor.set;

        Object.defineProperty(obj, prop, {
            get: function() {
                try {
                    const value = originalGetter ? originalGetter.call(this) : descriptor.value;
                    if (__shouldSkipLogging__()) return value;

                    const registrationStack = new Error().stack;
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'DOM Property Read',
                        object: objectName,
                        property: prop,
                        value: safeStringify(value),
                        registrationStack: registrationStack
                        }));
                    });
                    return value;
                } catch (e) {
                    return originalGetter ? originalGetter.call(this) : descriptor.value;
                }
            },
            set: function(value) {
                if (__shouldSkipLogging__()) {
                    if (originalSetter) {
                        return originalSetter.call(this, value);
                    } else {
                        descriptor.value = value;
                    }
                    return;
                }

                const registrationStack = new Error().stack;
                __safeLog__(() => {
                    __originalConsoleLog__(JSON.stringify({
                    type: 'DOM Property Write',
                    object: objectName,
                    property: prop,
                    value: safeStringify(value),
                    registrationStack: registrationStack
                    }));
                });
                if (originalSetter) {
                    return originalSetter.call(this, value);
                } else {
                    descriptor.value = value;
                }
            },
            configurable: true,
            enumerable: descriptor.enumerable
        });
    } catch (e) {
        __safeLog__(() => {
            __originalConsoleLog__(`[Interceptor] Failed to intercept ${objectName}.${prop}:`, e.message);
        });
    }
}

const documentPropertiesToTrace = [
    'referrer',
    'domain',
    'documentElement',
    'body',
    'head',
    'title',
    'URL',
    'documentURI',
    'charset',
    'characterSet',
    'contentType',
    'lastModified',
    'readyState',
    'hidden',
    'visibilityState',
    'forms',
    'images',
    'links',
    'scripts',
    'styleSheets',
    'activeElement',
    'currentScript',
    'designMode',
    'dir',
    'lang',
    'scrollingElement',
    'pictureInPictureEnabled',
    'fullscreenElement',
    'inputEncoding',
    'adoptedStyleSheets',
];

const windowPropertiesToTrace = [
    'history',
    'screen',
    'devicePixelRatio',
    'innerWidth',
    'innerHeight',
    'outerWidth',
    'outerHeight',
    'pageXOffset',
    'pageYOffset',
    'scrollX',
    'scrollY',
    'name',
    'top',
    'parent',
    'self',
    'opener',
    'frames',
    'performance',
    'crypto',
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'caches',
    'customElements',
    'permissions',
    'clipboard',
];

const navigatorPropertiesToTrace = [
    'userAgent',
    'appName',
    'appVersion',
    'platform',
    'language',
    'languages',
    'onLine',
    'cookieEnabled',
    'doNotTrack',
    'maxTouchPoints',
    'vendor',
    'hardwareConcurrency',
    'deviceMemory',
    'connection',
    'geolocation',
    'permissions',
];

const locationPropertiesToTrace = [
    'protocol',
    'host',
    'hostname',
    'port',
    'pathname',
    'search',
    'hash',
    'origin',
];

documentPropertiesToTrace.forEach(prop => {
    createPropertyInterceptor(Document.prototype, prop, 'document');
});

windowPropertiesToTrace.forEach(prop => {
    createPropertyInterceptor(window, prop, 'window');
});

if (navigator) {
    navigatorPropertiesToTrace.forEach(prop => {
        createPropertyInterceptor(Navigator.prototype, prop, 'navigator');
    });
}

if (window.location) {
    locationPropertiesToTrace.forEach(prop => {
        createPropertyInterceptor(Location.prototype, prop, 'location');
    });
}

const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
if (cookieDescriptor && cookieDescriptor.configurable) {
    Object.defineProperty(Document.prototype, 'cookie', {
        set: function (value) {
            if (__shouldSkipLogging__()) {
                return cookieDescriptor.set.call(this, value);
            }

            const registrationStack = new Error().stack;
            __safeLog__(() => {
                __originalConsoleLog__(JSON.stringify({
                type: 'Cookie Update',
                value: safeStringify(value),
                registrationStack: registrationStack
                }));
            });
            return cookieDescriptor.set.call(this, value);
        },
        get: function () {
            const value = cookieDescriptor.get.call(this);

            if (__shouldSkipLogging__()) {
                return value;
            }

            const registrationStack = new Error().stack;
            __safeLog__(() => {
                __originalConsoleLog__(JSON.stringify({
                type: 'Cookie Read',
                value: safeStringify(value),
                registrationStack: registrationStack
                }));
            });
            return value;
        },
        configurable: true
    });
} else {
    console.warn('[Interceptor] Document.cookie is not configurable and cannot be hooked.');
}

const originalXHROpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
    this._method = method;
    this._url = url;
    this._headers = {};
    return originalXHROpen.apply(this, arguments);
};

const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (!this._headers) this._headers = {};
    this._headers[name] = value;
    return originalXHRSetRequestHeader.apply(this, arguments);
};

const originalXHRSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function (body) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'XHR Request',
        method: this._method,
        url: this._url,
        headers: this._headers || {},
        body: safeStringify(body),
        registrationStack: registrationStack
        }));
    });

    this.addEventListener('load', function () {
        if (__shouldSkipLogging__()) return;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'XHR Response',
            url: this._url,
            status: this.status,
            statusText: this.statusText,
            responseType: this.responseType,
            responsePreview: (this.responseType === '' || this.responseType === 'text' || this.responseType === 'json')
            ? safeStringify(this.responseText, 1, 0, 200)
            : `[Non-text response: ${this.responseType}]`,
            registrationStack: registrationStack
            }));
        });
    }, { once: true });

    return originalXHRSend.apply(this, arguments);
};

const originalFetch = window.fetch;
window.fetch = function (...args) {
    const registrationStack = new Error().stack;

    let requestUrl = (args[0] instanceof Request) ? args[0].url : args[0];
    let requestArgs = safeStringify(args);

    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Fetch Request',
        url: requestUrl,
        arguments: requestArgs,
        registrationStack: registrationStack
        }));
    });

    return originalFetch.apply(this, args).then(response => {
        if (__shouldSkipLogging__()) return response;

        const responseClone = response.clone();

        const headers = {};
        responseClone.headers.forEach((value, key) => {
            headers[key] = value;
        });

        responseClone.text().then(text => {
             __safeLog__(() => {
                 __originalConsoleLog__(JSON.stringify({
                 type: 'Fetch Response',
                 url: responseClone.url,
                 status: responseClone.status,
                 statusText: responseClone.statusText,
                 responseType: responseClone.type,
                 headers: headers,
                 responsePreview: safeStringify(text, 1, 0, 200),
                 registrationStack: registrationStack
                 }));
             });
        }).catch(e => {
             __safeLog__(() => {
                 __originalConsoleLog__(JSON.stringify({
                 type: 'Fetch Response',
                 url: responseClone.url,
                 status: responseClone.status,
                 statusText: responseClone.statusText,
                 responseType: responseClone.type,
                 responsePreview: '[Response body could not be read]',
                 registrationStack: registrationStack
                 }));
             });
        });

        return response;
    });
};

const originalSetTimeout = window.setTimeout;
window.setTimeout = function (callback, delay, ...args) {
    const registrationStack = new Error().stack;

    if (typeof callback === 'string') {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Timeout (String) Set',
            delay: delay,
            codePreview: callback.substring(0, 200),
            codeLength: callback.length,
            registrationStack: registrationStack
            }));
        });
    } else {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Timeout (Function) Set',
            delay: delay,
            registrationStack: registrationStack
            }));
        });
    }
    return originalSetTimeout.call(this, callback, delay, ...args);
};

const originalSetInterval = window.setInterval;
window.setInterval = function (callback, delay, ...args) {
    const registrationStack = new Error().stack;

    if (typeof callback === 'string') {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Interval (String) Set',
            delay: delay,
            codePreview: callback.substring(0, 200),
            codeLength: callback.length,
            registrationStack: registrationStack
            }));
        });
    } else {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Interval (Function) Set',
            delay: delay,
            registrationStack: registrationStack
            }));
        });
    }
    return originalSetInterval.call(this, callback, delay, ...args);
};

const originalPushState = window.history.pushState;
window.history.pushState = function (state, title, url) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'History PushState',
        state: safeStringify(state),
        title: title,
        url: url,
        registrationStack: registrationStack
        }));
    });
    return originalPushState.apply(this, arguments);
};
const originalReplaceState = window.history.replaceState;
window.history.replaceState = function (state, title, url) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'History ReplaceState',
        state: safeStringify(state),
        title: title,
        url: url,
        registrationStack: registrationStack
        }));
    });
    return originalReplaceState.apply(this, arguments);
};
window.addEventListener('popstate', (e) => {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'History Popstate',
        state: safeStringify(e.state),
        registrationStack: registrationStack
        }));
    });
});

const OriginalWebSocket = window.WebSocket;
window.WebSocket = function (url, protocols) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'WebSocket Connection',
        url: url,
        protocols: protocols,
        registrationStack: registrationStack
        }));
    });

    const ws = new OriginalWebSocket(url, protocols);

    const originalSend = ws.send;
    ws.send = function(data) {
        const sendStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'WebSocket Send',
            url: url,
            dataType: typeof data,
            dataSize: (data && data.length) || (data && data.byteLength) || 0,
            dataPreview: safeStringify(data, 1, 0, 200),
            registrationStack: sendStack
            }));
        });
        return originalSend.apply(this, arguments);
    };

    let onmessageHandler = null;
    Object.defineProperty(ws, 'onmessage', {
        get: function() {
            return onmessageHandler;
        },
        set: function(handler) {
            onmessageHandler = function(event) {
                if (!__shouldSkipLogging__()) {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'WebSocket Receive (onmessage)',
                        url: url,
                        dataType: typeof event.data,
                        dataSize: (event.data && event.data.length) || (event.data && event.data.byteLength) || 0,
                        dataPreview: safeStringify(event.data, 1, 0, 200),
                        timestamp: Date.now()
                        }));
                    });
                }
                if (handler) return handler.call(this, event);
            };
        },
        configurable: true,
        enumerable: true
    });

    const originalWSAddEventListener = ws.addEventListener;
    ws.addEventListener = function(type, listener, ...args) {
        if (type === 'message' && listener) {
            const wrappedListener = function(event) {
                if (!__shouldSkipLogging__()) {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'WebSocket Receive (addEventListener)',
                        url: url,
                        dataType: typeof event.data,
                        dataSize: (event.data && event.data.length) || (event.data && event.data.byteLength) || 0,
                        dataPreview: safeStringify(event.data, 1, 0, 200),
                        timestamp: Date.now()
                        }));
                    });
                }
                return listener.call(this, event);
            };
            return originalWSAddEventListener.call(this, type, wrappedListener, ...args);
        }
        return originalWSAddEventListener.call(this, type, listener, ...args);
    };

    return ws;
};

window.onerror = function (message, source, lineno, colno, error) {
    const registrationStack = error && error.stack ? error.stack : new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Error',
        message: message,
        source: source,
        lineno: lineno,
        colno: colno,
        registrationStack: registrationStack
        }));
    });
};
window.onunhandledrejection = function (event) {
    const registrationStack = event.reason && event.reason.stack ? event.reason.stack : new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Unhandled Promise Rejection',
        reason: safeStringify(event.reason),
        registrationStack: registrationStack
        }));
    });
};

const OriginalIntersectionObserver = window.IntersectionObserver;
window.IntersectionObserver = function (callback, options) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'IntersectionObserver Created',
        options: safeStringify(options),
        registrationStack: registrationStack
        }));
    });
    return new OriginalIntersectionObserver(callback, options);
};

const OriginalResizeObserver = window.ResizeObserver;
window.ResizeObserver = function (callback) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'ResizeObserver Created',
        registrationStack: registrationStack
        }));
    });
    return new OriginalResizeObserver(callback);
};

if ('serviceWorker' in navigator) {
    const originalRegister = navigator.serviceWorker.register;
    navigator.serviceWorker.register = function (scriptURL, options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Service Worker Registration',
            scriptURL: scriptURL,
            options: safeStringify(options),
            registrationStack: registrationStack
            }));
        });
        return originalRegister.call(navigator.serviceWorker, scriptURL, options);
    };
}

const OriginalWorker = window.Worker;
window.Worker = function (scriptURL, options) {
    const registrationStack = new Error().stack;

    let scriptContent = '[External URL]';
    if (typeof scriptURL === 'string') {
        if (scriptURL.startsWith('blob:')) {
            scriptContent = '[Blob URL - content not directly accessible]';
        } else if (scriptURL.startsWith('data:')) {
            scriptContent = scriptURL.substring(0, 200) + (scriptURL.length > 200 ? '...' : '');
        }
    }

    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Web Worker Created',
        scriptURL: scriptURL,
        scriptContent: scriptContent,
        options: safeStringify(options),
        registrationStack: registrationStack
        }));
    });

    const worker = new OriginalWorker(scriptURL, options);

    const originalWorkerPostMessage = worker.postMessage;
    worker.postMessage = function(message, transfer) {
        const msgStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Worker PostMessage (to worker)',
            scriptURL: scriptURL,
            messagePreview: safeStringify(message, 1, 0, 200),
            hasTransfer: !!transfer,
            registrationStack: msgStack
            }));
        });
        return originalWorkerPostMessage.apply(this, arguments);
    };

    let onmessageHandler = null;
    Object.defineProperty(worker, 'onmessage', {
        get: function() {
            return onmessageHandler;
        },
        set: function(handler) {
            onmessageHandler = function(event) {
                if (!__shouldSkipLogging__()) {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'Worker Message (from worker, onmessage)',
                        scriptURL: scriptURL,
                        dataPreview: safeStringify(event.data, 1, 0, 200),
                        timestamp: Date.now()
                        }));
                    });
                }
                if (handler) return handler.call(this, event);
            };
        },
        configurable: true,
        enumerable: true
    });

    const originalWorkerAddEventListener = worker.addEventListener;
    worker.addEventListener = function(type, listener, ...args) {
        if (type === 'message' && listener) {
            const wrappedListener = function(event) {
                if (!__shouldSkipLogging__()) {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'Worker Message (from worker, addEventListener)',
                        scriptURL: scriptURL,
                        dataPreview: safeStringify(event.data, 1, 0, 200),
                        timestamp: Date.now()
                        }));
                    });
                }
                return listener.call(this, event);
            };
            return originalWorkerAddEventListener.call(this, type, wrappedListener, ...args);
        }
        return originalWorkerAddEventListener.call(this, type, listener, ...args);
    };

    return worker;
};

if ('BroadcastChannel' in window) {
    const OriginalBroadcastChannel = window.BroadcastChannel;
    window.BroadcastChannel = function (name) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'BroadcastChannel Created',
            name: name,
            registrationStack: registrationStack
            }));
        });
        return new OriginalBroadcastChannel(name);
    };
}

if ('geolocation' in navigator) {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    navigator.geolocation.getCurrentPosition = function (successCallback, errorCallback, options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Geolocation getCurrentPosition',
            options: safeStringify(options),
            registrationStack: registrationStack
            }));
        });
        return originalGetCurrentPosition(successCallback, errorCallback, options);
    };
    const originalWatchPosition = navigator.geolocation.watchPosition.bind(navigator.geolocation);
    navigator.geolocation.watchPosition = function (successCallback, errorCallback, options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Geolocation watchPosition',
            options: safeStringify(options),
            registrationStack: registrationStack
            }));
        });
        return originalWatchPosition(successCallback, errorCallback, options);
    };
}

const originalAddEventListener = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (__shouldSkipLogging__()) {
        return originalAddEventListener.call(this, type, listener, options);
    }

    const registrationStack = new Error().stack;
    try {
        const targetInfo = {
            tagName: this.tagName || this.nodeName || 'unknown',
            className: this.className || '',
            id: this.id || ''
        };

        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Event Listener Added',
            eventType: type,
            target: targetInfo,
            isCapture: (options && options.capture) || false,
            listenerLength: listener.toString().length,
            listenerPreview: listener.toString().substring(0, 100),
            registrationStack: registrationStack
            }));
        });
    } catch (e) {
    }
    return originalAddEventListener.call(this, type, listener, options);
};

const originalDefineProperty = Object.defineProperty;
Object.defineProperty = function (obj, prop, descriptor) {
    if (__shouldSkipLogging__()) {
        return originalDefineProperty.apply(this, arguments);
    }

    const registrationStack = new Error().stack;
    try {
        const objType = typeof obj;
        const isNativePrototype = obj === Object.prototype || obj === Function.prototype ||
                                 obj === Array.prototype || obj === String.prototype ||
                                 obj === Number.prototype || obj === Boolean.prototype;

        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Object.defineProperty Called',
            objectType: objType,
            property: prop,
            hasGetter: !!(descriptor && descriptor.get),
            hasSetter: !!(descriptor && descriptor.set),
            configurable: descriptor && descriptor.configurable,
            enumerable: descriptor && descriptor.enumerable,
            isNativePrototype: isNativePrototype,
            registrationStack: registrationStack
            }));
        });
    } catch (e) {
    }
    return originalDefineProperty.apply(this, arguments);
};

const originalCreateElement = Document.prototype.createElement;
const iframeCreationCount = { count: 0 };

Document.prototype.createElement = function (tagName, ...args) {
    const element = originalCreateElement.apply(this, [tagName, ...args]);

    if (tagName.toLowerCase() === 'script') {
        const descriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
        if (descriptor) {
            Object.defineProperty(element, 'src', {
                set: function(value) {
                    const registrationStack = new Error().stack;
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'Script Src Set',
                        src: value,
                        isExternal: value && (value.startsWith('http') || value.startsWith('//')),
                        isDataURL: value && value.startsWith('data:'),
                        registrationStack: registrationStack
                        }));
                    });
                    descriptor.set.call(this, value);
                },
                get: descriptor.get,
                configurable: true
            });
        }

        const textDescriptor = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
        if (textDescriptor) {
            Object.defineProperty(element, 'textContent', {
                set: function(value) {
                    const registrationStack = new Error().stack;
                    if (value && value.length > 20) {
                        __safeLog__(() => {
                            __originalConsoleLog__(JSON.stringify({
                            type: 'Inline Script Injected',
                            contentLength: value.length,
                            contentPreview: value.substring(0, 200),
                            registrationStack: registrationStack
                            }));
                        });
                    }
                    textDescriptor.set.call(this, value);
                },
                get: textDescriptor.get,
                configurable: true
            });
        }
    }

    if (tagName && tagName.toLowerCase() === 'iframe') {
        iframeCreationCount.count++;
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'IFrame Created (Potential Context Escape)',
            iframeNumber: iframeCreationCount.count,
            timestamp: Date.now(),
            registrationStack: registrationStack
            }));
        });

        if (iframeCreationCount.count > 3) {
            __safeLog__(() => {
                __originalConsoleLog__(JSON.stringify({
                type: 'WARNING: Multiple IFrames Created',
                count: iframeCreationCount.count,
                message: 'Possible hook evasion attempt via iframe context escape',
                timestamp: Date.now()
                }));
            });
        }
    }

    return element;
};

const originalFormSubmit = HTMLFormElement.prototype.submit;
HTMLFormElement.prototype.submit = function () {
    const registrationStack = new Error().stack;
    try {
        const formFields = [];
        for (let i = 0; i < this.elements.length; i++) {
            const el = this.elements[i];
            formFields.push({
                name: el.name || '',
                type: el.type || '',
                value_length: el.value ? el.value.length : 0
            });
        }

        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Form Submitted',
            action: this.action,
            method: this.method,
            fieldCount: this.elements.length,
            fields: formFields,
            formId: this.id,
            formClass: this.className,
            registrationStack: registrationStack
            }));
        });
    } catch (e) {
    }
    return originalFormSubmit.call(this);
};

const fieldTypes = ['input', 'textarea', 'select'];
fieldTypes.forEach(tagName => {
    try {
        let ProtoClass;
        if (tagName === 'input') ProtoClass = HTMLInputElement;
        else if (tagName === 'textarea') ProtoClass = HTMLTextAreaElement;
        else if (tagName === 'select') ProtoClass = HTMLSelectElement;

        if (!ProtoClass) return;

        const descriptor = Object.getOwnPropertyDescriptor(ProtoClass.prototype, 'value');
        if (descriptor && descriptor.set) {
            Object.defineProperty(ProtoClass.prototype, 'value', {
                get: function() {
                    const registrationStack = new Error().stack;
                    const value = descriptor.get.call(this);

                    if (this.type === 'password' || (this.name && this.name.toLowerCase().includes('pass'))) {
                        __safeLog__(() => {
                            __originalConsoleLog__(JSON.stringify({
                            type: 'Sensitive Field Read',
                            fieldType: this.type || tagName,
                            fieldName: this.name,
                            fieldId: this.id,
                            valueLength: value ? value.length : 0,
                            registrationStack: registrationStack
                            }));
                        });
                    }
                    return value;
                },
                set: function(val) {
                    const registrationStack = new Error().stack;
                    if (this.type === 'password' || (this.name && this.name.toLowerCase().includes('pass'))) {
                        __safeLog__(() => {
                            __originalConsoleLog__(JSON.stringify({
                            type: 'Sensitive Field Write',
                            fieldType: this.type || tagName,
                            fieldName: this.name,
                            fieldId: this.id,
                            valueLength: val ? val.length : 0,
                            registrationStack: registrationStack
                            }));
                        });
                    }
                    descriptor.set.call(this, val);
                },
                configurable: true
            });
        }
    } catch (e) {
    }
});

const originalSetAttribute = Element.prototype.setAttribute;
Element.prototype.setAttribute = function (name, value) {
    const registrationStack = new Error().stack;

    if (this.tagName === 'IFRAME' && name.toLowerCase() === 'src') {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'IFrame Src Set',
            src: value,
            isDataURL: value && value.startsWith('data:'),
            isExternal: value && (value.startsWith('http') || value.startsWith('//')),
            iframeId: this.id,
            iframeClass: this.className,
            registrationStack: registrationStack
            }));
        });
    } else {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'setAttribute Called',
            tagName: this.tagName,
            attribute: name,
            value: safeStringify(value),
            elementId: this.id,
            elementClass: this.className,
            registrationStack: registrationStack
            }));
        });
    }

    return originalSetAttribute.call(this, name, value);
};

const originalPostMessage = window.postMessage;
window.postMessage = function (message, targetOrigin, transfer) {
    const registrationStack = new Error().stack;
    try {
        let messageSize = 0;
        let messagePreview = '';

        if (typeof message === 'string') {
            messageSize = message.length;
            messagePreview = message.substring(0, 200);
        } else {
            const msgStr = JSON.stringify(message);
            messageSize = msgStr.length;
            messagePreview = msgStr.substring(0, 200);
        }

        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'postMessage Called',
            targetOrigin: targetOrigin,
            messageSize: messageSize,
            messagePreview: messagePreview,
            hasTransfer: !!transfer,
            registrationStack: registrationStack
            }));
        });
    } catch (e) {
    }
    return originalPostMessage.apply(this, arguments);
};

window.addEventListener('message', (event) => {
    const registrationStack = new Error().stack;
    try {
        let messagePreview = '';
        if (typeof event.data === 'string') {
            messagePreview = event.data.substring(0, 200);
        } else {
            messagePreview = JSON.stringify(event.data).substring(0, 200);
        }

        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'postMessage Received',
            origin: event.origin,
            source: event.source === window.parent ? 'parent' : event.source === window.opener ? 'opener' : 'other',
            messagePreview: messagePreview,
            registrationStack: registrationStack
            }));
        });
    } catch (e) {
    }
}, true);

function serializeNode(node) {
    if (!node) return null;
    if (node.nodeType === Node.TEXT_NODE) {
        return {
            nodeType: 'TEXT_NODE',
            textContent: node.textContent.trim().substring(0, 50) + (node.textContent.trim().length > 50 ? '...' : '')
        };
    }
    if (node.nodeType === Node.COMMENT_NODE) {
        return {
            nodeType: 'COMMENT_NODE',
            textContent: node.textContent.trim().substring(0, 50) + (node.textContent.trim().length > 50 ? '...' : '')
        };
    }
    if (node.nodeType !== Node.ELEMENT_NODE) {
        return {nodeType: node.nodeType, nodeName: node.nodeName};
    }
    let serialized = {
        nodeType: 'ELEMENT_NODE',
        nodeName: node.nodeName,
        tagName: node.tagName,
        id: node.id,
        className: node.className,
    };
    return serialized;
}

const methodsToOverride = [
    { proto: Node.prototype, method: "appendChild", targetIndex: -1, argIndex: 0 },
    { proto: Node.prototype, method: "removeChild", targetIndex: -1, argIndex: 0 },
    { proto: Node.prototype, method: "replaceChild", targetIndex: -1, argIndex: 1 },
    { proto: Node.prototype, method: "insertBefore", targetIndex: -1, argIndex: 0 },
    { proto: Element.prototype, method: "removeAttribute", targetIndex: -1, argIndex: 0 },
    { proto: Element.prototype, method: "toggleAttribute", targetIndex: -1, argIndex: 0 },
    { proto: DOMTokenList.prototype, method: "add", targetIndex: 0, argIndex: 0 },
    { proto: DOMTokenList.prototype, method: "remove", targetIndex: 0, argIndex: 0 },
    { proto: DOMTokenList.prototype, method: "toggle", targetIndex: 0, argIndex: 0 },
    { proto: CSSStyleDeclaration.prototype, method: "setProperty", targetIndex: 0, argIndex: 0 },
];

methodsToOverride.forEach(({ proto, method, targetIndex, argIndex }) => {
    try {
        if (!proto || !proto[method]) {
            console.warn(`[Interceptor] Skipping DOM override: ${proto.constructor.name}.${method} (not found)`);
            return;
        }

        const originalMethod = proto[method];

        proto[method] = function (...args) {
            const registrationStack = new Error().stack;

            let targetNode = null;
            if (targetIndex === -1) {
                targetNode = this;
            }

            __safeLog__(() => {
                __originalConsoleLog__(JSON.stringify({
                type: 'DOM Mutation',
                method: `${proto.constructor.name}.${method}`,
                target: serializeNode(targetNode),
                arguments: safeStringify(args),
                registrationStack: registrationStack
                }));
            });

            return originalMethod.apply(this, args);
        };
    } catch (err) {
        console.error(`[Interceptor] Failed to override ${proto.constructor.name}.${method}:`, err);
    }
});

const originalEval = window.eval;
window.eval = function (code) {
    const registrationStack = new Error().stack;
    const codeString = String(code);
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Eval Call',
        codePreview: codeString.substring(0, 200),
        codeLength: codeString.length,
        registrationStack: registrationStack
        }));
    });
    return originalEval.call(this, code);
};

const OriginalFunction = Function;
window.Function = function (...args) {
    const registrationStack = new Error().stack;
    const code = args[args.length - 1] || '';
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Function Constructor',
        codePreview: code.substring(0, 200),
        codeLength: code.length,
        registrationStack: registrationStack
        }));
    });
    return OriginalFunction.apply(this, args);
};

const originalQuerySelector = Document.prototype.querySelector;
Document.prototype.querySelector = function(selectors) {
    const registrationStack = new Error().stack;

    const lowerSelectors = selectors.toLowerCase();
    if (lowerSelectors.includes('password') || lowerSelectors.includes('pass') || lowerSelectors.includes('credit') || lowerSelectors.includes('card') || lowerSelectors.includes('cvv')) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Suspicious querySelector',
            selector: selectors,
            registrationStack: registrationStack
            }));
        });
    }
    return originalQuerySelector.apply(this, arguments);
};

const originalGetElementById = Document.prototype.getElementById;
Document.prototype.getElementById = function(id) {
    const registrationStack = new Error().stack;

    const lowerId = String(id).toLowerCase();
    if (lowerId.includes('password') || lowerId.includes('pass') || lowerId.includes('credit') || lowerId.includes('card') || lowerId.includes('cvv')) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Suspicious getElementById',
            id: id,
            registrationStack: registrationStack
            }));
        });
    }
    return originalGetElementById.apply(this, arguments);
};

const originalAtob = window.atob;
window.atob = function(encodedData) {
    const registrationStack = new Error().stack;
    const result = originalAtob.apply(this, arguments);

    const decodedString = String(result);
    if (decodedString.length > 20 && (decodedString.includes('function') || decodedString.includes('var') || decodedString.includes('('))) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'atob De-obfuscation',
            inputPreview: safeStringify(encodedData, 1, 0, 100),
            outputPreview: safeStringify(decodedString, 1, 0, 200),
            outputLength: decodedString.length,
            registrationStack: registrationStack
            }));
        });
    }
    return result;
};

const originalFromCharCode = String.fromCharCode;
String.fromCharCode = function(...codes) {
    const registrationStack = new Error().stack;
    const result = originalFromCharCode.apply(this, arguments);

    if (result.length > 50) {
         __safeLog__(() => {
             __originalConsoleLog__(JSON.stringify({
             type: 'String.fromCharCode De-obfuscation',
             codeCount: codes.length,
             outputPreview: safeStringify(result, 1, 0, 200),
             outputLength: result.length,
             registrationStack: registrationStack
             }));
         });
    }
    return result;
};

const originalJSONParse = JSON.parse;
JSON.parse = function(text) {
    const registrationStack = new Error().stack;
    const result = originalJSONParse.apply(this, arguments);

    try {
        const textPreview = safeStringify(text, 1, 0, 200);
        let suspicious = false;
        if (typeof result === 'object' && result !== null) {
            for (const k in result) {
                if (typeof result[k] === 'string' && result[k].length > 100) {
                    suspicious = true;
                    break;
                }
            }
        }

        if (suspicious) {
             __safeLog__(() => {
                 __originalConsoleLog__(JSON.stringify({
                 type: 'JSON.parse Suspicious Payload',
                 textPreview: textPreview,
                 registrationStack: registrationStack
                 }));
             });
        }
    } catch(e) {}

    return result;
};

const originalDocWrite = Document.prototype.write;
Document.prototype.write = function (...args) {
    const registrationStack = new Error().stack;
    const contentString = args.map(arg => String(arg)).join('');

    if (contentString && contentString.includes('<')) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Document.write Call',
            contentPreview: contentString.substring(0, 200),
            contentLength: contentString.length,
            isScript: contentString.toLowerCase().includes('<script'),
            registrationStack: registrationStack
            }));
        });
    }
    return originalDocWrite.apply(this, args);
};

const originalDocWriteLn = Document.prototype.writeln;
Document.prototype.writeln = function (...args) {
    const registrationStack = new Error().stack;
    const contentString = args.map(arg => String(arg)).join('');

    if (contentString && contentString.includes('<')) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Document.writeln Call',
            contentPreview: contentString.substring(0, 200),
            contentLength: contentString.length,
            isScript: contentString.toLowerCase().includes('<script'),
            registrationStack: registrationStack
            }));
        });
    }
    return originalDocWriteLn.apply(this, args);
};

function createPropertyInterceptorWithFilter(obj, prop, objectName) {
    try {
        const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
        if (!descriptor || !descriptor.configurable) return;

        const originalGetter = descriptor.get;
        const originalSetter = descriptor.set;

        Object.defineProperty(obj, prop, {
            get: function() {
                return originalGetter ? originalGetter.call(this) : descriptor.value;
            },
            set: function(value) {
                if (__shouldSkipLogging__()) {
                    if (originalSetter) {
                        return originalSetter.call(this, value);
                    } else {
                        descriptor.value = value;
                    }
                    return;
                }

                const registrationStack = new Error().stack;
                const valueString = String(value);

                if (valueString.toLowerCase().includes('<script') ||
                    valueString.toLowerCase().includes('javascript:') ||
                    valueString.toLowerCase().includes('onerror=') ||
                    valueString.toLowerCase().includes('onload=') ||
                    prop.toLowerCase() === 'srcdoc') {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'HTML Property Write (Suspicious)',
                        object: objectName,
                        property: prop,
                        target: serializeNode(this),
                        contentPreview: valueString.substring(0, 200),
                        contentLength: valueString.length,
                        registrationStack: registrationStack
                        }));
                    });
                }

                if (originalSetter) {
                    return originalSetter.call(this, value);
                } else {
                    descriptor.value = value;
                }
            },
            configurable: true,
            enumerable: descriptor.enumerable
        });
    } catch (e) {
        __safeLog__(() => {
            __originalConsoleLog__(`[Interceptor] Failed to intercept ${objectName}.${prop}:`, e.message);
        });
    }
}

if (typeof Element !== 'undefined') {
    createPropertyInterceptorWithFilter(Element.prototype, 'innerHTML', 'element');
    createPropertyInterceptorWithFilter(Element.prototype, 'outerHTML', 'element');
}

const originalWindowOpen = window.open;
window.open = function (url, target, features) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Popup Opened',
        url: url,
        target: target,
        features: features,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalWindowOpen.apply(this, arguments);
};

const hrefDescriptor = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
if (hrefDescriptor && hrefDescriptor.set && hrefDescriptor.configurable) {
    Object.defineProperty(Location.prototype, 'href', {
        get: hrefDescriptor.get,
        set: function(value) {
            const registrationStack = new Error().stack;
            __safeLog__(() => {
                __originalConsoleLog__(JSON.stringify({
                type: 'Redirect via location.href',
                newUrl: value,
                currentUrl: window.location.href,
                timestamp: Date.now(),
                registrationStack: registrationStack
                }));
            });
            return hrefDescriptor.set.call(this, value);
        },
        configurable: true
    });
}

const originalLocationReplace = Location.prototype.replace;
Location.prototype.replace = function(url) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Redirect via location.replace',
        newUrl: url,
        currentUrl: window.location.href,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalLocationReplace.call(this, url);
};

const originalLocationAssign = Location.prototype.assign;
Location.prototype.assign = function(url) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Redirect via location.assign',
        newUrl: url,
        currentUrl: window.location.href,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalLocationAssign.call(this, url);
};

window.addEventListener('beforeunload', (event) => {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Page Unload/Redirect Initiated',
        timestamp: Date.now(),
        currentUrl: window.location.href,
        returnValue: event.returnValue,
        registrationStack: registrationStack
        }));
    });
}, true);

window.addEventListener('unload', (event) => {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Page Unloaded',
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
}, true);

const originalAlert = window.alert;
window.alert = function(message) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Alert Dialog',
        message: safeStringify(message),
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalAlert.apply(this, arguments);
};

const originalConfirm = window.confirm;
window.confirm = function(message) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Confirm Dialog',
        message: safeStringify(message),
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalConfirm.apply(this, arguments);
};

const originalPrompt = window.prompt;
window.prompt = function(message, defaultValue) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Prompt Dialog',
        message: safeStringify(message),
        defaultValue: defaultValue,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalPrompt.apply(this, arguments);
};

const originalCreateObjectURL = URL.createObjectURL;
URL.createObjectURL = function(blob) {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Blob URL Created',
        blobType: blob.type,
        blobSize: blob.size,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalCreateObjectURL.apply(this, arguments);
};

const originalAnchorClick = HTMLAnchorElement.prototype.click;
HTMLAnchorElement.prototype.click = function() {
    const registrationStack = new Error().stack;
    if (this.download || this.href.startsWith('blob:')) {
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Download Triggered',
            href: this.href,
            download: this.download,
            target: this.target,
            timestamp: Date.now(),
            registrationStack: registrationStack
            }));
        });
    }
    return originalAnchorClick.apply(this, arguments);
};

window.addEventListener('blur', (event) => {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Window Blur (Possible Popup)',
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
}, true);

const originalRequestFullscreen = Element.prototype.requestFullscreen;
Element.prototype.requestFullscreen = function() {
    const registrationStack = new Error().stack;
    __safeLog__(() => {
        __originalConsoleLog__(JSON.stringify({
        type: 'Fullscreen Requested',
        element: this.tagName,
        elementId: this.id,
        elementClass: this.className,
        timestamp: Date.now(),
        registrationStack: registrationStack
        }));
    });
    return originalRequestFullscreen.apply(this, arguments);
};

if (navigator.clipboard && navigator.clipboard.writeText) {
    const originalClipboardWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function(text) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Clipboard Write',
            textLength: text ? text.length : 0,
            textPreview: text ? text.substring(0, 100) : '',
            timestamp: Date.now(),
            registrationStack: registrationStack
            }));
        });
        return originalClipboardWrite(text);
    };
}

if (navigator.clipboard && navigator.clipboard.readText) {
    const originalClipboardRead = navigator.clipboard.readText.bind(navigator.clipboard);
    navigator.clipboard.readText = function() {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Clipboard Read',
            timestamp: Date.now(),
            registrationStack: registrationStack
            }));
        });
        return originalClipboardRead();
    };
}

if (Element.prototype.attachShadow) {
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(options) {
        const registrationStack = new Error().stack;
        __safeLog__(() => {
            __originalConsoleLog__(JSON.stringify({
            type: 'Shadow DOM Attached',
            element: this.tagName,
            elementId: this.id,
            elementClass: this.className,
            mode: options && options.mode,
            delegatesFocus: options && options.delegatesFocus,
            registrationStack: registrationStack
            }));
        });
        return originalAttachShadow.apply(this, arguments);
    };
}

const originalToString = Function.prototype.toString;
Function.prototype.toString = function() {
    const result = originalToString.apply(this, arguments);

    const stack = new Error().stack;
    if (stack && !__shouldSkipLogging__()) {
        const suspiciousFunctions = ['fetch', 'XMLHttpRequest', 'eval', 'WebSocket',
                                      'addEventListener', 'appendChild', 'setAttribute'];

        for (const fname of suspiciousFunctions) {
            if (this.name === fname || stack.includes(fname)) {
                __safeLog__(() => {
                    __originalConsoleLog__(JSON.stringify({
                    type: 'Hook Detection Attempt',
                    functionName: this.name || '[anonymous]',
                    callerStack: stack.substring(0, 500),
                    timestamp: Date.now()
                    }));
                });
                break;
            }
        }
    }

    const monitoredFunctions = [
        window.fetch, window.eval,
        XMLHttpRequest.prototype.open, XMLHttpRequest.prototype.send,
        WebSocket.prototype.send,
        Element.prototype.setAttribute,
        Node.prototype.appendChild
    ];

    if (monitoredFunctions.includes(this)) {
        const functionName = this.name || 'anonymous';
        return `function ${functionName}() { [native code] }`;
    }

    return result;
};

if (typeof MutationObserver !== 'undefined') {
    try {
        const nativeMutationObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (__shouldSkipLogging__()) return;

                const isSignificant =
                    (mutation.type === 'childList' && mutation.addedNodes.length > 0) ||
                    (mutation.type === 'attributes' &&
                     (mutation.attributeName === 'src' ||
                      mutation.attributeName === 'href' ||
                      mutation.attributeName === 'srcdoc'));

                if (isSignificant) {
                    __safeLog__(() => {
                        __originalConsoleLog__(JSON.stringify({
                        type: 'MutationObserver (Native)',
                        mutationType: mutation.type,
                        target: serializeNode(mutation.target),
                        addedNodesCount: (mutation.addedNodes && mutation.addedNodes.length) || 0,
                        removedNodesCount: (mutation.removedNodes && mutation.removedNodes.length) || 0,
                        attributeName: mutation.attributeName,
                        oldValue: mutation.oldValue ? safeStringify(mutation.oldValue, 1, 0, 100) : null,
                        timestamp: Date.now()
                        }));
                    });
                }
            });
        });

        setTimeout(() => {
            nativeMutationObserver.observe(document.documentElement, {
                childList: true,
                attributes: true,
                attributeFilter: ['src', 'href', 'srcdoc', 'onclick', 'onerror', 'onload'],
                subtree: true,
                attributeOldValue: true
            });
        }, 1000);
    } catch (e) {
        __safeLog__(() => {
            __originalConsoleLog__('[Interceptor] Failed to initialize native MutationObserver:', e.message);
        });
    }
}

__safeLog__(() => {
    __originalConsoleLog__(JSON.stringify({
    type: 'Monitoring Script Fully Loaded',
    timestamp: Date.now(),
    version: '2.0.0-enhanced'
    }));
});