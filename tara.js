/*! For license information please see tara.js.LICENSE.txt */ ! function(e, t) {
    "object" == typeof exports && "object" == typeof module ? module.exports = t() : "function" == typeof define && define.amd ? define("tara", [], t) : "object" == typeof exports ? exports.tara = t() : e.tara = t()
}(self, (function() {
    return (() => {
        var __webpack_modules__ = {
                4537: e => {
                    "use strict";
                    e.exports = function(e, t) {
                        for (var n = new Array(arguments.length - 1), i = 0, o = 2, r = !0; o < arguments.length;) n[i++] = arguments[o++];
                        return new Promise((function(o, a) {
                            n[i] = function(e) {
                                if (r)
                                    if (r = !1, e) a(e);
                                    else {
                                        for (var t = new Array(arguments.length - 1), n = 0; n < t.length;) t[n++] = arguments[n];
                                        o.apply(null, t)
                                    }
                            };
                            try {
                                e.apply(t || null, n)
                            } catch (e) {
                                r && (r = !1, a(e))
                            }
                        }))
                    }
                },
                7419: (e, t) => {
                    "use strict";
                    var n = t;
                    n.length = function(e) {
                        var t = e.length;
                        if (!t) return 0;
                        for (var n = 0; --t % 4 > 1 && "=" === e.charAt(t);) ++n;
                        return Math.ceil(3 * e.length) / 4 - n
                    };
                    for (var i = new Array(64), o = new Array(123), r = 0; r < 64;) o[i[r] = r < 26 ? r + 65 : r < 52 ? r + 71 : r < 62 ? r - 4 : r - 59 | 43] = r++;
                    n.encode = function(e, t, n) {
                        for (var o, r = null, a = [], s = 0, l = 0; t < n;) {
                            var c = e[t++];
                            switch (l) {
                                case 0:
                                    a[s++] = i[c >> 2], o = (3 & c) << 4, l = 1;
                                    break;
                                case 1:
                                    a[s++] = i[o | c >> 4], o = (15 & c) << 2, l = 2;
                                    break;
                                case 2:
                                    a[s++] = i[o | c >> 6], a[s++] = i[63 & c], l = 0
                            }
                            s > 8191 && ((r || (r = [])).push(String.fromCharCode.apply(String, a)), s = 0)
                        }
                        return l && (a[s++] = i[o], a[s++] = 61, 1 === l && (a[s++] = 61)), r ? (s && r.push(String.fromCharCode.apply(String, a.slice(0, s))), r.join("")) : String.fromCharCode.apply(String, a.slice(0, s))
                    };
                    var a = "invalid encoding";
                    n.decode = function(e, t, n) {
                        for (var i, r = n, s = 0, l = 0; l < e.length;) {
                            var c = e.charCodeAt(l++);
                            if (61 === c && s > 1) break;
                            if (void 0 === (c = o[c])) throw Error(a);
                            switch (s) {
                                case 0:
                                    i = c, s = 1;
                                    break;
                                case 1:
                                    t[n++] = i << 2 | (48 & c) >> 4, i = c, s = 2;
                                    break;
                                case 2:
                                    t[n++] = (15 & i) << 4 | (60 & c) >> 2, i = c, s = 3;
                                    break;
                                case 3:
                                    t[n++] = (3 & i) << 6 | c, s = 0
                            }
                        }
                        if (1 === s) throw Error(a);
                        return n - r
                    }, n.test = function(e) {
                        return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(e)
                    }
                },
                9211: e => {
                    "use strict";

                    function t() {
                        this._listeners = {}
                    }
                    e.exports = t, t.prototype.on = function(e, t, n) {
                        return (this._listeners[e] || (this._listeners[e] = [])).push({
                            fn: t,
                            ctx: n || this
                        }), this
                    }, t.prototype.off = function(e, t) {
                        if (void 0 === e) this._listeners = {};
                        else if (void 0 === t) this._listeners[e] = [];
                        else
                            for (var n = this._listeners[e], i = 0; i < n.length;) n[i].fn === t ? n.splice(i, 1) : ++i;
                        return this
                    }, t.prototype.emit = function(e) {
                        var t = this._listeners[e];
                        if (t) {
                            for (var n = [], i = 1; i < arguments.length;) n.push(arguments[i++]);
                            for (i = 0; i < t.length;) t[i].fn.apply(t[i++].ctx, n)
                        }
                        return this
                    }
                },
                945: e => {
                    "use strict";

                    function t(e) {
                        return "undefined" != typeof Float32Array ? function() {
                            var t = new Float32Array([-0]),
                                n = new Uint8Array(t.buffer),
                                i = 128 === n[3];

                            function o(e, i, o) {
                                t[0] = e, i[o] = n[0], i[o + 1] = n[1], i[o + 2] = n[2], i[o + 3] = n[3]
                            }

                            function r(e, i, o) {
                                t[0] = e, i[o] = n[3], i[o + 1] = n[2], i[o + 2] = n[1], i[o + 3] = n[0]
                            }

                            function a(e, i) {
                                return n[0] = e[i], n[1] = e[i + 1], n[2] = e[i + 2], n[3] = e[i + 3], t[0]
                            }

                            function s(e, i) {
                                return n[3] = e[i], n[2] = e[i + 1], n[1] = e[i + 2], n[0] = e[i + 3], t[0]
                            }
                            e.writeFloatLE = i ? o : r, e.writeFloatBE = i ? r : o, e.readFloatLE = i ? a : s, e.readFloatBE = i ? s : a
                        }() : function() {
                            function t(e, t, n, i) {
                                var o = t < 0 ? 1 : 0;
                                if (o && (t = -t), 0 === t) e(1 / t > 0 ? 0 : 2147483648, n, i);
                                else if (isNaN(t)) e(2143289344, n, i);
                                else if (t > 34028234663852886e22) e((o << 31 | 2139095040) >>> 0, n, i);
                                else if (t < 11754943508222875e-54) e((o << 31 | Math.round(t / 1401298464324817e-60)) >>> 0, n, i);
                                else {
                                    var r = Math.floor(Math.log(t) / Math.LN2);
                                    e((o << 31 | r + 127 << 23 | 8388607 & Math.round(t * Math.pow(2, -r) * 8388608)) >>> 0, n, i)
                                }
                            }

                            function a(e, t, n) {
                                var i = e(t, n),
                                    o = 2 * (i >> 31) + 1,
                                    r = i >>> 23 & 255,
                                    a = 8388607 & i;
                                return 255 === r ? a ? NaN : o * (1 / 0) : 0 === r ? 1401298464324817e-60 * o * a : o * Math.pow(2, r - 150) * (a + 8388608)
                            }
                            e.writeFloatLE = t.bind(null, n), e.writeFloatBE = t.bind(null, i), e.readFloatLE = a.bind(null, o), e.readFloatBE = a.bind(null, r)
                        }(), "undefined" != typeof Float64Array ? function() {
                            var t = new Float64Array([-0]),
                                n = new Uint8Array(t.buffer),
                                i = 128 === n[7];

                            function o(e, i, o) {
                                t[0] = e, i[o] = n[0], i[o + 1] = n[1], i[o + 2] = n[2], i[o + 3] = n[3], i[o + 4] = n[4], i[o + 5] = n[5], i[o + 6] = n[6], i[o + 7] = n[7]
                            }

                            function r(e, i, o) {
                                t[0] = e, i[o] = n[7], i[o + 1] = n[6], i[o + 2] = n[5], i[o + 3] = n[4], i[o + 4] = n[3], i[o + 5] = n[2], i[o + 6] = n[1], i[o + 7] = n[0]
                            }

                            function a(e, i) {
                                return n[0] = e[i], n[1] = e[i + 1], n[2] = e[i + 2], n[3] = e[i + 3], n[4] = e[i + 4], n[5] = e[i + 5], n[6] = e[i + 6], n[7] = e[i + 7], t[0]
                            }

                            function s(e, i) {
                                return n[7] = e[i], n[6] = e[i + 1], n[5] = e[i + 2], n[4] = e[i + 3], n[3] = e[i + 4], n[2] = e[i + 5], n[1] = e[i + 6], n[0] = e[i + 7], t[0]
                            }
                            e.writeDoubleLE = i ? o : r, e.writeDoubleBE = i ? r : o, e.readDoubleLE = i ? a : s, e.readDoubleBE = i ? s : a
                        }() : function() {
                            function t(e, t, n, i, o, r) {
                                var a = i < 0 ? 1 : 0;
                                if (a && (i = -i), 0 === i) e(0, o, r + t), e(1 / i > 0 ? 0 : 2147483648, o, r + n);
                                else if (isNaN(i)) e(0, o, r + t), e(2146959360, o, r + n);
                                else if (i > 17976931348623157e292) e(0, o, r + t), e((a << 31 | 2146435072) >>> 0, o, r + n);
                                else {
                                    var s;
                                    if (i < 22250738585072014e-324) e((s = i / 5e-324) >>> 0, o, r + t), e((a << 31 | s / 4294967296) >>> 0, o, r + n);
                                    else {
                                        var l = Math.floor(Math.log(i) / Math.LN2);
                                        1024 === l && (l = 1023), e(4503599627370496 * (s = i * Math.pow(2, -l)) >>> 0, o, r + t), e((a << 31 | l + 1023 << 20 | 1048576 * s & 1048575) >>> 0, o, r + n)
                                    }
                                }
                            }

                            function a(e, t, n, i, o) {
                                var r = e(i, o + t),
                                    a = e(i, o + n),
                                    s = 2 * (a >> 31) + 1,
                                    l = a >>> 20 & 2047,
                                    c = 4294967296 * (1048575 & a) + r;
                                return 2047 === l ? c ? NaN : s * (1 / 0) : 0 === l ? 5e-324 * s * c : s * Math.pow(2, l - 1075) * (c + 4503599627370496)
                            }
                            e.writeDoubleLE = t.bind(null, n, 0, 4), e.writeDoubleBE = t.bind(null, i, 4, 0), e.readDoubleLE = a.bind(null, o, 0, 4), e.readDoubleBE = a.bind(null, r, 4, 0)
                        }(), e
                    }

                    function n(e, t, n) {
                        t[n] = 255 & e, t[n + 1] = e >>> 8 & 255, t[n + 2] = e >>> 16 & 255, t[n + 3] = e >>> 24
                    }

                    function i(e, t, n) {
                        t[n] = e >>> 24, t[n + 1] = e >>> 16 & 255, t[n + 2] = e >>> 8 & 255, t[n + 3] = 255 & e
                    }

                    function o(e, t) {
                        return (e[t] | e[t + 1] << 8 | e[t + 2] << 16 | e[t + 3] << 24) >>> 0
                    }

                    function r(e, t) {
                        return (e[t] << 24 | e[t + 1] << 16 | e[t + 2] << 8 | e[t + 3]) >>> 0
                    }
                    e.exports = t(t)
                },
                7199: module => {
                    "use strict";

                    function inquire(moduleName) {
                        try {
                            var mod = eval("quire".replace(/^/, "re"))(moduleName);
                            if (mod && (mod.length || Object.keys(mod).length)) return mod
                        } catch (e) {}
                        return null
                    }
                    module.exports = inquire
                },
                6662: e => {
                    "use strict";
                    e.exports = function(e, t, n) {
                        var i = n || 8192,
                            o = i >>> 1,
                            r = null,
                            a = i;
                        return function(n) {
                            if (n < 1 || n > o) return e(n);
                            a + n > i && (r = e(i), a = 0);
                            var s = t.call(r, a, a += n);
                            return 7 & a && (a = 1 + (7 | a)), s
                        }
                    }
                },
                4997: (e, t) => {
                    "use strict";
                    var n = t;
                    n.length = function(e) {
                        for (var t = 0, n = 0, i = 0; i < e.length; ++i)(n = e.charCodeAt(i)) < 128 ? t += 1 : n < 2048 ? t += 2 : 55296 == (64512 & n) && 56320 == (64512 & e.charCodeAt(i + 1)) ? (++i, t += 4) : t += 3;
                        return t
                    }, n.read = function(e, t, n) {
                        if (n - t < 1) return "";
                        for (var i, o = null, r = [], a = 0; t < n;)(i = e[t++]) < 128 ? r[a++] = i : i > 191 && i < 224 ? r[a++] = (31 & i) << 6 | 63 & e[t++] : i > 239 && i < 365 ? (i = ((7 & i) << 18 | (63 & e[t++]) << 12 | (63 & e[t++]) << 6 | 63 & e[t++]) - 65536, r[a++] = 55296 + (i >> 10), r[a++] = 56320 + (1023 & i)) : r[a++] = (15 & i) << 12 | (63 & e[t++]) << 6 | 63 & e[t++], a > 8191 && ((o || (o = [])).push(String.fromCharCode.apply(String, r)), a = 0);
                        return o ? (a && o.push(String.fromCharCode.apply(String, r.slice(0, a))), o.join("")) : String.fromCharCode.apply(String, r.slice(0, a))
                    }, n.write = function(e, t, n) {
                        for (var i, o, r = n, a = 0; a < e.length; ++a)(i = e.charCodeAt(a)) < 128 ? t[n++] = i : i < 2048 ? (t[n++] = i >> 6 | 192, t[n++] = 63 & i | 128) : 55296 == (64512 & i) && 56320 == (64512 & (o = e.charCodeAt(a + 1))) ? (i = 65536 + ((1023 & i) << 10) + (1023 & o), ++a, t[n++] = i >> 18 | 240, t[n++] = i >> 12 & 63 | 128, t[n++] = i >> 6 & 63 | 128, t[n++] = 63 & i | 128) : (t[n++] = i >> 12 | 224, t[n++] = i >> 6 & 63 | 128, t[n++] = 63 & i | 128);
                        return n - r
                    }
                },
                5958: function(e, t, n) {
                    "use strict";
                    var i = this && this.__decorate || function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        },
                        o = this && this.__metadata || function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        },
                        r = this && this.__param || function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.CerebroClient = void 0;
                    const a = n(8103);
                    n(8660);
                    const s = n(3204),
                        l = n(9854),
                        c = n(9176);
                    let d = class {
                        constructor(e, t, n) {
                            this.handlers = new Map, this.errorHandlers = new Map, this.requests = new Map, this.serverInitiatedAllowedMsgTypes = [], this.config = c.DefaultConfig, this.active = !1, this.logService = e, this.merge = t, this.connection = n
                        }
                        init(e, t) {
                            this.active ? this.logService.info("CerebroClient is already initialized.") : (this.config = this.merge(c.DefaultConfig, t || {}), this.logService.debug(`CerebroClient is in initialization process. Config: ${JSON.stringify(this.config)}`), this.connection.initialize(e, this.config), this.connection.addMessagesListener(this.handleMessage.bind(this)), this.active = !0)
                        }
                        registerHandler(e, t, n) {
                            if (this.handlers.has(e)) {
                                const t = `Can't register handler: A handler for message type '${e}' is already exist.`;
                                throw this.logService.error(t), new Error(t)
                            }
                            this.handlers.set(e, t), n && this.serverInitiatedAllowedMsgTypes.push(e)
                        }
                        registerErrorHandler(e, t) {
                            if (this.errorHandlers.has(e)) {
                                const t = `Can't register error handler: A handler for message type '${e}' is already exist.`;
                                throw this.logService.error(t), new Error(t)
                            }
                            this.errorHandlers.set(e, t)
                        }
                        sendMessage(e, t, n) {
                            const i = Object.assign({
                                messageType: e,
                                timeout: this.config.defaultMessageTimeout,
                                retryTimeout: this.config.defaultMessageRetryTimeout,
                                requestID: "",
                                attempts: 1,
                                originalMessage: t,
                                timeSent: Date.now()
                            }, n);
                            try {
                                i.requestID = this.connection.sendMessage(e, i.originalMessage, i.requestID), this.requests.set(i.requestID, i), i.retryTimeout && i.timeout && setTimeout((() => this.sendMessageRetryHandler(i)), i.retryTimeout)
                            } catch (e) {
                                throw this.logService.error("Error while sending message: ", t, "; error: ", e), e
                            }
                            return i.requestID
                        }
                        addConnectionEventListener(e, t) {
                            this.connection.addEventListener(e, t)
                        }
                        removeConnectionEventListener(e, t) {
                            this.connection.removeEventListener(e, t)
                        }
                        addConnectionStatusListeners(e, t) {
                            this.connection.addConnectionStatusListeners(e, t)
                        }
                        handleMessage(e) {
                            const t = e.detail;
                            this.logService.debug("Incoming Cerebro message: " + JSON.stringify(t));
                            let n = null;
                            if (t.requestID) {
                                if (n = this.requests.get(t.requestID), !n) return void this.logService.error(`Received message for not exist request id: ${t.requestID}.`);
                                this.requests.delete(t.requestID)
                            } else if (-1 === this.serverInitiatedAllowedMsgTypes.indexOf(t.type)) return void this.logService.error("Received message without request ID");
                            if (t.type === l.CerebroMessageType.ServerError) {
                                const e = t.message;
                                return void this.responseError(e.original_type, "Server Error" + (e.data ? `: ${e.data}` : ""), n)
                            }
                            if (t.type === l.CerebroMessageType.Ack) return;
                            const i = this.handlers.get(t.type);
                            if (i) try {
                                i(t.message)
                            } catch (e) {
                                this.logService.error(`Error while executing callback for message type ${t.type}: `, e)
                            } else this.logService.error(`Missing handler for message type: ${t.type}`)
                        }
                        sendMessageRetryHandler(e) {
                            let t = null;
                            if (this.requests.has(e.requestID))
                                if (e.attempts > this.config.maxMessageRetryAttempts && (t = "max retries reached"), Date.now() - e.timeSent >= e.timeout && (t = "timeout reached"), t) this.responseError(e.messageType, `Can't send message. RequestID: ${e.requestID}, error: ${t}`, e);
                                else {
                                    e.attempts++;
                                    try {
                                        this.sendMessage(e.messageType, e.originalMessage, e)
                                    } catch (t) {
                                        this.logService.error(`Error when retry to send message. RequestID: ${e.requestID}, error:`, t)
                                    }
                                }
                        }
                        responseError(e, t, n) {
                            this.logService.error(`CerebroClient Error: ${t}`);
                            const i = this.errorHandlers.get(e);
                            if (i) try {
                                i(t, n)
                            } catch (t) {
                                this.logService.error(`Error while executing error callback for message type ${e}: `, t)
                            } else this.logService.error(`Missing error handler for message type: ${e}`)
                        }
                    };
                    d = i([(0, a.injectable)(), r(0, (0, a.inject)(s.TYPES.ILogger)), r(1, (0, a.inject)(s.TYPES.IMerge)), r(2, (0, a.inject)(s.TYPES.ICerebroConnection)), o("design:paramtypes", [Object, Function, Object])], d), t.CerebroClient = d
                },
                197: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.DisableRetrySendMessageOptions = void 0, t.DisableRetrySendMessageOptions = {
                        retryTimeout: 0,
                        timeout: 0
                    }
                },
                9176: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.DefaultConfig = void 0, t.DefaultConfig = {
                        reconnectConfig: {
                            backoffFactor: 1.5,
                            randomFactor: .1,
                            startingDelay: 2e3,
                            maxTimeout: 3e5
                        },
                        heartbeatConfig: {
                            pingInterval: 5e3,
                            pingTimeout: 950,
                            missingHeartbeatInterval: 1e3,
                            missingHeartbeatThreshold: 3,
                            reconnectionHeartbeatTimeout: 1e3,
                            reconnectionHeartbeatThreshold: 3
                        },
                        defaultMessageTimeout: 1e4,
                        defaultMessageRetryTimeout: 3e3,
                        maxMessageRetryAttempts: 5
                    }
                },
                4559: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    })
                },
                322: function(e, t, n) {
                    "use strict";
                    var i = this && this.__decorate || function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        },
                        o = this && this.__metadata || function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        },
                        r = this && this.__param || function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.CerebroConnection = void 0;
                    const a = n(8103);
                    n(8660);
                    const s = n(3204),
                        l = n(9999),
                        c = n(9854),
                        d = n(9478),
                        u = n(9176),
                        p = n(757),
                        h = !0;
                    let f = class {
                        constructor(e, t, n) {
                            this.logService = e, this.uuid = t, this.heartbeat = n, this.pendingReconnect = null, this.attempts = 0, this.reconnects = 0, this.isConnected = !1, this.isReady = !1, this.isActive = !1, this.socket = null, this.config = u.DefaultConfig, this.listeners = {
                                message: [],
                                disconnect: [],
                                ready: []
                            }
                        }
                        initialize(e, t) {
                            this.isActive && this.handleError("CerebroConnection was already initialized.", h), e ? (this.isActive = !0, this.config = t, this.url = e, this.connect()) : this.handleError("CerebroConnection: initialization error: missing url", h)
                        }
                        sendMessage(e, t, n) {
                            let i;
                            const o = n || this.uuid.v4();
                            if (t instanceof d.client2cerebro.RawBinaryMessage) t.RequestID = o, i = d.client2cerebro.RawBinaryMessage.encode(t).finish();
                            else {
                                const n = {
                                    message: t,
                                    requestID: o,
                                    type: e
                                };
                                i = JSON.stringify(n)
                            }
                            this.socket || this.handleError("Can't send message: websocket is not initialized yet", h);
                            try {
                                this.socket.send(i)
                            } catch (e) {
                                this.handleError(`CerebroConnection error while sending message: ${JSON.stringify(e)}`, h)
                            }
                            return o
                        }
                        addConnectionStatusListeners(e, t) {
                            this.addEventListener(l.ConnectionEvents.Disconnect, e), this.addEventListener(l.ConnectionEvents.Ready, t)
                        }
                        addMessagesListener(e) {
                            this.addEventListener(l.ConnectionEvents.Message, e)
                        }
                        addEventListener(e, t) {
                            Object.prototype.hasOwnProperty.call(this.listeners, e) || (this.listeners[e] = []), this.listeners[e].push(t)
                        }
                        removeEventListener(e, t) {
                            if (!Object.prototype.hasOwnProperty.call(this.listeners, e)) return;
                            const n = this.listeners[e],
                                i = n.indexOf(t); - 1 !== i && n.splice(i, 1)
                        }
                        close() {
                            this.clearPendingReconnectIfNeeded(), this.closeSocketIfNeeded()
                        }
                        dispatchEvent(e) {
                            Object.prototype.hasOwnProperty.call(this.listeners, e.type) && this.listeners[e.type].forEach((t => {
                                try {
                                    t(e)
                                } catch (t) {
                                    this.logService.error(`CerebroConnection error while executing callback for type: ${e.type}. Error: `, t)
                                }
                            }))
                        }
                        onReady() {
                            this.dispatchEvent(new CustomEvent(l.ConnectionEvents.Ready)), 1 === this.reconnects && this.dispatchEvent(new CustomEvent(l.ConnectionEvents.ReadyOnce))
                        }
                        OnDisconnect() {
                            this.isConnected = !1, this.isReady = !1, this.dispatchEvent(new CustomEvent(l.ConnectionEvents.Disconnect)), !this.pendingReconnect && this.isActive && this.connect()
                        }
                        closeSocketIfNeeded() {
                            if (this.socket && this.socket.readyState !== WebSocket.CLOSED && this.socket.readyState !== WebSocket.CLOSING) try {
                                this.socket.close()
                            } catch (e) {
                                this.logService.error("Error while closing old socket: ", e)
                            } finally {
                                this.socket = null
                            }
                        }
                        connect() {
                            this.isReady || (this.closeSocketIfNeeded(), this.attempts++, this.socket = new WebSocket(this.url), this.pendingReconnect = setTimeout((() => {
                                this.pendingReconnect = null, this.connect()
                            }), this.getReconnectionDelay()), this.socket.addEventListener("open", (e => {
                                e.target === this.socket && (this.isConnected = !0, this.attempts = 0, this.reconnects++, this.initializeProtocol())
                            })), this.socket.addEventListener("error", (e => {
                                e.target === this.socket && this.logService.error("Cerebro socket error")
                            })), this.socket.addEventListener("message", (e => {
                                e.target === this.socket && this.onMessage(e)
                            })), this.socket.addEventListener("close", (e => {
                                e.target === this.socket && this.logService.error("Cerebro socket was closed: ", e)
                            })))
                        }
                        sendPingFunction() {
                            try {
                                this.sendMessage(c.CerebroMessageType.Ping, "")
                            } catch (e) {}
                        }
                        initializeProtocol() {
                            this.logService.info(`CerebroClient's websocket was opened. Tab ID: ${self.unbiasedTabID}, Top Level URL ID: ${self.unbiasedTopURLID}`);
                            const e = {
                                version: p.CEREBRO_PROTOCOL_VERSION,
                                tabID: self.unbiasedTabID,
                                topLevelURLID: self.unbiasedTopURLID,
                                userAgent: navigator.userAgent,
                                tenant: self.unbiasedTenant,
                                userSession: self.unbiasedUserSession,
                                failAt: self.failAt
                            };
                            this.sendMessage(c.CerebroMessageType.Init, e)
                        }
                        onMessage(e) {
                            const t = JSON.parse(e.data);
                            switch (t.type) {
                                case c.CerebroMessageType.Echo:
                                    this.isReady = !0, this.clearPendingReconnectIfNeeded(), this.heartbeat.start((() => this.sendPingFunction()), (() => this.onReady()), (() => this.OnDisconnect()), this.config.heartbeatConfig);
                                    break;
                                case c.CerebroMessageType.Ping:
                                    this.sendMessage(c.CerebroMessageType.Pong, "");
                                    break;
                                case c.CerebroMessageType.Pong:
                                    this.heartbeat.receivedPongMessage();
                                    break;
                                default:
                                    this.dispatchEvent(new CustomEvent(l.ConnectionEvents.Message, {
                                        detail: t
                                    }))
                            }
                        }
                        getReconnectionDelay() {
                            let e = Math.pow(this.config.reconnectConfig.backoffFactor, this.attempts) * this.config.reconnectConfig.startingDelay;
                            if (e > this.config.reconnectConfig.maxTimeout) return this.config.reconnectConfig.maxTimeout;
                            const t = e - e * this.config.reconnectConfig.randomFactor,
                                n = e + e * this.config.reconnectConfig.randomFactor;
                            return e = Math.random() * (n - t) + t, e
                        }
                        clearPendingReconnectIfNeeded() {
                            this.pendingReconnect && (clearTimeout(this.pendingReconnect), this.pendingReconnect = null)
                        }
                        handleError(e, t) {
                            if (this.logService.error(e), t) throw new Error(e)
                        }
                    };
                    f = i([(0, a.injectable)(), r(0, (0, a.inject)(s.TYPES.ILogger)), r(1, (0, a.inject)(s.TYPES.IUUID)), r(2, (0, a.inject)(s.TYPES.IHeartbeat)), o("design:paramtypes", [Object, Object, Object])], f), t.CerebroConnection = f
                },
                9999: (e, t) => {
                    "use strict";
                    var n;
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.ConnectionEvents = void 0, (n = t.ConnectionEvents || (t.ConnectionEvents = {})).Disconnect = "disconnect", n.Ready = "ready", n.ReadyOnce = "readyOnce", n.Message = "message"
                },
                4833: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    })
                },
                2438: function(e, t, n) {
                    "use strict";
                    var i = this && this.__decorate || function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        },
                        o = this && this.__metadata || function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.Heartbeat = void 0;
                    const r = n(8103);
                    n(8660);
                    const a = n(9176);
                    let s = class {
                        constructor() {
                            this.config = Object.assign({}, a.DefaultConfig.heartbeatConfig), this.receivedPong = !1, this.missingHeartbeats = 0, this.heartbeatIntervalID = 0, this.pingTimeoutID = 0, this.verifyHeartbeat = null
                        }
                        start(e, t, n, i) {
                            this.config = Object.assign(this.config, i), this.sendPingFunc = e, this.readyCallback = t, this.disconnectCallback = n, this.missingHeartbeats = 0, this.disconnectedHeartbeat(this.config.pingInterval, 0)
                        }
                        receivedPongMessage() {
                            this.pingTimeoutID && (this.pingTimeoutID = 0, this.receivedPong = !0, this.verifyHeartbeat && (this.clearTimeoutIfNeeded(), this.verifyHeartbeat()))
                        }
                        stop() {
                            this.clearTimeoutIfNeeded()
                        }
                        disconnectedHeartbeat(e, t) {
                            if (0 === e) return void this.readyCallback();
                            this.clearTimeoutIfNeeded();
                            const n = () => {
                                if (this.verifyHeartbeat = null, this.receivedPong) {
                                    if (t++, e = this.config.reconnectionHeartbeatTimeout, t >= this.config.reconnectionHeartbeatThreshold) {
                                        try {
                                            this.readyCallback && this.readyCallback()
                                        } catch (e) {}
                                        return void this.connectedHeartbeat(this.config.pingInterval)
                                    }
                                } else t = 0;
                                this.disconnectedHeartbeat(e, t)
                            };
                            this.heartbeatIntervalID = setTimeout(n, e), this.verifyHeartbeat = n, this.sendPing()
                        }
                        connectedHeartbeat(e) {
                            this.clearTimeoutIfNeeded(), this.heartbeatIntervalID = setTimeout((() => {
                                if (this.receivedPong) this.missingHeartbeats = 0, e = this.config.pingInterval;
                                else if (this.missingHeartbeats++, e = this.config.missingHeartbeatInterval, this.missingHeartbeats >= this.config.missingHeartbeatThreshold) return void(this.disconnectCallback && this.disconnectCallback());
                                this.connectedHeartbeat(e)
                            }), e), this.sendPing()
                        }
                        sendPing() {
                            this.receivedPong = !1, this.pingTimeoutID = setTimeout((() => {
                                this.pingTimeoutID = 0
                            }), this.config.pingTimeout);
                            try {
                                this.sendPingFunc && this.sendPingFunc()
                            } catch (e) {}
                        }
                        clearTimeoutIfNeeded() {
                            this.heartbeatIntervalID && (clearTimeout(this.heartbeatIntervalID), this.heartbeatIntervalID = 0)
                        }
                    };
                    s = i([(0, r.injectable)(), o("design:paramtypes", [])], s), t.Heartbeat = s
                },
                9689: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    })
                },
                3232: function(e, t, n) {
                    "use strict";
                    var i = this && this.__createBinding || (Object.create ? function(e, t, n, i) {
                            void 0 === i && (i = n), Object.defineProperty(e, i, {
                                enumerable: !0,
                                get: function() {
                                    return t[n]
                                }
                            })
                        } : function(e, t, n, i) {
                            void 0 === i && (i = n), e[i] = t[n]
                        }),
                        o = this && this.__setModuleDefault || (Object.create ? function(e, t) {
                            Object.defineProperty(e, "default", {
                                enumerable: !0,
                                value: t
                            })
                        } : function(e, t) {
                            e.default = t
                        }),
                        r = this && this.__importStar || function(e) {
                            if (e && e.__esModule) return e;
                            var t = {};
                            if (null != e)
                                for (var n in e) "default" !== n && Object.prototype.hasOwnProperty.call(e, n) && i(t, e, n);
                            return o(t, e), t
                        },
                        a = this && this.__exportStar || function(e, t) {
                            for (var n in e) "default" === n || Object.prototype.hasOwnProperty.call(t, n) || i(t, e, n)
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.CEREBRO_PROTOCOL_VERSION = t.TYPES = t.getContainerModule = t.getConversationsManager = t.getCerebroClient = void 0;
                    const s = r(n(8103));
                    n(8660);
                    const l = n(7140),
                        c = n(3204);
                    Object.defineProperty(t, "TYPES", {
                        enumerable: !0,
                        get: function() {
                            return c.PUBLIC_TYPES
                        }
                    }), t.getCerebroClient = function() {
                        return l.container.get(c.TYPES.ICerebroClient)
                    }, t.getConversationsManager = function() {
                        return l.container.get(c.TYPES.IConversationsManager)
                    }, t.getContainerModule = function() {
                        const e = l.container.get(c.TYPES.ICerebroClient),
                            t = l.container.get(c.TYPES.IConversationsManager);
                        return new s.ContainerModule((n => {
                            n(c.TYPES.ICerebroClient).toConstantValue(e), n(c.TYPES.IConversationsManager).toConstantValue(t)
                        }))
                    }, a(n(8442), t);
                    var d = n(757);
                    Object.defineProperty(t, "CEREBRO_PROTOCOL_VERSION", {
                        enumerable: !0,
                        get: function() {
                            return d.CEREBRO_PROTOCOL_VERSION
                        }
                    })
                },
                8442: function(e, t, n) {
                    "use strict";
                    var i = this && this.__createBinding || (Object.create ? function(e, t, n, i) {
                            void 0 === i && (i = n), Object.defineProperty(e, i, {
                                enumerable: !0,
                                get: function() {
                                    return t[n]
                                }
                            })
                        } : function(e, t, n, i) {
                            void 0 === i && (i = n), e[i] = t[n]
                        }),
                        o = this && this.__exportStar || function(e, t) {
                            for (var n in e) "default" === n || Object.prototype.hasOwnProperty.call(t, n) || i(t, e, n)
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), o(n(9854), t), o(n(197), t), o(n(4559), t), o(n(9999), t), o(n(4833), t), o(n(9689), t), o(n(1472), t), o(n(2918), t)
                },
                7140: function(e, t, n) {
                    "use strict";
                    var i = this && this.__createBinding || (Object.create ? function(e, t, n, i) {
                            void 0 === i && (i = n), Object.defineProperty(e, i, {
                                enumerable: !0,
                                get: function() {
                                    return t[n]
                                }
                            })
                        } : function(e, t, n, i) {
                            void 0 === i && (i = n), e[i] = t[n]
                        }),
                        o = this && this.__setModuleDefault || (Object.create ? function(e, t) {
                            Object.defineProperty(e, "default", {
                                enumerable: !0,
                                value: t
                            })
                        } : function(e, t) {
                            e.default = t
                        }),
                        r = this && this.__importStar || function(e) {
                            if (e && e.__esModule) return e;
                            var t = {};
                            if (null != e)
                                for (var n in e) "default" !== n && Object.prototype.hasOwnProperty.call(e, n) && i(t, e, n);
                            return o(t, e), t
                        },
                        a = this && this.__importDefault || function(e) {
                            return e && e.__esModule ? e : {
                                default: e
                            }
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.container = void 0;
                    const s = r(n(1614)),
                        l = a(n(9996)),
                        c = r(n(8103));
                    n(8660);
                    const d = n(3204),
                        u = n(9058),
                        p = n(5958),
                        h = n(2904),
                        f = n(322),
                        g = n(2438),
                        m = new c.Container;
                    t.container = m, m.bind(d.TYPES.ILogger).toDynamicValue((() => u.logger.getContextualLogger({}, {}, "cerebroClient", !0))), m.bind(d.TYPES.IUUID).toConstantValue(s), m.bind(d.TYPES.IMerge).toConstantValue(l.default), m.bind(d.TYPES.ICerebroClient).to(p.CerebroClient).inSingletonScope(), m.bind(d.TYPES.IConversationsManager).to(h.ConversationsManager).inSingletonScope(), m.bind(d.TYPES.ICerebroConnection).to(f.CerebroConnection).inSingletonScope(), m.bind(d.TYPES.IHeartbeat).to(g.Heartbeat)
                },
                3204: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.PUBLIC_TYPES = t.TYPES = void 0;
                    const n = {
                            ILogger: Symbol.for("ILogger"),
                            IUUID: Symbol.for("IUUID"),
                            IMerge: Symbol.for("IMerge"),
                            IHeartbeat: Symbol.for("IHeartbeat"),
                            ICerebroConnection: Symbol.for("ICerebroConnection")
                        },
                        i = {
                            ICerebroClient: Symbol.for("ICerebroClient"),
                            IConversationsManager: Symbol.for("IConversationsManager")
                        };
                    t.PUBLIC_TYPES = i;
                    const o = {
                        ...n,
                        ...i
                    };
                    t.TYPES = o
                },
                9854: (e, t) => {
                    "use strict";
                    var n;
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.CerebroMessageType = void 0, (n = t.CerebroMessageType || (t.CerebroMessageType = {})).Init = "init", n.Echo = "echo", n.Ping = "ping", n.Pong = "pong", n.Ack = "ack", n.ServerError = "error", n.C2SConversation = "c2sConversation", n.S2CConversation = "s2cConversation", n.C2SScreenshot = "c2sScreenshot"
                },
                757: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.CEREBRO_PROTOCOL_VERSION = void 0;
                    const n = parseInt("2");
                    t.CEREBRO_PROTOCOL_VERSION = n
                },
                3779: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.ConversationHandler = void 0, t.ConversationHandler = class {
                        constructor(e, t) {
                            this.conversationsManager = e, this.id = t
                        }
                        sendMessage(e) {
                            this.conversationsManager.sendMessage(this.id, e)
                        }
                        closeConversation() {
                            this.conversationsManager.closeConversation(this.id)
                        }
                        setNewHandler(e, t) {
                            this.conversationsManager.setNewHandler(this.id, e, t)
                        }
                        getID() {
                            return this.id
                        }
                    }
                },
                2904: function(e, t, n) {
                    "use strict";
                    var i = this && this.__decorate || function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        },
                        o = this && this.__metadata || function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        },
                        r = this && this.__param || function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.ConversationsManager = void 0;
                    const a = n(8103);
                    n(8660);
                    const s = n(3204),
                        l = n(2918),
                        c = n(9854),
                        d = n(3779);
                    let u = class {
                        constructor(e, t, n) {
                            this.CLOSED_CONVERSATIONS_CLEANUP_INTERVAL_IN_MINUTES = 5, this.conversations = new Map, this.closedConversations = [], this.DEFAULT_HANDLER_ID = "default", this.isActive = !1, this.logService = e, this.cerebroClient = t, this.uuid = n
                        }
                        init() {
                            if (!this.cerebroClient.active) {
                                const e = "ConversationsManager initialization failed due to CerebroClient is not yet initialized";
                                throw this.logService.error(e), new Error(e)
                            }
                            this.cerebroClient.registerHandler(c.CerebroMessageType.S2CConversation, this.handleMessage.bind(this), !0), this.cerebroClient.registerErrorHandler(c.CerebroMessageType.C2SConversation, this.handleError.bind(this)), this.isActive = !0, this.cleanClosedConversations()
                        }
                        handleMessage(e) {
                            if (!e.id) return void this.logService.error("ConversationsManager: Received message without conversation ID");
                            if (e.isServerInitiated) return void this.initiateConversation(e);
                            const t = this.conversations.get(e.id);
                            if (!t) return -1 !== this.closedConversations.indexOf(e.id) ? void this.logService.info(`ConversationsManager: Received message for closed conversation. ID: ${e.id}`) : void this.logService.error(`ConversationsManager: Missing metadata for conversation id: ${e.id}`);
                            t.state = e.state;
                            try {
                                t.handler(e)
                            } catch (t) {
                                this.logService.error(`ConversationsManager: Error while executing handler for conversation id ${e.id}: `, t)
                            }
                        }
                        handleError(e, t) {
                            this.logService.debug(`ConversationsManager: received error: ${e}`);
                            const n = t.originalMessage.id,
                                i = this.conversations.get(n);
                            if (i) try {
                                i.errorHandler(e, t)
                            } catch (e) {
                                this.logService.error(`ConversationsManager: Error while executing error handler for conversation id ${n}: `, e)
                            } else this.logService.error(`ConversationsManager: Missing metadata for conversation id: ${n}`)
                        }
                        startConversation(e, t, n) {
                            this.checkIfActive();
                            const i = this.uuid.v4(),
                                o = {
                                    id: i,
                                    handler: t,
                                    errorHandler: n,
                                    state: ""
                                };
                            this.conversations.set(i, o);
                            const r = {
                                topic: l.ConversationTopic.Dialog,
                                id: i,
                                state: "",
                                userInput: {
                                    type: l.ConversationInputType.Predefined,
                                    data: {
                                        transitionToTrigger: e
                                    }
                                }
                            };
                            return this.sendMessageInternal(r), new d.ConversationHandler(this, i)
                        }
                        closeConversation(e) {
                            this.checkIfActive(), this.closedConversations.push(e), this.conversations.delete(e)
                        }
                        sendMessage(e, t, n) {
                            this.checkIfActive();
                            const i = this.conversations.get(e);
                            if (!i) {
                                const t = `Missing metadata for conversation id: ${e}`;
                                throw this.logService.error(t), new Error(t)
                            }
                            const o = {
                                topic: l.ConversationTopic.Dialog,
                                id: i.id,
                                state: i.state,
                                userInput: t
                            };
                            this.sendMessageInternal(o, n)
                        }
                        registerDefaultHandler(e, t) {
                            if (this.checkIfActive(), this.conversations.has(this.DEFAULT_HANDLER_ID)) {
                                const e = "ConversationsManager: Can't set default handler: already exist!";
                                throw this.logService.error(e), new Error(e)
                            }
                            const n = {
                                id: this.DEFAULT_HANDLER_ID,
                                handler: e,
                                errorHandler: t,
                                state: ""
                            };
                            this.conversations.set(this.DEFAULT_HANDLER_ID, n)
                        }
                        setNewHandler(e, t, n) {
                            this.checkIfActive();
                            const i = this.conversations.get(e);
                            if (!i) {
                                const t = `ConversationsManager: Can't set new handler: Can't get metadata for id ${e}`;
                                throw this.logService.error(t), new Error(t)
                            }
                            i.handler = t, n && (i.errorHandler = n)
                        }
                        sendMessageInternal(e, t) {
                            this.cerebroClient.sendMessage(c.CerebroMessageType.C2SConversation, e, t)
                        }
                        initiateConversation(e) {
                            const t = this.conversations.get(this.DEFAULT_HANDLER_ID);
                            if (!t) return void this.logService.error("ConversationsManager: Error while handling server initiated conversation: no default handler!");
                            const n = {
                                id: this.uuid.v4(),
                                handler: t.handler,
                                errorHandler: t.errorHandler,
                                state: e.state
                            };
                            e.id = n.id, this.conversations.set(n.id, n);
                            const i = new d.ConversationHandler(this, n.id);
                            try {
                                t.handler(e, i)
                            } catch (e) {
                                this.logService.error("ConversationsManager: Error while executing default handler: ", e)
                            }
                        }
                        checkIfActive() {
                            if (!this.isActive) {
                                const e = "ConversationsManager isn't active";
                                throw this.logService.error(e), new Error(e)
                            }
                        }
                        cleanClosedConversations() {
                            this.closedConversations = [], setInterval((() => this.cleanClosedConversations()), 60 * this.CLOSED_CONVERSATIONS_CLEANUP_INTERVAL_IN_MINUTES * 1e3)
                        }
                    };
                    u = i([(0, a.injectable)(), r(0, (0, a.inject)(s.TYPES.ILogger)), r(1, (0, a.inject)(s.TYPES.ICerebroClient)), r(2, (0, a.inject)(s.TYPES.IUUID)), o("design:paramtypes", [Object, Object, Object])], u), t.ConversationsManager = u
                },
                2918: (e, t) => {
                    "use strict";
                    var n;
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.ConversationInputType = t.ConversationTopic = void 0, (t.ConversationTopic || (t.ConversationTopic = {})).Dialog = "dialog", (n = t.ConversationInputType || (t.ConversationInputType = {})).Text = "openText", n.Predefined = "predefined"
                },
                1472: (e, t) => {
                    "use strict";
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    })
                },
                9058: function(e, t, n) {
                    "use strict";
                    var i = this && this.__createBinding || (Object.create ? function(e, t, n, i) {
                            void 0 === i && (i = n), Object.defineProperty(e, i, {
                                enumerable: !0,
                                get: function() {
                                    return t[n]
                                }
                            })
                        } : function(e, t, n, i) {
                            void 0 === i && (i = n), e[i] = t[n]
                        }),
                        o = this && this.__setModuleDefault || (Object.create ? function(e, t) {
                            Object.defineProperty(e, "default", {
                                enumerable: !0,
                                value: t
                            })
                        } : function(e, t) {
                            e.default = t
                        }),
                        r = this && this.__importStar || function(e) {
                            if (e && e.__esModule) return e;
                            var t = {};
                            if (null != e)
                                for (var n in e) "default" !== n && Object.prototype.hasOwnProperty.call(e, n) && i(t, e, n);
                            return o(t, e), t
                        };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.logger = void 0, t.logger = r(n(5488))
                },
                5488: function(e, t, n) {
                    "use strict";
                    var i = this && this.__importDefault || function(e) {
                        return e && e.__esModule ? e : {
                            default: e
                        }
                    };
                    Object.defineProperty(t, "__esModule", {
                        value: !0
                    }), t.newContextualLogger = t.getContextualLogger = t.isContextualLogger = t.getLogger = void 0;
                    const o = i(n(2043)),
                        r = i(n(4530)),
                        a = o.default.methodFactory;

                    function s(e) {
                        return e ? o.default.getLogger(e) : o.default
                    }

                    function l(e) {
                        return void 0 !== e.extendContextualLogger
                    }

                    function c(e, t, n) {
                        const i = t.bufferSize || 10,
                            s = !1 !== t.shouldPrint,
                            l = 0 === t.bufferFlushInterval ? 0 : t.bufferFlushInterval || 6e3,
                            u = t.remoteURL || t.jsonOutput,
                            p = o.default,
                            h = n ? o.default.getLogger(n) : p;
                        if (function(e) {
                                return void 0 !== e.context
                            }(h)) throw new Error(`Logger "${n||"root logger"}" already exist`);
                        h.extendContextualLogger = (n, i, o) => {
                            if (!n) throw new Error("Misisng extension name");
                            return c({
                                ...e,
                                ...i
                            }, {
                                ...t,
                                ...o || {}
                            }, n)
                        }, h.name = n, h.context = e, h.messagesBuffer = [];
                        const f = [];
                        Object.entries(e).forEach((([e, t]) => f.push(`[${e}: ${t}]`)));
                        const g = f.join(" ");
                        return h.flush = () => {
                            if (!t.remoteURL) return;
                            if (0 === h.messagesBuffer.length) return;
                            const e = "[" + h.messagesBuffer.toString() + "]";
                            if ("undefined" != typeof window && window.navigator?.sendBeacon) window.navigator.sendBeacon(t.remoteURL, e);
                            else {
                                if ("undefined" == typeof fetch) throw new Error("Fetch API does not exist, if running on node.js consider using a polyfill (e.g. `node-fetch`)");
                                fetch(t.remoteURL, {
                                    body: e,
                                    method: "POST"
                                })
                            }
                            h.messagesBuffer = []
                        }, h.startFlushInterval = () => {
                            l && setInterval((() => {
                                h.flush()
                            }), l)
                        }, h.methodFactory = function(n, o, l) {
                            const c = a(n, o, l),
                                p = (...e) => {
                                    let o = "";
                                    const a = t.jsonOutput && s;
                                    if (t.remoteURL || a) try {
                                        o = (0, r.default)(e[0], d)
                                    } catch (t) {
                                        console.error("Error while stringifing log: ", t, " Original log:", e)
                                    }
                                    if (t.remoteURL && o && (this.messagesBuffer.push(o), this.messagesBuffer.length >= i && this.flush()), s) {
                                        if (t.jsonOutput) return void c(o);
                                        const i = g ? [g] : [];
                                        t.printTimestamp && i.push((new Date).toISOString()), t.printSeverity && i.push(`[${n.toUpperCase()}]`), this.name && t.printLoggerName && i.push(`[${this.name}]`);
                                        const r = u ? e[0].message : e;
                                        c(...i, ...r)
                                    }
                                };
                            return u ? function(e, t, n) {
                                return function(...i) {
                                    const o = {
                                        message: [],
                                        ...n
                                    };
                                    o.message.push(...i), o.severity = t;
                                    const r = Date.now();
                                    o.timestampSeconds = Math.floor(r / 1e3), o.timestampNanos = r - 1e3 * o.timestampSeconds, e(o)
                                }
                            }(p, n, e) : function(e, t, n) {
                                return function(...t) {
                                    e(...t)
                                }
                            }(p)
                        }, h.setLevel(h.getLevel()), h.startFlushInterval(), "undefined" != typeof document && document.addEventListener("visibilitychange", (() => {
                            "hidden" === document.visibilityState && h.flush()
                        })), h
                    }

                    function d(e, t) {
                        return "undefined" == typeof Element ? t : t instanceof Element ? function(e) {
                            let t = e.tagName || "";
                            const n = e.getAttribute("id");
                            t += n ? "#" + n : "";
                            const i = Array.from(e.classList).map((e => e)).join(".");
                            return t += i.length ? "." + i : "", "[DOM Element] - " + t
                        }(t) : t
                    }
                    t.getLogger = s, t.isContextualLogger = l, t.getContextualLogger = function(e, t, n, i) {
                        return l(s(n)) ? s(n) : n ? i ? (l(s()) ? s() : c({}, t)).extendContextualLogger(n, e, t) : c(e, t, n) : c(e, t)
                    }, t.newContextualLogger = c
                },
                2603: (e, t, n) => {
                    "use strict";
                    t.d = void 0;
                    const i = n(9058);
                    class o {
                        constructor(e, t) {
                            this.element = e, this.callback = t, this.log = i.logger.getContextualLogger({}, {
                                printSeverity: !0,
                                printLoggerName: !0
                            }, "CredentialsDetector", !0)
                        }
                        detect() {
                            let e = this.querySelectCredentials(this.element);
                            e = e.concat(this.findSuspiciousInputs(this.element)), e.length && this.callback(e), this.domObserver || this.startObserver()
                        }
                        startObserver() {
                            this.log.debug("Starting credentials detector observer"), this.stopObserver(), this.domObserver = new MutationObserver((e => {
                                let t = [];
                                for (const n of e) switch (n.type) {
                                    case "attributes":
                                        (o.isCredentialInputElement(n.target) || o.isSuspicious(n.target)) && t.push(n.target);
                                        break;
                                    case "childList":
                                        for (const e of n.addedNodes) {
                                            const n = e;
                                            n.querySelectorAll && (t = t.concat(this.querySelectCredentials(n)), t = t.concat(this.findSuspiciousInputs(n))), (o.isCredentialInputElement(e) || o.isSuspicious(e)) && t.push(n)
                                        }
                                }
                                t.length && this.callback(t)
                            }));
                            const e = {
                                attributes: !0,
                                attributeFilter: ["type"].concat(o.attributesToInspect),
                                childList: !0,
                                subtree: !0
                            };
                            this.domObserver.observe(this.element, e)
                        }
                        stopObserver() {
                            this.domObserver && this.domObserver.disconnect()
                        }
                        static detectOnElement(e) {
                            return this.isCredentialInputElement(e) || this.isSuspicious(e) || ("textarea" === e.tagName.toLocaleLowerCase() || "input" === e.tagName.toLocaleLowerCase() && o.textInputTypes.includes(e.type)) && this.findPasswordLabels()
                        }
                        static isCredentialInputElement(e) {
                            return "input" === e.nodeName.toLowerCase() && ["password", "email"].includes(e.type)
                        }
                        static isSuspicious(e) {
                            for (const t of o.attributesToInspect) {
                                const n = e.getAttribute && e.getAttribute(t);
                                if (n && (n.toLowerCase().includes("password") || n.toLowerCase().includes("mail") || n.toLowerCase().includes("user"))) return !0
                            }
                            return !1
                        }
                        findSuspiciousInputs(e) {
                            const t = [],
                                n = this.callback;
                            let i = Array.from(e.querySelectorAll("input[type='" + o.textInputTypes.join("'], input[type='") + "']"));
                            i = i.concat(Array.from(e.getElementsByTagName("textarea")));
                            for (const e of i) {
                                if (o.isSuspicious(e)) {
                                    t.push(e);
                                    continue
                                }
                                const i = e.onfocus;
                                e.onfocus = function(t) {
                                    i && i.call(this, t), o.findPasswordLabels() && n([e])
                                }
                            }
                            return t
                        }
                        querySelectCredentials(e) {
                            return Array.from(e.querySelectorAll("input[type='password'], input[type='email']"))
                        }
                    }
                    t.d = o, o.attributesToInspect = ["placeholder", "name", "id"], o.textInputTypes = ["text", "search", "url", "tel"], o.labelTags = ["label, h1, h2, h3, h4, h5, h6"], o.findPasswordLabels = () => {
                        for (const e of Array.from(document.querySelectorAll(o.labelTags.join(","))))
                            if (e.innerText.toLocaleLowerCase().includes("password")) return !0;
                        return !1
                    }
                },
                9478: (e, t, n) => {
                    "use strict";
                    var i, o = n(2100),
                        r = o.Reader,
                        a = o.Writer,
                        s = o.util,
                        l = o.roots.default || (o.roots.default = {});
                    l.client2cerebro = ((i = {}).RawBinaryMessage = function() {
                        function e(e) {
                            if (e)
                                for (var t = Object.keys(e), n = 0; n < t.length; ++n) null != e[t[n]] && (this[t[n]] = e[t[n]])
                        }
                        var t;
                        return e.prototype.Type = "", e.prototype.RequestID = "", e.prototype.ScreenshotMessage = null, Object.defineProperty(e.prototype, "Data", {
                            get: s.oneOfGetter(t = ["ScreenshotMessage"]),
                            set: s.oneOfSetter(t)
                        }), e.create = function(t) {
                            return new e(t)
                        }, e.encode = function(e, t) {
                            return t || (t = a.create()), null != e.Type && Object.hasOwnProperty.call(e, "Type") && t.uint32(10).string(e.Type), null != e.RequestID && Object.hasOwnProperty.call(e, "RequestID") && t.uint32(18).string(e.RequestID), null != e.ScreenshotMessage && Object.hasOwnProperty.call(e, "ScreenshotMessage") && l.client2cerebro.ScreenshotMessage.encode(e.ScreenshotMessage, t.uint32(26).fork()).ldelim(), t
                        }, e.encodeDelimited = function(e, t) {
                            return this.encode(e, t).ldelim()
                        }, e.decode = function(e, t) {
                            e instanceof r || (e = r.create(e));
                            for (var n = void 0 === t ? e.len : e.pos + t, i = new l.client2cerebro.RawBinaryMessage; e.pos < n;) {
                                var o = e.uint32();
                                switch (o >>> 3) {
                                    case 1:
                                        i.Type = e.string();
                                        break;
                                    case 2:
                                        i.RequestID = e.string();
                                        break;
                                    case 3:
                                        i.ScreenshotMessage = l.client2cerebro.ScreenshotMessage.decode(e, e.uint32());
                                        break;
                                    default:
                                        e.skipType(7 & o)
                                }
                            }
                            return i
                        }, e.decodeDelimited = function(e) {
                            return e instanceof r || (e = new r(e)), this.decode(e, e.uint32())
                        }, e.verify = function(e) {
                            if ("object" != typeof e || null === e) return "object expected";
                            if (null != e.Type && e.hasOwnProperty("Type") && !s.isString(e.Type)) return "Type: string expected";
                            if (null != e.RequestID && e.hasOwnProperty("RequestID") && !s.isString(e.RequestID)) return "RequestID: string expected";
                            if (null != e.ScreenshotMessage && e.hasOwnProperty("ScreenshotMessage")) {
                                var t = l.client2cerebro.ScreenshotMessage.verify(e.ScreenshotMessage);
                                if (t) return "ScreenshotMessage." + t
                            }
                            return null
                        }, e.fromObject = function(e) {
                            if (e instanceof l.client2cerebro.RawBinaryMessage) return e;
                            var t = new l.client2cerebro.RawBinaryMessage;
                            if (null != e.Type && (t.Type = String(e.Type)), null != e.RequestID && (t.RequestID = String(e.RequestID)), null != e.ScreenshotMessage) {
                                if ("object" != typeof e.ScreenshotMessage) throw TypeError(".client2cerebro.RawBinaryMessage.ScreenshotMessage: object expected");
                                t.ScreenshotMessage = l.client2cerebro.ScreenshotMessage.fromObject(e.ScreenshotMessage)
                            }
                            return t
                        }, e.toObject = function(e, t) {
                            t || (t = {});
                            var n = {};
                            return t.defaults && (n.Type = "", n.RequestID = ""), null != e.Type && e.hasOwnProperty("Type") && (n.Type = e.Type), null != e.RequestID && e.hasOwnProperty("RequestID") && (n.RequestID = e.RequestID), null != e.ScreenshotMessage && e.hasOwnProperty("ScreenshotMessage") && (n.ScreenshotMessage = l.client2cerebro.ScreenshotMessage.toObject(e.ScreenshotMessage, t), t.oneofs && (n.Data = "ScreenshotMessage")), n
                        }, e.prototype.toJSON = function() {
                            return this.constructor.toObject(this, o.util.toJSONOptions)
                        }, e
                    }(), i.ScreenshotMessage = function() {
                        function e(e) {
                            if (this.ElementsIDs = [], e)
                                for (var t = Object.keys(e), n = 0; n < t.length; ++n) null != e[t[n]] && (this[t[n]] = e[t[n]])
                        }
                        return e.prototype.RealURL = "", e.prototype.ElementsIDs = s.emptyArray, e.prototype.Image = s.newBuffer([]), e.create = function(t) {
                            return new e(t)
                        }, e.encode = function(e, t) {
                            if (t || (t = a.create()), null != e.RealURL && Object.hasOwnProperty.call(e, "RealURL") && t.uint32(10).string(e.RealURL), null != e.ElementsIDs && e.ElementsIDs.length)
                                for (var n = 0; n < e.ElementsIDs.length; ++n) t.uint32(18).string(e.ElementsIDs[n]);
                            return null != e.Image && Object.hasOwnProperty.call(e, "Image") && t.uint32(26).bytes(e.Image), t
                        }, e.encodeDelimited = function(e, t) {
                            return this.encode(e, t).ldelim()
                        }, e.decode = function(e, t) {
                            e instanceof r || (e = r.create(e));
                            for (var n = void 0 === t ? e.len : e.pos + t, i = new l.client2cerebro.ScreenshotMessage; e.pos < n;) {
                                var o = e.uint32();
                                switch (o >>> 3) {
                                    case 1:
                                        i.RealURL = e.string();
                                        break;
                                    case 2:
                                        i.ElementsIDs && i.ElementsIDs.length || (i.ElementsIDs = []), i.ElementsIDs.push(e.string());
                                        break;
                                    case 3:
                                        i.Image = e.bytes();
                                        break;
                                    default:
                                        e.skipType(7 & o)
                                }
                            }
                            return i
                        }, e.decodeDelimited = function(e) {
                            return e instanceof r || (e = new r(e)), this.decode(e, e.uint32())
                        }, e.verify = function(e) {
                            if ("object" != typeof e || null === e) return "object expected";
                            if (null != e.RealURL && e.hasOwnProperty("RealURL") && !s.isString(e.RealURL)) return "RealURL: string expected";
                            if (null != e.ElementsIDs && e.hasOwnProperty("ElementsIDs")) {
                                if (!Array.isArray(e.ElementsIDs)) return "ElementsIDs: array expected";
                                for (var t = 0; t < e.ElementsIDs.length; ++t)
                                    if (!s.isString(e.ElementsIDs[t])) return "ElementsIDs: string[] expected"
                            }
                            return null != e.Image && e.hasOwnProperty("Image") && !(e.Image && "number" == typeof e.Image.length || s.isString(e.Image)) ? "Image: buffer expected" : null
                        }, e.fromObject = function(e) {
                            if (e instanceof l.client2cerebro.ScreenshotMessage) return e;
                            var t = new l.client2cerebro.ScreenshotMessage;
                            if (null != e.RealURL && (t.RealURL = String(e.RealURL)), e.ElementsIDs) {
                                if (!Array.isArray(e.ElementsIDs)) throw TypeError(".client2cerebro.ScreenshotMessage.ElementsIDs: array expected");
                                t.ElementsIDs = [];
                                for (var n = 0; n < e.ElementsIDs.length; ++n) t.ElementsIDs[n] = String(e.ElementsIDs[n])
                            }
                            return null != e.Image && ("string" == typeof e.Image ? s.base64.decode(e.Image, t.Image = s.newBuffer(s.base64.length(e.Image)), 0) : e.Image.length && (t.Image = e.Image)), t
                        }, e.toObject = function(e, t) {
                            t || (t = {});
                            var n = {};
                            if ((t.arrays || t.defaults) && (n.ElementsIDs = []), t.defaults && (n.RealURL = "", t.bytes === String ? n.Image = "" : (n.Image = [], t.bytes !== Array && (n.Image = s.newBuffer(n.Image)))), null != e.RealURL && e.hasOwnProperty("RealURL") && (n.RealURL = e.RealURL), e.ElementsIDs && e.ElementsIDs.length) {
                                n.ElementsIDs = [];
                                for (var i = 0; i < e.ElementsIDs.length; ++i) n.ElementsIDs[i] = e.ElementsIDs[i]
                            }
                            return null != e.Image && e.hasOwnProperty("Image") && (n.Image = t.bytes === String ? s.base64.encode(e.Image, 0, e.Image.length) : t.bytes === Array ? Array.prototype.slice.call(e.Image) : e.Image), n
                        }, e.prototype.toJSON = function() {
                            return this.constructor.toObject(this, o.util.toJSONOptions)
                        }, e
                    }(), i), e.exports = l
                },
                390: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Z: () => s
                    });
                    var i = n(8081),
                        o = n.n(i),
                        r = n(3645),
                        a = n.n(r)()(o());
                    a.push([e.id, "@import url(https://fonts.googleapis.com/css2?family=Readex+Pro:wght@400;500;700&display=swap);"]), a.push([e.id, '#us-tara-frame{all:initial;position:fixed;right:20px;bottom:77px;width:320px;height:463px;border:solid 2px #dcdcdc;transition:opacity .5s;background-color:transparent;border-radius:16px 16px 4px 16px;padding:0px;opacity:0;z-index:2147483647;pointer-events:none;visibility:hidden}#us-tara-frame.outlook-addin{right:0px;bottom:0px;width:100%;height:100%;border-radius:0px}@media(max-width: 320px){#us-tara-frame{font-size:13px}}@media(max-width: 480px){#us-tara-frame{right:0;bottom:0;width:100%;border:none;border-bottom-left-radius:0px;border-bottom-right-radius:0px}}#us-indicator-frame{all:initial;width:44px;height:44px;border-radius:50%;position:fixed;bottom:18px;right:18px;border:none;z-index:2147483646;pointer-events:none;visibility:hidden;opacity:0}@media(max-width: 480px){#us-indicator-frame{right:12px;bottom:12px}}#us-indicator-frame.outlook-addin{display:none}#us-meddler-root{all:initial;color-scheme:none;pointer-events:none;height:100%;width:100%;margin:0px;padding:0px;border:none;position:fixed;top:0px;left:0px;z-index:2147483645;pointer-events:none}#us-meddler-root #meddler{all:initial;width:100%;height:100%;position:absolute;top:0px;right:0px;pointer-events:none;padding:0px;margin:0px;border:none;font-family:"Readex Pro"}#us-meddler-root #meddler #download-widget{width:100%;height:80px;background-color:#f5f5f5;position:fixed;bottom:0px;display:flex;flex-direction:row;align-items:flex-start}#us-meddler-root #meddler #download-widget .file-download-panel{pointer-events:auto;width:300px;border-right:solid 1px rgba(28,47,92,.05);padding:18px 16px}#us-meddler-root #meddler #download-widget .file-download-panel.complete{background-color:rgba(111,207,151,.1)}#us-meddler-root #meddler #download-widget .file-download-panel.downloading,#us-meddler-root #meddler #download-widget .file-download-panel.scanning{padding-top:8px;padding-bottom:8px}#us-meddler-root #meddler #download-widget .file-download-panel.downloading .file-download-action,#us-meddler-root #meddler #download-widget .file-download-panel.scanning .file-download-action{margin-bottom:4px}#us-meddler-root #meddler #download-widget .file-download-panel.downloading .file-download-details .file-ops,#us-meddler-root #meddler #download-widget .file-download-panel.scanning .file-download-details .file-ops{margin:initial}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-action{font-size:12px;font-family:"Readex Pro";font-weight:700;line-height:16px;color:rgba(28,47,92,.7)}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details{display:flex;flex-direction:row;align-items:flex-start;gap:16px}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-icon{height:44px;width:44px}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs{flex:1;display:flex;flex-direction:column;align-self:center;gap:4px}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-filename{font-family:"Readex Pro";font-size:16px;line-height:24px;font-weight:400}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status{font-family:"Readex Pro";font-weight:400;font-size:12px;line-height:16px}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.downloading,#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.scanning{color:#1c2f5c}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked{color:#c74646}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{color:#44be90}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked,#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{font-weight:700}#us-meddler-root #meddler #download-widget .file-download-panel .file-download-details .file-ops{width:24px;margin:auto}#us-meddler-root #meddler .flashlight-shadow{background-color:rgba(0,0,0,.5);position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity}#us-meddler-root #meddler .flashlight{position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity;background:radial-gradient(ellipse at center, transparent, transparent 60%, rgba(0, 0, 0, 0.5) 70%)}#us-meddler-root #meddler .radar-wrapper{width:300px;position:absolute;height:100%;right:0px}#us-meddler-root #meddler .radar-wrapper .augmentation-radar{pointer-events:auto;position:absolute;right:-27px;width:54px;height:54px;border-radius:27px;display:flex;justify-content:center;align-items:center;background-color:rgba(255,192,0,.1)}#us-meddler-root #meddler .radar-wrapper .augmentation-radar div.circle1{border-radius:14px;display:flex;justify-content:center;align-items:center;width:27px;height:27px;background-color:rgba(255,192,0,.3)}#us-meddler-root #meddler .radar-wrapper .augmentation-radar div.circle1 div.circle2{border-radius:8px;background-color:#ffc000;width:15px;height:15px}#us-meddler-root #meddler .radar-wrapper .bubble-with-arrow{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 12px 24px -4px rgba(145,158,171,.12);width:fit-content;height:fit-content;max-width:300px;opacity:0}#us-meddler-root #meddler .radar-wrapper .bubble-with-arrow div{font:inherit;color:inherit}#us-meddler-root #meddler .radar-wrapper .augmentation-radar:hover+.bubble-with-arrow{opacity:1}#us-meddler-root #meddler .radar-wrapper.top .augmentation-radar{top:-27px}#us-meddler-root #meddler .radar-wrapper.top .bubble-with-arrow{transform:translate(-80%, calc(-100% - 20px))}#us-meddler-root #meddler .radar-wrapper.bottom .augmentation-radar{bottom:-27px}#us-meddler-root #meddler .radar-wrapper.bottom .bubble-with-arrow{transform:translate(-80%, 20px)}#us-meddler-root #meddler .disabler{position:absolute;pointer-events:auto;background-color:rgba(80,80,80,.5);cursor:not-allowed}#us-meddler-root #meddler .walkthrough-box{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 16px 48px 0px rgba(0,0,0,.18);position:absolute;width:300px;max-height:100px;min-height:100px;display:flex;flex-direction:column;justify-content:start;transition-duration:.4s;transition-property:top,left,min-height,max-height,opacity;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);overflow:hidden;z-index:2;padding:0px}#us-meddler-root #meddler .walkthrough-box .walkthrough-box-content-wrapper .walkthrough-box-content-padding{padding:15px;display:flex;flex-direction:column}#us-meddler-root #meddler .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:flex;align-items:center;justify-content:center;background-color:rgba(16,25,107,.04)}#us-meddler-root #meddler .walkthrough-box.wide{width:355px}#us-meddler-root #meddler .walkthrough-box .closeButton{position:absolute;top:10px;right:10px;cursor:pointer}#us-meddler-root #meddler .walkthrough-box .text{font-size:14px;font-weight:400;font-family:"Readex Pro";color:#1c2f5c;opacity:0}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper{display:flex;flex-direction:row;justify-content:space-between;align-items:center;margin-top:30px}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .button{pointer-events:auto;height:38px;width:44px;border-radius:8px;text-align:center;font-size:15px;font-weight:500;cursor:pointer;background-color:#fff;border:solid 2px #f5f5f5;color:#1c2f5c;display:flex;align-items:center;justify-content:center}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .button.invisible{opacity:0}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .button.primary{background-color:#1c2f5c;color:#fff;border-color:#1c2f5c}@media(max-width: 480px){#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .button.primary{margin-right:50px}}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .button.button-text{padding:10px 30px;width:auto;display:block;box-sizing:border-box}#us-meddler-root #meddler .walkthrough-box .buttons-wrapper .progress{font-family:"Readex Pro";font-size:12px}@media(max-width: 480px){#us-meddler-root #meddler .walkthrough-box{position:fixed;width:100%;top:auto !important;left:0 !important;bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0}#us-meddler-root #meddler .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:none}}#us-meddler-root #meddler .focus-mask{position:absolute;top:0px;left:0px;height:100%;width:100%;transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:clip-path,opacity;background:repeating-linear-gradient(-45deg, rgba(0, 0, 0, 0.28) 0px, rgba(0, 0, 0, 0.2) 1px, rgba(0, 0, 0, 0.2) 4px, rgba(0, 0, 0, 0.28) 5px);z-index:-1}#us-meddler-root #meddler .custom-element-augmentation{position:absolute;box-sizing:border-box;pointer-events:none}#us-meddler-root #meddler .iframe-aug-wrapper{position:fixed;width:100%;height:100%;z-index:-3}#us-meddler-root #meddler .iframe-aug-wrapper .iframe-aug-bg-mask{position:fixed;background-color:#637381;width:100%;height:100%;z-index:1;pointer-events:auto}#us-meddler-root #meddler .iframe-aug-wrapper .iframe-aug{position:fixed;top:50%;left:50%;transform:translate(-50%, -50%);width:796px;height:532px;box-shadow:0px 16px 48px rgba(0,0,0,.176);border-radius:16px;border:none;z-index:2;background-color:#fff;pointer-events:auto}@media(max-width: 480px){#us-meddler-root #meddler .iframe-aug-wrapper .iframe-aug{top:20px;width:90%;height:70%;transform:translate(-50%, 0)}}#us-meddler-root #meddler .meddler-blur-mask{position:fixed;width:100%;height:100%;background-color:rgba(120,120,120,.7)}@supports(backdrop-filter: none){#us-meddler-root #meddler .meddler-blur-mask{background-color:rgba(120,120,120,.3);backdrop-filter:blur(10px)}}#us-meddler-root #meddler .bubble-with-arrow{position:absolute;border-radius:8px;box-shadow:0px 8px 16px rgba(145,158,171,.12);z-index:0;background-color:#fff}#us-meddler-root #meddler .bubble-with-arrow .content-container{background-color:inherit;display:block;border-radius:inherit}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content{height:100%;width:100%;background-color:inherit;z-index:0;padding:10px;padding-right:0px;display:block;box-sizing:border-box;border-radius:inherit}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content div{word-wrap:break-word}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{display:block;padding:44px 80px 48px 115px;overflow:hidden;position:relative}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding-top:1px;z-index:1;position:relative;pointer-events:auto}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{position:absolute;top:14px;left:-2px}#us-meddler-root #meddler .bubble-with-arrow .the-arrow{background-color:#fff;position:absolute;height:20px;width:20px;box-sizing:border-box;transform:translate(-50%) rotate(45deg);border-bottom:inherit;border-right:inherit;box-shadow:inherit;background-color:inherit;z-index:-1}@media(max-width: 480px){#us-meddler-root #meddler .bubble-with-arrow{left:8px !important;top:19px !important;width:calc(100% - 16px);box-sizing:border-box;max-width:initial}#us-meddler-root #meddler .bubble-with-arrow .content-container{padding:28px 12px}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content{padding:0px}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{padding:0px;background-color:rgba(0,0,0,.08);display:flex;justify-content:center;border-radius:20px}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding:7px 0px;z-index:1;position:relative}#us-meddler-root #meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{display:none}}#us-meddler-root #meddler .warningframe{z-index:1}#us-meddler-root #meddler div{all:initial;pointer-events:none}#us-meddler-root #meddler button{all:initial}#us-meddler-root #meddler.fading-children #download-widget{width:100%;height:80px;background-color:#f5f5f5;position:fixed;bottom:0px;display:flex;flex-direction:row;align-items:flex-start}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel{pointer-events:auto;width:300px;border-right:solid 1px rgba(28,47,92,.05);padding:18px 16px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.complete{background-color:rgba(111,207,151,.1)}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.downloading,#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.scanning{padding-top:8px;padding-bottom:8px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.downloading .file-download-action,#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.scanning .file-download-action{margin-bottom:4px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.downloading .file-download-details .file-ops,#us-meddler-root #meddler.fading-children #download-widget .file-download-panel.scanning .file-download-details .file-ops{margin:initial}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-action{font-size:12px;font-family:"Readex Pro";font-weight:700;line-height:16px;color:rgba(28,47,92,.7)}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details{display:flex;flex-direction:row;align-items:flex-start;gap:16px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-icon{height:44px;width:44px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs{flex:1;display:flex;flex-direction:column;align-self:center;gap:4px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-filename{font-family:"Readex Pro";font-size:16px;line-height:24px;font-weight:400}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status{font-family:"Readex Pro";font-weight:400;font-size:12px;line-height:16px}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.downloading,#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.scanning{color:#1c2f5c}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked{color:#c74646}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{color:#44be90}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked,#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{font-weight:700}#us-meddler-root #meddler.fading-children #download-widget .file-download-panel .file-download-details .file-ops{width:24px;margin:auto}#us-meddler-root #meddler.fading-children .flashlight-shadow{background-color:rgba(0,0,0,.5);position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity}#us-meddler-root #meddler.fading-children .flashlight{position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity;background:radial-gradient(ellipse at center, transparent, transparent 60%, rgba(0, 0, 0, 0.5) 70%)}#us-meddler-root #meddler.fading-children .radar-wrapper{width:300px;position:absolute;height:100%;right:0px}#us-meddler-root #meddler.fading-children .radar-wrapper .augmentation-radar{pointer-events:auto;position:absolute;right:-27px;width:54px;height:54px;border-radius:27px;display:flex;justify-content:center;align-items:center;background-color:rgba(255,192,0,.1)}#us-meddler-root #meddler.fading-children .radar-wrapper .augmentation-radar div.circle1{border-radius:14px;display:flex;justify-content:center;align-items:center;width:27px;height:27px;background-color:rgba(255,192,0,.3)}#us-meddler-root #meddler.fading-children .radar-wrapper .augmentation-radar div.circle1 div.circle2{border-radius:8px;background-color:#ffc000;width:15px;height:15px}#us-meddler-root #meddler.fading-children .radar-wrapper .bubble-with-arrow{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 12px 24px -4px rgba(145,158,171,.12);width:fit-content;height:fit-content;max-width:300px;opacity:0}#us-meddler-root #meddler.fading-children .radar-wrapper .bubble-with-arrow div{font:inherit;color:inherit}#us-meddler-root #meddler.fading-children .radar-wrapper .augmentation-radar:hover+.bubble-with-arrow{opacity:1}#us-meddler-root #meddler.fading-children .radar-wrapper.top .augmentation-radar{top:-27px}#us-meddler-root #meddler.fading-children .radar-wrapper.top .bubble-with-arrow{transform:translate(-80%, calc(-100% - 20px))}#us-meddler-root #meddler.fading-children .radar-wrapper.bottom .augmentation-radar{bottom:-27px}#us-meddler-root #meddler.fading-children .radar-wrapper.bottom .bubble-with-arrow{transform:translate(-80%, 20px)}#us-meddler-root #meddler.fading-children .disabler{position:absolute;pointer-events:auto;background-color:rgba(80,80,80,.5);cursor:not-allowed}#us-meddler-root #meddler.fading-children .walkthrough-box{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 16px 48px 0px rgba(0,0,0,.18);position:absolute;width:300px;max-height:100px;min-height:100px;display:flex;flex-direction:column;justify-content:start;transition-duration:.4s;transition-property:top,left,min-height,max-height,opacity;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);overflow:hidden;z-index:2;padding:0px}#us-meddler-root #meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .walkthrough-box-content-padding{padding:15px;display:flex;flex-direction:column}#us-meddler-root #meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:flex;align-items:center;justify-content:center;background-color:rgba(16,25,107,.04)}#us-meddler-root #meddler.fading-children .walkthrough-box.wide{width:355px}#us-meddler-root #meddler.fading-children .walkthrough-box .closeButton{position:absolute;top:10px;right:10px;cursor:pointer}#us-meddler-root #meddler.fading-children .walkthrough-box .text{font-size:14px;font-weight:400;font-family:"Readex Pro";color:#1c2f5c;opacity:0}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper{display:flex;flex-direction:row;justify-content:space-between;align-items:center;margin-top:30px}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .button{pointer-events:auto;height:38px;width:44px;border-radius:8px;text-align:center;font-size:15px;font-weight:500;cursor:pointer;background-color:#fff;border:solid 2px #f5f5f5;color:#1c2f5c;display:flex;align-items:center;justify-content:center}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .button.invisible{opacity:0}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .button.primary{background-color:#1c2f5c;color:#fff;border-color:#1c2f5c}@media(max-width: 480px){#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .button.primary{margin-right:50px}}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .button.button-text{padding:10px 30px;width:auto;display:block;box-sizing:border-box}#us-meddler-root #meddler.fading-children .walkthrough-box .buttons-wrapper .progress{font-family:"Readex Pro";font-size:12px}@media(max-width: 480px){#us-meddler-root #meddler.fading-children .walkthrough-box{position:fixed;width:100%;top:auto !important;left:0 !important;bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0}#us-meddler-root #meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:none}}#us-meddler-root #meddler.fading-children .focus-mask{position:absolute;top:0px;left:0px;height:100%;width:100%;transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:clip-path,opacity;background:repeating-linear-gradient(-45deg, rgba(0, 0, 0, 0.28) 0px, rgba(0, 0, 0, 0.2) 1px, rgba(0, 0, 0, 0.2) 4px, rgba(0, 0, 0, 0.28) 5px);z-index:-1}#us-meddler-root #meddler.fading-children .custom-element-augmentation{position:absolute;box-sizing:border-box;pointer-events:none}#us-meddler-root #meddler.fading-children .iframe-aug-wrapper{position:fixed;width:100%;height:100%;z-index:-3}#us-meddler-root #meddler.fading-children .iframe-aug-wrapper .iframe-aug-bg-mask{position:fixed;background-color:#637381;width:100%;height:100%;z-index:1;pointer-events:auto}#us-meddler-root #meddler.fading-children .iframe-aug-wrapper .iframe-aug{position:fixed;top:50%;left:50%;transform:translate(-50%, -50%);width:796px;height:532px;box-shadow:0px 16px 48px rgba(0,0,0,.176);border-radius:16px;border:none;z-index:2;background-color:#fff;pointer-events:auto}@media(max-width: 480px){#us-meddler-root #meddler.fading-children .iframe-aug-wrapper .iframe-aug{top:20px;width:90%;height:70%;transform:translate(-50%, 0)}}#us-meddler-root #meddler.fading-children .meddler-blur-mask{position:fixed;width:100%;height:100%;background-color:rgba(120,120,120,.7)}@supports(backdrop-filter: none){#us-meddler-root #meddler.fading-children .meddler-blur-mask{background-color:rgba(120,120,120,.3);backdrop-filter:blur(10px)}}#us-meddler-root #meddler.fading-children .bubble-with-arrow{position:absolute;border-radius:8px;box-shadow:0px 8px 16px rgba(145,158,171,.12);z-index:0;background-color:#fff}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container{background-color:inherit;display:block;border-radius:inherit}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content{height:100%;width:100%;background-color:inherit;z-index:0;padding:10px;padding-right:0px;display:block;box-sizing:border-box;border-radius:inherit}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content div{word-wrap:break-word}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{display:block;padding:44px 80px 48px 115px;overflow:hidden;position:relative}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding-top:1px;z-index:1;position:relative;pointer-events:auto}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{position:absolute;top:14px;left:-2px}#us-meddler-root #meddler.fading-children .bubble-with-arrow .the-arrow{background-color:#fff;position:absolute;height:20px;width:20px;box-sizing:border-box;transform:translate(-50%) rotate(45deg);border-bottom:inherit;border-right:inherit;box-shadow:inherit;background-color:inherit;z-index:-1}@media(max-width: 480px){#us-meddler-root #meddler.fading-children .bubble-with-arrow{left:8px !important;top:19px !important;width:calc(100% - 16px);box-sizing:border-box;max-width:initial}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container{padding:28px 12px}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content{padding:0px}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{padding:0px;background-color:rgba(0,0,0,.08);display:flex;justify-content:center;border-radius:20px}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding:7px 0px;z-index:1;position:relative}#us-meddler-root #meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{display:none}}#us-meddler-root #meddler.fading-children .warningframe{z-index:1}#us-meddler-root #meddler.fading-children div{opacity:0;transition:opacity .4s ease-in-out}#us-meddler-root #meddler.fading-children div.visible{opacity:1}#us-meddler-root #meddler.fading-children div.visible div{opacity:1}.us-pointer-events-allowed{pointer-events:auto !important}.unbiased-visible-frame{opacity:1 !important;visibility:visible !important}.unbiased-fadeable-frame{transition:opacity .3s ease-in-out}', ""]);
                    const s = a
                },
                7485: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Z: () => s
                    });
                    var i = n(8081),
                        o = n.n(i),
                        r = n(3645),
                        a = n.n(r)()(o());
                    a.push([e.id, "body{padding:0px;margin:0px;border:none}#tara-indicator{width:100%;height:100%;cursor:pointer;pointer-events:auto;box-sizing:border-box;border-radius:50%}#tara-indicator svg{width:100%;height:100%}#tara-indicator.healthy{border:solid 2px transparent}#tara-indicator.error{border:solid 2px #fc004a}#tara-indicator.warning{border:solid 2px #ffc000}", ""]);
                    const s = a
                },
                2839: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Z: () => s
                    });
                    var i = n(8081),
                        o = n.n(i),
                        r = n(3645),
                        a = n.n(r)()(o());
                    a.push([e.id, '#meddler{all:initial;width:100%;height:100%;position:absolute;top:0px;right:0px;pointer-events:none;padding:0px;margin:0px;border:none;font-family:"Readex Pro"}#meddler #download-widget{width:100%;height:80px;background-color:#f5f5f5;position:fixed;bottom:0px;display:flex;flex-direction:row;align-items:flex-start}#meddler #download-widget .file-download-panel{pointer-events:auto;width:300px;border-right:solid 1px rgba(28,47,92,.05);padding:18px 16px}#meddler #download-widget .file-download-panel.complete{background-color:rgba(111,207,151,.1)}#meddler #download-widget .file-download-panel.downloading,#meddler #download-widget .file-download-panel.scanning{padding-top:8px;padding-bottom:8px}#meddler #download-widget .file-download-panel.downloading .file-download-action,#meddler #download-widget .file-download-panel.scanning .file-download-action{margin-bottom:4px}#meddler #download-widget .file-download-panel.downloading .file-download-details .file-ops,#meddler #download-widget .file-download-panel.scanning .file-download-details .file-ops{margin:initial}#meddler #download-widget .file-download-panel .file-download-action{font-size:12px;font-family:"Readex Pro";font-weight:700;line-height:16px;color:rgba(28,47,92,.7)}#meddler #download-widget .file-download-panel .file-download-details{display:flex;flex-direction:row;align-items:flex-start;gap:16px}#meddler #download-widget .file-download-panel .file-download-details .file-download-icon{height:44px;width:44px}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs{flex:1;display:flex;flex-direction:column;align-self:center;gap:4px}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-filename{font-family:"Readex Pro";font-size:16px;line-height:24px;font-weight:400}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status{font-family:"Readex Pro";font-weight:400;font-size:12px;line-height:16px}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.downloading,#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.scanning{color:#1c2f5c}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked{color:#c74646}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{color:#44be90}#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked,#meddler #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{font-weight:700}#meddler #download-widget .file-download-panel .file-download-details .file-ops{width:24px;margin:auto}#meddler .flashlight-shadow{background-color:rgba(0,0,0,.5);position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity}#meddler .flashlight{position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity;background:radial-gradient(ellipse at center, transparent, transparent 60%, rgba(0, 0, 0, 0.5) 70%)}#meddler .radar-wrapper{width:300px;position:absolute;height:100%;right:0px}#meddler .radar-wrapper .augmentation-radar{pointer-events:auto;position:absolute;right:-27px;width:54px;height:54px;border-radius:27px;display:flex;justify-content:center;align-items:center;background-color:rgba(255,192,0,.1)}#meddler .radar-wrapper .augmentation-radar div.circle1{border-radius:14px;display:flex;justify-content:center;align-items:center;width:27px;height:27px;background-color:rgba(255,192,0,.3)}#meddler .radar-wrapper .augmentation-radar div.circle1 div.circle2{border-radius:8px;background-color:#ffc000;width:15px;height:15px}#meddler .radar-wrapper .bubble-with-arrow{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 12px 24px -4px rgba(145,158,171,.12);width:fit-content;height:fit-content;max-width:300px;opacity:0}#meddler .radar-wrapper .bubble-with-arrow div{font:inherit;color:inherit}#meddler .radar-wrapper .augmentation-radar:hover+.bubble-with-arrow{opacity:1}#meddler .radar-wrapper.top .augmentation-radar{top:-27px}#meddler .radar-wrapper.top .bubble-with-arrow{transform:translate(-80%, calc(-100% - 20px))}#meddler .radar-wrapper.bottom .augmentation-radar{bottom:-27px}#meddler .radar-wrapper.bottom .bubble-with-arrow{transform:translate(-80%, 20px)}#meddler .disabler{position:absolute;pointer-events:auto;background-color:rgba(80,80,80,.5);cursor:not-allowed}#meddler .walkthrough-box{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 16px 48px 0px rgba(0,0,0,.18);position:absolute;width:300px;max-height:100px;min-height:100px;display:flex;flex-direction:column;justify-content:start;transition-duration:.4s;transition-property:top,left,min-height,max-height,opacity;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);overflow:hidden;z-index:2;padding:0px}#meddler .walkthrough-box .walkthrough-box-content-wrapper .walkthrough-box-content-padding{padding:15px;display:flex;flex-direction:column}#meddler .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:flex;align-items:center;justify-content:center;background-color:rgba(16,25,107,.04)}#meddler .walkthrough-box.wide{width:355px}#meddler .walkthrough-box .closeButton{position:absolute;top:10px;right:10px;cursor:pointer}#meddler .walkthrough-box .text{font-size:14px;font-weight:400;font-family:"Readex Pro";color:#1c2f5c;opacity:0}#meddler .walkthrough-box .buttons-wrapper{display:flex;flex-direction:row;justify-content:space-between;align-items:center;margin-top:30px}#meddler .walkthrough-box .buttons-wrapper .button{pointer-events:auto;height:38px;width:44px;border-radius:8px;text-align:center;font-size:15px;font-weight:500;cursor:pointer;background-color:#fff;border:solid 2px #f5f5f5;color:#1c2f5c;display:flex;align-items:center;justify-content:center}#meddler .walkthrough-box .buttons-wrapper .button.invisible{opacity:0}#meddler .walkthrough-box .buttons-wrapper .button.primary{background-color:#1c2f5c;color:#fff;border-color:#1c2f5c}@media(max-width: 480px){#meddler .walkthrough-box .buttons-wrapper .button.primary{margin-right:50px}}#meddler .walkthrough-box .buttons-wrapper .button.button-text{padding:10px 30px;width:auto;display:block;box-sizing:border-box}#meddler .walkthrough-box .buttons-wrapper .progress{font-family:"Readex Pro";font-size:12px}@media(max-width: 480px){#meddler .walkthrough-box{position:fixed;width:100%;top:auto !important;left:0 !important;bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0}#meddler .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:none}}#meddler .focus-mask{position:absolute;top:0px;left:0px;height:100%;width:100%;transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:clip-path,opacity;background:repeating-linear-gradient(-45deg, rgba(0, 0, 0, 0.28) 0px, rgba(0, 0, 0, 0.2) 1px, rgba(0, 0, 0, 0.2) 4px, rgba(0, 0, 0, 0.28) 5px);z-index:-1}#meddler .custom-element-augmentation{position:absolute;box-sizing:border-box;pointer-events:none}#meddler .iframe-aug-wrapper{position:fixed;width:100%;height:100%;z-index:-3}#meddler .iframe-aug-wrapper .iframe-aug-bg-mask{position:fixed;background-color:#637381;width:100%;height:100%;z-index:1;pointer-events:auto}#meddler .iframe-aug-wrapper .iframe-aug{position:fixed;top:50%;left:50%;transform:translate(-50%, -50%);width:796px;height:532px;box-shadow:0px 16px 48px rgba(0,0,0,.176);border-radius:16px;border:none;z-index:2;background-color:#fff;pointer-events:auto}@media(max-width: 480px){#meddler .iframe-aug-wrapper .iframe-aug{top:20px;width:90%;height:70%;transform:translate(-50%, 0)}}#meddler .meddler-blur-mask{position:fixed;width:100%;height:100%;background-color:rgba(120,120,120,.7)}@supports(backdrop-filter: none){#meddler .meddler-blur-mask{background-color:rgba(120,120,120,.3);backdrop-filter:blur(10px)}}#meddler .bubble-with-arrow{position:absolute;border-radius:8px;box-shadow:0px 8px 16px rgba(145,158,171,.12);z-index:0;background-color:#fff}#meddler .bubble-with-arrow .content-container{background-color:inherit;display:block;border-radius:inherit}#meddler .bubble-with-arrow .content-container .the-content{height:100%;width:100%;background-color:inherit;z-index:0;padding:10px;padding-right:0px;display:block;box-sizing:border-box;border-radius:inherit}#meddler .bubble-with-arrow .content-container .the-content div{word-wrap:break-word}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{display:block;padding:44px 80px 48px 115px;overflow:hidden;position:relative}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding-top:1px;z-index:1;position:relative;pointer-events:auto}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{position:absolute;top:14px;left:-2px}#meddler .bubble-with-arrow .the-arrow{background-color:#fff;position:absolute;height:20px;width:20px;box-sizing:border-box;transform:translate(-50%) rotate(45deg);border-bottom:inherit;border-right:inherit;box-shadow:inherit;background-color:inherit;z-index:-1}@media(max-width: 480px){#meddler .bubble-with-arrow{left:8px !important;top:19px !important;width:calc(100% - 16px);box-sizing:border-box;max-width:initial}#meddler .bubble-with-arrow .content-container{padding:28px 12px}#meddler .bubble-with-arrow .content-container .the-content{padding:0px}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{padding:0px;background-color:rgba(0,0,0,.08);display:flex;justify-content:center;border-radius:20px}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding:7px 0px;z-index:1;position:relative}#meddler .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{display:none}}#meddler .warningframe{z-index:1}#meddler div{all:initial;pointer-events:none}#meddler button{all:initial}#meddler.fading-children #download-widget{width:100%;height:80px;background-color:#f5f5f5;position:fixed;bottom:0px;display:flex;flex-direction:row;align-items:flex-start}#meddler.fading-children #download-widget .file-download-panel{pointer-events:auto;width:300px;border-right:solid 1px rgba(28,47,92,.05);padding:18px 16px}#meddler.fading-children #download-widget .file-download-panel.complete{background-color:rgba(111,207,151,.1)}#meddler.fading-children #download-widget .file-download-panel.downloading,#meddler.fading-children #download-widget .file-download-panel.scanning{padding-top:8px;padding-bottom:8px}#meddler.fading-children #download-widget .file-download-panel.downloading .file-download-action,#meddler.fading-children #download-widget .file-download-panel.scanning .file-download-action{margin-bottom:4px}#meddler.fading-children #download-widget .file-download-panel.downloading .file-download-details .file-ops,#meddler.fading-children #download-widget .file-download-panel.scanning .file-download-details .file-ops{margin:initial}#meddler.fading-children #download-widget .file-download-panel .file-download-action{font-size:12px;font-family:"Readex Pro";font-weight:700;line-height:16px;color:rgba(28,47,92,.7)}#meddler.fading-children #download-widget .file-download-panel .file-download-details{display:flex;flex-direction:row;align-items:flex-start;gap:16px}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-icon{height:44px;width:44px}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs{flex:1;display:flex;flex-direction:column;align-self:center;gap:4px}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-filename{font-family:"Readex Pro";font-size:16px;line-height:24px;font-weight:400}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status{font-family:"Readex Pro";font-weight:400;font-size:12px;line-height:16px}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.downloading,#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.scanning{color:#1c2f5c}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked{color:#c74646}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{color:#44be90}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.blocked,#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-download-specs .file-download-status.complete{font-weight:700}#meddler.fading-children #download-widget .file-download-panel .file-download-details .file-ops{width:24px;margin:auto}#meddler.fading-children .flashlight-shadow{background-color:rgba(0,0,0,.5);position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity}#meddler.fading-children .flashlight{position:absolute;transition-duration:.4s;transition-property:width,height,top,left,opacity;background:radial-gradient(ellipse at center, transparent, transparent 60%, rgba(0, 0, 0, 0.5) 70%)}#meddler.fading-children .radar-wrapper{width:300px;position:absolute;height:100%;right:0px}#meddler.fading-children .radar-wrapper .augmentation-radar{pointer-events:auto;position:absolute;right:-27px;width:54px;height:54px;border-radius:27px;display:flex;justify-content:center;align-items:center;background-color:rgba(255,192,0,.1)}#meddler.fading-children .radar-wrapper .augmentation-radar div.circle1{border-radius:14px;display:flex;justify-content:center;align-items:center;width:27px;height:27px;background-color:rgba(255,192,0,.3)}#meddler.fading-children .radar-wrapper .augmentation-radar div.circle1 div.circle2{border-radius:8px;background-color:#ffc000;width:15px;height:15px}#meddler.fading-children .radar-wrapper .bubble-with-arrow{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 12px 24px -4px rgba(145,158,171,.12);width:fit-content;height:fit-content;max-width:300px;opacity:0}#meddler.fading-children .radar-wrapper .bubble-with-arrow div{font:inherit;color:inherit}#meddler.fading-children .radar-wrapper .augmentation-radar:hover+.bubble-with-arrow{opacity:1}#meddler.fading-children .radar-wrapper.top .augmentation-radar{top:-27px}#meddler.fading-children .radar-wrapper.top .bubble-with-arrow{transform:translate(-80%, calc(-100% - 20px))}#meddler.fading-children .radar-wrapper.bottom .augmentation-radar{bottom:-27px}#meddler.fading-children .radar-wrapper.bottom .bubble-with-arrow{transform:translate(-80%, 20px)}#meddler.fading-children .disabler{position:absolute;pointer-events:auto;background-color:rgba(80,80,80,.5);cursor:not-allowed}#meddler.fading-children .walkthrough-box{box-sizing:border-box;border-radius:8px;font-family:"Readex Pro";font-size:14px;font-weight:400;line-height:20px;letter-spacing:.01em;padding:16px;color:#1c2f5c;background-color:#fff;box-shadow:0px 16px 48px 0px rgba(0,0,0,.18);position:absolute;width:300px;max-height:100px;min-height:100px;display:flex;flex-direction:column;justify-content:start;transition-duration:.4s;transition-property:top,left,min-height,max-height,opacity;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);overflow:hidden;z-index:2;padding:0px}#meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .walkthrough-box-content-padding{padding:15px;display:flex;flex-direction:column}#meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:flex;align-items:center;justify-content:center;background-color:rgba(16,25,107,.04)}#meddler.fading-children .walkthrough-box.wide{width:355px}#meddler.fading-children .walkthrough-box .closeButton{position:absolute;top:10px;right:10px;cursor:pointer}#meddler.fading-children .walkthrough-box .text{font-size:14px;font-weight:400;font-family:"Readex Pro";color:#1c2f5c;opacity:0}#meddler.fading-children .walkthrough-box .buttons-wrapper{display:flex;flex-direction:row;justify-content:space-between;align-items:center;margin-top:30px}#meddler.fading-children .walkthrough-box .buttons-wrapper .button{pointer-events:auto;height:38px;width:44px;border-radius:8px;text-align:center;font-size:15px;font-weight:500;cursor:pointer;background-color:#fff;border:solid 2px #f5f5f5;color:#1c2f5c;display:flex;align-items:center;justify-content:center}#meddler.fading-children .walkthrough-box .buttons-wrapper .button.invisible{opacity:0}#meddler.fading-children .walkthrough-box .buttons-wrapper .button.primary{background-color:#1c2f5c;color:#fff;border-color:#1c2f5c}@media(max-width: 480px){#meddler.fading-children .walkthrough-box .buttons-wrapper .button.primary{margin-right:50px}}#meddler.fading-children .walkthrough-box .buttons-wrapper .button.button-text{padding:10px 30px;width:auto;display:block;box-sizing:border-box}#meddler.fading-children .walkthrough-box .buttons-wrapper .progress{font-family:"Readex Pro";font-size:12px}@media(max-width: 480px){#meddler.fading-children .walkthrough-box{position:fixed;width:100%;top:auto !important;left:0 !important;bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0}#meddler.fading-children .walkthrough-box .walkthrough-box-content-wrapper .title-image-wrapper{display:none}}#meddler.fading-children .focus-mask{position:absolute;top:0px;left:0px;height:100%;width:100%;transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:clip-path,opacity;background:repeating-linear-gradient(-45deg, rgba(0, 0, 0, 0.28) 0px, rgba(0, 0, 0, 0.2) 1px, rgba(0, 0, 0, 0.2) 4px, rgba(0, 0, 0, 0.28) 5px);z-index:-1}#meddler.fading-children .custom-element-augmentation{position:absolute;box-sizing:border-box;pointer-events:none}#meddler.fading-children .iframe-aug-wrapper{position:fixed;width:100%;height:100%;z-index:-3}#meddler.fading-children .iframe-aug-wrapper .iframe-aug-bg-mask{position:fixed;background-color:#637381;width:100%;height:100%;z-index:1;pointer-events:auto}#meddler.fading-children .iframe-aug-wrapper .iframe-aug{position:fixed;top:50%;left:50%;transform:translate(-50%, -50%);width:796px;height:532px;box-shadow:0px 16px 48px rgba(0,0,0,.176);border-radius:16px;border:none;z-index:2;background-color:#fff;pointer-events:auto}@media(max-width: 480px){#meddler.fading-children .iframe-aug-wrapper .iframe-aug{top:20px;width:90%;height:70%;transform:translate(-50%, 0)}}#meddler.fading-children .meddler-blur-mask{position:fixed;width:100%;height:100%;background-color:rgba(120,120,120,.7)}@supports(backdrop-filter: none){#meddler.fading-children .meddler-blur-mask{background-color:rgba(120,120,120,.3);backdrop-filter:blur(10px)}}#meddler.fading-children .bubble-with-arrow{position:absolute;border-radius:8px;box-shadow:0px 8px 16px rgba(145,158,171,.12);z-index:0;background-color:#fff}#meddler.fading-children .bubble-with-arrow .content-container{background-color:inherit;display:block;border-radius:inherit}#meddler.fading-children .bubble-with-arrow .content-container .the-content{height:100%;width:100%;background-color:inherit;z-index:0;padding:10px;padding-right:0px;display:block;box-sizing:border-box;border-radius:inherit}#meddler.fading-children .bubble-with-arrow .content-container .the-content div{word-wrap:break-word}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{display:block;padding:44px 80px 48px 115px;overflow:hidden;position:relative}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding-top:1px;z-index:1;position:relative;pointer-events:auto}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{position:absolute;top:14px;left:-2px}#meddler.fading-children .bubble-with-arrow .the-arrow{background-color:#fff;position:absolute;height:20px;width:20px;box-sizing:border-box;transform:translate(-50%) rotate(45deg);border-bottom:inherit;border-right:inherit;box-shadow:inherit;background-color:inherit;z-index:-1}@media(max-width: 480px){#meddler.fading-children .bubble-with-arrow{left:8px !important;top:19px !important;width:calc(100% - 16px);box-sizing:border-box;max-width:initial}#meddler.fading-children .bubble-with-arrow .content-container{padding:28px 12px}#meddler.fading-children .bubble-with-arrow .content-container .the-content{padding:0px}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer{padding:0px;background-color:rgba(0,0,0,.08);display:flex;justify-content:center;border-radius:20px}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer .bubble-urlbar-text{padding:7px 0px;z-index:1;position:relative}#meddler.fading-children .bubble-with-arrow .content-container .the-content .bubble-urlbar .bubbler-spacer svg{display:none}}#meddler.fading-children .warningframe{z-index:1}#meddler.fading-children div{opacity:0;transition:opacity .4s ease-in-out}#meddler.fading-children div.visible{opacity:1}#meddler.fading-children div.visible div{opacity:1}', ""]);
                    const s = a
                },
                5863: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Z: () => s
                    });
                    var i = n(8081),
                        o = n.n(i),
                        r = n(3645),
                        a = n.n(r)()(o());
                    a.push([e.id, "@import url(https://fonts.googleapis.com/css2?family=Readex+Pro:wght@400;500;700&display=swap);"]), a.push([e.id, 'html{overflow:scroll;overflow-x:hidden}::-webkit-scrollbar{width:0px;background:transparent}body{margin:0px;background-color:#fff}#tara-container{display:flex;flex-direction:column;height:100%;background-color:#fff;border-radius:16px 16px 4px 16px}@media(max-width: 480px){#tara-container{border-bottom-left-radius:0px;border-bottom-right-radius:0px}}.noshow{display:none}.height0{height:0px !important;padding:0px !important;margin:0px !important}.opacity0{opacity:0 !important}.shrinkable{transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:padding,margin,height}.fadeable{transition:opacity .4s cubic-bezier(0.215, 0.61, 0.355, 1)}.shrinknfade{transition-duration:.4s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:opacity,padding,margin,height}.tara-header{display:flex;flex-direction:row;justify-content:space-between;background-color:#10196b;align-items:center;height:44px;padding:12px;position:relative;box-sizing:border-box}@media(max-width: 480px){.tara-header{border:solid 2px #dcdcdc;border-bottom:none;border-top-left-radius:15px;border-top-right-radius:15px}}.tara-header .tara-header-component{display:flex;flex-direction:row;align-items:center}.tara-header .tara-header-component:first-child{justify-content:flex-start}.tara-header .tara-header-component:last-child{justify-content:flex-end}.tara-header #status{padding:4px 8px;background-color:transparent;opacity:0px;transition:opacity .2s cubic-bezier(0.215, 0.61, 0.355, 1)}.tara-header #status.warning{background-color:#ffc000;opacity:1px}.tara-header #status.error{background-color:#fc004a;opacity:1px}.tara-header #minimizer{width:15px;height:15px;display:flex;align-items:center;justify-content:center;margin-right:5px;cursor:pointer}.tara-header #minimizer div{width:10px;height:2px;background-color:#fff}.tara-header #tara-header-logo{margin-right:12px}.tara-header #tara-header-logo svg{width:20px;height:20px}.outlook-addin .tara-header{height:48px;justify-content:flex-start;gap:12px;padding-left:24px}.outlook-addin .tara-header:before{content:"powered by ";display:inline-block;font-family:"Readex Pro";color:#fff;font-size:12px}.outlook-addin #minimizer{display:none}#tara-user-input{box-sizing:border-box;min-height:53px;padding:16px 17px;flex-shrink:0;width:100%;overflow:hidden;position:relative;border-top:solid 1px rgba(0,0,0,.1);margin-top:auto}#tara-user-input #input-wrapper{display:flex;justify-content:space-between;flex-direction:row}#tara-user-input #input-wrapper .question-box{flex:1;margin-right:24px;height:18px;border:none;font-size:14px;line-height:18px;font-weight:500;font-family:"Readex Pro";color:#525252;outline:none}@media(max-width: 320px){#tara-user-input #input-wrapper .question-box{font-size:13px}}#tara-user-input #input-wrapper svg{width:16px;height:16px;cursor:pointer}#tara-chat-container{padding:0px 16px;overflow:scroll}#tara-floating-logo{width:30px;height:30px;bottom:0px;left:0px;transition:opacity .4s cubic-bezier(0.215, 0.61, 0.355, 1),top .4s cubic-bezier(0.215, 0.61, 0.355, 1);position:absolute}#tara-text-messages{padding-top:16px;position:relative}#scroll-target{height:0px}#chat-welcome{text-align:center;padding-right:42px;padding-top:34px}#chat-welcome #hand-wave-container{width:50px;height:50px;margin:auto;margin-bottom:23px}#chat-welcome #welcome-text{font-family:"Readex Pro";font-size:16px;font-weight:700;font-stretch:normal;font-style:normal;line-height:normal;letter-spacing:normal;text-align:center;color:#858585}@media(max-width: 320px){#chat-welcome #welcome-text{font-size:13px}}.tara-message-outer-container{width:100%;display:flex;flex-direction:column}.tara-message-outer-container.tara-container{justify-content:left}.tara-message-outer-container.user-container{justify-content:right}.tara-message-container{display:inline-block}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper{width:60%;min-width:280px;max-width:100%;display:flex;flex-direction:column;margin-bottom:16px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-header{background-color:rgba(145,158,171,.08);display:flex;flex-direction:row;justify-content:space-between;align-items:center;height:48px;border-top-left-radius:20px;border-top-right-radius:20px;padding:0px 16px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-header .category-name{color:#212b36;font-size:14px;font-family:"Readex Pro"}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-header .category-select-all{color:#36f;text-decoration:underline;cursor:pointer;font-size:14px;font-family:"Readex Pro"}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content{display:flex;flex-direction:column;border:solid 1px #dfe3e8;border-radius:20px;border-top-left-radius:0px;border-top-right-radius:0px;margin-bottom:16px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item{height:48px;border-bottom:solid 1px #dfe3e8;display:flex;flex-direction:row;align-items:center;padding:0px 16px;gap:12px;font-size:14px;font-family:"Readex Pro";justify-content:flex-start}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item:last-of-type{border-bottom:none;border-bottom-left-radius:20px;border-bottom-right-radius:20px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item.warning{background-color:#ffe7d9}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item svg{width:24px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item input{width:17px;height:17px;box-sizing:border-box;border:solid 2px #454f5b}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item .item-action{margin-left:auto;position:relative;z-index:2}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item .item-action:hover .bubble-with-arrow{opacity:1}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item .item-action .bubble-with-arrow{transition:opacity .4s cubic-bezier(0.215, 0.61, 0.355, 1);opacity:0;pointer-events:none;position:absolute;border-radius:8px;background-color:#000;color:#fff;font-size:12px;font-family:"Readex Pro";padding:6px;bottom:170%;right:-25px;width:100px}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item .item-action .bubble-with-arrow .the-arrow{right:17px;top:85%;transform:rotate(45deg) translate(0, 100%);position:absolute;height:20px;width:20px;box-sizing:border-box;transform:rotate(45deg) translate(-50%);border-bottom:inherit;border-right:inherit;box-shadow:inherit;background-color:inherit;z-index:-1}.tara-message-container.categorymultiselect-message .category-multi-select-wrapper .category-wrapper .category-content .category-item .item-action.warning{height:17px;width:17px;background-color:#b72136;color:#ffe7d9;text-align:center;font-size:13px;border-radius:8px;line-height:18px}.tara-message-container.tara-message .message-box,.tara-message-container.categorymultiselect-message .message-box{background-color:rgba(51,102,255,.08);border-bottom-left-radius:0px}.tara-message-container.tara-message .message-box.warning,.tara-message-container.categorymultiselect-message .message-box.warning{background-color:#ffc000;font-weight:700}.tara-message-container.tara-message .message-box.error,.tara-message-container.categorymultiselect-message .message-box.error{background-color:#fc004a;font-weight:700}.tara-message-container.tara-message .message-box.dot-flashing,.tara-message-container.categorymultiselect-message .message-box.dot-flashing{position:relative;left:15px;padding:0px;width:10px;height:10px;border-radius:5px;background-color:#5c6bc0;color:#5c6bc0;-webkit-animation:dot-flashing 1s infinite linear alternate;animation:dot-flashing 1s infinite linear alternate;-webkit-animation-delay:.5s;animation-delay:.5s}.tara-message-container.tara-message .message-box.dot-flashing::before,.tara-message-container.tara-message .message-box.dot-flashing::after,.tara-message-container.categorymultiselect-message .message-box.dot-flashing::before,.tara-message-container.categorymultiselect-message .message-box.dot-flashing::after{content:"";display:inline-block;position:absolute;top:0}.tara-message-container.tara-message .message-box.dot-flashing::before,.tara-message-container.categorymultiselect-message .message-box.dot-flashing::before{left:-15px;width:10px;height:10px;border-radius:5px;background-color:#5c6bc0;color:#5c6bc0;-webkit-animation:dot-flashing 1s infinite alternate;animation:dot-flashing 1s infinite alternate;-webkit-animation-delay:0s;animation-delay:0s}.tara-message-container.tara-message .message-box.dot-flashing::after,.tara-message-container.categorymultiselect-message .message-box.dot-flashing::after{left:15px;width:10px;height:10px;border-radius:5px;background-color:#5c6bc0;color:#5c6bc0;-webkit-animation:dot-flashing 1s infinite alternate;animation:dot-flashing 1s infinite alternate;-webkit-animation-delay:1s;animation-delay:1s}@-webkit-keyframes dot-flashing{0%{background-color:#5c6bc0}50%,100%{background-color:#f5f5f5}}@keyframes dot-flashing{0%{background-color:#5c6bc0}50%,100%{background-color:#f5f5f5}}.tara-message-container.user-message{align-self:flex-end}.tara-message-container.user-message .message-box{background-color:rgba(86,204,242,.1);text-align:right;color:#333;border-bottom-right-radius:0px}.tara-message-container .message-box{font-family:"Readex Pro";font-weight:500;font-size:14px;font-stretch:normal;font-style:normal;line-height:normal;letter-spacing:normal;display:inline-block;padding:17px 18px 19px;border-radius:20px;box-sizing:border-box;margin-bottom:14px;color:#1c2f5c}.tara-message-container .message-box.group{margin-bottom:5px}@media(max-width: 320px){.tara-message-container .message-box{font-size:13px}}.tara-message-container .tara-title-message{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:17px;margin-top:40px;margin-bottom:40px}.tara-message-container .tara-title-message .tara-title-message-title-text{font-family:"Readex Pro";font-weight:700;font-size:20px;line-height:30px;text-align:center;color:#283593}.tara-message-container .tara-title-message .tara-title-message-standard-text{color:#212b36;font-family:"Readex Pro";font-size:14px;line-height:22px;text-align:center;font-weight:400}.tara-message-container .tara-title-message .img-container{position:relative;min-height:50px}.tara-message-container .tara-title-message .img-container .title-image{position:absolute;top:50%;left:50%;transform:translate(-50%, -50%);z-index:1}.tara-message-container .tara-buttons{display:flex;margin-bottom:12px}.tara-message-container .tara-buttons.column{flex-direction:column;justify-content:end}.tara-message-container .tara-buttons.column button{margin:12px 0px 0px auto}.tara-message-container .tara-buttons.side-by-side{justify-content:flex-end;gap:12px}.tara-message-container .tara-buttons button{display:flex;flex-direction:row;justify-content:center;align-items:center;padding:10px;min-width:50px;height:36px;box-sizing:border-box;border:solid 1px rgba(28,47,92,.3);border-radius:8px;background-color:#fff;cursor:pointer;font-family:"Readex Pro";font-size:14px;font-weight:700;font-stretch:normal;font-style:normal;line-height:16px;letter-spacing:.01em;font-feature-settings:"ss02" on,"ss03" on,"ss04" on;color:#10196b}.tara-message-container .tara-buttons button.primary{background-color:#283593;border-color:#283593;color:#fff;box-shadow:0px 8px 16px rgba(51,102,255,.24)}.tara-message-container .tara-buttons button:first-child{margin-top:0px !important}.tara-message-container .tara-buttons button.disabled{opacity:.4;pointer-events:none;cursor:not-allowed}.tara-message-container .tara-buttons button.image{height:40px;box-sizing:border-box;padding:8px 19px;border-radius:20px;transition-duration:.3s;transition-timing-function:cubic-bezier(0.215, 0.61, 0.355, 1);transition-property:transform,margin,opacity;background-color:#f9fafb;border:solid 1px #c4cdd5;position:relative}.tara-message-container .tara-buttons button.image:hover{margin:0px 5px;transform:scale(1.15) translate(0, -10%);border-color:#74caff}@media(max-width: 320px){.tara-message-container .tara-buttons button{font-size:13px}}#tara-chips{display:flex;justify-content:center;padding:2px 10px 0px 10px;flex-wrap:wrap;width:90%;margin:auto}#tara-chips .chip{display:inline-block;height:40px;border-radius:20px;object-fit:contain;box-sizing:border-box;padding:0px 10px;background-color:#fff;border:solid 1px #10196b;font-family:"Readex Pro";font-size:13px;line-height:38px;font-weight:500;font-stretch:normal;font-style:normal;letter-spacing:normal;text-align:center;margin-bottom:14px;margin-right:14px;color:#10196b;cursor:pointer}#tara-chips .chip:last-child{margin-right:0px}', ""]);
                    const s = a
                },
                3645: e => {
                    "use strict";
                    e.exports = function(e) {
                        var t = [];
                        return t.toString = function() {
                            return this.map((function(t) {
                                var n = "",
                                    i = void 0 !== t[5];
                                return t[4] && (n += "@supports (".concat(t[4], ") {")), t[2] && (n += "@media ".concat(t[2], " {")), i && (n += "@layer".concat(t[5].length > 0 ? " ".concat(t[5]) : "", " {")), n += e(t), i && (n += "}"), t[2] && (n += "}"), t[4] && (n += "}"), n
                            })).join("")
                        }, t.i = function(e, n, i, o, r) {
                            "string" == typeof e && (e = [
                                [null, e, void 0]
                            ]);
                            var a = {};
                            if (i)
                                for (var s = 0; s < this.length; s++) {
                                    var l = this[s][0];
                                    null != l && (a[l] = !0)
                                }
                            for (var c = 0; c < e.length; c++) {
                                var d = [].concat(e[c]);
                                i && a[d[0]] || (void 0 !== r && (void 0 === d[5] || (d[1] = "@layer".concat(d[5].length > 0 ? " ".concat(d[5]) : "", " {").concat(d[1], "}")), d[5] = r), n && (d[2] ? (d[1] = "@media ".concat(d[2], " {").concat(d[1], "}"), d[2] = n) : d[2] = n), o && (d[4] ? (d[1] = "@supports (".concat(d[4], ") {").concat(d[1], "}"), d[4] = o) : d[4] = "".concat(o)), t.push(d))
                            }
                        }, t
                    }
                },
                8081: e => {
                    "use strict";
                    e.exports = function(e) {
                        return e[1]
                    }
                },
                9996: e => {
                    "use strict";
                    var t = function(e) {
                            return function(e) {
                                return !!e && "object" == typeof e
                            }(e) && ! function(e) {
                                var t = Object.prototype.toString.call(e);
                                return "[object RegExp]" === t || "[object Date]" === t || function(e) {
                                    return e.$$typeof === n
                                }(e)
                            }(e)
                        },
                        n = "function" == typeof Symbol && Symbol.for ? Symbol.for("react.element") : 60103;

                    function i(e, t) {
                        return !1 !== t.clone && t.isMergeableObject(e) ? s((n = e, Array.isArray(n) ? [] : {}), e, t) : e;
                        var n
                    }

                    function o(e, t, n) {
                        return e.concat(t).map((function(e) {
                            return i(e, n)
                        }))
                    }

                    function r(e) {
                        return Object.keys(e).concat(function(e) {
                            return Object.getOwnPropertySymbols ? Object.getOwnPropertySymbols(e).filter((function(t) {
                                return e.propertyIsEnumerable(t)
                            })) : []
                        }(e))
                    }

                    function a(e, t) {
                        try {
                            return t in e
                        } catch (e) {
                            return !1
                        }
                    }

                    function s(e, n, l) {
                        (l = l || {}).arrayMerge = l.arrayMerge || o, l.isMergeableObject = l.isMergeableObject || t, l.cloneUnlessOtherwiseSpecified = i;
                        var c = Array.isArray(n);
                        return c === Array.isArray(e) ? c ? l.arrayMerge(e, n, l) : function(e, t, n) {
                            var o = {};
                            return n.isMergeableObject(e) && r(e).forEach((function(t) {
                                o[t] = i(e[t], n)
                            })), r(t).forEach((function(r) {
                                (function(e, t) {
                                    return a(e, t) && !(Object.hasOwnProperty.call(e, t) && Object.propertyIsEnumerable.call(e, t))
                                })(e, r) || (a(e, r) && n.isMergeableObject(t[r]) ? o[r] = function(e, t) {
                                    if (!t.customMerge) return s;
                                    var n = t.customMerge(e);
                                    return "function" == typeof n ? n : s
                                }(r, n)(e[r], t[r], n) : o[r] = i(t[r], n))
                            })), o
                        }(e, n, l) : i(n, l)
                    }
                    s.all = function(e, t) {
                        if (!Array.isArray(e)) throw new Error("first argument should be an array");
                        return e.reduce((function(e, n) {
                            return s(e, n, t)
                        }), {})
                    };
                    var l = s;
                    e.exports = l
                },
                2215: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        D0: () => a,
                        GW: () => u,
                        fo: () => l
                    });
                    var i = n(3431),
                        o = n(2313),
                        r = n(896);

                    function a(e, t, n, r) {
                        ! function(e) {
                            if (void 0 !== e) throw new Error(i.Cl)
                        }(t), s(o.TAGGED, e, n.toString(), r)
                    }

                    function s(e, t, n, o) {
                        var a = function(e) {
                                var t = [];
                                if (Array.isArray(e)) {
                                    t = e;
                                    var n = (0, r.D)(t.map((function(e) {
                                        return e.key
                                    })));
                                    if (void 0 !== n) throw new Error(i.O8 + " " + n.toString())
                                } else t = [e];
                                return t
                            }(o),
                            s = {};
                        Reflect.hasOwnMetadata(e, t) && (s = Reflect.getMetadata(e, t));
                        var l = s[n];
                        if (void 0 === l) l = [];
                        else
                            for (var c = function(e) {
                                    if (a.some((function(t) {
                                            return t.key === e.key
                                        }))) throw new Error(i.O8 + " " + e.key.toString())
                                }, d = 0, u = l; d < u.length; d++) c(u[d]);
                        l.push.apply(l, a), s[n] = l, Reflect.defineMetadata(e, s, t)
                    }

                    function l(e) {
                        return function(t, n, r) {
                            "number" == typeof r ? a(t, n, r, e) : function(e, t, n) {
                                if (void 0 !== e.prototype) throw new Error(i.Cl);
                                s(o.TAGGED_PROP, e.constructor, t, n)
                            }(t, n, e)
                        }
                    }

                    function c(e, t) {
                        Reflect.decorate(e, t)
                    }

                    function d(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    }

                    function u(e, t, n) {
                        "number" == typeof n ? c([d(n, e)], t) : "string" == typeof n ? Reflect.decorate([e], t, n) : c([e], t)
                    }
                },
                7365: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        f: () => o
                    });
                    var i = n(2313),
                        o = (0, n(530).v)(i.INJECT_TAG)
                },
                530: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        v: () => a
                    });
                    var i = n(3431),
                        o = n(8625),
                        r = n(2215);

                    function a(e) {
                        return function(t) {
                            return function(n, a, s) {
                                if (void 0 === t) {
                                    var l = "function" == typeof n ? n.name : n.constructor.name;
                                    throw new Error((0, i.MS)(l))
                                }
                                return (0, r.fo)(new o.S(e, t))(n, a, s)
                            }
                        }
                    }
                },
                403: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        b: () => r
                    });
                    var i = n(3431),
                        o = n(2313);

                    function r() {
                        return function(e) {
                            if (Reflect.hasOwnMetadata(o.PARAM_TYPES, e)) throw new Error(i.gf);
                            var t = Reflect.getMetadata(o.DESIGN_PARAM_TYPES, e) || [];
                            return Reflect.defineMetadata(o.PARAM_TYPES, t, e), e
                        }
                    }
                },
                6315: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        h: () => i
                    });
                    var i = function() {
                        function e(e) {
                            this._cb = e
                        }
                        return e.prototype.unwrap = function() {
                            return this._cb()
                        }, e
                    }()
                },
                7936: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        N: () => a
                    });
                    var i = n(2313),
                        o = n(8625),
                        r = n(2215);

                    function a() {
                        return function(e, t, n) {
                            var a = new o.S(i.UNMANAGED_TAG, !0);
                            (0, r.D0)(e, t, n, a)
                        }
                    }
                },
                3431: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        $z: () => P,
                        Cl: () => v,
                        DL: () => E,
                        FJ: () => b,
                        GF: () => d,
                        H1: () => r,
                        Kt: () => s,
                        MS: () => p,
                        NE: () => g,
                        O8: () => o,
                        QY: () => h,
                        VF: () => l,
                        YG: () => M,
                        aD: () => R,
                        cm: () => c,
                        d1: () => y,
                        eP: () => u,
                        gf: () => i,
                        gq: () => O,
                        iD: () => A,
                        iI: () => w,
                        jT: () => f,
                        k_: () => k,
                        pv: () => m,
                        rR: () => C,
                        tE: () => I,
                        vD: () => S,
                        wk: () => x,
                        xU: () => _,
                        xZ: () => T,
                        yu: () => a
                    });
                    var i = "Cannot apply @injectable decorator multiple times.",
                        o = "Metadata key was used more than once in a parameter:",
                        r = "NULL argument",
                        a = "Key Not Found",
                        s = "Ambiguous match found for serviceIdentifier:",
                        l = "Could not unbind serviceIdentifier:",
                        c = "No matching bindings found for serviceIdentifier:",
                        d = "Missing required @injectable annotation in:",
                        u = "Missing required @inject or @multiInject annotation in:",
                        p = function(e) {
                            return "@inject called with undefined this could mean that the class " + e + " has a circular dependency problem. You can use a LazyServiceIdentifer to  overcome this limitation."
                        },
                        h = "Circular dependency found:",
                        f = "Invalid binding type:",
                        g = "No snapshot available to restore.",
                        m = "Invalid return type in middleware. Middleware must return!",
                        y = "Value provided to function binding must be a function!",
                        b = function(e) {
                            return "You are attempting to construct '" + e + "' in a synchronous way\n but it has asynchronous dependencies."
                        },
                        x = "The toSelf function can only be applied when a constructor is used as service identifier",
                        v = "The @inject @multiInject @tagged and @named decorators must be applied to the parameters of a class constructor or a class property.",
                        w = function() {
                            for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
                            return "The number of constructor arguments in the derived class " + e[0] + " must be >= than the number of constructor arguments of its base class."
                        },
                        _ = "Invalid Container constructor argument. Container options must be an object.",
                        k = "Invalid Container option. Default scope must be a string ('singleton' or 'transient').",
                        C = "Invalid Container option. Auto bind injectable must be a boolean",
                        S = "Invalid Container option. Skip base check must be a boolean",
                        E = "Cannot apply @preDestroy decorator multiple times in the same class",
                        I = "Cannot apply @postConstruct decorator multiple times in the same class",
                        A = "Attempting to unbind dependency with asynchronous destruction (@preDestroy or onDeactivation)",
                        O = function(e, t) {
                            return "@postConstruct error in class " + e + ": " + t
                        },
                        T = function(e, t) {
                            return "@preDestroy error in class " + e + ": " + t
                        },
                        M = function(e, t) {
                            return "onDeactivation() error in class " + e + ": " + t
                        },
                        R = function(e, t) {
                            return "It looks like there is a circular dependency in one of the '" + e + "' bindings. Please investigate bindings withservice identifier '" + t + "'."
                        },
                        P = "Maximum call stack size exceeded"
                },
                5466: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Nj: () => r,
                        Nt: () => o,
                        h6: () => i
                    });
                    var i = {
                            Request: "Request",
                            Singleton: "Singleton",
                            Transient: "Transient"
                        },
                        o = {
                            ConstantValue: "ConstantValue",
                            Constructor: "Constructor",
                            DynamicValue: "DynamicValue",
                            Factory: "Factory",
                            Function: "Function",
                            Instance: "Instance",
                            Invalid: "Invalid",
                            Provider: "Provider"
                        },
                        r = {
                            ClassProperty: "ClassProperty",
                            ConstructorArgument: "ConstructorArgument",
                            Variable: "Variable"
                        }
                },
                2313: (e, t, n) => {
                    "use strict";
                    n.r(t), n.d(t, {
                        DESIGN_PARAM_TYPES: () => p,
                        INJECT_TAG: () => s,
                        MULTI_INJECT_TAG: () => l,
                        NAMED_TAG: () => i,
                        NAME_TAG: () => o,
                        NON_CUSTOM_TAG_KEYS: () => g,
                        OPTIONAL_TAG: () => a,
                        PARAM_TYPES: () => u,
                        POST_CONSTRUCT: () => h,
                        PRE_DESTROY: () => f,
                        TAGGED: () => c,
                        TAGGED_PROP: () => d,
                        UNMANAGED_TAG: () => r
                    });
                    var i = "named",
                        o = "name",
                        r = "unmanaged",
                        a = "optional",
                        s = "inject",
                        l = "multi_inject",
                        c = "inversify:tagged",
                        d = "inversify:tagged_props",
                        u = "inversify:paramtypes",
                        p = "design:paramtypes",
                        h = "post_construct",
                        f = "pre_destroy",
                        g = [s, l, o, r, i, a]
                },
                8402: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        W: () => de
                    });
                    var i = n(5466),
                        o = n(5054),
                        r = function() {
                            function e(e, t) {
                                this.id = (0, o.id)(), this.activated = !1, this.serviceIdentifier = e, this.scope = t, this.type = i.Nt.Invalid, this.constraint = function(e) {
                                    return !0
                                }, this.implementationType = null, this.cache = null, this.factory = null, this.provider = null, this.onActivation = null, this.onDeactivation = null, this.dynamicValue = null
                            }
                            return e.prototype.clone = function() {
                                var t = new e(this.serviceIdentifier, this.scope);
                                return t.activated = t.scope === i.h6.Singleton && this.activated, t.implementationType = this.implementationType, t.dynamicValue = this.dynamicValue, t.scope = this.scope, t.type = this.type, t.factory = this.factory, t.provider = this.provider, t.constraint = this.constraint, t.onActivation = this.onActivation, t.onDeactivation = this.onDeactivation, t.cache = this.cache, t
                            }, e
                        }(),
                        a = n(3431),
                        s = n(2313),
                        l = n(9546);

                    function c(e) {
                        return e instanceof RangeError || e.message === a.$z
                    }
                    var d = n(5120),
                        u = function() {
                            function e(e) {
                                this.id = (0, o.id)(), this.container = e
                            }
                            return e.prototype.addPlan = function(e) {
                                this.plan = e
                            }, e.prototype.setCurrentRequest = function(e) {
                                this.currentRequest = e
                            }, e
                        }(),
                        p = n(8625),
                        h = function(e, t) {
                            this.parentContext = e, this.rootRequest = t
                        },
                        f = n(6315),
                        g = function() {
                            function e(e) {
                                this.str = e
                            }
                            return e.prototype.startsWith = function(e) {
                                return 0 === this.str.indexOf(e)
                            }, e.prototype.endsWith = function(e) {
                                var t, n = e.split("").reverse().join("");
                                return t = this.str.split("").reverse().join(""), this.startsWith.call({
                                    str: t
                                }, n)
                            }, e.prototype.contains = function(e) {
                                return -1 !== this.str.indexOf(e)
                            }, e.prototype.equals = function(e) {
                                return this.str === e
                            }, e.prototype.value = function() {
                                return this.str
                            }, e
                        }(),
                        m = function() {
                            function e(e, t, n, i) {
                                this.id = (0, o.id)(), this.type = e, this.serviceIdentifier = n;
                                var r = "symbol" == typeof t ? (0, d.We)(t) : t;
                                this.name = new g(r || ""), this.identifier = t, this.metadata = new Array;
                                var a = null;
                                "string" == typeof i ? a = new p.S(s.NAMED_TAG, i) : i instanceof p.S && (a = i), null !== a && this.metadata.push(a)
                            }
                            return e.prototype.hasTag = function(e) {
                                for (var t = 0, n = this.metadata; t < n.length; t++)
                                    if (n[t].key === e) return !0;
                                return !1
                            }, e.prototype.isArray = function() {
                                return this.hasTag(s.MULTI_INJECT_TAG)
                            }, e.prototype.matchesArray = function(e) {
                                return this.matchesTag(s.MULTI_INJECT_TAG)(e)
                            }, e.prototype.isNamed = function() {
                                return this.hasTag(s.NAMED_TAG)
                            }, e.prototype.isTagged = function() {
                                return this.metadata.some((function(e) {
                                    return s.NON_CUSTOM_TAG_KEYS.every((function(t) {
                                        return e.key !== t
                                    }))
                                }))
                            }, e.prototype.isOptional = function() {
                                return this.matchesTag(s.OPTIONAL_TAG)(!0)
                            }, e.prototype.getNamedTag = function() {
                                return this.isNamed() ? this.metadata.filter((function(e) {
                                    return e.key === s.NAMED_TAG
                                }))[0] : null
                            }, e.prototype.getCustomTags = function() {
                                return this.isTagged() ? this.metadata.filter((function(e) {
                                    return s.NON_CUSTOM_TAG_KEYS.every((function(t) {
                                        return e.key !== t
                                    }))
                                })) : null
                            }, e.prototype.matchesNamedTag = function(e) {
                                return this.matchesTag(s.NAMED_TAG)(e)
                            }, e.prototype.matchesTag = function(e) {
                                var t = this;
                                return function(n) {
                                    for (var i = 0, o = t.metadata; i < o.length; i++) {
                                        var r = o[i];
                                        if (r.key === e && r.value === n) return !0
                                    }
                                    return !1
                                }
                            }, e
                        }(),
                        y = function(e, t, n) {
                            if (n || 2 === arguments.length)
                                for (var i, o = 0, r = t.length; o < r; o++) !i && o in t || (i || (i = Array.prototype.slice.call(t, 0, o)), i[o] = t[o]);
                            return e.concat(i || Array.prototype.slice.call(t))
                        };

                    function b(e, t, n, i) {
                        var o = e.getConstructorMetadata(n),
                            r = o.compilerGeneratedMetadata;
                        if (void 0 === r) {
                            var s = a.GF + " " + t + ".";
                            throw new Error(s)
                        }
                        var l = o.userGeneratedMetadata,
                            c = Object.keys(l),
                            d = 0 === n.length && c.length > 0,
                            u = c.length > n.length,
                            p = function(e, t, n, i, o) {
                                for (var r = [], a = 0; a < o; a++) {
                                    var s = x(a, e, t, n, i);
                                    null !== s && r.push(s)
                                }
                                return r
                            }(i, t, r, l, d || u ? c.length : n.length),
                            h = w(e, n, t);
                        return y(y([], p, !0), h, !0)
                    }

                    function x(e, t, n, o, r) {
                        var s = r[e.toString()] || [],
                            l = k(s),
                            c = !0 !== l.unmanaged,
                            d = o[e];
                        if ((d = l.inject || l.multiInject || d) instanceof f.h && (d = d.unwrap()), c) {
                            if (!t && (d === Object || d === Function || void 0 === d)) {
                                var u = a.eP + " argument " + e + " in class " + n + ".";
                                throw new Error(u)
                            }
                            var p = new m(i.Nj.ConstructorArgument, l.targetName, d);
                            return p.metadata = s, p
                        }
                        return null
                    }

                    function v(e, t, n, i) {
                        var o = e || t;
                        if (void 0 === o) {
                            var r = a.GF + " for property " + String(n) + " in class " + i + ".";
                            throw new Error(r)
                        }
                        return o
                    }

                    function w(e, t, n) {
                        for (var o = e.getPropertiesMetadata(t), r = [], a = Object.getOwnPropertySymbols(o), s = 0, l = Object.keys(o).concat(a); s < l.length; s++) {
                            var c = l[s],
                                d = o[c],
                                u = k(d),
                                p = u.targetName || c,
                                h = v(u.inject, u.multiInject, c, n),
                                f = new m(i.Nj.ClassProperty, p, h);
                            f.metadata = d, r.push(f)
                        }
                        var g = Object.getPrototypeOf(t.prototype).constructor;
                        if (g !== Object) {
                            var b = w(e, g, n);
                            r = y(y([], r, !0), b, !0)
                        }
                        return r
                    }

                    function _(e, t) {
                        var n = Object.getPrototypeOf(t.prototype).constructor;
                        if (n !== Object) {
                            var i = b(e, (0, d.$P)(n), n, !0),
                                o = i.map((function(e) {
                                    return e.metadata.filter((function(e) {
                                        return e.key === s.UNMANAGED_TAG
                                    }))
                                })),
                                r = [].concat.apply([], o).length,
                                a = i.length - r;
                            return a > 0 ? a : _(e, n)
                        }
                        return 0
                    }

                    function k(e) {
                        var t = {};
                        return e.forEach((function(e) {
                            t[e.key.toString()] = e.value
                        })), {
                            inject: t[s.INJECT_TAG],
                            multiInject: t[s.MULTI_INJECT_TAG],
                            targetName: t[s.NAME_TAG],
                            unmanaged: t[s.UNMANAGED_TAG]
                        }
                    }
                    var C = function() {
                        function e(e, t, n, i, r) {
                            this.id = (0, o.id)(), this.serviceIdentifier = e, this.parentContext = t, this.parentRequest = n, this.target = r, this.childRequests = [], this.bindings = Array.isArray(i) ? i : [i], this.requestScope = null === n ? new Map : null
                        }
                        return e.prototype.addChildRequest = function(t, n, i) {
                            var o = new e(t, this.parentContext, this, n, i);
                            return this.childRequests.push(o), o
                        }, e
                    }();

                    function S(e) {
                        return e._bindingDictionary
                    }

                    function E(e, t, n, i, o) {
                        var r, s = A(n.container, o.serviceIdentifier);
                        return 0 === s.length && n.container.options.autoBindInjectable && "function" == typeof o.serviceIdentifier && e.getConstructorMetadata(o.serviceIdentifier).compilerGeneratedMetadata && (n.container.bind(o.serviceIdentifier).toSelf(), s = A(n.container, o.serviceIdentifier)), r = t ? s : s.filter((function(e) {
                                var t = new C(e.serviceIdentifier, n, i, e, o);
                                return e.constraint(t)
                            })),
                            function(e, t, n, i) {
                                switch (t.length) {
                                    case 0:
                                        if (n.isOptional()) return t;
                                        var o = (0, d.Cp)(e),
                                            r = a.cm;
                                        throw r += (0, d.BB)(o, n), r += (0, d.Vi)(i, o, A), new Error(r);
                                    case 1:
                                        return t;
                                    default:
                                        if (n.isArray()) return t;
                                        throw o = (0, d.Cp)(e), r = a.Kt + " " + o, r += (0, d.Vi)(i, o, A), new Error(r)
                                }
                            }(o.serviceIdentifier, r, o, n.container), r
                    }

                    function I(e, t, n, o, r, s) {
                        var l, c;
                        if (null === r) {
                            l = E(e, t, o, null, s), c = new C(n, o, null, l, s);
                            var u = new h(o, c);
                            o.addPlan(u)
                        } else l = E(e, t, o, r, s), c = r.addChildRequest(s.serviceIdentifier, l, s);
                        l.forEach((function(t) {
                            var n = null;
                            if (s.isArray()) n = c.addChildRequest(t.serviceIdentifier, t, s);
                            else {
                                if (t.cache) return;
                                n = c
                            }
                            if (t.type === i.Nt.Instance && null !== t.implementationType) {
                                var r = function(e, t) {
                                    return b(e, (0, d.$P)(t), t, !1)
                                }(e, t.implementationType);
                                if (!o.container.options.skipBaseClassChecks) {
                                    var l = _(e, t.implementationType);
                                    if (r.length < l) {
                                        var u = a.iI((0, d.$P)(t.implementationType));
                                        throw new Error(u)
                                    }
                                }
                                r.forEach((function(t) {
                                    I(e, !1, t.serviceIdentifier, o, n, t)
                                }))
                            }
                        }))
                    }

                    function A(e, t) {
                        var n = [],
                            i = S(e);
                        return i.hasKey(t) ? n = i.get(t) : null !== e.parent && (n = A(e.parent, t)), n
                    }

                    function O(e) {
                        return ("object" == typeof e && null !== e || "function" == typeof e) && "function" == typeof e.then
                    }

                    function T(e) {
                        return !!O(e) || Array.isArray(e) && e.some(O)
                    }
                    var M = function(e, t) {
                            return n = void 0, i = void 0, r = function() {
                                var n, i;
                                return function(e, t) {
                                    var n, i, o, r, a = {
                                        label: 0,
                                        sent: function() {
                                            if (1 & o[0]) throw o[1];
                                            return o[1]
                                        },
                                        trys: [],
                                        ops: []
                                    };
                                    return r = {
                                        next: s(0),
                                        throw: s(1),
                                        return: s(2)
                                    }, "function" == typeof Symbol && (r[Symbol.iterator] = function() {
                                        return this
                                    }), r;

                                    function s(r) {
                                        return function(s) {
                                            return function(r) {
                                                if (n) throw new TypeError("Generator is already executing.");
                                                for (; a;) try {
                                                    if (n = 1, i && (o = 2 & r[0] ? i.return : r[0] ? i.throw || ((o = i.return) && o.call(i), 0) : i.next) && !(o = o.call(i, r[1])).done) return o;
                                                    switch (i = 0, o && (r = [2 & r[0], o.value]), r[0]) {
                                                        case 0:
                                                        case 1:
                                                            o = r;
                                                            break;
                                                        case 4:
                                                            return a.label++, {
                                                                value: r[1],
                                                                done: !1
                                                            };
                                                        case 5:
                                                            a.label++, i = r[1], r = [0];
                                                            continue;
                                                        case 7:
                                                            r = a.ops.pop(), a.trys.pop();
                                                            continue;
                                                        default:
                                                            if (!((o = (o = a.trys).length > 0 && o[o.length - 1]) || 6 !== r[0] && 2 !== r[0])) {
                                                                a = 0;
                                                                continue
                                                            }
                                                            if (3 === r[0] && (!o || r[1] > o[0] && r[1] < o[3])) {
                                                                a.label = r[1];
                                                                break
                                                            }
                                                            if (6 === r[0] && a.label < o[1]) {
                                                                a.label = o[1], o = r;
                                                                break
                                                            }
                                                            if (o && a.label < o[2]) {
                                                                a.label = o[2], a.ops.push(r);
                                                                break
                                                            }
                                                            o[2] && a.ops.pop(), a.trys.pop();
                                                            continue
                                                    }
                                                    r = t.call(e, a)
                                                } catch (e) {
                                                    r = [6, e], i = 0
                                                } finally {
                                                    n = o = 0
                                                }
                                                if (5 & r[0]) throw r[1];
                                                return {
                                                    value: r[0] ? r[1] : void 0,
                                                    done: !0
                                                }
                                            }([r, s])
                                        }
                                    }
                                }(this, (function(o) {
                                    switch (o.label) {
                                        case 0:
                                            return o.trys.push([0, 2, , 3]), [4, t];
                                        case 1:
                                            return n = o.sent(), e.cache = n, [3, 3];
                                        case 2:
                                            throw i = o.sent(), e.cache = null, e.activated = !1, i;
                                        case 3:
                                            return [2]
                                    }
                                }))
                            }, new((o = void 0) || (o = Promise))((function(e, t) {
                                function a(e) {
                                    try {
                                        l(r.next(e))
                                    } catch (e) {
                                        t(e)
                                    }
                                }

                                function s(e) {
                                    try {
                                        l(r.throw(e))
                                    } catch (e) {
                                        t(e)
                                    }
                                }

                                function l(t) {
                                    var n;
                                    t.done ? e(t.value) : (n = t.value, n instanceof o ? n : new o((function(e) {
                                        e(n)
                                    }))).then(a, s)
                                }
                                l((r = r.apply(n, i || [])).next())
                            }));
                            var n, i, o, r
                        },
                        R = n(3328),
                        P = function() {
                            return P = Object.assign || function(e) {
                                for (var t, n = 1, i = arguments.length; n < i; n++)
                                    for (var o in t = arguments[n]) Object.prototype.hasOwnProperty.call(t, o) && (e[o] = t[o]);
                                return e
                            }, P.apply(this, arguments)
                        },
                        D = function(e, t, n, i) {
                            return new(n || (n = Promise))((function(o, r) {
                                function a(e) {
                                    try {
                                        l(i.next(e))
                                    } catch (e) {
                                        r(e)
                                    }
                                }

                                function s(e) {
                                    try {
                                        l(i.throw(e))
                                    } catch (e) {
                                        r(e)
                                    }
                                }

                                function l(e) {
                                    var t;
                                    e.done ? o(e.value) : (t = e.value, t instanceof n ? t : new n((function(e) {
                                        e(t)
                                    }))).then(a, s)
                                }
                                l((i = i.apply(e, t || [])).next())
                            }))
                        },
                        j = function(e, t) {
                            var n, i, o, r, a = {
                                label: 0,
                                sent: function() {
                                    if (1 & o[0]) throw o[1];
                                    return o[1]
                                },
                                trys: [],
                                ops: []
                            };
                            return r = {
                                next: s(0),
                                throw: s(1),
                                return: s(2)
                            }, "function" == typeof Symbol && (r[Symbol.iterator] = function() {
                                return this
                            }), r;

                            function s(r) {
                                return function(s) {
                                    return function(r) {
                                        if (n) throw new TypeError("Generator is already executing.");
                                        for (; a;) try {
                                            if (n = 1, i && (o = 2 & r[0] ? i.return : r[0] ? i.throw || ((o = i.return) && o.call(i), 0) : i.next) && !(o = o.call(i, r[1])).done) return o;
                                            switch (i = 0, o && (r = [2 & r[0], o.value]), r[0]) {
                                                case 0:
                                                case 1:
                                                    o = r;
                                                    break;
                                                case 4:
                                                    return a.label++, {
                                                        value: r[1],
                                                        done: !1
                                                    };
                                                case 5:
                                                    a.label++, i = r[1], r = [0];
                                                    continue;
                                                case 7:
                                                    r = a.ops.pop(), a.trys.pop();
                                                    continue;
                                                default:
                                                    if (!((o = (o = a.trys).length > 0 && o[o.length - 1]) || 6 !== r[0] && 2 !== r[0])) {
                                                        a = 0;
                                                        continue
                                                    }
                                                    if (3 === r[0] && (!o || r[1] > o[0] && r[1] < o[3])) {
                                                        a.label = r[1];
                                                        break
                                                    }
                                                    if (6 === r[0] && a.label < o[1]) {
                                                        a.label = o[1], o = r;
                                                        break
                                                    }
                                                    if (o && a.label < o[2]) {
                                                        a.label = o[2], a.ops.push(r);
                                                        break
                                                    }
                                                    o[2] && a.ops.pop(), a.trys.pop();
                                                    continue
                                            }
                                            r = t.call(e, a)
                                        } catch (e) {
                                            r = [6, e], i = 0
                                        } finally {
                                            n = o = 0
                                        }
                                        if (5 & r[0]) throw r[1];
                                        return {
                                            value: r[0] ? r[1] : void 0,
                                            done: !0
                                        }
                                    }([r, s])
                                }
                            }
                        };

                    function L(e) {
                        var t, n = new((t = e.constr).bind.apply(t, function(e, t, n) {
                            if (n || 2 === arguments.length)
                                for (var i, o = 0, r = t.length; o < r; o++) !i && o in t || (i || (i = Array.prototype.slice.call(t, 0, o)), i[o] = t[o]);
                            return e.concat(i || Array.prototype.slice.call(t))
                        }([void 0], e.constructorInjections, !1)));
                        return e.propertyRequests.forEach((function(t, i) {
                            var o = t.target.identifier,
                                r = e.propertyInjections[i];
                            n[o] = r
                        })), n
                    }

                    function F(e) {
                        return D(this, void 0, void 0, (function() {
                            var t, n, i, o;
                            return j(this, (function(r) {
                                for (t = [], n = 0, i = e; n < i.length; n++) o = i[n], Array.isArray(o) ? t.push(Promise.all(o)) : t.push(o);
                                return [2, Promise.all(t)]
                            }))
                        }))
                    }

                    function H(e, t) {
                        var n = function(e, t) {
                            var n, i;
                            if (Reflect.hasMetadata(s.POST_CONSTRUCT, e)) {
                                var o = Reflect.getMetadata(s.POST_CONSTRUCT, e);
                                try {
                                    return null === (i = (n = t)[o.value]) || void 0 === i ? void 0 : i.call(n)
                                } catch (t) {
                                    throw new Error((0, a.gq)(e.name, t.message))
                                }
                            }
                        }(e, t);
                        return O(n) ? n.then((function() {
                            return t
                        })) : t
                    }
                    var B = function(e) {
                            return function(t) {
                                t.parentContext.setCurrentRequest(t);
                                var n = t.bindings,
                                    i = t.childRequests,
                                    o = t.target && t.target.isArray(),
                                    r = !(t.parentRequest && t.parentRequest.target && t.target && t.parentRequest.target.matchesArray(t.target.serviceIdentifier));
                                if (o && r) return i.map((function(t) {
                                    return B(e)(t)
                                }));
                                if (!t.target.isOptional() || 0 !== n.length) {
                                    var a = n[0];
                                    return z(e, t, a)
                                }
                            }
                        },
                        N = function(e, t) {
                            var n = (0, R._o)(e);
                            return function(i, o) {
                                try {
                                    return n.factory.bind(e)(t)
                                } catch (e) {
                                    throw c(e) && (e = new Error(a.aD(n.factoryType, t.currentRequest.serviceIdentifier.toString()))), e
                                }
                            }()
                        },
                        U = function(e, t, n) {
                            var o, r = t.childRequests;
                            switch ((0, R.Xv)(n), n.type) {
                                case i.Nt.ConstantValue:
                                case i.Nt.Function:
                                    o = n.cache;
                                    break;
                                case i.Nt.Constructor:
                                    o = n.implementationType;
                                    break;
                                case i.Nt.Instance:
                                    o = function(e, t, n, o) {
                                        ! function(e, t) {
                                            e.scope !== i.h6.Singleton && function(e, t) {
                                                var n = "Class cannot be instantiated in " + (e.scope === i.h6.Request ? "request" : "transient") + " scope.";
                                                if ("function" == typeof e.onDeactivation) throw new Error((0, a.YG)(t.name, n));
                                                if (Reflect.hasMetadata(s.PRE_DESTROY, t)) throw new Error((0, a.xZ)(t.name, n))
                                            }(e, t)
                                        }(e, t);
                                        var r = function(e, t, n) {
                                            var o;
                                            if (t.length > 0) {
                                                var r = function(e, t) {
                                                        return e.reduce((function(e, n) {
                                                            var o = t(n);
                                                            return n.target.type === i.Nj.ConstructorArgument ? e.constructorInjections.push(o) : (e.propertyRequests.push(n), e.propertyInjections.push(o)), e.isAsync || (e.isAsync = T(o)), e
                                                        }), {
                                                            constructorInjections: [],
                                                            propertyInjections: [],
                                                            propertyRequests: [],
                                                            isAsync: !1
                                                        })
                                                    }(t, n),
                                                    a = P(P({}, r), {
                                                        constr: e
                                                    });
                                                o = r.isAsync ? function(e) {
                                                    return D(this, void 0, void 0, (function() {
                                                        var t, n;
                                                        return j(this, (function(i) {
                                                            switch (i.label) {
                                                                case 0:
                                                                    return [4, F(e.constructorInjections)];
                                                                case 1:
                                                                    return t = i.sent(), [4, F(e.propertyInjections)];
                                                                case 2:
                                                                    return n = i.sent(), [2, L(P(P({}, e), {
                                                                        constructorInjections: t,
                                                                        propertyInjections: n
                                                                    }))]
                                                            }
                                                        }))
                                                    }))
                                                }(a) : L(a)
                                            } else o = new e;
                                            return o
                                        }(t, n, o);
                                        return O(r) ? r.then((function(e) {
                                            return H(t, e)
                                        })) : H(t, r)
                                    }(n, n.implementationType, r, B(e));
                                    break;
                                default:
                                    o = N(n, t.parentContext)
                            }
                            return o
                        },
                        V = function(e, t, n) {
                            var o = function(e, t) {
                                return t.scope === i.h6.Singleton && t.activated ? t.cache : t.scope === i.h6.Request && e.has(t.id) ? e.get(t.id) : null
                            }(e, t);
                            return null !== o || function(e, t, n) {
                                t.scope === i.h6.Singleton && function(e, t) {
                                    e.cache = t, e.activated = !0, O(t) && M(e, t)
                                }(t, n), t.scope === i.h6.Request && function(e, t, n) {
                                    e.has(t.id) || e.set(t.id, n)
                                }(e, t, n)
                            }(e, t, o = n()), o
                        },
                        z = function(e, t, n) {
                            return V(e, n, (function() {
                                var i = U(e, t, n);
                                return O(i) ? i.then((function(e) {
                                    return W(t, n, e)
                                })) : W(t, n, i)
                            }))
                        };

                    function W(e, t, n) {
                        var i, o = G(e.parentContext, t, n),
                            r = J(e.parentContext.container),
                            a = r.next();
                        do {
                            i = a.value;
                            var s = e.parentContext,
                                l = e.serviceIdentifier,
                                c = Y(i, l);
                            o = O(o) ? q(c, s, o) : $(c, s, o), a = r.next()
                        } while (!0 !== a.done && !S(i).hasKey(e.serviceIdentifier));
                        return o
                    }
                    var G = function(e, t, n) {
                            return "function" == typeof t.onActivation ? t.onActivation(e, n) : n
                        },
                        $ = function(e, t, n) {
                            for (var i = e.next(); !i.done;) {
                                if (O(n = i.value(t, n))) return q(e, t, n);
                                i = e.next()
                            }
                            return n
                        },
                        q = function(e, t, n) {
                            return i = void 0, o = void 0, a = function() {
                                var i, o;
                                return function(e, t) {
                                    var n, i, o, r, a = {
                                        label: 0,
                                        sent: function() {
                                            if (1 & o[0]) throw o[1];
                                            return o[1]
                                        },
                                        trys: [],
                                        ops: []
                                    };
                                    return r = {
                                        next: s(0),
                                        throw: s(1),
                                        return: s(2)
                                    }, "function" == typeof Symbol && (r[Symbol.iterator] = function() {
                                        return this
                                    }), r;

                                    function s(r) {
                                        return function(s) {
                                            return function(r) {
                                                if (n) throw new TypeError("Generator is already executing.");
                                                for (; a;) try {
                                                    if (n = 1, i && (o = 2 & r[0] ? i.return : r[0] ? i.throw || ((o = i.return) && o.call(i), 0) : i.next) && !(o = o.call(i, r[1])).done) return o;
                                                    switch (i = 0, o && (r = [2 & r[0], o.value]), r[0]) {
                                                        case 0:
                                                        case 1:
                                                            o = r;
                                                            break;
                                                        case 4:
                                                            return a.label++, {
                                                                value: r[1],
                                                                done: !1
                                                            };
                                                        case 5:
                                                            a.label++, i = r[1], r = [0];
                                                            continue;
                                                        case 7:
                                                            r = a.ops.pop(), a.trys.pop();
                                                            continue;
                                                        default:
                                                            if (!((o = (o = a.trys).length > 0 && o[o.length - 1]) || 6 !== r[0] && 2 !== r[0])) {
                                                                a = 0;
                                                                continue
                                                            }
                                                            if (3 === r[0] && (!o || r[1] > o[0] && r[1] < o[3])) {
                                                                a.label = r[1];
                                                                break
                                                            }
                                                            if (6 === r[0] && a.label < o[1]) {
                                                                a.label = o[1], o = r;
                                                                break
                                                            }
                                                            if (o && a.label < o[2]) {
                                                                a.label = o[2], a.ops.push(r);
                                                                break
                                                            }
                                                            o[2] && a.ops.pop(), a.trys.pop();
                                                            continue
                                                    }
                                                    r = t.call(e, a)
                                                } catch (e) {
                                                    r = [6, e], i = 0
                                                } finally {
                                                    n = o = 0
                                                }
                                                if (5 & r[0]) throw r[1];
                                                return {
                                                    value: r[0] ? r[1] : void 0,
                                                    done: !0
                                                }
                                            }([r, s])
                                        }
                                    }
                                }(this, (function(r) {
                                    switch (r.label) {
                                        case 0:
                                            return [4, n];
                                        case 1:
                                            i = r.sent(), o = e.next(), r.label = 2;
                                        case 2:
                                            return o.done ? [3, 4] : [4, o.value(t, i)];
                                        case 3:
                                            return i = r.sent(), o = e.next(), [3, 2];
                                        case 4:
                                            return [2, i]
                                    }
                                }))
                            }, new((r = void 0) || (r = Promise))((function(e, t) {
                                function n(e) {
                                    try {
                                        l(a.next(e))
                                    } catch (e) {
                                        t(e)
                                    }
                                }

                                function s(e) {
                                    try {
                                        l(a.throw(e))
                                    } catch (e) {
                                        t(e)
                                    }
                                }

                                function l(t) {
                                    var i;
                                    t.done ? e(t.value) : (i = t.value, i instanceof r ? i : new r((function(e) {
                                        e(i)
                                    }))).then(n, s)
                                }
                                l((a = a.apply(i, o || [])).next())
                            }));
                            var i, o, r, a
                        },
                        Y = function(e, t) {
                            var n = e._activations;
                            return n.hasKey(t) ? n.get(t).values() : [].values()
                        },
                        J = function(e) {
                            for (var t = [e], n = e.parent; null !== n;) t.push(n), n = n.parent;
                            return {
                                next: function() {
                                    var e = t.pop();
                                    return void 0 !== e ? {
                                        done: !1,
                                        value: e
                                    } : {
                                        done: !0,
                                        value: void 0
                                    }
                                }
                            }
                        },
                        Z = n(9191),
                        X = function() {
                            function e(e) {
                                this._binding = e
                            }
                            return e.prototype.when = function(e) {
                                return this._binding.constraint = e, new K(this._binding)
                            }, e.prototype.whenTargetNamed = function(e) {
                                return this._binding.constraint = (0, Z.Ob)(e), new K(this._binding)
                            }, e.prototype.whenTargetIsDefault = function() {
                                return this._binding.constraint = function(e) {
                                    return null !== e && null !== e.target && !e.target.isNamed() && !e.target.isTagged()
                                }, new K(this._binding)
                            }, e.prototype.whenTargetTagged = function(e, t) {
                                return this._binding.constraint = (0, Z.pY)(e)(t), new K(this._binding)
                            }, e.prototype.whenInjectedInto = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && (0, Z.zc)(e)(t.parentRequest)
                                }, new K(this._binding)
                            }, e.prototype.whenParentNamed = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && (0, Z.Ob)(e)(t.parentRequest)
                                }, new K(this._binding)
                            }, e.prototype.whenParentTagged = function(e, t) {
                                return this._binding.constraint = function(n) {
                                    return null !== n && (0, Z.pY)(e)(t)(n.parentRequest)
                                }, new K(this._binding)
                            }, e.prototype.whenAnyAncestorIs = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && (0, Z.R9)(t, (0, Z.zc)(e))
                                }, new K(this._binding)
                            }, e.prototype.whenNoAncestorIs = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && !(0, Z.R9)(t, (0, Z.zc)(e))
                                }, new K(this._binding)
                            }, e.prototype.whenAnyAncestorNamed = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && (0, Z.R9)(t, (0, Z.Ob)(e))
                                }, new K(this._binding)
                            }, e.prototype.whenNoAncestorNamed = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && !(0, Z.R9)(t, (0, Z.Ob)(e))
                                }, new K(this._binding)
                            }, e.prototype.whenAnyAncestorTagged = function(e, t) {
                                return this._binding.constraint = function(n) {
                                    return null !== n && (0, Z.R9)(n, (0, Z.pY)(e)(t))
                                }, new K(this._binding)
                            }, e.prototype.whenNoAncestorTagged = function(e, t) {
                                return this._binding.constraint = function(n) {
                                    return null !== n && !(0, Z.R9)(n, (0, Z.pY)(e)(t))
                                }, new K(this._binding)
                            }, e.prototype.whenAnyAncestorMatches = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && (0, Z.R9)(t, e)
                                }, new K(this._binding)
                            }, e.prototype.whenNoAncestorMatches = function(e) {
                                return this._binding.constraint = function(t) {
                                    return null !== t && !(0, Z.R9)(t, e)
                                }, new K(this._binding)
                            }, e
                        }(),
                        K = function() {
                            function e(e) {
                                this._binding = e
                            }
                            return e.prototype.onActivation = function(e) {
                                return this._binding.onActivation = e, new X(this._binding)
                            }, e.prototype.onDeactivation = function(e) {
                                return this._binding.onDeactivation = e, new X(this._binding)
                            }, e
                        }(),
                        Q = function() {
                            function e(e) {
                                this._binding = e, this._bindingWhenSyntax = new X(this._binding), this._bindingOnSyntax = new K(this._binding)
                            }
                            return e.prototype.when = function(e) {
                                return this._bindingWhenSyntax.when(e)
                            }, e.prototype.whenTargetNamed = function(e) {
                                return this._bindingWhenSyntax.whenTargetNamed(e)
                            }, e.prototype.whenTargetIsDefault = function() {
                                return this._bindingWhenSyntax.whenTargetIsDefault()
                            }, e.prototype.whenTargetTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenTargetTagged(e, t)
                            }, e.prototype.whenInjectedInto = function(e) {
                                return this._bindingWhenSyntax.whenInjectedInto(e)
                            }, e.prototype.whenParentNamed = function(e) {
                                return this._bindingWhenSyntax.whenParentNamed(e)
                            }, e.prototype.whenParentTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenParentTagged(e, t)
                            }, e.prototype.whenAnyAncestorIs = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorIs(e)
                            }, e.prototype.whenNoAncestorIs = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorIs(e)
                            }, e.prototype.whenAnyAncestorNamed = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorNamed(e)
                            }, e.prototype.whenAnyAncestorTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenAnyAncestorTagged(e, t)
                            }, e.prototype.whenNoAncestorNamed = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorNamed(e)
                            }, e.prototype.whenNoAncestorTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenNoAncestorTagged(e, t)
                            }, e.prototype.whenAnyAncestorMatches = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorMatches(e)
                            }, e.prototype.whenNoAncestorMatches = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorMatches(e)
                            }, e.prototype.onActivation = function(e) {
                                return this._bindingOnSyntax.onActivation(e)
                            }, e.prototype.onDeactivation = function(e) {
                                return this._bindingOnSyntax.onDeactivation(e)
                            }, e
                        }(),
                        ee = function() {
                            function e(e) {
                                this._binding = e
                            }
                            return e.prototype.inRequestScope = function() {
                                return this._binding.scope = i.h6.Request, new Q(this._binding)
                            }, e.prototype.inSingletonScope = function() {
                                return this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.inTransientScope = function() {
                                return this._binding.scope = i.h6.Transient, new Q(this._binding)
                            }, e
                        }(),
                        te = function() {
                            function e(e) {
                                this._binding = e, this._bindingWhenSyntax = new X(this._binding), this._bindingOnSyntax = new K(this._binding), this._bindingInSyntax = new ee(e)
                            }
                            return e.prototype.inRequestScope = function() {
                                return this._bindingInSyntax.inRequestScope()
                            }, e.prototype.inSingletonScope = function() {
                                return this._bindingInSyntax.inSingletonScope()
                            }, e.prototype.inTransientScope = function() {
                                return this._bindingInSyntax.inTransientScope()
                            }, e.prototype.when = function(e) {
                                return this._bindingWhenSyntax.when(e)
                            }, e.prototype.whenTargetNamed = function(e) {
                                return this._bindingWhenSyntax.whenTargetNamed(e)
                            }, e.prototype.whenTargetIsDefault = function() {
                                return this._bindingWhenSyntax.whenTargetIsDefault()
                            }, e.prototype.whenTargetTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenTargetTagged(e, t)
                            }, e.prototype.whenInjectedInto = function(e) {
                                return this._bindingWhenSyntax.whenInjectedInto(e)
                            }, e.prototype.whenParentNamed = function(e) {
                                return this._bindingWhenSyntax.whenParentNamed(e)
                            }, e.prototype.whenParentTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenParentTagged(e, t)
                            }, e.prototype.whenAnyAncestorIs = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorIs(e)
                            }, e.prototype.whenNoAncestorIs = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorIs(e)
                            }, e.prototype.whenAnyAncestorNamed = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorNamed(e)
                            }, e.prototype.whenAnyAncestorTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenAnyAncestorTagged(e, t)
                            }, e.prototype.whenNoAncestorNamed = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorNamed(e)
                            }, e.prototype.whenNoAncestorTagged = function(e, t) {
                                return this._bindingWhenSyntax.whenNoAncestorTagged(e, t)
                            }, e.prototype.whenAnyAncestorMatches = function(e) {
                                return this._bindingWhenSyntax.whenAnyAncestorMatches(e)
                            }, e.prototype.whenNoAncestorMatches = function(e) {
                                return this._bindingWhenSyntax.whenNoAncestorMatches(e)
                            }, e.prototype.onActivation = function(e) {
                                return this._bindingOnSyntax.onActivation(e)
                            }, e.prototype.onDeactivation = function(e) {
                                return this._bindingOnSyntax.onDeactivation(e)
                            }, e
                        }(),
                        ne = function() {
                            function e(e) {
                                this._binding = e
                            }
                            return e.prototype.to = function(e) {
                                return this._binding.type = i.Nt.Instance, this._binding.implementationType = e, new te(this._binding)
                            }, e.prototype.toSelf = function() {
                                if ("function" != typeof this._binding.serviceIdentifier) throw new Error("" + a.wk);
                                var e = this._binding.serviceIdentifier;
                                return this.to(e)
                            }, e.prototype.toConstantValue = function(e) {
                                return this._binding.type = i.Nt.ConstantValue, this._binding.cache = e, this._binding.dynamicValue = null, this._binding.implementationType = null, this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.toDynamicValue = function(e) {
                                return this._binding.type = i.Nt.DynamicValue, this._binding.cache = null, this._binding.dynamicValue = e, this._binding.implementationType = null, new te(this._binding)
                            }, e.prototype.toConstructor = function(e) {
                                return this._binding.type = i.Nt.Constructor, this._binding.implementationType = e, this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.toFactory = function(e) {
                                return this._binding.type = i.Nt.Factory, this._binding.factory = e, this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.toFunction = function(e) {
                                if ("function" != typeof e) throw new Error(a.d1);
                                var t = this.toConstantValue(e);
                                return this._binding.type = i.Nt.Function, this._binding.scope = i.h6.Singleton, t
                            }, e.prototype.toAutoFactory = function(e) {
                                return this._binding.type = i.Nt.Factory, this._binding.factory = function(t) {
                                    return function() {
                                        return t.container.get(e)
                                    }
                                }, this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.toAutoNamedFactory = function(e) {
                                return this._binding.type = i.Nt.Factory, this._binding.factory = function(t) {
                                    return function(n) {
                                        return t.container.getNamed(e, n)
                                    }
                                }, new Q(this._binding)
                            }, e.prototype.toProvider = function(e) {
                                return this._binding.type = i.Nt.Provider, this._binding.provider = e, this._binding.scope = i.h6.Singleton, new Q(this._binding)
                            }, e.prototype.toService = function(e) {
                                this.toDynamicValue((function(t) {
                                    return t.container.get(e)
                                }))
                            }, e
                        }(),
                        ie = function() {
                            function e() {}
                            return e.of = function(t, n, i, o, r) {
                                var a = new e;
                                return a.bindings = t, a.middleware = n, a.deactivations = o, a.activations = i, a.moduleActivationStore = r, a
                            }, e
                        }(),
                        oe = function() {
                            function e() {
                                this._map = new Map
                            }
                            return e.prototype.getMap = function() {
                                return this._map
                            }, e.prototype.add = function(e, t) {
                                if (null == e) throw new Error(a.H1);
                                if (null == t) throw new Error(a.H1);
                                var n = this._map.get(e);
                                void 0 !== n ? n.push(t) : this._map.set(e, [t])
                            }, e.prototype.get = function(e) {
                                if (null == e) throw new Error(a.H1);
                                var t = this._map.get(e);
                                if (void 0 !== t) return t;
                                throw new Error(a.yu)
                            }, e.prototype.remove = function(e) {
                                if (null == e) throw new Error(a.H1);
                                if (!this._map.delete(e)) throw new Error(a.yu)
                            }, e.prototype.removeIntersection = function(e) {
                                var t = this;
                                this.traverse((function(n, i) {
                                    var o = e.hasKey(n) ? e.get(n) : void 0;
                                    if (void 0 !== o) {
                                        var r = i.filter((function(e) {
                                            return !o.some((function(t) {
                                                return e === t
                                            }))
                                        }));
                                        t._setValue(n, r)
                                    }
                                }))
                            }, e.prototype.removeByCondition = function(e) {
                                var t = this,
                                    n = [];
                                return this._map.forEach((function(i, o) {
                                    for (var r = [], a = 0, s = i; a < s.length; a++) {
                                        var l = s[a];
                                        e(l) ? n.push(l) : r.push(l)
                                    }
                                    t._setValue(o, r)
                                })), n
                            }, e.prototype.hasKey = function(e) {
                                if (null == e) throw new Error(a.H1);
                                return this._map.has(e)
                            }, e.prototype.clone = function() {
                                var t = new e;
                                return this._map.forEach((function(e, n) {
                                    e.forEach((function(e) {
                                        return t.add(n, "object" == typeof(i = e) && null !== i && "clone" in i && "function" == typeof i.clone ? e.clone() : e);
                                        var i
                                    }))
                                })), t
                            }, e.prototype.traverse = function(e) {
                                this._map.forEach((function(t, n) {
                                    e(n, t)
                                }))
                            }, e.prototype._setValue = function(e, t) {
                                t.length > 0 ? this._map.set(e, t) : this._map.delete(e)
                            }, e
                        }(),
                        re = function() {
                            function e() {
                                this._map = new Map
                            }
                            return e.prototype.remove = function(e) {
                                if (this._map.has(e)) {
                                    var t = this._map.get(e);
                                    return this._map.delete(e), t
                                }
                                return this._getEmptyHandlersStore()
                            }, e.prototype.addDeactivation = function(e, t, n) {
                                this._getModuleActivationHandlers(e).onDeactivations.add(t, n)
                            }, e.prototype.addActivation = function(e, t, n) {
                                this._getModuleActivationHandlers(e).onActivations.add(t, n)
                            }, e.prototype.clone = function() {
                                var t = new e;
                                return this._map.forEach((function(e, n) {
                                    t._map.set(n, {
                                        onActivations: e.onActivations.clone(),
                                        onDeactivations: e.onDeactivations.clone()
                                    })
                                })), t
                            }, e.prototype._getModuleActivationHandlers = function(e) {
                                var t = this._map.get(e);
                                return void 0 === t && (t = this._getEmptyHandlersStore(), this._map.set(e, t)), t
                            }, e.prototype._getEmptyHandlersStore = function() {
                                return {
                                    onActivations: new oe,
                                    onDeactivations: new oe
                                }
                            }, e
                        }(),
                        ae = function() {
                            return ae = Object.assign || function(e) {
                                for (var t, n = 1, i = arguments.length; n < i; n++)
                                    for (var o in t = arguments[n]) Object.prototype.hasOwnProperty.call(t, o) && (e[o] = t[o]);
                                return e
                            }, ae.apply(this, arguments)
                        },
                        se = function(e, t, n, i) {
                            return new(n || (n = Promise))((function(o, r) {
                                function a(e) {
                                    try {
                                        l(i.next(e))
                                    } catch (e) {
                                        r(e)
                                    }
                                }

                                function s(e) {
                                    try {
                                        l(i.throw(e))
                                    } catch (e) {
                                        r(e)
                                    }
                                }

                                function l(e) {
                                    var t;
                                    e.done ? o(e.value) : (t = e.value, t instanceof n ? t : new n((function(e) {
                                        e(t)
                                    }))).then(a, s)
                                }
                                l((i = i.apply(e, t || [])).next())
                            }))
                        },
                        le = function(e, t) {
                            var n, i, o, r, a = {
                                label: 0,
                                sent: function() {
                                    if (1 & o[0]) throw o[1];
                                    return o[1]
                                },
                                trys: [],
                                ops: []
                            };
                            return r = {
                                next: s(0),
                                throw: s(1),
                                return: s(2)
                            }, "function" == typeof Symbol && (r[Symbol.iterator] = function() {
                                return this
                            }), r;

                            function s(r) {
                                return function(s) {
                                    return function(r) {
                                        if (n) throw new TypeError("Generator is already executing.");
                                        for (; a;) try {
                                            if (n = 1, i && (o = 2 & r[0] ? i.return : r[0] ? i.throw || ((o = i.return) && o.call(i), 0) : i.next) && !(o = o.call(i, r[1])).done) return o;
                                            switch (i = 0, o && (r = [2 & r[0], o.value]), r[0]) {
                                                case 0:
                                                case 1:
                                                    o = r;
                                                    break;
                                                case 4:
                                                    return a.label++, {
                                                        value: r[1],
                                                        done: !1
                                                    };
                                                case 5:
                                                    a.label++, i = r[1], r = [0];
                                                    continue;
                                                case 7:
                                                    r = a.ops.pop(), a.trys.pop();
                                                    continue;
                                                default:
                                                    if (!((o = (o = a.trys).length > 0 && o[o.length - 1]) || 6 !== r[0] && 2 !== r[0])) {
                                                        a = 0;
                                                        continue
                                                    }
                                                    if (3 === r[0] && (!o || r[1] > o[0] && r[1] < o[3])) {
                                                        a.label = r[1];
                                                        break
                                                    }
                                                    if (6 === r[0] && a.label < o[1]) {
                                                        a.label = o[1], o = r;
                                                        break
                                                    }
                                                    if (o && a.label < o[2]) {
                                                        a.label = o[2], a.ops.push(r);
                                                        break
                                                    }
                                                    o[2] && a.ops.pop(), a.trys.pop();
                                                    continue
                                            }
                                            r = t.call(e, a)
                                        } catch (e) {
                                            r = [6, e], i = 0
                                        } finally {
                                            n = o = 0
                                        }
                                        if (5 & r[0]) throw r[1];
                                        return {
                                            value: r[0] ? r[1] : void 0,
                                            done: !0
                                        }
                                    }([r, s])
                                }
                            }
                        },
                        ce = function(e, t, n) {
                            if (n || 2 === arguments.length)
                                for (var i, o = 0, r = t.length; o < r; o++) !i && o in t || (i || (i = Array.prototype.slice.call(t, 0, o)), i[o] = t[o]);
                            return e.concat(i || Array.prototype.slice.call(t))
                        },
                        de = function() {
                            function e(e) {
                                var t = e || {};
                                if ("object" != typeof t) throw new Error("" + a.xU);
                                if (void 0 === t.defaultScope) t.defaultScope = i.h6.Transient;
                                else if (t.defaultScope !== i.h6.Singleton && t.defaultScope !== i.h6.Transient && t.defaultScope !== i.h6.Request) throw new Error("" + a.k_);
                                if (void 0 === t.autoBindInjectable) t.autoBindInjectable = !1;
                                else if ("boolean" != typeof t.autoBindInjectable) throw new Error("" + a.rR);
                                if (void 0 === t.skipBaseClassChecks) t.skipBaseClassChecks = !1;
                                else if ("boolean" != typeof t.skipBaseClassChecks) throw new Error("" + a.vD);
                                this.options = {
                                    autoBindInjectable: t.autoBindInjectable,
                                    defaultScope: t.defaultScope,
                                    skipBaseClassChecks: t.skipBaseClassChecks
                                }, this.id = (0, o.id)(), this._bindingDictionary = new oe, this._snapshots = [], this._middleware = null, this._activations = new oe, this._deactivations = new oe, this.parent = null, this._metadataReader = new l.p, this._moduleActivationStore = new re
                            }
                            return e.merge = function(t, n) {
                                for (var i = [], o = 2; o < arguments.length; o++) i[o - 2] = arguments[o];
                                var r = new e,
                                    a = ce([t, n], i, !0).map((function(e) {
                                        return S(e)
                                    })),
                                    s = S(r);

                                function l(e, t) {
                                    e.traverse((function(e, n) {
                                        n.forEach((function(e) {
                                            t.add(e.serviceIdentifier, e.clone())
                                        }))
                                    }))
                                }
                                return a.forEach((function(e) {
                                    l(e, s)
                                })), r
                            }, e.prototype.load = function() {
                                for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
                                for (var n = this._getContainerModuleHelpersFactory(), i = 0, o = e; i < o.length; i++) {
                                    var r = o[i],
                                        a = n(r.id);
                                    r.registry(a.bindFunction, a.unbindFunction, a.isboundFunction, a.rebindFunction, a.unbindAsyncFunction, a.onActivationFunction, a.onDeactivationFunction)
                                }
                            }, e.prototype.loadAsync = function() {
                                for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
                                return se(this, void 0, void 0, (function() {
                                    var t, n, i, o, r;
                                    return le(this, (function(a) {
                                        switch (a.label) {
                                            case 0:
                                                t = this._getContainerModuleHelpersFactory(), n = 0, i = e, a.label = 1;
                                            case 1:
                                                return n < i.length ? (o = i[n], r = t(o.id), [4, o.registry(r.bindFunction, r.unbindFunction, r.isboundFunction, r.rebindFunction, r.unbindAsyncFunction, r.onActivationFunction, r.onDeactivationFunction)]) : [3, 4];
                                            case 2:
                                                a.sent(), a.label = 3;
                                            case 3:
                                                return n++, [3, 1];
                                            case 4:
                                                return [2]
                                        }
                                    }))
                                }))
                            }, e.prototype.unload = function() {
                                for (var e = this, t = [], n = 0; n < arguments.length; n++) t[n] = arguments[n];
                                t.forEach((function(t) {
                                    var n = e._removeModuleBindings(t.id);
                                    e._deactivateSingletons(n), e._removeModuleHandlers(t.id)
                                }))
                            }, e.prototype.unloadAsync = function() {
                                for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
                                return se(this, void 0, void 0, (function() {
                                    var t, n, i, o;
                                    return le(this, (function(r) {
                                        switch (r.label) {
                                            case 0:
                                                t = 0, n = e, r.label = 1;
                                            case 1:
                                                return t < n.length ? (i = n[t], o = this._removeModuleBindings(i.id), [4, this._deactivateSingletonsAsync(o)]) : [3, 4];
                                            case 2:
                                                r.sent(), this._removeModuleHandlers(i.id), r.label = 3;
                                            case 3:
                                                return t++, [3, 1];
                                            case 4:
                                                return [2]
                                        }
                                    }))
                                }))
                            }, e.prototype.bind = function(e) {
                                var t = this.options.defaultScope || i.h6.Transient,
                                    n = new r(e, t);
                                return this._bindingDictionary.add(e, n), new ne(n)
                            }, e.prototype.rebind = function(e) {
                                return this.unbind(e), this.bind(e)
                            }, e.prototype.rebindAsync = function(e) {
                                return se(this, void 0, void 0, (function() {
                                    return le(this, (function(t) {
                                        switch (t.label) {
                                            case 0:
                                                return [4, this.unbindAsync(e)];
                                            case 1:
                                                return t.sent(), [2, this.bind(e)]
                                        }
                                    }))
                                }))
                            }, e.prototype.unbind = function(e) {
                                if (this._bindingDictionary.hasKey(e)) {
                                    var t = this._bindingDictionary.get(e);
                                    this._deactivateSingletons(t)
                                }
                                this._removeServiceFromDictionary(e)
                            }, e.prototype.unbindAsync = function(e) {
                                return se(this, void 0, void 0, (function() {
                                    var t;
                                    return le(this, (function(n) {
                                        switch (n.label) {
                                            case 0:
                                                return this._bindingDictionary.hasKey(e) ? (t = this._bindingDictionary.get(e), [4, this._deactivateSingletonsAsync(t)]) : [3, 2];
                                            case 1:
                                                n.sent(), n.label = 2;
                                            case 2:
                                                return this._removeServiceFromDictionary(e), [2]
                                        }
                                    }))
                                }))
                            }, e.prototype.unbindAll = function() {
                                var e = this;
                                this._bindingDictionary.traverse((function(t, n) {
                                    e._deactivateSingletons(n)
                                })), this._bindingDictionary = new oe
                            }, e.prototype.unbindAllAsync = function() {
                                return se(this, void 0, void 0, (function() {
                                    var e, t = this;
                                    return le(this, (function(n) {
                                        switch (n.label) {
                                            case 0:
                                                return e = [], this._bindingDictionary.traverse((function(n, i) {
                                                    e.push(t._deactivateSingletonsAsync(i))
                                                })), [4, Promise.all(e)];
                                            case 1:
                                                return n.sent(), this._bindingDictionary = new oe, [2]
                                        }
                                    }))
                                }))
                            }, e.prototype.onActivation = function(e, t) {
                                this._activations.add(e, t)
                            }, e.prototype.onDeactivation = function(e, t) {
                                this._deactivations.add(e, t)
                            }, e.prototype.isBound = function(e) {
                                var t = this._bindingDictionary.hasKey(e);
                                return !t && this.parent && (t = this.parent.isBound(e)), t
                            }, e.prototype.isCurrentBound = function(e) {
                                return this._bindingDictionary.hasKey(e)
                            }, e.prototype.isBoundNamed = function(e, t) {
                                return this.isBoundTagged(e, s.NAMED_TAG, t)
                            }, e.prototype.isBoundTagged = function(e, t, n) {
                                var o = !1;
                                if (this._bindingDictionary.hasKey(e)) {
                                    var r = this._bindingDictionary.get(e),
                                        a = function(e, t, n, o) {
                                            var r = new m(i.Nj.Variable, "", t, new p.S(n, o)),
                                                a = new u(e);
                                            return new C(t, a, null, [], r)
                                        }(this, e, t, n);
                                    o = r.some((function(e) {
                                        return e.constraint(a)
                                    }))
                                }
                                return !o && this.parent && (o = this.parent.isBoundTagged(e, t, n)), o
                            }, e.prototype.snapshot = function() {
                                this._snapshots.push(ie.of(this._bindingDictionary.clone(), this._middleware, this._activations.clone(), this._deactivations.clone(), this._moduleActivationStore.clone()))
                            }, e.prototype.restore = function() {
                                var e = this._snapshots.pop();
                                if (void 0 === e) throw new Error(a.NE);
                                this._bindingDictionary = e.bindings, this._activations = e.activations, this._deactivations = e.deactivations, this._middleware = e.middleware, this._moduleActivationStore = e.moduleActivationStore
                            }, e.prototype.createChild = function(t) {
                                var n = new e(t || this.options);
                                return n.parent = this, n
                            }, e.prototype.applyMiddleware = function() {
                                for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
                                var n = this._middleware ? this._middleware : this._planAndResolve();
                                this._middleware = e.reduce((function(e, t) {
                                    return t(e)
                                }), n)
                            }, e.prototype.applyCustomMetadataReader = function(e) {
                                this._metadataReader = e
                            }, e.prototype.get = function(e) {
                                var t = this._getNotAllArgs(e, !1);
                                return this._getButThrowIfAsync(t)
                            }, e.prototype.getAsync = function(e) {
                                return se(this, void 0, void 0, (function() {
                                    var t;
                                    return le(this, (function(n) {
                                        return t = this._getNotAllArgs(e, !1), [2, this._get(t)]
                                    }))
                                }))
                            }, e.prototype.getTagged = function(e, t, n) {
                                var i = this._getNotAllArgs(e, !1, t, n);
                                return this._getButThrowIfAsync(i)
                            }, e.prototype.getTaggedAsync = function(e, t, n) {
                                return se(this, void 0, void 0, (function() {
                                    var i;
                                    return le(this, (function(o) {
                                        return i = this._getNotAllArgs(e, !1, t, n), [2, this._get(i)]
                                    }))
                                }))
                            }, e.prototype.getNamed = function(e, t) {
                                return this.getTagged(e, s.NAMED_TAG, t)
                            }, e.prototype.getNamedAsync = function(e, t) {
                                return this.getTaggedAsync(e, s.NAMED_TAG, t)
                            }, e.prototype.getAll = function(e) {
                                var t = this._getAllArgs(e);
                                return this._getButThrowIfAsync(t)
                            }, e.prototype.getAllAsync = function(e) {
                                var t = this._getAllArgs(e);
                                return this._getAll(t)
                            }, e.prototype.getAllTagged = function(e, t, n) {
                                var i = this._getNotAllArgs(e, !0, t, n);
                                return this._getButThrowIfAsync(i)
                            }, e.prototype.getAllTaggedAsync = function(e, t, n) {
                                var i = this._getNotAllArgs(e, !0, t, n);
                                return this._getAll(i)
                            }, e.prototype.getAllNamed = function(e, t) {
                                return this.getAllTagged(e, s.NAMED_TAG, t)
                            }, e.prototype.getAllNamedAsync = function(e, t) {
                                return this.getAllTaggedAsync(e, s.NAMED_TAG, t)
                            }, e.prototype.resolve = function(e) {
                                var t = this.isBound(e);
                                t || this.bind(e).toSelf();
                                var n = this.get(e);
                                return t || this.unbind(e), n
                            }, e.prototype._preDestroy = function(e, t) {
                                if (Reflect.hasMetadata(s.PRE_DESTROY, e)) return t[Reflect.getMetadata(s.PRE_DESTROY, e).value]()
                            }, e.prototype._removeModuleHandlers = function(e) {
                                var t = this._moduleActivationStore.remove(e);
                                this._activations.removeIntersection(t.onActivations), this._deactivations.removeIntersection(t.onDeactivations)
                            }, e.prototype._removeModuleBindings = function(e) {
                                return this._bindingDictionary.removeByCondition((function(t) {
                                    return t.moduleId === e
                                }))
                            }, e.prototype._deactivate = function(e, t) {
                                var n = this,
                                    i = Object.getPrototypeOf(t).constructor;
                                try {
                                    if (this._deactivations.hasKey(e.serviceIdentifier)) {
                                        var o = this._deactivateContainer(t, this._deactivations.get(e.serviceIdentifier).values());
                                        if (O(o)) return this._handleDeactivationError(o.then((function() {
                                            return n._propagateContainerDeactivationThenBindingAndPreDestroyAsync(e, t, i)
                                        })), i)
                                    }
                                    var r = this._propagateContainerDeactivationThenBindingAndPreDestroy(e, t, i);
                                    if (O(r)) return this._handleDeactivationError(r, i)
                                } catch (e) {
                                    throw new Error(a.YG(i.name, e.message))
                                }
                            }, e.prototype._handleDeactivationError = function(e, t) {
                                return se(this, void 0, void 0, (function() {
                                    var n;
                                    return le(this, (function(i) {
                                        switch (i.label) {
                                            case 0:
                                                return i.trys.push([0, 2, , 3]), [4, e];
                                            case 1:
                                                return i.sent(), [3, 3];
                                            case 2:
                                                throw n = i.sent(), new Error(a.YG(t.name, n.message));
                                            case 3:
                                                return [2]
                                        }
                                    }))
                                }))
                            }, e.prototype._deactivateContainer = function(e, t) {
                                for (var n = this, i = t.next(); i.value;) {
                                    var o = i.value(e);
                                    if (O(o)) return o.then((function() {
                                        return n._deactivateContainerAsync(e, t)
                                    }));
                                    i = t.next()
                                }
                            }, e.prototype._deactivateContainerAsync = function(e, t) {
                                return se(this, void 0, void 0, (function() {
                                    var n;
                                    return le(this, (function(i) {
                                        switch (i.label) {
                                            case 0:
                                                n = t.next(), i.label = 1;
                                            case 1:
                                                return n.value ? [4, n.value(e)] : [3, 3];
                                            case 2:
                                                return i.sent(), n = t.next(), [3, 1];
                                            case 3:
                                                return [2]
                                        }
                                    }))
                                }))
                            }, e.prototype._getContainerModuleHelpersFactory = function() {
                                var e = this,
                                    t = function(e, t) {
                                        e._binding.moduleId = t
                                    },
                                    n = function(n) {
                                        return function(i) {
                                            var o = e.rebind(i);
                                            return t(o, n), o
                                        }
                                    },
                                    i = function(t) {
                                        return function(n, i) {
                                            e._moduleActivationStore.addActivation(t, n, i), e.onActivation(n, i)
                                        }
                                    },
                                    o = function(t) {
                                        return function(n, i) {
                                            e._moduleActivationStore.addDeactivation(t, n, i), e.onDeactivation(n, i)
                                        }
                                    };
                                return function(r) {
                                    return {
                                        bindFunction: (a = r, function(n) {
                                            var i = e.bind(n);
                                            return t(i, a), i
                                        }),
                                        isboundFunction: function(t) {
                                            return e.isBound(t)
                                        },
                                        onActivationFunction: i(r),
                                        onDeactivationFunction: o(r),
                                        rebindFunction: n(r),
                                        unbindFunction: function(t) {
                                            return e.unbind(t)
                                        },
                                        unbindAsyncFunction: function(t) {
                                            return e.unbindAsync(t)
                                        }
                                    };
                                    var a
                                }
                            }, e.prototype._getAll = function(e) {
                                return Promise.all(this._get(e))
                            }, e.prototype._get = function(e) {
                                var t = ae(ae({}, e), {
                                    contextInterceptor: function(e) {
                                        return e
                                    },
                                    targetType: i.Nj.Variable
                                });
                                if (this._middleware) {
                                    var n = this._middleware(t);
                                    if (null == n) throw new Error(a.pv);
                                    return n
                                }
                                return this._planAndResolve()(t)
                            }, e.prototype._getButThrowIfAsync = function(e) {
                                var t = this._get(e);
                                if (T(t)) throw new Error(a.FJ(e.serviceIdentifier));
                                return t
                            }, e.prototype._getAllArgs = function(e) {
                                return {
                                    avoidConstraints: !0,
                                    isMultiInject: !0,
                                    serviceIdentifier: e
                                }
                            }, e.prototype._getNotAllArgs = function(e, t, n, i) {
                                return {
                                    avoidConstraints: !1,
                                    isMultiInject: t,
                                    serviceIdentifier: e,
                                    key: n,
                                    value: i
                                }
                            }, e.prototype._planAndResolve = function() {
                                var e = this;
                                return function(t) {
                                    var n = function(e, t, n, i, o, r, a, l) {
                                        void 0 === l && (l = !1);
                                        var h = new u(t),
                                            f = function(e, t, n, i, o, r) {
                                                var a = e ? s.MULTI_INJECT_TAG : s.INJECT_TAG,
                                                    l = new p.S(a, n),
                                                    c = new m(t, "", n, l);
                                                if (void 0 !== o) {
                                                    var d = new p.S(o, r);
                                                    c.metadata.push(d)
                                                }
                                                return c
                                            }(n, i, o, 0, r, a);
                                        try {
                                            return I(e, l, o, h, null, f), h
                                        } catch (e) {
                                            throw c(e) && (0, d.Vo)(h.plan.rootRequest), e
                                        }
                                    }(e._metadataReader, e, t.isMultiInject, t.targetType, t.serviceIdentifier, t.key, t.value, t.avoidConstraints);
                                    return function(e) {
                                        return B(e.plan.rootRequest.requestScope)(e.plan.rootRequest)
                                    }(n = t.contextInterceptor(n))
                                }
                            }, e.prototype._deactivateIfSingleton = function(e) {
                                var t = this;
                                if (e.activated) return O(e.cache) ? e.cache.then((function(n) {
                                    return t._deactivate(e, n)
                                })) : this._deactivate(e, e.cache)
                            }, e.prototype._deactivateSingletons = function(e) {
                                for (var t = 0, n = e; t < n.length; t++) {
                                    var i = n[t];
                                    if (O(this._deactivateIfSingleton(i))) throw new Error(a.iD)
                                }
                            }, e.prototype._deactivateSingletonsAsync = function(e) {
                                return se(this, void 0, void 0, (function() {
                                    var t = this;
                                    return le(this, (function(n) {
                                        switch (n.label) {
                                            case 0:
                                                return [4, Promise.all(e.map((function(e) {
                                                    return t._deactivateIfSingleton(e)
                                                })))];
                                            case 1:
                                                return n.sent(), [2]
                                        }
                                    }))
                                }))
                            }, e.prototype._propagateContainerDeactivationThenBindingAndPreDestroy = function(e, t, n) {
                                return this.parent ? this._deactivate.bind(this.parent)(e, t) : this._bindingDeactivationAndPreDestroy(e, t, n)
                            }, e.prototype._propagateContainerDeactivationThenBindingAndPreDestroyAsync = function(e, t, n) {
                                return se(this, void 0, void 0, (function() {
                                    return le(this, (function(i) {
                                        switch (i.label) {
                                            case 0:
                                                return this.parent ? [4, this._deactivate.bind(this.parent)(e, t)] : [3, 2];
                                            case 1:
                                                return i.sent(), [3, 4];
                                            case 2:
                                                return [4, this._bindingDeactivationAndPreDestroyAsync(e, t, n)];
                                            case 3:
                                                i.sent(), i.label = 4;
                                            case 4:
                                                return [2]
                                        }
                                    }))
                                }))
                            }, e.prototype._removeServiceFromDictionary = function(e) {
                                try {
                                    this._bindingDictionary.remove(e)
                                } catch (t) {
                                    throw new Error(a.VF + " " + (0, d.Cp)(e))
                                }
                            }, e.prototype._bindingDeactivationAndPreDestroy = function(e, t, n) {
                                var i = this;
                                if ("function" == typeof e.onDeactivation) {
                                    var o = e.onDeactivation(t);
                                    if (O(o)) return o.then((function() {
                                        return i._preDestroy(n, t)
                                    }))
                                }
                                return this._preDestroy(n, t)
                            }, e.prototype._bindingDeactivationAndPreDestroyAsync = function(e, t, n) {
                                return se(this, void 0, void 0, (function() {
                                    return le(this, (function(i) {
                                        switch (i.label) {
                                            case 0:
                                                return "function" != typeof e.onDeactivation ? [3, 2] : [4, e.onDeactivation(t)];
                                            case 1:
                                                i.sent(), i.label = 2;
                                            case 2:
                                                return [4, this._preDestroy(n, t)];
                                            case 3:
                                                return i.sent(), [2]
                                        }
                                    }))
                                }))
                            }, e
                        }()
                },
                8103: (e, t, n) => {
                    "use strict";
                    n.r(t), n.d(t, {
                        AsyncContainerModule: () => l,
                        BindingScopeEnum: () => r.h6,
                        BindingTypeEnum: () => r.Nt,
                        Container: () => o.W,
                        ContainerModule: () => s,
                        LazyServiceIdentifer: () => g.h,
                        METADATA_KEY: () => O,
                        MetadataReader: () => S.p,
                        TargetTypeEnum: () => r.Nj,
                        createTaggedDecorator: () => c.fo,
                        decorate: () => c.GW,
                        getServiceIdentifierAsString: () => I.Cp,
                        id: () => a.id,
                        inject: () => f.f,
                        injectable: () => d.b,
                        interfaces: () => _,
                        multiBindToService: () => A.pi,
                        multiInject: () => b,
                        named: () => h,
                        namedConstraint: () => E.Ob,
                        optional: () => m,
                        postConstruct: () => k,
                        preDestroy: () => C,
                        tagged: () => p,
                        taggedConstraint: () => E.pY,
                        targetName: () => x,
                        traverseAncerstors: () => E.R9,
                        typeConstraint: () => E.zc,
                        unmanaged: () => y.N
                    });
                    var i = n(2313),
                        o = n(8402),
                        r = n(5466),
                        a = n(5054),
                        s = function(e) {
                            this.id = (0, a.id)(), this.registry = e
                        },
                        l = function(e) {
                            this.id = (0, a.id)(), this.registry = e
                        },
                        c = n(2215),
                        d = n(403),
                        u = n(8625);

                    function p(e, t) {
                        return (0, c.fo)(new u.S(e, t))
                    }

                    function h(e) {
                        return (0, c.fo)(new u.S(i.NAMED_TAG, e))
                    }
                    var f = n(7365),
                        g = n(6315);

                    function m() {
                        return (0, c.fo)(new u.S(i.OPTIONAL_TAG, !0))
                    }
                    var y = n(7936),
                        b = (0, n(530).v)(i.MULTI_INJECT_TAG);

                    function x(e) {
                        return function(t, n, o) {
                            var r = new u.S(i.NAME_TAG, e);
                            (0, c.D0)(t, n, o, r)
                        }
                    }
                    var v = n(3431);

                    function w(e, t) {
                        return function() {
                            return function(n, i) {
                                var o = new u.S(e, i);
                                if (Reflect.hasOwnMetadata(e, n.constructor)) throw new Error(t);
                                Reflect.defineMetadata(e, o, n.constructor)
                            }
                        }
                    }
                    var _, k = w(i.POST_CONSTRUCT, v.tE),
                        C = w(i.PRE_DESTROY, v.DL),
                        S = n(9546);
                    _ || (_ = {});
                    var E = n(9191),
                        I = n(5120),
                        A = n(3328),
                        O = i
                },
                8625: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        S: () => o
                    });
                    var i = n(2313),
                        o = function() {
                            function e(e, t) {
                                this.key = e, this.value = t
                            }
                            return e.prototype.toString = function() {
                                return this.key === i.NAMED_TAG ? "named: " + String(this.value).toString() + " " : "tagged: { key:" + this.key.toString() + ", value: " + String(this.value) + " }"
                            }, e
                        }()
                },
                9546: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        p: () => o
                    });
                    var i = n(2313),
                        o = function() {
                            function e() {}
                            return e.prototype.getConstructorMetadata = function(e) {
                                return {
                                    compilerGeneratedMetadata: Reflect.getMetadata(i.PARAM_TYPES, e),
                                    userGeneratedMetadata: Reflect.getMetadata(i.TAGGED, e) || {}
                                }
                            }, e.prototype.getPropertiesMetadata = function(e) {
                                return Reflect.getMetadata(i.TAGGED_PROP, e) || []
                            }, e
                        }()
                },
                9191: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Ob: () => s,
                        R9: () => r,
                        pY: () => a,
                        zc: () => l
                    });
                    var i = n(2313),
                        o = n(8625),
                        r = function(e, t) {
                            var n = e.parentRequest;
                            return null !== n && (!!t(n) || r(n, t))
                        },
                        a = function(e) {
                            return function(t) {
                                var n = function(n) {
                                    return null !== n && null !== n.target && n.target.matchesTag(e)(t)
                                };
                                return n.metaData = new o.S(e, t), n
                            }
                        },
                        s = a(i.NAMED_TAG),
                        l = function(e) {
                            return function(t) {
                                var n = null;
                                if (null !== t) {
                                    if (n = t.bindings[0], "string" == typeof e) return n.serviceIdentifier === e;
                                    var i = t.bindings[0].implementationType;
                                    return e === i
                                }
                                return !1
                            }
                        }
                },
                3328: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        Xv: () => l,
                        _o: () => c,
                        pi: () => s
                    });
                    var i, o = n(5120),
                        r = n(3431),
                        a = n(5466);
                    ! function(e) {
                        e.DynamicValue = "toDynamicValue", e.Factory = "toFactory", e.Provider = "toProvider"
                    }(i || (i = {}));
                    var s = function(e) {
                            return function(t) {
                                return function() {
                                    for (var n = [], i = 0; i < arguments.length; i++) n[i] = arguments[i];
                                    return n.forEach((function(n) {
                                        return e.bind(n).toService(t)
                                    }))
                                }
                            }
                        },
                        l = function(e) {
                            var t = null;
                            switch (e.type) {
                                case a.Nt.ConstantValue:
                                case a.Nt.Function:
                                    t = e.cache;
                                    break;
                                case a.Nt.Constructor:
                                case a.Nt.Instance:
                                    t = e.implementationType;
                                    break;
                                case a.Nt.DynamicValue:
                                    t = e.dynamicValue;
                                    break;
                                case a.Nt.Provider:
                                    t = e.provider;
                                    break;
                                case a.Nt.Factory:
                                    t = e.factory
                            }
                            if (null === t) {
                                var n = (0, o.Cp)(e.serviceIdentifier);
                                throw new Error(r.jT + " " + n)
                            }
                        },
                        c = function(e) {
                            switch (e.type) {
                                case a.Nt.Factory:
                                    return {
                                        factory: e.factory, factoryType: i.Factory
                                    };
                                case a.Nt.Provider:
                                    return {
                                        factory: e.provider, factoryType: i.Provider
                                    };
                                case a.Nt.DynamicValue:
                                    return {
                                        factory: e.dynamicValue, factoryType: i.DynamicValue
                                    };
                                default:
                                    throw new Error("Unexpected factory type " + e.type)
                            }
                        }
                },
                5054: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        id: () => o
                    });
                    var i = 0;

                    function o() {
                        return i++
                    }
                },
                896: (e, t, n) => {
                    "use strict";

                    function i(e) {
                        for (var t = new Set, n = 0, i = e; n < i.length; n++) {
                            var o = i[n];
                            if (t.has(o)) return o;
                            t.add(o)
                        }
                    }
                    n.d(t, {
                        D: () => i
                    })
                },
                5120: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        $P: () => c,
                        BB: () => l,
                        Cp: () => o,
                        Vi: () => r,
                        Vo: () => s,
                        We: () => d
                    });
                    var i = n(3431);

                    function o(e) {
                        return "function" == typeof e ? e.name : "symbol" == typeof e ? e.toString() : e
                    }

                    function r(e, t, n) {
                        var i = "",
                            o = n(e, t);
                        return 0 !== o.length && (i = "\nRegistered bindings:", o.forEach((function(e) {
                            var t = "Object";
                            null !== e.implementationType && (t = c(e.implementationType)), i = i + "\n " + t, e.constraint.metaData && (i = i + " - " + e.constraint.metaData)
                        }))), i
                    }

                    function a(e, t) {
                        return null !== e.parentRequest && (e.parentRequest.serviceIdentifier === t || a(e.parentRequest, t))
                    }

                    function s(e) {
                        e.childRequests.forEach((function(e) {
                            if (a(e, e.serviceIdentifier)) {
                                var t = function(e) {
                                    return function e(t, n) {
                                        void 0 === n && (n = []);
                                        var i = o(t.serviceIdentifier);
                                        return n.push(i), null !== t.parentRequest ? e(t.parentRequest, n) : n
                                    }(e).reverse().join(" --\x3e ")
                                }(e);
                                throw new Error(i.QY + " " + t)
                            }
                            s(e)
                        }))
                    }

                    function l(e, t) {
                        if (t.isTagged() || t.isNamed()) {
                            var n = "",
                                i = t.getNamedTag(),
                                o = t.getCustomTags();
                            return null !== i && (n += i.toString() + "\n"), null !== o && o.forEach((function(e) {
                                n += e.toString() + "\n"
                            })), " " + e + "\n " + e + " - " + n
                        }
                        return " " + e
                    }

                    function c(e) {
                        if (e.name) return e.name;
                        var t = e.toString(),
                            n = t.match(/^function\s*([^\s(]+)/);
                        return n ? n[1] : "Anonymous function: " + t
                    }

                    function d(e) {
                        return e.toString().slice(7, -1)
                    }
                },
                2023: (module, exports, __webpack_require__) => {
                    var __WEBPACK_AMD_DEFINE_RESULT__;
                    (function() {
                        "use strict";
                        var ERROR = "input is invalid type",
                            WINDOW = "object" == typeof window,
                            root = WINDOW ? window : {};
                        root.JS_SHA256_NO_WINDOW && (WINDOW = !1);
                        var WEB_WORKER = !WINDOW && "object" == typeof self,
                            NODE_JS = !root.JS_SHA256_NO_NODE_JS && "object" == typeof process && process.versions && process.versions.node;
                        NODE_JS ? root = __webpack_require__.g : WEB_WORKER && (root = self);
                        var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && module.exports,
                            AMD = __webpack_require__.amdO,
                            ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && "undefined" != typeof ArrayBuffer,
                            HEX_CHARS = "0123456789abcdef".split(""),
                            EXTRA = [-2147483648, 8388608, 32768, 128],
                            SHIFT = [24, 16, 8, 0],
                            K = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298],
                            OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"],
                            blocks = [];
                        !root.JS_SHA256_NO_NODE_JS && Array.isArray || (Array.isArray = function(e) {
                            return "[object Array]" === Object.prototype.toString.call(e)
                        }), !ARRAY_BUFFER || !root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW && ArrayBuffer.isView || (ArrayBuffer.isView = function(e) {
                            return "object" == typeof e && e.buffer && e.buffer.constructor === ArrayBuffer
                        });
                        var createOutputMethod = function(e, t) {
                                return function(n) {
                                    return new Sha256(t, !0).update(n)[e]()
                                }
                            },
                            createMethod = function(e) {
                                var t = createOutputMethod("hex", e);
                                NODE_JS && (t = nodeWrap(t, e)), t.create = function() {
                                    return new Sha256(e)
                                }, t.update = function(e) {
                                    return t.create().update(e)
                                };
                                for (var n = 0; n < OUTPUT_TYPES.length; ++n) {
                                    var i = OUTPUT_TYPES[n];
                                    t[i] = createOutputMethod(i, e)
                                }
                                return t
                            },
                            nodeWrap = function(method, is224) {
                                var crypto = eval("require('crypto')"),
                                    Buffer = eval("require('buffer').Buffer"),
                                    algorithm = is224 ? "sha224" : "sha256",
                                    nodeMethod = function(e) {
                                        if ("string" == typeof e) return crypto.createHash(algorithm).update(e, "utf8").digest("hex");
                                        if (null == e) throw new Error(ERROR);
                                        return e.constructor === ArrayBuffer && (e = new Uint8Array(e)), Array.isArray(e) || ArrayBuffer.isView(e) || e.constructor === Buffer ? crypto.createHash(algorithm).update(new Buffer(e)).digest("hex") : method(e)
                                    };
                                return nodeMethod
                            },
                            createHmacOutputMethod = function(e, t) {
                                return function(n, i) {
                                    return new HmacSha256(n, t, !0).update(i)[e]()
                                }
                            },
                            createHmacMethod = function(e) {
                                var t = createHmacOutputMethod("hex", e);
                                t.create = function(t) {
                                    return new HmacSha256(t, e)
                                }, t.update = function(e, n) {
                                    return t.create(e).update(n)
                                };
                                for (var n = 0; n < OUTPUT_TYPES.length; ++n) {
                                    var i = OUTPUT_TYPES[n];
                                    t[i] = createHmacOutputMethod(i, e)
                                }
                                return t
                            };

                        function Sha256(e, t) {
                            t ? (blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0, this.blocks = blocks) : this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], e ? (this.h0 = 3238371032, this.h1 = 914150663, this.h2 = 812702999, this.h3 = 4144912697, this.h4 = 4290775857, this.h5 = 1750603025, this.h6 = 1694076839, this.h7 = 3204075428) : (this.h0 = 1779033703, this.h1 = 3144134277, this.h2 = 1013904242, this.h3 = 2773480762, this.h4 = 1359893119, this.h5 = 2600822924, this.h6 = 528734635, this.h7 = 1541459225), this.block = this.start = this.bytes = this.hBytes = 0, this.finalized = this.hashed = !1, this.first = !0, this.is224 = e
                        }

                        function HmacSha256(e, t, n) {
                            var i, o = typeof e;
                            if ("string" === o) {
                                var r, a = [],
                                    s = e.length,
                                    l = 0;
                                for (i = 0; i < s; ++i)(r = e.charCodeAt(i)) < 128 ? a[l++] = r : r < 2048 ? (a[l++] = 192 | r >> 6, a[l++] = 128 | 63 & r) : r < 55296 || r >= 57344 ? (a[l++] = 224 | r >> 12, a[l++] = 128 | r >> 6 & 63, a[l++] = 128 | 63 & r) : (r = 65536 + ((1023 & r) << 10 | 1023 & e.charCodeAt(++i)), a[l++] = 240 | r >> 18, a[l++] = 128 | r >> 12 & 63, a[l++] = 128 | r >> 6 & 63, a[l++] = 128 | 63 & r);
                                e = a
                            } else {
                                if ("object" !== o) throw new Error(ERROR);
                                if (null === e) throw new Error(ERROR);
                                if (ARRAY_BUFFER && e.constructor === ArrayBuffer) e = new Uint8Array(e);
                                else if (!(Array.isArray(e) || ARRAY_BUFFER && ArrayBuffer.isView(e))) throw new Error(ERROR)
                            }
                            e.length > 64 && (e = new Sha256(t, !0).update(e).array());
                            var c = [],
                                d = [];
                            for (i = 0; i < 64; ++i) {
                                var u = e[i] || 0;
                                c[i] = 92 ^ u, d[i] = 54 ^ u
                            }
                            Sha256.call(this, t, n), this.update(d), this.oKeyPad = c, this.inner = !0, this.sharedMemory = n
                        }
                        Sha256.prototype.update = function(e) {
                            if (!this.finalized) {
                                var t, n = typeof e;
                                if ("string" !== n) {
                                    if ("object" !== n) throw new Error(ERROR);
                                    if (null === e) throw new Error(ERROR);
                                    if (ARRAY_BUFFER && e.constructor === ArrayBuffer) e = new Uint8Array(e);
                                    else if (!(Array.isArray(e) || ARRAY_BUFFER && ArrayBuffer.isView(e))) throw new Error(ERROR);
                                    t = !0
                                }
                                for (var i, o, r = 0, a = e.length, s = this.blocks; r < a;) {
                                    if (this.hashed && (this.hashed = !1, s[0] = this.block, s[16] = s[1] = s[2] = s[3] = s[4] = s[5] = s[6] = s[7] = s[8] = s[9] = s[10] = s[11] = s[12] = s[13] = s[14] = s[15] = 0), t)
                                        for (o = this.start; r < a && o < 64; ++r) s[o >> 2] |= e[r] << SHIFT[3 & o++];
                                    else
                                        for (o = this.start; r < a && o < 64; ++r)(i = e.charCodeAt(r)) < 128 ? s[o >> 2] |= i << SHIFT[3 & o++] : i < 2048 ? (s[o >> 2] |= (192 | i >> 6) << SHIFT[3 & o++], s[o >> 2] |= (128 | 63 & i) << SHIFT[3 & o++]) : i < 55296 || i >= 57344 ? (s[o >> 2] |= (224 | i >> 12) << SHIFT[3 & o++], s[o >> 2] |= (128 | i >> 6 & 63) << SHIFT[3 & o++], s[o >> 2] |= (128 | 63 & i) << SHIFT[3 & o++]) : (i = 65536 + ((1023 & i) << 10 | 1023 & e.charCodeAt(++r)), s[o >> 2] |= (240 | i >> 18) << SHIFT[3 & o++], s[o >> 2] |= (128 | i >> 12 & 63) << SHIFT[3 & o++], s[o >> 2] |= (128 | i >> 6 & 63) << SHIFT[3 & o++], s[o >> 2] |= (128 | 63 & i) << SHIFT[3 & o++]);
                                    this.lastByteIndex = o, this.bytes += o - this.start, o >= 64 ? (this.block = s[16], this.start = o - 64, this.hash(), this.hashed = !0) : this.start = o
                                }
                                return this.bytes > 4294967295 && (this.hBytes += this.bytes / 4294967296 << 0, this.bytes = this.bytes % 4294967296), this
                            }
                        }, Sha256.prototype.finalize = function() {
                            if (!this.finalized) {
                                this.finalized = !0;
                                var e = this.blocks,
                                    t = this.lastByteIndex;
                                e[16] = this.block, e[t >> 2] |= EXTRA[3 & t], this.block = e[16], t >= 56 && (this.hashed || this.hash(), e[0] = this.block, e[16] = e[1] = e[2] = e[3] = e[4] = e[5] = e[6] = e[7] = e[8] = e[9] = e[10] = e[11] = e[12] = e[13] = e[14] = e[15] = 0), e[14] = this.hBytes << 3 | this.bytes >>> 29, e[15] = this.bytes << 3, this.hash()
                            }
                        }, Sha256.prototype.hash = function() {
                            var e, t, n, i, o, r, a, s, l, c = this.h0,
                                d = this.h1,
                                u = this.h2,
                                p = this.h3,
                                h = this.h4,
                                f = this.h5,
                                g = this.h6,
                                m = this.h7,
                                y = this.blocks;
                            for (e = 16; e < 64; ++e) t = ((o = y[e - 15]) >>> 7 | o << 25) ^ (o >>> 18 | o << 14) ^ o >>> 3, n = ((o = y[e - 2]) >>> 17 | o << 15) ^ (o >>> 19 | o << 13) ^ o >>> 10, y[e] = y[e - 16] + t + y[e - 7] + n << 0;
                            for (l = d & u, e = 0; e < 64; e += 4) this.first ? (this.is224 ? (r = 300032, m = (o = y[0] - 1413257819) - 150054599 << 0, p = o + 24177077 << 0) : (r = 704751109, m = (o = y[0] - 210244248) - 1521486534 << 0, p = o + 143694565 << 0), this.first = !1) : (t = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10), i = (r = c & d) ^ c & u ^ l, m = p + (o = m + (n = (h >>> 6 | h << 26) ^ (h >>> 11 | h << 21) ^ (h >>> 25 | h << 7)) + (h & f ^ ~h & g) + K[e] + y[e]) << 0, p = o + (t + i) << 0), t = (p >>> 2 | p << 30) ^ (p >>> 13 | p << 19) ^ (p >>> 22 | p << 10), i = (a = p & c) ^ p & d ^ r, g = u + (o = g + (n = (m >>> 6 | m << 26) ^ (m >>> 11 | m << 21) ^ (m >>> 25 | m << 7)) + (m & h ^ ~m & f) + K[e + 1] + y[e + 1]) << 0, t = ((u = o + (t + i) << 0) >>> 2 | u << 30) ^ (u >>> 13 | u << 19) ^ (u >>> 22 | u << 10), i = (s = u & p) ^ u & c ^ a, f = d + (o = f + (n = (g >>> 6 | g << 26) ^ (g >>> 11 | g << 21) ^ (g >>> 25 | g << 7)) + (g & m ^ ~g & h) + K[e + 2] + y[e + 2]) << 0, t = ((d = o + (t + i) << 0) >>> 2 | d << 30) ^ (d >>> 13 | d << 19) ^ (d >>> 22 | d << 10), i = (l = d & u) ^ d & p ^ s, h = c + (o = h + (n = (f >>> 6 | f << 26) ^ (f >>> 11 | f << 21) ^ (f >>> 25 | f << 7)) + (f & g ^ ~f & m) + K[e + 3] + y[e + 3]) << 0, c = o + (t + i) << 0;
                            this.h0 = this.h0 + c << 0, this.h1 = this.h1 + d << 0, this.h2 = this.h2 + u << 0, this.h3 = this.h3 + p << 0, this.h4 = this.h4 + h << 0, this.h5 = this.h5 + f << 0, this.h6 = this.h6 + g << 0, this.h7 = this.h7 + m << 0
                        }, Sha256.prototype.hex = function() {
                            this.finalize();
                            var e = this.h0,
                                t = this.h1,
                                n = this.h2,
                                i = this.h3,
                                o = this.h4,
                                r = this.h5,
                                a = this.h6,
                                s = this.h7,
                                l = HEX_CHARS[e >> 28 & 15] + HEX_CHARS[e >> 24 & 15] + HEX_CHARS[e >> 20 & 15] + HEX_CHARS[e >> 16 & 15] + HEX_CHARS[e >> 12 & 15] + HEX_CHARS[e >> 8 & 15] + HEX_CHARS[e >> 4 & 15] + HEX_CHARS[15 & e] + HEX_CHARS[t >> 28 & 15] + HEX_CHARS[t >> 24 & 15] + HEX_CHARS[t >> 20 & 15] + HEX_CHARS[t >> 16 & 15] + HEX_CHARS[t >> 12 & 15] + HEX_CHARS[t >> 8 & 15] + HEX_CHARS[t >> 4 & 15] + HEX_CHARS[15 & t] + HEX_CHARS[n >> 28 & 15] + HEX_CHARS[n >> 24 & 15] + HEX_CHARS[n >> 20 & 15] + HEX_CHARS[n >> 16 & 15] + HEX_CHARS[n >> 12 & 15] + HEX_CHARS[n >> 8 & 15] + HEX_CHARS[n >> 4 & 15] + HEX_CHARS[15 & n] + HEX_CHARS[i >> 28 & 15] + HEX_CHARS[i >> 24 & 15] + HEX_CHARS[i >> 20 & 15] + HEX_CHARS[i >> 16 & 15] + HEX_CHARS[i >> 12 & 15] + HEX_CHARS[i >> 8 & 15] + HEX_CHARS[i >> 4 & 15] + HEX_CHARS[15 & i] + HEX_CHARS[o >> 28 & 15] + HEX_CHARS[o >> 24 & 15] + HEX_CHARS[o >> 20 & 15] + HEX_CHARS[o >> 16 & 15] + HEX_CHARS[o >> 12 & 15] + HEX_CHARS[o >> 8 & 15] + HEX_CHARS[o >> 4 & 15] + HEX_CHARS[15 & o] + HEX_CHARS[r >> 28 & 15] + HEX_CHARS[r >> 24 & 15] + HEX_CHARS[r >> 20 & 15] + HEX_CHARS[r >> 16 & 15] + HEX_CHARS[r >> 12 & 15] + HEX_CHARS[r >> 8 & 15] + HEX_CHARS[r >> 4 & 15] + HEX_CHARS[15 & r] + HEX_CHARS[a >> 28 & 15] + HEX_CHARS[a >> 24 & 15] + HEX_CHARS[a >> 20 & 15] + HEX_CHARS[a >> 16 & 15] + HEX_CHARS[a >> 12 & 15] + HEX_CHARS[a >> 8 & 15] + HEX_CHARS[a >> 4 & 15] + HEX_CHARS[15 & a];
                            return this.is224 || (l += HEX_CHARS[s >> 28 & 15] + HEX_CHARS[s >> 24 & 15] + HEX_CHARS[s >> 20 & 15] + HEX_CHARS[s >> 16 & 15] + HEX_CHARS[s >> 12 & 15] + HEX_CHARS[s >> 8 & 15] + HEX_CHARS[s >> 4 & 15] + HEX_CHARS[15 & s]), l
                        }, Sha256.prototype.toString = Sha256.prototype.hex, Sha256.prototype.digest = function() {
                            this.finalize();
                            var e = this.h0,
                                t = this.h1,
                                n = this.h2,
                                i = this.h3,
                                o = this.h4,
                                r = this.h5,
                                a = this.h6,
                                s = this.h7,
                                l = [e >> 24 & 255, e >> 16 & 255, e >> 8 & 255, 255 & e, t >> 24 & 255, t >> 16 & 255, t >> 8 & 255, 255 & t, n >> 24 & 255, n >> 16 & 255, n >> 8 & 255, 255 & n, i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, 255 & i, o >> 24 & 255, o >> 16 & 255, o >> 8 & 255, 255 & o, r >> 24 & 255, r >> 16 & 255, r >> 8 & 255, 255 & r, a >> 24 & 255, a >> 16 & 255, a >> 8 & 255, 255 & a];
                            return this.is224 || l.push(s >> 24 & 255, s >> 16 & 255, s >> 8 & 255, 255 & s), l
                        }, Sha256.prototype.array = Sha256.prototype.digest, Sha256.prototype.arrayBuffer = function() {
                            this.finalize();
                            var e = new ArrayBuffer(this.is224 ? 28 : 32),
                                t = new DataView(e);
                            return t.setUint32(0, this.h0), t.setUint32(4, this.h1), t.setUint32(8, this.h2), t.setUint32(12, this.h3), t.setUint32(16, this.h4), t.setUint32(20, this.h5), t.setUint32(24, this.h6), this.is224 || t.setUint32(28, this.h7), e
                        }, HmacSha256.prototype = new Sha256, HmacSha256.prototype.finalize = function() {
                            if (Sha256.prototype.finalize.call(this), this.inner) {
                                this.inner = !1;
                                var e = this.array();
                                Sha256.call(this, this.is224, this.sharedMemory), this.update(this.oKeyPad), this.update(e), Sha256.prototype.finalize.call(this)
                            }
                        };
                        var exports = createMethod();
                        exports.sha256 = exports, exports.sha224 = createMethod(!0), exports.sha256.hmac = createHmacMethod(), exports.sha224.hmac = createHmacMethod(!0), COMMON_JS ? module.exports = exports : (root.sha256 = exports.sha256, root.sha224 = exports.sha224, AMD && (__WEBPACK_AMD_DEFINE_RESULT__ = function() {
                            return exports
                        }.call(exports, __webpack_require__, exports, module), void 0 === __WEBPACK_AMD_DEFINE_RESULT__ || (module.exports = __WEBPACK_AMD_DEFINE_RESULT__)))
                    })()
                },
                4530: (e, t) => {
                    function n(e, t) {
                        var n = [],
                            i = [];
                        return null == t && (t = function(e, t) {
                                return n[0] === t ? "[Circular ~]" : "[Circular ~." + i.slice(0, n.indexOf(t)).join(".") + "]"
                            }),
                            function(o, r) {
                                if (n.length > 0) {
                                    var a = n.indexOf(this);
                                    ~a ? n.splice(a + 1) : n.push(this), ~a ? i.splice(a, 1 / 0, o) : i.push(o), ~n.indexOf(r) && (r = t.call(this, o, r))
                                } else n.push(r);
                                return null == e ? r : e.call(this, o, r)
                            }
                    }(e.exports = function(e, t, i, o) {
                        return JSON.stringify(e, n(t, o), i)
                    }).getSerialize = n
                },
                2043: function(e, t, n) {
                    var i, o;
                    ! function(r, a) {
                        "use strict";
                        i = function() {
                            var e = function() {},
                                t = "undefined",
                                n = typeof window !== t && typeof window.navigator !== t && /Trident\/|MSIE /.test(window.navigator.userAgent),
                                i = ["trace", "debug", "info", "warn", "error"];

                            function o(e, t) {
                                var n = e[t];
                                if ("function" == typeof n.bind) return n.bind(e);
                                try {
                                    return Function.prototype.bind.call(n, e)
                                } catch (t) {
                                    return function() {
                                        return Function.prototype.apply.apply(n, [e, arguments])
                                    }
                                }
                            }

                            function r() {
                                console.log && (console.log.apply ? console.log.apply(console, arguments) : Function.prototype.apply.apply(console.log, [console, arguments])), console.trace && console.trace()
                            }

                            function a(i) {
                                return "debug" === i && (i = "log"), typeof console !== t && ("trace" === i && n ? r : void 0 !== console[i] ? o(console, i) : void 0 !== console.log ? o(console, "log") : e)
                            }

                            function s(t, n) {
                                for (var o = 0; o < i.length; o++) {
                                    var r = i[o];
                                    this[r] = o < t ? e : this.methodFactory(r, t, n)
                                }
                                this.log = this.debug
                            }

                            function l(e, n, i) {
                                return function() {
                                    typeof console !== t && (s.call(this, n, i), this[e].apply(this, arguments))
                                }
                            }

                            function c(e, t, n) {
                                return a(e) || l.apply(this, arguments)
                            }

                            function d(e, n, o) {
                                var r, a = this;
                                n = null == n ? "WARN" : n;
                                var l = "loglevel";

                                function d() {
                                    var e;
                                    if (typeof window !== t && l) {
                                        try {
                                            e = window.localStorage[l]
                                        } catch (e) {}
                                        if (typeof e === t) try {
                                            var n = window.document.cookie,
                                                i = n.indexOf(encodeURIComponent(l) + "="); - 1 !== i && (e = /^([^;]+)/.exec(n.slice(i))[1])
                                        } catch (e) {}
                                        return void 0 === a.levels[e] && (e = void 0), e
                                    }
                                }
                                "string" == typeof e ? l += ":" + e : "symbol" == typeof e && (l = void 0), a.name = e, a.levels = {
                                    TRACE: 0,
                                    DEBUG: 1,
                                    INFO: 2,
                                    WARN: 3,
                                    ERROR: 4,
                                    SILENT: 5
                                }, a.methodFactory = o || c, a.getLevel = function() {
                                    return r
                                }, a.setLevel = function(n, o) {
                                    if ("string" == typeof n && void 0 !== a.levels[n.toUpperCase()] && (n = a.levels[n.toUpperCase()]), !("number" == typeof n && n >= 0 && n <= a.levels.SILENT)) throw "log.setLevel() called with invalid level: " + n;
                                    if (r = n, !1 !== o && function(e) {
                                            var n = (i[e] || "silent").toUpperCase();
                                            if (typeof window !== t && l) {
                                                try {
                                                    return void(window.localStorage[l] = n)
                                                } catch (e) {}
                                                try {
                                                    window.document.cookie = encodeURIComponent(l) + "=" + n + ";"
                                                } catch (e) {}
                                            }
                                        }(n), s.call(a, n, e), typeof console === t && n < a.levels.SILENT) return "No console available for logging"
                                }, a.setDefaultLevel = function(e) {
                                    n = e, d() || a.setLevel(e, !1)
                                }, a.resetLevel = function() {
                                    a.setLevel(n, !1),
                                        function() {
                                            if (typeof window !== t && l) {
                                                try {
                                                    return void window.localStorage.removeItem(l)
                                                } catch (e) {}
                                                try {
                                                    window.document.cookie = encodeURIComponent(l) + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC"
                                                } catch (e) {}
                                            }
                                        }()
                                }, a.enableAll = function(e) {
                                    a.setLevel(a.levels.TRACE, e)
                                }, a.disableAll = function(e) {
                                    a.setLevel(a.levels.SILENT, e)
                                };
                                var u = d();
                                null == u && (u = n), a.setLevel(u, !1)
                            }
                            var u = new d,
                                p = {};
                            u.getLogger = function(e) {
                                if ("symbol" != typeof e && "string" != typeof e || "" === e) throw new TypeError("You must supply a name when creating a logger.");
                                var t = p[e];
                                return t || (t = p[e] = new d(e, u.getLevel(), u.methodFactory)), t
                            };
                            var h = typeof window !== t ? window.log : void 0;
                            return u.noConflict = function() {
                                return typeof window !== t && window.log === u && (window.log = h), u
                            }, u.getLoggers = function() {
                                return p
                            }, u.default = u, u
                        }, void 0 === (o = i.call(t, n, t, e)) || (e.exports = o)
                    }()
                },
                8661: (e, t, n) => {
                    "use strict";
                    n.r(t), n.d(t, {
                        Children: () => h,
                        Component: () => o.wA,
                        Fragment: () => o.HY,
                        PureComponent: () => s,
                        StrictMode: () => q,
                        Suspense: () => m,
                        SuspenseList: () => x,
                        __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED: () => H,
                        cloneElement: () => V,
                        createContext: () => o.kr,
                        createElement: () => o.az,
                        createFactory: () => N,
                        createPortal: () => k,
                        createRef: () => o.Vf,
                        default: () => Y,
                        findDOMNode: () => W,
                        flushSync: () => $,
                        forwardRef: () => u,
                        hydrate: () => O,
                        isValidElement: () => U,
                        lazy: () => b,
                        memo: () => l,
                        render: () => A,
                        unmountComponentAtNode: () => z,
                        unstable_batchedUpdates: () => G,
                        useCallback: () => i.I4,
                        useContext: () => i.qp,
                        useDebugValue: () => i.Qb,
                        useEffect: () => i.d4,
                        useErrorBoundary: () => i.cO,
                        useImperativeHandle: () => i.aP,
                        useLayoutEffect: () => i.bt,
                        useMemo: () => i.Ye,
                        useReducer: () => i._Y,
                        useRef: () => i.sO,
                        useState: () => i.eJ,
                        version: () => B
                    });
                    var i = n(396),
                        o = n(6400);

                    function r(e, t) {
                        for (var n in t) e[n] = t[n];
                        return e
                    }

                    function a(e, t) {
                        for (var n in e)
                            if ("__source" !== n && !(n in t)) return !0;
                        for (var i in t)
                            if ("__source" !== i && e[i] !== t[i]) return !0;
                        return !1
                    }

                    function s(e) {
                        this.props = e
                    }

                    function l(e, t) {
                        function n(e) {
                            var n = this.props.ref,
                                i = n == e.ref;
                            return !i && n && (n.call ? n(null) : n.current = null), t ? !t(this.props, e) || !i : a(this.props, e)
                        }

                        function i(t) {
                            return this.shouldComponentUpdate = n, (0, o.az)(e, t)
                        }
                        return i.displayName = "Memo(" + (e.displayName || e.name) + ")", i.prototype.isReactComponent = !0, i.__f = !0, i
                    }(s.prototype = new o.wA).isPureReactComponent = !0, s.prototype.shouldComponentUpdate = function(e, t) {
                        return a(this.props, e) || a(this.state, t)
                    };
                    var c = o.YM.__b;
                    o.YM.__b = function(e) {
                        e.type && e.type.__f && e.ref && (e.props.ref = e.ref, e.ref = null), c && c(e)
                    };
                    var d = "undefined" != typeof Symbol && Symbol.for && Symbol.for("react.forward_ref") || 3911;

                    function u(e) {
                        function t(t, n) {
                            var i = r({}, t);
                            return delete i.ref, e(i, (n = t.ref || n) && ("object" != typeof n || "current" in n) ? n : null)
                        }
                        return t.$$typeof = d, t.render = t, t.prototype.isReactComponent = t.__f = !0, t.displayName = "ForwardRef(" + (e.displayName || e.name) + ")", t
                    }
                    var p = function(e, t) {
                            return null == e ? null : (0, o.bR)((0, o.bR)(e).map(t))
                        },
                        h = {
                            map: p,
                            forEach: p,
                            count: function(e) {
                                return e ? (0, o.bR)(e).length : 0
                            },
                            only: function(e) {
                                var t = (0, o.bR)(e);
                                if (1 !== t.length) throw "Children.only";
                                return t[0]
                            },
                            toArray: o.bR
                        },
                        f = o.YM.__e;
                    o.YM.__e = function(e, t, n) {
                        if (e.then)
                            for (var i, o = t; o = o.__;)
                                if ((i = o.__c) && i.__c) return null == t.__e && (t.__e = n.__e, t.__k = n.__k), i.__c(e, t);
                        f(e, t, n)
                    };
                    var g = o.YM.unmount;

                    function m() {
                        this.__u = 0, this.t = null, this.__b = null
                    }

                    function y(e) {
                        var t = e.__.__c;
                        return t && t.__e && t.__e(e)
                    }

                    function b(e) {
                        var t, n, i;

                        function r(r) {
                            if (t || (t = e()).then((function(e) {
                                    n = e.default || e
                                }), (function(e) {
                                    i = e
                                })), i) throw i;
                            if (!n) throw t;
                            return (0, o.az)(n, r)
                        }
                        return r.displayName = "Lazy", r.__f = !0, r
                    }

                    function x() {
                        this.u = null, this.o = null
                    }
                    o.YM.unmount = function(e) {
                        var t = e.__c;
                        t && t.__R && t.__R(), t && !0 === e.__h && (e.type = null), g && g(e)
                    }, (m.prototype = new o.wA).__c = function(e, t) {
                        var n = t.__c,
                            i = this;
                        null == i.t && (i.t = []), i.t.push(n);
                        var o = y(i.__v),
                            r = !1,
                            a = function() {
                                r || (r = !0, n.__R = null, o ? o(s) : s())
                            };
                        n.__R = a;
                        var s = function() {
                                if (!--i.__u) {
                                    if (i.state.__e) {
                                        var e = i.state.__e;
                                        i.__v.__k[0] = function e(t, n, i) {
                                            return t && (t.__v = null, t.__k = t.__k && t.__k.map((function(t) {
                                                return e(t, n, i)
                                            })), t.__c && t.__c.__P === n && (t.__e && i.insertBefore(t.__e, t.__d), t.__c.__e = !0, t.__c.__P = i)), t
                                        }(e, e.__c.__P, e.__c.__O)
                                    }
                                    var t;
                                    for (i.setState({
                                            __e: i.__b = null
                                        }); t = i.t.pop();) t.forceUpdate()
                                }
                            },
                            l = !0 === t.__h;
                        i.__u++ || l || i.setState({
                            __e: i.__b = i.__v.__k[0]
                        }), e.then(a, a)
                    }, m.prototype.componentWillUnmount = function() {
                        this.t = []
                    }, m.prototype.render = function(e, t) {
                        if (this.__b) {
                            if (this.__v.__k) {
                                var n = document.createElement("div"),
                                    i = this.__v.__k[0].__c;
                                this.__v.__k[0] = function e(t, n, i) {
                                    return t && (t.__c && t.__c.__H && (t.__c.__H.__.forEach((function(e) {
                                        "function" == typeof e.__c && e.__c()
                                    })), t.__c.__H = null), null != (t = r({}, t)).__c && (t.__c.__P === i && (t.__c.__P = n), t.__c = null), t.__k = t.__k && t.__k.map((function(t) {
                                        return e(t, n, i)
                                    }))), t
                                }(this.__b, n, i.__O = i.__P)
                            }
                            this.__b = null
                        }
                        var a = t.__e && (0, o.az)(o.HY, null, e.fallback);
                        return a && (a.__h = null), [(0, o.az)(o.HY, null, t.__e ? null : e.children), a]
                    };
                    var v = function(e, t, n) {
                        if (++n[1] === n[0] && e.o.delete(t), e.props.revealOrder && ("t" !== e.props.revealOrder[0] || !e.o.size))
                            for (n = e.u; n;) {
                                for (; n.length > 3;) n.pop()();
                                if (n[1] < n[0]) break;
                                e.u = n = n[2]
                            }
                    };

                    function w(e) {
                        return this.getChildContext = function() {
                            return e.context
                        }, e.children
                    }

                    function _(e) {
                        var t = this,
                            n = e.i;
                        t.componentWillUnmount = function() {
                            (0, o.sY)(null, t.l), t.l = null, t.i = null
                        }, t.i && t.i !== n && t.componentWillUnmount(), e.__v ? (t.l || (t.i = n, t.l = {
                            nodeType: 1,
                            parentNode: n,
                            childNodes: [],
                            appendChild: function(e) {
                                this.childNodes.push(e), t.i.appendChild(e)
                            },
                            insertBefore: function(e, n) {
                                this.childNodes.push(e), t.i.appendChild(e)
                            },
                            removeChild: function(e) {
                                this.childNodes.splice(this.childNodes.indexOf(e) >>> 1, 1), t.i.removeChild(e)
                            }
                        }), (0, o.sY)((0, o.az)(w, {
                            context: t.context
                        }, e.__v), t.l)) : t.l && t.componentWillUnmount()
                    }

                    function k(e, t) {
                        return (0, o.az)(_, {
                            __v: e,
                            i: t
                        })
                    }(x.prototype = new o.wA).__e = function(e) {
                        var t = this,
                            n = y(t.__v),
                            i = t.o.get(e);
                        return i[0]++,
                            function(o) {
                                var r = function() {
                                    t.props.revealOrder ? (i.push(o), v(t, e, i)) : o()
                                };
                                n ? n(r) : r()
                            }
                    }, x.prototype.render = function(e) {
                        this.u = null, this.o = new Map;
                        var t = (0, o.bR)(e.children);
                        e.revealOrder && "b" === e.revealOrder[0] && t.reverse();
                        for (var n = t.length; n--;) this.o.set(t[n], this.u = [1, 0, this.u]);
                        return e.children
                    }, x.prototype.componentDidUpdate = x.prototype.componentDidMount = function() {
                        var e = this;
                        this.o.forEach((function(t, n) {
                            v(e, n, t)
                        }))
                    };
                    var C = "undefined" != typeof Symbol && Symbol.for && Symbol.for("react.element") || 60103,
                        S = /^(?:accent|alignment|arabic|baseline|cap|clip(?!PathU)|color|dominant|fill|flood|font|glyph(?!R)|horiz|marker(?!H|W|U)|overline|paint|stop|strikethrough|stroke|text(?!L)|underline|unicode|units|v|vector|vert|word|writing|x(?!C))[A-Z]/,
                        E = "undefined" != typeof document,
                        I = function(e) {
                            return ("undefined" != typeof Symbol && "symbol" == typeof Symbol() ? /fil|che|rad/i : /fil|che|ra/i).test(e)
                        };

                    function A(e, t, n) {
                        return null == t.__k && (t.textContent = ""), (0, o.sY)(e, t), "function" == typeof n && n(), e ? e.__c : null
                    }

                    function O(e, t, n) {
                        return (0, o.ZB)(e, t), "function" == typeof n && n(), e ? e.__c : null
                    }
                    o.wA.prototype.isReactComponent = {}, ["componentWillMount", "componentWillReceiveProps", "componentWillUpdate"].forEach((function(e) {
                        Object.defineProperty(o.wA.prototype, e, {
                            configurable: !0,
                            get: function() {
                                return this["UNSAFE_" + e]
                            },
                            set: function(t) {
                                Object.defineProperty(this, e, {
                                    configurable: !0,
                                    writable: !0,
                                    value: t
                                })
                            }
                        })
                    }));
                    var T = o.YM.event;

                    function M() {}

                    function R() {
                        return this.cancelBubble
                    }

                    function P() {
                        return this.defaultPrevented
                    }
                    o.YM.event = function(e) {
                        return T && (e = T(e)), e.persist = M, e.isPropagationStopped = R, e.isDefaultPrevented = P, e.nativeEvent = e
                    };
                    var D, j = {
                            configurable: !0,
                            get: function() {
                                return this.class
                            }
                        },
                        L = o.YM.vnode;
                    o.YM.vnode = function(e) {
                        var t = e.type,
                            n = e.props,
                            i = n;
                        if ("string" == typeof t) {
                            var r = -1 === t.indexOf("-");
                            for (var a in i = {}, n) {
                                var s = n[a];
                                E && "children" === a && "noscript" === t || "value" === a && "defaultValue" in n && null == s || ("defaultValue" === a && "value" in n && null == n.value ? a = "value" : "download" === a && !0 === s ? s = "" : /ondoubleclick/i.test(a) ? a = "ondblclick" : /^onchange(textarea|input)/i.test(a + t) && !I(n.type) ? a = "oninput" : /^onfocus$/i.test(a) ? a = "onfocusin" : /^onblur$/i.test(a) ? a = "onfocusout" : /^on(Ani|Tra|Tou|BeforeInp|Compo)/.test(a) ? a = a.toLowerCase() : r && S.test(a) ? a = a.replace(/[A-Z0-9]/, "-$&").toLowerCase() : null === s && (s = void 0), i[a] = s)
                            }
                            "select" == t && i.multiple && Array.isArray(i.value) && (i.value = (0, o.bR)(n.children).forEach((function(e) {
                                e.props.selected = -1 != i.value.indexOf(e.props.value)
                            }))), "select" == t && null != i.defaultValue && (i.value = (0, o.bR)(n.children).forEach((function(e) {
                                e.props.selected = i.multiple ? -1 != i.defaultValue.indexOf(e.props.value) : i.defaultValue == e.props.value
                            }))), e.props = i, n.class != n.className && (j.enumerable = "className" in n, null != n.className && (i.class = n.className), Object.defineProperty(i, "className", j))
                        }
                        e.$$typeof = C, L && L(e)
                    };
                    var F = o.YM.__r;
                    o.YM.__r = function(e) {
                        F && F(e), D = e.__c
                    };
                    var H = {
                            ReactCurrentDispatcher: {
                                current: {
                                    readContext: function(e) {
                                        return D.__n[e.__c].props.value
                                    }
                                }
                            }
                        },
                        B = "17.0.2";

                    function N(e) {
                        return o.az.bind(null, e)
                    }

                    function U(e) {
                        return !!e && e.$$typeof === C
                    }

                    function V(e) {
                        return U(e) ? o.Tm.apply(null, arguments) : e
                    }

                    function z(e) {
                        return !!e.__k && ((0, o.sY)(null, e), !0)
                    }

                    function W(e) {
                        return e && (e.base || 1 === e.nodeType && e) || null
                    }
                    var G = function(e, t) {
                            return e(t)
                        },
                        $ = function(e, t) {
                            return e(t)
                        },
                        q = o.HY;
                    const Y = {
                        useState: i.eJ,
                        useReducer: i._Y,
                        useEffect: i.d4,
                        useLayoutEffect: i.bt,
                        useRef: i.sO,
                        useImperativeHandle: i.aP,
                        useMemo: i.Ye,
                        useCallback: i.I4,
                        useContext: i.qp,
                        useDebugValue: i.Qb,
                        version: "17.0.2",
                        Children: h,
                        render: A,
                        hydrate: O,
                        unmountComponentAtNode: z,
                        createPortal: k,
                        createElement: o.az,
                        createContext: o.kr,
                        createFactory: N,
                        cloneElement: V,
                        createRef: o.Vf,
                        Fragment: o.HY,
                        isValidElement: U,
                        findDOMNode: W,
                        Component: o.wA,
                        PureComponent: s,
                        memo: l,
                        forwardRef: u,
                        flushSync: $,
                        unstable_batchedUpdates: G,
                        StrictMode: o.HY,
                        Suspense: m,
                        SuspenseList: x,
                        lazy: b,
                        __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED: H
                    }
                },
                6400: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        HY: () => b,
                        Tm: () => N,
                        Vf: () => y,
                        YM: () => o,
                        ZB: () => B,
                        az: () => g,
                        bR: () => E,
                        h: () => g,
                        kr: () => U,
                        sY: () => H,
                        wA: () => x
                    });
                    var i, o, r, a, s, l, c, d = {},
                        u = [],
                        p = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;

                    function h(e, t) {
                        for (var n in t) e[n] = t[n];
                        return e
                    }

                    function f(e) {
                        var t = e.parentNode;
                        t && t.removeChild(e)
                    }

                    function g(e, t, n) {
                        var o, r, a, s = {};
                        for (a in t) "key" == a ? o = t[a] : "ref" == a ? r = t[a] : s[a] = t[a];
                        if (arguments.length > 2 && (s.children = arguments.length > 3 ? i.call(arguments, 2) : n), "function" == typeof e && null != e.defaultProps)
                            for (a in e.defaultProps) void 0 === s[a] && (s[a] = e.defaultProps[a]);
                        return m(e, s, o, r, null)
                    }

                    function m(e, t, n, i, a) {
                        var s = {
                            type: e,
                            props: t,
                            key: n,
                            ref: i,
                            __k: null,
                            __: null,
                            __b: 0,
                            __e: null,
                            __d: void 0,
                            __c: null,
                            __h: null,
                            constructor: void 0,
                            __v: null == a ? ++r : a
                        };
                        return null == a && null != o.vnode && o.vnode(s), s
                    }

                    function y() {
                        return {
                            current: null
                        }
                    }

                    function b(e) {
                        return e.children
                    }

                    function x(e, t) {
                        this.props = e, this.context = t
                    }

                    function v(e, t) {
                        if (null == t) return e.__ ? v(e.__, e.__.__k.indexOf(e) + 1) : null;
                        for (var n; t < e.__k.length; t++)
                            if (null != (n = e.__k[t]) && null != n.__e) return n.__e;
                        return "function" == typeof e.type ? v(e) : null
                    }

                    function w(e) {
                        var t, n;
                        if (null != (e = e.__) && null != e.__c) {
                            for (e.__e = e.__c.base = null, t = 0; t < e.__k.length; t++)
                                if (null != (n = e.__k[t]) && null != n.__e) {
                                    e.__e = e.__c.base = n.__e;
                                    break
                                } return w(e)
                        }
                    }

                    function _(e) {
                        (!e.__d && (e.__d = !0) && a.push(e) && !k.__r++ || l !== o.debounceRendering) && ((l = o.debounceRendering) || s)(k)
                    }

                    function k() {
                        for (var e; k.__r = a.length;) e = a.sort((function(e, t) {
                            return e.__v.__b - t.__v.__b
                        })), a = [], e.some((function(e) {
                            var t, n, i, o, r, a;
                            e.__d && (r = (o = (t = e).__v).__e, (a = t.__P) && (n = [], (i = h({}, o)).__v = o.__v + 1, R(a, o, i, t.__n, void 0 !== a.ownerSVGElement, null != o.__h ? [r] : null, n, null == r ? v(o) : r, o.__h), P(n, o), o.__e != r && w(o)))
                        }))
                    }

                    function C(e, t, n, i, o, r, a, s, l, c) {
                        var p, h, f, g, y, x, w, _ = i && i.__k || u,
                            k = _.length;
                        for (n.__k = [], p = 0; p < t.length; p++)
                            if (null != (g = n.__k[p] = null == (g = t[p]) || "boolean" == typeof g ? null : "string" == typeof g || "number" == typeof g || "bigint" == typeof g ? m(null, g, null, null, g) : Array.isArray(g) ? m(b, {
                                    children: g
                                }, null, null, null) : g.__b > 0 ? m(g.type, g.props, g.key, null, g.__v) : g)) {
                                if (g.__ = n, g.__b = n.__b + 1, null === (f = _[p]) || f && g.key == f.key && g.type === f.type) _[p] = void 0;
                                else
                                    for (h = 0; h < k; h++) {
                                        if ((f = _[h]) && g.key == f.key && g.type === f.type) {
                                            _[h] = void 0;
                                            break
                                        }
                                        f = null
                                    }
                                R(e, g, f = f || d, o, r, a, s, l, c), y = g.__e, (h = g.ref) && f.ref != h && (w || (w = []), f.ref && w.push(f.ref, null, g), w.push(h, g.__c || y, g)), null != y ? (null == x && (x = y), "function" == typeof g.type && g.__k === f.__k ? g.__d = l = S(g, l, e) : l = I(e, g, f, _, y, l), "function" == typeof n.type && (n.__d = l)) : l && f.__e == l && l.parentNode != e && (l = v(f))
                            } for (n.__e = x, p = k; p--;) null != _[p] && ("function" == typeof n.type && null != _[p].__e && _[p].__e == n.__d && (n.__d = v(i, p + 1)), L(_[p], _[p]));
                        if (w)
                            for (p = 0; p < w.length; p++) j(w[p], w[++p], w[++p])
                    }

                    function S(e, t, n) {
                        for (var i, o = e.__k, r = 0; o && r < o.length; r++)(i = o[r]) && (i.__ = e, t = "function" == typeof i.type ? S(i, t, n) : I(n, i, i, o, i.__e, t));
                        return t
                    }

                    function E(e, t) {
                        return t = t || [], null == e || "boolean" == typeof e || (Array.isArray(e) ? e.some((function(e) {
                            E(e, t)
                        })) : t.push(e)), t
                    }

                    function I(e, t, n, i, o, r) {
                        var a, s, l;
                        if (void 0 !== t.__d) a = t.__d, t.__d = void 0;
                        else if (null == n || o != r || null == o.parentNode) e: if (null == r || r.parentNode !== e) e.appendChild(o), a = null;
                            else {
                                for (s = r, l = 0;
                                    (s = s.nextSibling) && l < i.length; l += 2)
                                    if (s == o) break e;
                                e.insertBefore(o, r), a = r
                            } return void 0 !== a ? a : o.nextSibling
                    }

                    function A(e, t, n) {
                        "-" === t[0] ? e.setProperty(t, n) : e[t] = null == n ? "" : "number" != typeof n || p.test(t) ? n : n + "px"
                    }

                    function O(e, t, n, i, o) {
                        var r;
                        e: if ("style" === t)
                            if ("string" == typeof n) e.style.cssText = n;
                            else {
                                if ("string" == typeof i && (e.style.cssText = i = ""), i)
                                    for (t in i) n && t in n || A(e.style, t, "");
                                if (n)
                                    for (t in n) i && n[t] === i[t] || A(e.style, t, n[t])
                            }
                        else if ("o" === t[0] && "n" === t[1]) r = t !== (t = t.replace(/Capture$/, "")), t = t.toLowerCase() in e ? t.toLowerCase().slice(2) : t.slice(2), e.l || (e.l = {}), e.l[t + r] = n, n ? i || e.addEventListener(t, r ? M : T, r) : e.removeEventListener(t, r ? M : T, r);
                        else if ("dangerouslySetInnerHTML" !== t) {
                            if (o) t = t.replace(/xlink[H:h]/, "h").replace(/sName$/, "s");
                            else if ("href" !== t && "list" !== t && "form" !== t && "tabIndex" !== t && "download" !== t && t in e) try {
                                e[t] = null == n ? "" : n;
                                break e
                            } catch (e) {}
                            "function" == typeof n || (null != n && (!1 !== n || "a" === t[0] && "r" === t[1]) ? e.setAttribute(t, n) : e.removeAttribute(t))
                        }
                    }

                    function T(e) {
                        this.l[e.type + !1](o.event ? o.event(e) : e)
                    }

                    function M(e) {
                        this.l[e.type + !0](o.event ? o.event(e) : e)
                    }

                    function R(e, t, n, i, r, a, s, l, c) {
                        var d, u, p, f, g, m, y, v, w, _, k, S = t.type;
                        if (void 0 !== t.constructor) return null;
                        null != n.__h && (c = n.__h, l = t.__e = n.__e, t.__h = null, a = [l]), (d = o.__b) && d(t);
                        try {
                            e: if ("function" == typeof S) {
                                if (v = t.props, w = (d = S.contextType) && i[d.__c], _ = d ? w ? w.props.value : d.__ : i, n.__c ? y = (u = t.__c = n.__c).__ = u.__E : ("prototype" in S && S.prototype.render ? t.__c = u = new S(v, _) : (t.__c = u = new x(v, _), u.constructor = S, u.render = F), w && w.sub(u), u.props = v, u.state || (u.state = {}), u.context = _, u.__n = i, p = u.__d = !0, u.__h = []), null == u.__s && (u.__s = u.state), null != S.getDerivedStateFromProps && (u.__s == u.state && (u.__s = h({}, u.__s)), h(u.__s, S.getDerivedStateFromProps(v, u.__s))), f = u.props, g = u.state, p) null == S.getDerivedStateFromProps && null != u.componentWillMount && u.componentWillMount(), null != u.componentDidMount && u.__h.push(u.componentDidMount);
                                else {
                                    if (null == S.getDerivedStateFromProps && v !== f && null != u.componentWillReceiveProps && u.componentWillReceiveProps(v, _), !u.__e && null != u.shouldComponentUpdate && !1 === u.shouldComponentUpdate(v, u.__s, _) || t.__v === n.__v) {
                                        u.props = v, u.state = u.__s, t.__v !== n.__v && (u.__d = !1), u.__v = t, t.__e = n.__e, t.__k = n.__k, t.__k.forEach((function(e) {
                                            e && (e.__ = t)
                                        })), u.__h.length && s.push(u);
                                        break e
                                    }
                                    null != u.componentWillUpdate && u.componentWillUpdate(v, u.__s, _), null != u.componentDidUpdate && u.__h.push((function() {
                                        u.componentDidUpdate(f, g, m)
                                    }))
                                }
                                u.context = _, u.props = v, u.state = u.__s, (d = o.__r) && d(t), u.__d = !1, u.__v = t, u.__P = e, d = u.render(u.props, u.state, u.context), u.state = u.__s, null != u.getChildContext && (i = h(h({}, i), u.getChildContext())), p || null == u.getSnapshotBeforeUpdate || (m = u.getSnapshotBeforeUpdate(f, g)), k = null != d && d.type === b && null == d.key ? d.props.children : d, C(e, Array.isArray(k) ? k : [k], t, n, i, r, a, s, l, c), u.base = t.__e, t.__h = null, u.__h.length && s.push(u), y && (u.__E = u.__ = null), u.__e = !1
                            } else null == a && t.__v === n.__v ? (t.__k = n.__k, t.__e = n.__e) : t.__e = D(n.__e, t, n, i, r, a, s, c);
                            (d = o.diffed) && d(t)
                        }
                        catch (e) {
                            t.__v = null, (c || null != a) && (t.__e = l, t.__h = !!c, a[a.indexOf(l)] = null), o.__e(e, t, n)
                        }
                    }

                    function P(e, t) {
                        o.__c && o.__c(t, e), e.some((function(t) {
                            try {
                                e = t.__h, t.__h = [], e.some((function(e) {
                                    e.call(t)
                                }))
                            } catch (e) {
                                o.__e(e, t.__v)
                            }
                        }))
                    }

                    function D(e, t, n, o, r, a, s, l) {
                        var c, u, p, h = n.props,
                            g = t.props,
                            m = t.type,
                            y = 0;
                        if ("svg" === m && (r = !0), null != a)
                            for (; y < a.length; y++)
                                if ((c = a[y]) && "setAttribute" in c == !!m && (m ? c.localName === m : 3 === c.nodeType)) {
                                    e = c, a[y] = null;
                                    break
                                } if (null == e) {
                            if (null === m) return document.createTextNode(g);
                            e = r ? document.createElementNS("http://www.w3.org/2000/svg", m) : document.createElement(m, g.is && g), a = null, l = !1
                        }
                        if (null === m) h === g || l && e.data === g || (e.data = g);
                        else {
                            if (a = a && i.call(e.childNodes), u = (h = n.props || d).dangerouslySetInnerHTML, p = g.dangerouslySetInnerHTML, !l) {
                                if (null != a)
                                    for (h = {}, y = 0; y < e.attributes.length; y++) h[e.attributes[y].name] = e.attributes[y].value;
                                (p || u) && (p && (u && p.__html == u.__html || p.__html === e.innerHTML) || (e.innerHTML = p && p.__html || ""))
                            }
                            if (function(e, t, n, i, o) {
                                    var r;
                                    for (r in n) "children" === r || "key" === r || r in t || O(e, r, null, n[r], i);
                                    for (r in t) o && "function" != typeof t[r] || "children" === r || "key" === r || "value" === r || "checked" === r || n[r] === t[r] || O(e, r, t[r], n[r], i)
                                }(e, g, h, r, l), p) t.__k = [];
                            else if (y = t.props.children, C(e, Array.isArray(y) ? y : [y], t, n, o, r && "foreignObject" !== m, a, s, a ? a[0] : n.__k && v(n, 0), l), null != a)
                                for (y = a.length; y--;) null != a[y] && f(a[y]);
                            l || ("value" in g && void 0 !== (y = g.value) && (y !== e.value || "progress" === m && !y || "option" === m && y !== h.value) && O(e, "value", y, h.value, !1), "checked" in g && void 0 !== (y = g.checked) && y !== e.checked && O(e, "checked", y, h.checked, !1))
                        }
                        return e
                    }

                    function j(e, t, n) {
                        try {
                            "function" == typeof e ? e(t) : e.current = t
                        } catch (e) {
                            o.__e(e, n)
                        }
                    }

                    function L(e, t, n) {
                        var i, r;
                        if (o.unmount && o.unmount(e), (i = e.ref) && (i.current && i.current !== e.__e || j(i, null, t)), null != (i = e.__c)) {
                            if (i.componentWillUnmount) try {
                                i.componentWillUnmount()
                            } catch (e) {
                                o.__e(e, t)
                            }
                            i.base = i.__P = null
                        }
                        if (i = e.__k)
                            for (r = 0; r < i.length; r++) i[r] && L(i[r], t, "function" != typeof e.type);
                        n || null == e.__e || f(e.__e), e.__e = e.__d = void 0
                    }

                    function F(e, t, n) {
                        return this.constructor(e, n)
                    }

                    function H(e, t, n) {
                        var r, a, s;
                        o.__ && o.__(e, t), a = (r = "function" == typeof n) ? null : n && n.__k || t.__k, s = [], R(t, e = (!r && n || t).__k = g(b, null, [e]), a || d, d, void 0 !== t.ownerSVGElement, !r && n ? [n] : a ? null : t.firstChild ? i.call(t.childNodes) : null, s, !r && n ? n : a ? a.__e : t.firstChild, r), P(s, e)
                    }

                    function B(e, t) {
                        H(e, t, B)
                    }

                    function N(e, t, n) {
                        var o, r, a, s = h({}, e.props);
                        for (a in t) "key" == a ? o = t[a] : "ref" == a ? r = t[a] : s[a] = t[a];
                        return arguments.length > 2 && (s.children = arguments.length > 3 ? i.call(arguments, 2) : n), m(e.type, s, o || e.key, r || e.ref, null)
                    }

                    function U(e, t) {
                        var n = {
                            __c: t = "__cC" + c++,
                            __: e,
                            Consumer: function(e, t) {
                                return e.children(t)
                            },
                            Provider: function(e) {
                                var n, i;
                                return this.getChildContext || (n = [], (i = {})[t] = this, this.getChildContext = function() {
                                    return i
                                }, this.shouldComponentUpdate = function(e) {
                                    this.props.value !== e.value && n.some(_)
                                }, this.sub = function(e) {
                                    n.push(e);
                                    var t = e.componentWillUnmount;
                                    e.componentWillUnmount = function() {
                                        n.splice(n.indexOf(e), 1), t && t.call(e)
                                    }
                                }), e.children
                            }
                        };
                        return n.Provider.__ = n.Consumer.contextType = n
                    }
                    i = u.slice, o = {
                        __e: function(e, t) {
                            for (var n, i, o; t = t.__;)
                                if ((n = t.__c) && !n.__) try {
                                    if ((i = n.constructor) && null != i.getDerivedStateFromError && (n.setState(i.getDerivedStateFromError(e)), o = n.__d), null != n.componentDidCatch && (n.componentDidCatch(e), o = n.__d), o) return n.__E = n
                                } catch (t) {
                                    e = t
                                }
                            throw e
                        }
                    }, r = 0, x.prototype.setState = function(e, t) {
                        var n;
                        n = null != this.__s && this.__s !== this.state ? this.__s : this.__s = h({}, this.state), "function" == typeof e && (e = e(h({}, n), this.props)), e && h(n, e), null != e && this.__v && (t && this.__h.push(t), _(this))
                    }, x.prototype.forceUpdate = function(e) {
                        this.__v && (this.__e = !0, e && this.__h.push(e), _(this))
                    }, x.prototype.render = b, a = [], s = "function" == typeof Promise ? Promise.prototype.then.bind(Promise.resolve()) : setTimeout, k.__r = 0, c = 0
                },
                396: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        I4: () => _,
                        Qb: () => C,
                        Ye: () => w,
                        _Y: () => m,
                        aP: () => v,
                        bt: () => b,
                        cO: () => S,
                        d4: () => y,
                        eJ: () => g,
                        qp: () => k,
                        sO: () => x
                    });
                    var i, o, r, a = n(6400),
                        s = 0,
                        l = [],
                        c = a.YM.__b,
                        d = a.YM.__r,
                        u = a.YM.diffed,
                        p = a.YM.__c,
                        h = a.YM.unmount;

                    function f(e, t) {
                        a.YM.__h && a.YM.__h(o, e, s || t), s = 0;
                        var n = o.__H || (o.__H = {
                            __: [],
                            __h: []
                        });
                        return e >= n.__.length && n.__.push({}), n.__[e]
                    }

                    function g(e) {
                        return s = 1, m(M, e)
                    }

                    function m(e, t, n) {
                        var r = f(i++, 2);
                        return r.t = e, r.__c || (r.__ = [n ? n(t) : M(void 0, t), function(e) {
                            var t = r.t(r.__[0], e);
                            r.__[0] !== t && (r.__ = [t, r.__[1]], r.__c.setState({}))
                        }], r.__c = o), r.__
                    }

                    function y(e, t) {
                        var n = f(i++, 3);
                        !a.YM.__s && T(n.__H, t) && (n.__ = e, n.__H = t, o.__H.__h.push(n))
                    }

                    function b(e, t) {
                        var n = f(i++, 4);
                        !a.YM.__s && T(n.__H, t) && (n.__ = e, n.__H = t, o.__h.push(n))
                    }

                    function x(e) {
                        return s = 5, w((function() {
                            return {
                                current: e
                            }
                        }), [])
                    }

                    function v(e, t, n) {
                        s = 6, b((function() {
                            "function" == typeof e ? e(t()) : e && (e.current = t())
                        }), null == n ? n : n.concat(e))
                    }

                    function w(e, t) {
                        var n = f(i++, 7);
                        return T(n.__H, t) && (n.__ = e(), n.__H = t, n.__h = e), n.__
                    }

                    function _(e, t) {
                        return s = 8, w((function() {
                            return e
                        }), t)
                    }

                    function k(e) {
                        var t = o.context[e.__c],
                            n = f(i++, 9);
                        return n.c = e, t ? (null == n.__ && (n.__ = !0, t.sub(o)), t.props.value) : e.__
                    }

                    function C(e, t) {
                        a.YM.useDebugValue && a.YM.useDebugValue(t ? t(e) : e)
                    }

                    function S(e) {
                        var t = f(i++, 10),
                            n = g();
                        return t.__ = e, o.componentDidCatch || (o.componentDidCatch = function(e) {
                            t.__ && t.__(e), n[1](e)
                        }), [n[0], function() {
                            n[1](void 0)
                        }]
                    }

                    function E() {
                        for (var e; e = l.shift();)
                            if (e.__P) try {
                                e.__H.__h.forEach(A), e.__H.__h.forEach(O), e.__H.__h = []
                            } catch (t) {
                                e.__H.__h = [], a.YM.__e(t, e.__v)
                            }
                    }
                    a.YM.__b = function(e) {
                        o = null, c && c(e)
                    }, a.YM.__r = function(e) {
                        d && d(e), i = 0;
                        var t = (o = e.__c).__H;
                        t && (t.__h.forEach(A), t.__h.forEach(O), t.__h = [])
                    }, a.YM.diffed = function(e) {
                        u && u(e);
                        var t = e.__c;
                        t && t.__H && t.__H.__h.length && (1 !== l.push(t) && r === a.YM.requestAnimationFrame || ((r = a.YM.requestAnimationFrame) || function(e) {
                            var t, n = function() {
                                    clearTimeout(i), I && cancelAnimationFrame(t), setTimeout(e)
                                },
                                i = setTimeout(n, 100);
                            I && (t = requestAnimationFrame(n))
                        })(E)), o = null
                    }, a.YM.__c = function(e, t) {
                        t.some((function(e) {
                            try {
                                e.__h.forEach(A), e.__h = e.__h.filter((function(e) {
                                    return !e.__ || O(e)
                                }))
                            } catch (n) {
                                t.some((function(e) {
                                    e.__h && (e.__h = [])
                                })), t = [], a.YM.__e(n, e.__v)
                            }
                        })), p && p(e, t)
                    }, a.YM.unmount = function(e) {
                        h && h(e);
                        var t, n = e.__c;
                        n && n.__H && (n.__H.__.forEach((function(e) {
                            try {
                                A(e)
                            } catch (e) {
                                t = e
                            }
                        })), t && a.YM.__e(t, n.__v))
                    };
                    var I = "function" == typeof requestAnimationFrame;

                    function A(e) {
                        var t = o,
                            n = e.__c;
                        "function" == typeof n && (e.__c = void 0, n()), o = t
                    }

                    function O(e) {
                        var t = o;
                        e.__c = e.__(), o = t
                    }

                    function T(e, t) {
                        return !e || e.length !== t.length || t.some((function(t, n) {
                            return t !== e[n]
                        }))
                    }

                    function M(e, t) {
                        return "function" == typeof t ? t(e) : t
                    }
                },
                2100: (e, t, n) => {
                    "use strict";
                    e.exports = n(9482)
                },
                9482: (e, t, n) => {
                    "use strict";
                    var i = t;

                    function o() {
                        i.util._configure(), i.Writer._configure(i.BufferWriter), i.Reader._configure(i.BufferReader)
                    }
                    i.build = "minimal", i.Writer = n(1173), i.BufferWriter = n(3155), i.Reader = n(1408), i.BufferReader = n(593), i.util = n(9693), i.rpc = n(5994), i.roots = n(5350), i.configure = o, o()
                },
                1408: (e, t, n) => {
                    "use strict";
                    e.exports = l;
                    var i, o = n(9693),
                        r = o.LongBits,
                        a = o.utf8;

                    function s(e, t) {
                        return RangeError("index out of range: " + e.pos + " + " + (t || 1) + " > " + e.len)
                    }

                    function l(e) {
                        this.buf = e, this.pos = 0, this.len = e.length
                    }
                    var c, d = "undefined" != typeof Uint8Array ? function(e) {
                            if (e instanceof Uint8Array || Array.isArray(e)) return new l(e);
                            throw Error("illegal buffer")
                        } : function(e) {
                            if (Array.isArray(e)) return new l(e);
                            throw Error("illegal buffer")
                        },
                        u = function() {
                            return o.Buffer ? function(e) {
                                return (l.create = function(e) {
                                    return o.Buffer.isBuffer(e) ? new i(e) : d(e)
                                })(e)
                            } : d
                        };

                    function p() {
                        var e = new r(0, 0),
                            t = 0;
                        if (!(this.len - this.pos > 4)) {
                            for (; t < 3; ++t) {
                                if (this.pos >= this.len) throw s(this);
                                if (e.lo = (e.lo | (127 & this.buf[this.pos]) << 7 * t) >>> 0, this.buf[this.pos++] < 128) return e
                            }
                            return e.lo = (e.lo | (127 & this.buf[this.pos++]) << 7 * t) >>> 0, e
                        }
                        for (; t < 4; ++t)
                            if (e.lo = (e.lo | (127 & this.buf[this.pos]) << 7 * t) >>> 0, this.buf[this.pos++] < 128) return e;
                        if (e.lo = (e.lo | (127 & this.buf[this.pos]) << 28) >>> 0, e.hi = (e.hi | (127 & this.buf[this.pos]) >> 4) >>> 0, this.buf[this.pos++] < 128) return e;
                        if (t = 0, this.len - this.pos > 4) {
                            for (; t < 5; ++t)
                                if (e.hi = (e.hi | (127 & this.buf[this.pos]) << 7 * t + 3) >>> 0, this.buf[this.pos++] < 128) return e
                        } else
                            for (; t < 5; ++t) {
                                if (this.pos >= this.len) throw s(this);
                                if (e.hi = (e.hi | (127 & this.buf[this.pos]) << 7 * t + 3) >>> 0, this.buf[this.pos++] < 128) return e
                            }
                        throw Error("invalid varint encoding")
                    }

                    function h(e, t) {
                        return (e[t - 4] | e[t - 3] << 8 | e[t - 2] << 16 | e[t - 1] << 24) >>> 0
                    }

                    function f() {
                        if (this.pos + 8 > this.len) throw s(this, 8);
                        return new r(h(this.buf, this.pos += 4), h(this.buf, this.pos += 4))
                    }
                    l.create = u(), l.prototype._slice = o.Array.prototype.subarray || o.Array.prototype.slice, l.prototype.uint32 = (c = 4294967295, function() {
                        if (c = (127 & this.buf[this.pos]) >>> 0, this.buf[this.pos++] < 128) return c;
                        if (c = (c | (127 & this.buf[this.pos]) << 7) >>> 0, this.buf[this.pos++] < 128) return c;
                        if (c = (c | (127 & this.buf[this.pos]) << 14) >>> 0, this.buf[this.pos++] < 128) return c;
                        if (c = (c | (127 & this.buf[this.pos]) << 21) >>> 0, this.buf[this.pos++] < 128) return c;
                        if (c = (c | (15 & this.buf[this.pos]) << 28) >>> 0, this.buf[this.pos++] < 128) return c;
                        if ((this.pos += 5) > this.len) throw this.pos = this.len, s(this, 10);
                        return c
                    }), l.prototype.int32 = function() {
                        return 0 | this.uint32()
                    }, l.prototype.sint32 = function() {
                        var e = this.uint32();
                        return e >>> 1 ^ -(1 & e) | 0
                    }, l.prototype.bool = function() {
                        return 0 !== this.uint32()
                    }, l.prototype.fixed32 = function() {
                        if (this.pos + 4 > this.len) throw s(this, 4);
                        return h(this.buf, this.pos += 4)
                    }, l.prototype.sfixed32 = function() {
                        if (this.pos + 4 > this.len) throw s(this, 4);
                        return 0 | h(this.buf, this.pos += 4)
                    }, l.prototype.float = function() {
                        if (this.pos + 4 > this.len) throw s(this, 4);
                        var e = o.float.readFloatLE(this.buf, this.pos);
                        return this.pos += 4, e
                    }, l.prototype.double = function() {
                        if (this.pos + 8 > this.len) throw s(this, 4);
                        var e = o.float.readDoubleLE(this.buf, this.pos);
                        return this.pos += 8, e
                    }, l.prototype.bytes = function() {
                        var e = this.uint32(),
                            t = this.pos,
                            n = this.pos + e;
                        if (n > this.len) throw s(this, e);
                        return this.pos += e, Array.isArray(this.buf) ? this.buf.slice(t, n) : t === n ? new this.buf.constructor(0) : this._slice.call(this.buf, t, n)
                    }, l.prototype.string = function() {
                        var e = this.bytes();
                        return a.read(e, 0, e.length)
                    }, l.prototype.skip = function(e) {
                        if ("number" == typeof e) {
                            if (this.pos + e > this.len) throw s(this, e);
                            this.pos += e
                        } else
                            do {
                                if (this.pos >= this.len) throw s(this)
                            } while (128 & this.buf[this.pos++]);
                        return this
                    }, l.prototype.skipType = function(e) {
                        switch (e) {
                            case 0:
                                this.skip();
                                break;
                            case 1:
                                this.skip(8);
                                break;
                            case 2:
                                this.skip(this.uint32());
                                break;
                            case 3:
                                for (; 4 != (e = 7 & this.uint32());) this.skipType(e);
                                break;
                            case 5:
                                this.skip(4);
                                break;
                            default:
                                throw Error("invalid wire type " + e + " at offset " + this.pos)
                        }
                        return this
                    }, l._configure = function(e) {
                        i = e, l.create = u(), i._configure();
                        var t = o.Long ? "toLong" : "toNumber";
                        o.merge(l.prototype, {
                            int64: function() {
                                return p.call(this)[t](!1)
                            },
                            uint64: function() {
                                return p.call(this)[t](!0)
                            },
                            sint64: function() {
                                return p.call(this).zzDecode()[t](!1)
                            },
                            fixed64: function() {
                                return f.call(this)[t](!0)
                            },
                            sfixed64: function() {
                                return f.call(this)[t](!1)
                            }
                        })
                    }
                },
                593: (e, t, n) => {
                    "use strict";
                    e.exports = r;
                    var i = n(1408);
                    (r.prototype = Object.create(i.prototype)).constructor = r;
                    var o = n(9693);

                    function r(e) {
                        i.call(this, e)
                    }
                    r._configure = function() {
                        o.Buffer && (r.prototype._slice = o.Buffer.prototype.slice)
                    }, r.prototype.string = function() {
                        var e = this.uint32();
                        return this.buf.utf8Slice ? this.buf.utf8Slice(this.pos, this.pos = Math.min(this.pos + e, this.len)) : this.buf.toString("utf-8", this.pos, this.pos = Math.min(this.pos + e, this.len))
                    }, r._configure()
                },
                5350: e => {
                    "use strict";
                    e.exports = {}
                },
                5994: (e, t, n) => {
                    "use strict";
                    t.Service = n(7948)
                },
                7948: (e, t, n) => {
                    "use strict";
                    e.exports = o;
                    var i = n(9693);

                    function o(e, t, n) {
                        if ("function" != typeof e) throw TypeError("rpcImpl must be a function");
                        i.EventEmitter.call(this), this.rpcImpl = e, this.requestDelimited = Boolean(t), this.responseDelimited = Boolean(n)
                    }(o.prototype = Object.create(i.EventEmitter.prototype)).constructor = o, o.prototype.rpcCall = function e(t, n, o, r, a) {
                        if (!r) throw TypeError("request must be specified");
                        var s = this;
                        if (!a) return i.asPromise(e, s, t, n, o, r);
                        if (s.rpcImpl) try {
                            return s.rpcImpl(t, n[s.requestDelimited ? "encodeDelimited" : "encode"](r).finish(), (function(e, n) {
                                if (e) return s.emit("error", e, t), a(e);
                                if (null !== n) {
                                    if (!(n instanceof o)) try {
                                        n = o[s.responseDelimited ? "decodeDelimited" : "decode"](n)
                                    } catch (e) {
                                        return s.emit("error", e, t), a(e)
                                    }
                                    return s.emit("data", n, t), a(null, n)
                                }
                                s.end(!0)
                            }))
                        } catch (e) {
                            return s.emit("error", e, t), void setTimeout((function() {
                                a(e)
                            }), 0)
                        } else setTimeout((function() {
                            a(Error("already ended"))
                        }), 0)
                    }, o.prototype.end = function(e) {
                        return this.rpcImpl && (e || this.rpcImpl(null, null, null), this.rpcImpl = null, this.emit("end").off()), this
                    }
                },
                1945: (e, t, n) => {
                    "use strict";
                    e.exports = o;
                    var i = n(9693);

                    function o(e, t) {
                        this.lo = e >>> 0, this.hi = t >>> 0
                    }
                    var r = o.zero = new o(0, 0);
                    r.toNumber = function() {
                        return 0
                    }, r.zzEncode = r.zzDecode = function() {
                        return this
                    }, r.length = function() {
                        return 1
                    };
                    var a = o.zeroHash = "\0\0\0\0\0\0\0\0";
                    o.fromNumber = function(e) {
                        if (0 === e) return r;
                        var t = e < 0;
                        t && (e = -e);
                        var n = e >>> 0,
                            i = (e - n) / 4294967296 >>> 0;
                        return t && (i = ~i >>> 0, n = ~n >>> 0, ++n > 4294967295 && (n = 0, ++i > 4294967295 && (i = 0))), new o(n, i)
                    }, o.from = function(e) {
                        if ("number" == typeof e) return o.fromNumber(e);
                        if (i.isString(e)) {
                            if (!i.Long) return o.fromNumber(parseInt(e, 10));
                            e = i.Long.fromString(e)
                        }
                        return e.low || e.high ? new o(e.low >>> 0, e.high >>> 0) : r
                    }, o.prototype.toNumber = function(e) {
                        if (!e && this.hi >>> 31) {
                            var t = 1 + ~this.lo >>> 0,
                                n = ~this.hi >>> 0;
                            return t || (n = n + 1 >>> 0), -(t + 4294967296 * n)
                        }
                        return this.lo + 4294967296 * this.hi
                    }, o.prototype.toLong = function(e) {
                        return i.Long ? new i.Long(0 | this.lo, 0 | this.hi, Boolean(e)) : {
                            low: 0 | this.lo,
                            high: 0 | this.hi,
                            unsigned: Boolean(e)
                        }
                    };
                    var s = String.prototype.charCodeAt;
                    o.fromHash = function(e) {
                        return e === a ? r : new o((s.call(e, 0) | s.call(e, 1) << 8 | s.call(e, 2) << 16 | s.call(e, 3) << 24) >>> 0, (s.call(e, 4) | s.call(e, 5) << 8 | s.call(e, 6) << 16 | s.call(e, 7) << 24) >>> 0)
                    }, o.prototype.toHash = function() {
                        return String.fromCharCode(255 & this.lo, this.lo >>> 8 & 255, this.lo >>> 16 & 255, this.lo >>> 24, 255 & this.hi, this.hi >>> 8 & 255, this.hi >>> 16 & 255, this.hi >>> 24)
                    }, o.prototype.zzEncode = function() {
                        var e = this.hi >> 31;
                        return this.hi = ((this.hi << 1 | this.lo >>> 31) ^ e) >>> 0, this.lo = (this.lo << 1 ^ e) >>> 0, this
                    }, o.prototype.zzDecode = function() {
                        var e = -(1 & this.lo);
                        return this.lo = ((this.lo >>> 1 | this.hi << 31) ^ e) >>> 0, this.hi = (this.hi >>> 1 ^ e) >>> 0, this
                    }, o.prototype.length = function() {
                        var e = this.lo,
                            t = (this.lo >>> 28 | this.hi << 4) >>> 0,
                            n = this.hi >>> 24;
                        return 0 === n ? 0 === t ? e < 16384 ? e < 128 ? 1 : 2 : e < 2097152 ? 3 : 4 : t < 16384 ? t < 128 ? 5 : 6 : t < 2097152 ? 7 : 8 : n < 128 ? 9 : 10
                    }
                },
                9693: function(e, t, n) {
                    "use strict";
                    var i = t;

                    function o(e, t, n) {
                        for (var i = Object.keys(t), o = 0; o < i.length; ++o) void 0 !== e[i[o]] && n || (e[i[o]] = t[i[o]]);
                        return e
                    }

                    function r(e) {
                        function t(e, n) {
                            if (!(this instanceof t)) return new t(e, n);
                            Object.defineProperty(this, "message", {
                                get: function() {
                                    return e
                                }
                            }), Error.captureStackTrace ? Error.captureStackTrace(this, t) : Object.defineProperty(this, "stack", {
                                value: (new Error).stack || ""
                            }), n && o(this, n)
                        }
                        return (t.prototype = Object.create(Error.prototype)).constructor = t, Object.defineProperty(t.prototype, "name", {
                            get: function() {
                                return e
                            }
                        }), t.prototype.toString = function() {
                            return this.name + ": " + this.message
                        }, t
                    }
                    i.asPromise = n(4537), i.base64 = n(7419), i.EventEmitter = n(9211), i.float = n(945), i.inquire = n(7199), i.utf8 = n(4997), i.pool = n(6662), i.LongBits = n(1945), i.isNode = Boolean(void 0 !== n.g && n.g && n.g.process && n.g.process.versions && n.g.process.versions.node), i.global = i.isNode && n.g || "undefined" != typeof window && window || "undefined" != typeof self && self || this, i.emptyArray = Object.freeze ? Object.freeze([]) : [], i.emptyObject = Object.freeze ? Object.freeze({}) : {}, i.isInteger = Number.isInteger || function(e) {
                        return "number" == typeof e && isFinite(e) && Math.floor(e) === e
                    }, i.isString = function(e) {
                        return "string" == typeof e || e instanceof String
                    }, i.isObject = function(e) {
                        return e && "object" == typeof e
                    }, i.isset = i.isSet = function(e, t) {
                        var n = e[t];
                        return !(null == n || !e.hasOwnProperty(t)) && ("object" != typeof n || (Array.isArray(n) ? n.length : Object.keys(n).length) > 0)
                    }, i.Buffer = function() {
                        try {
                            var e = i.inquire("buffer").Buffer;
                            return e.prototype.utf8Write ? e : null
                        } catch (e) {
                            return null
                        }
                    }(), i._Buffer_from = null, i._Buffer_allocUnsafe = null, i.newBuffer = function(e) {
                        return "number" == typeof e ? i.Buffer ? i._Buffer_allocUnsafe(e) : new i.Array(e) : i.Buffer ? i._Buffer_from(e) : "undefined" == typeof Uint8Array ? e : new Uint8Array(e)
                    }, i.Array = "undefined" != typeof Uint8Array ? Uint8Array : Array, i.Long = i.global.dcodeIO && i.global.dcodeIO.Long || i.global.Long || i.inquire("long"), i.key2Re = /^true|false|0|1$/, i.key32Re = /^-?(?:0|[1-9][0-9]*)$/, i.key64Re = /^(?:[\\x00-\\xff]{8}|-?(?:0|[1-9][0-9]*))$/, i.longToHash = function(e) {
                        return e ? i.LongBits.from(e).toHash() : i.LongBits.zeroHash
                    }, i.longFromHash = function(e, t) {
                        var n = i.LongBits.fromHash(e);
                        return i.Long ? i.Long.fromBits(n.lo, n.hi, t) : n.toNumber(Boolean(t))
                    }, i.merge = o, i.lcFirst = function(e) {
                        return e.charAt(0).toLowerCase() + e.substring(1)
                    }, i.newError = r, i.ProtocolError = r("ProtocolError"), i.oneOfGetter = function(e) {
                        for (var t = {}, n = 0; n < e.length; ++n) t[e[n]] = 1;
                        return function() {
                            for (var e = Object.keys(this), n = e.length - 1; n > -1; --n)
                                if (1 === t[e[n]] && void 0 !== this[e[n]] && null !== this[e[n]]) return e[n]
                        }
                    }, i.oneOfSetter = function(e) {
                        return function(t) {
                            for (var n = 0; n < e.length; ++n) e[n] !== t && delete this[e[n]]
                        }
                    }, i.toJSONOptions = {
                        longs: String,
                        enums: String,
                        bytes: String,
                        json: !0
                    }, i._configure = function() {
                        var e = i.Buffer;
                        e ? (i._Buffer_from = e.from !== Uint8Array.from && e.from || function(t, n) {
                            return new e(t, n)
                        }, i._Buffer_allocUnsafe = e.allocUnsafe || function(t) {
                            return new e(t)
                        }) : i._Buffer_from = i._Buffer_allocUnsafe = null
                    }
                },
                1173: (e, t, n) => {
                    "use strict";
                    e.exports = u;
                    var i, o = n(9693),
                        r = o.LongBits,
                        a = o.base64,
                        s = o.utf8;

                    function l(e, t, n) {
                        this.fn = e, this.len = t, this.next = void 0, this.val = n
                    }

                    function c() {}

                    function d(e) {
                        this.head = e.head, this.tail = e.tail, this.len = e.len, this.next = e.states
                    }

                    function u() {
                        this.len = 0, this.head = new l(c, 0, 0), this.tail = this.head, this.states = null
                    }
                    var p = function() {
                        return o.Buffer ? function() {
                            return (u.create = function() {
                                return new i
                            })()
                        } : function() {
                            return new u
                        }
                    };

                    function h(e, t, n) {
                        t[n] = 255 & e
                    }

                    function f(e, t) {
                        this.len = e, this.next = void 0, this.val = t
                    }

                    function g(e, t, n) {
                        for (; e.hi;) t[n++] = 127 & e.lo | 128, e.lo = (e.lo >>> 7 | e.hi << 25) >>> 0, e.hi >>>= 7;
                        for (; e.lo > 127;) t[n++] = 127 & e.lo | 128, e.lo = e.lo >>> 7;
                        t[n++] = e.lo
                    }

                    function m(e, t, n) {
                        t[n] = 255 & e, t[n + 1] = e >>> 8 & 255, t[n + 2] = e >>> 16 & 255, t[n + 3] = e >>> 24
                    }
                    u.create = p(), u.alloc = function(e) {
                        return new o.Array(e)
                    }, o.Array !== Array && (u.alloc = o.pool(u.alloc, o.Array.prototype.subarray)), u.prototype._push = function(e, t, n) {
                        return this.tail = this.tail.next = new l(e, t, n), this.len += t, this
                    }, f.prototype = Object.create(l.prototype), f.prototype.fn = function(e, t, n) {
                        for (; e > 127;) t[n++] = 127 & e | 128, e >>>= 7;
                        t[n] = e
                    }, u.prototype.uint32 = function(e) {
                        return this.len += (this.tail = this.tail.next = new f((e >>>= 0) < 128 ? 1 : e < 16384 ? 2 : e < 2097152 ? 3 : e < 268435456 ? 4 : 5, e)).len, this
                    }, u.prototype.int32 = function(e) {
                        return e < 0 ? this._push(g, 10, r.fromNumber(e)) : this.uint32(e)
                    }, u.prototype.sint32 = function(e) {
                        return this.uint32((e << 1 ^ e >> 31) >>> 0)
                    }, u.prototype.uint64 = function(e) {
                        var t = r.from(e);
                        return this._push(g, t.length(), t)
                    }, u.prototype.int64 = u.prototype.uint64, u.prototype.sint64 = function(e) {
                        var t = r.from(e).zzEncode();
                        return this._push(g, t.length(), t)
                    }, u.prototype.bool = function(e) {
                        return this._push(h, 1, e ? 1 : 0)
                    }, u.prototype.fixed32 = function(e) {
                        return this._push(m, 4, e >>> 0)
                    }, u.prototype.sfixed32 = u.prototype.fixed32, u.prototype.fixed64 = function(e) {
                        var t = r.from(e);
                        return this._push(m, 4, t.lo)._push(m, 4, t.hi)
                    }, u.prototype.sfixed64 = u.prototype.fixed64, u.prototype.float = function(e) {
                        return this._push(o.float.writeFloatLE, 4, e)
                    }, u.prototype.double = function(e) {
                        return this._push(o.float.writeDoubleLE, 8, e)
                    };
                    var y = o.Array.prototype.set ? function(e, t, n) {
                        t.set(e, n)
                    } : function(e, t, n) {
                        for (var i = 0; i < e.length; ++i) t[n + i] = e[i]
                    };
                    u.prototype.bytes = function(e) {
                        var t = e.length >>> 0;
                        if (!t) return this._push(h, 1, 0);
                        if (o.isString(e)) {
                            var n = u.alloc(t = a.length(e));
                            a.decode(e, n, 0), e = n
                        }
                        return this.uint32(t)._push(y, t, e)
                    }, u.prototype.string = function(e) {
                        var t = s.length(e);
                        return t ? this.uint32(t)._push(s.write, t, e) : this._push(h, 1, 0)
                    }, u.prototype.fork = function() {
                        return this.states = new d(this), this.head = this.tail = new l(c, 0, 0), this.len = 0, this
                    }, u.prototype.reset = function() {
                        return this.states ? (this.head = this.states.head, this.tail = this.states.tail, this.len = this.states.len, this.states = this.states.next) : (this.head = this.tail = new l(c, 0, 0), this.len = 0), this
                    }, u.prototype.ldelim = function() {
                        var e = this.head,
                            t = this.tail,
                            n = this.len;
                        return this.reset().uint32(n), n && (this.tail.next = e.next, this.tail = t, this.len += n), this
                    }, u.prototype.finish = function() {
                        for (var e = this.head.next, t = this.constructor.alloc(this.len), n = 0; e;) e.fn(e.val, t, n), n += e.len, e = e.next;
                        return t
                    }, u._configure = function(e) {
                        i = e, u.create = p(), i._configure()
                    }
                },
                3155: (e, t, n) => {
                    "use strict";
                    e.exports = r;
                    var i = n(1173);
                    (r.prototype = Object.create(i.prototype)).constructor = r;
                    var o = n(9693);

                    function r() {
                        i.call(this)
                    }

                    function a(e, t, n) {
                        e.length < 40 ? o.utf8.write(e, t, n) : t.utf8Write ? t.utf8Write(e, n) : t.write(e, n)
                    }
                    r._configure = function() {
                        r.alloc = o._Buffer_allocUnsafe, r.writeBytesBuffer = o.Buffer && o.Buffer.prototype instanceof Uint8Array && "set" === o.Buffer.prototype.set.name ? function(e, t, n) {
                            t.set(e, n)
                        } : function(e, t, n) {
                            if (e.copy) e.copy(t, n, 0, e.length);
                            else
                                for (var i = 0; i < e.length;) t[n++] = e[i++]
                        }
                    }, r.prototype.bytes = function(e) {
                        o.isString(e) && (e = o._Buffer_from(e, "base64"));
                        var t = e.length >>> 0;
                        return this.uint32(t), t && this._push(r.writeBytesBuffer, t, e), this
                    }, r.prototype.string = function(e) {
                        var t = o.Buffer.byteLength(e);
                        return this.uint32(t), t && this._push(a, t, e), this
                    }, r._configure()
                },
                8660: (e, t, n) => {
                    var i;
                    ! function(e) {
                        ! function(t) {
                            var i = "object" == typeof n.g ? n.g : "object" == typeof self ? self : "object" == typeof this ? this : Function("return this;")(),
                                o = r(e);

                            function r(e, t) {
                                return function(n, i) {
                                    "function" != typeof e[n] && Object.defineProperty(e, n, {
                                        configurable: !0,
                                        writable: !0,
                                        value: i
                                    }), t && t(n, i)
                                }
                            }
                            void 0 === i.Reflect ? i.Reflect = e : o = r(i.Reflect, o),
                                function(e) {
                                    var t = Object.prototype.hasOwnProperty,
                                        n = "function" == typeof Symbol,
                                        i = n && void 0 !== Symbol.toPrimitive ? Symbol.toPrimitive : "@@toPrimitive",
                                        o = n && void 0 !== Symbol.iterator ? Symbol.iterator : "@@iterator",
                                        r = "function" == typeof Object.create,
                                        a = {
                                            __proto__: []
                                        }
                                    instanceof Array, s = !r && !a, l = {
                                        create: r ? function() {
                                            return j(Object.create(null))
                                        } : a ? function() {
                                            return j({
                                                __proto__: null
                                            })
                                        } : function() {
                                            return j({})
                                        },
                                        has: s ? function(e, n) {
                                            return t.call(e, n)
                                        } : function(e, t) {
                                            return t in e
                                        },
                                        get: s ? function(e, n) {
                                            return t.call(e, n) ? e[n] : void 0
                                        } : function(e, t) {
                                            return e[t]
                                        }
                                    }, c = Object.getPrototypeOf(Function), d = "object" == typeof process && process.env && "true" === process.env.REFLECT_METADATA_USE_MAP_POLYFILL, u = d || "function" != typeof Map || "function" != typeof Map.prototype.entries ? function() {
                                        var e = {},
                                            t = [],
                                            n = function() {
                                                function e(e, t, n) {
                                                    this._index = 0, this._keys = e, this._values = t, this._selector = n
                                                }
                                                return e.prototype["@@iterator"] = function() {
                                                    return this
                                                }, e.prototype[o] = function() {
                                                    return this
                                                }, e.prototype.next = function() {
                                                    var e = this._index;
                                                    if (e >= 0 && e < this._keys.length) {
                                                        var n = this._selector(this._keys[e], this._values[e]);
                                                        return e + 1 >= this._keys.length ? (this._index = -1, this._keys = t, this._values = t) : this._index++, {
                                                            value: n,
                                                            done: !1
                                                        }
                                                    }
                                                    return {
                                                        value: void 0,
                                                        done: !0
                                                    }
                                                }, e.prototype.throw = function(e) {
                                                    throw this._index >= 0 && (this._index = -1, this._keys = t, this._values = t), e
                                                }, e.prototype.return = function(e) {
                                                    return this._index >= 0 && (this._index = -1, this._keys = t, this._values = t), {
                                                        value: e,
                                                        done: !0
                                                    }
                                                }, e
                                            }();
                                        return function() {
                                            function t() {
                                                this._keys = [], this._values = [], this._cacheKey = e, this._cacheIndex = -2
                                            }
                                            return Object.defineProperty(t.prototype, "size", {
                                                get: function() {
                                                    return this._keys.length
                                                },
                                                enumerable: !0,
                                                configurable: !0
                                            }), t.prototype.has = function(e) {
                                                return this._find(e, !1) >= 0
                                            }, t.prototype.get = function(e) {
                                                var t = this._find(e, !1);
                                                return t >= 0 ? this._values[t] : void 0
                                            }, t.prototype.set = function(e, t) {
                                                var n = this._find(e, !0);
                                                return this._values[n] = t, this
                                            }, t.prototype.delete = function(t) {
                                                var n = this._find(t, !1);
                                                if (n >= 0) {
                                                    for (var i = this._keys.length, o = n + 1; o < i; o++) this._keys[o - 1] = this._keys[o], this._values[o - 1] = this._values[o];
                                                    return this._keys.length--, this._values.length--, t === this._cacheKey && (this._cacheKey = e, this._cacheIndex = -2), !0
                                                }
                                                return !1
                                            }, t.prototype.clear = function() {
                                                this._keys.length = 0, this._values.length = 0, this._cacheKey = e, this._cacheIndex = -2
                                            }, t.prototype.keys = function() {
                                                return new n(this._keys, this._values, i)
                                            }, t.prototype.values = function() {
                                                return new n(this._keys, this._values, r)
                                            }, t.prototype.entries = function() {
                                                return new n(this._keys, this._values, a)
                                            }, t.prototype["@@iterator"] = function() {
                                                return this.entries()
                                            }, t.prototype[o] = function() {
                                                return this.entries()
                                            }, t.prototype._find = function(e, t) {
                                                return this._cacheKey !== e && (this._cacheIndex = this._keys.indexOf(this._cacheKey = e)), this._cacheIndex < 0 && t && (this._cacheIndex = this._keys.length, this._keys.push(e), this._values.push(void 0)), this._cacheIndex
                                            }, t
                                        }();

                                        function i(e, t) {
                                            return e
                                        }

                                        function r(e, t) {
                                            return t
                                        }

                                        function a(e, t) {
                                            return [e, t]
                                        }
                                    }() : Map, p = d || "function" != typeof Set || "function" != typeof Set.prototype.entries ? function() {
                                        function e() {
                                            this._map = new u
                                        }
                                        return Object.defineProperty(e.prototype, "size", {
                                            get: function() {
                                                return this._map.size
                                            },
                                            enumerable: !0,
                                            configurable: !0
                                        }), e.prototype.has = function(e) {
                                            return this._map.has(e)
                                        }, e.prototype.add = function(e) {
                                            return this._map.set(e, e), this
                                        }, e.prototype.delete = function(e) {
                                            return this._map.delete(e)
                                        }, e.prototype.clear = function() {
                                            this._map.clear()
                                        }, e.prototype.keys = function() {
                                            return this._map.keys()
                                        }, e.prototype.values = function() {
                                            return this._map.values()
                                        }, e.prototype.entries = function() {
                                            return this._map.entries()
                                        }, e.prototype["@@iterator"] = function() {
                                            return this.keys()
                                        }, e.prototype[o] = function() {
                                            return this.keys()
                                        }, e
                                    }() : Set, h = new(d || "function" != typeof WeakMap ? function() {
                                        var e = l.create(),
                                            n = i();
                                        return function() {
                                            function e() {
                                                this._key = i()
                                            }
                                            return e.prototype.has = function(e) {
                                                var t = o(e, !1);
                                                return void 0 !== t && l.has(t, this._key)
                                            }, e.prototype.get = function(e) {
                                                var t = o(e, !1);
                                                return void 0 !== t ? l.get(t, this._key) : void 0
                                            }, e.prototype.set = function(e, t) {
                                                return o(e, !0)[this._key] = t, this
                                            }, e.prototype.delete = function(e) {
                                                var t = o(e, !1);
                                                return void 0 !== t && delete t[this._key]
                                            }, e.prototype.clear = function() {
                                                this._key = i()
                                            }, e
                                        }();

                                        function i() {
                                            var t;
                                            do {
                                                t = "@@WeakMap@@" + a()
                                            } while (l.has(e, t));
                                            return e[t] = !0, t
                                        }

                                        function o(e, i) {
                                            if (!t.call(e, n)) {
                                                if (!i) return;
                                                Object.defineProperty(e, n, {
                                                    value: l.create()
                                                })
                                            }
                                            return e[n]
                                        }

                                        function r(e, t) {
                                            for (var n = 0; n < t; ++n) e[n] = 255 * Math.random() | 0;
                                            return e
                                        }

                                        function a() {
                                            var e, t = (e = 16, "function" == typeof Uint8Array ? "undefined" != typeof crypto ? crypto.getRandomValues(new Uint8Array(e)) : "undefined" != typeof msCrypto ? msCrypto.getRandomValues(new Uint8Array(e)) : r(new Uint8Array(e), e) : r(new Array(e), e));
                                            t[6] = 79 & t[6] | 64, t[8] = 191 & t[8] | 128;
                                            for (var n = "", i = 0; i < 16; ++i) {
                                                var o = t[i];
                                                4 !== i && 6 !== i && 8 !== i || (n += "-"), o < 16 && (n += "0"), n += o.toString(16).toLowerCase()
                                            }
                                            return n
                                        }
                                    }() : WeakMap);

                                    function f(e, t, n) {
                                        var i = h.get(e);
                                        if (k(i)) {
                                            if (!n) return;
                                            i = new u, h.set(e, i)
                                        }
                                        var o = i.get(t);
                                        if (k(o)) {
                                            if (!n) return;
                                            o = new u, i.set(t, o)
                                        }
                                        return o
                                    }

                                    function g(e, t, n) {
                                        if (m(e, t, n)) return !0;
                                        var i = D(t);
                                        return !C(i) && g(e, i, n)
                                    }

                                    function m(e, t, n) {
                                        var i = f(t, n, !1);
                                        return !k(i) && !!i.has(e)
                                    }

                                    function y(e, t, n) {
                                        if (m(e, t, n)) return b(e, t, n);
                                        var i = D(t);
                                        return C(i) ? void 0 : y(e, i, n)
                                    }

                                    function b(e, t, n) {
                                        var i = f(t, n, !1);
                                        if (!k(i)) return i.get(e)
                                    }

                                    function x(e, t, n, i) {
                                        f(n, i, !0).set(e, t)
                                    }

                                    function v(e, t) {
                                        var n = w(e, t),
                                            i = D(e);
                                        if (null === i) return n;
                                        var o = v(i, t);
                                        if (o.length <= 0) return n;
                                        if (n.length <= 0) return o;
                                        for (var r = new p, a = [], s = 0, l = n; s < l.length; s++) {
                                            var c = l[s];
                                            r.has(c) || (r.add(c), a.push(c))
                                        }
                                        for (var d = 0, u = o; d < u.length; d++) c = u[d], r.has(c) || (r.add(c), a.push(c));
                                        return a
                                    }

                                    function w(e, t) {
                                        var n = [],
                                            i = f(e, t, !1);
                                        if (k(i)) return n;
                                        for (var r = function(e) {
                                                var t = M(e, o);
                                                if (!O(t)) throw new TypeError;
                                                var n = t.call(e);
                                                if (!S(n)) throw new TypeError;
                                                return n
                                            }(i.keys()), a = 0;;) {
                                            var s = R(r);
                                            if (!s) return n.length = a, n;
                                            var l = s.value;
                                            try {
                                                n[a] = l
                                            } catch (e) {
                                                try {
                                                    P(r)
                                                } finally {
                                                    throw e
                                                }
                                            }
                                            a++
                                        }
                                    }

                                    function _(e) {
                                        if (null === e) return 1;
                                        switch (typeof e) {
                                            case "undefined":
                                                return 0;
                                            case "boolean":
                                                return 2;
                                            case "string":
                                                return 3;
                                            case "symbol":
                                                return 4;
                                            case "number":
                                                return 5;
                                            case "object":
                                                return null === e ? 1 : 6;
                                            default:
                                                return 6
                                        }
                                    }

                                    function k(e) {
                                        return void 0 === e
                                    }

                                    function C(e) {
                                        return null === e
                                    }

                                    function S(e) {
                                        return "object" == typeof e ? null !== e : "function" == typeof e
                                    }

                                    function E(e, t) {
                                        switch (_(e)) {
                                            case 0:
                                            case 1:
                                            case 2:
                                            case 3:
                                            case 4:
                                            case 5:
                                                return e
                                        }
                                        var n = 3 === t ? "string" : 5 === t ? "number" : "default",
                                            o = M(e, i);
                                        if (void 0 !== o) {
                                            var r = o.call(e, n);
                                            if (S(r)) throw new TypeError;
                                            return r
                                        }
                                        return function(e, t) {
                                            if ("string" === t) {
                                                var n = e.toString;
                                                if (O(n) && !S(o = n.call(e))) return o;
                                                if (O(i = e.valueOf) && !S(o = i.call(e))) return o
                                            } else {
                                                var i;
                                                if (O(i = e.valueOf) && !S(o = i.call(e))) return o;
                                                var o, r = e.toString;
                                                if (O(r) && !S(o = r.call(e))) return o
                                            }
                                            throw new TypeError
                                        }(e, "default" === n ? "number" : n)
                                    }

                                    function I(e) {
                                        var t = E(e, 3);
                                        return "symbol" == typeof t ? t : function(e) {
                                            return "" + e
                                        }(t)
                                    }

                                    function A(e) {
                                        return Array.isArray ? Array.isArray(e) : e instanceof Object ? e instanceof Array : "[object Array]" === Object.prototype.toString.call(e)
                                    }

                                    function O(e) {
                                        return "function" == typeof e
                                    }

                                    function T(e) {
                                        return "function" == typeof e
                                    }

                                    function M(e, t) {
                                        var n = e[t];
                                        if (null != n) {
                                            if (!O(n)) throw new TypeError;
                                            return n
                                        }
                                    }

                                    function R(e) {
                                        var t = e.next();
                                        return !t.done && t
                                    }

                                    function P(e) {
                                        var t = e.return;
                                        t && t.call(e)
                                    }

                                    function D(e) {
                                        var t = Object.getPrototypeOf(e);
                                        if ("function" != typeof e || e === c) return t;
                                        if (t !== c) return t;
                                        var n = e.prototype,
                                            i = n && Object.getPrototypeOf(n);
                                        if (null == i || i === Object.prototype) return t;
                                        var o = i.constructor;
                                        return "function" != typeof o || o === e ? t : o
                                    }

                                    function j(e) {
                                        return e.__ = void 0, delete e.__, e
                                    }
                                    e("decorate", (function(e, t, n, i) {
                                        if (k(n)) {
                                            if (!A(e)) throw new TypeError;
                                            if (!T(t)) throw new TypeError;
                                            return function(e, t) {
                                                for (var n = e.length - 1; n >= 0; --n) {
                                                    var i = (0, e[n])(t);
                                                    if (!k(i) && !C(i)) {
                                                        if (!T(i)) throw new TypeError;
                                                        t = i
                                                    }
                                                }
                                                return t
                                            }(e, t)
                                        }
                                        if (!A(e)) throw new TypeError;
                                        if (!S(t)) throw new TypeError;
                                        if (!S(i) && !k(i) && !C(i)) throw new TypeError;
                                        return C(i) && (i = void 0),
                                            function(e, t, n, i) {
                                                for (var o = e.length - 1; o >= 0; --o) {
                                                    var r = (0, e[o])(t, n, i);
                                                    if (!k(r) && !C(r)) {
                                                        if (!S(r)) throw new TypeError;
                                                        i = r
                                                    }
                                                }
                                                return i
                                            }(e, t, n = I(n), i)
                                    })), e("metadata", (function(e, t) {
                                        return function(n, i) {
                                            if (!S(n)) throw new TypeError;
                                            if (!k(i) && ! function(e) {
                                                    switch (_(e)) {
                                                        case 3:
                                                        case 4:
                                                            return !0;
                                                        default:
                                                            return !1
                                                    }
                                                }(i)) throw new TypeError;
                                            x(e, t, n, i)
                                        }
                                    })), e("defineMetadata", (function(e, t, n, i) {
                                        if (!S(n)) throw new TypeError;
                                        return k(i) || (i = I(i)), x(e, t, n, i)
                                    })), e("hasMetadata", (function(e, t, n) {
                                        if (!S(t)) throw new TypeError;
                                        return k(n) || (n = I(n)), g(e, t, n)
                                    })), e("hasOwnMetadata", (function(e, t, n) {
                                        if (!S(t)) throw new TypeError;
                                        return k(n) || (n = I(n)), m(e, t, n)
                                    })), e("getMetadata", (function(e, t, n) {
                                        if (!S(t)) throw new TypeError;
                                        return k(n) || (n = I(n)), y(e, t, n)
                                    })), e("getOwnMetadata", (function(e, t, n) {
                                        if (!S(t)) throw new TypeError;
                                        return k(n) || (n = I(n)), b(e, t, n)
                                    })), e("getMetadataKeys", (function(e, t) {
                                        if (!S(e)) throw new TypeError;
                                        return k(t) || (t = I(t)), v(e, t)
                                    })), e("getOwnMetadataKeys", (function(e, t) {
                                        if (!S(e)) throw new TypeError;
                                        return k(t) || (t = I(t)), w(e, t)
                                    })), e("deleteMetadata", (function(e, t, n) {
                                        if (!S(t)) throw new TypeError;
                                        k(n) || (n = I(n));
                                        var i = f(t, n, !1);
                                        if (k(i)) return !1;
                                        if (!i.delete(e)) return !1;
                                        if (i.size > 0) return !0;
                                        var o = h.get(t);
                                        return o.delete(n), o.size > 0 || h.delete(t), !0
                                    }))
                                }(o)
                        }()
                    }(i || (i = {}))
                },
                3379: e => {
                    "use strict";
                    var t = [];

                    function n(e) {
                        for (var n = -1, i = 0; i < t.length; i++)
                            if (t[i].identifier === e) {
                                n = i;
                                break
                            } return n
                    }

                    function i(e, i) {
                        for (var r = {}, a = [], s = 0; s < e.length; s++) {
                            var l = e[s],
                                c = i.base ? l[0] + i.base : l[0],
                                d = r[c] || 0,
                                u = "".concat(c, " ").concat(d);
                            r[c] = d + 1;
                            var p = n(u),
                                h = {
                                    css: l[1],
                                    media: l[2],
                                    sourceMap: l[3],
                                    supports: l[4],
                                    layer: l[5]
                                };
                            if (-1 !== p) t[p].references++, t[p].updater(h);
                            else {
                                var f = o(h, i);
                                i.byIndex = s, t.splice(s, 0, {
                                    identifier: u,
                                    updater: f,
                                    references: 1
                                })
                            }
                            a.push(u)
                        }
                        return a
                    }

                    function o(e, t) {
                        var n = t.domAPI(t);
                        return n.update(e),
                            function(t) {
                                if (t) {
                                    if (t.css === e.css && t.media === e.media && t.sourceMap === e.sourceMap && t.supports === e.supports && t.layer === e.layer) return;
                                    n.update(e = t)
                                } else n.remove()
                            }
                    }
                    e.exports = function(e, o) {
                        var r = i(e = e || [], o = o || {});
                        return function(e) {
                            e = e || [];
                            for (var a = 0; a < r.length; a++) {
                                var s = n(r[a]);
                                t[s].references--
                            }
                            for (var l = i(e, o), c = 0; c < r.length; c++) {
                                var d = n(r[c]);
                                0 === t[d].references && (t[d].updater(), t.splice(d, 1))
                            }
                            r = l
                        }
                    }
                },
                9216: e => {
                    "use strict";
                    e.exports = function(e) {
                        var t = document.createElement("style");
                        return e.setAttributes(t, e.attributes), e.insert(t, e.options), t
                    }
                },
                3565: (e, t, n) => {
                    "use strict";
                    e.exports = function(e) {
                        var t = n.nc;
                        t && e.setAttribute("nonce", t)
                    }
                },
                7795: e => {
                    "use strict";
                    e.exports = function(e) {
                        var t = e.insertStyleElement(e);
                        return {
                            update: function(n) {
                                ! function(e, t, n) {
                                    var i = "";
                                    n.supports && (i += "@supports (".concat(n.supports, ") {")), n.media && (i += "@media ".concat(n.media, " {"));
                                    var o = void 0 !== n.layer;
                                    o && (i += "@layer".concat(n.layer.length > 0 ? " ".concat(n.layer) : "", " {")), i += n.css, o && (i += "}"), n.media && (i += "}"), n.supports && (i += "}");
                                    var r = n.sourceMap;
                                    r && "undefined" != typeof btoa && (i += "\n/*# sourceMappingURL=data:application/json;base64,".concat(btoa(unescape(encodeURIComponent(JSON.stringify(r)))), " */")), t.styleTagTransform(i, e, t.options)
                                }(t, e, n)
                            },
                            remove: function() {
                                ! function(e) {
                                    if (null === e.parentNode) return !1;
                                    e.parentNode.removeChild(e)
                                }(t)
                            }
                        }
                    }
                },
                4589: e => {
                    "use strict";
                    e.exports = function(e, t) {
                        if (t.styleSheet) t.styleSheet.cssText = e;
                        else {
                            for (; t.firstChild;) t.removeChild(t.firstChild);
                            t.appendChild(document.createTextNode(e))
                        }
                    }
                },
                2813: (e, t, n) => {
                    "use strict";
                    var i, o;
                    n.d(t, {
                            H: () => o,
                            p: () => i
                        }),
                        function(e) {
                            e.Custom = "Custom", e.Disabler = "Disabler", e.DangerFrame = "DangerFrame", e.WarningFrame = "WarningFrame", e.Flashlight = "Flashlight", e.Button = "Button", e.FileDownloadWidget = "FileDownloadWidget", e.WalkthroughBox = "WalkthroughBox", e.FocusMask = "FocusMask", e.IFrame = "IFrame", e.BlurMask = "BlurMask", e.BubbleWithArrow = "BubbleWithArrow", e.UrlBubble = "UrlBubble"
                        }(i || (i = {})),
                        function(e) {
                            e.Top = "Top", e.Bottom = "Bottom", e.Left = "Left", e.Right = "Right"
                        }(o || (o = {}))
                },
                8772: (e, t, n) => {
                    "use strict";
                    var i, o, r;
                    n.d(t, {
                            CP: () => i,
                            _j: () => a,
                            fo: () => r,
                            nY: () => o
                        }),
                        function(e) {
                            e.ElementValue = "ElementValue", e.ElementAttribute = "ElementAttribute"
                        }(i || (i = {})),
                        function(e) {
                            e.Date = "Date", e.Number = "Number", e.String = "String"
                        }(o || (o = {})),
                        function(e) {
                            e.Less = "Less", e.LessEqual = "LessEqual", e.Equal = "Equal", e.GreaterEqual = "GreaterEqual", e.Greater = "Greater", e.Between = "Between", e.EndsWith = "EndsWith", e.Regex = "Regex", e.BusinessEmail = "BusinessEmail"
                        }(r || (r = {}));
                    const a = "now"
                },
                7364: (e, t, n) => {
                    "use strict";
                    var i, o, r, a;
                    n.d(t, {
                            EV: () => a,
                            Jr: () => i,
                            Jz: () => o,
                            LS: () => r
                        }),
                        function(e) {
                            e.Text = "Text", e.Title = "Title", e.CategoryMultiSelect = "CategoryMultiSelect"
                        }(i || (i = {})),
                        function(e) {
                            e.Primary = "Primary", e.Secondary = "Seconary", e.Image = "Image"
                        }(o || (o = {})),
                        function(e) {
                            e.Column = "Column", e.Row = "Row"
                        }(r || (r = {})),
                        function(e) {
                            e.ThumbsUp = "ThumbsUp", e.ThumbsDown = "ThumbsDown"
                        }(a || (a = {}))
                },
                6453: (e, t, n) => {
                    "use strict";
                    var i;
                    n.d(t, {
                            O: () => i
                        }),
                        function(e) {
                            e.HideTara = "HideTara", e.ShowTara = "ShowTara", e.WaitForUserInput = "WaitForUserInput", e.WaitForEvent = "WaitForEvent", e.FocusElement = "FocusElement", e.Delay = "Delay", e.ClearContext = "ClearContext", e.SetVariable = "SetVariable", e.ClearVariable = "ClearVariable", e.RemoveDomElements = "RemoveDomElements", e.StartAugmentationFade = "StartAugmentationFade", e.StopAugmentationFade = "StopAugmentationFade", e.HideIndicator = "HideIndicator", e.ActivityLog = "ActivityLog", e.OpenTab = "OpenTab", e.ReleasePendingDownload = "ReleasePendingDownload", e.SetLocalStorage = "SetLocalStorage", e.GetElementData = "GetElementData", e.SetElementData = "SetElementData"
                        }(i || (i = {}))
                },
                2190: (e, t, n) => {
                    "use strict";
                    var i;
                    n.d(t, {
                            Av: () => o,
                            vd: () => i,
                            zp: () => r
                        }),
                        function(e) {
                            e.Empty = "Empty", e.Condition = "Condition", e.Message = "Message", e.Recursive = "Recursive", e.MiniScenario = "MiniScenario"
                        }(i || (i = {}));
                    const o = "RECURSIVE_NEXT",
                        r = "RECURSIVE_PREV"
                },
                3815: (e, t, n) => {
                    "use strict";
                    var i, o, r, a, s;
                    n.d(t, {
                            OP: () => r,
                            cg: () => a,
                            ue: () => s,
                            wi: () => o,
                            xG: () => l
                        }),
                        function(e) {
                            e.Open = "Open", e.Close = "Close"
                        }(i || (i = {})),
                        function(e) {
                            e.Healthy = "Healthy", e.Warning = "Warning", e.Error = "Error"
                        }(o || (o = {})),
                        function(e) {
                            e.FreeText = "FreeText", e.Predefined = "Predefined", e.Automatic = "Automatic"
                        }(r || (r = {})),
                        function(e) {
                            e[e.None = 0] = "None", e[e.ClientOnly = 1] = "ClientOnly", e[e.Full = 2] = "Full"
                        }(a || (a = {})),
                        function(e) {
                            e.Messages = "messages", e.Status = "status", e.Chips = "chips", e.OnUserInput = "onUserInput", e.Close = "close"
                        }(s || (s = {}));
                    const l = ["iframe#us-tara-frame", "input.question-box"]
                },
                6005: (e, t, n) => {
                    "use strict";
                    n.r(t), n.d(t, {
                        MetadataType: () => St,
                        TaraInitMode: () => k,
                        cerebro: () => zo,
                        conversationProxy: () => Vo,
                        initTara: () => $o,
                        myContainer: () => Uo
                    });
                    var i = n(3379),
                        o = n.n(i),
                        r = n(7795),
                        a = n.n(r),
                        s = n(3565),
                        l = n.n(s),
                        c = n(9216),
                        d = n.n(c),
                        u = n(4589),
                        p = n.n(u),
                        h = n(390),
                        f = {};
                    h.Z && h.Z.locals && (f.locals = h.Z.locals);
                    var g, m = 0,
                        y = {};
                    y.styleTagTransform = p(), y.setAttributes = l(), y.insert = function(e, t) {
                        t.target.appendChild(e)
                    }, y.domAPI = a(), y.insertStyleElement = d(), f.use = function(e) {
                        return y.options = e || {}, m++ || (g = o()(h.Z, y)), f
                    }, f.unuse = function() {
                        m > 0 && !--m && (g(), g = null)
                    };
                    const b = f;
                    var x = n(8402);
                    const v = "tara",
                        w = {
                            ITara: Symbol.for("ITara"),
                            IIndicator: Symbol.for("Indicator"),
                            IMeddler: Symbol.for("Meddler"),
                            IDominerService: Symbol.for("IDominerService"),
                            ITaraform: Symbol.for("ITaraform"),
                            IConversationProxy: Symbol.for("IConversationProxy"),
                            IDownloader: Symbol.for("IDownloader")
                        };
                    var _, k;
                    ! function(e) {
                        e.ElementRectRequest = "ElementRectRequest", e.ElementRectResponse = "ElementRectResponse"
                    }(_ || (_ = {})),
                    function(e) {
                        e.Standard = "Standard", e.OutlookAddin = "OutlookAddin"
                    }(k || (k = {}));
                    var C, S = n(3232),
                        E = n(403),
                        I = n(7365);
                    ! function(e) {
                        e.Downloading = "downloading", e.Scanning = "scanning", e.Success = "success", e.Blocked = "blocked", e.Error = "failed", e.Cancelled = "cancelled", e.Pending = "pending", e.Unknown = "unknown"
                    }(C || (C = {}));
                    var A = n(6400),
                        O = 0;

                    function T(e, t, n, i, o) {
                        var r, a, s = {};
                        for (a in t) "ref" == a ? r = t[a] : s[a] = t[a];
                        var l = {
                            type: e,
                            props: s,
                            key: n,
                            ref: r,
                            __k: null,
                            __: null,
                            __b: 0,
                            __e: null,
                            __d: void 0,
                            __c: null,
                            __h: null,
                            constructor: void 0,
                            __v: --O,
                            __source: i,
                            __self: o
                        };
                        if ("function" == typeof e && (r = e.defaultProps))
                            for (a in r) void 0 === s[a] && (s[a] = r[a]);
                        return A.YM.vnode && A.YM.vnode(l), l
                    }

                    function M(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "44",
                            height: "44",
                            viewBox: "0 0 44 44",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("circle", {
                            cx: "22",
                            cy: "22",
                            r: "22",
                            fill: "#1C2F5C",
                            "fill-opacity": "0.05"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M26 11H15C13.3431 11 12 12.3431 12 14V30C12 31.6569 13.3431 33 15 33H29C30.6569 33 32 31.6569 32 30V17L26 11Z",
                            fill: "#FC004A"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M26 11V17H32",
                            fill: "#1C2F5C",
                            "fill-opacity": "0.3"
                        }, []), "\n", (0, A.h)("path", {
                            "fill-rule": "evenodd",
                            "clip-rule": "evenodd",
                            d: "M23 18C23 17.4477 22.5523 17 22 17C21.4477 17 21 17.4477 21 18V22.6667C21 23.219 21.4477 23.6667 22 23.6667C22.5523 23.6667 23 23.219 23 22.6667L23 18ZM23 26C23 25.4477 22.5523 25 22 25C21.4477 25 21 25.4477 21 26V26.6667C21 27.219 21.4477 27.6667 22 27.6667C22.5523 27.6667 23 27.219 23 26.6667V26Z",
                            fill: "white"
                        }, []), "\n"])
                    }

                    function R(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "44",
                            height: "44",
                            viewBox: "0 0 44 44",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("circle", {
                            cx: "22",
                            cy: "22",
                            r: "22",
                            fill: "#1C2F5C",
                            "fill-opacity": "0.05"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M26 10.9996H15C13.3431 10.9996 12 12.3428 12 13.9996V29.9996C12 31.6565 13.3431 32.9996 15 32.9996H29C30.6569 32.9996 32 31.6565 32 29.9996V16.9996L26 10.9996Z",
                            fill: "#1C2F5C",
                            "fill-opacity": "0.7"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M26 10.9996V16.9996H32",
                            fill: "#1C2F5C"
                        }, []), "\n", (0, A.h)("path", {
                            "fill-rule": "evenodd",
                            "clip-rule": "evenodd",
                            d: "M21.3942 19.8103C21.612 19.6861 21.8714 19.6392 22.1251 19.6814C22.3787 19.7237 22.6027 19.8508 22.7605 20.0328C22.9178 20.2142 23.0001 20.4389 22.9998 20.6664L22.9998 20.6679C22.9998 20.803 22.8851 21.0418 22.4453 21.3348C22.256 21.4609 22.0595 21.5598 21.9064 21.6278C21.8312 21.6612 21.77 21.6856 21.7299 21.7009C21.71 21.7085 21.6955 21.7137 21.6874 21.7166L21.6805 21.719C21.2738 21.856 20.9998 22.2373 20.9998 22.6667V23.3329C20.9998 23.8852 21.4475 24.3329 21.9998 24.3329C22.5521 24.3329 22.9998 23.8852 22.9998 23.3329V23.3217C23.1698 23.2354 23.3606 23.1282 23.5542 22.9992C24.1144 22.626 24.9995 21.8656 24.9998 20.6685L24.9998 20.6695L23.9998 20.6679H24.9998V20.6685C25.0006 19.9524 24.7404 19.2633 24.2717 18.7228C23.8035 18.1826 23.1584 17.826 22.4537 17.7086C21.7493 17.5913 21.0233 17.7193 20.4029 18.0733C19.7819 18.4277 19.3034 18.9881 19.0596 19.6611C18.8715 20.1804 19.1399 20.7538 19.6592 20.9419C20.1784 21.13 20.7519 20.8616 20.94 20.3423C21.0188 20.1248 21.177 19.9343 21.3942 19.8103ZM21.9998 24.9996C21.4475 24.9996 20.9998 25.4473 20.9998 25.9996C20.9998 26.5519 21.4475 26.9996 21.9998 26.9996H22.0065C22.5587 26.9996 23.0065 26.5519 23.0065 25.9996C23.0065 25.4473 22.5587 24.9996 22.0065 24.9996H21.9998Z",
                            fill: "white"
                        }, []), "\n"])
                    }

                    function P(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "24",
                            height: "24",
                            viewBox: "0 0 24 24",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("g", {
                            opacity: "0.5"
                        }, ["\n", (0, A.h)("path", {
                            d: "M16 10L12 14L8 10",
                            stroke: "#1C2F5C",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n"]), "\n"])
                    }

                    function D(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "24",
                            height: "24",
                            viewBox: "0 0 24 24",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M19 12C19 15.866 15.866 19 12 19C8.13401 19 5 15.866 5 12C5 8.13401 8.13401 5 12 5C15.866 5 19 8.13401 19 12Z",
                            stroke: "#FC004A",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M12 9V12",
                            stroke: "#FC004A",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n", (0, A.h)("circle", {
                            cx: "12",
                            cy: "15",
                            r: "1",
                            fill: "#FC004A"
                        }, []), "\n"])
                    }

                    function j(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "24",
                            height: "24",
                            viewBox: "0 0 24 24",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("g", {
                            opacity: "0.5"
                        }, ["\n", (0, A.h)("path", {
                            "fill-rule": "evenodd",
                            "clip-rule": "evenodd",
                            d: "M15.7071 9.70711C16.0976 9.31658 16.0976 8.68342 15.7071 8.29289C15.3166 7.90237 14.6834 7.90237 14.2929 8.29289L12 10.5858L9.70711 8.29289C9.31658 7.90237 8.68342 7.90237 8.29289 8.29289C7.90237 8.68342 7.90237 9.31658 8.29289 9.70711L10.5858 12L8.29289 14.2929C7.90237 14.6834 7.90237 15.3166 8.29289 15.7071C8.68342 16.0976 9.31658 16.0976 9.70711 15.7071L12 13.4142L14.2929 15.7071C14.6834 16.0976 15.3166 16.0976 15.7071 15.7071C16.0976 15.3166 16.0976 14.6834 15.7071 14.2929L13.4142 12L15.7071 9.70711Z",
                            fill: "#1C2F5C"
                        }, []), "\n"]), "\n"])
                    }
                    const L = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"],
                        F = {
                            [C.Downloading]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    viewBox: "0 0 46 46",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("circle", {
                                    cx: "22",
                                    cy: "22",
                                    r: "22",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.05"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M43.1539 21.9995C43.1539 24.7775 42.6067 27.5283 41.5436 30.0948C40.4806 32.6613 38.9224 34.9933 36.9581 36.9576C34.9937 38.9219 32.6618 40.4801 30.0953 41.5432C27.5288 42.6062 24.778 43.1534 22 43.1534",
                                    stroke: "#56CCF2",
                                    "stroke-width": "4",
                                    "stroke-linecap": "round",
                                    "stroke-linejoin": "round"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11H15C13.3431 11 12 12.3431 12 14V30C12 31.6569 13.3431 33 15 33H29C30.6569 33 32 31.6569 32 30V17L26 11Z",
                                    fill: "#56CCF2"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11V17H32",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.3"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M23.3333 18.667V22.667H26L22 26.667L18 22.667H20.6667V18.667H23.3333Z",
                                    fill: "white"
                                }, []), "\n"])
                            },
                            [C.Scanning]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    viewBox: "0 0 46 46",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("circle", {
                                    cx: "22",
                                    cy: "22",
                                    r: "22",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.05"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M43.1539 21.9995C43.1539 24.7775 42.6067 27.5283 41.5436 30.0948C40.4806 32.6613 38.9224 34.9933 36.9581 36.9576C34.9937 38.9219 32.6618 40.4801 30.0953 41.5432C27.5288 42.6062 24.778 43.1534 22 43.1534",
                                    stroke: "#FFC000",
                                    "stroke-width": "4",
                                    "stroke-linecap": "round",
                                    "stroke-linejoin": "round"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11H15C13.3431 11 12 12.3431 12 14V30C12 31.6569 13.3431 33 15 33H29C30.6569 33 32 31.6569 32 30V17L26 11Z",
                                    fill: "#FFC000"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11V17H32",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.3"
                                }, []), "\n", (0, A.h)("path", {
                                    "fill-rule": "evenodd",
                                    "clip-rule": "evenodd",
                                    d: "M18.3335 21.333C18.3335 19.6762 19.6766 18.333 21.3335 18.333C22.9904 18.333 24.3335 19.6762 24.3335 21.333C24.3335 22.1511 24.0061 22.8926 23.4751 23.4338C23.4682 23.4404 23.4613 23.4471 23.4545 23.4539C23.4477 23.4607 23.441 23.4675 23.4345 23.4745C22.8932 24.0055 22.1516 24.333 21.3335 24.333C19.6766 24.333 18.3335 22.9899 18.3335 21.333ZM24.091 25.5045C23.3005 26.0281 22.3526 26.333 21.3335 26.333C18.5721 26.333 16.3335 24.0944 16.3335 21.333C16.3335 18.5716 18.5721 16.333 21.3335 16.333C24.0949 16.333 26.3335 18.5716 26.3335 21.333C26.3335 22.352 26.0286 23.2999 25.5052 24.0903L27.3741 25.9592C27.7646 26.3497 27.7646 26.9829 27.3741 27.3734C26.9835 27.7639 26.3504 27.7639 25.9598 27.3734L24.091 25.5045Z",
                                    fill: "white"
                                }, []), "\n"])
                            },
                            [C.Success]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "44",
                                    height: "44",
                                    viewBox: "0 0 44 44",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("circle", {
                                    cx: "22",
                                    cy: "22",
                                    r: "22",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.05"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11H15C13.3431 11 12 12.3431 12 14V30C12 31.6569 13.3431 33 15 33H29C30.6569 33 32 31.6569 32 30V17L26 11Z",
                                    fill: "#6FCF97"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11V17H32",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.3"
                                }, []), "\n", (0, A.h)("path", {
                                    "fill-rule": "evenodd",
                                    "clip-rule": "evenodd",
                                    d: "M23 18C23 17.4477 22.5523 17 22 17C21.4477 17 21 17.4477 21 18V22.6667C21 23.219 21.4477 23.6667 22 23.6667C22.5523 23.6667 23 23.219 23 22.6667L23 18ZM23 26C23 25.4477 22.5523 25 22 25C21.4477 25 21 25.4477 21 26V26.6667C21 27.219 21.4477 27.6667 22 27.6667C22.5523 27.6667 23 27.219 23 26.6667V26Z",
                                    fill: "white"
                                }, []), "\n"])
                            },
                            [C.Blocked]: M,
                            [C.Error]: M,
                            [C.Cancelled]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "44",
                                    height: "44",
                                    viewBox: "0 0 44 44",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("circle", {
                                    cx: "22",
                                    cy: "22",
                                    r: "22",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.05"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11H15C13.3431 11 12 12.3431 12 14V30C12 31.6569 13.3431 33 15 33H29C30.6569 33 32 31.6569 32 30V17L26 11Z",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.5"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26 11V17H32",
                                    fill: "#1C2F5C",
                                    "fill-opacity": "0.3"
                                }, []), "\n", (0, A.h)("path", {
                                    "fill-rule": "evenodd",
                                    "clip-rule": "evenodd",
                                    d: "M24.7071 20.7071C25.0976 20.3166 25.0976 19.6834 24.7071 19.2929C24.3166 18.9024 23.6834 18.9024 23.2929 19.2929L22 20.5858L20.7071 19.2929C20.3166 18.9024 19.6834 18.9024 19.2929 19.2929C18.9024 19.6834 18.9024 20.3166 19.2929 20.7071L20.5858 22L19.2929 23.2929C18.9024 23.6834 18.9024 24.3166 19.2929 24.7071C19.6834 25.0976 20.3166 25.0976 20.7071 24.7071L22 23.4142L23.2929 24.7071C23.6834 25.0976 24.3166 25.0976 24.7071 24.7071C25.0976 24.3166 25.0976 23.6834 24.7071 23.2929L23.4142 22L24.7071 20.7071Z",
                                    fill: "white"
                                }, []), "\n"])
                            },
                            [C.Unknown]: R,
                            [C.Pending]: R
                        },
                        H = {
                            [C.Downloading]: P,
                            [C.Scanning]: P,
                            [C.Success]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "24",
                                    height: "24",
                                    viewBox: "0 0 24 24",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("path", {
                                    d: "M12 20C16.4183 20 20 16.4183 20 12C20 7.58172 16.4183 4 12 4C7.58172 4 4 7.58172 4 12C4 16.4183 7.58172 20 12 20Z",
                                    fill: "#6FCF97",
                                    stroke: "#6FCF97",
                                    "stroke-width": "2",
                                    "stroke-linecap": "round",
                                    "stroke-linejoin": "round"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M8.18164 12.0005L10.7271 14.546L15.818 9.45508",
                                    stroke: "white",
                                    "stroke-width": "2",
                                    "stroke-linecap": "round",
                                    "stroke-linejoin": "round"
                                }, []), "\n"])
                            },
                            [C.Blocked]: D,
                            [C.Error]: D,
                            [C.Cancelled]: j,
                            [C.Unknown]: j,
                            [C.Pending]: j
                        };

                    function B(e) {
                        let t = "";
                        e.status === C.Downloading && (t = "Downloading to Unbiased"), e.status === C.Scanning && (t = "Scanning");
                        const [n, i] = function(e) {
                            if (0 === e) return [0, "Bytes"];
                            const t = Math.floor(Math.log(e) / Math.log(1024));
                            return [parseFloat((e / Math.pow(1024, t)).toFixed(2)), L[t]]
                        }(e.sizeBytes), o = function(e, t) {
                            if (0 === e) return 0;
                            const n = L.findIndex((e => e === t));
                            return (e / Math.pow(1024, n)).toFixed(2)
                        }(e.progress, i), r = F[e.status], a = H[e.status];
                        let s = "";
                        switch (e.status) {
                            case C.Downloading:
                            case C.Scanning:
                                s = `${o}/${n} ${i}`;
                                break;
                            case C.Blocked:
                                s = "Malicious File";
                                break;
                            case C.Cancelled:
                                s = "Cancelled";
                                break;
                            case C.Success:
                                s = "File Clean";
                                break;
                            case C.Error:
                                s = "Download Error";
                                break;
                            case C.Unknown:
                                s = "Blocked - Unknown file"
                        }
                        return T("div", Object.assign({
                            className: `file-download-panel ${e.status.toLowerCase()}`
                        }, {
                            children: [T("div", Object.assign({
                                className: "file-download-action"
                            }, {
                                children: t
                            }), void 0), T("div", Object.assign({
                                className: "file-download-details"
                            }, {
                                children: [T("div", Object.assign({
                                    className: "file-download-icon"
                                }, {
                                    children: T(r, {}, void 0)
                                }), void 0), T("div", Object.assign({
                                    className: "file-download-specs"
                                }, {
                                    children: [T("div", Object.assign({
                                        className: "file-download-filename"
                                    }, {
                                        children: e.filename
                                    }), void 0), T("div", Object.assign({
                                        className: `file-download-status ${e.status.toLowerCase()}`
                                    }, {
                                        children: s
                                    }), void 0)]
                                }), void 0), T("div", Object.assign({
                                    className: "file-ops"
                                }, {
                                    children: T(a, {}, void 0)
                                }), void 0)]
                            }), void 0)]
                        }), e.id)
                    }

                    function N(e) {
                        return e.visible ? T("div", Object.assign({
                            id: "download-widget"
                        }, {
                            children: Object.values(e.files).map((e => T(B, Object.assign({}, e), void 0)))
                        }), void 0) : null
                    }
                    n(8660);
                    var U = n(7936),
                        V = n(396);
                    let z = class {
                        constructor(e) {
                            this._propSetters = {}, this.stateMaker = () => {
                                const e = {};
                                for (const [t, n] of Object.entries(this._props)) {
                                    const [i, o] = (0, V.eJ)(n);
                                    this._propSetters[t] = o, e[t] = i
                                }
                                return e
                            }, this.props = () => this._props, this._props = {
                                ...e
                            }
                        }
                        setProp(e, t) {
                            this._props[e] = t, "function" == typeof this._propSetters[e] && this._propSetters[e](t)
                        }
                    };
                    var W, G;
                    z = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), (W = 0, G = (0, U.N)(), function(e, t) {
                        G(e, t, W)
                    }), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object])], z);

                    function $(e) {
                        const t = e.stateMaker(),
                            n = e.component;
                        return t.render ? T(n, Object.assign({}, t), void 0) : null
                    }
                    let q = class extends z {
                        constructor(e, t) {
                            super({
                                ...e,
                                render: !0
                            }), this.draw = () => [$, {
                                stateMaker: this.stateMaker,
                                component: this._component
                            }, this._key], this.setRender = e => this.setProp("render", e), this._component = t
                        }
                        init(e, t) {
                            this._utils = e.common, this._logger = e.logger, this._domUtils = e.dom, this._rectUtils = e.rect, this._config = e.config.config, this._meddlerRoot = t, this._key = this._utils.randomInt(), this._logger.debug(`Initializing augmentation ${this.getType()} - ${this._key}`)
                        }
                        getType() {
                            return this.props().type
                        }
                        get key() {
                            return this._key
                        }
                    };
                    q = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Function])], q);
                    const Y = {
                        IRectUtils: Symbol.for("IRectUtils"),
                        ICommonUtils: Symbol.for("ICommonUtils"),
                        IDomUtils: Symbol.for("IDomUtils"),
                        ILogger: Symbol.for("ILogger"),
                        IToolbox: Symbol.for("IToolbox"),
                        IConfigProvider: Symbol.for("IConfig"),
                        IContextStore: Symbol.for("IContextStore")
                    };
                    var J;
                    ! function(e) {
                        e.Parent = "Parent", e.Ancestor = "Ancestor"
                    }(J || (J = {}));
                    var Z = n(2813),
                        X = function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    let K = class extends q {
                        constructor(e, t) {
                            super({
                                files: {},
                                visible: !1,
                                type: Z.p.FileDownloadWidget
                            }, N), this.type = Z.p.FileDownloadWidget, this.startDownload = e => e.download_id && e.filename ? this.props().files[e.download_id] ? this.onError("Received start download request for an existing id.", e) : (0 === Object.keys(this.props().files).length && this.show(), void this.setProp("files", {
                                ...this.props().files,
                                [e.download_id]: {
                                    status: C.Downloading,
                                    id: e.download_id,
                                    progress: 0,
                                    filename: e.filename,
                                    sizeBytes: e.filesize
                                }
                            })) : this.onError("Invalid download start message. expected 'id' and 'filename' to exist.", e), this.downloadProgress = e => e.download_id && void 0 !== e.progress ? this.props().files[e.download_id] ? void this.updateFileStatus(e.download_id, {
                                progress: e.progress,
                                status: C.Downloading
                            }) : this.onError("Received progress request for a non existing id.", e) : this.onError("Invalid d/l progress message. expected 'id','progress' to exist.", e), this.downloadScanProgress = e => e.download_id && void 0 !== e.progress ? this.props().files[e.download_id] ? void this.updateFileStatus(e.download_id, {
                                progress: e.progress,
                                status: C.Scanning
                            }) : this.onError("Received progress request for a non existing id.", e) : this.onError("Invalid scan progress message. expected 'id','progress' to exist.", e), this.downloadComplete = e => {
                                if (!e.download_id || !e.status) return this.onError("Invalid download complete message. expected 'id' and 'status' to exist.", e);
                                if (e.status === C.Success && !e.link) return this.onError("Invalid download complete message. expected 'link' to exist.", e);
                                if (!this.props().files[e.download_id]) return this.onError("Received download complete request for a non existing id.", e);
                                const t = this.props().files[e.download_id];
                                this.updateFileStatus(e.download_id, {
                                    progress: t.sizeBytes,
                                    status: e.status,
                                    link: e.link
                                }), e.status === C.Success && this.download(e)
                            }, this.init(t, null);
                            const n = !0;
                            e.registerHandler("download_start", this.startDownload, n), e.registerHandler("download_progress", this.downloadProgress, n), e.registerHandler("scan_progress", this.downloadScanProgress, n), e.registerHandler("download_complete", this.downloadComplete, n)
                        }
                        onError(e, t) {
                            this._logger.error(e, t)
                        }
                        updateFileStatus(e, t) {
                            const n = {
                                ...this.props().files
                            };
                            n[e] = {
                                ...n[e],
                                ...t
                            }, this.setProp("files", n)
                        }
                        releasePendingDownload(e) {
                            const t = this.props().files[e];
                            t ? this.download({
                                link: t.link,
                                download_id: e,
                                status: t.status
                            }) : this._logger.error("releasePendingDownload received non existent id", e)
                        }
                        download(e) {
                            const t = document.createElement("iframe");
                            t.style.visibility = "hidden", t.style.display = "none";
                            const n = document.createAttribute("src");
                            n.value = e.link, t.attributes.setNamedItem(n), document.body.appendChild(t), setTimeout((() => {
                                this.removeFileDetails(e.download_id)
                            }), this._config.defaultTransitionDuration)
                        }
                        removeFileDetails(e) {
                            const t = this.props();
                            delete t.files[e], this.setProp("files", t.files), 0 === Object.keys(t.files).length && this.hide()
                        }
                        hide() {
                            this.setProp("visible", !1)
                        }
                        show() {
                            this.setProp("visible", !0)
                        }
                    };
                    K = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), X(0, (0, I.f)(S.TYPES.ICerebroClient)), X(1, (0, I.f)(Y.IToolbox)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], K);
                    var Q = n(7485),
                        ee = {};
                    Q.Z && Q.Z.locals && (ee.locals = Q.Z.locals);
                    var te, ne = 0,
                        ie = {};
                    ie.styleTagTransform = p(), ie.setAttributes = l(), ie.insert = function(e, t) {
                        t.target.appendChild(e)
                    }, ie.domAPI = a(), ie.insertStyleElement = d(), ee.use = function(e) {
                        return ie.options = e || {}, ne++ || (te = o()(Q.Z, ie)), ee
                    }, ee.unuse = function() {
                        ne > 0 && !--ne && (te(), te = null)
                    };
                    const oe = ee,
                        re = {
                            activityLoggerURL: window.unbiasedActivityLogsURL || "",
                            domPollingIntervalMs: 20,
                            elementAugmentationWaitMs: 500,
                            getFrameElementRectTimeout: 200,
                            defaultIframeLoadTimeout: 3e3,
                            outlookAddin: !0 === window.outlookAddin,
                            defaultTransitionDuration: 400,
                            augmentedElementVisibilityTrackingInterval: 500,
                            checkElementAugmentationVisibility: !0,
                            augmentationDefaultStyles: {
                                [Z.p.DangerFrame]: {
                                    border: "solid 1px red",
                                    backgroundColor: "rgba(255,0,0,0.1)",
                                    xPadding: 4,
                                    yPadding: 2
                                },
                                [Z.p.WarningFrame]: {
                                    border: "2px solid #FFC702",
                                    backgroundColor: "transparent",
                                    radar: {},
                                    xPadding: 10,
                                    yPadding: 10
                                },
                                [Z.p.Disabler]: {
                                    pointerEvents: "auto"
                                },
                                [Z.p.FocusMask]: {
                                    xPadding: 10,
                                    yPadding: 10
                                },
                                [Z.p.Custom]: {
                                    xPadding: 4,
                                    yPadding: 2
                                },
                                [Z.p.Flashlight]: {
                                    xPadding: 80,
                                    yPadding: 40
                                }
                            }
                        };
                    const ae = "outlook-addin";
                    let se = class extends z {
                        constructor(e) {
                            super(e.props), this._frame = null;
                            const t = {
                                supportEvents: !0,
                                ...e
                            };
                            this._frame = t.frameId && this.createFrame(t.frameId), this._node = this.createRootNode(this._frame ? this._frame.contentDocument : document, t.nodeId), this._frame && t.css.use({
                                target: this._frame.contentDocument.head
                            }), this._componentFunc = t.componentFunc, this._supportEvents = t.supportEvents, this.setVisibility(e.props.visible), this.render()
                        }
                        createFrame(e) {
                            const t = document.createElement("iframe");
                            return t.setAttribute("id", e), re.outlookAddin && t.classList.add(ae), document.body.appendChild(t), t
                        }
                        createRootNode(e, t) {
                            const n = e.createElement("div");
                            return n.setAttribute("id", t), n.classList.add("unbiased-fadeable-frame"), re.outlookAddin && n.classList.add(ae), e.body.appendChild(n), n
                        }
                        setVisibility(e) {
                            this._supportEvents && this._frame.classList[e ? "add" : "remove"]("us-pointer-events-allowed", "unbiased-visible-frame"), e !== this.props().visible && (this.setProp("visible", e), this.render())
                        }
                        hide() {
                            this.setVisibility(!1)
                        }
                        show() {
                            this.setVisibility(!0)
                        }
                        toggle() {
                            this.setVisibility(!this.props().visible)
                        }
                        render() {
                            const e = this._componentFunc;
                            (0, A.sY)(T(e, {
                                stateMaker: this.stateMaker
                            }, void 0), this._node)
                        }
                        frame() {
                            return this._frame
                        }
                        node() {
                            return this._node
                        }
                    };
                    var le;

                    function ce(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            viewBox: "0 0 40 40",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("circle", {
                            cx: "20",
                            cy: "20",
                            r: "20",
                            fill: "#10196B"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M33.9855 23.3753C33.1272 23.8872 32.0282 23.6336 31.3648 22.8863C28.5701 19.7386 24.447 17.8997 20.0004 17.8997C15.5549 17.8997 11.4235 19.7377 8.63469 22.884C7.97184 23.6319 6.87277 23.8867 6.01449 23.3749V23.3749C5.07787 22.8163 4.80069 21.5758 5.51389 20.7508C9.03722 16.6752 14.3144 14.2858 20.0004 14.2858C25.6869 14.2858 30.9645 16.6667 34.4878 20.7489C35.201 21.5751 34.9229 22.8163 33.9855 23.3753V23.3753Z",
                            fill: "#889DD0"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M20.0004 25.7142C14.3139 25.7142 9.03632 23.3333 5.513 19.2511C4.79989 18.4249 5.07794 17.1837 6.01531 16.6247V16.6247C6.8736 16.1128 7.97261 16.3664 8.63608 17.1137C11.4307 20.2614 15.5538 22.1003 20.0004 22.1003C24.4459 22.1003 28.5774 20.2623 31.3661 17.116C32.029 16.3681 33.1281 16.1133 33.9864 16.6251V16.6251C34.923 17.1837 35.2001 18.4242 34.4869 19.2492C30.9636 23.3248 25.6865 25.7142 20.0004 25.7142Z",
                            fill: "white"
                        }, []), "\n"])
                    }

                    function de(e) {
                        const t = e.stateMaker();
                        return T("div", Object.assign({
                            id: "tara-indicator",
                            className: t.status.toLowerCase(),
                            onClick: t.click
                        }, {
                            children: T(ce, {}, void 0)
                        }), void 0)
                    }
                    se = function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        }([(0, E.b)(), function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        }(0, (0, U.N)()), function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        }("design:paramtypes", [Object])], se),
                        function(e) {
                            e.Status = "status", e.Click = "click"
                        }(le || (le = {}));
                    var ue = n(3815);
                    let pe = class extends se {
                        constructor(e) {
                            super({
                                props: {
                                    status: ue.wi.Healthy,
                                    visible: !1,
                                    click: () => null
                                },
                                frameId: "us-indicator-frame",
                                nodeId: "tara-indicator-root",
                                css: oe,
                                componentFunc: de
                            }), this._tara = e, this.setProp(le.Click, (() => () => this._tara.toggle()))
                        }
                        setStatus(e) {
                            this.setProp(le.Status, e)
                        }
                    };
                    pe = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    }(0, (0, I.f)(w.ITara)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object])], pe);
                    var he = n(2839),
                        fe = {};
                    he.Z && he.Z.locals && (fe.locals = he.Z.locals);
                    var ge, me = 0,
                        ye = {};
                    ye.styleTagTransform = p(), ye.setAttributes = l(), ye.insert = function(e, t) {
                        t.target.appendChild(e)
                    }, ye.domAPI = a(), ye.insertStyleElement = d(), fe.use = function(e) {
                        return ye.options = e || {}, me++ || (ge = o()(he.Z, ye)), fe
                    }, fe.unuse = function() {
                        me > 0 && !--me && (ge(), ge = null)
                    };
                    const be = fe;

                    function xe(e) {
                        const t = e.stateMaker();
                        return T("div", Object.assign({
                            id: "meddler"
                        }, {
                            children: t.augmentations.map((e => {
                                const [t, n, i] = e();
                                return T(t, Object.assign({}, n), i)
                            }))
                        }), void 0)
                    }
                    var ve;
                    ! function(e) {
                        e.Augmentations = "augmentations"
                    }(ve || (ve = {}));
                    var we = n(8661);
                    class _e extends q {
                        constructor(e, t, n, i) {
                            if (super(t, n), this._observers = [], this._observedElements = [], this._observedDocuments = [], this._destroyed = !1, this._augmentationFailed = !1, this._elementVisible = !1, this.shouldRenderCheck = () => {
                                    const e = !this._augmentationFailed && this._elementVisible;
                                    e !== !!this.props().render && this.setRender(e)
                                }, this.scrolling = () => {
                                    this._selectorsUpdated || this.setProp("scrolling", !0), this._scrollingTimeout && clearTimeout(this._scrollingTimeout), this._scrollingTimeout = setTimeout((() => {
                                        this._scrollingTimeout = null, this.setProp("scrolling", !1), this.checkVisibility()
                                    }), this._config.defaultTransitionDuration), this.updateRequired()
                                }, this.updateRequired = async () => {
                                    if (this._destroyed) return;
                                    this.setProp("fixed", !1);
                                    const e = async () => {
                                        [this._elementRect, this._parent, this._element] = await this._domUtils.getElementRectAndParent(this._selectors, J.Ancestor), this._innerRect && this._innerRect.height && this._innerRect.width && !this._rectUtils.equalSize(this._elementRect, this._innerRect) ? this._rect = this._rectUtils.add(this._innerRect, this._rectUtils.topLeft(this._elementRect)) : this._rect = this._elementRect, this._domUtils.isPositionFixed(this._selectors) && !this.props().fixed && this.setProp("fixed", !0), this.elementRectUpdated(), this.checkVisibility()
                                    };
                                    try {
                                        await e()
                                    } catch {
                                        try {
                                            await this._domUtils.getElementWithTimeout(this._selectors, this._config.elementAugmentationWaitMs), await e()
                                        } catch {
                                            this._logger.debug(`Failed getting element for selectors ${this._selectors&&this._selectors.toString()}. Aborting render.`), this._augmentationFailed = !0, this.shouldRenderCheck()
                                        }
                                    }
                                }, this.checkVisibility = () => {
                                    if ([Z.p.Disabler, Z.p.WalkthroughBox].includes(this.props().type) || this._selectorsUpdated || !this._config.checkElementAugmentationVisibility || !this._element) return;
                                    const e = parseInt(window.getComputedStyle(this._element).borderRadius),
                                        t = this._rectUtils.pad(this._elementRect, -2 - e / 2, -2 - e / 2),
                                        n = (this.elementFromPoint(t.left, t.top, this._element) && 1) + (this.elementFromPoint(t.right, t.top, this._element) && 1) + (this.elementFromPoint(t.left, t.bottom, this._element) && 1) + (this.elementFromPoint(t.right, t.bottom, this._element) && 1) + (this.elementFromPoint(t.right - t.width / 4, t.bottom - t.height / 2, this._element) && 1) + (this.elementFromPoint(t.left + t.width / 4, t.bottom - t.height / 2, this._element) && 1);
                                    this._elementVisible = n >= 5, this.shouldRenderCheck()
                                }, this.trackVisibility = () => {
                                    this._trackVisibilityInterval = setInterval(this.checkVisibility, this._config.augmentedElementVisibilityTrackingInterval)
                                }, this._selectors = e, this._innerRect = i, _e._updateFunctions.push(this.updateRequired), !this._selectors) return this._augmentationFailed = !0, void this.shouldRenderCheck()
                        }
                        init(e, t) {
                            super.init(e, t), this.updateRequired(), this.registerObserversAndListeners()
                        }
                        setSelectors(e) {
                            this._selectorsUpdated = !0, this._selectors = e, this.cleanup(), this.registerObserversAndListeners(), this.updateRequired(), setTimeout((() => this._selectorsUpdated = !1), this._config.defaultTransitionDuration)
                        }
                        elementFromPoint(e, t, n) {
                            let i = document.elementFromPoint(e, t),
                                o = 0,
                                r = 0;
                            for (;
                                "IFRAME" === i.tagName && i !== n;) {
                                if ("us-tara-frame" === i.id) return !0;
                                const n = i,
                                    a = n.getBoundingClientRect();
                                o += a.x, r += a.y, i = n.contentDocument.elementFromPoint(e - o, t - r)
                            }
                            return !!this._meddlerRoot.contains(i) || i === n || n.contains(i)
                        }
                        async registerObserversAndListeners() {
                            if (this._selectors) {
                                this.trackVisibility();
                                for (let e = 0; e < this._selectors.length; e++) {
                                    const t = this._selectors.slice(0, e + 1);
                                    let n = await this._domUtils.getElementWithTimeout(t, this._config.elementAugmentationWaitMs);
                                    for (n && !this._observedDocuments.includes(n.ownerDocument) && (n.ownerDocument.addEventListener("scroll", this.scrolling), this._observedDocuments.push(n.ownerDocument)); n && "HTML" !== n.nodeName;) {
                                        let e = !1;
                                        const t = new ResizeObserver((() => {
                                            e ? this.updateRequired() : e = !0
                                        }));
                                        this._observedElements.includes(n) || (this._observers.push(t), this._observedElements.push(n), t.observe(n), n.addEventListener("scroll", this.scrolling)), n = n.parentElement
                                    }
                                }
                            }
                        }
                        cleanup() {
                            this._observedElements.forEach((e => e.removeEventListener("scroll", this.scrolling))), this._observedDocuments.forEach((e => e.removeEventListener("scroll", this.scrolling))), this._observers.forEach((e => e.disconnect())), this._observedDocuments = [], this._observedElements = [], this._observers = [], clearInterval(this._trackVisibilityInterval), this._trackVisibilityInterval = null
                        }
                        remove(e) {
                            this._logger.debug(`Removing augmentation ${this.getType()} - ${this.key}`), this._destroyed = !0, this.cleanup(), this._utils.removeValFromArray(_e._updateFunctions, this.updateRequired), e()
                        }
                    }

                    function ke(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "432",
                            height: "82",
                            viewBox: "0 0 432 82",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M0 20C0 8.95429 8.9543 0 20 0H1220C1231.05 0 1240 8.95431 1240 20V81.7326H0V20Z",
                            fill: "#DFE3E8"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M23.3521 37.6816C23.3521 29.9497 29.6201 23.6816 37.3521 23.6816C45.084 23.6816 51.3521 29.9497 51.3521 37.6816C51.3521 45.4136 45.084 51.6816 37.3521 51.6816C29.6201 51.6816 23.3521 45.4136 23.3521 37.6816Z",
                            fill: "white"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M36.8231 43.1458C37.1152 43.438 37.5889 43.438 37.881 43.1458C38.173 42.8539 38.1732 42.3805 37.8815 42.0883L34.2245 38.4248L42.6021 38.4248C43.0163 38.4248 43.3521 38.089 43.3521 37.6748C43.3521 37.2606 43.0163 36.9248 42.6021 36.9248L34.2246 36.9248L37.8838 33.2721C38.1782 32.9782 38.1785 32.5012 37.8843 32.2071C37.5904 31.9131 37.1137 31.9131 36.8198 32.2071L31.7965 37.2304C31.551 37.4758 31.551 37.8738 31.7965 38.1192L36.8231 43.1458Z",
                            fill: "#919EAB"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M87.3521 37.6816C87.3521 45.4136 81.084 51.6816 73.3521 51.6816C65.6201 51.6816 59.3521 45.4136 59.3521 37.6816C59.3521 29.9497 65.6201 23.6816 73.3521 23.6816C81.084 23.6816 87.3521 29.9497 87.3521 37.6816Z",
                            fill: "white"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M73.881 32.2175C73.5889 31.9253 73.1152 31.9253 72.8231 32.2175C72.5311 32.5094 72.5309 32.9827 72.8226 33.275L76.4796 36.9385L68.1021 36.9385C67.6878 36.9385 67.3521 37.2743 67.3521 37.6885C67.3521 38.1027 67.6878 38.4385 68.1021 38.4385L76.4796 38.4385L72.8203 42.0912C72.5259 42.3851 72.5256 42.8621 72.8198 43.1562C73.1137 43.4502 73.5904 43.4502 73.8843 43.1562L78.9076 38.1329C79.1531 37.8875 79.1531 37.4895 78.9076 37.244L73.881 32.2175Z",
                            fill: "#919EAB"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M99.3521 37.6816C99.3521 27.1882 107.859 18.6816 118.352 18.6816H918.352C928.845 18.6816 937.352 27.1882 937.352 37.6816C937.352 48.1751 928.845 56.6816 918.352 56.6816H118.352C107.859 56.6816 99.3521 48.1751 99.3521 37.6816Z",
                            fill: "white"
                        }, []), "\n"])
                    }

                    function Ce(e) {
                        const t = {},
                            n = {};
                        let i;
                        switch (e.arrowSide) {
                            case Z.H.Top:
                                t.bottom = "100%", t.transform = "translate(-50%, 85%) rotate(45deg)", i = "left";
                                break;
                            case Z.H.Bottom:
                                t.top = "100%", t.transform = "translate(-50%, -85%) rotate(45deg)", i = "left";
                                break;
                            case Z.H.Left:
                                t.right = "100%", t.transform = "translate(85%, -50%) rotate(45deg)", i = "top";
                                break;
                            case Z.H.Right:
                                t.left = "100%", t.transform = "translate(-85%, -50%) rotate(45deg)", i = "top"
                        }
                        return t[i] = 100 * e.arrowPlacement + "%", n.top = 100 * e.position.y + "%", n.left = 100 * e.position.x + "%", e.fixed && (n.position = "fixed"), T("div", Object.assign({
                            class: "bubble-with-arrow",
                            style: n
                        }, {
                            children: [T("div", {
                                class: "the-arrow",
                                style: t
                            }, void 0), T("div", Object.assign({
                                className: "content-container"
                            }, {
                                children: T("div", Object.assign({
                                    class: "the-content"
                                }, {
                                    children: e.content
                                }), void 0)
                            }), void 0)]
                        }), void 0)
                    }
                    _e._updateFunctions = [], _e.trackLayoutShift = () => {
                        new PerformanceObserver((() => {
                            _e._updateFunctions.forEach((e => e()))
                        })).observe({
                            type: "layout-shift",
                            buffered: !0
                        })
                    }, _e.trackLayoutShift();
                    const Se = "div.bubble-urlbar-text";

                    function Ee(e = {}) {
                        const t = e.placement || Z.H.Top,
                            n = e.bubble && T("div", {
                                dangerouslySetInnerHTML: {
                                    __html: e.bubble.content
                                }
                            }, void 0);
                        return T("div", Object.assign({
                            className: `radar-wrapper ${t.toLowerCase()}`
                        }, {
                            children: [T("div", Object.assign({
                                className: "augmentation-radar"
                            }, {
                                children: T("div", Object.assign({
                                    className: "circle1"
                                }, {
                                    children: T("div", {
                                        className: "circle2"
                                    }, void 0)
                                }), void 0)
                            }), void 0), e.bubble && e.bubble.content && e.bubble.content.length && T(Ce, Object.assign({}, {
                                ...e.bubble,
                                content: n,
                                position: {
                                    x: 1,
                                    y: t === Z.H.Top ? 0 : 1
                                },
                                arrowSide: t === Z.H.Top ? Z.H.Bottom : Z.H.Top,
                                arrowPlacement: .8
                            }), void 0)]
                        }), void 0)
                    }

                    function Ie(e) {
                        return T("div", Object.assign({
                            className: e.className,
                            style: {
                                ...e.style,
                                ...e.fixed ? {
                                    position: "fixed"
                                } : {},
                                left: `${e.rect.left}px`,
                                top: `${e.rect.top}px`,
                                width: `${e.rect.width}px`,
                                height: `${e.rect.height}px`,
                                ...e.scrolling ? {
                                    transform: "none"
                                } : {}
                            }
                        }, {
                            children: e.radar && T(Ee, Object.assign({}, e.radar), void 0)
                        }), void 0)
                    }

                    function Ae(e) {
                        const t = {
                            ...e
                        };
                        return t.style || (t.style = {}), re.augmentationDefaultStyles[e.type] && Object.entries(re.augmentationDefaultStyles[e.type]).forEach((([e, n]) => {
                            switch (e) {
                                case "xPadding":
                                    t.xPadding = void 0 !== t.xPadding ? t.xPadding : n;
                                    break;
                                case "yPadding":
                                    t.yPadding = void 0 !== t.yPadding ? t.yPadding : n;
                                    break;
                                case "radar":
                                    t.radar = void 0 !== t.radar ? t.radar : n;
                                    break;
                                default:
                                    t.style[e] || (t.style[e] = n)
                            }
                        })), t.className = e.type.toLowerCase(), t.scrolling = !1, t
                    }
                    class Oe extends _e {
                        constructor(e, t) {
                            super(e.elementSelectors, {
                                ...e,
                                rect: new DOMRect(0, 0, 0, 0),
                                className: e.className + " custom-element-augmentation"
                            }, t, e.innerRect ? new DOMRect(e.innerRect.left, e.innerRect.top, e.innerRect.width, e.innerRect.height) : void 0), this._desc = e
                        }
                        elementRectUpdated() {
                            const e = this._utils.valueOrDefault(this._desc.xPadding, this._config.augmentationDefaultStyles[this._desc.type].xPadding || 0),
                                t = this._utils.valueOrDefault(this._desc.yPadding, this._config.augmentationDefaultStyles[this._desc.type].yPadding || 0);
                            this.setProp("rect", new DOMRect(this._rect.x - e, this._rect.y - t, this._rect.width + 2 * e, this._rect.height + 2 * t))
                        }
                        update(e) {
                            this._desc = e, this.setSelectors(e.elementSelectors), this.setProp("innerRect", e.innerRect), this._innerRect = e.innerRect ? new DOMRect(e.innerRect.left, e.innerRect.top, e.innerRect.width, e.innerRect.height) : void 0
                        }
                    }

                    function Te(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "24",
                            height: "24",
                            viewBox: "0 0 24 24",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M19 12H5",
                            stroke: "black",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M12 19L5 12L12 5",
                            stroke: "black",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n"])
                    }

                    function Me(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "24",
                            height: "24",
                            viewBox: "0 0 24 24",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M5 12H19",
                            stroke: "white",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M12 5L19 12L12 19",
                            stroke: "white",
                            "stroke-width": "2",
                            "stroke-linecap": "round",
                            "stroke-linejoin": "round"
                        }, []), "\n"])
                    }
                    var Re;
                    ! function(e) {
                        e.IncomingEnvelope = "IncomingEnvelope"
                    }(Re || (Re = {}));
                    const Pe = {
                        [Re.IncomingEnvelope]: function(e) {
                            e.styles;
                            var t = Object.assign({}, e);
                            return delete t.styles, (0, A.h)("svg", Object.assign({
                                width: "62",
                                height: "62",
                                viewBox: "0 0 62 62",
                                fill: "none",
                                xmlns: "http://www.w3.org/2000/svg"
                            }, t), ["\n", (0, A.h)("path", {
                                d: "M12.0556 20.6666C12.0556 21.6172 11.284 22.3888 10.3333 22.3888H1.72222C0.771556 22.3888 0 21.6172 0 20.6666C0 19.7159 0.771556 18.9443 1.72222 18.9443H10.3333C11.284 18.9443 12.0556 19.7159 12.0556 20.6666ZM8.61111 29.2777C8.61111 30.2283 7.83956 30.9999 6.88889 30.9999H1.72222C0.771556 30.9999 0 30.2283 0 29.2777C0 28.327 0.771556 27.5554 1.72222 27.5554H6.88889C7.83956 27.5554 8.61111 28.327 8.61111 29.2777ZM5.16667 37.8888C5.16667 38.8412 4.39511 39.611 3.44444 39.611H1.72222C0.771556 39.611 0 38.8412 0 37.8888C0 36.9364 0.771556 36.1666 1.72222 36.1666H3.44444C4.39511 36.1666 5.16667 36.9364 5.16667 37.8888Z",
                                fill: "#55ACEE"
                            }, []), "\n", (0, A.h)("path", {
                                d: "M55.6291 43.0556C54.551 46.8599 50.5916 49.9444 46.7873 49.9444H12.3428C8.53842 49.9444 6.32881 46.8599 7.40692 43.0556L13.259 22.3889C14.3371 18.5845 18.2948 15.5 22.0992 15.5H56.5436C60.348 15.5 62.5594 18.5845 61.4813 22.3889L55.6291 43.0556Z",
                                fill: "#CCD6DD"
                            }, []), "\n", (0, A.h)("path", {
                                d: "M29.8569 30.3732L7.55069 46.4123C7.49213 46.4605 7.45769 46.5208 7.4043 46.569C7.71257 47.5507 8.29641 48.3653 9.11274 48.9525C9.17302 48.9129 9.23846 48.8957 9.29702 48.8492L31.6032 32.8084C32.4661 32.135 32.7761 31.0466 32.2939 30.3732C31.8099 29.6998 30.7215 29.6998 29.8569 30.3732ZM53.6408 46.569C53.615 46.5208 53.6132 46.4605 53.5822 46.414L40.3659 30.3732C39.882 29.6998 38.7935 29.6998 37.9272 30.3732C37.0644 31.0466 36.7561 32.135 37.2384 32.8084L50.4581 48.8492C50.4891 48.894 50.546 48.9129 50.5821 48.9525C51.7291 48.367 52.7762 47.5507 53.6408 46.569Z",
                                fill: "#99AAB5"
                            }, []), "\n", (0, A.h)("path", {
                                d: "M61.482 22.3889C62.5601 18.5845 60.3488 15.5 56.5444 15.5H22.1C18.2956 15.5 14.3379 18.5845 13.2598 22.3889L13.2236 22.5163L28.3895 37.0726C31.1985 39.8006 34.9133 39.6128 38.2492 37.7115L61.0291 23.9957L61.482 22.3889Z",
                                fill: "#99AAB5"
                            }, []), "\n", (0, A.h)("path", {
                                d: "M56.544 15.5H22.0995C19.3819 15.5 16.6074 17.0862 14.8369 19.3716L30.7106 34.5168C32.0006 35.7551 34.9025 35.7723 37.0071 34.5168L61.6245 19.4163C61.1664 17.1068 59.2789 15.5 56.544 15.5Z",
                                fill: "#E1E8ED"
                            }, []), "\n"])
                        }
                    };

                    function De(e) {
                        const [t, n] = (0, V.eJ)(), i = (0, V.sO)(), [o, r] = (0, V.eJ)(null), [a, s] = (0, V.eJ)(e.text), l = (0, V.I4)((e => {
                            n(e), new ResizeObserver((() => {
                                i.current && 0 === i.current.offsetHeight || (i.current && (e.style.maxHeight = `${i.current.offsetHeight}px`), i.current && (e.style.minHeight = `${i.current.offsetHeight}px`))
                            })).observe(i.current)
                        }), []), c = (0, V.I4)((e => {
                            setTimeout((() => e && (e.style.opacity = "1", 100))), r(e)
                        }), []);
                        if ((0, V.d4)((() => {
                                o && (o.style.transition = "opacity 0.3s ease-in-out", o.style.opacity = "1")
                            }), [a]), (0, V.d4)((() => {
                                t && i.current && o && (o.style.transition = "none", o.style.opacity = "0", s(e.text))
                            }), [e.text]), !e.anchorPoint) return null;
                        const d = e.fixed ? {
                            position: "fixed"
                        } : {};
                        switch (e.placement) {
                            case Z.H.Top:
                                d.bottom = `${e.anchorPoint.y}px`, d.left = `${e.anchorPoint.x}px`;
                                break;
                            case Z.H.Left:
                                d.top = `${e.anchorPoint.y}px`, d.right = `${e.anchorPoint.x}px`;
                                break;
                            case Z.H.Right:
                            case Z.H.Bottom:
                                d.top = `${e.anchorPoint.y}px`, d.left = `${e.anchorPoint.x}px`
                        }
                        e.scrolling && (d.transition = "none");
                        const u = e.titleImage && Pe[e.titleImage];
                        return T("div", Object.assign({
                            ref: l,
                            className: "walkthrough-box" + (e.nextText || e.prevText ? " wide visible" : ""),
                            style: d
                        }, {
                            children: T("div", Object.assign({
                                ref: i,
                                className: "walkthrough-box-content-wrapper"
                            }, {
                                children: [u && T("div", Object.assign({
                                    className: "title-image-wrapper"
                                }, {
                                    children: T(u, {}, void 0)
                                }), void 0), T("div", Object.assign({
                                    className: "walkthrough-box-content-padding"
                                }, {
                                    children: [T("div", {
                                        ref: c,
                                        className: "text",
                                        dangerouslySetInnerHTML: {
                                            __html: a
                                        }
                                    }, void 0), T("div", {
                                        className: "closeButton"
                                    }, void 0), T("div", Object.assign({
                                        className: "buttons-wrapper"
                                    }, {
                                        children: [T("div", Object.assign({
                                            className: `button ${e.prevText?" button-text":""}${1===e.index?"invisible":""}`,
                                            onClick: e.prevHandler
                                        }, {
                                            children: e.prevText ? e.prevText : T(Te, {}, void 0)
                                        }), void 0), T("div", Object.assign({
                                            className: "progress"
                                        }, {
                                            children: `${e.index} of ${e.total}`
                                        }), void 0), T("div", Object.assign({
                                            className: "button primary" + (e.nextText ? " button-text" : ""),
                                            onClick: e.nextHandler
                                        }, {
                                            children: e.nextText ? e.nextText : T(Me, {}, void 0)
                                        }), void 0)]
                                    }), void 0)]
                                }), void 0)]
                            }), void 0)
                        }), void 0)
                    }
                    var je;
                    ! function(e) {
                        e.Element = "Element", e.Standalone = "Standalone", e.Simple = "Simple"
                    }(je || (je = {}));
                    const Le = {
                        [Z.p.Custom]: {
                            baseType: je.Element,
                            component: Ie,
                            transformer: Ae
                        },
                        [Z.p.Disabler]: {
                            baseType: je.Element,
                            component: Ie,
                            transformer: Ae
                        },
                        [Z.p.DangerFrame]: {
                            baseType: je.Element,
                            component: Ie,
                            transformer: Ae
                        },
                        [Z.p.WarningFrame]: {
                            baseType: je.Element,
                            component: Ie,
                            transformer: Ae
                        },
                        [Z.p.Flashlight]: {
                            baseType: je.Element,
                            component: function(e) {
                                const {
                                    top: t,
                                    bottom: n,
                                    left: i,
                                    right: o
                                } = e.rect, {
                                    offsetWidth: r,
                                    offsetHeight: a
                                } = document.body;
                                return T(A.HY, {
                                    children: [T("div", {
                                        className: "flashlight-shadow",
                                        style: {
                                            top: "0px",
                                            left: "0px",
                                            width: `${r}px`,
                                            height: `${t}px`
                                        }
                                    }, void 0), T("div", {
                                        className: "flashlight-shadow",
                                        style: {
                                            top: `${n}px`,
                                            left: "0px",
                                            width: `${r}px`,
                                            height: a - n + "px"
                                        }
                                    }, void 0), T("div", {
                                        className: "flashlight-shadow",
                                        style: {
                                            top: `${t}px`,
                                            left: "0px",
                                            width: `${i}px`,
                                            height: n - t + "px"
                                        }
                                    }, void 0), T("div", {
                                        className: "flashlight-shadow",
                                        style: {
                                            top: `${t}px`,
                                            left: `${o}px`,
                                            width: r - o + "px",
                                            height: n - t + "px"
                                        }
                                    }, void 0), T("div", {
                                        className: "flashlight",
                                        style: {
                                            top: `${t}px`,
                                            left: `${i}px`,
                                            width: o - i + "px",
                                            height: n - t + "px"
                                        }
                                    }, void 0)]
                                }, void 0)
                            },
                            singleton: !0,
                            transformer: Ae
                        },
                        [Z.p.Button]: {
                            baseType: je.Simple,
                            component: function(e) {
                                return T("div", Object.assign({
                                    onClick: e.clickHandler,
                                    class: "button"
                                }, {
                                    children: e.text
                                }), void 0)
                            },
                            transformer: function(e, t, n) {
                                return {
                                    ...e,
                                    clickHandler: () => n("", ue.OP.Automatic, t, e.nextItem)
                                }
                            }
                        },
                        [Z.p.WalkthroughBox]: {
                            baseType: je.Standalone,
                            class: class extends _e {
                                constructor(e) {
                                    super(e.elementSelectors, {
                                        ...e
                                    }, De, e.innerRect ? new DOMRect(e.innerRect.left, e.innerRect.top, e.innerRect.width, e.innerRect.height) : void 0)
                                }
                                init(e, t) {
                                    super.init(e, t), this.update(this.props())
                                }
                                getPoint(e) {
                                    const t = void 0 !== this.props().xPadding ? this.props().xPadding : 25,
                                        n = void 0 !== this.props().yPadding ? this.props().yPadding : 10;
                                    if (!this._rect) return null;
                                    switch (e) {
                                        case Z.H.Top:
                                            return new DOMPoint(this._rect.left + t, document.body.offsetHeight - this._rect.y + n, 1, 1);
                                        case Z.H.Bottom:
                                            return new DOMPoint(this._rect.left + t, this._rect.y + n, 1, 1);
                                        case Z.H.Left:
                                            return new DOMPoint(document.body.offsetWidth - this._rect.left - t, this._rect.y - n, 1, 1);
                                        case Z.H.Right:
                                            return new DOMPoint(this._rect.right + t, this._rect.y - n, 1, 1)
                                    }
                                }
                                update(e) {
                                    this.setProp("anchorPoint", this.getPoint(e.placement)), this.setProp("index", e.index), this.setProp("text", e.text), this.setProp("nextHandler", e.nextHandler), this.setProp("prevHandler", e.prevHandler), this.setProp("placement", e.placement), this.setProp("nextText", e.nextText), this.setProp("prevText", e.prevText), this.setProp("xPadding", e.xPadding), this.setProp("yPadding", e.yPadding), this.setProp("innerRect", e.innerRect), this._innerRect = e.innerRect ? new DOMRect(e.innerRect.left, e.innerRect.top, e.innerRect.width, e.innerRect.height) : void 0, this.setProp("titleImage", e.titleImage), this.setSelectors(e.elementSelectors), (async () => {
                                        try {
                                            const t = await this._domUtils.getElementWithTimeout(e.elementSelectors, this._config.elementAugmentationWaitMs);
                                            t && !this._domUtils.isPositionFixed(e.elementSelectors) && t && t.scrollIntoView({
                                                block: "center",
                                                behavior: "smooth"
                                            })
                                        } catch {}
                                    })()
                                }
                                elementRectUpdated() {
                                    this.setProp("anchorPoint", this.getPoint(this.props().placement))
                                }
                            },
                            singleton: !0,
                            transformer: function(e, t, n) {
                                return {
                                    ...e,
                                    nextHandler: () => () => n("", ue.OP.Automatic, t, e.nextButton),
                                    prevHandler: () => () => n("", ue.OP.Automatic, t, e.prevButton),
                                    placement: e.placement || Z.H.Right,
                                    index: 1,
                                    total: 1,
                                    anchorPoint: new DOMPoint,
                                    scrolling: !1
                                }
                            }
                        },
                        [Z.p.FocusMask]: {
                            baseType: je.Element,
                            component: function(e) {
                                const t = window.innerHeight,
                                    n = document.body.offsetWidth,
                                    i = e.rect.top / t * 100 + "%",
                                    o = e.rect.bottom / t * 100 + "%",
                                    r = e.rect.left / n * 100 + "%",
                                    a = e.rect.right / n * 100 + "%";
                                return T("div", {
                                    className: "focus-mask",
                                    style: {
                                        clipPath: `polygon(0% 0%, 0% 100%, ${r} 100%, ${r} ${i}, ${a} ${i},${a} ${o}, ${r} ${o}, ${r} 100%, 100% 100%, 100% 0%)`,
                                        ...e.fixed ? {
                                            position: "fixed"
                                        } : {},
                                        ...e.scrolling ? {
                                            transition: "none"
                                        } : {}
                                    }
                                }, void 0)
                            },
                            singleton: !0,
                            transformer: Ae
                        },
                        [Z.p.IFrame]: {
                            baseType: je.Simple,
                            component: function(e) {
                                return T("div", Object.assign({
                                    className: "iframe-aug-wrapper",
                                    style: {
                                        zIndex: e.zIndex
                                    }
                                }, {
                                    children: [T("div", {
                                        className: "iframe-aug-bg-mask"
                                    }, void 0), T("iframe", {
                                        src: e.url,
                                        className: "iframe-aug",
                                        onLoad: e.onLoad
                                    }, void 0)]
                                }), void 0)
                            },
                            transformer: function(e, t, n) {
                                return {
                                    ...e,
                                    onLoad: () => e.nextItem ? n("", ue.OP.Automatic, t, e.nextItem) : {}
                                }
                            },
                            singleton: !0
                        },
                        [Z.p.BlurMask]: {
                            baseType: je.Simple,
                            component: function(e) {
                                return T("div", {
                                    className: "meddler-blur-mask",
                                    style: {
                                        backgroundColor: e.backgroundHue ? `rgba(${e.backgroundHue}, ${e.backgroundHue}, ${e.backgroundHue}, 0.2)` : void 0,
                                        backdropFilter: e.size ? `blur(${e.size}px)` : void 0
                                    }
                                }, void 0)
                            }
                        },
                        [Z.p.BubbleWithArrow]: {
                            baseType: je.Simple,
                            component: function(e) {
                                const t = T("div", {
                                    dangerouslySetInnerHTML: {
                                        __html: e.content
                                    }
                                }, void 0);
                                return T(Ce, Object.assign({}, {
                                    ...e,
                                    content: t
                                }), void 0)
                            }
                        },
                        [Z.p.UrlBubble]: {
                            baseType: je.Simple,
                            component: function(e) {
                                let t = "18px";
                                e.url.length > 30 && (t = "16px"), e.url.length > 45 && (t = "14px");
                                const n = T("div", Object.assign({
                                        className: "bubble-urlbar"
                                    }, {
                                        children: T("div", Object.assign({
                                            className: "bubbler-spacer"
                                        }, {
                                            children: [T(ke, {}, void 0), T("div", {
                                                className: "bubble-urlbar-text",
                                                style: {
                                                    fontSize: t
                                                },
                                                dangerouslySetInnerHTML: {
                                                    __html: e.url
                                                }
                                            }, void 0)]
                                        }), void 0)
                                    }), void 0),
                                    {
                                        arrowSide: i,
                                        arrowPlacement: o,
                                        position: r
                                    } = e,
                                    a = {
                                        arrowSide: i || Z.H.Top,
                                        arrowPlacement: o || .5,
                                        position: r || {
                                            x: .1,
                                            y: .02
                                        },
                                        fixed: !0,
                                        content: n
                                    };
                                return T(Ce, Object.assign({}, {
                                    ...a,
                                    content: n
                                }), void 0)
                            }
                        }
                    };
                    var Fe = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    const He = "fading-children";
                    let Be = class extends se {
                        constructor(e, t) {
                            super({
                                props: {
                                    visible: !0,
                                    augmentations: []
                                },
                                nodeId: "us-meddler-root",
                                css: be,
                                componentFunc: xe,
                                supportEvents: !1
                            }), this._augmentations = {}, this._singletons = {}, this._downloader = e, this._toolbox = t, this.clearAll(), this.initFader(), this.fadeAugmentations(!0)
                        }
                        augment(e, t = []) {
                            const n = [];
                            t.length && !this._augmentations[e] && (this._augmentations[e] = []);
                            const i = (t, i) => {
                                this._augmentations[t.context || e].push(i), n.push(i.draw)
                            };
                            for (const e of t) {
                                e.context && (this._augmentations[e.context] || (this._augmentations[e.context] = []));
                                const t = Le[e.type];
                                if (t.singleton && this._singletons[e.type]) {
                                    this._singletons[e.type].update && this._singletons[e.type].update(e);
                                    continue
                                }
                                let n;
                                switch (t.baseType) {
                                    case je.Standalone:
                                        n = new t.class(e);
                                        break;
                                    case je.Simple:
                                        n = new q(e, t.component);
                                        break;
                                    case je.Element:
                                        n = new Oe(e, t.component)
                                }
                                n.init(this._toolbox, this.node()), t.singleton && (this._singletons[e.type] = n), i(e, n)
                            }
                            n.length && this.setProp(ve.Augmentations, [...this.props().augmentations, ...n])
                        }
                        contextDone(e) {
                            const t = e => {
                                const t = [...this.props().augmentations];
                                this._toolbox.common.removeValFromArray(t, e) && this.setProp(ve.Augmentations, t)
                            };
                            if (this._augmentations[e]) {
                                for (const n of this._augmentations[e]) this._singletons[n.getType()] && delete this._singletons[n.getType()], n.remove ? n.remove((() => t(n.draw))) : t(n.draw);
                                delete this._augmentations[e]
                            }
                        }
                        clearAll() {
                            Object.keys(this._augmentations).forEach((e => this.contextDone(e))), this.setProp(ve.Augmentations, [...this.props().augmentations, this._downloader.draw]), this._augmentations["__-download-manager-__"] = [this._downloader]
                        }
                        fadeAugmentations(e) {
                            e ? this.meddlerRoot.classList.add(He) : this.meddlerRoot.classList.remove(He)
                        }
                        initFader() {
                            new MutationObserver((e => {
                                e.forEach((e => {
                                    e.addedNodes.forEach((e => {
                                        e instanceof HTMLDivElement && setTimeout((() => e.classList.add("visible")), 1)
                                    }))
                                }))
                            })).observe(this.meddlerRoot, {
                                childList: !0
                            })
                        }
                        get meddlerRoot() {
                            return this.node().querySelector("div#meddler")
                        }
                        processItemAugmentations(e, t, n) {
                            return e.map((e => Le[e.type].transformer ? Le[e.type].transformer(e, t, n) : e))
                        }
                    };
                    Be = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Fe(0, (0, I.f)(w.IDownloader)), Fe(1, (0, I.f)(Y.IToolbox)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], Be);
                    var Ne = n(5863),
                        Ue = {};
                    Ne.Z && Ne.Z.locals && (Ue.locals = Ne.Z.locals);
                    var Ve, ze = 0,
                        We = {};
                    We.styleTagTransform = p(), We.setAttributes = l(), We.insert = function(e, t) {
                        t.target.appendChild(e)
                    }, We.domAPI = a(), We.insertStyleElement = d(), Ue.use = function(e) {
                        return We.options = e || {}, ze++ || (Ve = o()(Ne.Z, We)), Ue
                    }, Ue.unuse = function() {
                        ze > 0 && !--ze && (Ve(), Ve = null)
                    };
                    const Ge = Ue;

                    function $e(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            viewBox: "0 0 398 398",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n    ", (0, A.h)("g", {
                            "fill-rule": "nonzero",
                            fill: "none"
                        }, ["\n        ", (0, A.h)("circle", {
                            fill: "#ffffff",
                            cx: "199",
                            cy: "199",
                            r: "199"
                        }, []), "\n        ", (0, A.h)("path", {
                            d: "M302.7 239.8c-22.8-35.6-61.5-56.9-103.7-56.9s-81 21.3-103.7 56.9l-27.1-17.3c28.7-44.9 77.6-71.8 130.8-71.8 53.2 0 102.1 26.8 130.8 71.8l-27.1 17.3z",
                            fill: "#9B51E0"
                        }, []), "\n        ", (0, A.h)("path", {
                            d: "M199 247.3c-53.2 0-102.1-26.8-130.8-71.8l27.1-17.3c22.8 35.6 61.5 56.9 103.7 56.9s81-21.3 103.7-56.9l27.1 17.3c-28.7 44.9-77.6 71.8-130.8 71.8z",
                            fill: "#10196B"
                        }, []), "\n        ", (0, A.h)("path", {
                            d: "M302.7 239.8c-22.8-35.6-61.5-56.9-103.7-56.9-18.9 0-36.9 4.2-53.7 12.3l-14.1-28.9c21.2-10.3 44-15.6 67.8-15.6 53.2 0 102.1 26.8 130.8 71.8l-27.1 17.3z",
                            fill: "#9B51E0"
                        }, []), "\n    "]), "\n"])
                    }

                    function qe(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "41",
                            height: "13",
                            viewBox: "0 0 41 13",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n    ", (0, A.h)("path", {
                            d: "M6.804 12.891V2.665a9.272 9.272 0 0 1 3.228 1.052l.816-2.285A10.96 10.96 0 0 0 5.415 0c-.972 0-1.92.12-2.846.363C1.643.604.787.955 0 1.414l.816 2.303a9.596 9.596 0 0 1 3.228-1.052v10.226h2.76zm8.72.109c.625 0 1.186-.13 1.683-.39.498-.26.915-.631 1.25-1.115v1.396h2.656V3.137h-2.656V4.55c-.706-1.015-1.712-1.523-3.02-1.523-.856 0-1.611.208-2.265.625-.654.417-1.16.998-1.519 1.741-.358.743-.538 1.605-.538 2.584 0 .99.182 1.867.547 2.629.364.761.88 1.35 1.545 1.767.665.417 1.437.626 2.317.626zm.625-2.248c-.695 0-1.259-.251-1.693-.753-.434-.501-.656-1.151-.668-1.949.012-.798.234-1.447.668-1.949.434-.502.998-.752 1.693-.752.625 0 1.148.217 1.57.652.423.436.669 1.01.738 1.723v.653c-.07.713-.315 1.287-.738 1.722-.422.435-.945.653-1.57.653zm10.664 2.14V8.194c0-.773.24-1.393.72-1.858.48-.466 1.131-.698 1.953-.698.185 0 .324.006.416.018v-2.63c-.694.013-1.302.176-1.822.49-.521.315-.943.774-1.267 1.378V3.137H24.14v9.754h2.673zM35.41 13c.625 0 1.186-.13 1.684-.39.497-.26.914-.631 1.25-1.115v1.396H41V3.137h-2.656V4.55c-.705-1.015-1.712-1.523-3.02-1.523-.856 0-1.611.208-2.265.625-.653.417-1.16.998-1.518 1.741-.36.743-.539 1.605-.539 2.584 0 .99.183 1.867.547 2.629.365.761.88 1.35 1.545 1.767.665.417 1.438.626 2.317.626zm.625-2.248c-.694 0-1.258-.251-1.692-.753-.434-.501-.657-1.151-.669-1.949.012-.798.235-1.447.669-1.949.434-.502.998-.752 1.692-.752.625 0 1.148.217 1.57.652.423.436.669 1.01.738 1.723v.653c-.069.713-.315 1.287-.737 1.722-.423.435-.946.653-1.571.653z",
                            fill: "#FFF",
                            "fill-rule": "nonzero"
                        }, []), "\n"])
                    }

                    function Ye(e) {
                        return T("div", Object.assign({
                            className: "tara-header"
                        }, {
                            children: [T("div", Object.assign({
                                className: "tara-header-component"
                            }, {
                                children: [T("div", Object.assign({
                                    id: "tara-header-logo"
                                }, {
                                    children: T($e, {}, void 0)
                                }), void 0), T(qe, {}, void 0)]
                            }), void 0), T("div", Object.assign({
                                className: "tara-header-component"
                            }, {
                                children: [T("div", {
                                    id: "status"
                                }, void 0), T("div", Object.assign({
                                    id: "minimizer",
                                    onClick: e.close
                                }, {
                                    children: T("div", {}, void 0)
                                }), void 0)]
                            }), void 0)]
                        }), void 0)
                    }
                    var Je, Ze;

                    function Xe(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "47",
                            height: "47",
                            viewBox: "0 0 47 47",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M6.35366 11.9011C7.58231 11.0423 9.43445 11.207 10.5376 12.118L9.27237 10.279C8.25415 8.82681 8.61883 7.2557 10.0723 6.23618C11.5258 5.22058 15.6444 7.95107 15.6444 7.95107C14.617 6.48452 14.8092 4.62585 16.2757 3.59718C17.7422 2.57243 19.7656 2.92665 20.793 4.39581L34.4128 23.636L32.677 40.4647L18.1906 35.1815L5.55503 16.4471C4.51852 14.9714 4.87666 12.9363 6.35366 11.9011Z",
                            fill: "#D2A077"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M3.52264 22.6047C3.52264 22.6047 2.04303 20.448 4.20102 18.9697C6.35639 17.4914 7.8347 19.6468 7.8347 19.6468L14.6982 29.6564C14.9348 29.2617 15.1936 28.8722 15.4824 28.4879L5.95643 14.5975C5.95643 14.5975 4.47812 12.4422 6.6348 10.9639C8.79018 9.48555 10.2685 11.6409 10.2685 11.6409L19.2285 24.7078C19.5618 24.4359 19.903 24.1628 20.2546 23.8948L9.86721 8.74443C9.86721 8.74443 8.3889 6.58906 10.5456 5.11075C12.701 3.63244 14.1793 5.78782 14.1793 5.78782L24.5666 20.9356C24.9483 20.7016 25.3261 20.499 25.7051 20.2846L15.9961 6.12635C15.9961 6.12635 14.5178 3.97097 16.6732 2.49267C18.8286 1.01436 20.3069 3.16973 20.3069 3.16973L30.5727 18.141L32.1333 20.418C25.6659 24.8542 25.0503 33.1999 28.7454 38.589C29.4839 39.6673 30.5622 38.9288 30.5622 38.9288C26.1273 32.4601 27.4814 25.1914 33.9502 20.7565L32.0431 11.2122C32.0431 11.2122 31.3308 8.69738 33.8443 7.98371C36.3591 7.27135 37.0728 9.78617 37.0728 9.78617L39.2752 16.3268C40.1483 18.9201 41.0777 21.5042 42.3076 23.9484C45.7806 30.8498 43.7062 39.4268 37.1577 43.9193C30.0145 48.8169 20.2494 46.9961 15.3504 39.8543L3.52264 22.6047Z",
                            fill: "#F3D2A2"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M15.6849 41.8264C10.4566 41.8264 5.17337 36.5432 5.17337 31.3149C5.17337 30.5921 4.644 30.0078 3.92118 30.0078C3.19837 30.0078 2.5592 30.5921 2.5592 31.3149C2.5592 39.1574 7.84242 44.4406 15.6849 44.4406C16.4077 44.4406 16.992 43.8014 16.992 43.0786C16.992 42.3558 16.4077 41.8264 15.6849 41.8264Z",
                            fill: "#5DADEC"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M9.14956 44.3857C5.22832 44.3857 2.61416 41.7715 2.61416 37.8503C2.61416 37.1274 2.0299 36.5432 1.30708 36.5432C0.584265 36.5432 0 37.1274 0 37.8503C0 43.0786 3.92124 46.9998 9.14956 46.9998C9.87238 46.9998 10.4566 46.4156 10.4566 45.6927C10.4566 44.9699 9.87238 44.3857 9.14956 44.3857ZM31.3699 2.55908C30.6484 2.55908 30.0628 3.14465 30.0628 3.86616C30.0628 4.58767 30.6484 5.17324 31.3699 5.17324C36.5983 5.17324 41.8266 9.86435 41.8266 15.6299C41.8266 16.3514 42.4121 16.937 43.1337 16.937C43.8552 16.937 44.4407 16.3514 44.4407 15.6299C44.4407 8.42264 39.2124 2.55908 31.3699 2.55908Z",
                            fill: "#5DADEC"
                        }, []), "\n", (0, A.h)("path", {
                            d: "M37.9053 0C37.1838 0 36.5983 0.530675 36.5983 1.25218C36.5983 1.97369 37.1838 2.61416 37.9053 2.61416C41.8266 2.61416 44.3859 5.52242 44.3859 9.09467C44.3859 9.81617 45.025 10.4017 45.7478 10.4017C46.4706 10.4017 47 9.81617 47 9.09467C47 4.0794 43.1337 0 37.9053 0Z",
                            fill: "#5DADEC"
                        }, []), "\n"])
                    }! function(e) {
                        e.Primary = "Primary", e.Secondary = "Secondary", e.Image = "Image"
                    }(Je || (Je = {})),
                    function(e) {
                        e.Tara = "Tara", e.User = "User", e.Title = "Title", e.CategoryMultiSelect = "CategoryMultiSelect"
                    }(Ze || (Ze = {}));
                    const Ke = JSON.parse('{"v":"5.5.7","meta":{"g":"LottieFiles AE 0.1.20","a":"","k":"","d":"","tc":"#FFFFFF"},"fr":60,"ip":0,"op":120,"w":279,"h":164,"nm":"â–½ Confetti","ddd":0,"assets":[],"layers":[{"ddd":0,"ind":1,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":2,"ty":4,"nm":"Oval","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[139,100.5,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-34.52,0],[0,34.52],[34.52,0],[0,-34.52]],"o":[[34.52,0],[0,-34.52],[-34.52,0],[0,34.52]],"v":[[0,62.5],[62.5,0],[0,-62.5],[-62.5,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"gf","o":{"a":0,"k":100,"ix":10},"r":1,"bm":0,"g":{"p":5,"k":{"a":0,"k":[0,1,1,1,0.254,1,1,1,0.508,1,1,1,0.754,1,1,1,1,1,1,1,0,1,0.254,0.997,0.508,0.993,0.754,0.497,1,0],"ix":9}},"s":{"a":0,"k":[0,0],"ix":5},"e":{"a":0,"k":[0,60.043],"ix":6},"t":2,"h":{"a":0,"k":0,"ix":7},"a":{"a":0,"k":0,"ix":8},"nm":"Gradient Fill 1","mn":"ADBE Vector Graphic - G-Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":4,"ty":4,"nm":"Shape Layer 2","sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":-22,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.098,"y":0.862},"o":{"x":0.47,"y":0},"t":0,"s":[140,91.717,0],"to":[-14.225,-0.927,0],"ti":[16.939,1.104,0]},{"i":{"x":0.627,"y":1},"o":{"x":0.295,"y":0.637},"t":87,"s":[53.373,85.946,0],"to":[-0.576,-0.038,0],"ti":[0.484,0.032,0]},{"t":110,"s":[51.75,85.967,0]}],"ix":2},"a":{"a":0,"k":[52.25,38.25,0],"ix":1},"s":{"a":0,"k":[100,101.875,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0]],"o":[[0,0],[0,0]],"v":[[47.5,36.5],[70.799,46.598]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[1,0.780392169952,0.019607843831,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":6,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"fl","c":{"a":0,"k":[0.386458004222,0.386458004222,0.386458004222,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Shape 1","np":3,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":0,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":100,"s":[100]},{"t":110,"s":[0]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":6,"ty":4,"nm":"Shape Layer 4","sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":56,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.022,"y":1},"o":{"x":0.404,"y":0},"t":0,"s":[140,91.717,0],"to":[2.458,9.042,0],"ti":[-2.458,-9.042,0]},{"t":109,"s":[154.75,145.967,0]}],"ix":2},"a":{"a":0,"k":[52.25,38.25,0],"ix":1},"s":{"a":0,"k":[100,101.875,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0]],"o":[[0,0],[0,0]],"v":[[43.468,32.055],[67.192,40.088]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[1,0.505882382393,0.427451014519,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":4,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"fl","c":{"a":0,"k":[0.386458004222,0.386458004222,0.386458004222,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Shape 1","np":3,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":100,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":100,"s":[0]},{"t":110,"s":[100]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":8,"ty":4,"nm":"Shape Layer 3","sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":56,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.022,"y":1},"o":{"x":0.404,"y":0},"t":0,"s":[140,91.717,0],"to":[-3.375,-9.292,0],"ti":[3.375,9.292,0]},{"t":109,"s":[119.75,35.967,0]}],"ix":2},"a":{"a":0,"k":[52.25,38.25,0],"ix":1},"s":{"a":0,"k":[100,101.875,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0]],"o":[[0,0],[0,0]],"v":[[47.5,36.5],[57,40]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.184313729405,0.282352954149,0.980392158031,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":4,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"fl","c":{"a":0,"k":[0.386458004222,0.386458004222,0.386458004222,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Shape 1","np":3,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":0,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":100,"s":[100]},{"t":110,"s":[0]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":10,"ty":4,"nm":"Shape Layer 1","sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":9,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.022,"y":1},"o":{"x":0.404,"y":0},"t":0,"s":[140,91.717,0],"to":[15.5,6.896,0],"ti":[-15.5,-6.896,0]},{"t":109,"s":[233,133.092,0]}],"ix":2},"a":{"a":0,"k":[52.25,38.25,0],"ix":1},"s":{"a":0,"k":[100,101.875,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0]],"o":[[0,0],[0,0]],"v":[[47.5,36.5],[57,40]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.184313729405,0.282352954149,0.980392158031,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":4,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"fl","c":{"a":0,"k":[0.386458004222,0.386458004222,0.386458004222,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Shape 1","np":3,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":100,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":100,"s":[0]},{"t":110,"s":[100]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":11,"ty":4,"nm":"â–¨ Confetti 6","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":12,"ty":4,"nm":"Oval 3","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.211,"y":1},"o":{"x":0.768,"y":0},"t":0,"s":[123.5,94.5,0],"to":[14.458,4.75,0],"ti":[-14.458,-4.75,0]},{"t":109,"s":[210.25,123,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":0,"s":[70,70,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[60,60,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[120,120,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-1.93,0],[0,1.93],[1.93,0],[0,-1.93]],"o":[[1.93,0],[0,-1.93],[-1.93,0],[0,1.93]],"v":[[0,3.5],[3.5,0],[0,-3.5],[-3.5,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[0.745098054409,0.360784322023,0.898039281368,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":13,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":14,"ty":4,"nm":"Oval 2","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.211,"y":1},"o":{"x":0.768,"y":0},"t":0,"s":[123.5,94.5,0],"to":[11.667,-3.333,0],"ti":[-11.667,3.333,0]},{"t":109,"s":[193.5,74.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":0,"s":[70,70,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[120,120,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-1.93,0],[0,1.93],[1.93,0],[0,-1.93]],"o":[[1.93,0],[0,-1.93],[-1.93,0],[0,1.93]],"v":[[0,3.5],[3.5,0],[0,-3.5],[-3.5,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[0.745098054409,0.360784322023,0.898039281368,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":15,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":16,"ty":4,"nm":"Oval","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.211,"y":1},"o":{"x":0.768,"y":0},"t":0,"s":[123.5,94.5,0],"to":[0,9.167,0],"ti":[0,-9.167,0]},{"t":110,"s":[123.5,149.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[120,120,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-1.93,0],[0,1.93],[1.93,0],[0,-1.93]],"o":[[1.93,0],[0,-1.93],[-1.93,0],[0,1.93]],"v":[[0,3.5],[3.5,0],[0,-3.5],[-3.5,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.780391991138,0.019608000293,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":17,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":18,"ty":4,"nm":"Rectangle Copy 4","tt":1,"sr":1,"ks":{"o":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":105,"s":[100]},{"t":110,"s":[0]}],"ix":11},"r":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":0,"s":[0]},{"t":110,"s":[720]}],"ix":10},"p":{"a":1,"k":[{"i":{"x":0,"y":1},"o":{"x":0.223,"y":0},"t":0,"s":[145.5,98.5,0],"to":[0.167,-8.5,0],"ti":[-0.167,8.5,0]},{"t":96,"s":[146.5,47.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":96,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[120,120,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[100,100,100]},{"t":110,"s":[120,120,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-2.5,-2.5],[2.5,-2.5],[2.5,2.5],[-2.5,2.5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.351772010326,0.246703997254,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":-289,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle Copy 4","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":19,"ty":4,"nm":"â–¨ Confetti 5","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":20,"ty":4,"nm":"Rectangle Copy 6","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":0,"s":[0]},{"t":110,"s":[1080]}],"ix":10},"p":{"a":1,"k":[{"i":{"x":0.134,"y":1},"o":{"x":0.167,"y":0.001},"t":0,"s":[121.5,95.5,0],"to":[19.167,2.5,0],"ti":[-19.167,-2.5,0]},{"t":109,"s":[236.5,110.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":90,"s":[100,100,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-2.5,-2.5],[2.5,-2.5],[2.5,2.5],[-2.5,2.5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.351772010326,0.246703997254,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":-289,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle Copy 3","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":21,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":22,"ty":4,"nm":"Rectangle Copy 3","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":0,"s":[0]},{"t":110,"s":[1080]}],"ix":10},"p":{"a":1,"k":[{"i":{"x":0.134,"y":1},"o":{"x":0.167,"y":0.001},"t":0,"s":[121.5,95.5,0],"to":[-14.167,7.5,0],"ti":[14.167,-7.5,0]},{"t":110,"s":[36.5,140.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":90,"s":[100,100,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-2.5,-2.5],[2.5,-2.5],[2.5,2.5],[-2.5,2.5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.351772010326,0.246703997254,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":-289,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle Copy 3","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":23,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":24,"ty":4,"nm":"Rectangle","tt":1,"sr":1,"ks":{"o":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":100,"s":[100]},{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":105,"s":[100]},{"t":110,"s":[0]}],"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0,"y":1},"o":{"x":0.413,"y":0},"t":0,"s":[135.379,104,0],"to":[13.083,-2.5,0],"ti":[-13.083,2.5,0]},{"t":110,"s":[213.879,89,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[130,130,100]},{"t":110,"s":[80,80,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-3.5,-3.5],[3.5,-3.5],[3.5,3.5],[-3.5,3.5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.780391991138,0.019608000293,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":-315,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":25,"ty":4,"nm":"â–¨ Confetti 4","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":26,"ty":4,"nm":"Oval Copy 4","tt":1,"sr":1,"ks":{"o":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":105,"s":[100]},{"t":110,"s":[0]}],"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.081,"y":1},"o":{"x":0.304,"y":0},"t":0,"s":[146,92,0],"to":[-14.167,2.917,0],"ti":[14.167,-2.917,0]},{"t":96,"s":[61,109.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":0,"s":[60,60,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":96,"s":[60,60,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":101,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[80,80,100]},{"t":110,"s":[100,100,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-2.21,0],[0,2.21],[2.21,0],[0,-2.21]],"o":[[2.21,0],[0,-2.21],[-2.21,0],[0,2.21]],"v":[[0,4],[4,0],[0,-4],[-4,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.101961001754,0.788235008717,0.768626987934,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval Copy","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":27,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":28,"ty":4,"nm":"Oval Copy 2","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.665,"y":1},"o":{"x":0.397,"y":0},"t":0,"s":[127,86,0],"to":[13.332,11.666,0],"ti":[-0.001,-0.001,0]},{"t":110,"s":[202,146,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[100,100,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-2.21,0],[0,2.21],[2.21,0],[0,-2.21]],"o":[[2.21,0],[0,-2.21],[-2.21,0],[0,2.21]],"v":[[0,4],[4,0],[0,-4],[-4,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.101961001754,0.788235008717,0.768626987934,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval Copy 2","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":29,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":30,"ty":4,"nm":"Oval Copy 3","tt":1,"sr":1,"ks":{"o":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":105,"s":[100]},{"t":110,"s":[0]}],"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.081,"y":1},"o":{"x":0.304,"y":0},"t":0,"s":[146,92,0],"to":[-9.167,-7.083,0],"ti":[9.167,7.083,0]},{"t":96,"s":[91,49.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":96,"s":[80,80,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":101,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[80,80,100]},{"t":110,"s":[100,100,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-2.21,0],[0,2.21],[2.21,0],[0,-2.21]],"o":[[2.21,0],[0,-2.21],[-2.21,0],[0,2.21]],"v":[[0,4],[4,0],[0,-4],[-4,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.101961001754,0.788235008717,0.768626987934,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval Copy","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":31,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":32,"ty":4,"nm":"Oval Copy","tt":1,"sr":1,"ks":{"o":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":105,"s":[100]},{"t":110,"s":[0]}],"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.081,"y":1},"o":{"x":0.304,"y":0},"t":0,"s":[146,92,0],"to":[-9.167,-7.083,0],"ti":[9.167,7.083,0]},{"t":96,"s":[91,49.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":96,"s":[80,80,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":101,"s":[100,100,100]},{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":105,"s":[80,80,100]},{"t":110,"s":[100,100,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[-2.21,0],[0,2.21],[2.21,0],[0,-2.21]],"o":[[2.21,0],[0,-2.21],[-2.21,0],[0,2.21]],"v":[[0,4],[4,0],[0,-4],[-4,0]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.101961001754,0.788235008717,0.768626987934,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Oval Copy","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":35,"ty":4,"nm":"â–¨ Confetti 3","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":36,"ty":4,"nm":"Path 2 Copy 2","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":133,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.166,"y":0.966},"o":{"x":0.399,"y":0},"t":0,"s":[141.5,96.5,0],"to":[13.333,-6.417,0],"ti":[-13.333,6.417,0]},{"t":110,"s":[221.5,58,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]],"v":[[-21,2.5],[-15.75,-2.5],[-10.5,2.5],[-5.25,-2.5],[0,2.5],[5.25,-2.5],[10.5,2.5],[15.75,-2.5],[21,2.5]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.113725498319,0.913725554943,0.717647075653,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":3.2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":28,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Path 2 Copy","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":0,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":80,"s":[100]},{"t":110,"s":[0]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":37,"ty":4,"nm":"â–¨ Confetti 9","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":38,"ty":4,"nm":"Path 2 Copy","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":1,"k":[{"i":{"x":0.166,"y":0.972},"o":{"x":0.399,"y":0},"t":0,"s":[141.5,96.5,0],"to":[-16.5,-7.333,0],"ti":[16.5,7.333,0]},{"t":110,"s":[42.5,52.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]],"v":[[-21,2.5],[-15.75,-2.5],[-10.5,2.5],[-5.25,-2.5],[0,2.5],[5.25,-2.5],[10.5,2.5],[15.75,-2.5],[21,2.5]],"c":false},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"st","c":{"a":0,"k":[0.745097994804,0.360783994198,0.898038983345,1],"ix":3},"o":{"a":0,"k":100,"ix":4},"w":{"a":0,"k":3.2,"ix":5},"lc":1,"lj":1,"ml":4,"bm":0,"nm":"Stroke 1","mn":"ADBE Vector Graphic - Stroke","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":28,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Path 2 Copy","np":2,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"tm","s":{"a":0,"k":0,"ix":1},"e":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":80,"s":[100]},{"t":110,"s":[0]}],"ix":2},"o":{"a":0,"k":0,"ix":3},"m":1,"ix":2,"nm":"Trim Paths 1","mn":"ADBE Vector Filter - Trim","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":39,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":40,"ty":4,"nm":"Rectangle Copy 5","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":0,"s":[-334]},{"t":110,"s":[26]}],"ix":10},"p":{"a":1,"k":[{"i":{"x":0.136,"y":1},"o":{"x":0.307,"y":0.03},"t":0,"s":[141.5,87,0],"to":[6.667,-6.917,0],"ti":[-6.667,6.917,0]},{"t":110,"s":[181.5,45.5,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":104,"s":[100,100,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[3.5,-3.5],[3.5,3.5],[-3.5,3.5],[-3.5,-3.5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ind":1,"ty":"sh","ix":2,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[2.1,-2.1],[-2.1,-2.1],[-2.1,2.1],[2.1,2.1]],"c":true},"ix":2},"nm":"Path 2","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"mm","mm":1,"nm":"Merge Paths 1","mn":"ADBE Vector Filter - Merge","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0.780391991138,0.019608000293,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle Copy 5","np":4,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":41,"ty":4,"nm":"â–¨ Confetti 2","parent":43,"td":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[0,0,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[-139.5,-82],[139.5,-82],[139.5,82],[-139.5,82]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Confetti","np":1,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false},{"ty":"fl","c":{"a":0,"k":[1,0,0,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":42,"ty":4,"nm":"Rectangle Copy 2","tt":1,"sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":1,"k":[{"i":{"x":[0.833],"y":[0.833]},"o":{"x":[0.167],"y":[0.167]},"t":0,"s":[-334]},{"t":110,"s":[26]}],"ix":10},"p":{"a":1,"k":[{"i":{"x":0.032,"y":1},"o":{"x":0.284,"y":0},"t":0,"s":[142,82,0],"to":[-10.833,10.833,0],"ti":[10.833,-10.833,0]},{"t":110,"s":[77,147,0]}],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":1,"k":[{"i":{"x":[0.833,0.833,0.833],"y":[0.833,0.833,0.833]},"o":{"x":[0.167,0.167,0.167],"y":[0.167,0.167,0.167]},"t":100,"s":[100,100,100]},{"t":110,"s":[0,0,100]}],"ix":6}},"ao":0,"shapes":[{"ty":"gr","it":[{"ind":0,"ty":"sh","ix":1,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[5,-5],[5,5],[-5,5],[-5,-5]],"c":true},"ix":2},"nm":"Path 1","mn":"ADBE Vector Shape - Group","hd":false},{"ind":1,"ty":"sh","ix":2,"ks":{"a":0,"k":{"i":[[0,0],[0,0],[0,0],[0,0]],"o":[[0,0],[0,0],[0,0],[0,0]],"v":[[3,-3],[-3,-3],[-3,3],[3,3]],"c":true},"ix":2},"nm":"Path 2","mn":"ADBE Vector Shape - Group","hd":false},{"ty":"mm","mm":1,"nm":"Merge Paths 1","mn":"ADBE Vector Filter - Merge","hd":false},{"ty":"fl","c":{"a":0,"k":[0.215686291456,0.309803932905,0.980392217636,1],"ix":4},"o":{"a":0,"k":100,"ix":5},"r":1,"bm":0,"nm":"Fill 1","mn":"ADBE Vector Graphic - Fill","hd":false},{"ty":"tr","p":{"a":0,"k":[0,0],"ix":2},"a":{"a":0,"k":[0,0],"ix":1},"s":{"a":0,"k":[100,100],"ix":3},"r":{"a":0,"k":0,"ix":6},"o":{"a":0,"k":100,"ix":7},"sk":{"a":0,"k":0,"ix":4},"sa":{"a":0,"k":0,"ix":5},"nm":"Transform"}],"nm":"Rectangle Copy 2","np":4,"cix":2,"bm":0,"ix":1,"mn":"ADBE Vector Group","hd":false}],"ip":0,"op":110,"st":0,"bm":0},{"ddd":0,"ind":43,"ty":3,"nm":"Confetti","sr":1,"ks":{"o":{"a":0,"k":100,"ix":11},"r":{"a":0,"k":0,"ix":10},"p":{"a":0,"k":[139.5,82,0],"ix":2},"a":{"a":0,"k":[0,0,0],"ix":1},"s":{"a":0,"k":[100,100,100],"ix":6}},"ao":0,"ip":0,"op":110,"st":0,"bm":0}],"markers":[]}');
                    var Qe = n(7364);
                    const et = {
                            [Qe.EV.ThumbsUp]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "24",
                                    height: "24",
                                    viewBox: "0 0 24 24",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("path", {
                                    d: "M23.237 11.2792C23.237 10.9582 23.1527 10.657 23.0115 10.3833C22.0697 7.62264 17.6604 7.8243 11.3886 7.68965C10.34 7.66731 10.9398 6.54226 11.3078 4.07264C11.5473 2.46643 10.4074 0 8.49147 0C5.33237 0 8.37137 2.26414 5.57818 7.86322C4.08572 10.8548 0.749634 9.17908 0.749634 12.1841V19.0244C0.749634 20.1941 0.876054 21.3185 2.68667 21.5036C4.44181 21.6829 4.04709 22.8194 6.57901 22.8194H19.2519C20.5428 22.8194 21.5928 21.8648 21.5928 20.6919C21.5928 20.2056 21.4053 19.7627 21.1026 19.4041C21.819 19.0397 22.3106 18.3518 22.3106 17.5541C22.3106 17.0691 22.1238 16.6262 21.8218 16.2682C22.5403 15.9045 23.0333 15.2159 23.0333 14.417C23.0333 13.8369 22.7748 13.3111 22.3584 12.9263C22.89 12.5364 23.237 11.9467 23.237 11.2792Z",
                                    fill: "#F2D1A1"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M14.0499 13.5746H20.8687C21.796 13.5746 22.6661 13.1823 23.1401 12.5511C23.335 12.291 23.2264 11.9544 22.8968 11.7996C22.5679 11.6448 22.1423 11.7319 21.9465 11.992C21.7223 12.2922 21.3078 12.4778 20.8679 12.4778H13.8859C13.194 12.4778 12.6313 12.0327 12.6313 11.4856C12.6313 10.9384 13.194 10.4934 13.8859 10.4934H18.5514C18.9342 10.4934 19.2449 10.2477 19.2449 9.94492C19.2449 9.64218 18.9342 9.39648 18.5514 9.39648H13.8851C12.4285 9.39648 11.2437 10.3335 11.2437 11.4856C11.2437 12.128 11.6201 12.6965 12.1986 13.0801C11.7112 13.4593 11.4077 13.9858 11.4077 14.5674C11.4077 15.2118 11.7865 15.7822 12.3682 16.1651C11.884 16.5437 11.5836 17.0683 11.5836 17.6487C11.5836 18.3507 12.0267 18.97 12.7003 19.3492C12.285 19.7184 12.0251 20.1991 12.0251 20.7306C12.0251 21.8826 13.2099 22.8197 14.6665 22.8197H19.0127C19.9399 22.8197 20.8109 22.4279 21.2848 21.7968C21.4805 21.5367 21.372 21.2001 21.0431 21.0453C20.7134 20.8917 20.2878 20.9763 20.0929 21.2364C19.867 21.5367 19.4525 21.7228 19.0127 21.7228H14.6665C13.9747 21.7228 13.412 21.2778 13.412 20.7306C13.412 20.1834 13.9747 19.7384 14.6665 19.7384H19.8226C20.7498 19.7384 21.6216 19.346 22.0947 18.7149C22.2905 18.4541 22.1819 18.1175 21.853 17.9634C21.521 17.806 21.097 17.8944 20.9028 18.1545C20.6738 18.4598 20.2696 18.6415 19.8226 18.6415H14.2251C13.5332 18.6415 12.9705 18.1959 12.9705 17.6487C12.9705 17.1015 13.5332 16.6565 14.2251 16.6565H20.6373C21.5645 16.6565 22.4355 16.2648 22.9094 15.6336C23.1052 15.3735 22.9966 15.0369 22.6677 14.8821C22.3372 14.7279 21.9125 14.8131 21.7175 15.0733C21.4885 15.3779 21.0843 15.5596 20.6373 15.5596H14.0499C13.3581 15.5596 12.7954 15.1146 12.7954 14.5674C12.7954 14.0203 13.3573 13.5746 14.0499 13.5746Z",
                                    fill: "#D19F77"
                                }, []), "\n"])
                            },
                            [Qe.EV.ThumbsDown]: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "24",
                                    height: "24",
                                    viewBox: "0 0 24 24",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("path", {
                                    d: "M23.2369 12.5431C23.2369 12.8546 23.1554 13.147 23.019 13.4127C22.1085 16.0921 17.8463 15.8964 11.7835 16.0271C10.7698 16.0488 11.3496 17.1407 11.7054 19.5377C11.9369 21.0967 10.835 23.4906 8.98292 23.4906C5.92912 23.4906 8.86682 21.293 6.16674 15.8586C4.72403 12.955 1.49915 14.5815 1.49915 11.6648V5.02633C1.49915 3.89102 1.62135 2.79968 3.37162 2.62006C5.06825 2.44539 4.68669 1.34229 7.13421 1.34229H19.3847C20.6326 1.34229 21.6476 2.26887 21.6476 3.40729C21.6476 3.87925 21.4663 4.3091 21.1737 4.65719C21.8662 5.01085 22.3414 5.67854 22.3414 6.45276C22.3414 6.92348 22.1608 7.35333 21.8689 7.7008C22.5634 8.05385 23.04 8.72215 23.04 9.49761C23.04 10.0606 22.7902 10.571 22.3876 10.9445C22.9015 11.3229 23.2369 11.8952 23.2369 12.5431Z",
                                    fill: "#F2D1A1"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M15.1983 10.5873H21.1647C21.9761 10.5873 22.7375 10.9797 23.1522 11.6109C23.3227 11.871 23.2277 12.2076 22.9393 12.3624C22.6515 12.5172 22.2791 12.4301 22.1078 12.17C21.9116 11.8697 21.5489 11.6842 21.164 11.6842H15.0548C14.4494 11.6842 13.957 12.1292 13.957 12.6764C13.957 13.2236 14.4494 13.6686 15.0548 13.6686H19.1371C19.472 13.6686 19.7439 13.9143 19.7439 14.217C19.7439 14.5198 19.472 14.7655 19.1371 14.7655H15.0541C13.7795 14.7655 12.7428 13.8284 12.7428 12.6764C12.7428 12.034 13.0722 11.4655 13.5784 11.0819C13.1519 10.7027 12.8863 10.1762 12.8863 9.59452C12.8863 8.95018 13.2178 8.37981 13.7268 7.99685C13.3031 7.61827 13.0403 7.09365 13.0403 6.51325C13.0403 5.81125 13.4279 5.19199 14.0174 4.81279C13.654 4.44361 13.4265 3.96287 13.4265 3.43135C13.4265 2.27933 14.4632 1.34229 15.7378 1.34229H19.5407C20.352 1.34229 21.1141 1.73402 21.5288 2.3652C21.7001 2.62531 21.6051 2.96189 21.3173 3.11671C21.0288 3.27027 20.6564 3.18566 20.4858 2.92554C20.2882 2.62531 19.9255 2.43916 19.5407 2.43916H15.7378C15.1324 2.43916 14.6401 2.88417 14.6401 3.43135C14.6401 3.97854 15.1324 4.42355 15.7378 4.42355H20.2494C21.0607 4.42355 21.8235 4.81592 22.2375 5.44709C22.4088 5.70783 22.3138 6.04441 22.026 6.1986C21.7354 6.35593 21.3644 6.26755 21.1946 6.00743C20.9941 5.70219 20.6405 5.52042 20.2494 5.52042H15.3516C14.7462 5.52042 14.2538 5.96607 14.2538 6.51325C14.2538 7.06043 14.7462 7.50545 15.3516 7.50545H20.9622C21.7736 7.50545 22.5357 7.89719 22.9504 8.52836C23.1216 8.78847 23.0266 9.12506 22.7389 9.27987C22.4497 9.43406 22.078 9.34882 21.9074 9.0887C21.707 8.78409 21.3534 8.60232 20.9622 8.60232H15.1983C14.5929 8.60232 14.1006 9.04733 14.1006 9.59452C14.1006 10.1417 14.5922 10.5873 15.1983 10.5873Z",
                                    fill: "#D19F77"
                                }, []), "\n"])
                            }
                        },
                        tt = e => T("button", Object.assign({
                            className: `${e.button.style.toLowerCase()}${e.disabled?" disabled":""}`,
                            onClick: e.button.click
                        }, {
                            children: e.button.text
                        }), e.button.text),
                        nt = e => {
                            const t = et[e.button.img];
                            return T("button", Object.assign({
                                className: `${e.button.style.toLowerCase()}${e.disabled?" disabled":""}`,
                                onClick: e.button.click
                            }, {
                                children: T(t, {}, void 0)
                            }), e.button.img)
                        };

                    function it(e) {
                        const t = e.buttons[0].layout || Qe.LS.Column;
                        return T("div", Object.assign({
                            className: "tara-buttons " + (t === Qe.LS.Row ? "side-by-side" : "column")
                        }, {
                            children: e.buttons.map((t => t.style === Je.Image ? T(nt, {
                                button: t,
                                disabled: e.isDisabled
                            }, void 0) : T(tt, {
                                button: t,
                                disabled: e.isDisabled
                            }, void 0)))
                        }), void 0)
                    }
                    const ot = {
                            HandWave: Xe,
                            Congrats: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "63",
                                    height: "55",
                                    viewBox: "0 0 63 55",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("path", {
                                    d: "M25.8488 11.381C25.6781 11.5517 25.5486 11.7575 25.4403 11.9831L25.4282 11.9709L8.33334 50.4799L8.35011 50.4967C8.03309 51.1109 8.56349 52.3607 9.6502 53.449C10.7369 54.5357 11.9867 55.0661 12.6009 54.7491L12.6162 54.7643L51.1252 37.668L51.113 37.6542C51.3371 37.5476 51.5429 37.418 51.7151 37.2442C54.0958 34.8635 50.2351 27.1437 43.0945 20.0016C35.9508 12.8595 28.2311 9.00032 25.8488 11.381Z",
                                    fill: "#3366FF"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M27.943 18.2581L8.76315 49.5122L8.33334 50.48L8.35011 50.4968C8.03309 51.111 8.56349 52.3608 9.6502 53.449C10.0038 53.8026 10.3711 54.0709 10.7308 54.298L34.0396 25.8788L27.943 18.2581Z",
                                    fill: "#84A9FF"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M43.2026 19.8828C50.3204 27.0036 54.2725 34.5938 52.0259 36.8374C49.7808 39.084 42.1906 35.1334 35.0683 28.0156C27.949 20.8948 23.9984 13.3015 26.2435 11.0565C28.4901 8.81139 36.0803 12.762 43.2026 19.8828Z",
                                    fill: "#091A7A"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M36.4629 20.7103C36.1596 20.9557 35.7633 21.0837 35.3442 21.038C34.0212 20.8947 32.9086 20.4344 32.1297 19.7074C31.3052 18.9377 30.8982 17.9044 31.0095 16.8695C31.2046 15.0527 33.0275 13.3853 36.1352 13.7206C37.3438 13.8501 37.8834 13.4615 37.9017 13.2755C37.923 13.0911 37.4795 12.5958 36.2708 12.4647C34.9479 12.3214 33.8353 11.8611 33.0549 11.1341C32.2303 10.3644 31.8219 9.33105 31.9347 8.29615C32.1328 6.47937 33.9541 4.81196 37.0588 5.1488C37.9398 5.24329 38.4046 5.06192 38.6013 4.94456C38.7583 4.84854 38.8207 4.75709 38.8268 4.70375C38.8451 4.51932 38.4077 4.02398 37.196 3.8929C36.3592 3.80145 35.7526 3.05157 35.8456 2.21329C35.9355 1.37654 36.6839 0.771452 37.5237 0.862901C40.6284 1.19669 42.055 3.21313 41.8584 5.03144C41.6602 6.85127 39.8389 8.51563 36.7311 8.18184C35.8502 8.08582 35.3899 8.26872 35.1918 8.38608C35.0348 8.48058 34.9708 8.57355 34.9647 8.62537C34.9448 8.81132 35.3853 9.30514 36.597 9.43621C39.7017 9.77153 41.1283 11.7864 40.9317 13.6048C40.7351 15.4215 38.9137 17.0889 35.8075 16.7521C34.9266 16.6576 34.4632 16.8405 34.2651 16.9563C34.1066 17.0539 34.0456 17.1453 34.0395 17.1972C34.0197 17.3816 34.4602 17.8769 35.6703 18.008C36.5056 18.0995 37.1137 18.8509 37.0207 19.6876C36.978 20.1052 36.7662 20.4665 36.4629 20.7103Z",
                                    fill: "#BD5BE4"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M54.8608 34.8057C57.868 33.9567 59.9423 35.298 60.4362 37.0584C60.93 38.8172 59.86 41.044 56.8544 41.8899C55.6808 42.2191 55.3288 42.78 55.376 42.9583C55.4278 43.1382 56.0238 43.4339 57.1943 43.1031C60.1999 42.2572 62.2743 43.5985 62.7681 45.3573C63.265 47.1177 62.192 49.3415 59.1848 50.1889C58.0128 50.5181 57.6592 51.0805 57.711 51.2588C57.7613 51.4372 58.3557 51.7328 59.5278 51.4036C60.3356 51.1765 61.1799 51.6475 61.407 52.4568C61.6326 53.2677 61.1617 54.109 60.3508 54.3376C57.3467 55.1835 55.2708 53.8453 54.774 52.0834C54.2801 50.3245 55.3516 48.1008 58.3603 47.2534C59.5339 46.9226 59.8859 46.3633 59.8341 46.1834C59.7854 46.0051 59.1909 45.7079 58.0204 46.0371C55.0117 46.8845 52.9389 45.5463 52.4435 43.7829C51.9482 42.024 53.0197 39.8003 56.0268 38.9514C57.1974 38.6237 57.5494 38.0597 57.5007 37.8829C57.4488 37.7031 56.8559 37.4074 55.6839 37.7366C54.873 37.9652 54.0332 37.4928 53.8046 36.6834C53.5775 35.8756 54.05 35.0343 54.8608 34.8057Z",
                                    fill: "#1DE9B7"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M43.1858 30.695C42.7377 30.695 42.2957 30.4984 41.9939 30.1234C41.4681 29.465 41.5763 28.5063 42.2317 27.9805C42.564 27.7137 50.4895 21.4891 61.6905 23.091C62.5242 23.2099 63.1033 23.9811 62.9845 24.8148C62.8656 25.647 62.1005 26.2323 61.2591 26.1073C51.3629 24.702 44.2085 30.3048 44.1384 30.3612C43.8549 30.5868 43.5196 30.695 43.1858 30.695Z",
                                    fill: "#BD5BE4"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M16.8989 24.3545C16.7541 24.3545 16.6063 24.3332 16.46 24.2905C15.6537 24.0482 15.1965 23.1992 15.4388 22.393C17.1657 16.6424 18.731 7.4655 16.8075 5.07259C16.5926 4.80129 16.2679 4.53457 15.5242 4.59096C14.0945 4.7007 14.2302 7.71698 14.2317 7.74746C14.2957 8.58727 13.6647 9.31886 12.8264 9.38135C11.9744 9.43317 11.255 8.81436 11.1925 7.97456C11.0356 5.87277 11.6894 1.82464 15.2955 1.55182C16.905 1.42988 18.2417 1.98924 19.1852 3.16284C22.7989 7.66059 19.1303 20.6996 18.3591 23.2694C18.1609 23.9293 17.5543 24.3545 16.8989 24.3545Z",
                                    fill: "#1DE9B7"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M46.9947 16.7338C48.2574 16.7338 49.2809 15.7102 49.2809 14.4476C49.2809 13.185 48.2574 12.1614 46.9947 12.1614C45.7321 12.1614 44.7085 13.185 44.7085 14.4476C44.7085 15.7102 45.7321 16.7338 46.9947 16.7338Z",
                                    fill: "#FFA48D"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M11.1773 30.4511C12.8608 30.4511 14.2256 29.0863 14.2256 27.4028C14.2256 25.7193 12.8608 24.3545 11.1773 24.3545C9.49379 24.3545 8.12903 25.7193 8.12903 27.4028C8.12903 29.0863 9.49379 30.4511 11.1773 30.4511Z",
                                    fill: "#9266CC"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M57.6637 31.9753C58.9263 31.9753 59.9499 30.9517 59.9499 29.689C59.9499 28.4264 58.9263 27.4028 57.6637 27.4028C56.401 27.4028 55.3774 28.4264 55.3774 29.689C55.3774 30.9517 56.401 31.9753 57.6637 31.9753Z",
                                    fill: "#54D62C"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M43.9464 50.2651C45.209 50.2651 46.2326 49.2415 46.2326 47.9788C46.2326 46.7162 45.209 45.6926 43.9464 45.6926C42.6837 45.6926 41.6602 46.7162 41.6602 47.9788C41.6602 49.2415 42.6837 50.2651 43.9464 50.2651Z",
                                    fill: "#FF4842"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M50.8051 9.11318C52.4886 9.11318 53.8534 7.74841 53.8534 6.06489C53.8534 4.38137 52.4886 3.0166 50.8051 3.0166C49.1216 3.0166 47.7568 4.38137 47.7568 6.06489C47.7568 7.74841 49.1216 9.11318 50.8051 9.11318Z",
                                    fill: "#FFCC4D"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M57.6637 15.2096C58.9263 15.2096 59.9499 14.1861 59.9499 12.9234C59.9499 11.6608 58.9263 10.6372 57.6637 10.6372C56.401 10.6372 55.3774 11.6608 55.3774 12.9234C55.3774 14.1861 56.401 15.2096 57.6637 15.2096Z",
                                    fill: "#FFCC4D"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M53.0913 21.3063C54.3539 21.3063 55.3775 20.2827 55.3775 19.0201C55.3775 17.7575 54.3539 16.7339 53.0913 16.7339C51.8286 16.7339 50.8051 17.7575 50.8051 19.0201C50.8051 20.2827 51.8286 21.3063 53.0913 21.3063Z",
                                    fill: "#FFCC4D"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M2.28622 40.7612C3.54886 40.7612 4.57243 39.7376 4.57243 38.4749C4.57243 37.2123 3.54886 36.1887 2.28622 36.1887C1.02357 36.1887 0 37.2123 0 38.4749C0 39.7376 1.02357 40.7612 2.28622 40.7612Z",
                                    fill: "#FFC107"
                                }, []), "\n"])
                            },
                            Star: function(e) {
                                e.styles;
                                var t = Object.assign({}, e);
                                return delete t.styles, (0, A.h)("svg", Object.assign({
                                    width: "121",
                                    height: "74",
                                    viewBox: "0 0 121 74",
                                    fill: "none",
                                    xmlns: "http://www.w3.org/2000/svg"
                                }, t), ["\n", (0, A.h)("path", {
                                    d: "M83.6084 36.927C83.6084 50.3684 72.7117 61.2652 59.2703 61.2652C45.8289 61.2652 34.9321 50.3684 34.9321 36.927C34.9321 23.4856 45.8289 12.5889 59.2703 12.5889C72.7117 12.5889 83.6084 23.4856 83.6084 36.927Z",
                                    fill: "#FFCC4D"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M59.2703 40.9836C54.3716 40.9836 51.1211 40.413 47.1012 39.6315C46.1831 39.4544 44.397 39.6315 44.397 42.3357C44.397 47.7442 50.61 54.5048 59.2703 54.5048C67.9293 54.5048 74.1436 47.7442 74.1436 42.3357C74.1436 39.6315 72.3574 39.453 71.4394 39.6315C67.4195 40.413 64.169 40.9836 59.2703 40.9836Z",
                                    fill: "#664500"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M47.1012 42.3354C47.1012 42.3354 51.1576 43.6876 59.2703 43.6876C67.383 43.6876 71.4393 42.3354 71.4393 42.3354C71.4393 42.3354 68.7351 47.7439 59.2703 47.7439C49.8054 47.7439 47.1012 42.3354 47.1012 42.3354Z",
                                    fill: "white"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M56.136 18.5558L49.9947 19.6388L46.8307 13.8883C46.4819 13.2541 45.7652 12.9147 45.0567 13.0391C44.3442 13.1649 43.7898 13.7301 43.6789 14.444L42.6716 20.9301L36.5303 22.0131C35.8069 22.1402 35.2485 22.723 35.1498 23.4518C35.0511 24.1806 35.4351 24.8891 36.1003 25.2055L41.6034 27.8178L40.592 34.3242C40.4798 35.0489 40.8476 35.7628 41.502 36.0941C41.744 36.2158 42.0037 36.2739 42.2619 36.2739C42.704 36.2739 43.1408 36.1009 43.4666 35.7709L48.2153 30.9561L54.3242 33.8563C54.9867 34.17 55.7763 34.0227 56.2793 33.4886C56.7823 32.9545 56.8824 32.1581 56.5295 31.5158L53.3547 25.745L57.6342 21.4074C58.1507 20.8841 58.2683 20.0864 57.9276 19.4346C57.5841 18.7829 56.8553 18.43 56.136 18.5558ZM62.4044 18.5558L68.5458 19.6388L71.7097 13.8883C72.0586 13.2541 72.7752 12.9147 73.4837 13.0391C74.1949 13.1649 74.7493 13.7301 74.8601 14.444L75.8675 20.9301L82.0088 22.0131C82.7335 22.1402 83.292 22.7216 83.3893 23.4504C83.4867 24.1792 83.104 24.8877 82.4388 25.2041L76.9357 27.8164L77.947 34.3228C78.0593 35.0476 77.6915 35.7615 77.0371 36.0928C76.795 36.2144 76.5354 36.2726 76.2772 36.2726C75.835 36.2726 75.3983 36.0995 75.0724 35.7696L70.3238 30.9547L64.2149 33.855C63.5524 34.1687 62.7627 34.0213 62.2598 33.4872C61.7568 32.9531 61.6567 32.1567 62.0096 31.5145L65.1844 25.745L60.9049 21.4074C60.3884 20.8841 60.2708 20.0864 60.6115 19.4346C60.9563 18.7829 61.6851 18.43 62.4044 18.5558Z",
                                    fill: "#E95F28"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M26.8201 59.0737L20.4754 56.1866L17.2635 62.3453L10.9188 59.4582L7.70698 65.6169L1.3623 62.7298",
                                    stroke: "#54D62C",
                                    "stroke-width": "4"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M15.8826 3.90283L25.0137 7.22105",
                                    stroke: "#3366FF",
                                    "stroke-width": "4"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M96.1971 23.7383L120 17.8631",
                                    stroke: "#FFC705",
                                    "stroke-width": "6"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M95.1146 62.9434L112.92 72.0653",
                                    stroke: "#FF816D",
                                    "stroke-width": "4"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M14.5648 31.8916L18.797 34.1721L16.5046 38.3781L12.2724 36.0976L14.5648 31.8916Z",
                                    fill: "#FF593E"
                                }, []), "\n", (0, A.h)("path", {
                                    d: "M94.1267 4.22684C95.299 4.22684 96.2525 3.27882 96.2525 2.11342C96.2525 0.948019 95.299 0 94.1267 0C92.9544 0 92.0009 0.948019 92.0009 2.11342C92.0009 3.27882 92.9544 4.22684 94.1267 4.22684Z",
                                    fill: "#BE5CE5"
                                }, []), "\n"])
                            }
                        },
                        rt = {
                            Congrats: Ke
                        },
                        at = {
                            Congrats: {
                                yOffset: 10
                            }
                        },
                        st = e => {
                            const [t, i] = (0, we.useState)(null);
                            return t ? rt[e.img] ? T(t, {
                                options: {
                                    animationData: rt[e.img],
                                    loop: !1
                                }
                            }, void 0) : null : (n.e(464).then(n.bind(n, 9464)).then((e => {
                                i((() => e.default))
                            })), null)
                        },
                        lt = e => {
                            if (ot[e]) {
                                const t = ot[e];
                                let n = {};
                                return at[e] && (n = {
                                    transform: `translate(-50%, calc(-50% + ${at[e].yOffset}px))`
                                }), T(t, {
                                    className: "title-image",
                                    style: n
                                }, void 0)
                            }
                            return rt[e] ? null : T("img", {
                                src: e
                            }, void 0)
                        },
                        ct = e => T("div", {
                            ref: e.lastref,
                            className: `message-box ${e.msg.status.toLowerCase()} ${e.group?"group":""}${e.dots?" dot-flashing":""}`,
                            dangerouslySetInnerHTML: {
                                __html: e.dots ? "" : e.msg.text
                            }
                        }, void 0),
                        dt = e => {
                            const t = e.msg,
                                [n, i] = (0, V.eJ)(!!t.dotsDelay);
                            return (0, V.d4)((() => {
                                t.dotsDelay && setTimeout((() => {
                                    i(!1)
                                }), t.dotsDelay)
                            }), []), T(A.HY, {
                                children: [T(ct, Object.assign({}, {
                                    ...e,
                                    dots: n
                                }), void 0), e.buttons && !n && T(it, {
                                    buttons: e.buttons,
                                    isDisabled: !e.isLast
                                }, void 0)]
                            }, void 0)
                        },
                        ut = {
                            excel: function(e) {
                                var t = e.styles,
                                    n = Object.assign({}, e);
                                return delete n.styles, (0, A.h)("svg", Object.assign({
                                    xmlns: "http://www.w3.org/2000/svg",
                                    viewBox: "0 0 24 24"
                                }, n), [(0, A.h)("defs", {}, [(0, A.h)("style", {}, [".excel-cls-1{fill:#21a366;}.excel-cls-2{fill:none;}.excel-cls-3{fill:#107c41;}.excel-cls-4{fill:#33c481;}.excel-cls-5{fill:#185c37;}.excel-cls-6{opacity:0.5;}.excel-cls-7{fill:#fff;}"])]), (0, A.h)("title", {}, ["Excel_24x"]), (0, A.h)("g", {
                                    id: "svg-excelIcon-27HlcJn"
                                }, [(0, A.h)("g", {
                                    id: "svg-excelIcon-SrA9-Hu",
                                    "data-name": "24"
                                }, [(0, A.h)("path", {
                                    class: [t && t["excel-cls-1"] || "excel-cls-1"].join(" "),
                                    d: "M16,1H7A1,1,0,0,0,6,2V7l10,5,4,1.5L24,12V7Z"
                                }, []), (0, A.h)("rect", {
                                    class: [t && t["excel-cls-2"] || "excel-cls-2"].join(" "),
                                    width: "24",
                                    height: "24"
                                }, []), (0, A.h)("rect", {
                                    class: [t && t["excel-cls-3"] || "excel-cls-3"].join(" "),
                                    x: "6",
                                    y: "7.02",
                                    width: "10",
                                    height: "4.98"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["excel-cls-4"] || "excel-cls-4"].join(" "),
                                    d: "M24,2V7H16V1h7A1,1,0,0,1,24,2Z"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["excel-cls-5"] || "excel-cls-5"].join(" "),
                                    d: "M16,12H6V22a1,1,0,0,0,1,1H23a1,1,0,0,0,1-1V17Z"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["excel-cls-6"] || "excel-cls-6"].join(" "),
                                    d: "M13.83,6H6V20h7.6A1.5,1.5,0,0,0,15,18.65V7.17A1.18,1.18,0,0,0,13.83,6Z"
                                }, []), (0, A.h)("rect", {
                                    id: "svg-excelIcon-3DiHK8n",
                                    "data-name": "Back Plate",
                                    class: [t && t["excel-cls-3"] || "excel-cls-3"].join(" "),
                                    y: "5",
                                    width: "14",
                                    height: "14",
                                    rx: "1.17"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["excel-cls-7"] || "excel-cls-7"].join(" "),
                                    d: "M3.43,16,6,12,3.64,8H5.55l1.3,2.55a4.63,4.63,0,0,1,.24.54h0a5.77,5.77,0,0,1,.27-.56L8.76,8h1.75L8.08,12l2.49,4H8.71l-1.5-2.8A2.14,2.14,0,0,1,7,12.83H7a1.54,1.54,0,0,1-.17.36L5.3,16Z"
                                }, []), (0, A.h)("rect", {
                                    class: [t && t["excel-cls-3"] || "excel-cls-3"].join(" "),
                                    x: "16",
                                    y: "12",
                                    width: "8",
                                    height: "5"
                                }, [])])])])
                            },
                            word: function(e) {
                                var t = e.styles,
                                    n = Object.assign({}, e);
                                return delete n.styles, (0, A.h)("svg", Object.assign({
                                    xmlns: "http://www.w3.org/2000/svg",
                                    viewBox: "0 0 24 24"
                                }, n), [(0, A.h)("defs", {}, [(0, A.h)("style", {}, [".word-cls-1{fill:none;}.word-cls-2{fill:#41a5ee;}.word-cls-3{fill:#2b7cd3;}.word-cls-4{fill:#185abd;}.word-cls-5{fill:#103f91;}.word-cls-6{opacity:0.5;}.word-cls-7{fill:#fff;}"])]), (0, A.h)("title", {}, ["Word_24x"]), (0, A.h)("g", {
                                    id: "svg-wordIcon-PjjHdS3"
                                }, [(0, A.h)("g", {
                                    id: "svg-wordIcon-2znknJh",
                                    "data-name": "24"
                                }, [(0, A.h)("rect", {
                                    class: [t && t["word-cls-1"] || "word-cls-1"].join(" "),
                                    width: "24",
                                    height: "24"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["word-cls-2"] || "word-cls-2"].join(" "),
                                    d: "M24,7V2a1,1,0,0,0-1-1H7A1,1,0,0,0,6,2V7l9,2Z"
                                }, []), (0, A.h)("polygon", {
                                    class: [t && t["word-cls-3"] || "word-cls-3"].join(" "),
                                    points: "24 7 6 7 6 12 15.5 14 24 12 24 7"
                                }, []), (0, A.h)("polygon", {
                                    class: [t && t["word-cls-4"] || "word-cls-4"].join(" "),
                                    points: "24 12 6 12 6 17 15 18.5 24 17 24 12"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["word-cls-5"] || "word-cls-5"].join(" "),
                                    d: "M6,17H24a0,0,0,0,1,0,0v5a1,1,0,0,1-1,1H7a1,1,0,0,1-1-1V17a0,0,0,0,1,0,0Z"
                                }, []), (0, A.h)("path", {
                                    class: [t && t["word-cls-6"] || "word-cls-6"].join(" "),
                                    d: "M13.83,6H6V20h7.6A1.5,1.5,0,0,0,15,18.65V7.17A1.18,1.18,0,0,0,13.83,6Z"
                                }, []), (0, A.h)("rect", {
                                    id: "svg-wordIcon-2G7-CaN",
                                    "data-name": "Back Plate",
                                    class: [t && t["word-cls-4"] || "word-cls-4"].join(" "),
                                    y: "5",
                                    width: "14",
                                    height: "14",
                                    rx: "1.17"
                                }, []), (0, A.h)("path", {
                                    id: "svg-wordIcon-2M0rIX-",
                                    class: [t && t["word-cls-7"] || "word-cls-7"].join(" "),
                                    d: "M10.16,16H8.72L7,10.48,5.28,16H3.84L2.24,8H3.68L4.8,13.6,6.48,8.16h1.2l1.6,5.44L10.4,8h1.36Z"
                                }, [])])])])
                            }
                        };

                    function pt(e) {
                        const t = e.icon ? ut[e.icon] : null;
                        return T("div", Object.assign({
                            className: "category-item" + (e.warning ? " warning" : "")
                        }, {
                            children: [T("input", {
                                type: "checkbox",
                                checked: e.selected,
                                onChange: () => {
                                    e.onChange(e.text, !e.selected)
                                }
                            }, void 0), e.icon && T(t, {}, void 0), e.url ? T("a", Object.assign({
                                href: e.url
                            }, {
                                children: e.text
                            }), void 0) : e.text, e.warning && T("div", Object.assign({
                                className: "item-action warning"
                            }, {
                                children: [T("div", Object.assign({
                                    className: "bubble-with-arrow"
                                }, {
                                    children: [T("div", {
                                        className: "the-arrow"
                                    }, void 0), e.warning]
                                }), void 0), "!"]
                            }), void 0)]
                        }), void 0)
                    }

                    function ht(e) {
                        const t = e.items.filter((e => e.selected)).length,
                            [n, i] = (0, V.eJ)(e.items),
                            o = (t, o) => {
                                e.onChange && e.onChange(e.category, t, o), n.find((e => e.text === t)).selected = o, i([...n])
                            },
                            r = 0 === n.filter((e => !0 !== e.selected)).length;
                        return T("div", Object.assign({
                            className: "category-wrapper"
                        }, {
                            children: [T("div", Object.assign({
                                className: "category-header"
                            }, {
                                children: [T("div", Object.assign({
                                    className: "category-name"
                                }, {
                                    children: [e.category, " (", t, "/", e.items.length, ")"]
                                }), void 0), T("div", Object.assign({
                                    className: "category-select-all",
                                    onClick: () => {
                                        i(n.map((e => (e.selected = !r, e))))
                                    }
                                }, {
                                    children: [r ? "de-" : "", "select all"]
                                }), void 0)]
                            }), void 0), T("div", Object.assign({
                                className: "category-content"
                            }, {
                                children: e.items.map((e => T(pt, Object.assign({}, e, {
                                    onChange: o
                                }), void 0)))
                            }), void 0)]
                        }), void 0)
                    }
                    const ft = {
                        [Ze.Title]: e => {
                            const t = e.msg;
                            return T(A.HY, {
                                children: [T("div", Object.assign({
                                    className: "tara-title-message",
                                    ref: e.lastref
                                }, {
                                    children: [T("div", Object.assign({
                                        className: "img-container"
                                    }, {
                                        children: [lt(t.img), T(st, {
                                            img: t.img
                                        }, void 0)]
                                    }), void 0), T("div", {
                                        className: "tara-title-message-title-text",
                                        dangerouslySetInnerHTML: {
                                            __html: t.title
                                        }
                                    }, void 0), T("div", {
                                        className: "tara-title-message-standard-text",
                                        dangerouslySetInnerHTML: {
                                            __html: t.text
                                        }
                                    }, void 0)]
                                }), void 0), e.buttons && T(it, {
                                    buttons: e.buttons,
                                    isDisabled: !e.isLast
                                }, void 0)]
                            }, void 0)
                        },
                        [Ze.User]: dt,
                        [Ze.Tara]: dt,
                        [Ze.CategoryMultiSelect]: function(e) {
                            const t = e.msg;
                            return T("div", Object.assign({
                                className: "category-multi-select-wrapper"
                            }, {
                                children: [T(ct, Object.assign({}, e), void 0), t.categories.map((e => T(ht, Object.assign({}, e), void 0))), e.buttons && T(it, {
                                    buttons: e.buttons,
                                    isDisabled: !e.isLast
                                }, void 0)]
                            }), void 0)
                        }
                    };

                    function gt(e) {
                        const t = e.msg.type.toLowerCase(),
                            n = e.msg.buttons,
                            i = {
                                ...e,
                                buttons: n
                            },
                            o = ft[e.msg.type];
                        return T("div", Object.assign({
                            className: `tara-message-outer-container ${t}-container`
                        }, {
                            children: T("div", Object.assign({
                                className: `tara-message-container ${t}-message`
                            }, {
                                children: T(o, Object.assign({}, i), void 0)
                            }), void 0)
                        }), void 0)
                    }
                    const mt = ["Hi, I am Tara", "your personal security assistant.", "How can I help you?"];

                    function yt() {
                        return T("div", Object.assign({
                            id: "chat-welcome"
                        }, {
                            children: [T("div", Object.assign({
                                id: "hand-wave-container"
                            }, {
                                children: T(Xe, {}, void 0)
                            }), void 0), T("div", Object.assign({
                                id: "welcome-text"
                            }, {
                                children: mt.map((e => T("span", {
                                    children: [e, T("br", {}, void 0)]
                                }, e)))
                            }), void 0)]
                        }), void 0)
                    }

                    function bt(e) {
                        const t = (0, A.Vf)(),
                            n = (0, A.Vf)(),
                            i = Math.max(...e.messages.map(((e, t) => e.type === Ze.Tara ? t : -1)));
                        return (0, we.useEffect)((() => {
                            t.current && t.current.scrollIntoView({
                                behavior: "smooth"
                            });
                            const n = e.messages[e.messages.length - 1],
                                i = n && n.type === Ze.Tara && n.dotsDelay ? n.dotsDelay + 10 : 0;
                            i && setTimeout((() => {
                                t.current && t.current.scrollIntoView({
                                    behavior: "smooth"
                                })
                            }), i)
                        }), [e.messages.length]), T("div", Object.assign({
                            id: "tara-chat-container"
                        }, {
                            children: [T("div", Object.assign({
                                id: "tara-text-messages"
                            }, {
                                children: e.messages.length ? T(A.HY, {
                                    children: e.messages.map(((e, t, o) => T(gt, {
                                        msg: e,
                                        group: o.length > t + 1 && e.type === o[t + 1].type && e.status === ue.wi.Healthy && o[t + 1].status === e.status,
                                        lastref: t === i ? n : null,
                                        isLast: t === o.length - 1
                                    }, `${e.key}${t}`)))
                                }, void 0) : T(yt, {}, void 0)
                            }), void 0), T("div", {
                                ref: t,
                                id: "scroll-target"
                            }, void 0)]
                        }), void 0)
                    }

                    function xt(e) {
                        e.styles;
                        var t = Object.assign({}, e);
                        return delete t.styles, (0, A.h)("svg", Object.assign({
                            width: "16",
                            height: "16",
                            viewBox: "0 0 16 16",
                            fill: "none",
                            xmlns: "http://www.w3.org/2000/svg"
                        }, t), ["\n", (0, A.h)("path", {
                            d: "M15.7068 0.292637C15.4338 0.0206365 15.0268 -0.0723635 14.6638 0.0586365L0.663812 5.05864C0.286812 5.19264 0.0258123 5.53964 0.00181231 5.93864C-0.0221877 6.33864 0.193812 6.71364 0.552812 6.89364L5.13881 9.18564L10.9998 4.99964L6.81281 10.8616L9.10481 15.4476C9.27581 15.7866 9.62281 15.9996 9.99981 15.9996C10.0208 15.9996 10.0408 15.9986 10.0608 15.9976C10.4608 15.9736 10.8078 15.7136 10.9428 15.3356L15.9428 1.33564C16.0718 0.972636 15.9798 0.565637 15.7068 0.292637Z",
                            fill: "#1C2F5C"
                        }, []), "\n"])
                    }

                    function vt(e) {
                        const t = t => t.currentTarget instanceof HTMLDivElement && e.click(t.currentTarget.textContent);
                        return T("div", Object.assign({
                            id: "tara-chips"
                        }, {
                            children: e.chips.map((e => T("div", Object.assign({
                                onClick: t,
                                className: "chip"
                            }, {
                                children: e
                            }), e)))
                        }), void 0)
                    }

                    function wt(e) {
                        const t = (0, A.Vf)(),
                            n = () => {
                                const n = t.current && t.current.value;
                                n && n.trim().length && (t.current.value = "", e.onUserInput(n))
                            };
                        return T("div", Object.assign({
                            id: "tara-user-input"
                        }, {
                            children: [T(vt, {
                                chips: e.chips,
                                click: e.onUserInput
                            }, void 0), T("div", Object.assign({
                                id: "input-wrapper"
                            }, {
                                children: [T("input", {
                                    ref: t,
                                    onKeyPress: e => {
                                        "Enter" === e.key && n()
                                    },
                                    className: "question-box",
                                    placeholder: "Consult with me"
                                }, void 0), T(xt, {
                                    onClick: n
                                }, void 0)]
                            }), void 0)]
                        }), void 0)
                    }

                    function _t(e) {
                        const t = e.stateMaker();
                        return T("div", Object.assign({
                            id: "tara-container"
                        }, {
                            children: [T(Ye, {
                                close: t.close
                            }, void 0), T(bt, {
                                messages: t.messages
                            }, void 0), T(wt, {
                                onUserInput: t.onUserInput,
                                chips: t.chips
                            }, void 0)]
                        }), void 0)
                    }
                    const kt = ["Show sharing policy", "Show my external shares", "Show shares about to expire"];
                    let Ct = class extends se {
                        constructor(e) {
                            super({
                                props: {
                                    messages: [],
                                    visible: !1,
                                    status: ue.wi.Healthy,
                                    chips: kt,
                                    onUserInput: () => null,
                                    close: () => null
                                },
                                frameId: "us-tara-frame",
                                nodeId: "tara-root",
                                css: Ge,
                                componentFunc: _t
                            }), this._inputListeners = [], this.onUserInput = e => {
                                let t = ue.cg.Full;
                                for (let n = this._inputListeners.length - 1; n >= 1; n--) {
                                    const i = this._inputListeners[n](e);
                                    if (t = void 0 !== i ? i : t, t === ue.cg.None) return
                                }
                                t === ue.cg.Full && this._inputListeners[0](e)
                            }, this.setProp(ue.ue.OnUserInput, (() => e => this.onUserInput(e))), this.setProp(ue.ue.Close, (() => () => this.hide())), this._utils = e
                        }
                        addMessage(e) {
                            this.props().messages.length && e.text === this.props().messages[this.props().messages.length - 1].text || this.setProp(ue.ue.Messages, [...this.props().messages, e])
                        }
                        setStatus(e) {
                            this.setProp(ue.ue.Status, e)
                        }
                        setChips(e) {
                            this.setProp(ue.ue.Chips, e)
                        }
                        addUserInputListener(e) {
                            this._inputListeners.push(e)
                        }
                        removeUserInputListener(e) {
                            this._utils.removeValFromArray(this._inputListeners, e)
                        }
                    };
                    var St;
                    Ct = function(e, t, n, i) {
                            var o, r = arguments.length,
                                a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                            if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                            else
                                for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                            return r > 3 && a && Object.defineProperty(t, n, a), a
                        }([(0, E.b)(), function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        }(0, (0, I.f)(Y.ICommonUtils)), function(e, t) {
                            if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                        }("design:paramtypes", [Object])], Ct),
                        function(e) {
                            e.CredentialFlow = "CredentialFlowMD", e.Empty = "Empty", e.ShowmeBuilder = "ShowmeBuilderMD", e.outlookAddin = "outlookAddin", e.LiveAttack = "LiveAttack"
                        }(St || (St = {}));
                    const Et = {
                        ICredentialsFlow: Symbol.for("ICredentialsFlow"),
                        IShowmeBuilder: Symbol.for("IShowmeBuilder"),
                        IOutlookAddin: Symbol.for("IOutlookAddin"),
                        ILiveAttack: Symbol.for("ILiveAttack")
                    };
                    var It = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    const At = "default";
                    let Ot = class {
                        constructor(e, t, n, i) {
                            this._conversationHandler = {}, this._metadataHandlers = {}, this.registerMetadataHandler = (e, t) => {
                                if (this._metadataHandlers[e]) throw new Error(`Trying to re-register handler for metadata type ${e}`);
                                this._metadataHandlers[e] = t
                            }, this.onUserInput = e => {
                                this.activeConversation.sendMessage({
                                    type: S.ConversationInputType.Text,
                                    data: {
                                        text: e
                                    }
                                })
                            }, this.responseCallback = (e, t, n) => {
                                if ([ue.OP.Predefined, ue.OP.Automatic].includes(t)) {
                                    if (!n) return;
                                    return this.activeConversation.sendMessage({
                                        type: S.ConversationInputType.Predefined,
                                        data: {
                                            transitionToTrigger: n
                                        }
                                    })
                                }
                                e && this.activeConversation.sendMessage({
                                    type: S.ConversationInputType.Text,
                                    data: {
                                        text: e
                                    }
                                })
                            }, this.onMessage = e => {
                                const [t, n, i] = this.parseServerMsg(e);
                                i(t, this.responseCallback, n)
                            }, this.onError = (e, t) => {
                                this._logger.error(`ConversationProxy received error: ${e}. Metadata:`, t)
                            }, this.startConversation = (e, t) => {
                                this._conversationHandler[e] = this._conversationManager.startConversation(e, (n => {
                                    !t || n.scenarioMetadata && 0 !== Object.keys(n.scenarioMetadata).length || (n.scenarioMetadata = t), this.onMessage(n), this._conversationHandler[e].setNewHandler(this.onMessage)
                                }), this.onError), this._activeConversation = e, this._lastDefaultConversationItem = null
                            }, this.endConversation = e => {
                                this._conversationHandler[e] && this._conversationHandler[e].closeConversation(), delete this._conversationHandler[e], e === this._activeConversation && (this._taraform.resetState(), this._activeConversation = At, this._lastDefaultConversationItem = null)
                            }, this._conversationManager = e, this._taraform = t, this._tara = n, this._logger = i, this.startDefaultConversation(), this._tara.addUserInputListener(this.onUserInput), this._taraform.init(), this.registerMetadataHandler(St.Empty, this._taraform.onMessage)
                        }
                        get activeConversation() {
                            return this._conversationHandler[this._activeConversation]
                        }
                        startDefaultConversation() {
                            this._conversationManager.registerDefaultHandler(((e, t) => {
                                this._conversationHandler.default = t, this._activeConversation = At;
                                const n = e.scenarioItem.itemName;
                                this._lastDefaultConversationItem !== n && (this._lastDefaultConversationItem = n, t.setNewHandler((e => {
                                    this.onMessage(e)
                                })), this.onMessage(e))
                            }), this.onError)
                        }
                        parseServerMsg(e) {
                            const t = e.scenarioMetadata;
                            t.type || (t.detections ? t.type = St.CredentialFlow : t.type = St.Empty);
                            const n = this._metadataHandlers[t.type];
                            if (!n) throw new Error(`No handler found for metadata of type ${t.type}`);
                            return [e.scenarioItem, t, n]
                        }
                    };
                    Ot = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), It(0, (0, I.f)(S.TYPES.IConversationsManager)), It(1, (0, I.f)(w.ITaraform)), It(2, (0, I.f)(w.ITara)), It(3, (0, I.f)(Y.ILogger)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object, Object])], Ot);
                    var Tt = n(7710),
                        Mt = n(2190);
                    const Rt = "InitialRuleRegistration",
                        Pt = "InputFocused",
                        Dt = [{
                            on: Rt,
                            name: "register-input-focus",
                            type: "FLOW_HOOK",
                            selectors: ["input"],
                            selectMultiple: !0,
                            event: "focus",
                            dispatchEvent: Pt
                        }, {
                            on: Rt,
                            name: "register-input-focus-in-iframe",
                            type: "FLOW_HOOK",
                            selectors: ["iframe", "input"],
                            selectMultiple: !0,
                            event: "focus",
                            dispatchEvent: Pt
                        }, {
                            on: Pt,
                            type: "CALLBACK",
                            name: "input-focused"
                        }];
                    var jt = n(2603),
                        Lt = n(6453),
                        Ft = function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    let Ht = class {
                        constructor(e, t, n, i, o, r) {
                            this.scenarioActive = !1, this._violationsMetadata = {}, this.checkActiveElement = () => {
                                if (!document.activeElement || "INPUT" !== document.activeElement.nodeName || !jt.d.detectOnElement(document.activeElement)) return !1;
                                const e = `logo-mistmatch-${this._utils.randomInt()}`;
                                return document.activeElement.setAttribute("data-unbiased-id", e), this.scenarioActive || document.activeElement.blur(), this._violationsMetadata.inputElement = `[data-unbiased-id="${e}"]`, this._violationsMetadata.inputText = "You're being asked to enter your credentials on a website that looks suspicious", !0
                            }, this.flowHandler = (e, t, n) => {
                                const i = (e, n, i) => {
                                        [Tt.b.IntroAugmentations, Tt.b.WalkthroughSteps, Tt.b.IntroContext, Tt.b.InputSelectors, Tt.b.LogoSelectors].forEach((e => this._context.set(e, null))), this.scenarioActive = !1, t(e, n, i)
                                    },
                                    o = () => {
                                        this.checkActiveElement() && (this.constructScenarioVars(), this.scenarioActive || (this.scenarioActive = !0, this._taraform.onMessage(e, i)))
                                    };
                                this._dominerDeregister && this._dominerDeregister(), this._dominerDeregister = this._dominer.applyRules(Dt, o), n.detections.forEach((e => {
                                    switch (e.type) {
                                        case Tt.$.LogoDetectionMismatch:
                                            this.extractLogoData(e);
                                            break;
                                        case Tt.$.NoHTTPS:
                                            this._violationsMetadata.httpText = e.text;
                                            break;
                                        case Tt.$.PhishingURL:
                                            this._violationsMetadata.phishingText = e.text
                                    }
                                })), this._context.set(Tt.b.Additionals, n.additional), o()
                            }, this._taraform = e, this._rectUtils = t, this._dominer = i, this._utils = o, this._context = r, n.registerMetadataHandler(St.CredentialFlow, this.flowHandler)
                        }
                        extractLogoData(e) {
                            if (e.vertices) {
                                const t = this._rectUtils.fromVertices(e.vertices),
                                    n = this._rectUtils.center(t),
                                    i = document.elementFromPoint(n.x, n.y),
                                    o = `logo-mistmatch-${this._utils.randomInt()}`;
                                i.setAttribute("data-unbiased-id", o), this._violationsMetadata.logoElement = `[data-unbiased-id="${o}"]`, this._violationsMetadata.logoText = e.text, this._violationsMetadata.logoRect = this._rectUtils.subtract(t, this._rectUtils.topLeft(i.getBoundingClientRect()))
                            } else delete this._violationsMetadata.logoRect, delete this._violationsMetadata.logoElement, delete this._violationsMetadata.logoText
                        }
                        constructScenarioVars() {
                            const e = [],
                                t = [],
                                n = "logo-detection-walkthrough",
                                i = (e, t, i) => ({
                                    type: Z.p.WalkthroughBox,
                                    elementSelectors: [e],
                                    text: t,
                                    nextButton: Mt.Av,
                                    prevButton: Mt.zp,
                                    innerRect: i,
                                    context: n,
                                    xPadding: e === Se ? 100 : 20
                                }),
                                o = (e, t) => ({
                                    type: Z.p.FocusMask,
                                    elementSelectors: [e],
                                    innerRect: t,
                                    context: n
                                }),
                                r = (e, t) => ({
                                    type: Z.p.WarningFrame,
                                    elementSelectors: [e],
                                    innerRect: t
                                }),
                                a = (e, t, n) => [i(e, t, n), o(e, n), r(e, n)];
                            if (this._violationsMetadata.httpText) {
                                const n = {
                                    type: Z.p.UrlBubble,
                                    url: '<span style="{color:red}">http</span>://' + window.location.hostname
                                };
                                e.push(n), t.push({
                                    augmentations: [n, ...a(Se, this._violationsMetadata.httpText)]
                                })
                            }
                            if (this._violationsMetadata.phishingText) {
                                const n = {
                                    type: Z.p.UrlBubble,
                                    url: '<span style="{color:red}">http</span>://' + window.location.hostname
                                };
                                this._violationsMetadata.httpText || e.push(n), t.push({
                                    augmentations: [n, ...a(Se, this._violationsMetadata.phishingText)]
                                })
                            }
                            this._violationsMetadata.logoElement && (e.push({
                                ...r(this._violationsMetadata.logoElement, this._violationsMetadata.logoRect),
                                context: Tt.b.IntroContext
                            }), t.push({
                                augmentations: a(this._violationsMetadata.logoElement, this._violationsMetadata.logoText, this._violationsMetadata.logoRect)
                            })), this._violationsMetadata.inputElement && (e.push({
                                ...r(this._violationsMetadata.inputElement),
                                context: Tt.b.IntroContext
                            }, {
                                type: Z.p.Disabler,
                                elementSelectors: [this._violationsMetadata.inputElement],
                                context: Tt.b.IntroContext
                            }), t.push({
                                augmentations: a(this._violationsMetadata.inputElement, this._violationsMetadata.inputText)
                            })), t[t.length - 1].postProcess = [{
                                type: Lt.O.ClearContext,
                                contexts: [n]
                            }], this._context.set(Tt.b.IntroAugmentations, e), this._context.set(Tt.b.WalkthroughSteps, t), this._context.set(Tt.b.IntroContext, Tt.b.IntroContext), this._context.set(Tt.b.InputSelectors, [this._violationsMetadata.inputElement]), this._context.set(Tt.b.LogoSelectors, [this._violationsMetadata.logoElement])
                        }
                    };
                    Ht = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Ft(0, (0, I.f)(w.ITaraform)), Ft(1, (0, I.f)(Y.IRectUtils)), Ft(2, (0, I.f)(w.IConversationProxy)), Ft(3, (0, I.f)(w.IDominerService)), Ft(4, (0, I.f)(Y.ICommonUtils)), Ft(5, (0, I.f)(Y.IContextStore)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object, Object, Object, Object])], Ht);
                    const Bt = "live-attack-augmentations";
                    var Nt = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let Ut = class {
                        constructor(e, t) {
                            this.flowHandler = (e, t, n) => {
                                const i = [];
                                n.targets.forEach((e => {
                                    i.push({
                                        type: Z.p.WarningFrame,
                                        elementSelectors: e.selectors,
                                        context: "scenario",
                                        radar: {
                                            placement: e.radarPosition,
                                            bubble: {
                                                content: e.text
                                            }
                                        }
                                    })
                                })), this._taraform.setScenarioVar(Bt, i), this._taraform.onMessage(e, ((e, n, i) => {
                                    this._taraform.setScenarioVar(Bt, null), t(e, n, i)
                                }))
                            }, this._taraform = e, t.registerMetadataHandler(St.LiveAttack, this.flowHandler)
                        }
                    };
                    Ut = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Nt(0, (0, I.f)(w.ITaraform)), Nt(1, (0, I.f)(w.IConversationProxy)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], Ut);
                    const Vt = "outlook-addin-categories",
                        zt = "on-change-category-item",
                        Wt = "outlook-adding-violoation-check-next-item";
                    let Gt = class {
                        constructor(e) {
                            this.isArrayLike = e => {
                                if ("number" != typeof e.length) return !1;
                                if (0 === e.length) return !0;
                                const t = typeof e[0];
                                for (let n = 0; n < e.length; n++)
                                    if (typeof e[n] !== t) return !1;
                                return !0
                            }, this.isMainFrame = () => this._config.outlookAddin || self.location === self.parent.location, this.openTab = e => {
                                window.open(e, "_blank").focus()
                            }, this.isEmail = e => !!e.match("(?:[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9][a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])"), this.setLocalStorage = (e, t) => {
                                window.localStorage.setItem(e, JSON.stringify(t))
                            }, this._config = e.config
                        }
                        async sleep(e) {
                            return new Promise((t => setTimeout(t, e)))
                        }
                        randomInt(e = 5) {
                            const t = Math.pow(10, e - 1);
                            return t + Math.floor(Math.random() * (Math.pow(10, e) - t))
                        }
                        removeValFromArray(e, t) {
                            const n = e.indexOf(t);
                            return n > -1 && (e.splice(n, 1), !0)
                        }
                        valueOrDefault(e, t) {
                            return void 0 === e ? t : e
                        }
                        unvar(e, t) {
                            if ("object" != typeof e) return e;
                            if (Array.isArray(e)) {
                                const n = [...e];
                                return n.forEach(((e, n, i) => {
                                    "object" == typeof e && (e.$var && (e = t[e.$var], i.splice(n, 1, e)), i.splice(n, 1, this.unvar(e, t)))
                                })), n
                            }
                            const n = {
                                ...e
                            };
                            for (const e in n) {
                                const i = n[e];
                                if ("object" == typeof i)
                                    if (i.$var) {
                                        let o = t[i.$var];
                                        "object" != typeof o || Array.isArray(o) || (delete i.$var, o = {
                                            ...o,
                                            ...i
                                        }), n[e] = o
                                    } else n[e] = this.unvar(i, t)
                            }
                            return n
                        }
                    };
                    Gt = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    }(0, (0, I.f)(Y.IConfigProvider)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object])], Gt);
                    class $t {
                        constructor(e) {
                            this.config = e
                        }
                        updateConfig(e) {
                            Object.entries(e).forEach((([e, t]) => {
                                this.config[e] = t
                            }))
                        }
                    }
                    const qt = "allow",
                        Yt = "block",
                        Jt = {
                            mini: "mini",
                            categories: "categories",
                            confirmSelectionWithViolation: "confirmSelection",
                            confirmSelectionCheckViolation: "confirmSelectionCheckVar",
                            confirmEncrypt: "confirmEncrypt",
                            encrypting: "encrypting",
                            encrypting2: "encrypting2",
                            sendUnencrypted: "sendUnencrypted",
                            requestSubmitted: "requestSubmitted",
                            end: Yt,
                            send: qt
                        },
                        Zt = new Gt(new $t(re)),
                        Xt = {
                            firstItem: Jt.mini,
                            name: "outlookSendProtect",
                            desc: {
                                [Jt.mini]: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: Jt.categories,
                                    desc: {
                                        [Jt.categories]: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            message: {
                                                text: "The email attachment you're trying to send to someone outside the organization contains sensitive data.                         Please review and confirm the details below before sending the message.",
                                                type: Qe.Jr.CategoryMultiSelect,
                                                categories: {
                                                    $var: Vt
                                                },
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Cancel",
                                                    nextItem: Yt
                                                }, {
                                                    type: Qe.Jz.Primary,
                                                    text: "Confirm",
                                                    nextItem: Jt.confirmSelectionCheckViolation,
                                                    userMessage: "Confirm selection"
                                                }]
                                            }
                                        },
                                        [Jt.confirmSelectionCheckViolation]: {
                                            type: Mt.vd.Empty,
                                            nextItem: {
                                                $var: Wt
                                            }
                                        },
                                        [Jt.confirmSelectionWithViolation]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "According to company policy, attachments being sent to external recipients need                         to be encrypted with a label that limits access to the data for 30 days. Can I go ahead and encrypt the file?"
                                            },
                                            nextItem: Jt.confirmEncrypt
                                        },
                                        [Jt.confirmEncrypt]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                text: "Please confirm you would like to encrypt the file",
                                                type: Qe.Jr.Text,
                                                buttons: [{
                                                    type: Qe.Jz.Primary,
                                                    text: "Confirm",
                                                    nextItem: Jt.encrypting,
                                                    userMessage: "Confirm encryption"
                                                }, {
                                                    text: "Cancel",
                                                    nextItem: Yt
                                                }, {
                                                    text: "I need to send it unencrypted",
                                                    nextItem: Jt.sendUnencrypted,
                                                    userMessage: "Send unencrypted"
                                                }]
                                            },
                                            nextItem: Jt.encrypting
                                        },
                                        [Jt.encrypting]: {
                                            type: Mt.vd.Message,
                                            message: "Great, please hang on while I encrypt it.",
                                            nextItem: Jt.encrypting2
                                        },
                                        [Jt.encrypting2]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                dotsDelay: 3e3,
                                                text: 'All set. I encrypted the file and applied the label."',
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Cancel",
                                                    nextItem: Yt
                                                }, {
                                                    type: Qe.Jz.Primary,
                                                    text: "Send",
                                                    nextItem: qt
                                                }]
                                            }
                                        },
                                        [Jt.sendUnencrypted]: {
                                            type: Mt.vd.Message,
                                            message: "Please add a justification for sending unencrypted attachment",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: Jt.requestSubmitted
                                        },
                                        [Jt.requestSubmitted]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: `Your request was submitted for approval using ServiceNow ticket <a href="" target="_blank">CHG${Zt.randomInt(7)}</a>.                         I'll keep you posted.`,
                                                dotsDelay: 1200,
                                                buttons: [{
                                                    text: "Got it",
                                                    type: Qe.Jz.Primary,
                                                    nextItem: Yt
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Kt = Jt;
                    var Qt = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let en = class {
                        constructor(e, t) {
                            this.flowHandler = (e, t, n) => {
                                const i = {
                                    type: Qe.Jr.CategoryMultiSelect,
                                    text: "",
                                    categories: [{
                                        category: "Recipients",
                                        items: n.recipients[0].emailAddressesDetails.map((e => ({
                                            text: e.displayName,
                                            selected: !0,
                                            warning: e.emailAddress.endsWith("@contoso.to") ? void 0 : "Outside your organization"
                                        }))),
                                        onChangeVar: zt
                                    }, {
                                        category: "Attachemnts",
                                        items: n.attachments.map((e => ({
                                            text: e.name,
                                            selected: !0,
                                            icon: this.fileTypeByName(e.name),
                                            url: e.url
                                        }))),
                                        onChangeVar: zt
                                    }]
                                };
                                this._taraform.setScenarioVar(Vt, i.categories);
                                const o = () => this._taraform.setScenarioVar(Wt, i.categories[0].items.filter((e => !0 === e.selected && e.warning)).length ? Kt.confirmSelectionWithViolation : Kt.send);
                                this._taraform.setScenarioVar(zt, ((e, t, n) => {
                                    i.categories.find((t => t.category === e)).items.find((e => e.text === t)).selected = n, o()
                                })), o(), this._taraform.onMessage(e, ((e, t, o) => {
                                    const r = i.categories[0].items.filter((e => !1 === e.selected)).map((e => n.recipients[0].emailAddressesDetails.find((t => t.displayName === e.text)).emailAddress)),
                                        a = i.categories[1].items.filter((e => !1 === e.selected)).map((e => n.attachments.find((t => t.name === e.text)).id));
                                    n.callback(o, a, r)
                                }))
                            }, this._taraform = e, t.registerMetadataHandler(St.outlookAddin, this.flowHandler)
                        }
                        fileTypeByName(e) {
                            return {
                                docx: "word",
                                xlsx: "excel"
                            } [e.split(".").pop().toLowerCase()]
                        }
                    };
                    en = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Qt(0, (0, I.f)(w.ITaraform)), Qt(1, (0, I.f)(w.IConversationProxy)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], en);
                    const tn = "why-suspicious-showme-steps",
                        nn = "why-suspicious-frame",
                        on = "training-token",
                        rn = "activity-log-data",
                        an = "iframe-aug",
                        sn = "focus-mask";
                    var ln = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let cn = class {
                        constructor(e, t, n) {
                            this.deRegisterArray = [], this.target = [], this.flowHandler = (e, t, n) => {
                                for (let e = 0; e < n.steps.length - 1; e++) {
                                    const t = e > 0 ? n.steps[e - 1] : null,
                                        i = e < n.steps.length - 1 ? n.steps[e + 1] : null,
                                        o = n.steps[e];
                                    t && o.iframeSrc && !t.iframeSrc && (t.clearIframeContext = !0), i && o.iframeSrc && !i.iframeSrc && (i.clearIframeContext = !0)
                                }
                                n.steps.forEach((t => this.processBuilderStep(t, e.itemName))), this._taraform.setScenarioVar(tn, this.target), this.deRegisterArray.push(tn, nn);
                                const i = {
                                    user: n.user,
                                    campaign: n.campaign,
                                    playbook: n.playbook,
                                    tenant: n.tenant,
                                    name: n.name
                                };
                                this._taraform.setScenarioVar(rn, i), this._taraform.setScenarioVar(on, n.token), this._taraform.onMessage(e, ((e, n, i) => {
                                    this.deRegisterArray.forEach((e => this._taraform.setScenarioVar(e, null))), t(e, n, i)
                                }), n)
                            }, this._taraform = e, this._logger = n, t.registerMetadataHandler(St.ShowmeBuilder, this.flowHandler)
                        }
                        getSelectorsBasedAugmentation(e, t, n, i) {
                            const o = [{
                                type: Z.p.WarningFrame,
                                elementSelectors: e.selectors
                            }, {
                                type: Z.p.WalkthroughBox,
                                text: e.text,
                                elementSelectors: e.selectors,
                                nextButton: Mt.Av,
                                prevButton: Mt.zp,
                                context: t,
                                xPadding: n,
                                yPadding: i,
                                titleImage: e.titleImage
                            }];
                            return e.dropFocusMask || o.push({
                                type: Z.p.FocusMask,
                                elementSelectors: e.selectors,
                                context: sn
                            }), o
                        }
                        processIframeBuilderStep(e, t) {
                            const n = {
                                    augmentations: []
                                },
                                i = {
                                    type: Z.p.IFrame,
                                    url: e.iframeSrc,
                                    timeout: re.defaultIframeLoadTimeout,
                                    context: an
                                };
                            n.augmentations.push(i), n.augmentations.push(...this.getSelectorsBasedAugmentation(e, t)), n.postProcess = [{
                                type: Lt.O.StartAugmentationFade
                            }], this.target.push(n), this._taraform.setScenarioVar(nn, {
                                ...i,
                                zIndex: -2
                            })
                        }
                        processUrlBubbleStep(e, t) {
                            e.text.forEach((n => {
                                this.target.push({
                                    augmentations: [{
                                        type: Z.p.UrlBubble,
                                        url: e.urlBubble
                                    }, ...this.getSelectorsBasedAugmentation({
                                        selectors: ["div.bubble-urlbar-text"],
                                        text: n
                                    }, t, 100, 20)]
                                })
                            }))
                        }
                        processElementStep(e, t) {
                            this.target.push({
                                augmentations: [...this.getSelectorsBasedAugmentation(e, t)]
                            })
                        }
                        processBuilderStep(e, t) {
                            if (e.iframeSrc ? this.processIframeBuilderStep(e, t) : e.urlBubble ? this.processUrlBubbleStep(e, t) : e.selectors ? this.processElementStep(e, t) : this._logger.error("Could not infer builder step type:", e), e.clearIframeContext || e.dropFocusMask) {
                                const t = this.target[this.target.length - 1];
                                t.preProcess || (t.preProcess = []);
                                const n = [];
                                e.clearIframeContext && n.push(an), e.dropFocusMask && n.push(sn), t.preProcess.push({
                                    type: Lt.O.ClearContext,
                                    contexts: n
                                })
                            }
                        }
                    };
                    cn = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), ln(0, (0, I.f)(w.ITaraform)), ln(1, (0, I.f)(w.IConversationProxy)), ln(2, (0, I.f)(Y.ILogger)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object])], cn);
                    const dn = [{
                            on: Rt,
                            name: "IdentifyProfileElement",
                            type: "IDENTIFICATION",
                            selectors: ['div[data-test="user-settings-dropdown-toggle"]'],
                            timeout: 12e3,
                            dispatchEvent: "ClickUpSettingsFound"
                        }, {
                            on: "ClickUpSettingsFound",
                            type: "START_CONVERSATION",
                            name: "StartConversation",
                            conversation: "clickUpMfaGuide",
                            context: {
                                userSettingsDropdown: {
                                    selectors: ['div[data-test="user-settings-dropdown-toggle"]'],
                                    validate: !0
                                },
                                userSettingsDropdownMySettings: {
                                    selectors: ['a[data-test="user-settings-menu-item-my-settings"]'],
                                    validate: !1
                                },
                                userSettings2fa: {
                                    selectors: ["div.cu-user-settings__2fa"],
                                    validate: !1
                                }
                            }
                        }],
                        un = [{
                            on: Rt,
                            name: "IdentifyClickUpSignUpEmail",
                            type: "IDENTIFICATION",
                            selectors: ['input[type="email"]'],
                            timeout: 5e3,
                            dispatchEvent: "clickupSignup"
                        }, {
                            on: "clickupSignup",
                            type: "START_CONVERSATION",
                            name: "StartConversation",
                            conversation: "clickupSignup",
                            context: {
                                submitButton: {
                                    validate: !0,
                                    selectors: ['button[type="submit"']
                                },
                                signupEmail: {
                                    validate: !0,
                                    selectors: ['input[id="signup-email"]']
                                },
                                signupEmailRow: {
                                    validate: !0,
                                    selectors: ['div[id="signup-form-email-row"]']
                                }
                            }
                        }],
                        pn = [{
                            on: Rt,
                            name: "waitForAcceptCookies",
                            type: "IDENTIFICATION",
                            selectors: ['div[id="accept"]'],
                            timeout: 2e3,
                            dispatchEvent: "acceptCookiesAvailable"
                        }, {
                            on: "acceptCookiesAvailable",
                            name: "acceptCookiesAvailable",
                            type: "FLOW_HOOK",
                            selectors: ['div[id="accept"]'],
                            event: "click",
                            dispatchEvent: "initTara"
                        }, {
                            on: "initTara",
                            name: "startPhishingDemo",
                            type: "START_CONVERSATION",
                            conversation: "phishing_training"
                        }, {
                            on: Rt,
                            name: "waitForAcceptCookiesMobile",
                            type: "IDENTIFICATION",
                            selectors: ['div[id="accept--mobile"]'],
                            timeout: 2e3,
                            dispatchEvent: "acceptCookiesAvailableMobile"
                        }, {
                            on: "acceptCookiesAvailableMobile",
                            name: "acceptCookiesAvailableMobile",
                            type: "FLOW_HOOK",
                            selectors: ['div[id="accept--mobile"]'],
                            event: "click",
                            dispatchEvent: "initTara"
                        }],
                        hn = "dialogOpened",
                        fn = "uploadDialogDetected",
                        gn = "uploadClosed",
                        mn = [{
                            on: Rt,
                            name: "waitForDialog",
                            type: "OBSERVER",
                            selectors: ["body"],
                            config: {
                                childList: !0,
                                attributes: !0,
                                attributeFilter: ["class"]
                            },
                            searchFor: {
                                addedNodes: [{
                                    classList: ["ReactModalPortal"]
                                }]
                            },
                            dispatchEvent: hn
                        }, {
                            on: hn,
                            name: "verifyUploadDialog",
                            type: "IDENTIFICATION",
                            selectors: ["div.ReactModalPortal button.multifolder-permissions-modal-upload-button,                    div.ReactModalPortal div.cdm-create-folder-modal--dig"],
                            dispatchEvent: fn,
                            timeout: 5e3
                        }, {
                            on: fn,
                            name: "startConversation",
                            type: "START_CONVERSATION",
                            conversation: "dropboxUpload",
                            context: {
                                uploadButton: {
                                    validate: !0,
                                    selectors: ["div.ReactModalPortal button.multifolder-permissions-modal-upload-button,                 div.ReactModalPortal div.cdm-create-folder-modal--dig button.dig-Button:last-of-type"]
                                },
                                cancelButton: {
                                    validate: !0,
                                    selectors: ["div.ReactModalPortal div.multifolder-permissions-modal-footer button.dig-Button:first-of-type,                 div.ReactModalPortal div.cdm-create-folder-modal--dig button.dig-Button:first-of-type"]
                                }
                            }
                        }, {
                            on: fn,
                            name: "waitForDialogClose",
                            type: "OBSERVER",
                            selectors: ["body"],
                            config: {
                                childList: !0,
                                attributes: !0,
                                attributeFilter: ["class"]
                            },
                            searchFor: {
                                removedNodes: [{
                                    classList: ["ReactModalPortal"]
                                }]
                            },
                            dispatchEvent: gn
                        }, {
                            on: gn,
                            name: "endConversation",
                            type: "END_CONVERSATION",
                            conversation: "dropboxUpload"
                        }],
                        yn = [{
                            on: Rt,
                            type: "START_CONVERSATION",
                            conversation: "dropboxSignin",
                            name: "start-dropbox-signin",
                            context: {
                                emailInput: {
                                    validate: !0,
                                    selectors: ['input[type="email"]']
                                }
                            }
                        }],
                        bn = "ShareProcessStarting",
                        xn = "ShareDialogOpened",
                        vn = "WaitForDialog",
                        wn = "IdentifyShareDialog",
                        _n = [{
                            on: Rt,
                            name: "TopShareButtonClick",
                            type: "FLOW_HOOK",
                            selectors: ["span#docs-titlebar-share-client-button div.jfk-button-action"],
                            event: "click",
                            dispatchEvent: bn
                        }, {
                            on: bn,
                            name: "IdentifyShareDialogSequence",
                            type: "SEQUENCE",
                            ruleSequence: [vn, wn],
                            dispatchEvent: xn
                        }, {
                            name: vn,
                            type: "IDENTIFICATION",
                            timeout: 6e3,
                            selectors: ["iframe[src^='/sharing/drive']", "div.quantumWizDialogBackground.isOpen"]
                        }, {
                            name: wn,
                            type: "IDENTIFICATION",
                            timeout: 2e3,
                            selectors: ["iframe[src^='/sharing/drive']", ".boqDrivesharedialogCommonAnimatedfadeContainer > div > .boqDrivesharedialogCommonTitlebarTitleBar"]
                        }, {
                            on: xn,
                            name: "WaitForAnyoneWithLink",
                            type: "OBSERVER",
                            selectors: ["iframe[src^='/sharing/drive']", ".boqDrivesharedialogDialogsShareCardContainer:nth-child(2)"],
                            config: {
                                characterData: !0,
                                subtree: !0
                            },
                            searchFor: {
                                target: {
                                    wholeText: "Anyone on the [iI]nternet with this link can view"
                                }
                            },
                            dispatchEvent: "AnyoneWithLink"
                        }],
                        kn = "ContextMenuTriggered",
                        Cn = "ContextMenuShareButtonFound",
                        Sn = "ShareProcessStarting",
                        En = "ShareDialogOpened",
                        In = "WaitForDialog",
                        An = "IdentifyShareDialog",
                        On = [{
                            on: Rt,
                            name: "BodyContextMenuHook",
                            type: "FLOW_HOOK",
                            selectors: ["body"],
                            event: "contextmenu",
                            dispatchEvent: kn
                        }, {
                            on: kn,
                            name: "IdentifyShareButton",
                            type: "IDENTIFICATION",
                            selectors: ['div.h-w.a-w.a-w-Xi.a-mb-w.a-w-Mr div[data-tooltip^="Share "'],
                            dispatchEvent: Cn,
                            timeout: 1e3
                        }, {
                            on: Cn,
                            type: "FLOW_HOOK",
                            name: "ShareButtonHook",
                            event: "mouseup",
                            selectors: ["div.h-w.a-w.a-w-Xi.a-mb-w.a-w-Mr"],
                            condition: {
                                target: {
                                    innerText: "Share"
                                }
                            },
                            dispatchEvent: Sn
                        }, {
                            on: Sn,
                            name: "IdentifyShareDialogSequence",
                            type: "SEQUENCE",
                            ruleSequence: [In, An],
                            dispatchEvent: En
                        }, {
                            name: In,
                            type: "IDENTIFICATION",
                            timeout: 6e3,
                            selectors: ["iframe[src^='/sharing/share']", "div.quantumWizDialogBackground.isOpen"]
                        }, {
                            name: An,
                            type: "IDENTIFICATION",
                            timeout: 5e3,
                            selectors: ["iframe[src^='/sharing/share']", ".boqDrivesharedialogCommonAnimatedfadeContainer > div > .boqDrivesharedialogCommonTitlebarTitleBar"]
                        }, {
                            on: En,
                            name: "WaitForAnyoneWithLink",
                            type: "OBSERVER",
                            selectors: ["iframe[src^='/sharing/share']", ".boqDrivesharedialogDialogsShareCardContainer:nth-child(2)"],
                            config: {
                                characterData: !0,
                                subtree: !0
                            },
                            searchFor: {
                                target: {
                                    wholeText: "Anyone on the [iI]nternet with this link can view"
                                }
                            },
                            dispatchEvent: "AnyoneWithLink"
                        }],
                        Tn = "ContextMenuTriggered",
                        Mn = "ContextMenuShareButtonFound",
                        Rn = "ShareProcessStarting",
                        Pn = "ShareDialogOpened",
                        Dn = "AnyoneWithLink",
                        jn = "LinkSettingsOpen",
                        Ln = "LinkSettingsOpening",
                        Fn = "MenuShareButtonFound",
                        Hn = "DetailsListAvailable",
                        Bn = "DetailsListClicked",
                        Nn = "CancelAnyoneWithLink",
                        Un = [{
                            on: Rt,
                            name: "WaitForDetailsList",
                            type: "IDENTIFICATION",
                            selectors: ["div.ms-DetailsList-contentWrapper"],
                            timeout: 5e3,
                            dispatchEvent: Hn
                        }, {
                            on: Hn,
                            name: "DetailsListHook",
                            type: "FLOW_HOOK",
                            selectors: ["div.ms-DetailsList-contentWrapper"],
                            event: "click",
                            dispatchEvent: Bn
                        }, {
                            on: Hn,
                            name: "HookItemShareButtons",
                            type: "FLOW_HOOK",
                            selectors: ['button[aria-label="Share the selected item with other people"]'],
                            selectMultiple: !0,
                            event: "click",
                            dispatchEvent: Rn
                        }, {
                            on: Bn,
                            type: "IDENTIFICATION",
                            name: "WaitForCommandBar",
                            selectors: ['button[role="menuitem"][name="Share"]'],
                            timeout: 1e3,
                            dispatchEvent: Fn
                        }, {
                            on: Fn,
                            name: "TopActionsShareButtonHook",
                            type: "FLOW_HOOK",
                            selectors: ['button[role="menuitem"][name="Share"]'],
                            event: "click",
                            dispatchEvent: Rn
                        }, {
                            on: Rt,
                            name: "BodyContextMenuHook",
                            type: "FLOW_HOOK",
                            selectors: ["body"],
                            event: "contextmenu",
                            dispatchEvent: Tn
                        }, {
                            on: Tn,
                            name: "IdentifyShareButton",
                            type: "IDENTIFICATION",
                            selectors: ['div.ms-ContextualMenu-container button[data-automationid="shareCommand"'],
                            dispatchEvent: Mn,
                            timeout: 1e3
                        }, {
                            on: Mn,
                            type: "FLOW_HOOK",
                            name: "ContextMenuShareButtonHook",
                            event: "click",
                            selectors: ['div.ms-ContextualMenu-container button[data-automationid="shareCommand"'],
                            condition: {
                                target: {
                                    innerText: "Share"
                                }
                            },
                            dispatchEvent: Rn
                        }, {
                            on: Rn,
                            name: "WaitForShareDialog",
                            type: "IDENTIFICATION",
                            timeout: 6e3,
                            selectors: ['iframe[id="shareFrame"]', "div.od-ShareHintDetail"],
                            dispatchEvent: Pn
                        }, {
                            on: Pn,
                            name: "LinkSettingsClickHook",
                            type: "FLOW_HOOK",
                            event: "click",
                            selectors: ['iframe[id="shareFrame"]', 'div[aria-label="Link settings"]'],
                            dispatchEvent: Ln
                        }, {
                            on: Ln,
                            type: "IDENTIFICATION",
                            name: "WaitForLinkSettingsOpen",
                            selectors: ['iframe[id="shareFrame"]', 'button[aria-label="Anyone with the link  "]'],
                            timeout: 2e3,
                            dispatchEvent: jn
                        }, {
                            on: jn,
                            name: "IsAnyoneWithLink",
                            timeout: 20,
                            type: "IDENTIFICATION",
                            selectors: ['iframe[id="shareFrame"]', 'button[aria-label="Anyone with the link  "][aria-checked="true"]'],
                            dispatchEvent: Dn
                        }, {
                            on: Dn,
                            name: "startAnyoneWithLinkConversation",
                            type: "START_CONVERSATION",
                            conversation: "anyoneWithLink",
                            context: {
                                applyButton: {
                                    validate: !0,
                                    selectors: ['iframe[id="shareFrame"]', ".od-ModifyPermissions-actions button:nth-child(1)"]
                                },
                                anyoneWithLinkOption: {
                                    validate: !0,
                                    selectors: ['iframe[id="shareFrame"]', '[aria-label="Anyone with the link  "]']
                                },
                                expirationDate: {
                                    validate: !0,
                                    selectors: ['iframe[id="shareFrame"]', 'div[aria-label*="expiration date" i]']
                                },
                                datePicker: {
                                    validate: !1,
                                    selectors: ['iframe[id="shareFrame"]', "div.ms-DatePicker-callout"]
                                },
                                datePickerDateArea: {
                                    validate: !1,
                                    selectors: ['iframe[id="shareFrame"]', "div.ms-DatePicker-callout .ms-DatePicker-table tbody"]
                                }
                            }
                        }, {
                            on: jn,
                            name: "WaitForAnyoneWithLink",
                            type: "OBSERVER",
                            selectors: ['iframe[id="shareFrame"]', 'button[aria-label="Anyone with the link  "]'],
                            config: {
                                attributes: !0,
                                attributeFilter: ["aria-checked"]
                            },
                            searchFor: {
                                target: {
                                    classList: ["is-selected"]
                                }
                            },
                            dispatchEvent: Dn
                        }, {
                            on: Dn,
                            name: "BodyClickCancelIframeHook",
                            event: "click",
                            selectors: ["body"],
                            dispatchEvent: Nn,
                            type: "FLOW_HOOK"
                        }, {
                            on: Dn,
                            name: "CancelAnyoneWithLink",
                            type: "OBSERVER",
                            selectors: ['iframe[id="shareFrame"]', 'button[aria-label="Anyone with the link  "]'],
                            config: {
                                attributes: !0,
                                attributeFilter: ["aria-checked"]
                            },
                            searchFor: {
                                target: {
                                    classList: ["!is-selected"]
                                }
                            },
                            dispatchEvent: Nn
                        }, {
                            on: jn,
                            name: "ShareDialogCloseButton",
                            type: "FLOW_HOOK",
                            event: "click",
                            selectors: ['iframe[id="shareFrame"]', 'button[aria-label="Close"]'],
                            dispatchEvent: Nn
                        }, {
                            on: jn,
                            name: "LinkSettingsCloseApplyHook",
                            type: "FLOW_HOOK",
                            event: "click",
                            selectors: ['iframe[id="shareFrame"]', 'button[id="od-ModifyPermissions-apply-id"]'],
                            dispatchEvent: Rn
                        }, {
                            on: jn,
                            name: "LinkSettingsCloseCancelHook",
                            type: "FLOW_HOOK",
                            event: "click",
                            selectors: ['iframe[id="shareFrame"]', "div.od-ModifyPermissions-actions button.ms-Button--default"],
                            dispatchEvent: Rn
                        }, {
                            on: jn,
                            name: "LinkSettingsCloseCancelHook2",
                            type: "FLOW_HOOK",
                            event: "click",
                            selectors: ['iframe[id="shareFrame"]', "div.od-ModifyPermissions-actions button.ms-Button--default"],
                            dispatchEvent: Nn
                        }, {
                            on: Nn,
                            name: "cancelAnyoneWithLinkConversation",
                            type: "END_CONVERSATION",
                            conversation: "anyoneWithLink"
                        }];
                    var Vn = n(9058),
                        zn = function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    let Wn = class {
                        constructor(e, t, n, i, o, r) {
                            this._conversationProxy = e, this._indicator = n, this._tara = t, this._utils = i, this._domUtils = o, this._context = r;
                            const a = Vn.logger.getLogger();
                            Vn.logger.isContextualLogger(a) ? this._logger = a.extendContextualLogger("dominer", {}) : this._logger = Vn.logger.newContextualLogger({}, null, "dominer"), this._logger.setLevel("debug"), this.trackRules()
                        }
                        getRules(e) {
                            return function(e) {
                                const t = {
                                    "https://docs.google.com/document/d/[0-9a-zA-Z-_]+/edit": _n,
                                    "https://drive.google.com/.*": On,
                                    "https://[a-zA-Z0-9-]+.sharepoint.com/.*/onedrive.aspx": Un,
                                    "https://app.clickup.com/signup": un,
                                    "https://app.clickup.com/\\d+/v/l/.*": dn,
                                    "https://micr0soft-365.xyz/index3.html": pn,
                                    "https://www.dropbox.com/home": mn,
                                    "https://www.dropbox.com/login": yn
                                };
                                for (const [n, i] of Object.entries(t))
                                    if (e.match(new RegExp(n))) return i
                            }(e)
                        }
                        getConversation(e) {
                            return function(e) {
                                const t = {};
                                for (const [n, i] of Object.entries(t))
                                    if (e.match(new RegExp(n))) return i
                            }(e)
                        }
                        applyRules(e, t, n, i) {
                            const o = {
                                startConversation: this._conversationProxy.startConversation,
                                endConversation: this._conversationProxy.endConversation,
                                callback: t,
                                setSymbol: this._context.set
                            };
                            return function(e, t, n, i, o, r) {
                                const a = {};

                                function s(e, t) {
                                    a[e] && (i.debug(`Duplicate de-register called for ${e}. This can happen when node is removed and reinserted.`), a[e]()), a[e] = () => {
                                        i.debug(`Running deregistration for rule '${e}'`), t()
                                    }
                                }

                                function l(e, n) {
                                    i.debug("Dispatching event: " + e), t.dispatchEvent(new CustomEvent(e, {
                                        detail: n
                                    }))
                                }

                                function c(t) {
                                    return e.find((e => e.name === t))
                                }
                                async function d(e) {
                                    i.debug("starting rule sequence ", e.name, e.ruleSequence);
                                    for (const t of e.ruleSequence) {
                                        i.debug("starting rule " + t + " of sequence", e.ruleSequence);
                                        const n = c(t);
                                        if (!n) throw new Error("Invalid rule in ruleSequence: " + t);
                                        if (!await b(n)) return i.debug("rule " + t + " failed. stopping sequence"), !1
                                    }
                                    return e.dispatchEvent && l(e.dispatchEvent, e.eventDetails), !0
                                }
                                async function u(e) {
                                    const t = e.timeout ? await r.getElementsWithTimeout(e.selectors, e.timeout) : r.getElements(e.selectors);
                                    return t.length ? (e.promise && e.promise.resolve(null), new Promise((n => {
                                        const o = t => {
                                                if (i.debug("Flow hook triggered " + e.name), e.condition && !h(e.condition, t)) return i.debug("Condition not matched"), void n(!1);
                                                e.dispatchEvent && l(e.dispatchEvent), n(!0)
                                            },
                                            r = [];
                                        s(`${e.name}-hook`, (() => r.forEach((t => t.removeEventListener(e.event, o, {
                                            capture: !0
                                        }))))), t.forEach((t => {
                                            r.push(t), t.addEventListener(e.event, o, {
                                                capture: !0
                                            })
                                        }))
                                    }))) : (e.promise && e.promise.reject(`Element not found for selector: '${e.selectors.toString()}'`), i.error(`Element not found for selector: '${e.selectors.toString()}'`), !1)
                                }
                                async function p(e) {
                                    const t = e.timeout ? await r.getElementWithTimeout(e.selectors, e.timeout) : r.getElement(e.selectors);
                                    return t ? (e.dispatchEvent && l(e.dispatchEvent), i.debug("Element identified!", t)) : i.debug("Could not find element for selectors", e.selectors, "rule", e.name), !!t
                                }

                                function h(e, t) {
                                    if (typeof e != typeof t) return !1;
                                    if (["boolean", "string", "number", "bigint", "symbol"].includes(typeof e)) return e === t;
                                    if (["function", "undefined"].includes(typeof t)) return !1;
                                    if (Array.isArray(e)) {
                                        if (!o.isArrayLike(t)) return !1;
                                        const n = Array.from(t);
                                        for (const t of e)
                                            if ("string" == typeof t) {
                                                if (t.startsWith("!") && !n.includes(t.substring(1)) || !t.startsWith("!") && n.includes(t)) return !0
                                            } else
                                                for (let e = 0; e < n.length; e++)
                                                    if (h(t, n[e])) return !0;
                                        return !1
                                    }
                                    for (const n of Object.keys(e))
                                        if (void 0 !== t[n] && h(e[n], t[n])) return !0;
                                    return !1
                                }
                                async function f(e) {
                                    let t = null;
                                    const n = e.timeout ? await r.getElementWithTimeout(e.selectors, e.timeout) : r.getElement(e.selectors);
                                    return n ? new Promise((o => {
                                        t = new MutationObserver((t => {
                                            t.forEach((t => {
                                                h(e.searchFor, t) && (l(e.dispatchEvent), o(!0))
                                            }))
                                        })), s(`${e.name}-observe`, (() => t.disconnect())), i.debug("observing", n, e.config), t.observe(n, e.config), e.promise && e.promise.resolve(null)
                                    })) : (e.promise && e.promise.reject("Cannot find target observation node " + e.selectors.toString()), i.error("Cannot find target observation node " + e.selectors.toString()), !1)
                                }

                                function g(e) {
                                    if (e.context) {
                                        let t = !0;
                                        if (Object.entries(e.context).filter((([e, t]) => t.validate)).forEach((([n, o]) => {
                                                r.getElement(o.selectors) || (t = !1, i.error(`Cannot trigger startConversation. Context element missing.                     Rule: ${e.name}, Symbol: ${n}, selectors: ${o.selectors.toString()}`))
                                            })), !t) return;
                                        Object.entries(e.context).forEach((([e, t]) => n.setSymbol(e, t.selectors)))
                                    }
                                    return n.startConversation(e.conversation), !0
                                }

                                function m(e) {
                                    return n.endConversation(e.conversation), !0
                                }

                                function y() {
                                    return n.callback && n.callback(), !0
                                }
                                async function b(e) {
                                    try {
                                        i.debug("Processing " + e.type + " rule " + e.name, e);
                                        const t = {
                                            SEQUENCE: d,
                                            FLOW_HOOK: u,
                                            IDENTIFICATION: p,
                                            OBSERVER: f,
                                            START_CONVERSATION: g,
                                            END_CONVERSATION: m,
                                            CALLBACK: y
                                        };
                                        if (!t[e.type]) throw new Error("Unexpected rule type " + e.type);
                                        const n = await t[e.type](e);
                                        return e.promise && e.promise.resolve(n), n
                                    } catch (t) {
                                        e.promise && e.promise.reject(t.message), i.error(t)
                                    }
                                } {
                                    const t = {};
                                    for (const n of e) {
                                        if (t[n.name]) throw new Error(`Rules names must be unique! found duplicate rule '${n.name}'`);
                                        t[n.name] = !0
                                    }
                                }
                                return e.filter((e => !!e.on)).forEach((e => function(e) {
                                    i.debug("Registering event listener for " + e.name);
                                    const n = t => {
                                        i.debug("Event triggered " + t.type), b(e)
                                    };
                                    s(`${e.name}-listener`, (() => t.removeEventListener(e.on, n))), t.addEventListener(e.on, n)
                                }(e))), l(Rt), () => {
                                    Object.values(a).forEach((e => e()))
                                }
                            }(e, n || this._tara.frame(), o, i || this._logger, this._utils, this._domUtils)
                        }
                        trackRules() {
                            let e = null;
                            const t = () => {
                                const t = this.getRules(window.location.href);
                                t && (e && e(), this._indicator.show(), e = this.applyRules(t, null, this._tara.frame(), this._logger));
                                const n = this.getConversation(window.location.href);
                                n && (this._indicator.show(), this._conversationProxy.startConversation(n))
                            };
                            t();
                            let n = window.location.href;
                            setInterval((() => {
                                window.location.href !== n && (t(), n = window.location.href)
                            }), 1e3)
                        }
                    };
                    Wn = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), zn(0, (0, I.f)(w.IConversationProxy)), zn(1, (0, I.f)(w.ITara)), zn(2, (0, I.f)(w.IIndicator)), zn(3, (0, I.f)(Y.ICommonUtils)), zn(4, (0, I.f)(Y.IDomUtils)), zn(5, (0, I.f)(Y.IContextStore)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object, Object, Object, Object])], Wn);
                    const Gn = {
                            IMessageParser: Symbol.for("IMessageParser"),
                            IOperator: Symbol.for("IOperator"),
                            IConditioner: Symbol.for("IConditioner")
                        },
                        $n = {
                            IActivityLogger: Symbol.for("IActivityLogger")
                        };
                    var qn = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let Yn = class {
                        constructor(e, t, n, i, o, r, a, s, l, c, d, u) {
                            this.onUserInput = e => {
                                this._tara.addMessage({
                                    text: e,
                                    type: Ze.User,
                                    key: `resp-${this._utils.randomInt()}`,
                                    status: ue.wi.Healthy
                                })
                            }, this.handleOperationList = async e => {
                                for (let t = 0; t < e.length; t++) await this.handleOperation(e[t])
                            }, this.handleOperation = async e => {
                                switch (e.type) {
                                    case Lt.O.HideTara:
                                        this._tara.hide();
                                        break;
                                    case Lt.O.ShowTara:
                                        this._tara.show(), this._indicator.show();
                                        break;
                                    case Lt.O.WaitForUserInput:
                                        await this._operator.waitForUserInput(this._tara, e);
                                        break;
                                    case Lt.O.WaitForEvent:
                                        await this._operator.waitForEvent(e.event, e.elementSelectors);
                                        break;
                                    case Lt.O.Delay:
                                        await this._utils.sleep(e.ms);
                                        break;
                                    case Lt.O.ClearContext:
                                        e.contexts.forEach((e => this._meddler.contextDone(e)));
                                        break;
                                    case Lt.O.SetVariable:
                                        this._context.set(e.name, e.value);
                                        break;
                                    case Lt.O.ClearVariable:
                                        this._context.set(e.name, null);
                                        break;
                                    case Lt.O.RemoveDomElements:
                                        this._domUtils.getElements(e.elementSelectors).forEach((e => e.remove()));
                                        break;
                                    case Lt.O.StartAugmentationFade:
                                        this._meddler.fadeAugmentations(!0);
                                        break;
                                    case Lt.O.StopAugmentationFade:
                                        this._meddler.fadeAugmentations(!1);
                                        break;
                                    case Lt.O.HideIndicator:
                                        this._indicator.hide();
                                        break;
                                    case Lt.O.ActivityLog:
                                        this._activityLogger.sendLog(e.token, e.data);
                                        break;
                                    case Lt.O.OpenTab:
                                        this._utils.openTab(e.url);
                                        break;
                                    case Lt.O.ReleasePendingDownload:
                                        this._downloader.releasePendingDownload(e.downloadId);
                                        break;
                                    case Lt.O.FocusElement:
                                        this._domUtils.focusElement(e.elementSelectors);
                                        break;
                                    case Lt.O.SetLocalStorage:
                                        this._utils.setLocalStorage(e.key, e.value);
                                        break;
                                    case Lt.O.GetElementData:
                                        this._context.set(e.varName, this._domUtils.getElementData(e.elementSelectors, e.attribute));
                                        break;
                                    case Lt.O.SetElementData:
                                        this._domUtils.setElementData(e.elementSelectors, e.value, e.attribute)
                                }
                            }, this.onMessage = (e, t) => {
                                const n = (e, n, i, o) => {
                                    t(e, n, o)
                                };
                                e.type === Mt.vd.MiniScenario ? this.handleMiniScenario(e, n) : this.handleAtomicItem(e, n)
                            }, this.setStatus = e => {
                                this._tara.setStatus(e), this._indicator.setStatus(e)
                            }, this.setScenarioVar = (e, t) => {
                                this._logger.warn('Used deprecated method "setScenarioVar"', (new Error).stack), this._context.set(e, t)
                            }, this.getScenarioVar = e => (this._logger.warn('Used deprecated method "getScenarioVar"', (new Error).stack), this._context.get(e)), this._tara = e, this._indicator = t, this._meddler = n, this._messageParser = i, this._logger = a, this._conditioner = o, this._operator = r, this._utils = s, this._domUtils = l, this._activityLogger = c, this._downloader = d, this._context = u
                        }
                        init() {
                            this._tara.addUserInputListener(this.onUserInput)
                        }
                        handleMiniScenario(e, t) {
                            let n = null;
                            const i = (o, r, a, s) => {
                                if (e.desc[s]) return e.desc[s].itemName = s, setTimeout((() => {
                                    this.handleAtomicItem(e.desc[s], i)
                                }), 0);
                                this._tara.removeUserInputListener(n), t(o, r, a, s)
                            };
                            n = t => {
                                if (e.desc[t]) return e.desc[t].itemName = t, this._tara.addMessage({
                                    text: t,
                                    type: Ze.User,
                                    key: `resp-${this._utils.randomInt()}`,
                                    status: ue.wi.Healthy
                                }), setTimeout((() => {
                                    this.handleAtomicItem(e.desc[t], i)
                                }), 0), ue.cg.None
                            }, this._tara.addUserInputListener(n), this.handleAtomicItem(e.desc[e.firstItem], i)
                        }
                        async handleAtomicItem(e, t) {
                            const n = this._utils.unvar(e, this._context.getContext()),
                                i = async (e, i, o, r) => {
                                    i !== ue.OP.Automatic && e && this._tara.addMessage({
                                        text: e,
                                        type: Ze.User,
                                        key: `resp-${o}`,
                                        status: ue.wi.Healthy
                                    }), n.postProcess && await this.handleOperationList(n.postProcess), n.augmentations && this._meddler.contextDone(n.itemName), r && t(e, i, o, r)
                                };
                            n.preProcess && await this.handleOperationList(n.preProcess), n.taraStatus && this.setStatus(n.taraStatus);
                            const o = n.augmentations ? this._meddler.processItemAugmentations(n.augmentations, n.itemName, i) : [];
                            this._meddler.augment(n.itemName, o), {
                                [Mt.vd.Empty]: () => i("", ue.OP.Automatic, "", n.nextItem),
                                [Mt.vd.Message]: () => this.handleMessageItem(n, i),
                                [Mt.vd.Condition]: () => this.handleConditionItem(n, i),
                                [Mt.vd.Recursive]: () => this.handleRecursiveItem(n, i)
                            } [n.type]()
                        }
                        handleConditionItem(e, t) {
                            const n = this._conditioner.checkCondition(e);
                            t("", ue.OP.Automatic, e.itemName, n ? e.ifTrue : e.ifFalse)
                        }
                        handleMessageItem(e, t) {
                            this._tara.setChips(e.chips || []), this._tara.addMessage(this._messageParser.scenarioMessage2TaraMessage(e, t, this.handleOperation)), e.message.buttons || t("", ue.OP.Automatic, e.itemName, e.nextItem)
                        }
                        handleRecursiveItem(e, t) {
                            let n = 0;
                            const i = () => `${e.itemName}-step${n}`;
                            let o = null;
                            const r = async () => {
                                const t = e.steps[n];
                                t.preProcess && await this.handleOperationList(t.preProcess);
                                const r = t.augmentations ? this._meddler.processItemAugmentations(t.augmentations, i(), o) : [];
                                r.forEach((t => {
                                    t.type === Z.p.WalkthroughBox && (t.index = n + 1, t.total = e.steps.length)
                                })), this._meddler.augment(i(), r), t.autoNextTimeoutMs && setTimeout((() => o("", ue.OP.Automatic, i(), Mt.Av)), t.autoNextTimeoutMs)
                            };
                            o = async (o, a, s, l) => {
                                const c = e.steps[n];
                                if (c.postProcess && await this.handleOperationList(c.postProcess), this._meddler.contextDone(i()), l === Mt.Av) n += 1;
                                else {
                                    if (l !== Mt.zp) return t(o, a, e.itemName, l);
                                    n -= 1
                                }
                                if (n === e.steps.length) return e.doneMessage && this._tara.addMessage({
                                    text: e.doneMessage,
                                    key: s,
                                    type: Ze.Tara,
                                    status: ue.wi.Healthy
                                }), t(e.doneMessage, ue.OP.Automatic, e.itemName, e.nextItem);
                                r()
                            }, r()
                        }
                        resetState() {
                            this.setStatus(ue.wi.Healthy), this._tara.hide(), this._meddler.clearAll()
                        }
                    };
                    Yn = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), qn(0, (0, I.f)(w.ITara)), qn(1, (0, I.f)(w.IIndicator)), qn(2, (0, I.f)(w.IMeddler)), qn(3, (0, I.f)(Gn.IMessageParser)), qn(4, (0, I.f)(Gn.IConditioner)), qn(5, (0, I.f)(Gn.IOperator)), qn(6, (0, I.f)(Y.ILogger)), qn(7, (0, I.f)(Y.ICommonUtils)), qn(8, (0, I.f)(Y.IDomUtils)), qn(9, (0, I.f)($n.IActivityLogger)), qn(10, (0, I.f)(w.IDownloader)), qn(11, (0, I.f)(Y.IContextStore)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object, Object, Object, Object, Object, Object, Object, Object, Object, Object])], Yn);
                    var Jn = n(8772),
                        Zn = n(2023),
                        Xn = function(e, t) {
                            return function(n, i) {
                                t(n, i, e)
                            }
                        };
                    const Kn = Vn.logger.getLogger(v);
                    let Qn = class {
                        constructor(e, t) {
                            this._domUtils = e, this._commonUtils = t
                        }
                        isBusinessEmail(e, t) {
                            if (this._commonUtils.isEmail(e)) return t.some((t => {
                                if (!e.endsWith(`.${t.data2}`)) return !1;
                                const n = e.substring(e.indexOf("@") + 1, e.length - t.data2.length - 1);
                                return (0, Zn.sha256)(n + (window.unbiasdLocaion || window.location).hostname) === t.data1
                            }))
                        }
                        valueBasedCondition(e, t, n, i) {
                            const o = {
                                [Jn.fo.Equal]: () => t === n,
                                [Jn.fo.Greater]: () => t > n,
                                [Jn.fo.GreaterEqual]: () => t >= n,
                                [Jn.fo.Less]: () => t < n,
                                [Jn.fo.LessEqual]: () => t <= n,
                                [Jn.fo.Between]: () => t >= n && t < i,
                                [Jn.fo.EndsWith]: () => "string" == typeof t && t.endsWith(n),
                                [Jn.fo.Regex]: () => "string" == typeof t && !!t.match(new RegExp(n)),
                                [Jn.fo.BusinessEmail]: () => this.isBusinessEmail(t, n)
                            };
                            return o[e.op] || Kn.error("Error in conditioner - valueBasedCondition - cannot find op for condition", e), o[e.op]()
                        }
                        getValue(e, t) {
                            switch (e.type) {
                                case Jn.CP.ElementValue:
                                    return t.textContent || t.value;
                                case Jn.CP.ElementAttribute:
                                    return t.getAttribute(e.attribute);
                                default:
                                    Kn.error("Error in conditioner getValue - invalid condition type", e)
                            }
                        }
                        parseValue(e, t) {
                            const n = {
                                [Jn.nY.Date]: () => new Date(t).getTime(),
                                [Jn.nY.Number]: () => parseFloat(`${t}`),
                                [Jn.nY.String]: () => `${t}`
                            };
                            return n[e.dataType] || Kn.error("Error in conditioner parseValue - no parser found for condition", e), n[e.dataType]()
                        }
                        getCompareValues(e) {
                            switch (e.op) {
                                case Jn.fo.Between: {
                                    const t = e.base === Jn._j ? new Date : new Date(this.parseValue(e, e.base));
                                    return {
                                        [Jn.nY.Date]: () => [t, new Date(t.getTime() + 1e3 * e.target)].sort(((e, t) => e.getTime() - t.getTime())),
                                        [Jn.nY.Number]: () => [e.base, e.target],
                                        [Jn.nY.String]: () => {
                                            throw new Error("Unexpected string data type with op between.")
                                        }
                                    } [e.dataType]()
                                }
                                case Jn.fo.BusinessEmail:
                                    return [e.target, null];
                                default:
                                    return [this.parseValue(e, e.target), null]
                            }
                        }
                        checkCondition(e) {
                            const t = this._domUtils.getElement(e.elementSelectors);
                            if (!t) return !1;
                            const n = this.parseValue(e.condition, this.getValue(e.condition, t)),
                                [i, o] = this.getCompareValues(e.condition);
                            return this.valueBasedCondition(e.condition, n, i, o)
                        }
                    };
                    Qn = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Xn(0, (0, I.f)(Y.IDomUtils)), Xn(1, (0, I.f)(Y.ICommonUtils)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], Qn);
                    var ei = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let ti = class {
                        constructor(e, t) {
                            this._logger = t, this._context = e
                        }
                        scenarioMessage2TaraMessage(e, t, n) {
                            const i = "string" == typeof e.message ? {
                                type: Qe.Jr.Text,
                                text: e.message,
                                buttons: e.buttons
                            } : e.message;
                            let o;
                            switch (e.message = i, i.type) {
                                case Qe.Jr.Text: {
                                    const t = i;
                                    o = {
                                        text: t.text,
                                        type: Ze.Tara,
                                        status: e.taraStatus || ue.wi.Healthy,
                                        key: e.itemName,
                                        dotsDelay: t.dotsDelay
                                    }
                                }
                                break;
                            case Qe.Jr.Title: {
                                const t = e.message;
                                o = {
                                    text: t.text,
                                    type: Ze.Title,
                                    status: e.taraStatus || ue.wi.Healthy,
                                    key: e.itemName,
                                    title: t.title,
                                    img: t.img
                                }
                            }
                            break;
                            case Qe.Jr.CategoryMultiSelect: {
                                const t = e.message;
                                o = {
                                    text: t.text,
                                    type: Ze.CategoryMultiSelect,
                                    categories: t.categories.map((e => ({
                                        ...e,
                                        onChange: e.onChangeVar ? this._context.get(e.onChangeVar) : void 0
                                    }))),
                                    key: e.itemName,
                                    status: e.taraStatus || ue.wi.Healthy
                                }
                            }
                            }
                            return e.buttons && (this._logger.warn("DEPRECATED usage of the buttons keyword in scenario item"), delete e.buttons), i.buttons && (o.buttons = [], i.buttons.forEach(((i, r) => {
                                switch (i.type) {
                                    case void 0:
                                    case Qe.Jz.Primary:
                                    case Qe.Jz.Secondary:
                                        o.buttons.push({
                                            text: i.text,
                                            click: () => {
                                                "op" in i && n(i.op), "nextItem" in i && t(i.text, ue.OP.Predefined, e.itemName, i.nextItem)
                                            },
                                            style: i.type === Qe.Jz.Primary ? Je.Primary : Je.Secondary,
                                            userMessage: i.userMessage ? i.userMessage : i.text,
                                            layout: 0 === r ? i.layout || Qe.LS.Column : void 0
                                        });
                                        break;
                                    case Qe.Jz.Image:
                                        o.buttons.push({
                                            img: i.img,
                                            click: () => {
                                                "op" in i && n(i.op), "nextItem" in i && t(i.userMessage, ue.OP.Predefined, e.itemName, i.nextItem)
                                            },
                                            style: Je.Image,
                                            userMessage: i.userMessage,
                                            layout: 0 === r ? i.layout || Qe.LS.Column : void 0
                                        })
                                }
                            }))), o
                        }
                    };
                    ti = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), ei(0, (0, I.f)(Y.IContextStore)), ei(1, (0, I.f)(Y.ILogger)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], ti);
                    var ni = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let ii = class {
                        constructor(e, t) {
                            this._domUtils = e, this._activityLogger = t
                        }
                        async waitForEvent(e, t) {
                            const n = await this._domUtils.getElementWithTimeout(t, 120);
                            return new Promise((t => {
                                n.addEventListener(e, (function i() {
                                    n.removeEventListener(e, i), t(null)
                                }))
                            }))
                        }
                        waitForUserInput(e, t) {
                            return new Promise((n => {
                                const i = o => (n(null), e.removeUserInputListener(i), t.logData && this._activityLogger.sendLog(t.token, {
                                    ...t.logData,
                                    feedback: o
                                }), t.propagate);
                                e.addUserInputListener(i), this._domUtils.focusElement(ue.xG)
                            }))
                        }
                    };
                    ii = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), ni(0, (0, I.f)(Y.IDomUtils)), ni(1, (0, I.f)($n.IActivityLogger)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], ii);
                    var oi = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let ri = class {
                        constructor(e, t) {
                            this.sendLog = async (e, t) => {
                                if (e && t && this._logPath) try {
                                    const n = await fetch(`${this._logPath}/log`, {
                                        method: "POST",
                                        headers: {
                                            "Content-Type": "application/json",
                                            Authorization: `Bearer ${e}`
                                        },
                                        body: JSON.stringify({
                                            originating_service: "Tara",
                                            log_info: t
                                        })
                                    });
                                    n.ok ? this._logger.debug("Activity log sent:", t) : this._logger.error("Failed sending activity log", n.status, n.statusText, t)
                                } catch (e) {
                                    this._logger.error("Failed to send activity log", t, e)
                                }
                            }, this._logger = e, this._logPath = t.config.activityLoggerURL, this._logPath || e.error("Error initializing activity logger. Path not provided.")
                        }
                    };
                    ri = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), oi(0, (0, I.f)(Y.ILogger)), oi(1, (0, I.f)(Y.IConfigProvider)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], ri);
                    const ai = {
                            first: "first",
                            buttons: "buttons",
                            augmentation: "augmentation",
                            domops: "domops",
                            close: "close",
                            conditionals: "conditionals",
                            augmentations: {
                                flashlight: "flashlight",
                                disabler: "disabler",
                                framer: "framer",
                                iframe: "iframe",
                                blur: "blur",
                                bubble: "bubble"
                            },
                            operations: {
                                waitEvent: "waitEvent"
                            },
                            conditions: {
                                inWeekMessage: "inWeekMessage",
                                inWeekCheck: "inWeekCheck",
                                inWeekWaitChange: "inWeekWaitChange"
                            },
                            iframe: {
                                walkthrough: "walkthrough"
                            },
                            messageTypes: "messageTypes",
                            messageType: {
                                categoryMultiSelect: "categoryMultiSelect"
                            }
                        },
                        si = {
                            name: "testScenario",
                            firstItem: "first",
                            desc: {
                                first: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Hi there, this is a test helper scenario. what do you want to test?",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Features",
                                            userMessage: "You want to see more buttons. this is custom user message",
                                            nextItem: ai.buttons,
                                            type: Qe.Jz.Primary,
                                            layout: Qe.LS.Row
                                        }, {
                                            text: "Close",
                                            op: {
                                                type: Lt.O.HideTara
                                            }
                                        }]
                                    },
                                    preProcess: [{
                                        type: Lt.O.ShowTara
                                    }]
                                },
                                [ai.buttons]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Good choice! The following three buttons lead to testing different Tara capabilities.",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Augmentation",
                                            nextItem: ai.augmentation
                                        }, {
                                            text: "DOM operations",
                                            nextItem: ai.domops
                                        }, {
                                            text: "Conditions",
                                            nextItem: ai.conditionals
                                        }, {
                                            text: "Message Types",
                                            nextItem: ai.messageTypes
                                        }, {
                                            text: "Back",
                                            nextItem: ai.first
                                        }]
                                    }
                                },
                                [ai.messageTypes]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        type: Qe.Jr.Text,
                                        text: "Select the type of message you want to test",
                                        buttons: [{
                                            text: "Category multi select",
                                            nextItem: ai.messageType.categoryMultiSelect
                                        }, {
                                            text: "Back",
                                            nextItem: ai.buttons
                                        }]
                                    }
                                },
                                [ai.messageType.categoryMultiSelect]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Choose recepients and attachments",
                                        type: Qe.Jr.CategoryMultiSelect,
                                        categories: [{
                                            category: "Recepients",
                                            items: [{
                                                text: "Elliot.alderson@gmail.com",
                                                warning: "Outside your organization"
                                            }, {
                                                text: "Marhsall Russon"
                                            }, {
                                                text: "Tiffany Welick",
                                                selected: !0
                                            }]
                                        }, {
                                            category: "Attachemnts",
                                            items: [{
                                                text: "Report.xlsx",
                                                icon: "excel"
                                            }, {
                                                text: "loremipsumdolore...docx",
                                                icon: "word"
                                            }]
                                        }],
                                        buttons: [{
                                            text: "Back",
                                            nextItem: ai.messageTypes
                                        }]
                                    }
                                },
                                [ai.augmentation]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Here are some augmentation options we support:",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Flashlight",
                                            nextItem: ai.augmentations.flashlight
                                        }, {
                                            text: "Disabler",
                                            nextItem: ai.augmentations.disabler
                                        }, {
                                            text: "Framer",
                                            nextItem: ai.augmentations.framer
                                        }, {
                                            text: "IFrame",
                                            nextItem: ai.augmentations.iframe
                                        }, {
                                            text: "Blur",
                                            nextItem: ai.augmentations.blur
                                        }, {
                                            text: "Bubble",
                                            nextItem: ai.augmentations.bubble
                                        }, {
                                            text: "Back",
                                            nextItem: ai.buttons
                                        }]
                                    }
                                },
                                [ai.augmentations.bubble]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        type: Qe.Jr.Text,
                                        text: "Tooltip bubble",
                                        buttons: [{
                                            text: "back",
                                            nextItem: ai.augmentation
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.BubbleWithArrow,
                                        position: {
                                            x: .1,
                                            y: .02
                                        },
                                        arrowPlacement: .7,
                                        arrowSide: Z.H.Top,
                                        content: "Hi! i am a <b> Friendly </b> bubble!"
                                    }]
                                },
                                [ai.augmentations.blur]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Background blur on the entire screen",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "back",
                                            nextItem: ai.augmentation
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.BlurMask
                                    }]
                                },
                                [ai.augmentations.flashlight]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "This is a flashlight example",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "back",
                                            nextItem: ai.augmentation
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.Flashlight,
                                        elementSelectors: ["#flashlight-target"]
                                    }]
                                },
                                [ai.augmentations.disabler]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: 'The "Block Me" button is now blocked',
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "back",
                                            nextItem: ai.augmentation
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.Disabler,
                                        elementSelectors: ["#blockme-button"]
                                    }]
                                },
                                [ai.augmentations.framer]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "I have framed the content box or emphasis. check it out!",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "back",
                                            nextItem: ai.augmentation
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.WarningFrame,
                                        elementSelectors: ["#frame-text"],
                                        radar: {
                                            bubble: {
                                                content: "hello framer and have a nice day"
                                            },
                                            placement: Z.H.Bottom
                                        }
                                    }, {
                                        type: Z.p.DangerFrame,
                                        elementSelectors: ["#blockme-button"]
                                    }]
                                },
                                [ai.augmentations.iframe]: {
                                    type: Mt.vd.Message,
                                    message: "Loading Iframe",
                                    augmentations: [{
                                        type: Z.p.IFrame,
                                        url: "emailFrame.html",
                                        nextItem: [ai.iframe.walkthrough],
                                        context: "iframe-example"
                                    }],
                                    postProcess: [{
                                        type: Lt.O.Delay,
                                        ms: 1e3
                                    }]
                                },
                                [ai.iframe.walkthrough]: {
                                    type: Mt.vd.Recursive,
                                    steps: [{
                                        augmentations: [{
                                            type: Z.p.FocusMask,
                                            elementSelectors: ['iframe[src="emailFrame.html"]', "button"],
                                            context: "walkthrough",
                                            xPadding: 10,
                                            yPadding: 10
                                        }, {
                                            type: Z.p.WalkthroughBox,
                                            text: "We can augment an element within the frame",
                                            elementSelectors: ['iframe[src="emailFrame.html"]', "button"],
                                            nextButton: Mt.Av,
                                            prevButton: Mt.zp,
                                            context: "walkthrough"
                                        }]
                                    }, {
                                        augmentations: [{
                                            type: Z.p.FocusMask,
                                            elementSelectors: ['div[id="frame-text"]'],
                                            context: "walkthrough"
                                        }, {
                                            type: Z.p.WalkthroughBox,
                                            text: "and then a random element outside of the frame",
                                            elementSelectors: ['div[id="frame-text"]'],
                                            nextText: "Done",
                                            nextButton: Mt.Av,
                                            prevButton: Mt.zp,
                                            context: "walkthrough"
                                        }]
                                    }],
                                    doneMessage: "Finished with frame - going back to augmenatations",
                                    nextItem: [ai.augmentations],
                                    postProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["iframe-example", "walkthrough"]
                                    }]
                                },
                                [ai.domops]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Choose the example operation you wish to see",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "wait for event",
                                            nextItem: ai.operations.waitEvent
                                        }, {
                                            text: "Back",
                                            nextItem: ai.buttons
                                        }]
                                    }
                                },
                                [ai.operations.waitEvent]: {
                                    type: Mt.vd.Message,
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        elementSelectors: ['div[id="frame-text"]'],
                                        event: "click"
                                    }],
                                    nextItem: ai.domops,
                                    message: "If you click the framed text you will be directed to the previous menu.",
                                    augmentations: [{
                                        type: Z.p.DangerFrame,
                                        elementSelectors: ['div[id="frame-text"]']
                                    }]
                                },
                                [ai.conditionals]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "We can check that things in the dom have values we need.",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Before date",
                                            nextItem: ai.conditions.inWeekMessage
                                        }, {
                                            text: "Back",
                                            nextItem: ai.buttons
                                        }]
                                    }
                                },
                                [ai.conditions.inWeekMessage]: {
                                    type: Mt.vd.Message,
                                    message: "In the input field - enter a date in the following week.",
                                    nextItem: ai.conditions.inWeekCheck
                                },
                                [ai.conditions.inWeekCheck]: {
                                    type: Mt.vd.Condition,
                                    condition: {
                                        type: Jn.CP.ElementValue,
                                        dataType: Jn.nY.Date,
                                        op: Jn.fo.Between,
                                        base: "now",
                                        target: 604800
                                    },
                                    elementSelectors: ["input"],
                                    ifFalse: ai.conditions.inWeekWaitChange,
                                    ifTrue: ai.conditionals
                                },
                                [ai.conditions.inWeekWaitChange]: {
                                    type: Mt.vd.Empty,
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        event: "keyup",
                                        elementSelectors: ["input"]
                                    }],
                                    nextItem: ai.conditions.inWeekCheck
                                }
                            }
                        },
                        li = "WantToShareExternally",
                        ci = "LimitSharePeriod",
                        di = "CheckSharePeriod",
                        ui = "SettingSaferOption",
                        pi = "OverridePolicy",
                        hi = "HelpLimitExpirationStep1",
                        fi = "Ok",
                        gi = "HelpLimitExpirationStep2",
                        mi = "ManualSetExpirationCheckDate",
                        yi = {
                            name: "AnyoneWithLink",
                            firstItem: "mini-scenario",
                            desc: {
                                "mini-scenario": {
                                    itemName: "mini-scenario",
                                    type: Mt.vd.MiniScenario,
                                    firstItem: li,
                                    desc: {
                                        [li]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                text: "The option you selected may give unauthorized users access to sensitive information. Are you sure you want to proceed? ",
                                                type: Qe.Jr.Text,
                                                buttons: [{
                                                    text: "Yes",
                                                    nextItem: di,
                                                    layout: Qe.LS.Row
                                                }, {
                                                    text: "No",
                                                    nextItem: ui,
                                                    type: Qe.Jz.Primary
                                                }]
                                            },
                                            augmentations: [{
                                                context: "scenario",
                                                type: Z.p.Disabler,
                                                elementSelectors: {
                                                    $var: "applyButton"
                                                }
                                            }, {
                                                context: "scenario",
                                                type: Z.p.WarningFrame,
                                                elementSelectors: {
                                                    $var: "anyoneWithLinkOption"
                                                }
                                            }],
                                            taraStatus: ue.wi.Warning,
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }]
                                        },
                                        [ui]: {
                                            type: Mt.vd.Message,
                                            message: "Great. Please select another sharing option in the window."
                                        },
                                        [di]: {
                                            type: Mt.vd.Condition,
                                            condition: {
                                                type: Jn.CP.ElementValue,
                                                dataType: Jn.nY.Date,
                                                op: Jn.fo.Between,
                                                base: "now",
                                                target: 1209600
                                            },
                                            elementSelectors: {
                                                $var: "expirationDate"
                                            },
                                            ifTrue: fi,
                                            ifFalse: ci
                                        },
                                        [ci]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                text: 'According to organization policy, links that are shared with "Anyone with the link"  should expire after 14 days to avoid potentially sensitive information getting into the wrong hands.',
                                                type: Qe.Jr.Text,
                                                buttons: [{
                                                    text: "Show me how to set the expiration date",
                                                    nextItem: hi,
                                                    type: Qe.Jz.Primary
                                                }, {
                                                    text: "I will set the expiration date",
                                                    nextItem: mi
                                                }, {
                                                    text: "I need to make it available for longer",
                                                    nextItem: pi
                                                }]
                                            }
                                        },
                                        [mi]: {
                                            type: Mt.vd.Condition,
                                            preProcess: [{
                                                type: Lt.O.WaitForEvent,
                                                elementSelectors: {
                                                    $var: "expirationDate"
                                                },
                                                event: "click"
                                            }, {
                                                type: Lt.O.WaitForEvent,
                                                elementSelectors: {
                                                    $var: "datePicker"
                                                },
                                                event: "click"
                                            }, {
                                                type: Lt.O.Delay,
                                                ms: 50
                                            }],
                                            condition: {
                                                base: "now",
                                                target: 1209600,
                                                type: Jn.CP.ElementValue,
                                                op: Jn.fo.Between,
                                                dataType: Jn.nY.Date
                                            },
                                            ifTrue: fi,
                                            ifFalse: mi,
                                            elementSelectors: {
                                                $var: "expirationDate"
                                            }
                                        },
                                        [pi]: {
                                            type: Mt.vd.Message,
                                            message: "Please provide justification for this.",
                                            chips: ["It doesn't contain confidential data", "It's shared under NDA"],
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput
                                            }, {
                                                type: Lt.O.HideTara
                                            }]
                                        },
                                        "It doesn't contain confidential data": {
                                            type: Mt.vd.Message,
                                            message: "Ok",
                                            postProcess: [{
                                                type: Lt.O.HideTara
                                            }, {
                                                type: Lt.O.ClearContext,
                                                contexts: ["scenario"]
                                            }]
                                        },
                                        "It's shared under NDA": {
                                            type: Mt.vd.Message,
                                            message: "Ok",
                                            postProcess: [{
                                                type: Lt.O.HideTara
                                            }, {
                                                type: Lt.O.ClearContext,
                                                contexts: ["scenario"]
                                            }]
                                        },
                                        [hi]: {
                                            type: Mt.vd.Message,
                                            message: "Click the 'Set expiration date' field.",
                                            augmentations: [{
                                                type: Z.p.Flashlight,
                                                elementSelectors: {
                                                    $var: "expirationDate"
                                                },
                                                context: "flashlight"
                                            }],
                                            postProcess: [{
                                                type: Lt.O.WaitForEvent,
                                                elementSelectors: {
                                                    $var: "expirationDate"
                                                },
                                                event: "click"
                                            }],
                                            nextItem: gi
                                        },
                                        [gi]: {
                                            type: Mt.vd.Message,
                                            message: "Choose a date in the next 14 days",
                                            augmentations: [{
                                                type: Z.p.Flashlight,
                                                elementSelectors: {
                                                    $var: "datePicker"
                                                },
                                                context: "flashlight"
                                            }],
                                            postProcess: [{
                                                type: Lt.O.WaitForEvent,
                                                elementSelectors: {
                                                    $var: "datePickerDateArea"
                                                },
                                                event: "click"
                                            }, {
                                                type: Lt.O.ClearContext,
                                                contexts: ["flashlight"]
                                            }],
                                            nextItem: di
                                        },
                                        Limit14Set: {
                                            type: Mt.vd.Message,
                                            message: "Sharing file externally will be limited to 14 days",
                                            postProcess: [{
                                                type: Lt.O.HideTara
                                            }]
                                        },
                                        [fi]: {
                                            type: Mt.vd.Message,
                                            message: "Ok",
                                            postProcess: [{
                                                type: Lt.O.HideTara
                                            }, {
                                                type: Lt.O.ClearContext,
                                                contexts: ["scenario"]
                                            }],
                                            taraStatus: ue.wi.Healthy
                                        }
                                    }
                                }
                            }
                        },
                        bi = "UseCase",
                        xi = "PersonalUseChosen",
                        vi = "PersonalUseEmailIsEmail",
                        wi = "PersonalUseEmailUpdate",
                        _i = "PersonalUseEmailVerify",
                        ki = "PersonalUseError",
                        Ci = "PersonalUseDone",
                        Si = "PersonalUseDone2",
                        Ei = "PersonalUseOk",
                        Ii = "BusinessUseJustification",
                        Ai = "BusinessUseReminders",
                        Oi = "BusinessUseEmailUpdate",
                        Ti = "BusinessUseEmailVerify",
                        Mi = "BusinessUsePersonalEmail",
                        Ri = "BusinessUseEmailOk",
                        Pi = "BusinessUseEmailIsEmail",
                        Di = "Confidential",
                        ji = "(?:[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9][a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])",
                        Li = {
                            name: "Clickup Signup",
                            firstItem: Di,
                            desc: {
                                [Di]: {
                                    preProcess: [{
                                        type: Lt.O.ShowTara
                                    }],
                                    type: Mt.vd.Message,
                                    message: "<b>Confidential Mode</b> <br/>Nothing is reported unless explicitly mentioned otherwise",
                                    nextItem: bi
                                },
                                [bi]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "You are about to join ClickUp, a project management application. What are you using this tool for?",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Personal Use",
                                            nextItem: xi,
                                            layout: Qe.LS.Row
                                        }, {
                                            text: "Business Use",
                                            nextItem: Ii
                                        }]
                                    },
                                    augmentations: [{
                                        type: Z.p.Disabler,
                                        elementSelectors: {
                                            $var: "submitButton"
                                        },
                                        context: "scenario"
                                    }],
                                    preProcess: [{
                                        type: Lt.O.ShowTara
                                    }]
                                },
                                [xi]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "I am going to turn myself off",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Got it",
                                            nextItem: Ei
                                        }]
                                    },
                                    preProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["scenario"]
                                    }],
                                    postProcess: [{
                                        type: Lt.O.HideIndicator
                                    }, {
                                        type: Lt.O.HideTara
                                    }]
                                },
                                [Ei]: {
                                    type: Mt.vd.Empty
                                },
                                [wi]: {
                                    type: Mt.vd.Empty,
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        event: "keyup",
                                        elementSelectors: {
                                            $var: "signupEmail"
                                        }
                                    }],
                                    nextItem: vi
                                },
                                [vi]: {
                                    type: Mt.vd.Condition,
                                    condition: {
                                        type: Jn.CP.ElementValue,
                                        op: Jn.fo.Regex,
                                        dataType: Jn.nY.String,
                                        target: ji
                                    },
                                    elementSelectors: {
                                        $var: "signupEmail"
                                    },
                                    ifFalse: wi,
                                    ifTrue: _i
                                },
                                [_i]: {
                                    type: Mt.vd.Condition,
                                    condition: {
                                        type: Jn.CP.ElementValue,
                                        target: "@contoso.to",
                                        dataType: Jn.nY.String,
                                        op: Jn.fo.EndsWith
                                    },
                                    elementSelectors: {
                                        $var: "signupEmail"
                                    },
                                    ifTrue: ki,
                                    ifFalse: Ci
                                },
                                [Ci]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "For security reasons, do not upload any business data when using ClickUp for your personal use",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Got it",
                                            nextItem: Si
                                        }]
                                    },
                                    taraStatus: ue.wi.Healthy,
                                    postProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["scenario"]
                                    }]
                                },
                                [Si]: {
                                    type: Mt.vd.Empty,
                                    preProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["scenario"]
                                    }, {
                                        type: Lt.O.HideTara
                                    }]
                                },
                                [ki]: {
                                    type: Mt.vd.Message,
                                    message: "Using your company email for personal use is against the company policy. Please use your personal email.",
                                    nextItem: wi,
                                    taraStatus: ue.wi.Warning,
                                    postProcess: [{
                                        type: Lt.O.ShowTara
                                    }]
                                },
                                [Ii]: {
                                    type: Mt.vd.Message,
                                    message: "Please enter <b>business justification</b> for using Click Up ",
                                    chips: ["My team uses it", "A vendor uses it", "Testing for company use"],
                                    postProcess: [{
                                        type: Lt.O.WaitForUserInput
                                    }]
                                },
                                "My team uses it": {
                                    type: Mt.vd.Empty,
                                    nextItem: Ai
                                },
                                "A vendor uses it": {
                                    type: Mt.vd.Empty,
                                    nextItem: Ai
                                },
                                "Testing for company use": {
                                    type: Mt.vd.Empty,
                                    nextItem: Ai
                                },
                                [Ai]: {
                                    type: Mt.vd.Message,
                                    message: "For security reasons:",
                                    nextItem: "reminders1"
                                },
                                reminders1: {
                                    type: Mt.vd.Message,
                                    message: "Use company email in the â€œEmailâ€ field",
                                    nextItem: "reminders2"
                                },
                                reminders2: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Do not upload any confidential company data into Click-Up",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Got it",
                                            nextItem: Pi
                                        }]
                                    },
                                    postProcess: [{
                                        type: Lt.O.HideTara
                                    }]
                                },
                                [Oi]: {
                                    type: Mt.vd.Empty,
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        event: "keyup",
                                        elementSelectors: {
                                            $var: "signupEmail"
                                        }
                                    }],
                                    nextItem: Pi
                                },
                                [Pi]: {
                                    type: Mt.vd.Condition,
                                    condition: {
                                        type: Jn.CP.ElementValue,
                                        op: Jn.fo.Regex,
                                        dataType: Jn.nY.String,
                                        target: ji
                                    },
                                    elementSelectors: {
                                        $var: "signupEmail"
                                    },
                                    ifFalse: Oi,
                                    ifTrue: Ti
                                },
                                [Ti]: {
                                    type: Mt.vd.Condition,
                                    condition: {
                                        type: Jn.CP.ElementValue,
                                        target: "@contoso.to",
                                        dataType: Jn.nY.String,
                                        op: Jn.fo.EndsWith
                                    },
                                    elementSelectors: {
                                        $var: "signupEmail"
                                    },
                                    ifFalse: Mi,
                                    ifTrue: Ri
                                },
                                [Mi]: {
                                    type: Mt.vd.Message,
                                    message: "Using your personal email for business use is against company policy. Please use your company email.",
                                    nextItem: Oi,
                                    preProcess: [{
                                        type: Lt.O.ShowTara
                                    }],
                                    augmentations: [{
                                        type: Z.p.Disabler,
                                        elementSelectors: {
                                            $var: "submitButton"
                                        },
                                        context: "scenario"
                                    }, {
                                        type: Z.p.WarningFrame,
                                        context: "scenario",
                                        elementSelectors: {
                                            $var: "signupEmailRow"
                                        }
                                    }],
                                    taraStatus: ue.wi.Warning
                                },
                                [Ri]: {
                                    type: Mt.vd.Empty,
                                    taraStatus: ue.wi.Healthy,
                                    preProcess: [{
                                        type: Lt.O.HideTara
                                    }],
                                    nextItem: Oi,
                                    postProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["scenario"]
                                    }]
                                }
                            }
                        },
                        Fi = "onLogin",
                        Hi = "startMfaGuide",
                        Bi = "selectUser",
                        Ni = "selectSettings",
                        Ui = "showMfa",
                        Vi = "readAboutMFA",
                        zi = "mfaDone",
                        Wi = {
                            name: "clickUpMfaGuide",
                            firstItem: Fi,
                            desc: {
                                [Fi]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Welcome to ClickUp! To keep your account secure, please enable multi-factor authentication",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "OK",
                                            nextItem: Hi,
                                            type: Qe.Jz.Primary
                                        }, {
                                            text: "Remind me later",
                                            op: {
                                                type: Lt.O.HideTara
                                            }
                                        }, {
                                            text: "Skip multi-factor authentication",
                                            op: {
                                                type: Lt.O.HideTara
                                            }
                                        }]
                                    },
                                    preProcess: [{
                                        type: Lt.O.ShowTara
                                    }]
                                },
                                [Hi]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Can I assist you with setting up MFA?",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Show me how to enable MFA",
                                            nextItem: Bi,
                                            type: Qe.Jz.Primary
                                        }, {
                                            text: "Read more about enabling MFA",
                                            nextItem: Vi
                                        }, {
                                            text: "I'll do it later",
                                            op: {
                                                type: Lt.O.HideTara
                                            }
                                        }]
                                    }
                                },
                                [Vi]: {
                                    type: Mt.vd.Message,
                                    message: 'Click <a href="https://clickup.com/features/2fa" target="_blank">this link</a> to read more about MFA in clickup'
                                },
                                [Bi]: {
                                    type: Mt.vd.Message,
                                    message: "Select your account",
                                    augmentations: [{
                                        context: "flashlight",
                                        type: Z.p.Flashlight,
                                        elementSelectors: {
                                            $var: "userSettingsDropdown"
                                        }
                                    }],
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        event: "click",
                                        elementSelectors: {
                                            $var: "userSettingsDropdown"
                                        }
                                    }],
                                    nextItem: Ni
                                },
                                [Ni]: {
                                    type: Mt.vd.Message,
                                    message: 'Click "My Settings"',
                                    augmentations: [{
                                        context: "flashlight",
                                        type: Z.p.Flashlight,
                                        elementSelectors: {
                                            $var: "userSettingsDropdownMySettings"
                                        }
                                    }],
                                    postProcess: [{
                                        type: Lt.O.WaitForEvent,
                                        event: "click",
                                        elementSelectors: {
                                            $var: "userSettingsDropdownMySettings"
                                        }
                                    }],
                                    nextItem: Ui
                                },
                                [Ui]: {
                                    type: Mt.vd.Message,
                                    message: {
                                        text: "Please configure MFA",
                                        type: Qe.Jr.Text,
                                        buttons: [{
                                            text: "Got it",
                                            nextItem: zi
                                        }]
                                    },
                                    augmentations: [{
                                        context: "flashlight",
                                        type: Z.p.Flashlight,
                                        elementSelectors: {
                                            $var: "userSettings2fa"
                                        }
                                    }],
                                    postProcess: [{
                                        type: Lt.O.ClearContext,
                                        contexts: ["flashlight"]
                                    }]
                                },
                                [zi]: {
                                    type: Mt.vd.Empty,
                                    postProcess: [{
                                        type: Lt.O.HideTara
                                    }]
                                }
                            }
                        },
                        Gi = "Completed",
                        $i = {
                            name: "Phishing training",
                            firstItem: "phishingTraining",
                            desc: {
                                phishingTraining: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: "IsSimulation",
                                    desc: {
                                        IsSimulation: {
                                            type: Mt.vd.Condition,
                                            condition: {
                                                attribute: "data-unbiased-simulation",
                                                type: Jn.CP.ElementAttribute,
                                                dataType: Jn.nY.String,
                                                op: Jn.fo.Equal,
                                                target: "true"
                                            },
                                            elementSelectors: ["body"],
                                            ifTrue: "StartSimulation",
                                            ifFalse: "StartTraining"
                                        },
                                        StartSimulation: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "You just shared your credentials on a suspicious website. Let me show you how this happened",
                                                buttons: [{
                                                    text: "Show me more",
                                                    nextItem: "WhyItsSuspicious"
                                                }]
                                            },
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }, {
                                                type: Lt.O.SetVariable,
                                                name: "user-error-selector",
                                                value: '[data-unbiased-simulation="user-error"]'
                                            }],
                                            taraStatus: ue.wi.Warning
                                        },
                                        StartTraining: {
                                            type: Mt.vd.Empty,
                                            nextItem: "TrainingWelcome",
                                            preProcess: [{
                                                type: Lt.O.SetVariable,
                                                name: "user-error-selector",
                                                value: 'input[id="input"]'
                                            }]
                                        },
                                        TrainingWelcome: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Welcome to <br />your security training!",
                                                text: "We're going to walk you through how Tara works to protect you. <br /><br />This will only take a couple of minutes.",
                                                img: "HandWave",
                                                buttons: [{
                                                    text: "Let's Start",
                                                    type: Qe.Jz.Primary,
                                                    nextItem: "WhyItsSuspicious"
                                                }]
                                            },
                                            augmentations: [{
                                                type: Z.p.BlurMask
                                            }, {
                                                $var: nn
                                            }],
                                            postProcess: [{
                                                type: Lt.O.StopAugmentationFade
                                            }]
                                        },
                                        WhyItsSuspicious: {
                                            type: Mt.vd.Recursive,
                                            preProcess: [{
                                                type: Lt.O.HideTara
                                            }, {
                                                type: Lt.O.RemoveDomElements,
                                                elementSelectors: [".mail-frame-wrapper"]
                                            }],
                                            postProcess: [{
                                                type: Lt.O.ClearContext,
                                                contexts: ["phishingTraining", an, sn]
                                            }, {
                                                type: Lt.O.ShowTara
                                            }],
                                            steps: {
                                                $var: tn
                                            },
                                            nextItem: "IsSimulationPostTraining"
                                        },
                                        IsSimulationPostTraining: {
                                            type: Mt.vd.Condition,
                                            condition: {
                                                attribute: "data-unbiased-simulation",
                                                type: Jn.CP.ElementAttribute,
                                                dataType: Jn.nY.String,
                                                op: Jn.fo.Equal,
                                                target: "true"
                                            },
                                            elementSelectors: ["body"],
                                            ifTrue: "Empty",
                                            ifFalse: "TrainingDone"
                                        },
                                        Empty: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Learning to recognize the signs of phishing attempts can help keep you and your organization safe.",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Show me again",
                                                    nextItem: "WhyItsSuspicious"
                                                }, {
                                                    text: "Done",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    }
                                                }]
                                            }
                                        },
                                        TrainingDone: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Way to go!",
                                                text: "You're done with the training.",
                                                img: "Congrats"
                                            },
                                            postProcess: [{
                                                type: Lt.O.Delay,
                                                ms: 2e3
                                            }],
                                            nextItem: "HowWasIt"
                                        },
                                        HowWasIt: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ActivityLog,
                                                token: {
                                                    $var: on
                                                },
                                                data: {
                                                    $var: rn,
                                                    campaign_status: Gi,
                                                    campaign_status_severity: 150
                                                }
                                            }],
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "How did it go?",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    type: Qe.Jz.Image,
                                                    img: Qe.EV.ThumbsDown,
                                                    nextItem: "CanWeImprove",
                                                    op: {
                                                        type: Lt.O.ActivityLog,
                                                        token: {
                                                            $var: on
                                                        },
                                                        data: {
                                                            $var: rn,
                                                            feedback: "thumbs-down"
                                                        }
                                                    }
                                                }, {
                                                    type: Qe.Jz.Image,
                                                    img: Qe.EV.ThumbsUp,
                                                    op: {
                                                        type: Lt.O.ActivityLog,
                                                        token: {
                                                            $var: on
                                                        },
                                                        data: {
                                                            $var: rn,
                                                            feedback: "thumbs-up"
                                                        }
                                                    },
                                                    nextItem: "Thanks"
                                                }]
                                            }
                                        },
                                        CanWeImprove: {
                                            type: Mt.vd.Message,
                                            message: "Can you share some more details?",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                token: {
                                                    $var: on
                                                },
                                                logData: {
                                                    $var: rn
                                                }
                                            }],
                                            nextItem: "Thanks"
                                        },
                                        Thanks: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Thanks for the feedback!",
                                                img: "Star",
                                                text: ""
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        qi = {
                            logo: ["img.logo"],
                            download: ["div.img a.btn"]
                        },
                        Yi = {
                            original: {
                                tara1: "The file you are trying to download is suspicious.<br/><br/>To protect you and your organization the download was blocked",
                                button: "Show me why it's suspicious",
                                wtMail: "You received an email inviting you to install zoom software.",
                                wtLogo: "You are trying to download a file from an unknown website that suspiciously looks like zoom",
                                wtDownload: "<b>You are trying to download an installer file.</b><br /><br />Software vendors never send links to installer files over email. However, threat actors send such installer files via email in order to get people to install Malware.",
                                wtScanResult: "We scanned the binary file you are trying to download:<br />https://z00m-meetings/Zoom.pkg.<br/<br/>However, there is not enough infromation to confirm it is safe. We reported it to the security team",
                                done: "All set"
                            },
                            neutral: {
                                tara1: "The file you are trying to download is suspicious. To protect you and your organization the download was blocked.",
                                button: "Show me why this file is suspicious",
                                wtMail: "This mail was sent from the domain noreply@z00m-meetings.net. An attempt to impersonate a known brand like Zoom may indicate a phishing attempt.",
                                wtLogo: "You are trying to download a file from an unknown website that suspiciously looks like Zoom",
                                wtDownload: "You are trying to download an installer file.  <br />Software vendors never send links to installer files over email. However, threat actors send such installer files via email in order to get people to install Malware",
                                wtScanResult: "We scanned the binary file you are trying to download https://z00m-meetings/installer.exe, however, there is not enough information to confirm it is safe. We reported it to the security team.",
                                done: "All set!"
                            },
                            assistant: {
                                tara1: "Unfortunately the file you're trying to download is suspicious, and your organization has chosen to block it to protect you. ",
                                button: "Show me why it's suspicious",
                                wtMail: 'I\'m happy to walk you through this. First, I noticed that the email was sent from noreply@z00m-meetings.net. The domain uses zeros in the name "Zoom," instead of the letter "o," as the real Zoom does. It looks like this site is pretending to be Zoom. ',
                                wtLogo: "I noticed that you're being asked to download a file from the site, which isn't the real Zoom site. ",
                                wtDownload: "I noticed that you're being asked to download an installer file. I've been informed that software vendors never send links to installer files by email. Cyberattackers, however, use this tactic to get people to install malware. ",
                                wtScanResult: "I had this binary file scanned for you (https://z00m-meetings/installer.exe) and wasn't able to confirm that it's safe, so I reported it to the security team on your behalf. I appreciate your cooperation in this matter. ",
                                done: "Thanks for your patience and cooperation. I'm glad to assist with anything else you need. "
                            },
                            techy: {
                                tara1: "I blocked this download, as my assessment showed that it's likely malicious. ",
                                button: "Show me why it's suspicious",
                                wtMail: 'Hackers often use URLs that look like the one they\'re trying to impersonate. Check out how they\'re being sneaky here and using "z00m-meetings.net" instead of "zoom.com" or "zoom.us" ',
                                wtLogo: "This site is passing itself off as Zoom and trying to manipulate you into downloading a file. ",
                                wtDownload: "You're being asked to download an installer file, which is a sign of an attempt to hack you. Software vendors never send links to installer files by email. ",
                                wtScanResult: "I scanned this file (https://z00m-meetings/installer.exe) and determined that it's not safe to proceed. The security team and I will take it from here. Don't click on anything. ",
                                done: "Another cyberattack foiled. Cheers!"
                            },
                            coach: {
                                tara1: "Since the file looks suspicious, we're blocking the download to protect you and your organization. ",
                                button: "Show me why it's suspicious",
                                wtMail: "Let's take a look at the URL. We can see that the email is coming from noreply@z00m-meetings.net, which isn't the real Zoom URL. That's typically a sign of phishing. ",
                                wtLogo: "You're being asked to download a file from a non-verified site that is attempting to look like Zoom.",
                                wtDownload: "Looks like the sender wants you to download an installer file. That's a red flag, since software vendors never send links to installer files over email. They always link you to a website where you can download them. ",
                                wtScanResult: "The security team and I reviewed the binary file (https://z00m-meetings/installer.exe) and weren't able to find enough information to confirm that it's safe. We've got you covered from here. ",
                                done: "Way to go! You're all set. "
                            }
                        },
                        Ji = Yi[new URLSearchParams(window.location.search).get("flavor")] || Yi.original,
                        Zi = {
                            name: "zoomDownload",
                            firstItem: "mini",
                            desc: {
                                mini: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: "Danger",
                                    desc: {
                                        Danger: {
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: Ji.tara1,
                                                buttons: [{
                                                    type: Qe.Jz.Primary,
                                                    text: Ji.button,
                                                    nextItem: "WhySuspicious"
                                                }]
                                            },
                                            taraStatus: ue.wi.Warning
                                        },
                                        WhySuspicious: {
                                            type: Mt.vd.Recursive,
                                            preProcess: [{
                                                type: Lt.O.HideTara
                                            }],
                                            steps: [{
                                                augmentations: [{
                                                    url: "/zoomEmail.html",
                                                    timeout: 2e3,
                                                    type: Z.p.IFrame
                                                }, {
                                                    elementSelectors: ['iframe[src^="/zoomEmail.html"]', ".button"],
                                                    xPadding: 10,
                                                    yPadding: 10,
                                                    type: Z.p.FocusMask,
                                                    context: "box"
                                                }, {
                                                    nextButton: "RECURSIVE_NEXT",
                                                    text: Ji.wtMail,
                                                    context: "box",
                                                    type: Z.p.WalkthroughBox,
                                                    prevButton: "RECURSIVE_PREV",
                                                    elementSelectors: ['iframe[src^="/zoomEmail.html"]', ".button"]
                                                }, {
                                                    type: Z.p.WarningFrame,
                                                    elementSelectors: ['iframe[src^="/zoomEmail.html"]', ".button"]
                                                }]
                                            }, {
                                                augmentations: [{
                                                    type: Z.p.WalkthroughBox,
                                                    text: Ji.wtLogo,
                                                    elementSelectors: qi.logo,
                                                    nextButton: Mt.Av,
                                                    prevButton: Mt.zp,
                                                    context: "box"
                                                }, {
                                                    type: Z.p.FocusMask,
                                                    elementSelectors: qi.logo,
                                                    context: "focus"
                                                }, {
                                                    type: Z.p.WarningFrame,
                                                    elementSelectors: qi.logo
                                                }]
                                            }, {
                                                augmentations: [{
                                                    type: Z.p.WalkthroughBox,
                                                    text: Ji.wtDownload,
                                                    elementSelectors: qi.download,
                                                    nextButton: Mt.Av,
                                                    prevButton: Mt.zp,
                                                    context: "box"
                                                }, {
                                                    type: Z.p.FocusMask,
                                                    elementSelectors: qi.download,
                                                    context: "focus"
                                                }, {
                                                    type: Z.p.WarningFrame,
                                                    elementSelectors: qi.download
                                                }]
                                            }, {
                                                augmentations: [{
                                                    type: Z.p.WalkthroughBox,
                                                    text: Ji.wtScanResult,
                                                    nextButton: Mt.Av,
                                                    prevButton: Mt.zp,
                                                    elementSelectors: [".file-download-panel"],
                                                    nextText: "Got it",
                                                    context: "box",
                                                    placement: Z.H.Top
                                                }, {
                                                    type: Z.p.FocusMask,
                                                    elementSelectors: ['div[id="download-widget"]'],
                                                    context: "focus",
                                                    yPadding: 0,
                                                    xPadding: 0
                                                }]
                                            }],
                                            postProcess: [{
                                                type: Lt.O.ClearContext,
                                                contexts: ["box", "focus"]
                                            }, {
                                                type: Lt.O.ShowTara
                                            }],
                                            nextItem: "Done",
                                            doneMessage: Ji.done
                                        },
                                        Done: {
                                            type: Mt.vd.Empty
                                        }
                                    }
                                }
                            }
                        },
                        Xi = {
                            name: "Download training",
                            firstItem: "downloadTraining",
                            desc: {
                                downloadTraining: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: "IsSimulation",
                                    desc: {
                                        IsSimulation: {
                                            type: Mt.vd.Condition,
                                            condition: {
                                                attribute: "data-unbiased-simulation",
                                                type: Jn.CP.ElementAttribute,
                                                dataType: Jn.nY.String,
                                                op: Jn.fo.Equal,
                                                target: "true"
                                            },
                                            elementSelectors: ["body"],
                                            ifTrue: "StartSimulation",
                                            ifFalse: "StartTraining"
                                        },
                                        StartSimulation: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "You are about to download a malicious file. Let me show you how this happened",
                                                buttons: [{
                                                    text: "Show me more",
                                                    nextItem: "WhyItsMalicious"
                                                }]
                                            },
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }, {
                                                type: Lt.O.SetVariable,
                                                name: "user-error-selector",
                                                value: '[data-unbiased-simulation="user-error"]'
                                            }],
                                            taraStatus: ue.wi.Warning
                                        },
                                        StartTraining: {
                                            type: Mt.vd.Empty,
                                            nextItem: "TrainingWelcome",
                                            preProcess: [{
                                                type: Lt.O.SetVariable,
                                                name: "user-error-selector",
                                                value: 'input[id="input"]'
                                            }]
                                        },
                                        TrainingWelcome: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Welcome to <br />your security training!",
                                                text: "We're going to walk you through how Tara works to protect you. <br /><br />This will only take a couple of minutes.",
                                                img: "HandWave",
                                                buttons: [{
                                                    text: "Let's Start",
                                                    type: Qe.Jz.Primary,
                                                    nextItem: "WhyItsMalicious"
                                                }]
                                            },
                                            augmentations: [{
                                                type: Z.p.BlurMask
                                            }, {
                                                $var: nn
                                            }],
                                            postProcess: [{
                                                type: Lt.O.StopAugmentationFade
                                            }]
                                        },
                                        WhyItsMalicious: {
                                            type: Mt.vd.Recursive,
                                            preProcess: [{
                                                type: Lt.O.HideTara
                                            }, {
                                                type: Lt.O.RemoveDomElements,
                                                elementSelectors: [".mail-frame-wrapper"]
                                            }],
                                            postProcess: [{
                                                type: Lt.O.ClearContext,
                                                contexts: ["downloadTraining", an, sn]
                                            }, {
                                                type: Lt.O.ShowTara
                                            }],
                                            steps: {
                                                $var: tn
                                            },
                                            nextItem: "IsSimulationPostTraining"
                                        },
                                        IsSimulationPostTraining: {
                                            type: Mt.vd.Condition,
                                            condition: {
                                                attribute: "data-unbiased-simulation",
                                                type: Jn.CP.ElementAttribute,
                                                dataType: Jn.nY.String,
                                                op: Jn.fo.Equal,
                                                target: "true"
                                            },
                                            elementSelectors: ["body"],
                                            ifTrue: "Empty",
                                            ifFalse: "TrainingDone"
                                        },
                                        Empty: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Remember, phishing mail can put you and your organization at risk. Be safe.",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Show me again",
                                                    nextItem: "WhyItsMalicious"
                                                }, {
                                                    text: "Done",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    }
                                                }]
                                            }
                                        },
                                        TrainingDone: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Way to go!",
                                                text: "You're done with the training.",
                                                img: "Congrats"
                                            },
                                            postProcess: [{
                                                type: Lt.O.Delay,
                                                ms: 2e3
                                            }],
                                            nextItem: "HowWasIt"
                                        },
                                        HowWasIt: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ActivityLog,
                                                token: {
                                                    $var: on
                                                },
                                                data: {
                                                    $var: rn,
                                                    campaign_status: Gi,
                                                    campaign_status_severity: 150
                                                }
                                            }],
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "How did it go?",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    type: Qe.Jz.Image,
                                                    img: Qe.EV.ThumbsDown,
                                                    op: {
                                                        type: Lt.O.ActivityLog,
                                                        token: {
                                                            $var: on
                                                        },
                                                        data: {
                                                            $var: rn,
                                                            feedback: "thumbs-down"
                                                        }
                                                    },
                                                    nextItem: "CanWeImprove"
                                                }, {
                                                    type: Qe.Jz.Image,
                                                    img: Qe.EV.ThumbsUp,
                                                    nextItem: "Thanks",
                                                    op: {
                                                        type: Lt.O.ActivityLog,
                                                        token: {
                                                            $var: on
                                                        },
                                                        data: {
                                                            $var: rn,
                                                            feedback: "thumbs-up"
                                                        }
                                                    }
                                                }]
                                            }
                                        },
                                        CanWeImprove: {
                                            type: Mt.vd.Message,
                                            message: "Can you share some more details?",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                token: {
                                                    $var: on
                                                },
                                                logData: {
                                                    $var: rn
                                                }
                                            }],
                                            nextItem: "Thanks"
                                        },
                                        Thanks: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Title,
                                                title: "Thanks for the feedback!",
                                                img: "Star",
                                                text: ""
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Ki = {
                            name: "SWG Access",
                            firstItem: "miniScenario",
                            desc: {
                                miniScenario: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: "Start",
                                    desc: {
                                        Start: {
                                            type: Mt.vd.Empty,
                                            nextItem: "Welcome",
                                            preProcess: [{
                                                type: Lt.O.SetVariable,
                                                name: "category-text",
                                                value: {
                                                    $var: "categoryText"
                                                }
                                            }]
                                        },
                                        Welcome: {
                                            type: Mt.vd.Message,
                                            taraStatus: ue.wi.Healthy,
                                            nextItem: "Questionnaire",
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Hi there, you are trying to access a website for the first time. Unfortunately, there is not enough information\n                    to assume that this website is safe. Please help me validating this website by answering a few questions."
                                            }
                                        },
                                        Questionnaire: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "What is the purpose of accessing this website?",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Personal use",
                                                    nextItem: "PersonalUse"
                                                }, {
                                                    text: "Business use",
                                                    nextItem: "BusinessUseJustification"
                                                }]
                                            }
                                        },
                                        PersonalUse: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Accessing this website for personal use is not allowed when using your business profile.",
                                                buttons: [{
                                                    text: "Got it!",
                                                    nextItem: "GotIt"
                                                }]
                                            }
                                        },
                                        GotIt: {
                                            type: Mt.vd.Message,
                                            message: "Thank You"
                                        },
                                        BusinessUseJustification: {
                                            type: Mt.vd.Message,
                                            message: "Please add a justification for accessing this website",
                                            chips: ["Customer's website", "Vendor's website", "I know this website"],
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput
                                            }]
                                        },
                                        "Customer's website": {
                                            type: Mt.vd.Empty,
                                            nextItem: "SiteType"
                                        },
                                        "Vendor's website": {
                                            type: Mt.vd.Empty,
                                            nextItem: "SiteType"
                                        },
                                        "I know this website": {
                                            type: Mt.vd.Empty,
                                            nextItem: "SiteType"
                                        },
                                        SiteType: {
                                            type: Mt.vd.Message,
                                            message: "Can you please share what type of website this is?",
                                            chips: ["Finance and Banking", "Computing & Internet", "Business & Commercial", "Medical Health", "Education"],
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput
                                            }]
                                        },
                                        "Finance and Banking": {
                                            type: Mt.vd.Empty,
                                            nextItem: "Upload"
                                        },
                                        "Computing & Internet": {
                                            type: Mt.vd.Empty,
                                            nextItem: "Upload"
                                        },
                                        "Business & Commercial": {
                                            type: Mt.vd.Empty,
                                            nextItem: "Upload"
                                        },
                                        "Medical Health": {
                                            type: Mt.vd.Empty,
                                            nextItem: "Upload"
                                        },
                                        Education: {
                                            type: Mt.vd.Empty,
                                            nextItem: "Upload"
                                        },
                                        Upload: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Do you plan uploading data to this website?",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Yes",
                                                    nextItem: "Approval"
                                                }, {
                                                    text: "No",
                                                    nextItem: "Approval"
                                                }]
                                            }
                                        },
                                        Approval: {
                                            type: Mt.vd.Message,
                                            nextItem: "Scanning",
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "Thank you for your cooperation, I am getting an approval"
                                            }
                                        },
                                        Scanning: {
                                            type: Mt.vd.Message,
                                            nextItem: "SafeAccess",
                                            postProcess: [{
                                                type: Lt.O.Delay,
                                                ms: 3e3
                                            }],
                                            message: {
                                                type: Qe.Jr.Text,
                                                dotsDelay: 3e3,
                                                text: "This website doesn't seem malicious."
                                            }
                                        },
                                        SafeAccess: {
                                            type: Mt.vd.Message,
                                            message: {
                                                $var: "messageText"
                                            },
                                            postProcess: [{
                                                type: Lt.O.SetLocalStorage,
                                                key: "___UNBIASED_LSP___",
                                                value: {
                                                    time: Date.now(),
                                                    target: {
                                                        $var: "targetURL"
                                                    }
                                                }
                                            }]
                                        }
                                    }
                                }
                            }
                        };
                    var Qi = n(1920);
                    const eo = "mini",
                        to = "notOnedrive",
                        no = "statePurpose",
                        io = "personalUse",
                        oo = "businessUse",
                        ro = "clear",
                        ao = "close",
                        so = {
                            firstItem: eo,
                            name: "dropboxSignin",
                            desc: {
                                [eo]: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: to,
                                    desc: {
                                        [to]: {
                                            type: Mt.vd.Message,
                                            message: 'Please note that the file sharing organizational app is                     <a href="https://onedrive.live.com/about/en-us/signin" target="_blank">OneDrive</a>',
                                            preProcess: [{
                                                type: Lt.O.Delay,
                                                ms: 1e3
                                            }, {
                                                type: Lt.O.ShowTara
                                            }],
                                            augmentations: [{
                                                type: Z.p.Disabler,
                                                elementSelectors: {
                                                    $var: "emailInput"
                                                },
                                                context: "scenario"
                                            }],
                                            nextItem: no
                                        },
                                        [no]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "What is the purpose of using DropBox?",
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Personal Use",
                                                    nextItem: io
                                                }, {
                                                    type: Qe.Jz.Primary,
                                                    text: "Business Use",
                                                    nextItem: oo
                                                }]
                                            }
                                        },
                                        [io]: {
                                            type: Mt.vd.Message,
                                            message: "Accessing Dropbox for personal use is not allowed â€“ <b>see the organizational policy</b>"
                                        },
                                        [oo]: {
                                            type: Mt.vd.Message,
                                            message: "Please provide business justification",
                                            chips: ["My team uses it", "A vendor uses it", "Testing for company use"],
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: ro
                                        },
                                        [ro]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: "According to the organizational policy, only encrypted files are allowed to be uploaded to Dropbox",
                                                buttons: [{
                                                    type: Qe.Jz.Primary,
                                                    text: "Got it",
                                                    op: {
                                                        type: Lt.O.ClearContext,
                                                        contexts: ["scenario"]
                                                    },
                                                    nextItem: ao
                                                }]
                                            }
                                        },
                                        [ao]: {
                                            type: Mt.vd.Empty,
                                            preProcess: [{
                                                type: Lt.O.HideTara
                                            }]
                                        }
                                    }
                                }
                            }
                        },
                        lo = "mini",
                        co = "notInPolicy",
                        uo = "notEncrypted",
                        po = "requestApproval",
                        ho = "releaseUpload",
                        fo = "closeTara",
                        go = "howToEncrypt",
                        mo = {
                            name: "dropboxUpload",
                            firstItem: lo,
                            desc: {
                                [lo]: {
                                    firstItem: co,
                                    type: Mt.vd.MiniScenario,
                                    desc: {
                                        [co]: {
                                            preProcess: [{
                                                type: Lt.O.Delay,
                                                ms: 500
                                            }, {
                                                type: Lt.O.ShowTara
                                            }],
                                            type: Mt.vd.Message,
                                            message: "According to the organizational policy, uploading a file in this application requires either encryption or an approval.",
                                            nextItem: uo
                                        },
                                        [uo]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                dotsDelay: 1500,
                                                text: "The file is not encrypted.<br />                         Please cancel the operation, encrypt the file and upload it again",
                                                buttons: [{
                                                    type: Qe.Jz.Primary,
                                                    text: "Got it",
                                                    nextItem: fo
                                                }, {
                                                    text: "Show me how to encrypt a file",
                                                    nextItem: go
                                                }, {
                                                    text: "Request an exception",
                                                    nextItem: po
                                                }]
                                            },
                                            augmentations: [{
                                                type: Z.p.Disabler,
                                                elementSelectors: {
                                                    $var: "uploadButton"
                                                },
                                                context: "scenario"
                                            }, {
                                                type: Z.p.WarningFrame,
                                                elementSelectors: {
                                                    $var: "cancelButton"
                                                },
                                                context: "scenario",
                                                xPadding: 3,
                                                yPadding: 3,
                                                radar: {}
                                            }, {
                                                type: Z.p.FocusMask,
                                                elementSelectors: {
                                                    $var: "cancelButton"
                                                },
                                                context: "scenario",
                                                xPadding: 3,
                                                yPadding: 3
                                            }]
                                        },
                                        [po]: {
                                            type: Mt.vd.Message,
                                            message: "Please provide business justification",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: ho
                                        },
                                        [ho]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: `Thank you. I created ticket CHG${new Gt(new $t(re)).randomInt(7)} for you. I'll keep you posted`,
                                                dotsDelay: 1e3,
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "View ticket",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    }
                                                }, {
                                                    layout: Qe.LS.Row,
                                                    text: "Got it",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    },
                                                    type: Qe.Jz.Primary
                                                }]
                                            }
                                        },
                                        reUpload: {
                                            type: Mt.vd.Empty,
                                            postProcess: [{
                                                type: Lt.O.HideTara
                                            }]
                                        },
                                        [fo]: {
                                            type: Mt.vd.Empty,
                                            preProcess: [{
                                                type: Lt.O.HideTara
                                            }]
                                        },
                                        [go]: {
                                            type: Mt.vd.Empty
                                        }
                                    }
                                }
                            }
                        },
                        yo = "augment",
                        bo = {
                            name: "liveAttack",
                            firstItem: yo,
                            desc: {
                                [yo]: {
                                    type: Mt.vd.Empty,
                                    augmentations: {
                                        $var: Bt
                                    }
                                }
                            }
                        },
                        xo = "Welcome",
                        vo = "PersonalUse",
                        wo = "BusinessUse",
                        _o = "GraphicDesign",
                        ko = "IKnowMiro",
                        Co = "RequestException",
                        So = "CreateTicket",
                        Eo = {
                            name: "malwareDownload",
                            firstItem: "mini",
                            desc: {
                                mini: {
                                    type: Mt.vd.MiniScenario,
                                    firstItem: xo,
                                    desc: {
                                        [xo]: {
                                            type: Mt.vd.Message,
                                            preProcess: [{
                                                type: Lt.O.ShowTara
                                            }],
                                            message: {
                                                text: "I noticed youâ€™re downloading a software installation file. I donâ€™t recognize it. What is the purpose of this software?",
                                                type: Qe.Jr.Text,
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Personal use",
                                                    nextItem: vo
                                                }, {
                                                    text: "Business use",
                                                    nextItem: wo,
                                                    type: Qe.Jz.Primary
                                                }]
                                            }
                                        },
                                        [vo]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                text: 'Downloading unknown software for personal use is not allowed. See the <a href="javascript:void(0)">organizational policy</a>',
                                                type: Qe.Jr.Text,
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "Request an Exception",
                                                    nextItem: Co
                                                }, {
                                                    text: "Got it",
                                                    type: Qe.Jz.Primary,
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    }
                                                }]
                                            }
                                        },
                                        [Co]: {
                                            type: Mt.vd.Message,
                                            message: "Please provide business justification",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: So
                                        },
                                        [So]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                text: `Thank you. I created ticket CHG${new Gt(new $t(re)).randomInt(7)} for you. I'll keep you posted`,
                                                dotsDelay: 1e3,
                                                buttons: [{
                                                    layout: Qe.LS.Row,
                                                    text: "View ticket",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    }
                                                }, {
                                                    layout: Qe.LS.Row,
                                                    text: "Got it",
                                                    op: {
                                                        type: Lt.O.HideTara
                                                    },
                                                    type: Qe.Jz.Primary
                                                }]
                                            }
                                        },
                                        [wo]: {
                                            type: Mt.vd.Message,
                                            message: "Can you share what type of software this is?",
                                            chips: ["Finance", "Productivity", "Audio", "Marketing", "Software Development", "Graphic Design", "Other"],
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: _o
                                        },
                                        [_o]: {
                                            type: Mt.vd.Message,
                                            message: "Please specify the name of the vendor that publishes this software. I want to check that itâ€™s safe to download it",
                                            postProcess: [{
                                                type: Lt.O.WaitForUserInput,
                                                propagate: ue.cg.ClientOnly
                                            }],
                                            nextItem: ko
                                        },
                                        [ko]: {
                                            type: Mt.vd.Message,
                                            message: {
                                                type: Qe.Jr.Text,
                                                dotsDelay: 3e3,
                                                text: "I know Miro. Their official website is miro.com. I highly recommend you download the                         software from there. Software installation is much safer when done from the official vendorâ€™s website",
                                                buttons: [{
                                                    type: Qe.Jz.Primary,
                                                    text: "Take me to miro.com",
                                                    op: {
                                                        type: Lt.O.OpenTab,
                                                        url: "https://miro.com"
                                                    }
                                                }, {
                                                    text: "I have to download it from here",
                                                    op: {
                                                        type: Lt.O.ReleasePendingDownload,
                                                        downloadId: {
                                                            $var: "pending-download-id"
                                                        }
                                                    }
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Io = {
                            test: si,
                            phishingTraining: $i,
                            anyoneWithLink: yi,
                            clickupSignup: Li,
                            clickUpMfaGuide: Wi,
                            zoomDownload: Zi,
                            downloadTraining: Xi,
                            swgAccess: Ki,
                            logoDetection: Qi.N,
                            liveAttack: bo,
                            malwareDownload: Eo,
                            dropboxSignin: so,
                            dropboxUpload: mo,
                            outlookSendProtect: Xt,
                            default: {
                                name: "Default",
                                firstItem: "",
                                desc: {}
                            }
                        };
                    var Ao = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    const Oo = {
                            type: Mt.vd.Message,
                            itemName: "help",
                            message: "I'm Tara. your personal security assistance. I will be guiding you in your online path and warn you whenever something looks off."
                        },
                        To = {
                            type: Mt.vd.Message,
                            itemName: "company policy",
                            message: "In our company we are wise enough to install tools that help us be better professionals. Like Tara."
                        },
                        Mo = {
                            type: Mt.vd.Message,
                            itemName: "sorry",
                            message: "Currently in work - come back on the next release"
                        };
                    let Ro = class {
                        constructor(e, t) {
                            this._log = e, this._utils = t
                        }
                        handleMessage(e) {
                            throw new Error("Method not implemented.")
                        }
                        handleError(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        sendMessage(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        closeConversation(e) {
                            throw new Error("Method not implemented.")
                        }
                        setNewHandler(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        startConversation(e, t) {
                            let n = t;
                            const i = function(e) {
                                    if (Io[e]) return Io[e]
                                }(e),
                                o = this._log,
                                r = this._utils.randomInt;

                            function a(e) {
                                let t = i.desc[e];
                                if (!t) switch (e && e.toLowerCase()) {
                                    case "help":
                                        t = Oo;
                                        break;
                                    case "company policy":
                                        t = To;
                                        break;
                                    case "":
                                    case kt[0].toLowerCase():
                                    case kt[1].toLowerCase():
                                        return;
                                    default:
                                        t = Mo
                                }
                                setTimeout((() => n(function(e, t) {
                                    return e.itemName = t, {
                                        id: `c2s-${r()}`,
                                        state: t,
                                        scenarioItem: e,
                                        scenarioMetadata: {},
                                        isServerInitiated: !1
                                    }
                                }(t, e))), 0)
                            }
                            return a(i.firstItem), {
                                sendMessage: function(e) {
                                    e.type === S.ConversationInputType.Predefined ? a(e.data.transitionToTrigger) : a(e.data.text)
                                },
                                closeConversation: function() {
                                    o.info("close conversation")
                                },
                                setNewHandler: e => {
                                    n = e
                                },
                                getID: () => `${r()}`
                            }
                        }
                        registerDefaultHandler(e) {
                            this._log.info("Registering default handler", e)
                        }
                        init() {
                            this._log.info("init")
                        }
                    };
                    Ro = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Ao(0, (0, I.f)(Y.ILogger)), Ao(1, (0, I.f)(Y.ICommonUtils)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], Ro);
                    class Po {
                        constructor() {
                            this.handlers = new Map, this.active = !0, this.url = "", this.log = Vn.logger.getLogger(v), this.downloadMessage = (e, t) => {
                                this.handlers.get(t)(e)
                            }
                        }
                        init(e) {
                            this.url = e
                        }
                        registerHandler(e, t, n) {
                            this.handlers.set(e, t)
                        }
                        registerErrorHandler(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        sendMessage(e, t, n) {
                            return this.log.info("sending message, msgType:", e, "msg:", t), "fake-request-id"
                        }
                        addConnectionEventListener(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        removeConnectionEventListener(e, t) {
                            throw new Error("Method not implemented.")
                        }
                        addConnectionStatusListeners(e, t) {
                            throw new Error("Method not implemented.")
                        }
                    }

                    function Do(e) {
                        e.bind(w.IMeddler).to(Be).inSingletonScope(), e.bind(w.IDownloader).to(K).inSingletonScope();
                        const t = new Po;
                        e.bind(S.TYPES.ICerebroClient).toConstantValue(t)
                    }
                    let jo = class {
                        constructor() {
                            this._store = {}, this.get = e => this._store[e], this.set = (e, t) => {
                                t ? this._store[e] = t : delete this._store[e]
                            }
                        }
                        getContext() {
                            return {
                                ...this._store
                            }
                        }
                    };
                    jo = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)()], jo);
                    var Lo = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let Fo = class {
                        constructor(e, t) {
                            this._utils = e, this._config = t.config, window.addEventListener("message", (e => {
                                const t = e.data;
                                t.type === _.ElementRectRequest && (async () => {
                                    const n = await this.getElementRect(t.details.selectors, t.details.origin);
                                    if (!n) return;
                                    const i = {
                                        key: t.key,
                                        type: _.ElementRectResponse,
                                        details: {
                                            rect: n
                                        }
                                    };
                                    e.source.postMessage(i, {
                                        targetOrigin: e.origin
                                    })
                                })()
                            }))
                        }
                        async getFrameElementRect(e, t, n) {
                            const i = this._utils.randomInt();
                            return new Promise(((o, r) => {
                                window.addEventListener("message", (e => {
                                    const n = e.data;
                                    n.key === i && n.type === _.ElementRectResponse && e.origin === t.src && o(n.details.rect)
                                }));
                                const a = {
                                    key: i,
                                    type: _.ElementRectRequest,
                                    details: {
                                        selectors: e,
                                        origin: n
                                    }
                                };
                                t.contentWindow.postMessage(a, t.src), setTimeout((() => r("getFrameElementRect timeout for " + t.src)), this._config.getFrameElementRectTimeout)
                            }))
                        }
                        async getElementRectAndParent(e, t = J.Parent) {
                            let n, i = new DOMRect(0, 0, 0, 0),
                                o = document;
                            for (let r = 0; r < e.length; r++) {
                                const a = e[r];
                                if (n = o.querySelector(a), !n) throw new Error(`Selector not found: ${a}`);
                                const s = n.getBoundingClientRect();
                                if (i = t === J.Parent ? s : new DOMRect(s.x + i.x, s.y + i.y, s.width, s.height), "IFRAME" === n.nodeName && (o = n.contentDocument, null === o)) {
                                    const o = e.slice(r + 1);
                                    i = await this.getFrameElementRect(o, n, t), n = null;
                                    break
                                }
                            }
                            return [i, o, n]
                        }
                        async getElementRect(e, t = J.Parent) {
                            const [n] = await this.getElementRectAndParent(e, t);
                            return n
                        }
                        async getElementWithTimeout(e, t = 0) {
                            return this.getElementWithTimeoutBase(e, t, !1)
                        }
                        async getElementsWithTimeout(e, t = 0) {
                            return this.getElementWithTimeoutBase(e, t, !0)
                        }
                        async getElementWithTimeoutBase(e, t, n) {
                            let i, o = !1;
                            setTimeout((() => o = !0), t), i = n ? this.getElements(e) : this.getElement(e);
                            const r = () => !!i && (!Array.isArray(i) || i.length > 0);
                            for (; !o && !r() && t > 0;) {
                                !r() && t > 0 && await this._utils.sleep(this._config.domPollingIntervalMs);
                                try {
                                    i = n ? this.getElements(e) : this.getElement(e)
                                } catch {}
                            }
                            return i
                        }
                        getElements(e) {
                            const t = this.getElementBase(e);
                            return t.length ? t : []
                        }
                        getElement(e) {
                            const t = this.getElementBase(e);
                            return t.length ? t[0] : null
                        }
                        getElementBase(e, t = document) {
                            const n = [...e],
                                i = [],
                                o = n.shift();
                            return t.querySelectorAll(o).forEach((e => {
                                let t = e;
                                if (0 === n.length) return i.push(t);
                                t instanceof HTMLIFrameElement && (t = t.contentDocument), i.push(...this.getElementBase(n, t))
                            })), i
                        }
                        isPositionFixed(e) {
                            for (let t = 0; t < e.length; t++) {
                                const n = e.slice(0, t + 1);
                                let i = this.getElement(n);
                                for (; i;) {
                                    if ("fixed" === window.getComputedStyle(i).position) {
                                        if ("IFRAME" === i.tagName && t < e.length - 1) break;
                                        return !0
                                    }
                                    i = i.parentElement
                                }
                            }
                            return !1
                        }
                        focusElement(e) {
                            this.getElement(e).focus()
                        }
                        getElementData(e, t) {
                            const n = this.getElement(e);
                            return t ? "value" === t && n instanceof HTMLInputElement ? n.value : n.getAttribute(t) : n.innerText
                        }
                        setElementData(e, t, n) {
                            const i = this.getElement(e);
                            n ? "value" === n && i instanceof HTMLInputElement ? i.value = t : i.setAttribute(n, t) : i.innerHTML = t
                        }
                    };
                    Fo = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Lo(0, (0, I.f)(Y.ICommonUtils)), Lo(1, (0, I.f)(Y.IConfigProvider)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object])], Fo);
                    let Ho = class {
                        constructor() {
                            this.fromVertices = e => {
                                const t = Math.min(...e.map((e => e.x))),
                                    n = Math.max(...e.map((e => e.x))),
                                    i = Math.min(...e.map((e => e.y))),
                                    o = Math.max(...e.map((e => e.y)));
                                return new DOMRect(t, i, n - t, o - i)
                            }, this.center = e => ({
                                x: (e.left + e.right) / 2,
                                y: (e.top + e.bottom) / 2
                            }), this.topLeft = e => ({
                                x: e.left,
                                y: e.top
                            }), this.add = (e, t) => new DOMRect(e.x + t.x, e.y + t.y, e.width, e.height), this.subtract = (e, t) => new DOMRect(e.x - t.x, e.y - t.y, e.width, e.height), this.equalSize = (e, t) => e.width === t.width && e.height === t.height, this.pad = (e, t, n) => new DOMRect(e.x - t, e.y - n, e.width + 2 * t, e.height + 2 * n)
                        }
                    };
                    Ho = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)()], Ho);
                    var Bo = function(e, t) {
                        return function(n, i) {
                            t(n, i, e)
                        }
                    };
                    let No = class {
                        constructor(e, t, n, i, o) {
                            this.common = e, this.dom = t, this.logger = n, this.rect = i, this.config = o
                        }
                    };
                    No = function(e, t, n, i) {
                        var o, r = arguments.length,
                            a = r < 3 ? t : null === i ? i = Object.getOwnPropertyDescriptor(t, n) : i;
                        if ("object" == typeof Reflect && "function" == typeof Reflect.decorate) a = Reflect.decorate(e, t, n, i);
                        else
                            for (var s = e.length - 1; s >= 0; s--)(o = e[s]) && (a = (r < 3 ? o(a) : r > 3 ? o(t, n, a) : o(t, n)) || a);
                        return r > 3 && a && Object.defineProperty(t, n, a), a
                    }([(0, E.b)(), Bo(0, (0, I.f)(Y.ICommonUtils)), Bo(1, (0, I.f)(Y.IDomUtils)), Bo(2, (0, I.f)(Y.ILogger)), Bo(3, (0, I.f)(Y.IRectUtils)), Bo(4, (0, I.f)(Y.IConfigProvider)), function(e, t) {
                        if ("object" == typeof Reflect && "function" == typeof Reflect.metadata) return Reflect.metadata(e, t)
                    }("design:paramtypes", [Object, Object, Object, Object, Object])], No);
                    const Uo = new x.W;
                    let Vo = null,
                        zo = null;
                    ! function(e) {
                        e.bind(Y.ICommonUtils).to(Gt), e.bind(Y.IDomUtils).to(Fo), e.bind(Y.IRectUtils).to(Ho), e.bind(Y.IToolbox).to(No).inSingletonScope(), e.bind(Y.IConfigProvider).toConstantValue(new $t(re)), e.bind(Y.IContextStore).toConstantValue(new jo), e.bind(Y.ILogger).toDynamicValue((() => Vn.logger.getContextualLogger({}, {}, v, !0)))
                    }(Uo);
                    const Wo = Uo.get(Y.ICommonUtils);

                    function Go() {
                        const e = Uo.get(Y.ILogger);
                        e.setLevel("info"), Object.getOwnPropertyDescriptor(window, "taraInstalled") ? e.error("Can only install tara once!") : (Object.defineProperty(window, "taraInstalled", {
                            value: !0,
                            writable: !1
                        }), Wo.isMainFrame() ? function(e) {
                            Do(e), e.bind(w.ITara).to(Ct).inSingletonScope(), e.bind(w.IIndicator).to(pe).inSingletonScope(), e.bind(w.IDominerService).to(Wn).inSingletonScope(), e.bind(w.ITaraform).to(Yn).inSingletonScope(), e.bind(w.IConversationProxy).to(Ot).inSingletonScope(), e.bind($n.IActivityLogger).to(ri).inSingletonScope(), e.bind(S.TYPES.IConversationsManager).to(Ro).inSingletonScope(),
                                function(e) {
                                    e.bind(Et.ICredentialsFlow).to(Ht).inSingletonScope(), e.bind(Et.IShowmeBuilder).to(cn).inSingletonScope(), e.bind(Et.IOutlookAddin).to(en).inSingletonScope(), e.bind(Et.ILiveAttack).to(Ut).inSingletonScope()
                                }(e),
                                function(e) {
                                    e.bind(Gn.IConditioner).to(Qn), e.bind(Gn.IMessageParser).to(ti), e.bind(Gn.IOperator).to(ii)
                                }(e)
                        }(Uo) : function(e) {
                            Do(e)
                        }(Uo), b.use({
                            target: document.head
                        }), Wo.isMainFrame() ? (e.info("Installing taraform on main frame"), Uo.get(w.IDominerService), Vo = Uo.get(w.IConversationProxy)) : (e.info("Installing taraform on frame " + window.location.origin), Uo.get(w.IMeddler)), zo = Uo.get(S.TYPES.ICerebroClient), function(e) {
                            e.get(Et.ICredentialsFlow), e.get(Et.IShowmeBuilder), e.get(Et.IOutlookAddin), e.get(Et.ILiveAttack)
                        }(Uo))
                    }

                    function $o(e = k.Standard, t) {
                        alert(1);
                    }
                },
                7710: (e, t, n) => {
                    "use strict";
                    var i, o;
                    n.d(t, {
                            $: () => i,
                            b: () => o
                        }),
                        function(e) {
                            e.LogoDetectionMismatch = "LogoDetectionMismatch", e.NoHTTPS = "NoHTTPS", e.PhishingURL = "PhishingURL"
                        }(i || (i = {})),
                        function(e) {
                            e.IntroAugmentations = "intro-augmentations", e.WalkthroughSteps = "walkthrough-steps", e.LogoSelectors = "logoMismatchLogoSelectors", e.InputSelectors = "logoMismatchInputSelectors", e.IntroContext = "intro-violations", e.Additionals = "Additionals"
                        }(o || (o = {}))
                },
                1920: (e, t, n) => {
                    "use strict";
                    n.d(t, {
                        N: () => u
                    });
                    var i = n(9058),
                        o = n(2813),
                        r = n(8772),
                        a = n(7364),
                        s = n(6453),
                        l = n(2190),
                        c = n(3815),
                        d = n(7710);
                    e = n.hmd(e);
                    const u = {
                        firstItem: "mini",
                        name: "phishing",
                        desc: {
                            mini: {
                                type: l.vd.MiniScenario,
                                itemName: "mini",
                                firstItem: "first",
                                desc: {
                                    first: {
                                        type: l.vd.Message,
                                        message: "<b>This looks like a phishing website.</b> Continuing could put you and your organization at risk",
                                        taraStatus: c.wi.Warning,
                                        preProcess: [{
                                            type: s.O.ShowTara
                                        }],
                                        nextItem: "showButtons"
                                    },
                                    showButtons: {
                                        type: l.vd.Message,
                                        message: {
                                            text: "What would you like to do?",
                                            type: a.Jr.Text,
                                            buttons: [{
                                                text: "Got it, report it",
                                                type: a.Jz.Primary,
                                                nextItem: "reportMessageAndClose"
                                            }, {
                                                text: "Show me why it's suspicious",
                                                nextItem: "whySuspicious"
                                            }, {
                                                text: "I think this is a mistake",
                                                nextItem: "thisIsAMistake"
                                            }]
                                        },
                                        augmentations: {
                                            $var: d.b.IntroAugmentations
                                        }
                                    },
                                    reportMessageAndClose: {
                                        type: l.vd.Message,
                                        message: "I reported this phishing attempt to the security team. Please don't enter anything, and close the page. Stay safe!",
                                        taraStatus: c.wi.Healthy,
                                        postProcess: [{
                                            type: s.O.ClearContext,
                                            contexts: ["aug-scenario"]
                                        }]
                                    },
                                    whySuspicious: {
                                        type: l.vd.Recursive,
                                        doneMessage: "All set",
                                        preProcess: [{
                                            type: s.O.HideTara
                                        }, {
                                            type: s.O.ClearContext,
                                            contexts: [d.b.IntroContext]
                                        }],
                                        postProcess: [{
                                            type: s.O.ClearContext,
                                            contexts: ["box"]
                                        }, {
                                            type: s.O.ShowTara
                                        }],
                                        steps: {
                                            $var: d.b.WalkthroughSteps
                                        },
                                        nextItem: "showButtons"
                                    },
                                    thisIsAMistake: {
                                        type: l.vd.Message,
                                        message: {
                                            text: "This website looks suspicious. Entering your credentials could put your account and data at risk.                         To keep yourself safe, I recommend stopping and closing the page. Are you sure you want to continue?",
                                            type: a.Jr.Text,
                                            buttons: [{
                                                text: "No",
                                                type: a.Jz.Primary,
                                                nextItem: "reportMessageAndClose",
                                                layout: a.LS.Row
                                            }, {
                                                text: "Yes, continue anyway",
                                                nextItem: "takeTheRisk"
                                            }]
                                        }
                                    },
                                    takeTheRisk: {
                                        type: l.vd.Message,
                                        message: "For your security, I reported this to the security team. They'll be in touch with you if necessary. We're here to keep you safe",
                                        postProcess: [{
                                            type: s.O.ClearContext,
                                            contexts: ["scenario", d.b.IntroContext]
                                        }],
                                        nextItem: "emailUpdate"
                                    },
                                    emailUpdate: {
                                        type: l.vd.Empty,
                                        preProcess: [{
                                            elementSelectors: {
                                                $var: d.b.InputSelectors
                                            },
                                            type: s.O.GetElementData,
                                            attribute: "value",
                                            varName: "emailInputValue"
                                        }],
                                        postProcess: [{
                                            type: s.O.WaitForEvent,
                                            event: "keyup",
                                            elementSelectors: {
                                                $var: d.b.InputSelectors
                                            }
                                        }],
                                        nextItem: "emailValidation"
                                    },
                                    emailValidation: {
                                        type: l.vd.Condition,
                                        condition: {
                                            type: r.CP.ElementValue,
                                            target: {
                                                $var: d.b.Additionals
                                            },
                                            dataType: r.nY.String,
                                            op: r.fo.BusinessEmail
                                        },
                                        elementSelectors: {
                                            $var: d.b.InputSelectors
                                        },
                                        preProcess: [{
                                            type: s.O.ClearContext,
                                            contexts: ["danger-aug-scenario", "aug-scenario", "scenario"]
                                        }],
                                        ifFalse: "emailUpdate",
                                        ifTrue: "organizationEmail"
                                    },
                                    organizationEmail: {
                                        type: l.vd.Message,
                                        taraStatus: c.wi.Error,
                                        message: "You won't be able to sign in with your organization's credentials until it's                         reviewed by the security team. Thanks for understanding!",
                                        preProcess: [{
                                            type: s.O.ClearContext,
                                            contexts: ["aug-scenario"]
                                        }, {
                                            elementSelectors: {
                                                $var: d.b.InputSelectors
                                            },
                                            type: s.O.SetElementData,
                                            attribute: "value",
                                            value: {
                                                $var: "emailInputValue"
                                            }
                                        }],
                                        augmentations: [{
                                            type: o.p.DangerFrame,
                                            elementSelectors: {
                                                $var: d.b.LogoSelectors
                                            },
                                            context: "danger-aug-scenario",
                                            xPadding: 10,
                                            yPadding: 10
                                        }, {
                                            type: o.p.DangerFrame,
                                            elementSelectors: {
                                                $var: d.b.InputSelectors
                                            },
                                            context: "danger-aug-scenario",
                                            xPadding: 10,
                                            yPadding: 10
                                        }],
                                        nextItem: "emailUpdate"
                                    }
                                }
                            }
                        }
                    };
                    if (n.c[n.s] === e) {
                        const e = {
                            function: "",
                            scenarioItem: u.desc.mini
                        };
                        i.logger.getLogger("temp").info(JSON.stringify(e, null, "\t"))
                    }
                },
                1614: (e, t, n) => {
                    "use strict";
                    var i;
                    n.r(t), n.d(t, {
                        NIL: () => T,
                        parse: () => m,
                        stringify: () => d,
                        v1: () => g,
                        v3: () => S,
                        v4: () => E,
                        v5: () => O,
                        validate: () => s,
                        version: () => M
                    });
                    var o = new Uint8Array(16);

                    function r() {
                        if (!i && !(i = "undefined" != typeof crypto && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || "undefined" != typeof msCrypto && "function" == typeof msCrypto.getRandomValues && msCrypto.getRandomValues.bind(msCrypto))) throw new Error("crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported");
                        return i(o)
                    }
                    const a = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i,
                        s = function(e) {
                            return "string" == typeof e && a.test(e)
                        };
                    for (var l = [], c = 0; c < 256; ++c) l.push((c + 256).toString(16).substr(1));
                    const d = function(e) {
                        var t = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0,
                            n = (l[e[t + 0]] + l[e[t + 1]] + l[e[t + 2]] + l[e[t + 3]] + "-" + l[e[t + 4]] + l[e[t + 5]] + "-" + l[e[t + 6]] + l[e[t + 7]] + "-" + l[e[t + 8]] + l[e[t + 9]] + "-" + l[e[t + 10]] + l[e[t + 11]] + l[e[t + 12]] + l[e[t + 13]] + l[e[t + 14]] + l[e[t + 15]]).toLowerCase();
                        if (!s(n)) throw TypeError("Stringified UUID is invalid");
                        return n
                    };
                    var u, p, h = 0,
                        f = 0;
                    const g = function(e, t, n) {
                            var i = t && n || 0,
                                o = t || new Array(16),
                                a = (e = e || {}).node || u,
                                s = void 0 !== e.clockseq ? e.clockseq : p;
                            if (null == a || null == s) {
                                var l = e.random || (e.rng || r)();
                                null == a && (a = u = [1 | l[0], l[1], l[2], l[3], l[4], l[5]]), null == s && (s = p = 16383 & (l[6] << 8 | l[7]))
                            }
                            var c = void 0 !== e.msecs ? e.msecs : Date.now(),
                                g = void 0 !== e.nsecs ? e.nsecs : f + 1,
                                m = c - h + (g - f) / 1e4;
                            if (m < 0 && void 0 === e.clockseq && (s = s + 1 & 16383), (m < 0 || c > h) && void 0 === e.nsecs && (g = 0), g >= 1e4) throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
                            h = c, f = g, p = s;
                            var y = (1e4 * (268435455 & (c += 122192928e5)) + g) % 4294967296;
                            o[i++] = y >>> 24 & 255, o[i++] = y >>> 16 & 255, o[i++] = y >>> 8 & 255, o[i++] = 255 & y;
                            var b = c / 4294967296 * 1e4 & 268435455;
                            o[i++] = b >>> 8 & 255, o[i++] = 255 & b, o[i++] = b >>> 24 & 15 | 16, o[i++] = b >>> 16 & 255, o[i++] = s >>> 8 | 128, o[i++] = 255 & s;
                            for (var x = 0; x < 6; ++x) o[i + x] = a[x];
                            return t || d(o)
                        },
                        m = function(e) {
                            if (!s(e)) throw TypeError("Invalid UUID");
                            var t, n = new Uint8Array(16);
                            return n[0] = (t = parseInt(e.slice(0, 8), 16)) >>> 24, n[1] = t >>> 16 & 255, n[2] = t >>> 8 & 255, n[3] = 255 & t, n[4] = (t = parseInt(e.slice(9, 13), 16)) >>> 8, n[5] = 255 & t, n[6] = (t = parseInt(e.slice(14, 18), 16)) >>> 8, n[7] = 255 & t, n[8] = (t = parseInt(e.slice(19, 23), 16)) >>> 8, n[9] = 255 & t, n[10] = (t = parseInt(e.slice(24, 36), 16)) / 1099511627776 & 255, n[11] = t / 4294967296 & 255, n[12] = t >>> 24 & 255, n[13] = t >>> 16 & 255, n[14] = t >>> 8 & 255, n[15] = 255 & t, n
                        };

                    function y(e, t, n) {
                        function i(e, i, o, r) {
                            if ("string" == typeof e && (e = function(e) {
                                    e = unescape(encodeURIComponent(e));
                                    for (var t = [], n = 0; n < e.length; ++n) t.push(e.charCodeAt(n));
                                    return t
                                }(e)), "string" == typeof i && (i = m(i)), 16 !== i.length) throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
                            var a = new Uint8Array(16 + e.length);
                            if (a.set(i), a.set(e, i.length), (a = n(a))[6] = 15 & a[6] | t, a[8] = 63 & a[8] | 128, o) {
                                r = r || 0;
                                for (var s = 0; s < 16; ++s) o[r + s] = a[s];
                                return o
                            }
                            return d(a)
                        }
                        try {
                            i.name = e
                        } catch (e) {}
                        return i.DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8", i.URL = "6ba7b811-9dad-11d1-80b4-00c04fd430c8", i
                    }

                    function b(e) {
                        return 14 + (e + 64 >>> 9 << 4) + 1
                    }

                    function x(e, t) {
                        var n = (65535 & e) + (65535 & t);
                        return (e >> 16) + (t >> 16) + (n >> 16) << 16 | 65535 & n
                    }

                    function v(e, t, n, i, o, r) {
                        return x((a = x(x(t, e), x(i, r))) << (s = o) | a >>> 32 - s, n);
                        var a, s
                    }

                    function w(e, t, n, i, o, r, a) {
                        return v(t & n | ~t & i, e, t, o, r, a)
                    }

                    function _(e, t, n, i, o, r, a) {
                        return v(t & i | n & ~i, e, t, o, r, a)
                    }

                    function k(e, t, n, i, o, r, a) {
                        return v(t ^ n ^ i, e, t, o, r, a)
                    }

                    function C(e, t, n, i, o, r, a) {
                        return v(n ^ (t | ~i), e, t, o, r, a)
                    }
                    const S = y("v3", 48, (function(e) {
                            if ("string" == typeof e) {
                                var t = unescape(encodeURIComponent(e));
                                e = new Uint8Array(t.length);
                                for (var n = 0; n < t.length; ++n) e[n] = t.charCodeAt(n)
                            }
                            return function(e) {
                                for (var t = [], n = 32 * e.length, i = "0123456789abcdef", o = 0; o < n; o += 8) {
                                    var r = e[o >> 5] >>> o % 32 & 255,
                                        a = parseInt(i.charAt(r >>> 4 & 15) + i.charAt(15 & r), 16);
                                    t.push(a)
                                }
                                return t
                            }(function(e, t) {
                                e[t >> 5] |= 128 << t % 32, e[b(t) - 1] = t;
                                for (var n = 1732584193, i = -271733879, o = -1732584194, r = 271733878, a = 0; a < e.length; a += 16) {
                                    var s = n,
                                        l = i,
                                        c = o,
                                        d = r;
                                    n = w(n, i, o, r, e[a], 7, -680876936), r = w(r, n, i, o, e[a + 1], 12, -389564586), o = w(o, r, n, i, e[a + 2], 17, 606105819), i = w(i, o, r, n, e[a + 3], 22, -1044525330), n = w(n, i, o, r, e[a + 4], 7, -176418897), r = w(r, n, i, o, e[a + 5], 12, 1200080426), o = w(o, r, n, i, e[a + 6], 17, -1473231341), i = w(i, o, r, n, e[a + 7], 22, -45705983), n = w(n, i, o, r, e[a + 8], 7, 1770035416), r = w(r, n, i, o, e[a + 9], 12, -1958414417), o = w(o, r, n, i, e[a + 10], 17, -42063), i = w(i, o, r, n, e[a + 11], 22, -1990404162), n = w(n, i, o, r, e[a + 12], 7, 1804603682), r = w(r, n, i, o, e[a + 13], 12, -40341101), o = w(o, r, n, i, e[a + 14], 17, -1502002290), n = _(n, i = w(i, o, r, n, e[a + 15], 22, 1236535329), o, r, e[a + 1], 5, -165796510), r = _(r, n, i, o, e[a + 6], 9, -1069501632), o = _(o, r, n, i, e[a + 11], 14, 643717713), i = _(i, o, r, n, e[a], 20, -373897302), n = _(n, i, o, r, e[a + 5], 5, -701558691), r = _(r, n, i, o, e[a + 10], 9, 38016083), o = _(o, r, n, i, e[a + 15], 14, -660478335), i = _(i, o, r, n, e[a + 4], 20, -405537848), n = _(n, i, o, r, e[a + 9], 5, 568446438), r = _(r, n, i, o, e[a + 14], 9, -1019803690), o = _(o, r, n, i, e[a + 3], 14, -187363961), i = _(i, o, r, n, e[a + 8], 20, 1163531501), n = _(n, i, o, r, e[a + 13], 5, -1444681467), r = _(r, n, i, o, e[a + 2], 9, -51403784), o = _(o, r, n, i, e[a + 7], 14, 1735328473), n = k(n, i = _(i, o, r, n, e[a + 12], 20, -1926607734), o, r, e[a + 5], 4, -378558), r = k(r, n, i, o, e[a + 8], 11, -2022574463), o = k(o, r, n, i, e[a + 11], 16, 1839030562), i = k(i, o, r, n, e[a + 14], 23, -35309556), n = k(n, i, o, r, e[a + 1], 4, -1530992060), r = k(r, n, i, o, e[a + 4], 11, 1272893353), o = k(o, r, n, i, e[a + 7], 16, -155497632), i = k(i, o, r, n, e[a + 10], 23, -1094730640), n = k(n, i, o, r, e[a + 13], 4, 681279174), r = k(r, n, i, o, e[a], 11, -358537222), o = k(o, r, n, i, e[a + 3], 16, -722521979), i = k(i, o, r, n, e[a + 6], 23, 76029189), n = k(n, i, o, r, e[a + 9], 4, -640364487), r = k(r, n, i, o, e[a + 12], 11, -421815835), o = k(o, r, n, i, e[a + 15], 16, 530742520), n = C(n, i = k(i, o, r, n, e[a + 2], 23, -995338651), o, r, e[a], 6, -198630844), r = C(r, n, i, o, e[a + 7], 10, 1126891415), o = C(o, r, n, i, e[a + 14], 15, -1416354905), i = C(i, o, r, n, e[a + 5], 21, -57434055), n = C(n, i, o, r, e[a + 12], 6, 1700485571), r = C(r, n, i, o, e[a + 3], 10, -1894986606), o = C(o, r, n, i, e[a + 10], 15, -1051523), i = C(i, o, r, n, e[a + 1], 21, -2054922799), n = C(n, i, o, r, e[a + 8], 6, 1873313359), r = C(r, n, i, o, e[a + 15], 10, -30611744), o = C(o, r, n, i, e[a + 6], 15, -1560198380), i = C(i, o, r, n, e[a + 13], 21, 1309151649), n = C(n, i, o, r, e[a + 4], 6, -145523070), r = C(r, n, i, o, e[a + 11], 10, -1120210379), o = C(o, r, n, i, e[a + 2], 15, 718787259), i = C(i, o, r, n, e[a + 9], 21, -343485551), n = x(n, s), i = x(i, l), o = x(o, c), r = x(r, d)
                                }
                                return [n, i, o, r]
                            }(function(e) {
                                if (0 === e.length) return [];
                                for (var t = 8 * e.length, n = new Uint32Array(b(t)), i = 0; i < t; i += 8) n[i >> 5] |= (255 & e[i / 8]) << i % 32;
                                return n
                            }(e), 8 * e.length))
                        })),
                        E = function(e, t, n) {
                            var i = (e = e || {}).random || (e.rng || r)();
                            if (i[6] = 15 & i[6] | 64, i[8] = 63 & i[8] | 128, t) {
                                n = n || 0;
                                for (var o = 0; o < 16; ++o) t[n + o] = i[o];
                                return t
                            }
                            return d(i)
                        };

                    function I(e, t, n, i) {
                        switch (e) {
                            case 0:
                                return t & n ^ ~t & i;
                            case 1:
                            case 3:
                                return t ^ n ^ i;
                            case 2:
                                return t & n ^ t & i ^ n & i
                        }
                    }

                    function A(e, t) {
                        return e << t | e >>> 32 - t
                    }
                    const O = y("v5", 80, (function(e) {
                            var t = [1518500249, 1859775393, 2400959708, 3395469782],
                                n = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
                            if ("string" == typeof e) {
                                var i = unescape(encodeURIComponent(e));
                                e = [];
                                for (var o = 0; o < i.length; ++o) e.push(i.charCodeAt(o))
                            } else Array.isArray(e) || (e = Array.prototype.slice.call(e));
                            e.push(128);
                            for (var r = e.length / 4 + 2, a = Math.ceil(r / 16), s = new Array(a), l = 0; l < a; ++l) {
                                for (var c = new Uint32Array(16), d = 0; d < 16; ++d) c[d] = e[64 * l + 4 * d] << 24 | e[64 * l + 4 * d + 1] << 16 | e[64 * l + 4 * d + 2] << 8 | e[64 * l + 4 * d + 3];
                                s[l] = c
                            }
                            s[a - 1][14] = 8 * (e.length - 1) / Math.pow(2, 32), s[a - 1][14] = Math.floor(s[a - 1][14]), s[a - 1][15] = 8 * (e.length - 1) & 4294967295;
                            for (var u = 0; u < a; ++u) {
                                for (var p = new Uint32Array(80), h = 0; h < 16; ++h) p[h] = s[u][h];
                                for (var f = 16; f < 80; ++f) p[f] = A(p[f - 3] ^ p[f - 8] ^ p[f - 14] ^ p[f - 16], 1);
                                for (var g = n[0], m = n[1], y = n[2], b = n[3], x = n[4], v = 0; v < 80; ++v) {
                                    var w = Math.floor(v / 20),
                                        _ = A(g, 5) + I(w, m, y, b) + x + t[w] + p[v] >>> 0;
                                    x = b, b = y, y = A(m, 30) >>> 0, m = g, g = _
                                }
                                n[0] = n[0] + g >>> 0, n[1] = n[1] + m >>> 0, n[2] = n[2] + y >>> 0, n[3] = n[3] + b >>> 0, n[4] = n[4] + x >>> 0
                            }
                            return [n[0] >> 24 & 255, n[0] >> 16 & 255, n[0] >> 8 & 255, 255 & n[0], n[1] >> 24 & 255, n[1] >> 16 & 255, n[1] >> 8 & 255, 255 & n[1], n[2] >> 24 & 255, n[2] >> 16 & 255, n[2] >> 8 & 255, 255 & n[2], n[3] >> 24 & 255, n[3] >> 16 & 255, n[3] >> 8 & 255, 255 & n[3], n[4] >> 24 & 255, n[4] >> 16 & 255, n[4] >> 8 & 255, 255 & n[4]]
                        })),
                        T = "00000000-0000-0000-0000-000000000000",
                        M = function(e) {
                            if (!s(e)) throw TypeError("Invalid UUID");
                            return parseInt(e.substr(14, 1), 16)
                        }
                }
            },
            __webpack_module_cache__ = {},
            inProgress, dataWebpackPrefix;

        function __webpack_require__(e) {
            var t = __webpack_module_cache__[e];
            if (void 0 !== t) return t.exports;
            var n = __webpack_module_cache__[e] = {
                id: e,
                loaded: !1,
                exports: {}
            };
            return __webpack_modules__[e].call(n.exports, n, n.exports, __webpack_require__), n.loaded = !0, n.exports
        }
        __webpack_require__.m = __webpack_modules__, __webpack_require__.c = __webpack_module_cache__, __webpack_require__.amdO = {}, __webpack_require__.n = e => {
            var t = e && e.__esModule ? () => e.default : () => e;
            return __webpack_require__.d(t, {
                a: t
            }), t
        }, __webpack_require__.d = (e, t) => {
            for (var n in t) __webpack_require__.o(t, n) && !__webpack_require__.o(e, n) && Object.defineProperty(e, n, {
                enumerable: !0,
                get: t[n]
            })
        }, __webpack_require__.f = {}, __webpack_require__.e = e => Promise.all(Object.keys(__webpack_require__.f).reduce(((t, n) => (__webpack_require__.f[n](e, t), t)), [])), __webpack_require__.u = e => e + ".js", __webpack_require__.g = function() {
            if ("object" == typeof globalThis) return globalThis;
            try {
                return this || new Function("return this")()
            } catch (e) {
                if ("object" == typeof window) return window
            }
        }(), __webpack_require__.hmd = e => ((e = Object.create(e)).children || (e.children = []), Object.defineProperty(e, "exports", {
            enumerable: !0,
            set: () => {
                throw new Error("ES Modules may not assign module.exports or exports.*, Use ESM export syntax, instead: " + e.id)
            }
        }), e), __webpack_require__.o = (e, t) => Object.prototype.hasOwnProperty.call(e, t), inProgress = {}, dataWebpackPrefix = "[name]:", __webpack_require__.l = (e, t, n, i) => {
            if (inProgress[e]) inProgress[e].push(t);
            else {
                var o, r;
                if (void 0 !== n)
                    for (var a = document.getElementsByTagName("script"), s = 0; s < a.length; s++) {
                        var l = a[s];
                        if (l.getAttribute("src") == e || l.getAttribute("data-webpack") == dataWebpackPrefix + n) {
                            o = l;
                            break
                        }
                    }
                o || (r = !0, (o = document.createElement("script")).charset = "utf-8", o.timeout = 120, __webpack_require__.nc && o.setAttribute("nonce", __webpack_require__.nc), o.setAttribute("data-webpack", dataWebpackPrefix + n), o.src = e), inProgress[e] = [t];
                var c = (t, n) => {
                        o.onerror = o.onload = null, clearTimeout(d);
                        var i = inProgress[e];
                        if (delete inProgress[e], o.parentNode && o.parentNode.removeChild(o), i && i.forEach((e => e(n))), t) return t(n)
                    },
                    d = setTimeout(c.bind(null, void 0, {
                        type: "timeout",
                        target: o
                    }), 12e4);
                o.onerror = c.bind(null, o.onerror), o.onload = c.bind(null, o.onload), r && document.head.appendChild(o)
            }
        }, __webpack_require__.r = e => {
            "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(e, Symbol.toStringTag, {
                value: "Module"
            }), Object.defineProperty(e, "__esModule", {
                value: !0
            })
        }, __webpack_require__.p = "", (() => {
            var e = {
                843: 0
            };
            __webpack_require__.f.j = (t, n) => {
                var i = __webpack_require__.o(e, t) ? e[t] : void 0;
                if (0 !== i)
                    if (i) n.push(i[2]);
                    else {
                        var o = new Promise(((n, o) => i = e[t] = [n, o]));
                        n.push(i[2] = o);
                        var r = __webpack_require__.p + __webpack_require__.u(t),
                            a = new Error;
                        __webpack_require__.l(r, (n => {
                            if (__webpack_require__.o(e, t) && (0 !== (i = e[t]) && (e[t] = void 0), i)) {
                                var o = n && ("load" === n.type ? "missing" : n.type),
                                    r = n && n.target && n.target.src;
                                a.message = "Loading chunk " + t + " failed.\n(" + o + ": " + r + ")", a.name = "ChunkLoadError", a.type = o, a.request = r, i[1](a)
                            }
                        }), "chunk-" + t, t)
                    }
            };
            var t = (t, n) => {
                    var i, o, [r, a, s] = n,
                        l = 0;
                    if (r.some((t => 0 !== e[t]))) {
                        for (i in a) __webpack_require__.o(a, i) && (__webpack_require__.m[i] = a[i]);
                        s && s(__webpack_require__)
                    }
                    for (t && t(n); l < r.length; l++) o = r[l], __webpack_require__.o(e, o) && e[o] && e[o][0](), e[o] = 0
                },
                n = self.webpackChunk_name_ = self.webpackChunk_name_ || [];
            n.forEach(t.bind(null, 0)), n.push = t.bind(null, n.push.bind(n))
        })();
        var __webpack_exports__ = __webpack_require__(__webpack_require__.s = 6005);
        return __webpack_exports__
    })()
}));