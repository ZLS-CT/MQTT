const JavaString = Java.type("java.lang.String")

const KEEPALIVE_MS = 30_000
const RECONNECT_MS = 5_000

// MQTT packets
const PKT_CONNECT = 0x10
const PKT_CONNACK = 0x20
const PKT_PUBLISH = 0x30
const PKT_SUBSCRIBE = 0x82
const PKT_SUBACK = 0x90
const PKT_PINGREQ = 0xC0
const PKT_PINGRESP = 0xD0
const PKT_DISCONNECT = 0xE0
const PKT_UNSUBSCRIBE = 0xA2
const PKT_UNSUBACK = 0xB0

const ChatLog = (...strings) => ChatLib.chat("§6[MQTT] §r" + strings.join(" | "))

const gzipDecompress = (byteArray) => {
    const input = new ByteArrayInputStream(byteArray)
    const gz = new GZIPInputStream(input)
    const out = new ByteArrayOutputStream()
    const buffer = JavaArray.newInstance(Byte.TYPE, 4096)
    let n
    while ((n = gz.read(buffer)) != -1) {
        out.write(buffer, 0, n)
    }
    gz.close()
    out.close()
    return new JavaString(out.toByteArray(), "UTF-8")
}

export class MQTTClient {
    constructor(
        hostURL,
        hostPort,
        hostUsername,
        hostPassword,
        certPaths = [],
        subscriptions = [],
        clientID = null,
    ) {
        this.hostURL = hostURL
        this.hostPort = hostPort
        this.hostUsername = hostUsername
        this.hostPassword = hostPassword
        this.clientID = clientID ?? `ct-client-${System.getProperty("user.name")}`
        this.certPaths = certPaths

        this.socket = null
        this.outStream = null
        this.inStream = null
        this.connected = false
        this.running = false
        this.topicCallbacks = {}
        this.compressionTypes = {}

        this._pendingSubscriptions = []
        subscriptions.forEach(({ topic, callback, compressionType }) => {
            this.subscribe(topic, callback, compressionType)
        })

        register("gameLoad", () => {
            this.start()
        })
        register("gameUnload", () => {
            this.stop()
        })
    }

    start() {
        if (this.running) return
        this.running = true
        this._startConnectThread()
    }
    stop() {
        this.running = false
        this._disconnect()
    }
    subscribe(topic, callback = null, compressionType = null) {
        if (!topic) {
            ChatLog("Invalid topic")
            return
        }
        this.topicCallbacks[topic] = callback
        if (compressionType) {
            this.compressionTypes[topic] = compressionType
        }
        this._pendingSubscriptions.push(topic)
    }
    unsubscribe(topic) {
        delete this.topicCallbacks[topic]
        delete this.compressionTypes[topic]
        if (this.connected) {
            this._sendUnsubscribe(topic)
            this._waitForUnsuback()
            ChatLog(`Unsubscribed from: ${topic}`)
        }
    }

    _buildSSLSocketFactory() {
        const cf = CertificateFactory.getInstance("X.509")

        const ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null, null)
        this.certPaths.forEach((path) => {
            const certName = path.substring(path.lastIndexOf("/") + 1)
            const fis = new FileInputStream(path)
            const cert = cf.generateCertificate(fis)
            fis.close()
            ks.setCertificateEntry(certName, cert)
        })

        const tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)

        const ctx = SSLContext.getInstance("TLS")
        ctx.init(null, tmf.getTrustManagers(), null)

        return ctx.getSocketFactory()
    }
    _startConnectThread() {
        new Thread(() => this._connect()).start()
    }
    _connect() {
        if (!this.running) return
        try {
            ChatLog(`Connecting to ${this.hostURL}:${this.hostPort}`)

            const factory = this._buildSSLSocketFactory()
            this.socket = factory.createSocket(this.hostURL, this.hostPort)
            this.socket.setSoTimeout(0)
            this.socket.setTcpNoDelay(true)

            this.inStream = new DataInputStream(this.socket.getInputStream())
            this.outStream = new DataOutputStream(this.socket.getOutputStream())

            this._sendConnect()
            this._waitForConnack()

            this.connected = true
            this._pendingSubscriptions.forEach((topic) => {
                this._sendSubscribe(topic)
                this._waitForSuback()
                ChatLog(`Subscribed to: ${topic}`)
            })
            this._pendingSubscriptions = []

            this._startPingThread()
            this._readLoop()

        } catch (e) {
            ChatLog("Connection failed:", e, e.stack)
            this._scheduleReconnect()
        }
    }
    _scheduleReconnect() {
        this.connected = false
        this._closeSocket()
        if (!this.running) return
        ChatLog(`Reconnecting in ${RECONNECT_MS / 1000}s...`)
        new Thread(() => {
            Thread.sleep(RECONNECT_MS)
            this._connect()
        }).start()
    }
    _disconnect() {
        this.connected = false
        try {
            if (this.socket && !this.socket.isClosed()) {
                this._sendDisconnect()
            }
        } catch (e) {
            ChatLog("Disconnect failed:", e, e.stack)
        }
        this._closeSocket()
    }
    _closeSocket() {
        try {
            if (this.socket) {
                this.socket.close()
            }
        } catch (e) {
            ChatLog("Socket close failed:", e, e.stack)
        }
    }
    _readLoop() {
        try {
            while (this.running && this.connected) {
                const packetType = this.inStream.readByte() & 0xF0
                const remaining = this._readRemainingLength()

                if (packetType === PKT_PUBLISH) {
                    this._handlePublish(remaining)
                } else if (packetType === PKT_PINGRESP) {
                    // keepalive acknowledged
                } else {
                    this.inStream.skipBytes(remaining)
                }
            }
        } catch (e) {
            if (this.running) {
                ChatLog("Read error:", e, e.stack)
                this._scheduleReconnect()
            }
        }
    }
    _startPingThread() {
        new Thread(() => {
            while (this.running && this.connected) {
                Thread.sleep(KEEPALIVE_MS)
                if (!this.connected) break
                try {
                    this._sendPingReq()
                } catch (e) {
                    ChatLog("Ping failed:", e, e.stack)
                    this._scheduleReconnect()
                    break
                }
            }
        }).start()
    }
    _writePacket(firstByte, bodyFn) {
        const buf = new ByteArrayOutputStream()
        bodyFn(buf)
        const body = buf.toByteArray()

        this.outStream.write(firstByte)

        let len = body.length
        do {
            let digit = len % 128
            len = Math.floor(len / 128)
            if (len > 0) digit |= 0x80
            this.outStream.write(digit)
        } while (len > 0)

        this.outStream.write(body, 0, body.length)
        this.outStream.flush()
    }
    _sendConnect() {
        const keepaliveSec = Math.floor(KEEPALIVE_MS / 1000)
        this._writePacket(PKT_CONNECT, (buf) => {
            // Protocol name "MQTT"
            buf.write(0x00)
            buf.write(0x04)
            buf.write(0x4D)
            buf.write(0x51)
            buf.write(0x54)
            buf.write(0x54)
            // Protocol level 3.1.1
            buf.write(0x04)
            // Connect flags: reused session + username + password
            buf.write(0xC0)
            // Keepalive
            buf.write((keepaliveSec >> 8) & 0xFF)
            buf.write(keepaliveSec & 0xFF)
            // Payload: clientID, username, password
            this._appendString(buf, this.clientID)
            this._appendString(buf, this.hostUsername)
            this._appendString(buf, this.hostPassword)
        })
    }
    _sendSubscribe(topic) {
        this._writePacket(PKT_SUBSCRIBE, (buf) => {
            buf.write(0x00); buf.write(0x01) // packet id
            this._appendString(buf, topic)
            buf.write(0x00) // QoS 0
        })
    }
    _sendUnsubscribe(topic) {
        this._writePacket(PKT_UNSUBSCRIBE, (buf) => {
            buf.write(0x00); buf.write(0x02) // packet id
            this._appendString(buf, topic)
        })
    }
    _sendPingReq() {
        this.outStream.write(PKT_PINGREQ)
        this.outStream.write(0x00)
        this.outStream.flush()
    }
    _sendDisconnect() {
        this.outStream.write(PKT_DISCONNECT)
        this.outStream.write(0x00)
        this.outStream.flush()
    }
    _waitForConnack() {
        const b0 = this.inStream.readByte() & 0xFF
        const b1 = this.inStream.readByte() & 0xFF // remaining length, always 2
        const b2 = this.inStream.readByte() & 0xFF // session present
        const b3 = this.inStream.readByte() & 0xFF // return code
        ChatLog(`CONNACK bytes: 0x${b0.toString(16)} 0x${b1.toString(16)} 0x${b2.toString(16)} 0x${b3.toString(16)}`)
        if ((b0 & 0xF0) !== PKT_CONNACK) {
            throw new Error(`Expected CONNACK (0x20), got: 0x${b0.toString(16)}`)
        }
        if (b3 !== 0) {
            throw new Error(`Broker refused: ${this._connackReason(b3)}`)
        }
    }
    _waitForSuback() {
        while (true) {
            const b0 = this.inStream.readByte() & 0xFF
            const packetType = b0 & 0xF0

            if (packetType === PKT_SUBACK) {
                const remaining = this._readRemainingLength()
                this.inStream.skipBytes(remaining)
                return
            } else if (packetType === PKT_PUBLISH) {
                // broker sent a message before SUBACK, handle it
                const remaining = this._readRemainingLength()
                this._handlePublish(remaining)
            } else {
                const remaining = this._readRemainingLength()
                this.inStream.skipBytes(remaining)
            }
        }
    }
    _waitForUnsuback() {
        const b0 = this.inStream.readByte() & 0xFF
        if ((b0 & 0xF0) !== PKT_UNSUBACK) {
            throw new Error(`Expected UNSUBACK, got: 0x${b0.toString(16)}`)
        }
        const remaining = this._readRemainingLength()
        this.inStream.skipBytes(remaining)
    }
    _handlePublish(remaining) {
        const topicLen = ((this.inStream.readByte() & 0xFF) << 8) | (this.inStream.readByte() & 0xFF)
        const topicBytes = JavaArray.newInstance(Byte.TYPE, topicLen)
        this.inStream.readFully(topicBytes)

        const payloadLen = remaining - 2 - topicLen
        const payloadBytes = JavaArray.newInstance(Byte.TYPE, payloadLen)
        this.inStream.readFully(payloadBytes)

        const topic = new JavaString(topicBytes, "UTF-8")
        const callback = this.topicCallbacks[topic]
        if (!callback) return

        try {
            const compressionType = this.compressionTypes[topic]
            let payload = payloadBytes

            if (compressionType?.includes("gzip")) {
                payload = gzipDecompress(payload)
            }
            if (compressionType?.includes("json")) {
                payload = JSON.parse(String(payload))
            }
            callback(payload)
        } catch (e) {
            ChatLog("Handler error:", e, e.stack)
        }
    }
    _appendString(buf, str) {
        const bytes = new JavaString(str).getBytes("UTF-8")
        buf.write((bytes.length >> 8) & 0xFF)
        buf.write(bytes.length & 0xFF)
        buf.write(bytes, 0, bytes.length)
    }
    _readRemainingLength() {
        let multiplier = 1, value = 0, digit
        do {
            digit = this.inStream.readByte()
            value += (digit & 0x7F) * multiplier
            multiplier *= 128
        } while ((digit & 0x80) !== 0)
        return value
    }
    _connackReason(code) {
        const reasons = {
            1: "Unacceptable protocol version",
            2: "Identifier rejected",
            3: "Server unavailable",
            4: "Bad username or password",
            5: "Not authorized",
        }
        return reasons[code] || `Unknown (0x${code.toString(16)})`
    }
}
