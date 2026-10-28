const JavaString = Java.type("java.lang.String")

const KEEPALIVE_MS = 30_000
const RECONNECT_MS = 5_000
const PUBACK_TIMEOUT_MS = 10_000

// MQTT packets
const PKT_CONNECT = 0x10
const PKT_CONNACK = 0x20
const PKT_PUBLISH_QOS1 = 0x32
const PKT_PUBACK = 0x40
const PKT_PINGREQ = 0xC0
const PKT_PINGRESP = 0xD0
const PKT_DISCONNECT = 0xE0

const ConsoleLog = (...strings) => console.log("§6[MQTT] §r" + strings.join(" | "))

const gzipCompress = (byteArray) => {
    const out = new ByteArrayOutputStream()
    const gz = new GZIPOutputStream(out)
    gz.write(byteArray, 0, byteArray.length)
    gz.close()
    return out.toByteArray()
}

export class MQTTPublisher {
    constructor(
        hostURL,
        hostPort,
        hostUsername,
        hostPassword,
        certPaths = [],
        clientID = null,
    ) {
        this.hostURL = hostURL
        this.hostPort = hostPort
        this.hostUsername = hostUsername
        this.hostPassword = hostPassword
        this.clientID = clientID ?? `ct-publisher-${System.getProperty("user.name")}`
        this.certPaths = certPaths

        this.socket = null
        this.outStream = null
        this.inStream = null
        this.connected = false
        this.running = false
        this.reconnecting = false
        this.pingOutstanding = false

        this.nextPacketID = 1
        this.pendingAcks = {}
        this.executor = null

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
        this.executor = Executors.newSingleThreadExecutor()
        this._startConnectThread()
    }
    stop() {
        this.running = false
        this._disconnect()
        if (this.executor) {
            this.executor.shutdownNow()
            this.executor = null
        }
    }
    publish(topic, data, compressionType = "") {
        if (!topic) return
        if (!this.connected || !this.executor) {
            ConsoleLog(`Not connected - publish dropped on "${topic}"`)
            return
        }

        this.executor.execute(() => {
            try {
                let payload = this._toBytes(data)
                if (compressionType?.includes("gzip")) {
                    payload = gzipCompress(payload)
                }
                this._sendPublish(topic, payload)
            } catch (e) {
                ConsoleLog(`Publish failed on "${topic}":`, e, e.stack)
                this._scheduleReconnect()
            }
        })
    }

    _toBytes(data) {
        const str = typeof data === "string" ? data : JSON.stringify(data)
        return new JavaString(str).getBytes("UTF-8")
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
            ConsoleLog(`Connecting to ${this.hostURL}:${this.hostPort}`)

            const factory = this._buildSSLSocketFactory()
            this.socket = factory.createSocket(this.hostURL, this.hostPort)
            this.socket.setSoTimeout(0)
            this.socket.setTcpNoDelay(true)

            this.inStream = new DataInputStream(this.socket.getInputStream())
            this.outStream = new DataOutputStream(this.socket.getOutputStream())

            this._sendConnect()
            this._waitForConnack()

            this.connected = true
            this.reconnecting = false
            this.pingOutstanding = false
            this.pendingAcks = {}
            ConsoleLog("Connected.")

            this._startPingThread()
            this._readLoop()

        } catch (e) {
            ConsoleLog("Connection failed:", e, e.stack)
            this._scheduleReconnect()
        }
    }
    _scheduleReconnect() {
        if (this.reconnecting) return
        this.connected = false
        this._closeSocket()
        if (!this.running) return
        this.reconnecting = true
        ConsoleLog(`Reconnecting in ${RECONNECT_MS / 1000}s...`)
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
            ConsoleLog("Disconnect failed:", e, e.stack)
        }
        this._closeSocket()
    }
    _closeSocket() {
        try {
            if (this.socket) {
                this.socket.close()
            }
        } catch (e) {
            ConsoleLog("Socket close failed:", e, e.stack)
        }
    }
    _readLoop() {
        try {
            while (this.running && this.connected) {
                const packetType = this.inStream.readByte() & 0xF0
                const remaining = this._readRemainingLength()

                if (packetType === PKT_PUBACK) {
                    this._handlePuback(remaining)
                } else if (packetType === PKT_PINGRESP) {
                    this.pingOutstanding = false
                } else {
                    this.inStream.skipBytes(remaining)
                }
            }
        } catch (e) {
            if (this.running) {
                ConsoleLog("Read error:", e, e.stack)
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
                    if (this.pingOutstanding) {
                        throw new Error("no PINGRESP received")
                    }
                    this._sendPingReq()
                    this.pingOutstanding = true
                    this._checkStaleAcks()
                } catch (e) {
                    ConsoleLog("Ping failed:", e, e.stack)
                    this._scheduleReconnect()
                    break
                }
            }
        }).start()
    }
    _checkStaleAcks() {
        const now = Date.now()
        Object.keys(this.pendingAcks).forEach((id) => {
            const { topic, sentAt } = this.pendingAcks[id]
            if (now - sentAt > PUBACK_TIMEOUT_MS) {
                ConsoleLog(`No PUBACK for "${topic}" (id ${id})`)
                delete this.pendingAcks[id]
            }
        })
    }
    _writePacket(firstByte, bodyFn) {
        const buf = new ByteArrayOutputStream()
        bodyFn(buf)
        const body = buf.toByteArray()

        const packet = new ByteArrayOutputStream()
        packet.write(firstByte)

        let len = body.length
        do {
            let digit = len % 128
            len = Math.floor(len / 128)
            if (len > 0) digit |= 0x80
            packet.write(digit)
        } while (len > 0)

        packet.write(body, 0, body.length)

        const bytes = packet.toByteArray()
        this.outStream.write(bytes, 0, bytes.length)
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
            // Connect flags: clean session + username + password
            buf.write(0xC2)
            // Keepalive
            buf.write((keepaliveSec >> 8) & 0xFF)
            buf.write(keepaliveSec & 0xFF)
            // Payload: clientID, username, password
            this._appendString(buf, this.clientID)
            this._appendString(buf, this.hostUsername)
            this._appendString(buf, this.hostPassword)
        })
    }
    _sendPublish(topic, payloadBytes) {
        const packetID = this._nextPacketID()
        this.pendingAcks[packetID] = { topic, sentAt: Date.now() }

        this._writePacket(PKT_PUBLISH_QOS1, (buf) => {
            this._appendString(buf, topic)
            buf.write((packetID >> 8) & 0xFF)
            buf.write(packetID & 0xFF)
            buf.write(payloadBytes, 0, payloadBytes.length)
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
        const b1 = this.inStream.readByte() & 0xFF
        const b2 = this.inStream.readByte() & 0xFF
        const b3 = this.inStream.readByte() & 0xFF
        if ((b0 & 0xF0) !== PKT_CONNACK) {
            throw new Error(`Expected CONNACK (0x20), got: 0x${b0.toString(16)}`)
        }
        if (b3 !== 0) {
            throw new Error(`Broker refused: ${this._connackReason(b3)}`)
        }
    }
    _handlePuback(remaining) {
        const packetID = ((this.inStream.readByte() & 0xFF) << 8) | (this.inStream.readByte() & 0xFF)
        this.inStream.skipBytes(remaining - 2)
        delete this.pendingAcks[packetID]
    }
    _nextPacketID() {
        this.nextPacketID = (this.nextPacketID % 0xFFFF) + 1
        return this.nextPacketID
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
