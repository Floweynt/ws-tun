"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ipv4ToInt = exports.intToIpv4 = exports.recvPacket = exports.readPacket = exports.sendError = exports.logError = exports.sendPacket = exports.getPacketNonce = exports.DuplexDataPacket = exports.DuplexCloseChannel = exports.S2COpenTcpV4ChannelAck = exports.C2SOpenTcpV4Channel = exports.DuplexErrorPacket = exports.S2CAuthenticatedPacket = exports.C2STryAuthenticatePacket = exports.S2CHelloPacket = exports.C2SHelloPacket = exports.readString = exports.writeString = exports.DPX_DATA = exports.DPX_ERROR = exports.DPX_CLOSE_CHANNEL = exports.S2C_OPEN_TCPV4_CHANNEL_ACK = exports.C2S_OPEN_TCPV4_CHANNEL = exports.S2C_AUTH = exports.C2S_TRY_AUTH = exports.S2C_HELLO = exports.C2S_HELLO = exports.PROTOCOL_VERSION = exports.setToken = exports.server = exports.client = void 0;
const v8_1 = __importDefault(require("v8"));
const assert_1 = __importDefault(require("assert"));
const crypto_1 = __importDefault(require("crypto"));
const logging_1 = require("./logging");
// cursed hacks
let isClient = false;
let nonce = 0;
let token = null;
const client = () => isClient = true;
exports.client = client;
const server = () => isClient = false;
exports.server = server;
const setToken = (t) => token = t;
exports.setToken = setToken;
exports.PROTOCOL_VERSION = 1;
exports.C2S_HELLO = 0x00;
exports.S2C_HELLO = 0x01;
exports.C2S_TRY_AUTH = 0x02;
exports.S2C_AUTH = 0x03;
exports.C2S_OPEN_TCPV4_CHANNEL = 0x14;
exports.S2C_OPEN_TCPV4_CHANNEL_ACK = 0x15;
exports.DPX_CLOSE_CHANNEL = 0x16;
exports.DPX_ERROR = 0x17;
exports.DPX_DATA = 0x18;
const writeString = (buf, val) => {
    buf.writeUint32(val.length);
    buf.writeRawBytes(Buffer.from(val, "utf-8"));
};
exports.writeString = writeString;
const readString = (buf) => {
    const len = buf.readUint32();
    return buf.readRawBytes(len).toString("utf-8");
};
exports.readString = readString;
class C2SHelloPacket {
    constructor(clientName, clientVer, key) {
        this.type = exports.C2S_HELLO;
        this.getClientVersion = () => { return this.clientVer; };
        this.getClientName = () => { return this.clientName; };
        this.getKey = () => { return this.key; };
        this.read = (buf) => {
            this.clientName = (0, exports.readString)(buf);
            this.clientVer = (0, exports.readString)(buf);
            this.key = (0, exports.readString)(buf);
        };
        this.write = (buf) => {
            (0, exports.writeString)(buf, this.clientName);
            (0, exports.writeString)(buf, this.clientVer);
            (0, exports.writeString)(buf, this.key);
        };
        this.toString = () => `C2SHelloPacket { name = "${this.clientName}", version = "${this.clientVer}" }`;
        this.clientName = clientName;
        this.clientVer = clientVer;
        this.key = key;
    }
}
exports.C2SHelloPacket = C2SHelloPacket;
C2SHelloPacket.empty = () => new C2SHelloPacket("", "", "");
C2SHelloPacket.create = (clientName, clientVer, key) => new C2SHelloPacket(clientName, clientVer, key);
class S2CHelloPacket {
    constructor(serverName, serverVersion, protocolVersion, verifiable) {
        this.type = exports.S2C_HELLO;
        this.getServerName = () => { return this.serverName; };
        this.getServerVersion = () => { return this.serverVersion; };
        this.getProtocolVersion = () => { return this.protocolVersion; };
        this.getVerifiable = () => { return this.verifiable; };
        this.read = (buf) => {
            this.serverName = (0, exports.readString)(buf);
            this.serverVersion = (0, exports.readString)(buf);
            this.protocolVersion = buf.readUint32();
            this.verifiable = buf.readRawBytes(32);
        };
        this.write = (buf) => {
            (0, exports.writeString)(buf, this.serverName);
            (0, exports.writeString)(buf, this.serverVersion);
            buf.writeUint32(this.protocolVersion);
            buf.writeRawBytes(this.verifiable);
        };
        this.toString = () => `S2CHelloPacket { name = "${this.serverName}", version = "${this.serverVersion}, protocol_version = ${this.protocolVersion} }`;
        this.serverName = serverName;
        this.serverVersion = serverVersion;
        this.protocolVersion = protocolVersion;
        this.verifiable = verifiable;
        if (verifiable.length != 32) {
            throw Error("bad verifiable length");
        }
    }
}
exports.S2CHelloPacket = S2CHelloPacket;
S2CHelloPacket.empty = () => new S2CHelloPacket("", "", -1, new Uint8Array(32));
S2CHelloPacket.create = (serverName, serverVersion, protocolVersion, verifiable) => new S2CHelloPacket(serverName, serverVersion, protocolVersion, verifiable);
class C2STryAuthenticatePacket {
    constructor(signature) {
        this.type = exports.C2S_TRY_AUTH;
        this.getSignature = () => { return this.signature; };
        this.read = (buf) => {
            this.signature = buf.readRawBytes(buf.readUint32());
        };
        this.write = (buf) => {
            buf.writeUint32(this.signature.length);
            buf.writeRawBytes(this.signature);
        };
        this.toString = () => "C2STryAuthenticatePacket { ... }";
        this.signature = signature;
    }
}
exports.C2STryAuthenticatePacket = C2STryAuthenticatePacket;
C2STryAuthenticatePacket.empty = () => new C2STryAuthenticatePacket(Buffer.alloc(0));
C2STryAuthenticatePacket.create = (signature) => new C2STryAuthenticatePacket(signature);
class S2CAuthenticatedPacket {
    constructor(token) {
        this.type = exports.S2C_AUTH;
        this.getToken = () => { return this.token; };
        this.read = (buf) => {
            this.token = buf.readRawBytes(buf.readUint32());
        };
        this.write = (buf) => {
            buf.writeUint32(this.token.length);
            buf.writeRawBytes(this.token);
        };
        this.toString = () => "S2CAuthenticatedPacket { ... }";
        this.token = token;
    }
}
exports.S2CAuthenticatedPacket = S2CAuthenticatedPacket;
S2CAuthenticatedPacket.empty = () => new S2CAuthenticatedPacket(Buffer.alloc(0));
S2CAuthenticatedPacket.create = (token) => new S2CAuthenticatedPacket(token);
class DuplexErrorPacket {
    constructor(category, message) {
        this.type = exports.DPX_ERROR;
        this.getCategory = () => { return this.category; };
        this.getMessage = () => { return this.message; };
        this.read = (buf) => {
            this.category = (0, exports.readString)(buf);
            this.message = (0, exports.readString)(buf);
        };
        this.write = (buf) => {
            (0, exports.writeString)(buf, this.category);
            (0, exports.writeString)(buf, this.message);
        };
        this.toString = () => `DuplexErrorPacket(${this.category}) { message = "${this.message}" }`;
        this.category = category;
        this.message = message;
    }
}
exports.DuplexErrorPacket = DuplexErrorPacket;
DuplexErrorPacket.empty = () => new DuplexErrorPacket("ok", "");
DuplexErrorPacket.create = (category, message) => new DuplexErrorPacket(category, message);
class C2SOpenTcpV4Channel {
    constructor(channelId, ip, port) {
        this.type = exports.C2S_OPEN_TCPV4_CHANNEL;
        this.getChannelId = () => { return this.channelId; };
        this.getIp = () => { return (0, exports.intToIpv4)(this.ip); };
        this.getPort = () => { return this.port; };
        this.read = (buf) => {
            this.channelId = buf.readUint32();
            this.ip = buf.readUint32();
            this.port = buf.readUint32();
        };
        this.write = (buf) => {
            buf.writeUint32(this.channelId);
            buf.writeUint32(this.ip);
            buf.writeUint32(this.port);
        };
        this.toString = () => `C2SOpenTcpV4Channel(${this.channelId}) { target = ${this.getIp()}:${this.port} }`;
        this.channelId = channelId;
        this.ip = ip;
        this.port = port;
    }
}
exports.C2SOpenTcpV4Channel = C2SOpenTcpV4Channel;
C2SOpenTcpV4Channel.empty = () => new C2SOpenTcpV4Channel(-1, 0, 0);
C2SOpenTcpV4Channel.create = (channelId, ip, port) => new C2SOpenTcpV4Channel(channelId, typeof ip === "number" ? ip : (0, exports.ipv4ToInt)(ip), port);
class S2COpenTcpV4ChannelAck {
    constructor(channelId) {
        this.type = exports.S2C_OPEN_TCPV4_CHANNEL_ACK;
        this.getChannelId = () => { return this.channelId; };
        this.read = (buf) => {
            this.channelId = buf.readUint32();
        };
        this.write = (buf) => {
            buf.writeUint32(this.channelId);
        };
        this.toString = () => `S2COpenTcpV4ChannelAck(${this.channelId}) { }`;
        this.channelId = channelId;
    }
}
exports.S2COpenTcpV4ChannelAck = S2COpenTcpV4ChannelAck;
S2COpenTcpV4ChannelAck.empty = () => new S2COpenTcpV4ChannelAck(-1);
S2COpenTcpV4ChannelAck.create = (channelId) => new S2COpenTcpV4ChannelAck(channelId);
class DuplexCloseChannel {
    constructor(channelId) {
        this.type = exports.DPX_CLOSE_CHANNEL;
        this.getChannelId = () => { return this.channelId; };
        this.read = (buf) => {
            this.channelId = buf.readUint32();
        };
        this.write = (buf) => {
            buf.writeUint32(this.channelId);
        };
        this.toString = () => `DuplexCloseChannel(${this.channelId}) { }`;
        this.channelId = channelId;
    }
}
exports.DuplexCloseChannel = DuplexCloseChannel;
DuplexCloseChannel.empty = () => new DuplexCloseChannel(-1);
DuplexCloseChannel.create = (channelId) => new DuplexCloseChannel(channelId);
class DuplexDataPacket {
    constructor(channelId, data) {
        this.type = exports.DPX_DATA;
        this.getChannelId = () => { return this.channelId; };
        this.getData = () => { return this.data; };
        this.read = (buf) => {
            this.channelId = buf.readUint32();
            this.data = buf.readRawBytes(buf.readUint32());
        };
        this.write = (buf) => {
            buf.writeUint32(this.channelId);
            buf.writeUint32(this.data.length);
            buf.writeRawBytes(this.data);
        };
        this.toString = () => `DuplexDataPacket(${this.channelId}) { data = <buffer, size = ${this.data.length}> }`;
        this.channelId = channelId;
        this.data = data;
    }
}
exports.DuplexDataPacket = DuplexDataPacket;
DuplexDataPacket.empty = () => new DuplexDataPacket(-1, Buffer.alloc(0));
DuplexDataPacket.create = (channelId, data) => new DuplexDataPacket(channelId, data);
const ID_TO_CONSTRUCTOR = {
    [exports.C2S_HELLO]: C2SHelloPacket.empty,
    [exports.S2C_HELLO]: S2CHelloPacket.empty,
    [exports.DPX_ERROR]: DuplexErrorPacket.empty,
    [exports.C2S_OPEN_TCPV4_CHANNEL]: C2SOpenTcpV4Channel.empty,
    [exports.S2C_OPEN_TCPV4_CHANNEL_ACK]: S2COpenTcpV4ChannelAck.empty,
    [exports.DPX_DATA]: DuplexDataPacket.empty,
    [exports.DPX_CLOSE_CHANNEL]: DuplexCloseChannel.empty,
    [exports.C2S_TRY_AUTH]: C2STryAuthenticatePacket.empty,
    [exports.S2C_AUTH]: S2CAuthenticatedPacket.empty,
};
const getPacketNonce = (token, nonce) => {
    const tempBuffer = Buffer.alloc(4);
    tempBuffer.writeUint32LE(nonce);
    return crypto_1.default.createHash("sha256").update(Buffer.concat([token, tempBuffer])).digest();
};
exports.getPacketNonce = getPacketNonce;
const writePacket = (packet) => {
    const serializer = new v8_1.default.Serializer();
    // write id
    const tempBuffer = Buffer.alloc(1);
    tempBuffer.writeUint8(packet.type);
    serializer.writeRawBytes(tempBuffer);
    if (isClient && token) {
        const currentNonce = nonce++;
        const packetNonce = (0, exports.getPacketNonce)(token, currentNonce);
        serializer.writeRawBytes(packetNonce);
    }
    packet.write(serializer);
    return serializer.releaseBuffer();
};
const sendPacket = (ws, packet) => {
    logging_1.logger.debug(`send packet ${packet.toString()}`);
    ws.send(writePacket(packet), {
        binary: true,
    });
};
exports.sendPacket = sendPacket;
const logError = (packet) => {
    logging_1.logger.error(`(${packet.getCategory()}): ${packet.getMessage()}`);
};
exports.logError = logError;
const sendError = (ws, category, message) => {
    logging_1.logger.error(`(${category}): ${message}`);
    (0, exports.sendPacket)(ws, DuplexErrorPacket.create(category, message));
};
exports.sendError = sendError;
const readPacket = (buf) => {
    const id = buf.readUint8();
    if (!ID_TO_CONSTRUCTOR[id]) {
        throw Error(`failed to create packet with type = ${id}`);
    }
    const packet = ID_TO_CONSTRUCTOR[id]();
    packet.read(new v8_1.default.Deserializer(buf.subarray(1)));
    return packet;
};
exports.readPacket = readPacket;
const recvPacket = (ws, handler, getExpectedNonce) => {
    ws.on("message", (message) => {
        (0, assert_1.default)(message instanceof Buffer);
        const id = message.readUint8();
        if (!ID_TO_CONSTRUCTOR[id]) {
            throw Error(`failed to create packet with type = ${id}`);
        }
        let packetBuf = message.subarray(1);
        if (getExpectedNonce) {
            const digest = packetBuf.subarray(0, 32);
            const expectedNonce = getExpectedNonce();
            if (!digest.equals(expectedNonce)) {
                (0, exports.sendError)(ws, "token", "bad nonce");
                return;
            }
            packetBuf = packetBuf.subarray(32);
        }
        const packet = ID_TO_CONSTRUCTOR[id]();
        packet.read(new v8_1.default.Deserializer(packetBuf));
        logging_1.logger.debug(`recv packet ${packet.toString()}`);
        handler(packet);
    });
};
exports.recvPacket = recvPacket;
const intToIpv4 = (ip) => `${ip >>> 24}.${ip >> 16 & 255}.${ip >> 8 & 255}.${ip & 255}`;
exports.intToIpv4 = intToIpv4;
const ipv4ToInt = (ip) => ip.split(".").reduce((val, octet) => (val << 8) + parseInt(octet, 10), 0) >>> 0;
exports.ipv4ToInt = ipv4ToInt;
