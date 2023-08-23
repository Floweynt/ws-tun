"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ws_1 = require("ws");
const config_1 = require("./config");
const protocol_1 = require("./protocol");
const assert_1 = __importDefault(require("assert"));
const net_1 = require("net");
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const logging_1 = require("./logging");
const sockopt_1 = require("./sockopt");
const args = process.argv.slice(1);
if (args.length !== 3) {
    console.error(`Usage: ${args[0]} [url] [key]`);
}
// generate keys
const { publicKey, privateKey, } = (0, crypto_1.generateKeyPairSync)("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: "spki",
        format: "pem",
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
    },
});
const websocket = new ws_1.WebSocket(args[1]);
class Channel {
    constructor(id, socket) {
        this.onWebsocketData = (data) => {
            if (!this.isStarted)
                return;
            this.socket.write(data);
        };
        this.start = () => {
            if (this.isStarted)
                return;
            this.isStarted = true;
            this.socket.on("data", (data) => {
                (0, protocol_1.sendPacket)(websocket, protocol_1.DuplexDataPacket.create(this.id, data));
            });
            this.socket.on("close", () => {
                this.close();
            });
        };
        this.close = (send = true) => {
            if (this.isClosed) {
                return;
            }
            this.isClosed = true;
            this.socket.destroy();
            if (send) {
                (0, protocol_1.sendPacket)(websocket, protocol_1.DuplexCloseChannel.create(this.id));
            }
        };
        this.started = () => this.isStarted && !this.isClosed;
        this.id = id;
        this.socket = socket;
        this.isStarted = false;
        this.isClosed = false;
    }
}
let channelId = 0;
const channels = new Map();
const validateStatusControl = (channelId, cb) => {
    if (!channels.has(channelId)) {
        (0, protocol_1.sendPacket)(websocket, protocol_1.DuplexErrorPacket.create("packet", `attempting to control status of nonexistent channel ${channelId}`));
        return;
    }
    const chan = channels.get(channelId);
    (0, assert_1.default)(chan !== undefined);
    cb(chan);
};
const run = () => {
    const server = (0, net_1.createServer)();
    server.on("connection", (socket) => {
        const [realTargetIp, realTargetPort] = (0, sockopt_1.getOriginalDest)(socket);
        const id = channelId++;
        (0, protocol_1.sendPacket)(websocket, protocol_1.C2SOpenTcpV4Channel.create(id, realTargetIp, realTargetPort));
        channels.set(id, new Channel(id, socket));
    });
    server.listen(config_1.CLIENT_SERVER_PORT, "0.0.0.0", () => {
        logging_1.logger.info(`internal server started on 0.0.0.0:${config_1.CLIENT_SERVER_PORT}`);
    });
    (0, protocol_1.recvPacket)(websocket, (packet) => {
        if (packet.type == protocol_1.S2C_OPEN_TCPV4_CHANNEL_ACK) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                if (channel.started()) {
                    (0, protocol_1.sendError)(websocket, "packet", "attempting to open an already open channel");
                    return;
                }
                channel.start();
            });
        }
        else if (packet.type == protocol_1.DPX_DATA) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                if (!channel.started()) {
                    (0, protocol_1.sendError)(websocket, "packet", "writing to channel that has not been open");
                    channel.start();
                }
                channel.onWebsocketData(packet.getData());
            });
        }
        else if (packet.type == protocol_1.DPX_CLOSE_CHANNEL) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                channel.close(false);
                channels.delete(packet.getChannelId());
            });
        }
        else if (packet.type == protocol_1.DPX_ERROR) {
            (0, protocol_1.logError)(packet);
        }
        else {
            (0, protocol_1.sendError)(websocket, "packet", `bad packet type: ${packet.type}`);
        }
    });
};
const key = (0, fs_1.readFileSync)(args[2], "utf-8");
websocket.on("open", () => {
    (0, protocol_1.sendPacket)(websocket, protocol_1.C2SHelloPacket.create(config_1.CLIENT_NAME, config_1.VERSION, publicKey));
    websocket.once("message", (message) => {
        (0, assert_1.default)(message instanceof Buffer);
        const packet = (0, protocol_1.readPacket)(message);
        if (packet.type != protocol_1.S2C_HELLO) {
            logging_1.logger.error("protocol error: expected S2CHelloPacket");
            process.exit(-1);
        }
        logging_1.logger.info(`connected to server: "${packet.getServerName()}" v${packet.getServerVersion()}`);
        logging_1.logger.info(`running protocol version ${packet.getProtocolVersion()}`);
        if (packet.getProtocolVersion() != protocol_1.PROTOCOL_VERSION) {
            logging_1.logger.error(`protocol error: protocol mismatch: server wants ${packet.getProtocolVersion()}, but I support ${protocol_1.PROTOCOL_VERSION}`);
            process.exit(-1);
        }
        (0, protocol_1.sendPacket)(websocket, protocol_1.C2STryAuthenticatePacket.create((0, crypto_1.sign)(undefined, packet.getVerifiable(), key)));
        websocket.once("message", (message) => {
            (0, assert_1.default)(message instanceof Buffer);
            const packet = (0, protocol_1.readPacket)(message);
            if (packet.type == protocol_1.S2C_AUTH) {
                const token = (0, crypto_1.privateDecrypt)(privateKey, packet.getToken());
                (0, protocol_1.client)();
                (0, protocol_1.setToken)(token);
                logging_1.logger.debug(`token = ${token.toString("hex")}`);
                run();
            }
            else if (packet.type == protocol_1.DPX_ERROR) {
                logging_1.logger.error("failed to authenticate");
                process.exit(-1);
            }
            else {
                logging_1.logger.error("protocol error: expected S2CAuthenticatedPacket or DuplexErrorPacket");
                process.exit(-1);
            }
        });
    });
});
