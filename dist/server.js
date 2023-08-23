"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ws_1 = require("ws");
const net_1 = require("net");
const protocol_1 = require("./protocol");
const config_1 = require("./config");
const assert_1 = __importDefault(require("assert"));
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const path_1 = require("path");
const walk_sync_1 = __importDefault(require("walk-sync"));
const logging_1 = require("./logging");
const args = process.argv.slice(1);
if (args.length !== 3) {
    console.error(`Usage: ${args[0]} [port] [keys]`);
}
const keys = (0, walk_sync_1.default)(args[2], { directories: false, })
    .map((path) => (0, path_1.resolve)(args[2], path))
    .map((path) => (0, fs_1.readFileSync)(path));
class Channel {
    constructor(id, socket, channels, websocket) {
        this.onData = (buffer) => {
            this.socket.write(buffer);
        };
        this.started = () => this.isStarted && !this.isClosed;
        this.close = (send = true) => {
            if (this.isClosed) {
                return;
            }
            this.isClosed = true;
            this.channels.delete(this.id);
            this.socket.destroy();
            if (send) {
                (0, protocol_1.sendPacket)(this.websocket, protocol_1.DuplexCloseChannel.create(this.id));
            }
        };
        this.id = id;
        this.socket = socket;
        this.channels = channels;
        this.websocket = websocket;
        this.isClosed = false;
        this.isStarted = false;
        this.socket.on("error", () => {
            this.close();
        });
        this.socket.on("close", () => {
            this.close();
        });
        this.socket.on("connect", () => {
            this.isStarted = true;
            (0, protocol_1.sendPacket)(websocket, protocol_1.S2COpenTcpV4ChannelAck.create(id));
        });
        this.socket.on("data", (buffer) => {
            (0, protocol_1.sendPacket)(websocket, protocol_1.DuplexDataPacket.create(id, buffer));
        });
    }
}
class ConnectionInstance {
    constructor(socket, token) {
        this.validateStatusControl = (channelId, cb) => {
            if (!this.channels.has(channelId)) {
                (0, protocol_1.sendPacket)(this.socket, protocol_1.DuplexErrorPacket.create("packet", `attempting to control status of nonexistent channel ${channelId}`));
                return;
            }
            const chan = this.channels.get(channelId);
            (0, assert_1.default)(chan !== undefined);
            cb(chan);
        };
        this.close = () => {
        };
        this.forceClose = () => {
            this.channels.forEach((socket) => {
                socket.close();
            });
            this.socket.close();
        };
        this.socket = socket;
        this.channels = new Map();
        this.token = token;
        this.nonce = 0;
        (0, protocol_1.recvPacket)(socket, (packet) => {
            if (packet.type == protocol_1.C2S_OPEN_TCPV4_CHANNEL) {
                if (this.channels.has(packet.getChannelId())) {
                    (0, protocol_1.sendError)(this.socket, "packet", `duplicate channel id ${packet.getChannelId()}`);
                }
                logging_1.logger.debug(`attempted to connect to ${packet.getIp()}:${packet.getPort()}`);
                const socket = (0, net_1.createConnection)(packet.getPort(), packet.getIp());
                const channel = new Channel(packet.getChannelId(), socket, this.channels, this.socket);
                this.channels.set(packet.getChannelId(), channel);
            }
            else if (packet.type == protocol_1.DPX_DATA) {
                this.validateStatusControl(packet.getChannelId(), (channel) => {
                    if (!channel.started()) {
                        (0, protocol_1.sendError)(socket, "packet", "writing to channel that has not been open");
                        return;
                    }
                    channel.onData(packet.getData());
                });
            }
            else if (packet.type == protocol_1.DPX_CLOSE_CHANNEL) {
                this.validateStatusControl(packet.getChannelId(), (channel) => {
                    channel.close(false);
                    this.channels.delete(packet.getChannelId());
                });
            }
            else if (packet.type == protocol_1.DPX_ERROR) {
                (0, protocol_1.logError)(packet);
            }
            else {
                (0, protocol_1.sendError)(socket, "packet", `bad packet type: ${packet.type}`);
            }
        }, () => {
            logging_1.logger.info(`${Buffer.from(this.token).toString("hex")} ${this.nonce}`);
            return (0, protocol_1.getPacketNonce)(this.token, this.nonce++);
        });
    }
}
let socketId = 0;
const id2instance = new Map();
const server = new ws_1.WebSocketServer({
    host: "0.0.0.0",
    port: parseInt(args[1]),
});
server.on("connection", (socket) => {
    const id = socketId++;
    socket.on("close", () => {
        logging_1.logger.info(`client #${id} disconnected`);
        id2instance.delete(id);
    });
    socket.once("message", (message) => {
        (0, assert_1.default)(message instanceof Buffer);
        const packet = (0, protocol_1.readPacket)(message);
        if (packet.type != protocol_1.C2S_HELLO) {
            (0, protocol_1.sendError)(socket, "packet", "please be polite");
            return;
        }
        const clientKey = packet.getKey();
        const verifiable = (0, crypto_1.randomBytes)(32);
        (0, protocol_1.sendPacket)(socket, protocol_1.S2CHelloPacket.create(config_1.SERVER_NAME, config_1.VERSION, protocol_1.PROTOCOL_VERSION, verifiable));
        logging_1.logger.info(`client ("${packet.getClientName()}" v${packet.getClientVersion()}) connected, assigned id #${id}`);
        socket.once("message", (message) => {
            (0, assert_1.default)(message instanceof Buffer);
            const packet = (0, protocol_1.readPacket)(message);
            if (packet.type != protocol_1.C2S_TRY_AUTH) {
                (0, protocol_1.sendError)(socket, "packet", "please authenticate before sending any packet");
                return;
            }
            const success = keys.reduce((success, key) => success || (0, crypto_1.verify)(undefined, verifiable, key, packet.getSignature()), false);
            if (!success) {
                (0, protocol_1.sendError)(socket, "auth", "failed to authenticate");
                return;
            }
            const token = (0, crypto_1.randomBytes)(32);
            logging_1.logger.debug(`client ${id} is using token ${token.toString("hex")}`);
            id2instance.set(id, new ConnectionInstance(socket, token));
            (0, protocol_1.sendPacket)(socket, protocol_1.S2CAuthenticatedPacket.create((0, crypto_1.publicEncrypt)(clientKey, token)));
        });
    });
});
server.on("listening", () => {
    logging_1.logger.info(`server started on ${parseInt(args[1])}`);
});
