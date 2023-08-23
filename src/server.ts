import { WebSocketServer , WebSocket } from "ws";
import { Socket, createConnection } from "net";
import { C2S_HELLO, C2S_OPEN_TCPV4_CHANNEL, C2S_TRY_AUTH, DPX_CLOSE_CHANNEL, DPX_DATA, DPX_ERROR, DuplexCloseChannel, DuplexDataPacket, DuplexErrorPacket, getPacketNonce, logError, PROTOCOL_VERSION, readPacket, recvPacket as recvPacket, S2CAuthenticatedPacket, S2CHelloPacket, S2COpenTcpV4ChannelAck, sendError, sendPacket } from "./protocol";
import { SERVER_NAME, VERSION } from "./config";
import assert from "assert";
import { publicEncrypt, randomBytes, verify } from "crypto";
import { readFileSync }from "fs";
import { resolve } from "path";
import walk from "walk-sync";
import { logger } from "./logging";

const args = process.argv.slice(1);

if(args.length !== 3) {
    console.error(`Usage: ${args[0]} [port] [keys]`);
}

const keys = walk(args[2], { directories: false, })
    .map((path) => resolve(args[2], path))
    .map((path) => readFileSync(path));

class Channel {
    private readonly id: number;
    private readonly socket: Socket;
    private readonly channels: Map<number, Channel>;
    private readonly websocket: WebSocket;
    private isClosed: boolean;
    private isStarted: boolean;

    public constructor(id: number, socket: Socket, channels: Map<number, Channel>, websocket : WebSocket) {
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
            sendPacket(websocket, S2COpenTcpV4ChannelAck.create(id));
        });

        this.socket.on("data", (buffer) => {
            sendPacket(websocket, DuplexDataPacket.create(id, buffer));
        });
    }

    public readonly onData = (buffer: Buffer) => {
        this.socket.write(buffer);
    };

    public readonly started = () => this.isStarted && !this.isClosed;

    public readonly close = (send: boolean = true) => {
        if(this.isClosed) {
            return;
        }

        this.isClosed = true;
        this.channels.delete(this.id);
        this.socket.destroy();
        if(send) {
            sendPacket(this.websocket, DuplexCloseChannel.create(this.id));
        }
    };
}

class ConnectionInstance {
    private readonly socket : WebSocket;
    private readonly channels: Map<number, Channel>;
    private readonly token: Uint8Array;
    private nonce: number;

    private readonly validateStatusControl = (channelId: number, cb: (c: Channel) => void) => {
        if(!this.channels.has(channelId)) {
            sendPacket(this.socket, DuplexErrorPacket.create("packet", `attempting to control status of nonexistent channel ${channelId}`));
            return;
        }

        const chan = this.channels.get(channelId);
        assert(chan !== undefined);
        cb(chan);
    };

    public constructor(socket: WebSocket,  token: Uint8Array) {
        this.socket = socket;
        this.channels = new Map();
        this.token = token;
        this.nonce = 0;

        recvPacket(socket, (packet) => {
            if(packet.type == C2S_OPEN_TCPV4_CHANNEL) {
                if(this.channels.has(packet.getChannelId())) {
                    sendError(this.socket, "packet", `duplicate channel id ${packet.getChannelId()}`);
                }

                logger.debug(`attempted to connect to ${packet.getIp()}:${packet.getPort()}`);
                const socket = createConnection(packet.getPort(), packet.getIp());
                const channel = new Channel(packet.getChannelId(), socket, this.channels, this.socket);
                this.channels.set(packet.getChannelId(), channel);
            }
            else if(packet.type == DPX_DATA) {
                this.validateStatusControl(packet.getChannelId(), (channel) => {
                    if(!channel.started()) {
                        sendError(socket, "packet", "writing to channel that has not been open");
                        return;
                    }

                    channel.onData(packet.getData());
                });
            }
            else if(packet.type == DPX_CLOSE_CHANNEL) {
                this.validateStatusControl(packet.getChannelId(), (channel) => {
                    channel.close(false);
                    this.channels.delete(packet.getChannelId());
                });
            }
            else if(packet.type == DPX_ERROR) {
                logError(packet);
            }
            else {
                sendError(socket, "packet", `bad packet type: ${packet.type}`);
            }
        }, () => {
            logger.info(`${Buffer.from(this.token).toString("hex")} ${this.nonce}`);
            return getPacketNonce(this.token, this.nonce++);
        });
    }  

    public readonly close = () => {
    };

    public readonly forceClose = () => {
        this.channels.forEach((socket) => {
            socket.close();
        });

        this.socket.close();
    };
}

let socketId = 0;
const id2instance = new Map<number, ConnectionInstance>();

const server = new WebSocketServer({
    host: "0.0.0.0",
    port: parseInt(args[1]),
});

server.on("connection", (socket) => {
    const id = socketId++;

    socket.on("close", () => {
        logger.info(`client #${id} disconnected`);
        id2instance.delete(id);
    });

    socket.once("message", (message) => {
        assert(message instanceof Buffer);

        const packet = readPacket(message);
        if(packet.type != C2S_HELLO) {
            sendError(socket, "packet", "please be polite");
            return;
        }

        const clientKey = packet.getKey();
        const verifiable = randomBytes(32);
        sendPacket(socket, S2CHelloPacket.create(SERVER_NAME, VERSION, PROTOCOL_VERSION, verifiable));
        logger.info(`client ("${packet.getClientName()}" v${packet.getClientVersion()}) connected, assigned id #${id}`);

        socket.once("message", (message) => {
            assert(message instanceof Buffer);

            const packet = readPacket(message);
            if(packet.type != C2S_TRY_AUTH) {
                sendError(socket, "packet", "please authenticate before sending any packet");
                return;
            }

            const success = keys.reduce<boolean>((success, key) => 
                success || verify(undefined, verifiable, key, packet.getSignature()), false);

            if(!success) {
                sendError(socket, "auth", "failed to authenticate");
                return;
            }

            const token = randomBytes(32);
            logger.debug(`client ${id} is using token ${token.toString("hex")}`);
            id2instance.set(id, new ConnectionInstance(socket, token));
            sendPacket(socket, S2CAuthenticatedPacket.create(publicEncrypt(clientKey, token)));
        });
    });
});

server.on("listening", () => {
    logger.info(`server started on ${ parseInt(args[1])}`);
});

