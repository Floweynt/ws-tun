import { WebSocket } from "ws";
import { CLIENT_NAME, CLIENT_SERVER_PORT, VERSION } from "./config";
import { C2SHelloPacket, C2SOpenTcpV4Channel, C2STryAuthenticatePacket, client, DPX_CLOSE_CHANNEL, DPX_DATA, DPX_ERROR, DuplexCloseChannel, DuplexDataPacket, DuplexErrorPacket, logError, Packet, PROTOCOL_VERSION, readPacket, recvPacket, S2C_AUTH, S2C_HELLO, S2C_OPEN_TCPV4_CHANNEL_ACK, sendError, sendPacket, setToken } from "./protocol";
import assert from "assert";
import { Socket, createServer } from "net";
import { generateKeyPairSync, privateDecrypt, sign } from "crypto";
import { readFileSync } from "fs";
import { logger } from "./logging";
import { getOriginalDest } from "./sockopt";

const args = process.argv.slice(1);

if(args.length !== 3) {
    console.error(`Usage: ${args[0]} [url] [key]`);
}

// generate keys

const { publicKey, privateKey, } = generateKeyPairSync("rsa", {
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

const websocket = new WebSocket(args[1]);

class Channel {
    private readonly socket: Socket;
    private readonly id: number;
    private isStarted: boolean;
    private isClosed: boolean;

    public constructor(id: number, socket: Socket) {
        this.id = id;
        this.socket = socket;
        this.isStarted = false;
        this.isClosed = false;
    }

    public readonly onWebsocketData = (data: Buffer) => {
        if(!this.isStarted)
            return;
        this.socket.write(data);
    };

    public readonly start = () => {
        if(this.isStarted)
            return;
        this.isStarted = true;

        this.socket.on("data", (data: Buffer) => {
            sendPacket(websocket, DuplexDataPacket.create(this.id, data));
        });

        this.socket.on("close", () => {
            this.close();
        });
    };

    public readonly close = (send: boolean = true) => {
        if(this.isClosed) {
            return;
        }

        this.isClosed = true;
        this.socket.destroy();
        if(send) {
            sendPacket(websocket, DuplexCloseChannel.create(this.id));
        }
    };

    public readonly started = () => this.isStarted && !this.isClosed;
}

let channelId = 0;
const channels = new Map<number, Channel>();

const validateStatusControl = (channelId: number, cb: (c: Channel) => void) => {
    if(!channels.has(channelId)) {
        sendPacket(websocket, DuplexErrorPacket.create("packet", `attempting to control status of nonexistent channel ${channelId}`));
        return;
    }

    const chan = channels.get(channelId);
    assert(chan !== undefined);
    cb(chan);
};

const run = () => {
    const server = createServer();

    server.on("connection", (socket: Socket) => {
        const [realTargetIp, realTargetPort] = getOriginalDest(socket);
        const id = channelId++;
        sendPacket(websocket, C2SOpenTcpV4Channel.create(id, realTargetIp, realTargetPort));
        channels.set(id, new Channel(id, socket));
    });

    server.listen(CLIENT_SERVER_PORT, "0.0.0.0", () => {
        logger.info(`internal server started on 0.0.0.0:${CLIENT_SERVER_PORT}`);
    });

    recvPacket(websocket, (packet: Packet) => {
        if(packet.type == S2C_OPEN_TCPV4_CHANNEL_ACK) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                if(channel.started()) {
                    sendError(websocket, "packet", "attempting to open an already open channel");
                    return;
                }

                channel.start();
            });
        }
        else if(packet.type == DPX_DATA) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                if(!channel.started()) {
                    sendError(websocket, "packet", "writing to channel that has not been open");
                    channel.start();
                }

                channel.onWebsocketData(packet.getData());
            });
        }
        else if(packet.type == DPX_CLOSE_CHANNEL) {
            validateStatusControl(packet.getChannelId(), (channel) => {
                channel.close(false);
                channels.delete(packet.getChannelId());
            });
        }
        else if(packet.type == DPX_ERROR) {
            logError(packet);
        }
        else {
            sendError(websocket, "packet", `bad packet type: ${packet.type}`);
        }
    });
};

const key = readFileSync(args[2], "utf-8");

websocket.on("open", () => {
    sendPacket(websocket, C2SHelloPacket.create(CLIENT_NAME, VERSION, publicKey));
    
    websocket.once("message", (message) => {
        assert(message instanceof Buffer);

        const packet = readPacket(message);

        if(packet.type != S2C_HELLO) {
            logger.error("protocol error: expected S2CHelloPacket");
            process.exit(-1);
        }

        logger.info(`connected to server: "${packet.getServerName()}" v${packet.getServerVersion()}`);
        logger.info(`running protocol version ${packet.getProtocolVersion()}`);

        if(packet.getProtocolVersion() != PROTOCOL_VERSION) {
            logger.error(`protocol error: protocol mismatch: server wants ${packet.getProtocolVersion()}, but I support ${PROTOCOL_VERSION}`);
            process.exit(-1);
        }

        sendPacket(websocket, C2STryAuthenticatePacket.create(sign(undefined, packet.getVerifiable(), key)));

        websocket.once("message", (message) => {
            assert(message instanceof Buffer);

            const packet = readPacket(message);

            if(packet.type == S2C_AUTH) {
                const token = privateDecrypt(privateKey, packet.getToken());
                client();
                setToken(token);
                logger.debug(`token = ${token.toString("hex")}`);
                run();
            }
            else if(packet.type == DPX_ERROR) {
                logger.error("failed to authenticate");
                process.exit(-1);
            }
            else {
                logger.error("protocol error: expected S2CAuthenticatedPacket or DuplexErrorPacket");
                process.exit(-1);
            }
        });
    });
});

