import commandLineArgs from "command-line-args";
import { expectArgument, setLogLevel } from "./args";

const options = commandLineArgs([
    { name: "verbose", type: String, defaultValue: "info", },
    { name: "keys", alias: "k", type: String, },
    { name: "port", alias: "p", type: Number, defaultValue: 8000, },
    { name: "host", alias: "h", type: String, defaultValue: "0.0.0.0", }
]);

const port = options["port"];
const host = options["host"];
const keyDir = options["keys"];
const verbosity = options["verbose"];

expectArgument("missing required argument 'keys'", keyDir);

if(["info", "debug0", "debug1", "debug2", "debug3"].find((x) => x == verbosity) == undefined) {
    console.error(`verbosity should be info or debug0-3, but got ${verbosity}`);
    process.exit(-1);
}

setLogLevel(verbosity == "info" ? undefined : verbosity as "debug0" | "debug1" | "debug2" | "debug3");

import { logger } from "./logging";
import { WebSocketServer , WebSocket, OPEN } from "ws";
import { Socket, createConnection } from "net";
import { C2S_HELLO, C2S_OPEN_TCPV4_CHANNEL, C2S_TRY_AUTH, DPX_CLOSE_CHANNEL, DPX_DATA, DPX_ERROR, DuplexCloseChannel, DuplexDataPacket, 
    getPacketNonce, logError, Packet, PacketNonce, PROTOCOL_VERSION, readPacket, readPacketNonce, S2CAuthenticatedPacket, S2CHelloPacket, 
    S2COpenTcpV4ChannelAck, sendError, writePacket } from "./protocol";
import { SERVER_NAME, VERSION } from "./config";
import assert from "assert";
import { publicEncrypt, randomBytes, verify } from "crypto";
import { readFileSync }from "fs";
import { resolve } from "path";
import walk from "walk-sync";
import * as errors from "./errors";

const keys = walk(keyDir, { directories: false, })
    .map((path) => resolve(keyDir, path))
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
            writePacket(websocket, S2COpenTcpV4ChannelAck.create(id));
        });

        this.socket.on("data", (buffer) => {
            writePacket(websocket, DuplexDataPacket.create(id, buffer));
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
            writePacket(this.websocket, DuplexCloseChannel.create(this.id));
        }
    };
}

class ConnectionInstance {
    private readonly socket : WebSocket;
    private readonly channels: Map<number, Channel>;
    private readonly token: Uint8Array;
    private currentId: number;

    private readonly validateChannel = (channelId: number, cb: (c: Channel) => void) => {
        if(!this.channels.has(channelId)) {
            sendError(this.socket, errors.badChannel(channelId));
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
        this.currentId = -1;
    }

    public readonly run = async () => {
        while(this.socket.readyState == OPEN) {
            let res: [PacketNonce, Packet] | undefined;
            try {
                res = await readPacketNonce(this.socket);
            } catch(err) {
                console.log(err);
                sendError(this.socket, errors.packetParse);
                this.socket.terminate();
                return;
            }

            assert(res != undefined);
            
            const [nonce, packet] = res;

            // nonce checking
            if(nonce[1] <= this.currentId) {
                console.debug(`${nonce[1]} <= ${this.currentId}`);
                sendError(this.socket, errors.badNonce);
                continue;
            }

            this.currentId = nonce[1];
            const expectedNonce = getPacketNonce(this.token, nonce[1]);
        
            if(!Buffer.from(expectedNonce[0]).equals(Buffer.from(nonce[0]))) {
                logger.debug2(`readPacketNonce: nonce = ${Buffer.from(nonce[0]).toString("hex")}, expected = ${Buffer.from(expectedNonce[0]).toString("hex")}, n = ${nonce[1]}`);
                sendError(this.socket, errors.badNonce);
                continue;
            }

            switch(packet.type) {
            case C2S_OPEN_TCPV4_CHANNEL: {
                if(this.channels.has(packet.getChannelId())) {
                    sendError(this.socket, errors.duplicateChannel(packet.getChannelId()));
                    continue;
                }

                logger.debug0(`attempted to connect to ${packet.getIp()}:${packet.getPort()}`);
                const socket = createConnection(packet.getPort(), packet.getIp());
                const channel = new Channel(packet.getChannelId(), socket, this.channels, this.socket);
                this.channels.set(packet.getChannelId(), channel);
                break;
            }

            case DPX_DATA:
                this.validateChannel(packet.getChannelId(), (channel) => {
                    if(!channel.started()) {
                        sendError(this.socket, errors.badChannel(packet.getChannelId()));
                        return;
                    }

                    channel.onData(packet.getData());
                });
                break;

            case DPX_CLOSE_CHANNEL:

                this.validateChannel(packet.getChannelId(), (channel) => {
                    channel.close(false);
                    this.channels.delete(packet.getChannelId());
                });
                break;
            
            case DPX_ERROR:
                logError(packet);
                break;

            default:
                sendError(this.socket, errors.badPacketType(packet));
            }            
        }
    }; 

    public readonly close = () => {
        this.forceClose();
    };

    public readonly forceClose = () => {
        logger.info("closing client");
        this.channels.forEach((socket) => {
            socket.close();
        });

        this.socket.terminate();
    };
}

let socketId = 0;
const id2instance = new Map<number, ConnectionInstance>();

const server = new WebSocketServer({
    host: host,
    port: port,
});

server.on("connection", async (socket) => {
    const id = socketId++;

    socket.on("close", () => {
        logger.info(`client #${id} disconnected`);
        id2instance.delete(id);
    });

    try {
        const hello = await readPacket(socket);

        if(hello.type != C2S_HELLO) {
            sendError(socket, errors.noHandshake);
            socket.terminate();
            return;
        }

        const clientKey = hello.getKey();
        const verifiable = randomBytes(32);
        writePacket(socket, S2CHelloPacket.create(SERVER_NAME, VERSION, PROTOCOL_VERSION, verifiable));
        logger.info(`client ("${hello.getClientName()}" v${hello.getClientVersion()}) connected, assigned id #${id}`);

        const auth = await readPacket(socket);

        if(auth.type != C2S_TRY_AUTH) {
            sendError(socket, errors.noAuth);
            socket.terminate();
            return;
        }

        const success = keys.reduce<boolean>((success, key) => success || verify(undefined, verifiable, key, auth.getSignature()), false);

        if(!success) {
            sendError(socket, errors.authFail);
            socket.terminate();
            return;
        }  

        const token = randomBytes(32);
        logger.debug0(`client ${id} is using token ${token.toString("hex")}`);
        
        const connection = new ConnectionInstance(socket, token);
        connection.run();
        id2instance.set(id, connection);
        writePacket(socket, S2CAuthenticatedPacket.create(publicEncrypt(clientKey, token)));
    } catch(err) {
        sendError(socket, errors.packetParse);
        socket.terminate();
    } 
});

server.on("listening", () => {
    logger.info(`server started on ${host}:${port}`);
});

