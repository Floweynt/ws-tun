import { expectArgument, setLogLevel } from "./args";
import commandLineArgs from "command-line-args";

const options = commandLineArgs([
    { name: "verbose", type: String, defaultValue: "info", },
    { name: "key", alias: "k", type: String, },
    { name: "remote", alias: "r", type: String, }
]);

const remote = options["remote"];
const keyFile = options["key"];
const verbosity = options["verbose"];

expectArgument("missing required argument 'remote'", remote);
expectArgument("missing required argument 'key'", keyFile);

if(["info", "debug0", "debug1", "debug2", "debug3"].find((x) => x == verbosity) == undefined) {
    console.error(`verbosity should be info or debug0-3, but got ${verbosity}`);
    process.exit(-1);
}

setLogLevel(verbosity == "info" ? undefined : verbosity as "debug0" | "debug1" | "debug2" | "debug3");

import { logger } from "./logging";
import * as errors from "./errors";
import { getOriginalDest } from "./sockopt";
import { WebSocket } from "ws";
import { CLIENT_NAME, CLIENT_SERVER_PORT, VERSION } from "./config";
import { C2SHelloPacket, C2SOpenTcpV4Channel, C2STryAuthenticatePacket, DPX_CLOSE_CHANNEL, DPX_DATA, DPX_ERROR, DuplexCloseChannel, DuplexDataPacket, getPacketNonce, logError, PacketNonce, readPacket, S2C_AUTH, S2C_HELLO, S2C_OPEN_TCPV4_CHANNEL_ACK, sendError, writePacket } from "./protocol";
import assert from "assert";
import { Socket, createServer } from "net";
import { generateKeyPairSync, privateDecrypt, sign } from "crypto";
import { readFileSync } from "fs";

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

let nonce = 0;
let channelId = 0;

const nextNonce = (token: Uint8Array): PacketNonce => getPacketNonce(token, nonce++);

const channels = new Map<number, Channel>();
const key = readFileSync(keyFile, "utf-8");

const websocket = new WebSocket(remote);
class Channel {
    private readonly socket: Socket;
    private readonly id: number;
    private isStarted: boolean;
    private isClosed: boolean;
    private readonly token: Uint8Array;

    public constructor(id: number, socket: Socket,  token: Uint8Array) {
        this.id = id;
        this.socket = socket;
        this.isStarted = false;
        this.isClosed = false;
        this.token = token;
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
            writePacket(websocket, DuplexDataPacket.create(this.id, data), nextNonce(this.token));
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
            writePacket(websocket, DuplexCloseChannel.create(this.id), nextNonce(this.token));
        }
    };

    public readonly started = () => this.isStarted && !this.isClosed;
}

const validateChannel = (token: Uint8Array, channelId: number, cb: (c: Channel) => void) => {
    if(!channels.has(channelId)) {
        sendError(websocket,  errors.badChannel(channelId), nextNonce(token));
        return;
    }

    const chan = channels.get(channelId);
    assert(chan !== undefined);
    cb(chan);
};

const run = async (token: Uint8Array) => {
    const server = createServer();

    server.on("connection", (socket: Socket) => {
        const [realTargetIp, realTargetPort] = getOriginalDest(socket);
        const id = channelId++;
        writePacket(websocket, C2SOpenTcpV4Channel.create(id, realTargetIp, realTargetPort), nextNonce(token));
        channels.set(id, new Channel(id, socket, token));
    });

    server.listen(CLIENT_SERVER_PORT, "127.0.0.1", () => {
        // we listen on loopback, since this server shouldn't be exposed to any outside traffic
        logger.info(`internal server started on 127.0.0.1:${CLIENT_SERVER_PORT}`);
    });

    while(websocket.readyState == WebSocket.OPEN) {
        const packet = await readPacket(websocket);

        switch(packet.type) {
        case S2C_OPEN_TCPV4_CHANNEL_ACK:
            validateChannel(token, packet.getChannelId(), (channel) => {
                if(channel.started()) {
                    sendError(websocket, errors.duplicateChannel(packet.getChannelId()), nextNonce(token));
                    return;
                }

                channel.start();
            });
            break;

        case DPX_DATA:
            validateChannel(token, packet.getChannelId(), (channel) => {
                if(!channel.started()) {
                    sendError(websocket, errors.useBeforeOpen(packet.getChannelId()),  nextNonce(token));
                    channel.start();
                }

                channel.onWebsocketData(packet.getData());
            });
            break;

        case DPX_CLOSE_CHANNEL:
            validateChannel(token, packet.getChannelId(), (channel) => {
                channel.close(false);
                channels.delete(packet.getChannelId());
            });
            break;

        case DPX_ERROR:
            logError(packet);
            break;

        default: 
            sendError(websocket, errors.badPacketType(packet),  nextNonce(token));
            break;
        }
    }
};

websocket.on("open", async () => {
    try {
        writePacket(websocket, C2SHelloPacket.create(CLIENT_NAME, VERSION, publicKey));
        const hello = await readPacket(websocket);

        if(hello.type != S2C_HELLO) {
            logger.error("protocol error: expected S2CHelloPacket");
            process.exit(-1);
        }

        logger.info(`connected to server: "${hello.getServerName()}" v${hello.getServerVersion()}`);
        logger.info(`running protocol version ${hello.getProtocolVersion()}`);


        writePacket(websocket, C2STryAuthenticatePacket.create(sign(undefined, hello.getVerifiable(), key)));

        const auth = await readPacket(websocket);
        
        if(auth.type == S2C_AUTH) {
            const token = privateDecrypt(privateKey, auth.getToken());
            logger.debug0(`token = ${token.toString("hex")}`);
            run(token);
        }
        else if(auth.type == DPX_ERROR) {
            logger.error("failed to authenticate");
            process.exit(-1);
        }
        else {
            logger.error("protocol error: expected S2CAuthenticatedPacket or DuplexErrorPacket");
            process.exit(-1);
        }
    }
    catch (err){
        logger.error("handshake failed");
        logger.debug0("except", err);
        process.exit(-1);
    }
});

websocket.on("close", () => {
    logger.fatal("connection to server was closed");
    process.exit(-1);
});

