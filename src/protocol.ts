import v8 from "v8";
import WebSocket, { RawData } from "ws";
import assert from "assert";
import crypto from "crypto";
import { once } from "events";
import { ErrorCategory, ProtocolError } from "./errors";
import { logger } from "./logging";

export const PROTOCOL_VERSION = 1;

export const C2S_HELLO                  = 0x00;
export const S2C_HELLO                  = 0x01;
export const C2S_TRY_AUTH               = 0x02;
export const S2C_AUTH                   = 0x03;

export const C2S_OPEN_TCPV4_CHANNEL     = 0x14;
export const S2C_OPEN_TCPV4_CHANNEL_ACK = 0x15;
export const DPX_CLOSE_CHANNEL          = 0x16;
export const DPX_ERROR                  = 0x17;
export const DPX_DATA                   = 0x18;

interface SerializablePacket {
    readonly type: number
    readonly write: (buf: v8.Serializer) => void,
    readonly read: (buf: v8.Deserializer) => void,
    readonly toString: () => string,
}

export const writeString = (buf: v8.Serializer, val: string) => {
    buf.writeUint32(val.length);
    buf.writeRawBytes(Buffer.from(val, "utf-8"));
};

export const readString = (buf: v8.Deserializer): string => {
    const len = buf.readUint32();
    return buf.readRawBytes(len).toString("utf-8");
};

export class C2SHelloPacket implements SerializablePacket {
    private clientName: string;
    private clientVer: string;
    private key: string;

    public readonly type = C2S_HELLO;

    private constructor(clientName: string, clientVer: string, key: string) {
        this.clientName = clientName;
        this.clientVer = clientVer;
        this.key = key;
    }

    public static readonly empty = () => new C2SHelloPacket("", "", ""); 
    public static readonly create = (clientName: string, clientVer: string, key: string) => new C2SHelloPacket(clientName, clientVer, key);

    public readonly getClientVersion = () => { return this.clientVer; };
    public readonly getClientName = () => { return this.clientName; };
    public readonly getKey = () => { return this.key; };

    public readonly read = (buf: v8.Deserializer) =>  {
        this.clientName = readString(buf);
        this.clientVer = readString(buf);
        this.key = readString(buf);
    };

    public readonly write = (buf: v8.Serializer) => {
        writeString(buf, this.clientName);
        writeString(buf, this.clientVer);
        writeString(buf, this.key);
    };

    public readonly toString = () =>
        `C2SHelloPacket { name = "${this.clientName}", version = "${this.clientVer}" }`;
}

export class S2CHelloPacket implements SerializablePacket {
    private serverName: string;
    private serverVersion: string;
    private protocolVersion: number;
    private verifiable: Uint8Array;

    public readonly type = S2C_HELLO;

    private constructor(serverName: string, serverVersion: string, protocolVersion: number, verifiable: Uint8Array) {
        this.serverName = serverName;
        this.serverVersion = serverVersion;
        this.protocolVersion = protocolVersion;
        this.verifiable = verifiable;

        if(verifiable.length != 32) {
            throw Error("bad verifiable length");
        }
    }

    public static readonly empty = () => new S2CHelloPacket("", "", -1, new Uint8Array(32)); 
    public static readonly create = (serverName: string, serverVersion: string, protocolVersion: number, verifiable: Uint8Array) => 
        new S2CHelloPacket(serverName, serverVersion, protocolVersion, verifiable); 

    public readonly getServerName = () => { return this.serverName; };
    public readonly getServerVersion = () => { return this.serverVersion; };
    public readonly getProtocolVersion = () => { return this.protocolVersion; };
    public readonly getVerifiable = () => { return this.verifiable; };

    public readonly read = (buf: v8.Deserializer) =>  {
        this.serverName = readString(buf);
        this.serverVersion = readString(buf);
        this.protocolVersion = buf.readUint32();
        this.verifiable = buf.readRawBytes(32);
    };

    public readonly write = (buf: v8.Serializer) => {
        writeString(buf, this.serverName);
        writeString(buf, this.serverVersion);
        buf.writeUint32(this.protocolVersion);
        buf.writeRawBytes(this.verifiable);
    };

    public readonly toString = () =>
        `S2CHelloPacket { name = "${this.serverName}", version = "${this.serverVersion}, protocol_version = ${this.protocolVersion} }`;
}

export class C2STryAuthenticatePacket implements SerializablePacket {
    private signature: Buffer;

    public readonly type = C2S_TRY_AUTH;

    private constructor(signature: Buffer) {
        this.signature = signature;
    }

    public static readonly empty = () => new C2STryAuthenticatePacket(Buffer.alloc(0)); 
    public static readonly create = (signature: Buffer) => 
        new C2STryAuthenticatePacket(signature); 

    public readonly getSignature = () => { return this.signature; };

    public readonly read = (buf: v8.Deserializer) =>  {
        this.signature = buf.readRawBytes(buf.readUint32());
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.signature.length);
        buf.writeRawBytes(this.signature);
    };

    public readonly toString = () =>
        "C2STryAuthenticatePacket { ... }";
}

export class S2CAuthenticatedPacket implements SerializablePacket {
    private token: Buffer;

    public readonly type = S2C_AUTH;

    private constructor(token: Buffer) {
        this.token = token;
    }

    public static readonly empty = () => new S2CAuthenticatedPacket(Buffer.alloc(0)); 
    public static readonly create = (token: Buffer) => 
        new S2CAuthenticatedPacket(token); 

    public readonly getToken = () => { return this.token; };

    public readonly read = (buf: v8.Deserializer) =>  {
        this.token = buf.readRawBytes(buf.readUint32());
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.token.length);
        buf.writeRawBytes(this.token);
    };

    public readonly toString = () =>
        "S2CAuthenticatedPacket { ... }";
}

export class DuplexErrorPacket implements SerializablePacket {
    private data: ProtocolError;

    public readonly type = DPX_ERROR;

    private constructor(data: ProtocolError) {
        this.data = data;
    }

    public static readonly empty = () => new DuplexErrorPacket([0, "ok", ""]);
    public static readonly create = (data: ProtocolError) => new DuplexErrorPacket(data);

    public readonly getData = () => { return this.data; };
    public readonly getCode = () => { return this.data[0]; };
    public readonly getCategory = () => { return this.data[1]; };
    public readonly getMessage = () => { return this.data[2]; };

    public readonly read = (buf: v8.Deserializer) => {
        this.data = [
            buf.readUint32(),
            readString(buf) as ErrorCategory,
            readString(buf)
        ];
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.data[0]);    
        writeString(buf, this.data[1]);    
        writeString(buf, this.data[2]);    
    };

    public readonly toString = () =>
        `DuplexErrorPacket(${this.getCategory()}) { message = "${this.getMessage()}", code = "${this.getCode()}" }`;
}

export class C2SOpenTcpV4Channel implements SerializablePacket {
    private channelId: number;
    private ip: number;
    private port: number;

    public readonly type = C2S_OPEN_TCPV4_CHANNEL;

    private constructor(channelId: number, ip: number, port: number) {
        this.channelId = channelId;
        this.ip = ip;
        this.port = port;
    }

    public static readonly empty = () => new C2SOpenTcpV4Channel(-1, 0, 0);
    public static readonly create = (channelId: number, ip: number | string, port: number) => 
        new C2SOpenTcpV4Channel(channelId, typeof ip === "number" ? ip : ipv4ToInt(ip), port);

    public readonly getChannelId = () => { return this.channelId; };
    public readonly getIp= () => { return intToIpv4(this.ip); };
    public readonly getPort = () => { return this.port; };

    public readonly read = (buf: v8.Deserializer) => {
        this.channelId = buf.readUint32();
        this.ip = buf.readUint32();
        this.port = buf.readUint32();
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.channelId);
        buf.writeUint32(this.ip);
        buf.writeUint32(this.port);
    };

    public readonly toString = () =>
        `C2SOpenTcpV4Channel(${this.channelId}) { target = ${this.getIp()}:${this.port} }`;
}

export class S2COpenTcpV4ChannelAck implements SerializablePacket {
    private channelId: number;

    public readonly type = S2C_OPEN_TCPV4_CHANNEL_ACK;

    private constructor(channelId: number) {
        this.channelId = channelId;
    }

    public static readonly empty = () => new S2COpenTcpV4ChannelAck(-1) ;
    public static readonly create = (channelId: number) => new S2COpenTcpV4ChannelAck(channelId);

    public readonly getChannelId = () => { return this.channelId; };

    public readonly read = (buf: v8.Deserializer) => {
        this.channelId = buf.readUint32();
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.channelId);
    };

    public readonly toString = () =>
        `S2COpenTcpV4ChannelAck(${this.channelId}) { }`;
}

export class DuplexCloseChannel implements SerializablePacket {
    private channelId: number;

    public readonly type = DPX_CLOSE_CHANNEL;

    private constructor(channelId: number) {
        this.channelId = channelId;
    }

    public static readonly empty = () => new DuplexCloseChannel(-1);
    public static readonly create = (channelId: number) => new DuplexCloseChannel(channelId);

    public readonly getChannelId = () => { return this.channelId; };

    public readonly read = (buf: v8.Deserializer) => {
        this.channelId = buf.readUint32();
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.channelId);
    };

    public readonly toString = () =>
        `DuplexCloseChannel(${this.channelId}) { }`;
}

export class DuplexDataPacket implements SerializablePacket{
    private channelId: number;
    private data: Buffer;

    public readonly type = DPX_DATA;

    private constructor(channelId: number, data: Buffer) {
        this.channelId = channelId;
        this.data = data;
    }

    public static readonly empty = () => new DuplexDataPacket(-1, Buffer.alloc(0)) ;
    public static readonly create = (channelId: number, data: Buffer) => new DuplexDataPacket(channelId, data);

    public readonly getChannelId = () => { return this.channelId; };
    public readonly getData = () => { return this.data; };

    public readonly read = (buf: v8.Deserializer) => {
        this.channelId = buf.readUint32();
        this.data = buf.readRawBytes(buf.readUint32());
    };

    public readonly write = (buf: v8.Serializer) => {
        buf.writeUint32(this.channelId);
        buf.writeUint32(this.data.length);
        buf.writeRawBytes(this.data);
    };

    public readonly toString = () =>
        `DuplexDataPacket(${this.channelId}) { data = <buffer, size = ${this.data.length}> }`;
}

export type Packet = 
      C2SHelloPacket 
    | S2CHelloPacket 
    | DuplexErrorPacket 
    | C2SOpenTcpV4Channel 
    | S2COpenTcpV4ChannelAck 
    | DuplexCloseChannel
    | C2STryAuthenticatePacket
    | S2CAuthenticatedPacket
    | DuplexDataPacket;

const ID_TO_CONSTRUCTOR: {[key: number]: () => Packet} = {
    [C2S_HELLO]:C2SHelloPacket.empty,
    [S2C_HELLO]:  S2CHelloPacket.empty,
    [DPX_ERROR]: DuplexErrorPacket.empty,
    [C2S_OPEN_TCPV4_CHANNEL]: C2SOpenTcpV4Channel.empty,
    [S2C_OPEN_TCPV4_CHANNEL_ACK]: S2COpenTcpV4ChannelAck.empty,
    [DPX_DATA]:DuplexDataPacket.empty,
    [DPX_CLOSE_CHANNEL]: DuplexCloseChannel.empty,
    [C2S_TRY_AUTH]:  C2STryAuthenticatePacket.empty,
    [S2C_AUTH]: S2CAuthenticatedPacket.empty,
};

export type PacketNonce = [Uint8Array, number];

export const getPacketNonce = (token: Uint8Array, nonce: number): PacketNonce => {
    const tempBuffer = Buffer.alloc(4);
    tempBuffer.writeUint32LE(nonce);
    return [crypto.createHash("sha256").update(Buffer.concat([token, tempBuffer])).digest(), nonce];
};

const doWritePacket = (serializer: v8.Serializer, packet: Packet): Buffer => {
    const tempBuffer = Buffer.alloc(1);
    tempBuffer.writeUint8(packet.type);
    serializer.writeRawBytes(tempBuffer); 
    packet.write(serializer);
    return serializer.releaseBuffer();
};

export const writePacket = (ws: WebSocket, packet: Packet, nonce?: PacketNonce) => {
    logger.debug1(`send packet ${packet.toString()} ${nonce ? `nonce = ${Buffer.from(nonce[0]).toString("hex")}, id = ${nonce[1]}` : ""}`);
    const ser = new v8.Serializer();

    if(nonce) {
        assert(nonce[0].length == 32);
        ser.writeUint32(nonce[1]);
        ser.writeRawBytes(nonce[0]);
    }

    ws.send(doWritePacket(ser, packet), {
        binary: true,
    });
};

export const logError = (packet: DuplexErrorPacket) => {
    logger.error(`(${packet.getCategory()}): ${packet.getMessage()}`);
};

export const sendError = (ws: WebSocket, data: ProtocolError, token?: PacketNonce) => {
    logger.error(`(${data[1]}): ${data[2]}`);
    writePacket(ws, DuplexErrorPacket.create(data), token);
};

const readSocket = async(socket: WebSocket): Promise<RawData> => {
    return (await once(socket, "message"))[0];
};

const doReadPacket = async (deserializer:  v8.Deserializer) => {
    const id = deserializer.readRawBytes(1).readUint8();
    if(!ID_TO_CONSTRUCTOR[id]) {
        throw Error(`failed to create packet with type = ${id}`);
    }

    const packet = ID_TO_CONSTRUCTOR[id]();
    packet.read(deserializer);
    logger.debug1(`recv packet ${packet.toString()}`);

    return packet;
};

export const readPacket = async (socket: WebSocket): Promise<Packet> => {
    const message = await readSocket(socket);
    assert(message instanceof Buffer);
    return await doReadPacket(new v8.Deserializer(message));
};

export const readPacketNonce = async (socket: WebSocket): Promise<[PacketNonce, Packet]> => {
    const message = await readSocket(socket);
    assert(message instanceof Buffer);

    const deserializer = new v8.Deserializer(message);
    const id = deserializer.readUint32();
    const nonce = deserializer.readRawBytes(32);
    logger.debug1(`readPacketNonce: nonce = ${Buffer.from(nonce).toString("hex")}, id = ${id}`);
    return [[nonce, id], await doReadPacket(deserializer)];
};

// random utilities

export const intToIpv4 = (ip: number): string =>
    `${ip >>> 24}.${ip >> 16 & 255}.${ip >> 8 & 255}.${ip & 255}`;

export const ipv4ToInt = (ip: string): number => 
    ip.split(".").reduce((val, octet) => (val << 8) + parseInt(octet, 10), 0) >>> 0;


