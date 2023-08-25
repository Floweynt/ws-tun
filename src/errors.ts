import { Packet } from "./protocol";


// error types]
export type ErrorCategory = 
    // no error (this shouldn't be sent)
    "ok" | 
    // error relating to packets themselves (format, etc)
    "packet" | 
    // errors relating to the nonce that each C2S packet should have
    "nonce" | 
    // errors relating to authentication (currently only sent if the client's authentication attempt fails because the signature was bad)
    "auth" | 
    // errors relating to channels
    "channel" | 
    // errors relating to the handshake process
    "handshake";

export type ProtocolError = [number, ErrorCategory, string];

export const badChannel = (id: number): ProtocolError => 
    [1, "channel", `attempting to use nonexistent channel ${id}`];

export const useBeforeOpen = (id: number): ProtocolError => 
    [2, "channel", `attempting to use channel ${id} before open`];

export const duplicateChannel = (id: number): ProtocolError => 
    [3, "channel", `attempting to open channel that already exists ${id}`];

export const badPacketType = (packet: Packet): ProtocolError => 
    [4, "packet", `unexpected packet type received: ${packet.type}`];

export const packetParse: ProtocolError =
    [5, "packet", "failed to parse packet"];

export const badNonce: ProtocolError =
    [6, "nonce", "bad nonce"];

export const badPacketId: ProtocolError =
    [7, "nonce", "bad packet id"];

export const noHandshake: ProtocolError =
    [8, "handshake", "expected handshake"];

export const noAuth: ProtocolError =
    [9, "handshake", "expected authenticate"];

export const authFail: ProtocolError =
    [10, "auth", "failed to authenticate"];
