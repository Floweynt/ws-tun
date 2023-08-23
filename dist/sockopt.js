"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOriginalDest = void 0;
const ffi_napi_1 = __importDefault(require("ffi-napi"));
const ref_struct_napi_1 = __importDefault(require("ref-struct-napi"));
const ref_napi_1 = __importDefault(require("ref-napi"));
const current = ffi_napi_1.default.Library(null, {
    "getsockopt": ["int", ["int", "int", "int", "pointer", "pointer"]],
    "ntohs": ["uint16", ["uint16"]],
});
const SOL_IP = 0;
const SO_ORIGINAL_DST = 80;
const AF_INET = 2;
const SockaddrIn = (0, ref_struct_napi_1.default)([
    ["int16", "sin_family"],
    ["uint16", "sin_port"],
    ["uint32", "sin_addr"],
    ["uint32", "trash1"],
    ["uint32", "trash2"]
]);
const getOriginalDest = (client) => {
    const dst = new SockaddrIn;
    const dstLen = ref_napi_1.default.alloc(ref_napi_1.default.types.int, SockaddrIn.size);
    const r = current.getsockopt(client._handle.fd, SOL_IP, SO_ORIGINAL_DST, dst.ref(), dstLen); // eslint-disable-line
    if (r === -1) {
        throw new Error("getsockopt(SO_ORIGINAL_DST) error");
    }
    if (dst.sin_family !== AF_INET) {
        throw new Error("getsockopt(SO_ORIGINAL_DST) returns unknown family: " + dst.sin_family);
    }
    const ipAddrVal = dst.ref();
    const ipAddr = ipAddrVal[4] + "." + ipAddrVal[5] + "." + ipAddrVal[6] + "." + ipAddrVal[7];
    return [ipAddr, current.ntohs(dst.sin_port)];
};
exports.getOriginalDest = getOriginalDest;
