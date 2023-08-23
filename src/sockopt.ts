import ffi from "ffi-napi";
import net from "net";
import StructType from "ref-struct-napi";
import ref from "ref-napi";

const current = ffi.Library(null, {
    "getsockopt": [ "int", [ "int", "int", "int", "pointer", "pointer"]],
    "ntohs": ["uint16", ["uint16"]],
});

const SOL_IP = 0;
const SO_ORIGINAL_DST = 80;
const AF_INET = 2;

const SockaddrIn = StructType([
    ["int16", "sin_family"],
    ["uint16", "sin_port"],
    ["uint32", "sin_addr"],
    ["uint32", "trash1"],
    ["uint32", "trash2"]
]);

export const getOriginalDest = (client: net.Socket): [string, number] => {
    const dst = new SockaddrIn;
    const dstLen = ref.alloc(ref.types.int, SockaddrIn.size);

    const r = current.getsockopt((client as any)._handle.fd, SOL_IP, SO_ORIGINAL_DST, dst.ref(), dstLen); // eslint-disable-line
    
    if (r === -1) {
        throw new Error("getsockopt(SO_ORIGINAL_DST) error");
    }

    if (dst.sin_family !== AF_INET) {
        throw new Error("getsockopt(SO_ORIGINAL_DST) returns unknown family: " + dst.sin_family );
    }

    const ipAddrVal = dst.ref(); 
    const ipAddr = ipAddrVal[4] + "." + ipAddrVal[5] + "." + ipAddrVal[6] + "." + ipAddrVal[7];

    return [ipAddr, current.ntohs(dst.sin_port)];
};

