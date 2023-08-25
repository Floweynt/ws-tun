
type VerboseLevel = "debug0" | "debug1" | "debug2" | "debug3";

let l: VerboseLevel | undefined;
export const setLogLevel = (level?: VerboseLevel) => { 
    l = level;
};

export const getLogLevel = (): VerboseLevel | undefined => {
    return l;
};

export const expectArgument  = (name: string, val: unknown) => {
    if(val === undefined) {
        console.error(name);
        process.exit(-1);
    }
};
