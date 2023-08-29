
type VerboseLevel = "debug0" | "debug1" | "debug2" | "debug3";

let level: VerboseLevel | undefined;
export const setLogLevel = (newLevel?: VerboseLevel) => { 
    level = newLevel;
};

export const getLogLevel = (): VerboseLevel | undefined => {
    return level;
};

export const expectArgument  = (name: string, val: unknown) => {
    if(val === undefined) {
        console.error(name);
        process.exit(-1);
    }
};
