import winston, { format } from "winston";
import { getLogLevel } from "./args";

const env: "dev" | "prod" = process.env.NODE_ENV == "prod" ? "prod" : "dev";

const levels = {
    levels: {
        fatal: 0,
        error: 1,
        warn: 2,
        info: 3,
        debug0: 4,
        debug1: 5,
        debug2: 6,
        debug3: 7,
    },
    colors: {
        fatal: "red",
        error: "red",
        warn: "yellow",
        info: "blue",
        debug0: "gray",
        debug1: "gray",
        debug2: "gray",
        debug3: "gray",
    },
};

export const logger = ((verboseLevel?: "debug0" | "debug1" | "debug2" | "debug3") => { 
    let level: typeof verboseLevel | "info" = verboseLevel;
    if(!level) {
        level = env == "dev" ? "debug0" : "info";
    }

    return winston.createLogger({
        level: level,
        levels: levels.levels,
        format: winston.format.colorize(),
        transports: [
            new winston.transports.Console({
                format: winston.format.combine(
                    format.colorize({ colors: levels.colors, }),
                    format.timestamp({
                        format: "YYYY-MM-DD hh:mm:ss",
                    }),
                    format.printf(info => `[${info.timestamp}] [${info.level}]: ${info.message}`)
                ),
            })
        ],
    }) as winston.Logger & Record<keyof typeof levels.levels, winston.LeveledLogMethod>;
})(getLogLevel());
