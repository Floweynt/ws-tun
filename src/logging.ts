import winston, { format } from "winston";

const env: "dev" | "prod" = process.env.NODE_ENV == "prod" ? "prod" : "dev";

export const logger = winston.createLogger({
    level: env == "dev" ? "debug" : "info",
    format: winston.format.colorize(),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                format.colorize(),
                format.timestamp({
                    format: "YYYY-MM-DD hh:mm:ss",
                }),
                format.printf(info => `[${info.timestamp}] [${info.level}]: ${info.message}`)
            ),
        })
    ],
});

