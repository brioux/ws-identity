// fabricRegistry.ts : exposes endpoint for registering and enrolling fabric user
import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { Router, Request, Response } from 'express';
import { query, validationResult, body } from 'express-validator';
import { WsIdentityServer } from '../ws-identity-server'
import { WebSocketClient } from '../web-socket-client'

export interface WsClientRouterOpts {
    logLevel: LogLevelDesc;
    wsIdentityServer: WsIdentityServer;
}

export class WsClientRouter {
    public readonly className = "WsClientRouter";
    private readonly log: Logger;
    private readonly client: WebSocketClient;
    public readonly router: Router;

    constructor(private readonly opts: WsClientRouterOpts) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
        this.router = Router();
        this.__registerHandlers();
    }

    private __registerHandlers() {
        this.router.post(
            '/sign',
            [body('digest').isString().notEmpty(),],
            this.sign.bind(this),
        );
        this.router.get(
            '/get-pub',
            this.getPub.bind(this),
        );
    }
    private async sign(req: Request, res: Response) {
        console.log(req)
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        try {
            console.log(req.body);
            const digest = Buffer.from(req.body.digest,'base64');
            const resp = await (req as any).client.sign(digest);
            return res.status(200).json(resp);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }

    private async getPub(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        try {
            const resp = (req as any).client.pubKeyEcdsa
            return res.status(200).json(resp);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }
}
