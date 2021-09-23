// fabricRegistry.ts : exposes endpoint for registering and enrolling fabric user
import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { Application, Router, Request, Response } from 'express';
import { query, validationResult, body } from 'express-validator';
import { 
    WsIdentityServer, 
    WsIdentityServerOpts 
} from './web-socket-server';
import { WsSessionRouter } from './routers/session'
import { WsClientRouter } from './routers/client'
export interface WsIdentityRouterOpts {
    logLevel?: LogLevelDesc;
    app: Application;
    server: any;
}

export class WsIdentityRouter {
    public readonly className = "WsIdentityRouter";
    private readonly log: Logger;
    public readonly router: Router;

    constructor(private readonly opts: WsIdentityRouterOpts) {
        opts.logLevel = opts.logLevel || "info";
        this.log = LoggerProvider.getOrCreate({ 
            label: this.className, level: opts.logLevel 
        });
        const wsPath = process.env.WEB_SOCKET_IDENTITY_PATH || '/sessions';
        const wsIdentityServerOpts: WsIdentityServerOpts = {
            path: wsPath,
            server: opts.server,
            logLevel: opts.logLevel,
        };
        const wsIdentityServer = new WsIdentityServer(wsIdentityServerOpts);
        const auth = async (req: Request, res: Response, next) => {    
            const sessionId= req.header('X-SessionId');
            const signature= req.header('X-Signature');
            if (!signature && !sessionId) {
                return res.sendStatus(403);
            } 
            try {
                (req as any).client = wsIdentityServer.getClient(sessionId, signature);
                next();
            } catch (error) {
                return res.sendStatus(403);
            }
        };        

        const wsSessionRouter = 
            new WsSessionRouter({
                logLevel: opts.logLevel,
                wsIdentityServer: wsIdentityServer,
            });
        const wsClientRouter = 
            new WsClientRouter({
                wsIdentityServer: wsIdentityServer,
                logLevel: opts.logLevel
            });
        opts.app.use(
            '/v1/identity',
            wsSessionRouter.router,
        );
        opts.app.use(
            '/v1/identity',
            auth,
            wsClientRouter.router,
        );
    }
}
