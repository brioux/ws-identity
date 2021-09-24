import {
  LogLevelDesc,
  Logger,
  LoggerProvider,
} from "@hyperledger/cactus-common";
import WebSocket from "ws";
import { KJUR } from "jsrsasign";
import { parse, URLSearchParams } from "url";
import { randomBytes } from "crypto";
import http, { Server } from "http";
import net from "net";
import { 
  WebSocketClient, 
  WSClientOpts,
  ECCurveType  } from "./web-socket-client";
import { getClientIp } from '@supercharge/request-ip';

export enum ECCurveLong {
  p256 = "secp256r1",
  p384 = "secp384r1",
}

export interface WsIdentityServerOpts {
  // existing server where all incoming web socket connections are directed.
  server: Server;
  // path for all incoming web-socket connection
  // TODO currently optional. setting this will generate error
  // if incoming connections are not directed here
  path?: string;

  logLevel: LogLevelDesc;
}

interface WebSocketTicket {
  pubKeyHex: string;
  ip: string;
}

interface IWebSocketClients {
  // the pubKeyHex of the client or client abject instance
  // key is a unique/ranfrom session ID provided to the external client
  [key: string]: null | WebSocketTicket | WebSocketClient;
}

export class WsIdentityServer {
  public readonly className = "WsIdentityServer";
  private clients: IWebSocketClients = {};
  private readonly log: Logger;
  private readonly webSocketServer: WebSocket.Server;
  public readonly hostAddress: any;

  constructor(private readonly opts: WsIdentityServerOpts) {
    const fnTag = `${this.className}#constructor`;
    this.log = LoggerProvider.getOrCreate({
      level: opts.logLevel || "INFO",
      label: this.className,
    });
    this.opts.path = opts.path || '/sessions';
    this.webSocketServer = new WebSocket.Server({
      noServer: true,
      path: opts.path,
      //clientTracking: true,
    });
    this.hostAddress = this.opts.server.address();
    this.hostAddress.path = this.opts.path;
    this.hostAddress.uri = `http://localhost:${this.hostAddress.port}${this.opts.path}`
    this.log.debug(
      `${fnTag} setup ws-identity-server at ${this.hostAddress.uri}`,
    );
    //Checks.nonBlankString(opts.path, `${fnTag} options.path`);

    const { log, clients, webSocketServer } = this;
    opts.server.on("upgrade", function upgrade(
      request: http.IncomingMessage,
      socket: net.Socket,
      head: Buffer,
    ) {
      log.debug(
        `${fnTag} validation of server upgrade before establishing web-socket connection`,
      );
      try {
        const { path, pathname } = parse(request.url as string);
        const params = path?.split("?")[1];
        if (opts.path && pathname !== opts.path) {
          throw new Error(
            `incoming web-socket connections directed to ${pathname}, but required path is ${opts.path}`,
          );
        }
        const headers = request.headers;
        const connectionParams = new URLSearchParams(params);
        log.debug(
          `${fnTag} params received by new web-socket client: ${connectionParams}`,
        );

        const sessionId = headers.sessionId as string;
        const signature = headers.signature as string;
        const curve = headers.crv as ECCurveType;
        const paramErrs = [];
        if (!sessionId) {
          paramErrs.push(`header 'sessionId' not provided`);
        }
        if (!signature) {
          paramErrs.push(`header 'signature' not provided`);
        }
        if (!curve) {
          paramErrs.push(`header 'curve' not provided`);
        }
        if (paramErrs.length > 0) {
          throw new Error(paramErrs.join("\r\n"));
        }

        const client = clients[sessionId] as WebSocketTicket;
        if (!client) {
          throw new Error(
            `server is not waiting for client with sessionId ${sessionId} `,
          );
        } else if (client.constructor.name == "WebSocketClient") {
          throw new Error(
            `a client has already been opened for sessionId ${sessionId}`,
          );
        }
        const clientIp = getClientIp(request);
        if(client.ip !== clientIp){
          throw new Error(
            `session is expecting incoming client with ip ${client.ip} but incoming ip is ${clientIp}`
          )
        };
        const pubKeyHex: string = client.pubKeyHex;
        log.debug(
          `${fnTag} build public ECDSA curve using the pub-key-hex ${pubKeyHex.substring(
            0,
            12,
          )}... to verify the sessionId signature`,
        );
        const pubKeyEcdsa = new KJUR.crypto.ECDSA({
          curve: ECCurveLong[curve],
          pub: pubKeyHex,
        });
        if (!pubKeyEcdsa.verifyHex(sessionId, signature, pubKeyHex)) {
          throw new Error("the signature does not match the public key");
        }

        webSocketServer.handleUpgrade(
          request as http.IncomingMessage,
          socket as net.Socket,
          head as Buffer, (webSocket) => {
            const wsClientOpts: WSClientOpts = {
              pubKeyHex,
              webSocket,
              curve,
              pubKeyEcdsa,
              logLevel: opts.logLevel,
            };
            clients[sessionId] = new WebSocketClient(wsClientOpts);
            webSocketServer.emit("connection", webSocket, sessionId);
          },
        );
      } catch (error) {
        socket.write(`HTTP/1.1 401 Unauthorized\r\n\r\n${error}`);
        throw new Error(`${fnTag} incoming connection denied: ${error}`);
        socket.destroy();
      }
    });
    webSocketServer.on("connection", function connection(
      webSocket: WebSocket,
      sessionId: string,
    ) {
      const client = clients[sessionId] as null | WebSocketClient;
      log.info(`session ${sessionId} in progress for ${client?.keyName}`);
      webSocket.onclose = function () {
        log.info(
          `${fnTag} client closed for sessionId ${sessionId} and pub-key-hex ${client?.keyName}`,
        );
        clients[sessionId] = null;
      };
    });
  }
  /**
   * @description create a unique sessionId for web socket connection for a given public key hex
   */
  public newSessionId(pubKeyHex: string, clientIp: string):string {
    const fnTag = `${this.className}#new-session-id`;
    const sessionId = randomBytes(8).toString("hex");
    this.clients[sessionId] = {pubKeyHex, ip: clientIp} as WebSocketTicket;
    this.log.debug(
      `${fnTag} assign new session id ${sessionId} to public key ${pubKeyHex.substring(
        0,
        12,
      )}...`,
    );
    return sessionId;
  }
  public close() {
    Object.values(this.clients).forEach((value) => {
      if (typeof value === "object") {
        (value as WebSocketClient)?.close();
      }
    });
    this.clients = {};
    this.webSocketServer.close();
  }
  public getClient(sessionId: string, signature: string): WebSocketClient {
    const fnTag = `${this.className}#get-client`;
    this.log.debug(`${fnTag} request client for sessionId ${sessionId}`);
    const client = this.clients[sessionId] as WebSocketClient;
    let err;
    if (client.constructor.name !== "WebSocketClient"){
      err = `${fnTag} not client connected for sessionId ${sessionId}`
    }
    else if (
      !client.pubKeyEcdsa.verifyHex(sessionId, signature, client.pubKeyHex)
    ) {
      err = `${fnTag} the signature does not match the public key for sessionId ${sessionId}`
    }
    if(err){  
      this.log.error(err);
      throw new Error(err);
    }
    return client;
  }

  public async waitForSocketClient(
    sessionId: string,
    address?: any,
  ): Promise<void> {
    const { log, waitForSocketClient } = this;
    const client = this.clients[sessionId];
    if (address) {
      log.info(
        `waiting for web-socket connection from client for ${sessionId}`,
      );
    }
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (client.constructor?.name === "WebSocketClient") {
          log.info(`web-socket client established for sessionId ${sessionId}`);
          resolve();
        } else {
          waitForSocketClient(sessionId).then(resolve);
        }
      });
    });
  }
}