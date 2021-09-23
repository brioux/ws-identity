import {
  Logger,
  LoggerProvider,
  LogLevelDesc,
} from "@hyperledger/cactus-common";
import WebSocket from "ws";
import { KJUR } from "jsrsasign";

export enum ECCurveType {
  P256 = "p256",
  P384 = "p384",
}

interface ISignatureRes {
  signature: string;
  curve: string;
}

export interface WSClientOpts {
  // web socket used to communicate with external client
  webSocket: WebSocket;
  // public key hex operated by external client
  pubKeyHex: string;
  // Ecdsa object from jsrsasign package used in the getPub method
  // Built before creating a new client to verify the incoming webSocket connection
  pubKeyEcdsa: KJUR.crypto.ECDSA;
  curve: ECCurveType;
  logLevel?: LogLevelDesc;
}

interface IDigestQueue {
  digest: Buffer;
  signature: Buffer;
}

export class WebSocketClient {
  public readonly className = "WebSocketClient";
  public readonly pubKeyEcdsa: KJUR.crypto.ECDSA; //KJUR.crypto.ECDSA for csr requests;
  public readonly pubKeyHex: string;
  public readonly keyName: string;
  public readonly curve: string;

  private readonly log: Logger;
  private readonly webSocket: WebSocket;
  private digestQueue: IDigestQueue[] = []; // Array of Digests to queue signing requests in series

  constructor(opts: WSClientOpts) {
    this.log = LoggerProvider.getOrCreate({
      label: "WebSocketClient",
      level: opts.logLevel || "INFO",
    });
    this.webSocket = opts.webSocket;
    this.pubKeyHex = opts.pubKeyHex;
    this.curve = opts.curve;
    this.pubKeyEcdsa = opts.pubKeyEcdsa;
    this.keyName = `${this.pubKeyHex.substring(0, 12)}...`;
    this.digestQueue = [];

    const { pubKeyHex, pubKeyEcdsa, digestQueue, webSocket, log } = this;
    this.webSocket.on("message", function incoming(signature: Buffer) {
      const queueI = digestQueue.length;
      log.debug(
        `append signature to digestQueue index ${queueI} and mark as processed`,
      );
      const digest = digestQueue[queueI - 1].digest;
      digestQueue[queueI - 1].signature = Buffer.from(signature);

      const verified = pubKeyEcdsa.verifyHex(
        digest.toString("hex"),
        signature.toString("hex"),
        pubKeyHex,
      );
      if (!verified) {
        const err = `signature for digest queue ${queueI} does not match the public key`;
        log.error(err);
        webSocket.close();
        throw new Error(err);
      }
    });
  }

  /**
   * @description : sign message and return in a format that fabric understand
   * @param digest to be singed
   */
  async sign(digest: Buffer): Promise<ISignatureRes> {
    const fnTag = `${this.className}#sign`;
    this.log.debug(
      `${fnTag} send digest for pub-key ${this.keyName}: digest-size = ${digest.length}`,
    );
    let queueI = this.digestQueue.length - 1; //spot in the digest queue
    if (
      queueI >= 0 &&
      this.digestQueue[queueI].signature.toString().length == 0
    ) {
      // TO DO: enable parallel signature processing?
      throw new Error("waiting for a previous digest signature");
    }
    this.digestQueue.push({ digest: digest, signature: Buffer.from("") });
    this.webSocket.send(digest);

    queueI = this.digestQueue.length;
    this.log.debug(`${fnTag} wait for digest ${queueI} to be signed`);
    queueI -= 1;
    const signature = await this.inDigestQueue(queueI);
    return {signature: signature.toString('base64'), curve: this.curve};
  }

  public close() {
    this.webSocket.close();
  }
  /**
  * @description : wait for digest in queue to be processed
  * @param index
  * @return signature as Buffer
  */
  private inDigestQueue(
    queueI: number,
  ): Promise<Buffer> {
    const { digestQueue, inDigestQueue } = this;
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (digestQueue[queueI].signature.toString().length > 0) {
          resolve(digestQueue[queueI].signature);
        } else {
          inDigestQueue(queueI).then(resolve);
        }
      });
    });
  }
}

