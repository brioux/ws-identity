import {
  Logger,
  LoggerProvider,
  LogLevelDesc
} from '@hyperledger/cactus-common'
import WebSocket from 'ws'
import { KJUR } from 'jsrsasign'
// import { WsWalletReq, WsWalletRes } from 'ws-wallet'

export interface WSClientOpts {
  // web socket used to communicate with external client
  webSocket: WebSocket;
  // Ecdsa object from jsrsasign package used in the getPub method
  // Built before creating a new client to verify the incoming webSocket connection
  pubKeyEcdsa: KJUR.crypto.ECDSA;
  logLevel?: LogLevelDesc;
}

interface IDigestQueue {
  digest: Buffer;
  signature?: Buffer;
}

export class WebSocketClient {
  public readonly className = 'WebSocketClient';
  public readonly pubKeyEcdsa: KJUR.crypto.ECDSA; // KJUR.crypto.ECDSA for csr requests;
  public readonly pubKeyHex: string;
  public readonly keyName: string;
  public processing: boolean[] = [];
  private readonly log: Logger;
  private readonly webSocket: WebSocket;
  private digestQueue: IDigestQueue[] = []; // Array of Digests to queue signing requests in series

  constructor (opts: WSClientOpts) {
    this.log = LoggerProvider.getOrCreate({
      label: 'WebSocketClient',
      level: opts.logLevel || 'INFO'
    })
    this.webSocket = opts.webSocket
    this.pubKeyEcdsa = opts.pubKeyEcdsa
    this.pubKeyHex = this.pubKeyEcdsa.pubKeyHex
    this.keyName = `${this.pubKeyHex.substring(0, 12)}...`
    this.digestQueue = []

    const { pubKeyHex, pubKeyEcdsa, digestQueue, processing, webSocket, log } = this
    this.webSocket.on('message', function incoming (signature: Buffer) { // message: WsWalletRes
      let queueI = digestQueue.length
      log.debug(
        `append signature to digest queue index ${queueI} and mark as processed`
      )
      queueI -= 1
      const digest = digestQueue[queueI].digest
      digestQueue[queueI].signature = signature
      processing[queueI] = false
      const verified = pubKeyEcdsa.verifyHex(
        digest.toString('hex'),
        signature.toString('hex'),
        pubKeyHex
      )
      if (!verified) {
        const err = `signature for digest queue index ${queueI + 1} does not match the public key`
        webSocket.close()
        throw new Error(err)
      }
    })
  }

  /**
   * @description : sign message and return in a format that fabric understand
   * @param digest to be singed
   */
  async sign (digest: Buffer): Promise<Buffer> {
    const fnTag = `${this.className}#sign`
    this.log.debug(
      `${fnTag} send digest for pub-key ${this.keyName}: digest-size = ${digest.length}`
    )
    let queueI = this.digestQueue.length - 1 // spot in the digest queue
    if (this.processing[queueI]) {
      throw new Error(`digest is currently beign processed in queue at index ${queueI}`)
      // TODO do we want to handlle parrallel signature requests?
      // do we expect the client to ever return signatures in different order than received?
    }
    if (this.webSocket.readyState !== 1) {
      throw new Error(`ws connection is not open, current state is ${this.webSocket.readyState}`)
    }
    this.digestQueue.push({ digest: digest })
    this.processing.push(true)

    queueI = this.digestQueue.length

    // const message:WsWalletReq = {digest: digest,index: queueI};
    this.webSocket.send(digest)
    this.log.debug(`${fnTag} wait for digest ${queueI} to be signed`)
    queueI -= 1
    await inDigestQueue(this, queueI)
    if (this.digestQueue[queueI].signature) {
      const signature = this.digestQueue[queueI].signature
      return signature
    } else {
      throw new Error(`client failed to return a signature for digest queue index ${queueI + 1}`)
    }
  }

  public close () {
    this.webSocket.close()
  }
}

/**
* @description : wait for digest in queue to be processed
* @param index
* @return signature as Buffer
*/
function inDigestQueue (
  client: WebSocketClient,
  queueI: number,
  attempt = 0
): Promise<void> {
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (!client.processing[queueI] || attempt === 1e6) {
        // attempt sets limit on waiting for processing
        // TODO improve handling of processing digests
        resolve()
      } else {
        attempt += 1
        inDigestQueue(client, queueI, attempt).then(resolve)
      }
    })
  })
}
