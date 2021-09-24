import express, { Application, Request, Response, NextFunction } from "express";
import bodyParser from "body-parser";
import { WsIdentityRouter } from './src/router';
import https from 'https'
import http from 'http'
const app: Application = express()
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.get("/", (req: Request, res: Response) => {
  res.send("TS App is Running")
});

const port = process.env.WEB_SOCKET_SERVER_PORT || '8700';

const credentials = {
  key: process.env.SSL_KEY,
  cert: process.env.SSL_CERT
};
//const server = https.createServer(credentials, app);
const server = http.createServer(app);

server.listen(port, () => {
  console.log(`server is running on PORT ${port}`)
})
new WsIdentityRouter({
    app: app,
    server: server,
    logLevel: 'debug'});



