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
let server = http.createServer(app);
try{
    //server = https.createServer(credentials, app);
    
}catch(error){
    throw new Error(`error starting server: ${error}`);
}

server.listen(port, () => {
  console.log(`server is running on PORT ${port}`)
})
new WsIdentityRouter({
    app: app,
    server: server,
    logLevel: 'debug'});

app._router.stack.forEach(print.bind(null, []))

function print (path, layer) {
  if (layer.route) {
    layer.route.stack.forEach(print.bind(null, path.concat(split(layer.route.path))))
  } else if (layer.name === 'router' && layer.handle.stack) {
    layer.handle.stack.forEach(print.bind(null, path.concat(split(layer.regexp))))
  } else if (layer.method) {
    console.log('%s /%s',
      layer.method.toUpperCase(),
      path.concat(split(layer.regexp)).filter(Boolean).join('/'))
  }
}

function split (thing) {
  if (typeof thing === 'string') {
    return thing.split('/')
  } else if (thing.fast_slash) {
    return ''
  } else {
    var match = thing.toString()
      .replace('\\/?', '')
      .replace('(?=\\/|$)', '$')
      .match(/^\/\^((?:\\[.*+?^${}()|[\]\\\/]|[^.*+?^${}()|[\]\\\/])*)\$\//)
    return match
      ? match[1].replace(/\\(.)/g, '$1').split('/')
      : '<complex:' + thing.toString() + '>'
  }
}



