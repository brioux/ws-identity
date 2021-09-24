FROM node:12.13.0-alpine as build
WORKDIR /app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package.json /app/package.json

RUN npm install

COPY src /app/src
COPY tsconfig.json /app/tsconfig.json
COPY tslint.json /app/tslint.json
COPY app.ts /app/app.ts

RUN npm run build
RUN npm ci --production

FROM alpine:3
RUN apk add nodejs --no-cache
WORKDIR /app
COPY --from=build /app/dist /app
COPY --from=build /app/node_modules /app/node_modules

#RUN npm run start
CMD [ "node", "./app.js" ]
