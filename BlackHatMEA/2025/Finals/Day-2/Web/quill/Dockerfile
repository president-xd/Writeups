FROM node:22-slim AS base

WORKDIR /app

COPY package*.json .

RUN npm i -y

COPY src /app

EXPOSE 3000

ENTRYPOINT ["node", "/app/index.js"]
