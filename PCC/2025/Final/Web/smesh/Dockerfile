FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY app.js .
COPY views ./views

RUN echo "PCC{FAKE_FLAG}" > /flag.txt && chmod 444 /flag.txt

EXPOSE 3000

CMD ["node", "app.js"]

