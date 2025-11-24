FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y curl wget git supervisor redis-server

ENV GO_VERSION=1.22.2

RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV NODE_VERSION=20.x

RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION} | bash - && \
    apt-get install -y nodejs

RUN go version && node --version && npm --version

WORKDIR /app/service
COPY challenge/service/ ./

RUN go mod tidy
RUN go build -o service .
RUN mkdir /app/service/uploads

WORKDIR /app/sso
COPY challenge/sso/package*.json ./
RUN npm ci 
COPY challenge/sso/ ./

COPY config/supervisord.conf /etc/supervisord.conf

ENV FLAG=HTB{REDACTED}

CMD service redis-server start  && /usr/bin/supervisord -c /etc/supervisord.conf




