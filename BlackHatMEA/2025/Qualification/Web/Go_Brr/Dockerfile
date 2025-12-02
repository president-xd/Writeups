FROM golang:1.22-alpine AS builder

WORKDIR /app


COPY . .

RUN go build -o server app.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/server .
COPY --from=builder /app/app.py .

RUN apk add --no-cache python3 py3-pip supervisor
# RUN apk add py3-pip
RUN pip3 install requests flask --break-system-packages
EXPOSE 8081



# RUN apk add --no-cache supervisor

COPY supervisord.conf /etc/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
