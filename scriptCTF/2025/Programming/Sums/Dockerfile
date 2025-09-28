FROM python:3.10-alpine3.19

RUN apk update && apk add socat && adduser -D -h /home/chall -s /bin/bash chall
WORKDIR /home/chall
COPY server.py /home/chall/server.py
COPY solve /home/chall/solve
RUN chmod +x /home/chall/solve

USER chall
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python /home/chall/server.py"]

