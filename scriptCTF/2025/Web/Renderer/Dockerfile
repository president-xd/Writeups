FROM python:3.10-alpine3.19

RUN apk update && apk add socat && adduser -D -h /home/chall -s /bin/bash chall
RUN pip install Flask
COPY app.py /home/chall/app.py
COPY ./static/ /home/chall/static
COPY ./templates/ /home/chall/templates
RUN chown -R chall:chall /home/chall/

USER chall

WORKDIR /home/chall
CMD ["python", "app.py"]
