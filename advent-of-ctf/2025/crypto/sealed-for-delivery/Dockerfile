FROM python:3.11-slim

WORKDIR /app

RUN pip install pycryptodome

COPY chal.py server.py ./

CMD ["python", "-u", "server.py"]
