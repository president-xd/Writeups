FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    libpng16-16 \
    libjpeg62-turbo \
    libgomp1 \
    libxml2 \
    libltdl7 \
    libfontconfig1 \
    libfreetype6 \
    libx11-6 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' --home /home/chall --shell /bin/bash chall

RUN pip install flask

WORKDIR /home/chall

COPY main.py /home/chall/
COPY logo.png /home/chall/
COPY public/ /home/chall/public/
COPY magick/ /home/chall/magick/

RUN mkdir -p /home/chall/uploads

ENV LD_LIBRARY_PATH=/home/chall/magick/lib:$LD_LIBRARY_PATH

RUN chown -R chall:chall /home/chall
RUN chmod +x /home/chall/magick/bin/*

USER chall

# Expose port
EXPOSE 5000

CMD ["python", "main.py"]
