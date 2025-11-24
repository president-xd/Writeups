docker build --tag=web-desires . && \
docker run -p 1337:1337 --rm --name=web-desires -it web-desires