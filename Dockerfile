FROM alpine:3.17

WORKDIR /app
COPY ./zig-out/bin/main .
COPY ./configs/config.json .

ENTRYPOINT [ "/app/main", "config.json" ]
