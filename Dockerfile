FROM alpine:3.17 as builder

WORKDIR /app
RUN apk update && apk add zig --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
COPY build.zig ./
COPY ./libs ./libs
COPY ./src ./src
RUN zig build -Drelease-safe

FROM alpine:3.17

WORKDIR /app
COPY --from=builder /app/zig-out/bin/main .

ENTRYPOINT [ "/app/main", "config.json" ]
