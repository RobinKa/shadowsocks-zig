# Shadowsocks written in Zig

Client and server implementation of [Shadowsocks 2022](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md) written in [Zig](https://ziglang.org).

Shadowsocks 2022 is an encrypted proxy protocol utilizing a pre-shared key and was designed to be hard to detect to avoid government censorship.

## Features

The main function will run a server. The first argument will be used for the path to the json config (see the [configs directory](configs/) for examples). If no argument is passed, the environment variables `SHADOWSOCKS_PORT`, `SHADOWSOCKS_KEY` and `SHADOWSOCKS_METHOD` will be used and all need to be set.

The client is currently just a struct with an interface similar to sockets, see the [tests](src/shadowsocks/tests.zig) for how to use it.

The following encryption methods are currently supported:

- Blake3Aes128Gcm
- Blake3Aes256Gcm
- Blake3ChaCha8Poly1305
- Blake3ChaCha12Poly1305
- Blake3ChaCha20Poly1305

UDP is not yet supported.
