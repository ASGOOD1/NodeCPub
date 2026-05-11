
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libpcre2-dev \
        libssl-dev \
        libsqlite3-dev \
        libncurses-dev \
        uuid-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY src/ ./

RUN gcc -o antivirus_server \
        server.c \
        scanner.c \
        pe_scanner.c \
        base64.c \
        sha256.c \
        -I. \
        -lpthread \
        -lpcre2-8 \
        -lssl -lcrypto \
        -lsqlite3 \
        -luuid \
        -Wall -Wextra -O2 -Werror

        
RUN gcc -o admin \
        admin.c \
        sha256.c \
        -I. \
        -lpthread \
        -lncurses \
        -lssl -lcrypto \
        -Wall -Wextra -O2 -Werror

        
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 \
        libssl3 \
        libsqlite3-0 \
        libncurses6 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 appuser

WORKDIR /app

COPY --from=builder /build/antivirus_server .
COPY --from=builder /build/admin .

COPY users.db .

COPY src/dist ./src/dist/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080 8081 9000

ENTRYPOINT ["./antivirus_server"]