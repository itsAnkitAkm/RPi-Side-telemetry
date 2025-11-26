// rpi_dtls_client.cpp
// Minimal DTLS client (mbedTLS), blocking handshake, sends one application payload and exits.
//
// Build:
//   g++ -std=c++17 rpi_dtls_client.cpp -o rpi_dtls_client -lmbedtls -lmbedx509 -lmbedcrypto
//
// Replace SERVER_IP with your AWS public IP before running.

#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

static const char* SERVER_IP = "YOUR_AWS_PUBLIC_IP"; // <--- REPLACE THIS
static const int SERVER_PORT = 4444;
static const char* PSK_IDENTITY = "drone-D123";
static const char* PSK_HEX = "73656372657450534b"; // must match server

static void print_mbed_err(int ret, const char *where) {
    char errbuf[200];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    std::cerr << where << " error: " << errbuf << " (" << ret << ")\n";
}

static std::vector<unsigned char> hex2bin(const char* hex) {
    std::vector<unsigned char> out;
    size_t len = strlen(hex);
    out.reserve(len/2);
    for(size_t i=0;i+1<len;i+=2){
        unsigned int v=0;
        sscanf(hex+i, "%02x", &v);
        out.push_back((unsigned char)v);
    }
    return out;
}

// BIO context
struct bio_ctx {
    int fd;
    sockaddr_in peer;
    socklen_t peerlen;
};

// send callback: matches mbedtls_ssl_send_t
static int bio_send(void *v, const unsigned char *buf, size_t len) {
    bio_ctx *c = reinterpret_cast<bio_ctx*>(v);
    ssize_t s = sendto(c->fd, buf, len, 0, (sockaddr*)&(c->peer), c->peerlen);
    if (s < 0) {
        perror("sendto");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return (int)s;
}

// recv callback (non-timeout): matches mbedtls_ssl_recv_t
static int bio_recv(void *v, unsigned char *buf, size_t len) {
    bio_ctx *c = reinterpret_cast<bio_ctx*>(v);
    sockaddr_in from;
    socklen_t flen = sizeof(from);
    // Non-blocking, return WANT_READ if no data
    ssize_t r = recvfrom(c->fd, buf, len, MSG_DONTWAIT, (sockaddr*)&from, &flen);
    if (r < 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    // optional: ensure packet from server peer
    // (we accept any packet here — change if you want strict check)
    return (int)r;
}

// recv with timeout: matches mbedtls_ssl_recv_timeout_t
static int bio_recv_timeout(void *v, unsigned char *buf, size_t len, uint32_t timeout_ms) {
    bio_ctx *c = reinterpret_cast<bio_ctx*>(v);
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(c->fd, &rf);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(c->fd + 1, &rf, nullptr, nullptr, &tv);
    if (sel == 0) {
        // timeout
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    if (sel < 0) {
        perror("select");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t r = recvfrom(c->fd, buf, len, 0, (sockaddr*)&from, &flen);
    if (r < 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    // optional: check from == expected server peer
    return (int)r;
}

int main(){
    // create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv.sin_addr) != 1) {
        std::cerr << "[client] invalid SERVER_IP\n"; return 1;
    }

    // mbedTLS init
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_context entropy;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    mbedtls_ctr_drbg_init(&ctr);
    mbedtls_entropy_init(&entropy);

    const char *pers = "dtls-client";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        std::cerr << "ctr_drbg_seed failed\n"; return 1;
    }

    if (mbedtls_ssl_config_defaults(&conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        std::cerr << "ssl_config_defaults failed\n"; return 1;
    }

    // set PSK
    auto psk = hex2bin(PSK_HEX);
    if (mbedtls_ssl_conf_psk(&conf, psk.data(), psk.size(),
                             (const unsigned char*)PSK_IDENTITY, strlen(PSK_IDENTITY)) != 0) {
        std::cerr << "conf_psk failed\n"; return 1;
    }

    mbedtls_ssl_setup(&ssl, &conf);

    // set BIO context & callbacks
    bio_ctx ctx;
    ctx.fd = sock;
    ctx.peer = serv;
    ctx.peerlen = sizeof(serv);

    mbedtls_ssl_set_bio(&ssl, &ctx, bio_send, bio_recv, bio_recv_timeout);

    // handshake (blocking-ish)
    int ret;
    int tries = 0;
    const int MAX_TRIES = 3000;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (++tries > MAX_TRIES) { std::cerr << "[client] handshake timeout\n"; return 1; }
            usleep(1000);
            continue;
        } else {
            print_mbed_err(ret, "handshake");
            return 1;
        }
    }
    std::cout << "[client] handshake OK\n";

    // send application message
    char payload[256];
    snprintf(payload, sizeof(payload), "MAVLINK-TEST: Hello from RPi, ts=%ld", time(nullptr));
    int w = mbedtls_ssl_write(&ssl, (const unsigned char*)payload, strlen(payload));
    if (w < 0) {
        print_mbed_err(w, "ssl_write");
    } else {
        std::cout << "[client] sent " << w << " bytes\n";
    }

    // optional: wait for server reply
    unsigned char buf[1500];
    int rlen = mbedtls_ssl_read(&ssl, buf, sizeof(buf)-1);
    if (rlen > 0) {
        buf[rlen] = 0;
        std::cout << "[client] recv: " << (char*)buf << "\n";
    } else if (rlen == MBEDTLS_ERR_SSL_WANT_READ || rlen == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // nothing received - okay
    } else if (rlen < 0) {
        print_mbed_err(rlen, "ssl_read");
    }

    // cleanup
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    close(sock);
    return 0;
}
