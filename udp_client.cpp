#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

int main(){
    const char *AWS_IP = "3.110.91.204";
    const int PORT = 50000;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock<0) {
        perror("socket");
        return 1;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    inet_pton(AF_INET, AWS_IP, &serv.sin_addr);

    const char *msg = "hello-from-rpi";
    ssize_t sent = sendto(sock, msg, strlen(msg), 0, (sockaddr*)&serv, sizeof(serv));
    if(sent < 0){
        perror("sendto");
        return 1;
    }

       // wait for reply
    char buf[1500];
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fromlen);
    if (n < 0) { perror("recvfrom"); return 1; }
    buf[n] = 0;
    std::cout << "Got reply: " << buf << "\n";
    close(sock);
    return 0;
}