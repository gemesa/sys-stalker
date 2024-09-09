#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <string.h>

void send_info(const char *hostname, const char *port, const char *data) {
    struct addrinfo hints, *res;
    int sockfd;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, port, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        perror("socket");
        freeaddrinfo(res);
        return;
    }

    status = connect(sockfd, res->ai_addr, res->ai_addrlen);
    if (status == -1) {
        perror("connect");
        close(sockfd);
        freeaddrinfo(res);
        return;
    }

    printf("Sending data to %s:%s\n", hostname, port);

    if (send(sockfd, data, strlen(data), 0) == -1) {
        perror("send");
    } else {
        printf("Data sent successfully.\n");
    }

    close(sockfd);
    freeaddrinfo(res);
}

int main() {
    struct utsname sys_info;
    if (uname(&sys_info) == -1) {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    pid_t pid = getpid();

    printf("PID: %d\n", pid);

    char info[256];
    snprintf(info, sizeof(info),
             "System Info: %s %s %s %s %s, Process ID: %d\n",
             sys_info.sysname, sys_info.nodename, sys_info.release,
             sys_info.version, sys_info.machine, pid);

    printf("Collected info:\n%s", info);

    send_info("localhost", "8080", info);

    return 0;
}
