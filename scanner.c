/*
 * This program will showcase the work of port scan
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

//TCP connect
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

void post(const int status, const int port);

int check_port(const char *ip, int port) {
  struct sockaddr_in target_addr;

  // 1. Create an active IPv4 TCP socket
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    perror("Socket creation failed");
    return -1;
  }

  fcntl(sock_fd, F_SETFL, O_NONBLOCK);

  // 2. Set a timeout so we don't hang forever on filtered ports
  struct timeval timeout;
  timeout.tv_sec = 2;       // 2 sec
  timeout.tv_usec = 0;

  // 3.Configure target details
  target_addr.sin_family = AF_INET;
  target_addr.sin_port = htons(port);   // Byte order conversion

  // Convert text IP (e.g "127.0.0.1") to binary form
  if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
    printf("[!] Invalid Ip address structure\n");
    close(sock_fd);
    return -1;
  }

  // 4. Attempt to connect to the remote host
  // connect() return 0 if the three-way handshake succeds
  int status = connect(sock_fd, (struct sockaddr *)&target_addr, sizeof(target_addr));

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(sock_fd, &fdset);
  int result = select(sock_fd + 1, NULL, &fdset, NULL, &timeout);
  
  //status = 2:  FILTERED
  //status = 1:  OPEN
  //status = 0:  CLOSED

  // 5. Clean up the file descriptor immediately

  if (result > 0) {
    int erro = 0;
    socklen_t len = sizeof(erro);
    getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &erro, &len);
    status = (erro == 0) ? 1 : 0;  // 0 = CLOSED, 1 = OPEN
  }
  else if(result == 0) {status = 2;}  // Port is CLOSED or FILTERED
  else {status = 0;}

  close(sock_fd);
  return status;
}

int main(int argc, char *argv[] ) {
  if (argc != 3) {
    printf("Usage: %s <Target Ip> <Port>\n", argv[0]);
    printf("Example: %s 127.0.0.1 80\n", argv[0]);
    return 1;
  }

    char *target_ip = argv[1];
    int port = atoi(argv[2]);   // Convert string argument to integer

    printf("[*] Probing %s on port %d...\n", target_ip, port);

    post(check_port(target_ip, port), port);

    return 0;
}

void post(const int status, const int port) {
    switch (status) {
        case 2:
            printf("[-] Port %d is FILTERED\n", port);
            break;
        case 1:
            printf("[+] Port %d is OPEN!\n", port);
            break;
        case 0:
            printf("[-] Port %d is CLOSED\n", port);
            break;
    }
}
