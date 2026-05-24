/*
 * This program will showcase the work of port scan
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

int check_port(const char *ip, int port) {
  int sock_fd;
  struct sockaddr_in target_addr;

  // 1. Create an active IPv4 TCP socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    perror("Socket creation failed");
    return -1;
  }

  // 2. Set a timeout so we don't hang forever on filtered ports
  struct timeval timeout;
  timeout.tv_sec = 2;       // 2 sec
  timeout.tv_usec = 0;

  // Set timeout for the connection attempt
  setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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
  int result = connect(sock_fd, (struct sockaddr *)&target_addr, sizeof(target_addr));

  // 5. Clean up the file descriptor immediately
  close(sock_fd);

  if (result == 0) {
    return 1;   // Port is OPEN 
  }
  else {
    return 0;  // Port is CLOSED or FILTERED
  }
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

    if (check_port(target_ip, port)) {
      printf("[+] Port %d is OPEN!\n", port);
    }
    else {
      printf("[-] Port %d is CLOSED or FILTERED\n", port);
    }

    return 0;
}
