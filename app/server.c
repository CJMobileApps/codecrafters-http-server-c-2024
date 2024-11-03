#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int main() {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    char buffer[BUFFER_SIZE] = {0};

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    printf("Logs from your program will appear here!\n");

    int client_addr_len, new_socket;
    struct sockaddr_in client_addr;

    // Create socket file descriptor
    const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Since the tester restarts your program quite often, setting SO_REUSEADDR
    // ensures that we don't run into 'Address already in use' errors
    const int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Define server address
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4221),
        .sin_addr = {htonl(INADDR_ANY)},
    };

    // Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    const int connection_backlog = 5;
    if (listen(server_fd, connection_backlog) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for a client to connect...\n");
    client_addr_len = sizeof(client_addr);

    if ((new_socket = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len)) < 0) {
        perror("Accept Failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Client connected\n");

    // Read the request from the client
    const long readRequestClient = read(new_socket, buffer, BUFFER_SIZE);
    if (readRequestClient < 0) {
        perror("Read failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // printf("Received request:\n%s\n", buffer);
    printf("Received request: \n\n");


    char *savePtr;

    // Start processing the buffer by splitting it on newline characters
    char *line = strtok_r(buffer, "\n", &savePtr); // Get the first line

    while (line != NULL) {
        printf("%s\n", line);
        line = strtok_r(NULL, "\n", &savePtr);
    }

    // TODO this is a temp response
    const char *response =
        "HTTP/1.1 200 OK\r\n\r\n";

    // Write and send response to the client
    const long writeRequestClient = write(new_socket, response, strlen(response));
    if (writeRequestClient < 0) {
        perror("Send Response failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Response sent to client\n%s\n", response);

    // Close the connection with the client
    close(new_socket);
    close(server_fd);

    return 0;
}
