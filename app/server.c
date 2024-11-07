#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

// Function to split a string by spaces and return an array of tokens
char **split_string_by_space(const char *input, int *out_count) {
    int capacity = 10; // Initial capacity for the tokens array
    int count = 0;     // Number of tokens found so far

    // Allocate memory for the initial array of tokens
    // ReSharper disable once CppDFAMemoryLeak we free this when we return the function pointer
    char **tokens = malloc(capacity * sizeof(char *));

    if (tokens == NULL) {
        perror("Unable to allocate memory for tokens array");
        exit(EXIT_FAILURE);
    }

    // Create a modifiable copy of the input string (since strtok modifies the string)
    char *input_copy = strdup(input);
    if (input_copy == NULL) {
        perror("Unable to allocate memory for input copy");
        free(tokens); // Free the initial allocation before exiting
        exit(EXIT_FAILURE);
    }

    // Get the first token from the input string (splits by spaces)
    const char *token = strtok(input_copy, " ");
    while (token != NULL) {
        // Check if we need to expand the tokens array
        if (count >= capacity) {
            capacity *= 2; // Double the capacity for scalability

            // ReSharper disable once CppDFAMemoryLeak we free this when we return the function pointer
            tokens = realloc(tokens, capacity * sizeof(char *)); // NOLINT(*-suspicious-realloc-usage)
            if (tokens == NULL) {
                perror("Unable to reallocate memory for tokens array");
                free(input_copy); // Free the copy before exiting
                exit(EXIT_FAILURE);
            }
        }

        // Store a duplicate of the token in the tokens array
        tokens[count++] = strdup(token);

        // Get the next token from the input string
        token = strtok(NULL, " ");
    }

    // Free the copy of the input string since it is no longer needed
    free(input_copy);

    // Set the output count to the number of tokens found
    *out_count = count;

    // Return the array of tokens
    return tokens;
}

typedef struct {
    char *httpVersion;
    char *content;
    char *statusCode;
    char *optionalReasonPhrase;
//     val crlfStatusLine: String = "\r\n",
//     // contentBytes: ByteArray? = null,
//     // contentLength: String = "",
//     // contentType: String = "",
//     // encoding: String = "",
} ServerResponse;

ServerResponse *buildServerResponse() {
    ServerResponse *serverResponse = malloc(sizeof(ServerResponse));
    serverResponse->httpVersion = "HTTP/1.1";

    return serverResponse;
}


char* getResponseBody(ServerResponse *serverResponse) {
    char* responseBody = "";
    // if not gzip compression set responseBody
    // val responseBody = if(!encoding.contains(ServerState.AllowedEncoding.GZIP.name.lowercase())) {
    //
    //     getResponseBody() which will be serverResponse->content
    // } else ""

    return responseBody;
}

char* getStatusLine(const ServerResponse *serverResponse) {
    char *crlfStatusLine = "\r\n";
    if(serverResponse == NULL) return crlfStatusLine;

    const char *space = " ";

    char* newString = malloc(strlen(serverResponse->httpVersion)
        + strlen(serverResponse->statusCode)
        + strlen(space)
        + strlen(serverResponse->optionalReasonPhrase)
        + strlen(space)
        + strlen(crlfStatusLine)
        + 1
    );

    //return "$httpVersion $statusCode $optionalReasonPhrase$crlfStatusLine";
    strcpy(newString, serverResponse->httpVersion);
    strcat(newString, space);
    strcat(newString, serverResponse->statusCode);
    strcat(newString, space);
    strcat(newString, serverResponse->optionalReasonPhrase);
    strcat(newString, crlfStatusLine);

    return newString;
}

char* getHeader(const ServerResponse *serverResponse) {
    // Headers (Empty)
    char* crlfHeadersLine = "\r\n";

    if(serverResponse == NULL) return crlfHeadersLine;

    if(serverResponse->content == NULL ||   strcmp(serverResponse->content, "") == 0) {
        return crlfHeadersLine;
    }

    //  val contentLength = "Content-Length: ${this.contentLength}\r\n"
    //
    //  val contentEncoding = if(encoding.isNotEmpty()) "Content-Encoding: $encoding\r\n" else ""
    //
    //  return "$contentType$contentEncoding$contentLength$crlfHeadersLine"

    return "";
}

char* getServerResponse(ServerResponse *serverResponse) {
    char *statusLine = getStatusLine(serverResponse);
    const char *header = getHeader(serverResponse);
    const char *responseBody = getResponseBody(serverResponse);


    const size_t size = strlen(statusLine) + strlen(header) + strlen(responseBody) + 1;
    char *str = malloc(size);
    strcpy(str, statusLine);
    strcat(str, header);
    strcat(str, responseBody);

    return str;
}

typedef struct {
    char *requestStatusLine;
    char *requestHostPort;
    char *requestUserAgent;
    char *requestHeader;
    char *requestContentLength;
    char *requestBody;
    char *requestContentEncoding;
} ServerRequest;

ServerRequest *parseClientRequest(char *line, char *savePtr) {
    ServerRequest *serverRequest = malloc(sizeof(ServerRequest));

    while (line != NULL) {
        if (strstr(line, "GET") != NULL
            || strstr(line, "POST") != NULL
            || strstr(line, "PUT") != NULL
            || strstr(line, "DELETE") != NULL
        ) {
            serverRequest->requestStatusLine = line;
            printf("%s\n", serverRequest->requestStatusLine);
        }

        if (strstr(line, "Host: ") != NULL) {
            serverRequest->requestHostPort = line;
            printf("%s\n", serverRequest->requestHostPort);
        }

        if (strstr(line, "User-Agent: ") != NULL) {
            serverRequest->requestUserAgent = line;
            printf("%s\n", serverRequest->requestUserAgent);
        }

        if (strstr(line, "Content-Length: ") != NULL) {
            serverRequest->requestContentLength = line;
            printf("%s\n", serverRequest->requestContentLength);
        }

        if (strstr(line, "Accept-Encoding: ") != NULL) {
            serverRequest->requestContentEncoding = line;
            printf("%s\n", serverRequest->requestContentEncoding);
        }

        line = strtok_r(NULL, "\n", &savePtr);
    }

    return serverRequest;
}

void setCreatedServerResponse(ServerResponse *serverResponse) {
    if(serverResponse == NULL) return;

    serverResponse->statusCode = "201";
    serverResponse->optionalReasonPhrase = "Created";
}

void setFoundOkServerResponse(ServerResponse *serverResponse) {
    if(serverResponse == NULL) return;

    serverResponse->statusCode = "200";
    serverResponse->optionalReasonPhrase = "OK";
}

void setNotFoundServerResponse(ServerResponse *serverResponse) {
    if(serverResponse == NULL) return;

    serverResponse->statusCode = "404";
    serverResponse->optionalReasonPhrase = "Not Found";
}

void buildResponseStatusLine(const ServerRequest *serverRequest, ServerResponse *serverResponse) {
    if(serverRequest == NULL) return;

    int count; // Variable to store the number of tokens

    // Call the split function and retrieve the tokens array
    char **result = split_string_by_space(serverRequest->requestStatusLine, &count);

    if(count >= 2) {
        if (strcmp(result[1], "/") == 0) {
            setFoundOkServerResponse(serverResponse);
        } else {
            setNotFoundServerResponse(serverResponse);
        }
    }
    free(result);
    // ReSharper disable once CppDFAMemoryLeak
}

void main() {
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

    ServerRequest *serverRequest = parseClientRequest(line, savePtr);

    ServerResponse *serverResponse = buildServerResponse();

    buildResponseStatusLine(serverRequest, serverResponse);

    char *response = getServerResponse(serverResponse);

    // Write and send response to the client
    const long writeRequestClient = write(new_socket, response, strlen(response));
    if (writeRequestClient < 0) {
        perror("Send Response failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Response sent to client\n%s\n", response);

    free(response);
    free(serverResponse);
    free(serverRequest);


    // Close the connection with the client
    close(new_socket);
    close(server_fd);
}
