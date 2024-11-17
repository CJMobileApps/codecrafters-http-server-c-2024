#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <zlib.h>

#define BUFFER_SIZE 1024
#define MAX_CONCURRENT_CONNECTIONS 5  // Limit to 5 concurrent connections
char directoryName[256] = "";

// GZIP Constants
char *gzipAcceptedEncoding = "gzip";
#define GZIP_HEADER_FOOTER_SIZE 100
#define ZLIB_COMPRESSION_LEVEL Z_BEST_COMPRESSION
#define GZIP_WINDOW_BITS (15 + 16)
#define ZLIB_MEM_LEVEL 8

pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex to protect the active_connections counter
int active_connections = 0; // Shared counter to track the number of active connections

char *int_to_string(const int value) {
    // Determine the length needed for the string (including the null terminator)
    int length = snprintf(NULL, 0, "%d", value);

    // Allocate memory for the string
    char *result = malloc(length + 1);
    if (result == NULL) {
        return NULL; // Handle allocation failure
    }

    // Convert the integer to a string
    snprintf(result, length + 1, "%d", value);

    return result;
}

//todo why is this broke?
// Function to split a string by spaces and return an array of tokens
char **split_string_by_separator(const char *input, int *out_count, const char *separator) {
    int capacity = 10; // Initial capacity for the tokens array
    int count = 0; // Number of tokens found so far

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
    const char *token = strtok(input_copy, separator);
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
    char *body;
    int size;
} ResponseBody;


ResponseBody *initResponseBody() {
    ResponseBody *responseBody = malloc(sizeof(ResponseBody));
    responseBody->body = strdup(""); // Initialize the pointer to NULL for safety
    responseBody->size = 0;
    return responseBody;
}

void freeResponseBody(ResponseBody *responseBody) {
    responseBody->body = strdup(""); // Initialize the pointer to NULL for safety
    free(responseBody->body);

    responseBody->size = 0;
}

typedef struct {
    char *httpVersion;
    char *content;
    char *statusCode;
    char *optionalReasonPhrase;
    int contentLength;
    char *contentType;
    char *contentEncoding;
} ServerResponse;

ServerResponse *buildServerResponse() {
    ServerResponse *serverResponse = malloc(sizeof(ServerResponse));
    serverResponse->httpVersion = strdup("");
    serverResponse->content = strdup("");
    serverResponse->statusCode = strdup("");
    serverResponse->optionalReasonPhrase = strdup("");
    serverResponse->contentType = strdup("");
    serverResponse->contentEncoding = strdup("");

    serverResponse->httpVersion = "HTTP/1.1";

    return serverResponse;
}

void freeServerResponse(ServerResponse *serverResponse) {
    serverResponse->httpVersion = strdup("");
    free(serverResponse->httpVersion);

    serverResponse->content = strdup("");
    free(serverResponse->content);

    serverResponse->statusCode = strdup("");
    free(serverResponse->statusCode);

    serverResponse->optionalReasonPhrase = strdup("");
    free(serverResponse->optionalReasonPhrase);

    serverResponse->contentType = strdup("");
    free(serverResponse->contentType);

    serverResponse->contentEncoding = strdup("");
    free(serverResponse->contentEncoding);
}

void getResponseBody(ServerResponse *serverResponse, ResponseBody *responseBody) {
    if (responseBody == NULL) return;

    // Handle NULL or invalid input
    if (serverResponse == NULL || serverResponse->content == NULL) {
        responseBody->size = 0;
        responseBody->body = strdup("");
        return;
    }

    // Check for GZIP encoding
    if (strstr(serverResponse->contentEncoding, "gzip") != NULL) {
        const char *input = serverResponse->content;
        const size_t input_len = strlen(input);

        // Allocate memory for the compressed data
        const size_t max_compressed_len = input_len + GZIP_HEADER_FOOTER_SIZE;
        char *compressed = malloc(max_compressed_len);
        if (compressed == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            responseBody->size = 0;
            responseBody->body = strdup("");
            return;
        }

        // Initialize zlib stream
        z_stream stream = {0};
        if (deflateInit2(&stream, ZLIB_COMPRESSION_LEVEL, Z_DEFLATED, GZIP_WINDOW_BITS, ZLIB_MEM_LEVEL,
                         Z_DEFAULT_STRATEGY) != Z_OK) {
            fprintf(stderr, "Failed to initialize deflate stream\n");
            free(compressed);
            responseBody->size = 0;
            responseBody->body = strdup("");
            return;
        }

        // Configure input and output for compression
        stream.avail_in = input_len;
        stream.next_in = (unsigned char *) input;
        stream.avail_out = max_compressed_len;
        stream.next_out = (unsigned char *) compressed;

        // Perform compression
        if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
            fprintf(stderr, "Compression failed\n");
            deflateEnd(&stream);
            free(compressed);
            return;
        }

        // Get compressed length
        const size_t compressed_len = max_compressed_len - stream.avail_out;

        // Clean up zlib stream
        deflateEnd(&stream);

        // Update server response and response body
        serverResponse->contentLength = (int) compressed_len;
        responseBody->size = (int) compressed_len;
        responseBody->body = compressed;
    } else {
        // Return original content if not GZIP-encoded
        responseBody->size = (int) strlen(serverResponse->content);
        responseBody->body = strdup(serverResponse->content);
    }
}

char *getStatusLine(const ServerResponse *serverResponse) {
    const char *crlfStatusLine = "\r\n";
    if (serverResponse == NULL) {
        char *newString = malloc(strlen(crlfStatusLine) + 1);
        strcpy(newString, crlfStatusLine);
        return newString;
    }

    const char *space = " ";

    char *newString = malloc(strlen(serverResponse->httpVersion)
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

char *getHeader(const ServerResponse *serverResponse) {
    // Headers (Empty)
    const char *crlfHeadersLine = "\r\n";

    if (serverResponse == NULL) {
        char *contentLength = malloc(strlen(crlfHeadersLine) + 1);
        return contentLength;
    }

    const char *contentLengthPreString = "Content-Length: ";
    const char *contentLengthPostString = "\r\n";

    char *contentLengthToString = int_to_string(serverResponse->contentLength);

    char *contentLength = malloc(
        strlen(contentLengthPreString)
        + strlen(contentLengthToString)
        + strlen(contentLengthPostString)
        + 1
    );

    strcpy(contentLength, contentLengthPreString);
    strcat(contentLength, contentLengthToString);
    strcat(contentLength, contentLengthPostString);

    // val contentEncoding = if(encoding.isNotEmpty()) "Content-Encoding: $encoding\r\n" else ""
    const char *contentEncoding;
    if (serverResponse->contentEncoding != NULL && serverResponse->contentEncoding[0] != '\0') {
        const char *contentEncodingPreString = "Content-Encoding: ";
        const char *contentEncodingPostString = "\r\n";

        contentEncoding = malloc(
            strlen(contentLengthPreString)
            + strlen(serverResponse->contentEncoding)
            + strlen(contentLengthPostString)
            + 1
        );

        strcpy(contentEncoding, contentEncodingPreString);
        strcat(contentEncoding, serverResponse->contentEncoding);
        strcat(contentEncoding, contentEncodingPostString);
    } else {
        contentEncoding = "";
    }

    char *headerResponse = malloc(
        strlen(serverResponse->contentType)
        + strlen(contentEncoding)
        + strlen(contentLength)
        + strlen(crlfHeadersLine)
        + 1
    );
    // return "$contentType$contentEncoding$contentLength$crlfHeadersLine"
    strcpy(headerResponse, serverResponse->contentType);
    strcat(headerResponse, contentEncoding);
    strcat(headerResponse, contentLength);
    strcat(headerResponse, crlfHeadersLine);


    free(contentLengthToString);
    return headerResponse;
}

char *getServerResponse(ServerResponse *serverResponse, ResponseBody *responseBody) {
    char *statusLine = getStatusLine(serverResponse);

    getResponseBody(serverResponse, responseBody);
    char *header = getHeader(serverResponse);


    const size_t size = strlen(statusLine) + strlen(header) + 1;
    char *str = malloc(size);
    strcpy(str, statusLine);
    strcat(str, header);

    free(header);
    free(statusLine);

    return str;
}

typedef struct {
    char *requestStatusLine;
    char *requestHostPort;
    char *requestUserAgent;
    char *requestHeader;
    char *requestContentLength;
    long contentLength;
    char *requestBody;
    char *requestContentEncoding;
    char *requestContent;
} ServerRequest;

void freeServerRequest(ServerRequest *serverRequest) {
    serverRequest->requestStatusLine = strdup("");
    free(serverRequest->requestStatusLine);

    serverRequest->requestHostPort = strdup("");
    free(serverRequest->requestHostPort);

    serverRequest->requestUserAgent = strdup("");
    free(serverRequest->requestUserAgent);

    serverRequest->requestHeader = strdup("");
    free(serverRequest->requestHeader);

    serverRequest->requestContentLength = strdup("");
    free(serverRequest->requestContentLength);

    serverRequest->requestBody = strdup("");
    free(serverRequest->requestBody);

    serverRequest->requestContentEncoding = strdup("");
    free(serverRequest->requestContentEncoding);

    serverRequest->requestContent = strdup("");
    free(serverRequest->requestContent);
}


ServerRequest *parseClientRequest(char *line, char *savePtr) {
    ServerRequest *serverRequest = malloc(sizeof(ServerRequest));
    serverRequest->requestStatusLine = strdup("");
    serverRequest->requestHostPort = strdup("");
    serverRequest->requestUserAgent = strdup("");
    serverRequest->requestHeader = strdup("");
    serverRequest->requestContentLength = strdup("");
    serverRequest->requestBody = strdup("");
    serverRequest->requestContentEncoding = strdup("");
    serverRequest->requestContent = strdup("");

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

            int pathCount;

            // echo/abc
            char **pathArray = split_string_by_separator(line, &pathCount, " ");

            if (pathCount >= 2) {
                char *end;
                const long contentLength = strtol(pathArray[1], &end, 10);
                serverRequest->contentLength = contentLength;
            }

            free(pathArray);
            printf("%s\n", serverRequest->requestContentLength);
        }

        if (strstr(line, "Accept-Encoding: ") != NULL) {
            serverRequest->requestContentEncoding = line;
            printf("%s\n", serverRequest->requestContentEncoding);
        }

        // get request body from POST
        if (strlen(line) == serverRequest->contentLength) {
            serverRequest->requestContent = line;
            printf("%s\n", serverRequest->requestContent);
        }

        line = strtok_r(NULL, "\n", &savePtr);
    }

    // ReSharper disable once CppDFAMemoryLeak
    return serverRequest;
}

void setCreatedServerResponse(ServerResponse *serverResponse) {
    if (serverResponse == NULL) return;

    serverResponse->statusCode = "201";
    serverResponse->optionalReasonPhrase = "Created";
}

void setFoundOkServerResponse(ServerResponse *serverResponse) {
    if (serverResponse == NULL) return;

    serverResponse->statusCode = "200";
    serverResponse->optionalReasonPhrase = "OK";
}

void setContentOctetStreamServerResponse(ServerResponse *serverResponse, char *content) {
    if (serverResponse == NULL) return;

    serverResponse->content = content;
    serverResponse->contentLength = (int) strlen(content);
    serverResponse->contentType = "Content-Type: application/octet-stream\r\n";
}

void setContentTextPlainServerResponse(ServerResponse *serverResponse, char *content) {
    if (serverResponse == NULL) return;

    serverResponse->content = content;
    serverResponse->contentLength = (int) strlen(content);
    serverResponse->contentType = "Content-Type: text/plain\r\n";
}

void setNotFoundServerResponse(ServerResponse *serverResponse) {
    if (serverResponse == NULL) return;

    serverResponse->statusCode = "404";
    serverResponse->optionalReasonPhrase = "Not Found";
}

void setCreated201ServerResponse(ServerResponse *serverResponse) {
    if (serverResponse == NULL) return;

    serverResponse->statusCode = "201";
    serverResponse->optionalReasonPhrase = "Created";
}

void buildResponseStatusLine(const ServerRequest *serverRequest, ServerResponse *serverResponse) {
    if (serverRequest == NULL) return;
    if (serverResponse == NULL) return;

    if (serverRequest->requestContentEncoding != NULL) {
        int requestContentEncodingArrayCount = 0; // Variable to store the number of tokens

        // Call the split function and retrieve the tokens array
        char **requestContentEncodingArray = split_string_by_separator(
            serverRequest->requestContentEncoding,
            &requestContentEncodingArrayCount,
            " "
        );

        for (int i = 0; i < requestContentEncodingArrayCount; i++) {
            const char *contentEncodingString = requestContentEncodingArray[i];

            if (strstr(contentEncodingString, gzipAcceptedEncoding) != NULL) {
                char *contentEncoding = gzipAcceptedEncoding;
                serverResponse->contentEncoding = contentEncoding;
            }
        }
    }

    int requestStatusLineArrayCount = 0; // Variable to store the number of tokens

    // Call the split function and retrieve the tokens array
    char **requestStatusLineArray = split_string_by_separator(
        serverRequest->requestStatusLine,
        &requestStatusLineArrayCount,
        " "
    );

    if (requestStatusLineArrayCount >= 2) {
        if (strcmp(requestStatusLineArray[1], "/") == 0) {
            setContentTextPlainServerResponse(serverResponse, "");
            setFoundOkServerResponse(serverResponse);
        } else if (strstr(requestStatusLineArray[1], "/echo/") != NULL) {
            int pathCount;

            // echo/abc
            char **pathArray = split_string_by_separator(requestStatusLineArray[1], &pathCount, "/");

            if (pathCount <= 2) {
                setContentTextPlainServerResponse(serverResponse, pathArray[1]);
                setFoundOkServerResponse(serverResponse);
            } else {
                setContentTextPlainServerResponse(serverResponse, "");
                setNotFoundServerResponse(serverResponse);
            }
        } else if (strstr(requestStatusLineArray[1], "/user-agent") != NULL) {
            int userAgentCount;

            // User-Agent: foobar/1.2.3
            char **userAgentArray = split_string_by_separator(serverRequest->requestUserAgent, &userAgentCount, " ");

            char *userAgent = userAgentArray[1];

            // Remove last character I think it's a space
            const size_t len = strlen(userAgent);
            if (len > 0) {
                userAgent[len - 1] = '\0'; // Replace the last character with the null terminator
            }

            setContentTextPlainServerResponse(serverResponse, userAgent);
            setFoundOkServerResponse(serverResponse);
        } else if (strstr(requestStatusLineArray[1], "/files/") != NULL) {
            int pathCount;

            // echo/abc
            char **pathArray = split_string_by_separator(requestStatusLineArray[1], &pathCount, "/");

            if (pathCount <= 2) {
                if (strstr(serverRequest->requestStatusLine, "GET") != NULL) {
                    char *fileName = malloc(
                        strlen(directoryName)
                        + strlen(pathArray[1])
                        + 1
                    );

                    strcpy(fileName, directoryName);
                    strcat(fileName, pathArray[1]);

                    FILE *file = fopen(fileName, "r");
                    if (file == NULL) {
                        perror("Error opening file");
                        setContentTextPlainServerResponse(serverResponse, "");
                        setNotFoundServerResponse(serverResponse);
                        return;
                    }

                    // Define a buffer and read the file in chunks
                    // Dynamically allocate the buffer
                    const size_t bufferSize = 1024;
                    size_t bytesRead;
                    char *buffer = malloc(bufferSize);

                    while ((bytesRead = fread(buffer, 1, bufferSize, file)) > 0) {
                        // Write the buffer contents to standard output
                        fwrite(buffer, 1, bytesRead, stdout);
                    }

                    fclose(file);

                    setContentOctetStreamServerResponse(serverResponse, buffer);
                    setFoundOkServerResponse(serverResponse);
                } else if (strstr(serverRequest->requestStatusLine, "POST") != NULL) {
                    char *fileName = malloc(
                        strlen(directoryName)
                        + strlen(pathArray[1])
                        + 1
                    );
                    strcpy(fileName, directoryName);
                    strcat(fileName, pathArray[1]);

                    FILE *file = fopen(fileName, "w+");
                    if (file == NULL) {
                        perror("Error opening file");
                        return;
                    }

                    const size_t bytesWritten = fwrite(
                        serverRequest->requestContent, sizeof(char),
                        strlen(serverRequest->requestContent), file
                    );
                    if (bytesWritten != strlen(serverRequest->requestContent)) {
                        perror("Error writing to file");
                    }

                    free(fileName);
                    fclose(file);
                    setContentTextPlainServerResponse(serverResponse, "");
                    setCreated201ServerResponse(serverResponse);
                }
            } else {
                setContentTextPlainServerResponse(serverResponse, "");
                setNotFoundServerResponse(serverResponse);
            }
        } else {
            setContentTextPlainServerResponse(serverResponse, "");
            setNotFoundServerResponse(serverResponse);
        }
    }
    free(requestStatusLineArray);
    // ReSharper disable once CppDFAMemoryLeak
}

void *createServer(int server_fd, char *buffer);

// Wrapper function to call createServer
void *threadWrapper(void *arg) {
    printf("Waiting for a client to connect...\n");
    const int server_fd = *(int *) arg; // Unpack the server_fd from the passed argument
    char buffer[BUFFER_SIZE] = {0}; // Buffer for reading requests

    // Wait for the active_connections to be less than the maximum allowed
    pthread_mutex_lock(&connection_mutex);
    active_connections++;
    pthread_mutex_unlock(&connection_mutex);


    createServer(server_fd, buffer); // Call the actual server function
    return NULL;
}

void *createServer(const int server_fd, char *buffer) {
    int client_addr_len;

    int new_socket;
    struct sockaddr_in client_addr;

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

    ResponseBody *responseBody = initResponseBody();

    char *response = getServerResponse(serverResponse, responseBody);

    // Write and send response to the client
    const long writeRequestClient = write(new_socket, response, strlen(response));
    if (writeRequestClient < 0) {
        perror("Send Response failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Response sent to client\n%s\n", response);
    printf("responseBody->size %d\n", responseBody->size);
    printf("responseBody->body %s\n", responseBody->body);

    const long writeRequestClient2 = write(new_socket, responseBody->body, responseBody->size);
    if (writeRequestClient2 < 0) {
        perror("Send Response 2 failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    free(response);
    freeResponseBody(responseBody);
    freeServerResponse(serverResponse);
    free(serverResponse);
    freeServerRequest(serverRequest);
    free(serverRequest);

    // Close the connection with the client
    close(new_socket);

    // Decrement the active_connections counter after finishing the request
    pthread_mutex_lock(&connection_mutex);
    active_connections--;
    pthread_mutex_unlock(&connection_mutex);

    return NULL;
}

// argc: (argument count)
// argv: (argument vector) is an array of C strings (character pointers) that represents each argument passed to the program.
int main(const int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    printf("Logs from your program will appear here!\n");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
            // Copy the next argument as the directory path
            strncpy(directoryName, argv[i + 1], sizeof(directoryName) - 1);
            directoryName[sizeof(directoryName) - 1] = '\0'; // Null-terminate to avoid overflow
            break;
        }
    }

    if (strlen(directoryName) > 1) {
        printf("args --directory name is %s\n", directoryName);
    }

    // Create socket file descriptor
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    while (true) {
        pthread_t thread;

        if (active_connections > MAX_CONCURRENT_CONNECTIONS) continue;
        printf("active_connections: %d\n", active_connections);
        pthread_create(&thread, NULL, threadWrapper, &server_fd);
        pthread_detach(thread);
    }

    //free(server_fd); (this will never be reached)
    return 0;
}
