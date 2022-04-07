#include <cstring>
#include <sys/stat.h>
#include <fstream>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>


const size_t BUFFER_SIZE = 65507;

// Evaluate `x`: if non-zero, describe it as a standard error code and exit with an error.
#define CHECK(x)                                                          \
    do {                                                                  \
        int err = (x);                                                    \
        if (err != 0) {                                                   \
            fprintf(stderr, "Error: %s returned %d in %s at %s:%d\n%s\n", \
                #x, err, __func__, __FILE__, __LINE__, strerror(err));    \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Evaluate `x`: if false, print an error message and exit with an error.
#define ENSURE(x)                                                         \
    do {                                                                  \
        bool result = (x);                                                \
        if (!result) {                                                    \
            fprintf(stderr, "Error: %s was false in %s at %s:%d\n",       \
                #x, __func__, __FILE__, __LINE__);                        \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Check if errno is non-zero, and if so, print an error message and exit with an error.
#define PRINT_ERRNO()                                                  \
    do {                                                               \
        if (errno != 0) {                                              \
            fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n",    \
              errno, __func__, __FILE__, __LINE__, strerror(errno));   \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)


// Set `errno` to 0 and evaluate `x`. If `errno` changed, describe it and exit.
#define CHECK_ERRNO(x)                                                             \
    do {                                                                           \
        errno = 0;                                                                 \
        (void) (x);                                                                \
        PRINT_ERRNO();                                                             \
    } while (0)

// Note: the while loop above wraps the statements so that the macro can be used with a semicolon
// for example: if (a) CHECK(x); else CHECK(y);


// Print an error message and exit with an error.
void fatal(const char *fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}


uint16_t read_port(char *string) {
    errno = 0;
    unsigned long port = strtoul(string, NULL, 10);
    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        fatal("%ul is not a valid port number", port);
    }

    return (uint16_t) port;
}

int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket
    ENSURE(socket_fd > 0);
    // after socket() call; we should close(sock) on any execution path;

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
    server_address.sin_port = htons(port);

    // bind the socket to a concrete address
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                        (socklen_t) sizeof(server_address)));

    return socket_fd;
}

size_t read_message(int socket_fd, struct sockaddr_in *client_address, char *buffer, size_t max_length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0; // we do not request anything special
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (len < 0) {
        PRINT_ERRNO();
    }
    return (size_t) len;
}

void send_message(int socket_fd, const struct sockaddr_in *client_address, const char *message, size_t length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address, address_length);
    ENSURE(sent_length == (ssize_t) length);
}

int MIN_PORT = 0;
int MAX_PORT = 65535;
int MAX_TIMEOUT = 86400;

bool does_file_exist(const std::string& name) 
{
    struct stat buffer; 
    printf("bedziemy sprawdzac dla %s\n", name.c_str());
    return (stat(name.c_str(), &buffer) == 0); 
}

bool check_arguments(std::string filename, int port, int timeout)
{
    if (!does_file_exist(filename))
    {
        fprintf(stderr, "File does not exist.\n");
        return false;
    }
    if (port > MAX_PORT || port < MIN_PORT)
    {
        fprintf(stderr, "Wrong port value.\n");
        return false;
    }
    if (timeout < 1 || timeout > MAX_TIMEOUT)
    {
        fprintf(stderr, "Wrong timeout value.\n");
        return false;
    }
    return true;
}

class event
{
    public:
    // int id; // wystarczy indeks w wektorze
    std::string name;
    int tickets_count;
};

void read_file_to_map(std::string filename, std::vector<event>& events)
{
    std::ifstream file_stream;
    std::string title;
    std::string tickets_str;
    int tickets;
    file_stream.open(filename);

    while (getline(file_stream, title))
    {
        getline(file_stream, tickets_str);
        tickets = stoi(tickets_str);
        event e;
        e.name = title;
        e.tickets_count = tickets;
        events.push_back(e);
    } 

    file_stream.close();  
}

void wypisz_eventy(const std::vector<event> events)
{
    for (auto event: events)
    {
        printf("%s %d\n", event.name.c_str(), event.tickets_count);
    }
}

void check_alloc(void* ptr)
{
    if (ptr == 0)
    {
        fprintf(stderr, "Fatal allocation error\n");
        exit(1);
    }
}

void process_get_events(char* buffer)
{
}

// odczytuje bufor, przetwarza żądanie i umieszcza w buforze stosowną odpowiedź
void process_request(char* buffer)
{
    if (buffer[0] == 1)
    {
        process_get_events(buffer);
    }
    else if (buffer[0] == 3)
    {
        process_get_reservation(buffer);
    }
    else if (buffer[0] == 5)
    {
        process_get_tickets(buffer);
    }
    // nic nie robimy jak id jest złe
}

int main(int argc, char *argv[])
{
    std::string filename;
    uint16_t port = 2022;
    uint32_t timeout = 5;
    for (size_t i = 1; i < argc; i += 2)
    {
        printf("%s %s\n", argv[i], argv[i+1]);
        if (strcmp(argv[i], "-f\0") == 0)
        {
            filename = argv[i + 1];
        }
        if (strcmp(argv[i], "-p\0") == 0)
        {
            port = atoi(argv[i + 1]);
        }
        if (strcmp(argv[i], "-t\0") == 0)
        {
            timeout = atoi(argv[i + 1]);
        }
    }
    if (!check_arguments(filename, port, timeout))
    {
        fprintf(stderr, "Wrong arguments, server terminated.\n");
        return 1;
    }
    
    std::vector<event> events;
    read_file_to_map(filename, events);
    // wypisz_mape(events);

    int socket_fd = bind_socket(port);
    struct sockaddr_in client_address;
    char* buffer = (char*)malloc(BUFFER_SIZE * sizeof(char));
    check_alloc(buffer);

    while (true)
    {
        size_t read_length = read_message(socket_fd, &client_address, buffer, sizeof(buffer));
        char* client_ip = inet_ntoa(client_address.sin_addr);
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("received %zd bytes from client %s:%u: '%.*s'\n", read_length, client_ip, client_port,
               (int) read_length, buffer); // note: we specify the length of the printed string
        process_request(buffer);
        send_message(socket_fd, &client_address, buffer, read_length);
    }
    
    return 0;
}
