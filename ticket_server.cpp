#include <cstring>
#include <sys/stat.h>
#include <fstream>
#include <vector>
#include <set>
#include <ctime>

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
const size_t MIN_PORT = 0;
const size_t MAX_PORT = 65535;
const size_t MAX_TIMEOUT = 86400;
const size_t BYTE_SIZE = 256;
const unsigned int GET_EVENTS_ID = 1;
const unsigned int EVENTS_ID = 2;
const unsigned int GET_RESERVATION_ID = 3;
const unsigned int RESERVATION_ID = 4;
const unsigned int GET_TICKETS_ID = 5;
const unsigned int TICKETS_ID = 6;
const unsigned int BAD_REQUEST_ID = 255;
const size_t MAX_TICKET_COUNT = (BUFFER_SIZE - 7)/7;
const uint16_t DEFAULT_PORT = 2022;
const uint32_t DEFAULT_TIMEOUT = 5;

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
    int ticket_count;
    size_t name_length;

    size_t get_size() const
    {
        return name_length + 4;
    }

};

class reservation
{
    public:
    unsigned int reservation_id;
    unsigned int event_id;
    size_t ticket_count;
    char* cookie;
    unsigned long long expiration_time;
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
        e.ticket_count = tickets;
        e.name_length = title.length();
        events.push_back(e);
    } 

    file_stream.close();  
}

// funkcja tylko do debugu
void wypisz_eventy(const std::vector<event> events)
{
    for (auto event: events)
    {
        printf("%s %d\n", event.name.c_str(), event.ticket_count);
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

void push_event_to_buffer(char* buffer, const event e, const size_t id)
{
    // ta cała funkcja jest źle
    buffer[0] = id;
    buffer[1] = e.ticket_count / BYTE_SIZE;
    buffer[2] = e.ticket_count % BYTE_SIZE;
    buffer[3] = e.name_length;
    strcpy(&(buffer[4]), e.name.c_str());
}


void process_get_events(char* buffer, const std::vector<event> events)
{
    size_t remaining_size = BUFFER_SIZE-1;
    buffer[0] = EVENTS_ID;
    size_t num_of_events = events.size();
    for (size_t i = 0; i < num_of_events; i++)
    {
        if (events[i].get_size() > remaining_size)
        {
            // nie możemy tego eventu wsadzić, przechodzimy do następnego
            continue;
        }
        else
        {
            push_event_to_buffer(&(buffer[BUFFER_SIZE-1-remaining_size]), events[i], i);
            // wsadzamy event do buffera
        }
    }
}

unsigned int read_id_from_buffer(const char* buffer)
{
    unsigned int res = 0;
    unsigned int num_of_bytes = 4;

    for (unsigned int i = 0; i < num_of_bytes; i++)
    {
        res *= BYTE_SIZE;
        res += buffer[i];
    } 
    
    return res;
}

size_t read_ticket_count_from_buffer(const char* buffer)
{
    size_t res = 0;
    unsigned int num_of_bytes = 2;

    for (size_t i = 0; i < num_of_bytes; i++)
    {
        res *= BYTE_SIZE;
        res += buffer[i];
    } 
    
    return res;
}

void push_id_to_buffer(char* buffer, unsigned int id)
{
    unsigned int num_of_bytes = 4;

    for (unsigned int i = num_of_bytes - 1; i >= 0; i--)
    {
        buffer[i] = id % BYTE_SIZE;
        id /= BYTE_SIZE;
    }
}

void push_bad_request(char* buffer, const unsigned int id)
{
    buffer[0] = BAD_REQUEST_ID;
    push_id_to_buffer(&(buffer[1]), id);
    
}

void process_get_reservation(char* buffer, const std::vector<event> events, std::set<reservation>& reservations, const unsigned int num_of_events, unsigned int reservation_id_counter)
{
    /* Serwer odpowiada komunikatem BAD_REQUEST z wartością event_id w odpowiedzi na komunikat GET_RESERVATION, jeśli prośba nie może być zrealizowana, klient podał nieprawidłowe event_id, prosi o zero biletów, liczba dostępnych biletów jest mniejsza niż żądana, bilety zostały w międzyczasie zarezerwowane przez innego klienta, żądana liczba biletów nie mieści się w komunikacie TICKETS (który musi się zmieścić w jednym datagramie UDP). */
    /* RESERVATION – message_id = 4, reservation_id, event_id, ticket_count, cookie, expiration_time, odpowiedź na komunikat GET_RESERVATION potwierdzająca rezerwację, zawierająca czas, do którego należy odebrać zarezerwowane bilety; */
    
    unsigned int event_id = read_id_from_buffer(&(buffer[1]));
    if (event_id >= num_of_events)
    {
        push_bad_request(buffer, event_id);
        return;
    }

    size_t ticket_count = read_ticket_count_from_buffer(&(buffer[5]));
    if (ticket_count == 0 || ticket_count < events[event_id].ticket_count || ticket_count > MAX_TICKET_COUNT)
    {
        push_bad_request(buffer, event_id);
        return;
    }
    
    reservation r;
    r.reservation_id = reservation_id_counter + 1;
    reservation_id_counter++;
    r.event_id = event_id;
    r.ticket_count = ticket_count;
    r.cookie = generate_cookie(r.reservation_id, r.event_id);
    time_t time_in_sec;
    time(&time_in_sec);
    r.expiration_time = (long long)time_in_sec;
    reservations.push(r);

    buffer[0] = RESERVATION_ID;
    push_reservation_to_buffer(&(buffer[1]), r);
    /*push_id_to_buffer(&(buffer[1]), r.reservation_id);
    push_id_to_buffer(&(buffer[5]), r.event_id);
    push_ticket_count_to_buffer(&(buffer[9]), r.ticket_count);*/
    // teraz musimy odesłać r komunikatem RESERVATION

}

// odczytuje bufor, przetwarza żądanie i umieszcza w buforze stosowną odpowiedź
void process_request(char* buffer, const std::vector<event> events, std::set<reservation> reservations, const unsigned int num_of_events)
{
    if (buffer[0] == GET_EVENTS_ID)
    {
        process_get_events(buffer, events, num_of_events);
    }
    else if (buffer[0] == GET_RESERVATION_ID)
    {
        process_get_reservation(buffer, events, reservations, num_of_events);
    }
    else if (buffer[0] == GET_TICKETS_ID)
    {
        process_get_tickets(buffer);
    }
    // nic nie robimy jak id jest złe
}

int main(int argc, char *argv[])
{
    std::string filename;
    uint16_t port = DEFAULT_PORT;
    uint32_t timeout = DEFAULT_TIMEOUT;
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

    unsigned int reservation_id_counter = MIN_RESERVATION_ID - 1;
    std::set<reservation> reservations;

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
