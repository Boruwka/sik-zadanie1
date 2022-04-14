#include <string.h>
#include <sys/stat.h>
#include <time.h>

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
const size_t MAX_TICKET_COUNT = 9357; // (BUFFER_SIZE - 7) / 7
const uint16_t DEFAULT_PORT = 2022;
const uint32_t DEFAULT_TIMEOUT = 5;
const size_t COOKIE_LEN = 48;
const size_t TICKET_LEN = 7;
const size_t MIN_RESERVATION_ID = 99999; // idk czy tyle, trzeba to sprawdzić
const size_t MAX_TITLE_SIZE = 80; // też idk czy tyle

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
    fprintf(stderr, "wysylamy dlugosc %ld\n", length);
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address, address_length);
    ENSURE(sent_length == (ssize_t) length);
}



bool does_file_exist(const char* name) 
{
    struct stat buffer; 
    printf("bedziemy sprawdzac dla %s\n", name);
    return (stat(name, &buffer) == 0); 
}

bool check_arguments(const char* filename, const int port, const int timeout)
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

struct event_t
{
    // int id; // wystarczy indeks w wektorze
    char* name;
    uint16_t ticket_count;
    size_t name_length;

};

typedef struct event_t event_t;

size_t event_get_size(const event_t* e)
{
    return e->name_length + 4;
}

struct reservation_t
{
    unsigned int reservation_id;
    unsigned int event_id;
    uint16_t ticket_count;
    char* cookie;
    unsigned long long expiration_time; 
};

typedef struct reservation_t reservation_t;

struct reservations_t
{
    reservation_t* tab;
    size_t allocated_size;
    size_t size;
};

typedef struct reservations_t reservations_t;

void init_reservations_t(reservations_t r)
{
    r.size = 0;
    r.allocated_size = 2;
    r.tab = malloc(2 * sizeof(reservation_t));
}


void read_file_to_array(char* filename, event_t** events, size_t* num_of_events)
{
    FILE* fptr = fopen(filename, "r");
    char* title = malloc(MAX_TITLE_SIZE * sizeof(char));
    char* tickets_str = malloc(MAX_TITLE_SIZE * sizeof(char));
    int tickets;
    size_t restrict_size = MAX_TITLE_SIZE;
    (*events) = malloc(2 * sizeof(event_t));
    (*num_of_events) = 0; 
    size_t allocated_size = 2;   
    //fprintf(stderr, "tu dziala wewnatrz read events = %ld *events = %ld\n", events, *events);

    while (getline(&title, &restrict_size, fptr) >= 0)
    {
        //fprintf(stderr, "tu dziala pentla getline %s\n", title);
        getline(&tickets_str, &restrict_size, fptr);
        //fprintf(stderr, "kolejne getline to %s\n", tickets_str);
        tickets = atoi(tickets_str);
        (*num_of_events)++;
        if ((*num_of_events) > allocated_size)
        {
            //fprintf(stderr, "trzeba zrealokowac\n");
            allocated_size *= 2;
            //fprintf(stderr, "%ld\n", (*events));
            (*events) = realloc((*events), allocated_size * sizeof(event_t));
        }
        //fprintf(stderr, "zrealokowane\n");
        //fprintf(stderr, "%ld\n", (*events));
        (*events)[(*num_of_events) - 1].name = malloc(MAX_TITLE_SIZE * sizeof(char));
        
        //fprintf(stderr, "zmallocowane\n");
        strcpy((*events)[(*num_of_events) - 1].name, title);
        //fputs((*events)[(*num_of_events) - 1].name, stderr);
        //fprintf(stderr, "tu dziala\n");
        (*events)[(*num_of_events) - 1].ticket_count = tickets;
        (*events)[(*num_of_events) - 1].name_length = strlen(title);
        //fprintf(stderr, "tu dziala\n");
    } 

    /*fprintf(stderr, "bedziemy wypisywac tablice\n");
    for (size_t i = 0; i < 3; i++)
    {
        fprintf(stderr, "%s %d\n", (*events)[i].name, (*events)[i].ticket_count);
    }
    fprintf(stderr, "wypisana\n"); */

    fclose(fptr);  
}

// funkcja tylko do debugu
void wypisz_eventy(const event_t* events, size_t num_of_events)
{
    // fprintf(stderr, "bedziemy wypisywac eventy num = %u\n", num_of_events);
    for (size_t i = 0; i < num_of_events; i++)
    {
        fprintf(stderr, "%s %d\n", events[i].name, events[i].ticket_count);
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

unsigned int push_ticket_count_to_buffer(char* buffer, const uint16_t ticket_count)
{
    buffer[0] = ticket_count / BYTE_SIZE;
    buffer[1] = ticket_count % BYTE_SIZE;
    return sizeof(ticket_count);
}

unsigned int push_cookie_to_buffer(char* buffer, char* cookie)
{
    for (size_t i = 0; i < COOKIE_LEN; i++)
    {
        buffer[i] = cookie[i];
    }
    return COOKIE_LEN;
}

unsigned int push_exp_time_to_buffer(char* buffer, long long exp_time)
{
    size_t num_of_bytes = sizeof(exp_time);
    for (int i = 0; i < num_of_bytes; i++)
    {
        buffer[i] = exp_time % BYTE_SIZE;
        exp_time /= BYTE_SIZE;
    }
    
    return num_of_bytes;
}

unsigned int push_id_to_buffer(char* buffer, unsigned int id)
{
    int num_of_bytes = sizeof(id);

    for (int i = num_of_bytes - 1; i >= 0; i--)
    {
        //fprintf(stderr, "pentla push id i = %d\n", i);
        buffer[i] = id % BYTE_SIZE;
        id /= BYTE_SIZE;
    }
    //fprintf(stderr, "po pentli\n");
    return num_of_bytes;
}

unsigned int push_event_to_buffer(char* buffer, const event_t e, const size_t id)
{
    fprintf(stderr, "bedziemy wsadzac event\n");
    size_t position = 0;
    push_id_to_buffer(buffer, id);
    //fprintf(stderr, "tu dziala\n");
    position += sizeof(id);
    push_ticket_count_to_buffer(&(buffer[position]), e.ticket_count);
    //fprintf(stderr, "tu dziala\n");
    position += sizeof(e.ticket_count);
    buffer[position] = e.name_length;
    //fprintf(stderr, "tu dziala\n");
    position++;
    strcpy(&(buffer[position]), e.name);
    fprintf(stderr, "wsadzony, bufor to teraz %s\n", buffer);
    return position + strlen(e.name);
}


unsigned int process_get_events(char* buffer, const event_t* events, const size_t num_of_events)
{
    size_t remaining_size = BUFFER_SIZE-2;
    buffer[0] = EVENTS_ID;
    unsigned int send_length = 1;
    // size_t num_of_events = events.size();
    for (size_t i = 0; i < num_of_events; i++)
    {
        fprintf(stderr, "event nr %ld\n", i);
        if (event_get_size(&(events[i])) > remaining_size)
        {
            fprintf(stderr, "nie mozemy go wsadzic\n");
            // nie możemy tego eventu wsadzić, przechodzimy do następnego
            continue;
        }
        else
        {
            fprintf(stderr, "wsadzamy go na pozycji %ld\n", BUFFER_SIZE-1-remaining_size);
            push_event_to_buffer(&(buffer[BUFFER_SIZE-1-remaining_size]), events[i], i);
            remaining_size -= event_get_size(&(events[i]));
            send_length += event_get_size(&(events[i]));
            // wsadzamy event do buffera
        }
    }

    fprintf(stderr, "get events, wyslemy taki bufor: %s\n", buffer);
    return send_length;
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



size_t push_bad_request(char* buffer, const unsigned int id)
{
    buffer[0] = BAD_REQUEST_ID;
    push_id_to_buffer(&(buffer[1]), id);
    return 1 + sizeof(id);
    
}

void fill_with_random_values(char* buffer, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        buffer[i] = (char)rand();
    }
}

char* generate_cookie(const unsigned int reservation_id, const unsigned int event_id)
{
    size_t num_of_id_bytes = sizeof(reservation_id);
    char* cookie = (char*)malloc(COOKIE_LEN * sizeof(char));
    check_alloc(cookie);
    push_id_to_buffer(cookie, reservation_id);
    push_id_to_buffer(&(cookie[num_of_id_bytes]), event_id);
    fill_with_random_values(&(cookie[2 * num_of_id_bytes]), COOKIE_LEN - num_of_id_bytes);
}

size_t push_reservation_to_buffer(char* buffer, reservation_t r)
{
    // reservation_id, event_id, ticket_count, cookie, expiration_time
    size_t pos = 0;
    push_id_to_buffer(buffer, r.reservation_id);
    pos += sizeof(r.reservation_id);
    push_id_to_buffer(&(buffer[pos]), r.event_id);
    pos += sizeof(r.event_id);
    push_ticket_count_to_buffer(&(buffer[pos]), r.event_id);
    pos += sizeof(r.ticket_count);
    push_cookie_to_buffer(&(buffer[pos]), r.cookie);
    pos += COOKIE_LEN;
    push_exp_time_to_buffer(&(buffer[pos]), r.expiration_time);
    pos += sizeof(r.expiration_time);
    return pos;
}

void reservations_insert(reservations_t* reservations, const reservation_t r)
{
    reservations->size++;
    if (reservations->size > reservations->allocated_size)
    {
        reservations->allocated_size *= 2;
        reservations->tab = realloc(reservations->tab, reservations->allocated_size);
    }
    reservations->tab[reservations->size - 1] = r;
}

size_t process_get_reservation(char* buffer, const event_t* events, reservations_t* reservations, const unsigned int num_of_events, unsigned int* reservation_id_counter)
{
    /* Serwer odpowiada komunikatem BAD_REQUEST z wartością event_id w odpowiedzi na komunikat GET_RESERVATION, jeśli prośba nie może być zrealizowana, klient podał nieprawidłowe event_id, prosi o zero biletów, liczba dostępnych biletów jest mniejsza niż żądana, bilety zostały w międzyczasie zarezerwowane przez innego klienta, żądana liczba biletów nie mieści się w komunikacie TICKETS (który musi się zmieścić w jednym datagramie UDP). */
    /* RESERVATION – message_id = 4, reservation_id, event_id, ticket_count, cookie, expiration_time, odpowiedź na komunikat GET_RESERVATION potwierdzająca rezerwację, zawierająca czas, do którego należy odebrać zarezerwowane bilety; */
    
    unsigned int event_id = read_id_from_buffer(&(buffer[1]));
    if (event_id >= num_of_events)
    {
        return push_bad_request(buffer, event_id);
    }

    size_t ticket_count = read_ticket_count_from_buffer(&(buffer[5]));
    if (ticket_count == 0 || ticket_count < events[event_id].ticket_count || ticket_count > MAX_TICKET_COUNT)
    {
        return push_bad_request(buffer, event_id);
    }
    
    reservation_t r;
    r.reservation_id = (*reservation_id_counter) + 1;
    reservation_id_counter++;
    r.event_id = event_id;
    r.ticket_count = ticket_count;
    r.cookie = generate_cookie(r.reservation_id, r.event_id);
    time_t time_in_sec;
    time(&time_in_sec);
    r.expiration_time = (long long)time_in_sec;
    reservations_insert(reservations, r);

    buffer[0] = RESERVATION_ID;
    unsigned int send_length = 1;
    send_length += push_reservation_to_buffer(&(buffer[1]), r);
    return send_length;
    /*push_id_to_buffer(&(buffer[1]), r.reservation_id);
    push_id_to_buffer(&(buffer[5]), r.event_id);
    push_ticket_count_to_buffer(&(buffer[9]), r.ticket_count);*/
    // teraz musimy odesłać r komunikatem RESERVATION

}

char* generate_ticket(unsigned int reservation_id)
{
    char* ticket = (char*)malloc(TICKET_LEN * sizeof(char));
    push_id_to_buffer(ticket, reservation_id);
    /* for (i = sizeof(reservation_id); i < TICKET_LEN; i++)
    {
        FIL
    } */
    fill_with_random_values(&(ticket[sizeof(reservation_id)]), TICKET_LEN - sizeof(reservation_id));
}

size_t push_tickets_to_buffer(char* buffer, const unsigned int reservation_id, const uint16_t ticket_count)
{
    for (uint16_t i = 0; i < ticket_count; i++)
    {
        char* ticket = generate_ticket(reservation_id);
        for (size_t j = 0; j < TICKET_LEN; j++)
        {
            buffer[TICKET_LEN * i + j] = ticket[j];
        }
        free(ticket);
    }
    
    return TICKET_LEN * ticket_count;
}

size_t process_get_tickets(char* buffer, reservations_t* reservations)
{
    /* Serwer odpowiada komunikatem BAD_REQUEST z wartością reservation_id w odpowiedzi na komunikat GET_TICKETS, jeśli minął czas na odebranie biletów, klient podał nieprawidłowe reservation_id lub cookie. */
    /* GET_TICKETS – message_id = 5, reservation_id, cookie, prośba o wysłanie zarezerwowanych biletów. */
    /* TICKETS – message_id = 6, reservation_id, ticket_count > 0, ticket, …, ticket, odpowiedź na komunikat GET_TICKETS zawierająca ticket_count pól typu ticket; */
    size_t pos = 1;
    unsigned int reservation_id = read_id_from_buffer(&(buffer[pos]));
    pos += sizeof(reservation_id);
    char* cookie = (char*)malloc(COOKIE_LEN * sizeof(char));
    for (size_t i = 0; i < COOKIE_LEN; i++)
    {
        cookie[i] = buffer[pos + i];
    }
    
    size_t reservation_index = reservation_id - MIN_RESERVATION_ID;
    if (reservation_index < 0  || reservation_index >= reservations->size)
    {
        return push_bad_request(buffer, reservation_id);
    }
    
    time_t time_in_sec;
    time(&time_in_sec);
    reservation_t r = reservations->tab[reservation_index];
    r.expiration_time = (long long)time_in_sec;
    if (reservations->tab[reservation_index].expiration_time > time_in_sec)
    {
        return push_bad_request(buffer, reservation_id);
    }

    if (strcmp(reservations->tab[reservation_index].cookie, cookie) != 0)
    {
        return push_bad_request(buffer, reservation_id);
    }

    buffer[0] = TICKETS_ID;
    pos = 1;
    push_id_to_buffer(&(buffer[pos]), reservation_id);
    pos += sizeof(reservation_id);
    push_ticket_count_to_buffer(&(buffer[pos]), r.ticket_count);
    pos += sizeof(r.ticket_count);
    pos += push_tickets_to_buffer(&(buffer[pos]), reservation_id, r.ticket_count);
    return pos;

}

// odczytuje bufor, przetwarza żądanie i umieszcza w buforze stosowną odpowiedź
void process_request(char* buffer, const event_t* events, reservations_t* reservations, const unsigned int num_of_events, unsigned int* reservation_id_counter, size_t* send_length)
{
    fprintf(stderr, "bedziemy procesowac requesta\n");
    if (buffer[0] == GET_EVENTS_ID)
    {
        fprintf(stderr, "to get events\n");
        *send_length = process_get_events(buffer, events, num_of_events);
    }
    else if (buffer[0] == GET_RESERVATION_ID)
    {
        *send_length = process_get_reservation(buffer, events, reservations, num_of_events, reservation_id_counter);
    }
    else if (buffer[0] == GET_TICKETS_ID)
    {
        *send_length = process_get_tickets(buffer, reservations);
    }
    // nic nie robimy jak id jest złe
}

int main(int argc, char *argv[])
{
    char* filename;
    int port = DEFAULT_PORT;
    int timeout = DEFAULT_TIMEOUT;
    bool filename_loaded = false;
    
    if (argc % 2 == 0 || argc < 2)
    {
        fprintf(stderr, "Wrong number of arguments, server terminated.\n");
        return 1;
    }

    fprintf(stderr, "%d\n", atoi("a\0"));
    for (size_t i = 1; i < argc; i += 2)
    {
        printf("%s %s\n", argv[i], argv[i+1]);
        if (strcmp(argv[i], "-f\0") == 0)
        {
            //fprintf(stderr, "plik");
            filename_loaded = true;
            filename = argv[i + 1];
        }
        else if (strcmp(argv[i], "-p\0") == 0)
        {
            //fprintf(stderr, "port\n");
            port = atoi(argv[i + 1]);
            if (port == 0 && strcmp(argv[i + 1], "0\0") != 0)
            {
                fprintf(stderr, "Wrong port\n");
                return 1;
            }
            // fprintf(stderr, "%d\n", port);
        }
        else if (strcmp(argv[i], "-t\0") == 0)
        {
            timeout = atoi(argv[i + 1]);
        }
        else
        {
            fprintf(stderr, "Wrong parameter flag, server terminated.\n");
            exit(1);
        }
    }

    if (!check_arguments(filename, port, timeout))
    {
        fprintf(stderr, "Wrong arguments, server terminated.\n");
        return 1;
    }
    if (!filename_loaded)
    {
        fprintf(stderr, "No filename given\n");
        return 1;
    }
    
    //fprintf(stderr, "tu dziala\n");
    event_t* events;
    size_t num_of_events;
    //fprintf(stderr, "tu dziala &events = %ld events = %ld\n", &events, events);
    read_file_to_array(filename, &events, &num_of_events);
    wypisz_eventy(events, num_of_events);
    fprintf(stderr, "czytanie eventow dziala\n");

    int socket_fd = bind_socket(port);
    struct sockaddr_in client_address;
    char* buffer = (char*)malloc(BUFFER_SIZE * sizeof(char));
    check_alloc(buffer);

    unsigned int reservation_id_counter = MIN_RESERVATION_ID - 1;
    reservations_t reservations; // po prostu tablica z realokowaniem
    init_reservations_t(reservations);
    size_t send_length = 0;

    while (true)
    {
        // fprintf(stderr, "tu dziala\n");
        size_t read_length = read_message(socket_fd, &client_address, buffer, BUFFER_SIZE);
        char* client_ip = inet_ntoa(client_address.sin_addr);
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("received %zd bytes from client %s:%u: '%.*s'\n", read_length, client_ip, client_port,
               (int) read_length, buffer); // note: we specify the length of the printed string
        process_request(buffer, events, &reservations, num_of_events, &reservation_id_counter, &send_length);
        send_message(socket_fd, &client_address, buffer, send_length);
    }
    
    return 0;
}
