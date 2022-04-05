#include <cstring>
#include <unordered_map>
#include <sys/stat.h>
#include <fstream>

int MIN_PORT = 1024;
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

void read_file_to_map(std::string filename, std::unordered_map<std::string, int>& events)
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
        events.insert(std::make_pair(title, tickets));
    } 

    file_stream.close();  
}

void wypisz_mape(std::unordered_map<std::string, int> events)
{
    for (auto event: events)
    {
        printf("%s %d\n", event.first.c_str(), event.second);
    }
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
    
    std::unordered_map<std::string, int> events;
    read_file_to_map(filename, events);
    wypisz_mape(events);
    return 0;
}
