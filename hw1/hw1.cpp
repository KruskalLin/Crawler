// hw1.cpp

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <set>
#include <queue>
#include <string>
#include "pch.h"
#include "stdafx.h"
#pragma comment(lib, "ws2_32.lib")

#define INITIAL_BUF_SIZE 4096
#define THRESHOLD 1024
#define TIMEOUT_SEC 10
#define MAX_ROBOT_READ 16384
#define MAX_PAGE_READ 2097152

class Socket {
    SOCKET sock;
    char* buf;
    int allocatedSize;
    int curPos;
    bool verbose;

public:
    Socket(SOCKET s, bool verbose) : sock(s), verbose(verbose), buf(nullptr), allocatedSize(0), curPos(0) {
        buf = new char[INITIAL_BUF_SIZE];
        allocatedSize = INITIAL_BUF_SIZE;
        std::memset(buf, '\0', INITIAL_BUF_SIZE);
    }

    bool Read(int maxRead) {
        int ret;
        fd_set fd;
        timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;
        clock_t t = clock();

        while (true) {
            FD_ZERO(&fd);
            FD_SET(sock, &fd);
            if ((ret = select(0, &fd, nullptr, nullptr, &timeout)) > 0) {
                // new data available; now read the next segment
                int bytes = recv(sock, buf + curPos, allocatedSize - curPos, 0);
                if ((double)(clock() - t) / CLOCKS_PER_SEC > TIMEOUT_SEC) {
                    if (verbose)
                        printf("failed with slow download\n");
                    break;
                }
                if (bytes == SOCKET_ERROR) {
                    if (verbose)
                        printf("failed with %d on recv\n", WSAGetLastError());
                    break;
                }
                if (bytes == 0) {
                    // NULL-terminate buffer
                    buf[curPos] = '\0';
                    return true;
                }

                curPos += bytes;

                if (curPos > maxRead) {
                    if (verbose)
                        printf("failed with exceeding max\n");
                    break;
                }

                if (allocatedSize - curPos < THRESHOLD) {
                    // memcpy the buffer into a bigger array
                    int resize = allocatedSize * 2;
                    char* resizeBuf = new char[resize];
                    std::memset(resizeBuf, '\0', resize);
                    memcpy(resizeBuf, buf, curPos);
                    delete[] buf;
                    buf = resizeBuf;
                    allocatedSize = resize;
                }
            }
            else if (ret == 0) {
                if (verbose)
                    printf("failed with timeout\n");
                break;
            }
            else {
                if (verbose)
                    printf("failed with %d on select\n", WSAGetLastError());
                break;
            }
        }
        return false;
    }

    char* GetBuffer() const {
        return buf;
    }

    int GetCurPos() const {
        return curPos;
    }
};

bool IsValidPort(const char* port_str) {
    int port = std::atoi(port_str);
    return port > 0 && port < 65536;
}

bool connect_socket(char* request, char* urlCopy, SOCKET sock, char* method, bool verbose) {
    size_t httpRequestLength = strlen(request) + strlen(urlCopy) + 100;
    char* sendBuf = new char[httpRequestLength];
    std::memset(sendBuf, '\0', httpRequestLength);
    sprintf_s(sendBuf, httpRequestLength, "%s %s HTTP/1.0\r\nHost: %s\r\nUser-agent: myTAMUcrawler/1.0\r\nConnection: close\r\n\r\n", method, request, urlCopy);
    if (send(sock, sendBuf, httpRequestLength, 0) == SOCKET_ERROR)
    {
        if (verbose)
            printf("failed with %d on send\n", WSAGetLastError());
        delete[] sendBuf;
        return false;
    }
    delete[] sendBuf;
    return true;
}

void cleanup(char* urlCopy, char* port, char* request) {
    free(urlCopy);
    free(port);
    delete[] request;
}


class Crawler {
public:
    Crawler(int num_threads, bool verbose);
    ~Crawler();
    bool LoadPage(char* method, char* port, char* request, char* urlCopy, sockaddr_in server, int maxRead, char* statusCode, char** buf, int* bufLength);
    bool ProcessURL(const char* url);
    bool ReadFile(const char* filename);
    void StartCrawling();
    static DWORD WINAPI ThreadProc(LPVOID lpParam);
    static DWORD WINAPI StatsThreadProc(LPVOID lpParam);

    void Run();       // Method for crawling threads
    void StatsRun();  // Method for stats thread

private:
    bool verbose;

    std::queue<std::string> url_queue;
    CRITICAL_SECTION queue_lock;  
    CRITICAL_SECTION ip_set_lock;
    CRITICAL_SECTION host_set_lock;
    HANDLE eventQuit;   // Signals when to quit
    int num_threads;

    // Statistics variables
    LONG urls_processed;
    LONG urls_pages;
    LONG urls_bytes;
    LONG total_bytes;
    LONG urls_extracted;     // (E)
    LONG dns_lookup;         // (D)
    LONG robot_check;        // (R)
    LONG urls_success;       // (C)
    LONG total_links_found;  // (L)
    LONG active_thread_count;
    LONG code2;
    LONG code3;
    LONG code4;
    LONG code5;
    LONG code_unknown;

    clock_t start_time;      // Start time for elapsed time calculation

    std::set<DWORD> seenIPs;
    std::set<std::string> seenHosts;
};

Crawler::Crawler(int num_threads, bool verbose) : num_threads(num_threads), verbose(verbose), urls_processed(0), urls_pages(0), urls_bytes(0), total_bytes(0), urls_extracted(0), dns_lookup(0), robot_check(0), urls_success(0), total_links_found(0), active_thread_count(0), code2(0), code3(0), code4(0), code5(0), code_unknown(0) {
    InitializeCriticalSection(&queue_lock);
    InitializeCriticalSection(&ip_set_lock);
    InitializeCriticalSection(&host_set_lock);
    eventQuit = CreateEvent(NULL, TRUE, FALSE, NULL);  // Manual-reset event, initially non-signaled
}

Crawler::~Crawler() {
    DeleteCriticalSection(&queue_lock);
    DeleteCriticalSection(&ip_set_lock);
    DeleteCriticalSection(&host_set_lock);
    CloseHandle(eventQuit);
}


bool Crawler::LoadPage(char* method, char* port, char* request, char* urlCopy, sockaddr_in server, int maxRead, char* statusCode, char** buf, int* bufLength) {
    clock_t t = clock();

    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        if (verbose)
            printf("failed with %d\n", WSAGetLastError());
        WSACleanup();
        cleanup(urlCopy, port, request);
        return false;
    }
    // open a TCP socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        if (verbose)
            printf("failed with %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return false;
    }
    // connect to the server on port
    if (connect(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        if (verbose)
            printf("failed with %d on connect\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return false;
    }

    if (!connect_socket(request, urlCopy, sock, method, verbose)) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    if (verbose)
        printf("done in %.2f sec\n", (double)(clock() - t) / CLOCKS_PER_SEC);
    if (verbose)
        printf("\tLoading... ");
    t = clock();
    Socket s(sock, verbose);
    if (!s.Read(maxRead)) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    *buf = s.GetBuffer();
    *bufLength = s.GetCurPos();
    if (strncmp(*buf, "HTTP/", 5) != 0) {
        if (verbose)
            printf("failed with non-HTTP header (does not begin with HTTP/)\n");
        closesocket(sock);
        WSACleanup();
        return false;
    }
    if (verbose)
        printf("done in %.2f sec with %d bytes\n", (double)(clock() - t) / CLOCKS_PER_SEC, *bufLength);
    InterlockedIncrement(&urls_pages);
    InterlockedAdd(&urls_bytes, (LONG)*bufLength);
    InterlockedAdd(&total_bytes, (LONG)*bufLength);
    if (verbose)
        printf("\tVerifying header... ");
    std::memset(statusCode, '\0', 4);
    statusCode[0] = (*buf)[9];
    statusCode[1] = (*buf)[10];
    statusCode[2] = (*buf)[11];
    if (verbose)
        printf("status code %s\n", statusCode);
    closesocket(sock);
    WSACleanup();
    return true;
}

bool Crawler::ProcessURL(const char* url) {
    if (verbose) {
        printf("URL: %s\n", url);
        printf("\tParsing URL... ");
    }
    const char* httpPrefix = "http://";
    if (strncmp(url, httpPrefix, strlen(httpPrefix)) != 0) {
        if (verbose)
            printf("failed with invalid scheme\n");
        return false;
    }

    char* urlCopy = _strdup(url + strlen(httpPrefix));

    char* fragment = strchr(urlCopy, '#');
    if (fragment) {
        *fragment++ = '\0';
    }

    char* query = strchr(urlCopy, '?');
    if (query) {
        *query++ = '\0';
    }

    char* path = strchr(urlCopy, '/');
    if (path) {
        *path++ = '\0';
    }

    char* port = strchr(urlCopy, ':');
    if (port) {
        *port++ = '\0';
        if (!IsValidPort(port)) {
            if (verbose)
                printf("failed with invalid port\n");
            free(urlCopy);
            return false;
        }
    }
    else {
        port = _strdup("80");
    }

    // build the request string
    size_t requestLength = 2 + (path ? strlen(path) : 0) + (query ? strlen(query) + 1 : 0);
    char* request = new char[requestLength];
    std::memset(request, '\0', requestLength);
    request[0] = '/';
    if (path) {
        strcat_s(request, requestLength, path);
    }
    if (query) {
        strcat_s(request, requestLength, "?");
        strcat_s(request, requestLength, query);
    }

    if (strlen(urlCopy) > MAX_HOST_LEN) {
        if (verbose)
            printf("exceed maximum host len\n");
        cleanup(urlCopy, port, request);
        return false;
    }

    if (strlen(request) > MAX_REQUEST_LEN) {
        if (verbose)
            printf("exceed maximum request len\n");
        cleanup(urlCopy, port, request);
        return false;
    }
    if (verbose)
        printf("host %s, port %s\n", urlCopy, port);
    if (verbose)
        printf("\tChecking host uniqueness... ");

    EnterCriticalSection(&host_set_lock);
    auto hostResult = seenHosts.insert(std::string(urlCopy));
    LeaveCriticalSection(&host_set_lock);

    if (hostResult.second) {
        if (verbose)
            printf("passed\n");
    }
    else {
        if (verbose)
            printf("failed\n");
        cleanup(urlCopy, port, request);
        return false;
    }
    if (verbose)
        printf("\tDoing DNS... ");
    clock_t t = clock();

    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        if (verbose)
            printf("failed with %d\n", WSAGetLastError());
        WSACleanup();
        cleanup(urlCopy, port, request);
        return false;
    }

    // structure used in DNS lookups
    struct hostent* remote;

    // structure for connecting to server
    struct sockaddr_in server;

    // first assume that the string is an IP address
    DWORD IP = inet_addr(urlCopy);
    if (IP == INADDR_NONE)
    {
        // if not a valid IP, then do a DNS lookup
        if ((remote = gethostbyname(urlCopy)) == NULL)
        {
            if (verbose)
                printf("failed with %d\n", WSAGetLastError());
            cleanup(urlCopy, port, request);
            return false;
        }
        else // take the first IP address and copy into sin_addr
            memcpy((char*)&(server.sin_addr), remote->h_addr, remote->h_length);
    }
    else
    {
        // if a valid IP, directly drop its binary version into sin_addr
        server.sin_addr.S_un.S_addr = IP;
    }
    if (verbose)
        printf("done in %.2f sec, found %s\n", (double)(clock() - t) / CLOCKS_PER_SEC, inet_ntoa(server.sin_addr));

    InterlockedIncrement(&dns_lookup);

    if (verbose)
        printf("\tChecking IP uniqueness... ");
    EnterCriticalSection(&ip_set_lock);
    auto ipResult = seenIPs.insert(server.sin_addr.s_addr);
    LeaveCriticalSection(&ip_set_lock);
    if (ipResult.second) {
        if (verbose)
            printf("passed\n");
    }
    else {
        if (verbose)
            printf("failed\n");
        cleanup(urlCopy, port, request);
        return false;
    }


    // setup the port # and protocol type
    server.sin_family = AF_INET;
    server.sin_port = htons(std::atoi(port));		// host-to-network flips the byte order

    char statusCode[4];
    char* buf;
    int bufLength;
    if (verbose)
        printf("\tConnecting on robots... ");
    char robotsRequest[20] = "/robots.txt";
    char robotMethod[5] = "HEAD";
    if (!LoadPage(robotMethod, port, robotsRequest, urlCopy, server, MAX_ROBOT_READ, statusCode, &buf, &bufLength)) {
        cleanup(urlCopy, port, request);
        return false;
    }

    if (statusCode[0] != '4') {
        return false;
    }
    InterlockedIncrement(&robot_check);
    if (verbose)
        printf("*\tConnecting on page... ");
    char method[4] = "GET";
    if (!LoadPage(method, port, request, urlCopy, server, MAX_PAGE_READ, statusCode, &buf, &bufLength)) {
        cleanup(urlCopy, port, request);
        return false;
    }
    cleanup(urlCopy, port, request);

    InterlockedIncrement(&urls_success);

    char* headerEnd = strstr(buf, "\r\n\r\n");
    size_t headerLength = headerEnd - buf + 4;

    if (statusCode[0] == '2') {
        InterlockedIncrement(&code2);
            
        if (verbose)
            printf("+\tParsing page... ");
        t = clock();

        HTMLParserBase* parser = new HTMLParserBase;
        int nLinks;
        char* baseURL = _strdup(url);
        char* linkBuffer = parser->Parse(headerEnd, bufLength - headerLength, baseURL, (int)strlen(baseURL), &nLinks);
        // check for errors indicated by negative values
        if (nLinks < 0)
            nLinks = 0;

        delete parser;		// this internally deletes linkBuffer
        free(baseURL);
        if (verbose)
            printf("done in %.2f sec with %d links\n", (double)(clock() - t) / CLOCKS_PER_SEC, nLinks);

        InterlockedAdd(&dns_lookup, (LONG)nLinks);
    }
    else if (statusCode[0] == '3') {
        InterlockedIncrement(&code3);
    }
    else if (statusCode[0] == '4') {
        InterlockedIncrement(&code4);
    }
    else if (statusCode[0] == '5') {
        InterlockedIncrement(&code5);
    } else {
        InterlockedIncrement(&code_unknown);
    }
    return true;
}


bool Crawler::ReadFile(const char* filename) {
    FILE* file;
    errno_t err = fopen_s(&file, filename, "rb");
    if (err == 0) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char* buf = new char[file_size + 1];
        std::memset(buf, '\0', file_size + 1);
        fread(buf, 1, file_size, file);
        buf[file_size] = '\0';

        fclose(file);
        printf("Opened %s with size %d\n", filename, file_size);

        int url_count = 0;
        for (long i = 0; i < file_size; i++) {
            if (buf[i] == '\n') {
                url_count++;
            }
        }
        if (buf[file_size - 1] != '\n') {
            url_count++;
        }

        char* current_url = buf;
        int url_index = 0;
        for (long i = 0; i < file_size; i++) {
            if (buf[i] == '\r') {
                buf[i] = '\0';
            }
            if (buf[i] == '\n') {
                buf[i] = '\0';
                std::string url(current_url);
                EnterCriticalSection(&queue_lock);
                url_queue.push(url);
                LeaveCriticalSection(&queue_lock);
                url_index++;
                current_url = buf + i + 1;
            }
        }
        if (*current_url != '\0') {
            std::string url(current_url);
            EnterCriticalSection(&queue_lock);
            url_queue.push(url);
            LeaveCriticalSection(&queue_lock);
        }

        delete[] buf;
        return true;
    }
    else {
        if (verbose)
            printf("file does not exist\n");
        return false;
    }
}

void Crawler::StartCrawling() {
    start_time = clock();

    HANDLE* threads = new HANDLE[num_threads];
    for (int i = 0; i < num_threads; i++) {
        threads[i] = CreateThread(NULL, 0, ThreadProc, this, 0, NULL);
    }

    HANDLE statsThread = CreateThread(NULL, 0, StatsThreadProc, this, 0, NULL);
    
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
    
    SetEvent(eventQuit);
    
    WaitForSingleObject(statsThread, INFINITE);

    for (int i = 0; i < num_threads; i++) {
        CloseHandle(threads[i]);
    }
    CloseHandle(statsThread);
    delete[] threads;

    clock_t current_time = clock();
    int elapsed_time = (int)((double)(current_time - start_time) / CLOCKS_PER_SEC);
    size_t hosts_size = seenHosts.size();
    size_t ips_size = seenIPs.size();
    printf("\nExtracted %d URLs @ %d/s\n", urls_extracted, urls_extracted / elapsed_time);
    printf("Looked up %d DNS names @ %d/s\n", hosts_size, hosts_size / elapsed_time);
    printf("Attempted %d robots @ %d/s\n", ips_size, ips_size / elapsed_time);
    printf("Crawled %d pages @ %d/s (%.2f MB)\n", urls_success, urls_success / elapsed_time, static_cast<float>(total_bytes) / 1000000);
    printf("Parsed %d links @ %d/s\n", total_links_found, total_links_found / elapsed_time);
    printf("HTTP codes: 2xx = %d, 3xx = %d, 4xx = %d, 5xx = %d, other = %d\n", code2, code3, code4, code5, code_unknown);
}

DWORD WINAPI Crawler::ThreadProc(LPVOID lpParam) {
    Crawler* crawler = (Crawler*)lpParam;
    crawler->Run();
    return 0;
}

DWORD WINAPI Crawler::StatsThreadProc(LPVOID lpParam) {
    Crawler* crawler = (Crawler*)lpParam;
    crawler->StatsRun();
    return 0;
}

void Crawler::Run() {
    InterlockedIncrement(&active_thread_count);
    while (true) {
        std::string url;
        EnterCriticalSection(&queue_lock);
        if (url_queue.empty()) {
            LeaveCriticalSection(&queue_lock);
            break;
        }
        
        url = url_queue.front();
        url_queue.pop();
        LeaveCriticalSection(&queue_lock);
        InterlockedIncrement(&urls_extracted);

        ProcessURL(url.c_str());

        InterlockedIncrement(&urls_processed);
    }
    InterlockedDecrement(&active_thread_count);
}

void Crawler::StatsRun() {
    while (WaitForSingleObject(eventQuit, 2000) == WAIT_TIMEOUT) {
        clock_t current_time = clock();
        int elapsed_time = (int)((double)(current_time - start_time) / CLOCKS_PER_SEC);

        EnterCriticalSection(&queue_lock);
        size_t queue_size = url_queue.size();
        LeaveCriticalSection(&queue_lock);

        EnterCriticalSection(&host_set_lock);
        size_t hosts_size = seenHosts.size();
        LeaveCriticalSection(&host_set_lock);

        EnterCriticalSection(&ip_set_lock);
        size_t ips_size = seenIPs.size();
        LeaveCriticalSection(&ip_set_lock);

        printf("[%3d] %3ld Q %6zu E %7ld H %6zu D %6ld I %5zu R %5ld C %5ld L %4ld\n",
            elapsed_time,
            active_thread_count,
            queue_size,
            urls_extracted,
            hosts_size,
            dns_lookup,
            ips_size,
            robot_check,
            urls_success,
            total_links_found);

        printf("\t*** crawling %.1f pps @ %.1f Mbps\n", static_cast<float>(urls_pages) / 2.0, static_cast<float>(urls_bytes) / 2.0 / 1000000);
        InterlockedExchange(&urls_pages, 0);
        InterlockedExchange(&urls_bytes, 0);

    }
}




int main(int argc, char* argv[])
{

    if (argc == 2) {
        const char* url = argv[1];
        Crawler crawler(1, true);
        crawler.ProcessURL(url);
        return 0;
    }
    else if (argc == 3) {
        int num_threads = std::atoi(argv[1]);
        const char* filename = argv[2];

        Crawler crawler(num_threads, false);
        if(crawler.ReadFile(filename) == false)
            return 1;
        crawler.StartCrawling();

        return 0;
    }
    else {
        printf("Single Argument Usage: hw1.exe http://host[:port][/path][?query][#fragment]\nDouble Argument Usage: hw1.exe 1 URL-input.txt\n");
        return 1;
    }
}