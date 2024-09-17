// hw1.cpp

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <set>
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

public:
    Socket(SOCKET s) : sock(s), buf(nullptr), allocatedSize(0), curPos(0) {
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
                    printf("failed with slow download\n");
                    break;
                }
                if (bytes == SOCKET_ERROR) {
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
                printf("failed with timeout\n");
                break;
            }
            else {
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

bool connect_socket(char* request, char* urlCopy, SOCKET sock, char* method) {
    size_t httpRequestLength = strlen(request) + strlen(urlCopy) + 100;
    char* sendBuf = new char[httpRequestLength];
    std::memset(sendBuf, '\0', httpRequestLength);
    sprintf_s(sendBuf, httpRequestLength, "%s %s HTTP/1.0\r\nHost: %s\r\nUser-agent: myTAMUcrawler/1.0\r\nConnection: close\r\n\r\n", method, request, urlCopy);
    if (send(sock, sendBuf, httpRequestLength, 0) == SOCKET_ERROR)
    {
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


bool load_page(char* method, char* port, char* request, char* urlCopy, sockaddr_in server, int maxRead, char* statusCode, char** buf, int* bufLength) {
    clock_t t = clock();
    
    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        printf("failed with %d\n", WSAGetLastError());
        WSACleanup();
        cleanup(urlCopy, port, request);
        return false;
    }
    // open a TCP socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        printf("failed with %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return false;
    }
    // connect to the server on port
    if (connect(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        printf("failed with %d on connect\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return false;
    }

    if (!connect_socket(request, urlCopy, sock, method)) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    printf("done in %.2f sec\n", (double)(clock() - t) / CLOCKS_PER_SEC);

    printf("\tLoading... ");
    t = clock();
    Socket s(sock);
    if (!s.Read(maxRead)) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    *buf = s.GetBuffer();
    *bufLength = s.GetCurPos();
    if (strncmp(*buf, "HTTP/", 5) != 0) {
        printf("failed with non-HTTP header (does not begin with HTTP/)\n");
        closesocket(sock);
        WSACleanup();
        return false;
    }
    printf("done in %.2f sec with %d bytes\n", (double)(clock() - t) / CLOCKS_PER_SEC, *bufLength);

    printf("\tVerifying header... ");
    std::memset(statusCode, '\0', 4);
    statusCode[0] = (*buf)[9];
    statusCode[1] = (*buf)[10];
    statusCode[2] = (*buf)[11];
    printf("status code %s\n", statusCode);
    closesocket(sock);
    WSACleanup();
    return true;
}

bool processURL(const char* url, std::set<DWORD>& seenIPs, std::set<std::string>& seenHosts) {
    printf("URL: %s\n", url);
    printf("\tParsing URL... ");

    const char* httpPrefix = "http://";
    if (strncmp(url, httpPrefix, strlen(httpPrefix)) != 0) {
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
        printf("exceed maximum host len\n");
        cleanup(urlCopy, port, request);
        return false;
    }

    if (strlen(request) > MAX_REQUEST_LEN) {
        printf("exceed maximum request len\n");
        cleanup(urlCopy, port, request);
        return false;
    }

    printf("host %s, port %s\n", urlCopy, port);

    printf("\tChecking host uniqueness... ");
    auto hostResult = seenHosts.insert(std::string(urlCopy));
    if (hostResult.second) {
        printf("passed\n");
    }
    else {
        printf("failed\n");
        cleanup(urlCopy, port, request);
        return false;
    }

    printf("\tDoing DNS... ");
    clock_t t = clock();

    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
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

    printf("done in %.2f sec, found %s\n", (double)(clock() - t) / CLOCKS_PER_SEC, inet_ntoa(server.sin_addr));

    printf("\tChecking IP uniqueness... ");
    auto ipResult = seenIPs.insert(server.sin_addr.s_addr);
    if (ipResult.second) {
        printf("passed\n");
    }
    else {
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
    printf("\tConnecting on robots... ");
    char robotsRequest[20] = "/robots.txt";
    char robotMethod[5] = "HEAD";
    if (!load_page(robotMethod, port, robotsRequest, urlCopy, server, MAX_ROBOT_READ, statusCode, &buf, &bufLength)) {
        cleanup(urlCopy, port, request);
        return false;
    }

    if (statusCode[0] != '4') {
        return false;
    }

    printf("*\tConnecting on page... ");
    char method[4] = "GET";
    if (!load_page(method, port, request, urlCopy, server, MAX_PAGE_READ, statusCode, &buf, &bufLength)) {
        cleanup(urlCopy, port, request);
        return false;
    }
    cleanup(urlCopy, port, request);

    char* headerEnd = strstr(buf, "\r\n\r\n");
    size_t headerLength = headerEnd - buf + 4;

    if (statusCode[0] == '2') {
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
        printf("done in %.2f sec with %d links\n", (double)(clock() - t) / CLOCKS_PER_SEC, nLinks);
    }
    return true;
}

int main(int argc, char* argv[])
{

    std::set<DWORD> seenIPs;
    std::set<std::string> seenHosts;

    if (argc == 2) {
        const char* url = argv[1];
        processURL(url, seenIPs, seenHosts);
        return 0;
    }
    else if (argc == 3) {
        int num_threads = std::atoi(argv[1]);
        const char* filename = argv[2];

        if (num_threads != 1) {
            printf("Usage: hw1.exe 1 URL-input.txt\n");
            return 1;
        }
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

            char** url_list = (char**) malloc(url_count * sizeof(char*));
            char* current_url = buf;
            int url_index = 0;
            for (long i = 0; i < file_size; i++) {
                if (buf[i] == '\r') {
                    buf[i] = '\0';
                }
                if (buf[i] == '\n') {
                    buf[i] = '\0';
                    url_list[url_index] = current_url;
                    url_index++;
                    current_url = buf + i + 1;
                }
            }
            if (*current_url != '\0') {
                url_list[url_index] = current_url;
            }

            for (int i = 0; i < url_count; i++) {
                processURL(url_list[i], seenIPs, seenHosts);
            }

            free(url_list);
            delete[] buf;
        }
        else {
            printf("file does not exist\n");
            return 1;
        }


        return 0;
    }
    else {
        printf("Single Argument Usage: hw1.exe http://host[:port][/path][?query][#fragment]\nDouble Argument Usage: hw1.exe 1 URL-input.txt\n");
        return 1;
    }
}