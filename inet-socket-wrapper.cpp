#include <iostream>
#include <string>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>

#include "inet-socket-wrapper.h"

#ifdef WIN32

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


namespace InetSocketWrapper
{
        // tworzenie gniazda do odbierania
        bool InetSocket::BindToAddress(const char *host, const char *port)
        {
            if(this->sockfd > 0)
                closesocket(this->sockfd);
            
            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = AI_PASSIVE;   
            hints.ai_protocol = this->protocol;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;

            int gai_err;
            if((gai_err = getaddrinfo(host, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerrorA(gai_err));
                WSACleanup();
                freeaddrinfo(result);
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                this->sockfd = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(this->sockfd == INVALID_SOCKET) /* utworzenie gniazda do odbierania */
                    continue;

                int reuse = 1;
                if(setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == SOCKET_ERROR)
                {
                    std::string err = std::string("setsockopt: ") + std::to_string(WSAGetLastError());
                    WSACleanup();
                    freeaddrinfo(result);
                    exit(EXIT_FAILURE);
                }

                
                /* powiazanie gniazda z adresem IP i portem */
                if(bind(this->sockfd,p->ai_addr,p->ai_addrlen) == 0)
                {
                    break;
                }

                closesocket(this->sockfd);
            }

            if(p == NULL)
            {
                freeaddrinfo(result);
                return false;
            }

            freeaddrinfo(result);

            return true;
        }

        // tworzenie gniazda do wysylania
        bool InetSocket::ConnectToRemote(const char *addr, const char *port)
        {
            if(this->sockfd > 0)
                closesocket(this->sockfd);
            
            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = 0;
            hints.ai_protocol = this->protocol;  

            int gai_err;
            if((gai_err = getaddrinfo(addr, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerrorA(gai_err));
                WSACleanup();
                freeaddrinfo(result);
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                this->sockfd = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(this->sockfd == INVALID_SOCKET) /* utworzenie gniazda do wysylania */
                    continue;
                
                if(connect(this->sockfd,p->ai_addr,p->ai_addrlen) == 0)
                {
                    break;
                }

                closesocket(this->sockfd);
            }

            if(p == NULL)
            {
                freeaddrinfo(result);
                return false;
            }

            freeaddrinfo(result);

            return true;
        }

        sockaddr* InetSocket::GetRemoteHostInfo(const char *addr, const char *port)
        {
            size_t reslen;

            if(this->domain == IPv4)
            {
                reslen = sizeof(sockaddr_in);
            }
            else if(this->domain == IPv6)
            {
                reslen = sizeof(sockaddr_in6);
            }
            sockaddr *res = (sockaddr *)malloc(reslen);

            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = 0;
            hints.ai_protocol = this->protocol;  

            int gai_err;
            if((gai_err = getaddrinfo(addr, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerrorA(gai_err));
                WSACleanup();
                freeaddrinfo(result);
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                SocketDescriptor sock = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(sock == INVALID_SOCKET) /* utworzenie gniazda do wysylania */
                    continue;
                
                if(connect(sock,p->ai_addr,p->ai_addrlen) == 0)
                {
                    memcpy(res, p->ai_addr, p->ai_addrlen);
                    closesocket(sock);
                    break;
                }

                closesocket(sock);
            }

            freeaddrinfo(result);

            return res;
        }

        int InetSocket::Send(const byte *data, size_t len, int flags)
        {
            int n;
            if((n = send(this->sockfd, (char *)data, len, flags)) == SOCKET_ERROR)
            {
                std::string err = std::string("send: ") + std::to_string(WSAGetLastError());
                WSACleanup();
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::Receive(byte *buffer, size_t len, int flags)
        {
            memset(buffer, 0, len);
            int n;
            if((n = recv(this->sockfd, (char *)buffer, len, flags)) == SOCKET_ERROR)
            {
                std::string err = std::string("recv: ") + std::to_string(WSAGetLastError());
                WSACleanup();
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::SendTo(const byte *data, size_t len, sockaddr *addr, socklen_t addrlen, int flags)
        {
            int n;
            if((n = sendto(this->sockfd, (char *)data, len, flags, addr, addrlen)) == SOCKET_ERROR)
            {
                std::string err = std::string("sendto: ") + std::to_string(WSAGetLastError());
                WSACleanup();
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::ReceiveFrom(byte *buffer, size_t len, sockaddr *addr, socklen_t &addrlen, int flags)
        {
            memset(buffer, 0, len);
            int n;
            if((n = recvfrom(this->sockfd, (char *)buffer, len, flags, addr, &addrlen)) == SOCKET_ERROR)
            {
                std::string err = std::string("recvfrom: ") + std::to_string(WSAGetLastError());
                WSACleanup();
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }
            return n;
        }

        SocketDescriptor InetSocket::Accept(sockaddr *addr, socklen_t &addrlen)
        {
            SocketDescriptor newsockfd;
            if((newsockfd = accept(this->sockfd, addr, &addrlen)) == INVALID_SOCKET)
            {
                std::string err = std::string("accept: ") + std::to_string(WSAGetLastError());
                WSACleanup();
                std::cout << "ERROR " << err << std::endl;
                exit(EXIT_FAILURE);
            }

            return newsockfd;
        }


        InetSocket::InetSocket(InternetProtocol ip, SocketType type)
        {
            if(type == TCP || type == UDP)
            {
                this->type = type;
            }
            else
            {
                std::cout << "InetSocket: Invalid socket type" << std::endl;
                exit(EXIT_FAILURE);
            }

            if(ip == IPv4 || ip == IPv6)
            {
                this->domain = ip;
            }
            else
            {
                std::cout << "InetSocket: Invalid Internet Protocol" << std::endl;
                exit(EXIT_FAILURE);
            }

            int err;
            err = WSAStartup(MAKEWORD(2,2), &this->wsaData);
            if (err != 0) {

                std::string error = std::string("WSAStartup failed with error: ");
                error += std::to_string(err);
                throw std::runtime_error(error.c_str());
            }
        }

        InetSocket::InetSocket(SocketDescriptor sockd)
        {
            this->sockfd = sockd;
        }

        InetSocket::~InetSocket()
        {
            closesocket(this->sockfd);
        }

        bool InetSocket::CreateSocketDescriptor()
        {
            SocketDescriptor sock = socket(this->domain, this->type, this->protocol);
            if(sock == INVALID_SOCKET)
            {
                WSACleanup();
                return false;
            }

            this->sockfd = sock;
            return true;
        }

        bool InetSocket::Bind(SocketAddress addr)
        {
            char port[6];
            snprintf(port, 6, "%d", addr.port);

            return BindToAddress(addr.host.c_str(), port);
        }

        bool InetSocket::Connect(SocketAddress addr)
        {
            char port[6];
            snprintf(port, 6, "%d", addr.port);

            return ConnectToRemote(addr.host.c_str(), port);
        }

        void InetSocket::Listen(int backlog)
        {
            if(listen(this->sockfd, backlog) < 0)
            {
                std::string err = std::string("listen: ") + std::to_string(WSAGetLastError());
                exit(EXIT_FAILURE);
            }
        }

        void InetSocket::Close()
        {
            closesocket(this->sockfd);
        }

        InetSocket InetSocket::AcceptConnection(SocketAddress &ClientAddress)
        {
            SocketDescriptor newsockfd;

            if(this->domain == IPv4)
            {
                sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);

                newsockfd = Accept((sockaddr *)&addr, addrlen);

                char addrstr[INET_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin_addr.s_addr, addrstr, INET_ADDRSTRLEN);
                std::string s(addrstr);

                ClientAddress.host = s;
                ClientAddress.port = ntohs(addr.sin_port);
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 addr;
                socklen_t addrlen = sizeof(addr);

                newsockfd = Accept((sockaddr *)&addr, addrlen);

                char addrstr[INET6_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin6_addr.s6_addr, addrstr, INET6_ADDRSTRLEN);
                std::string s(addrstr);

                ClientAddress.host = s;
                ClientAddress.port = ntohs(addr.sin6_port);
            }

            return InetSocket(newsockfd);
        }

        bool InetSocket::SendBytes(const byte *data, size_t len, int flags)
        {
            return Send(data, len, flags);
        }

        int InetSocket::SendString(const std::string &data, int flags)
        {
            return Send((byte *)data.c_str(), data.length(), flags);
        }

        int InetSocket::ReceiveBytes(byte *buffer, size_t len, int flags)
        {
            return Receive(buffer, len, flags);
        }

        std::string InetSocket::ReceiveString(size_t len, int flags)
        {
            byte *buf = new byte[len];
            std::string buffer = ""; 
            int result = Receive(buf, len, flags);
            if(result)
            {
                std::string s((const char *)buf);
                buffer = s;
            }

            delete [] buf;

            return buffer;
        }

        int InetSocket::SendBytesTo(byte *data, size_t len, SocketAddress target, int flags)
        {
            char port[6];
            snprintf(port, 6, "%d", target.port);

            if(this->domain == IPv4)
            {
                sockaddr_in *addr = (sockaddr_in *)GetRemoteHostInfo(target.host.c_str(), port);
                socklen_t addrlen = sizeof(sockaddr_in);
                int n = SendTo(data, len, (sockaddr *)addr, addrlen, flags);
                free(addr);
                return n;
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 *addr = (sockaddr_in6 *)GetRemoteHostInfo(target.host.c_str(), port);
                socklen_t addrlen = sizeof(sockaddr_in6);
                int n = SendTo(data, len, (sockaddr *)addr, addrlen, flags);
                free(addr);
                return n;
            }

            return -1;
        }

        int InetSocket::SendStringTo(const std::string &data, SocketAddress target, int flags)
        {
            return SendBytesTo((byte *)data.c_str(), data.length(), target, flags);
        }

        int InetSocket::ReceiveBytesFrom(byte *buffer, size_t len, SocketAddress &source, int flags)
        {
            int n;
            if(this->domain == IPv4)
            {
                sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);
                n = ReceiveFrom(buffer, len, (sockaddr *)&addr, addrlen, flags);

                char addrstr[INET_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin_addr.s_addr, addrstr, INET_ADDRSTRLEN);
                std::string s(addrstr);

                source.host = s;
                source.port = ntohs(addr.sin_port);
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 addr;
                socklen_t addrlen = sizeof(addr);
                n = ReceiveFrom(buffer, len, (sockaddr *)&addr, addrlen, flags);

                char addrstr[INET6_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin6_addr.s6_addr, addrstr, INET6_ADDRSTRLEN);
                std::string s(addrstr);

                source.host = s;
                source.port = ntohs(addr.sin6_port);
            }

            return n;
        }

        std::string InetSocket::ReceiveStringFrom(size_t len, SocketAddress &source, int flags)
        {
            byte *buf = new byte[len];
            ReceiveBytesFrom(buf, len, source, flags);
            return std::string((char*)buf);
        }

}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>


namespace InetSocketWrapper
{
        // tworzenie gniazda do odbierania
        bool InetSocket::BindToAddress(const char *host, const char *port)
        {
            if(this->sockfd > 0)
                close(this->sockfd);
            
            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = AI_PASSIVE;   
            hints.ai_protocol = this->protocol;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;

            int gai_err;
            if((gai_err = getaddrinfo(host, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerror(gai_err));
                freeaddrinfo(result);
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                this->sockfd = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(this->sockfd < 0) /* utworzenie gniazda do odbierania */
                    continue;

                int reuse = 1;
                if(setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
                {
                    std::string err = std::string("setsockopt: ") + std::string(strerror(errno));
                    freeaddrinfo(result);
                    exit(EXIT_FAILURE);
                }

                
                /* powiazanie gniazda z adresem IP i portem */
                if(bind(this->sockfd,p->ai_addr,p->ai_addrlen) == 0)
                {
                    break;
                }

                close(this->sockfd);
            }

            if(p == NULL)
            {
                freeaddrinfo(result);
                return false;
            }

            freeaddrinfo(result);

            return true;
        }

        // tworzenie gniazda do wysylania
        bool InetSocket::ConnectToRemote(const char *addr, const char *port)
        {
            if(this->sockfd > 0)
                close(this->sockfd);
            
            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = 0;
            hints.ai_protocol = this->protocol;  

            int gai_err;
            if((gai_err = getaddrinfo(addr, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerror(gai_err));
                freeaddrinfo(result);
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                this->sockfd = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(this->sockfd < 0) /* utworzenie gniazda do wysylania */
                    continue;
                
                if(connect(this->sockfd,p->ai_addr,p->ai_addrlen) == 0)
                {
                    break;
                }

                close(this->sockfd);
            }

            if(p == NULL)
            {
                freeaddrinfo(result);
                return false;
            }

            freeaddrinfo(result);

            return true;
        }

        sockaddr* InetSocket::GetRemoteHostInfo(const char *addr, const char *port)
        {
            size_t reslen;

            if(this->domain == IPv4)
            {
                reslen = sizeof(sockaddr_in);
            }
            else if(this->domain == IPv6)
            {
                reslen = sizeof(sockaddr_in6);
            }
            sockaddr *res = (sockaddr *)malloc(reslen);

            struct addrinfo hints, *result, *p;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = this->domain;
            hints.ai_socktype = this->type;
            hints.ai_flags = 0;
            hints.ai_protocol = this->protocol;  

            int gai_err;
            if((gai_err = getaddrinfo(addr, port, &hints, &result)) != 0)
            {
                std::string err = std::string("getaddrinfo: ") + std::string(gai_strerror(gai_err));
                freeaddrinfo(result);
                exit(EXIT_FAILURE);
            }

            for(p = result; p != NULL; p = p->ai_next)
            {
                SocketDescriptor sock = socket(p->ai_family,p->ai_socktype,p->ai_protocol);
                if(sock < 0) /* utworzenie gniazda do wysylania */
                    continue;
                
                if(connect(sock,p->ai_addr,p->ai_addrlen) == 0)
                {
                    memcpy(res, p->ai_addr, p->ai_addrlen);
                    close(sock);
                    break;
                }

                close(sock);
            }

            freeaddrinfo(result);

            return res;
        }

        int InetSocket::Send(const byte *data, size_t len, int flags)
        {
            int n;
            if((n = send(this->sockfd, data, len, flags)) < 0)
            {
                std::string err = std::string("send: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::Receive(byte *buffer, size_t len, int flags)
        {
            bzero(buffer, len);
            int n;
            if((n = recv(this->sockfd, buffer, len, flags)) < 0)
            {
                std::string err = std::string("recv: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::SendTo(const byte *data, size_t len, sockaddr *addr, socklen_t addrlen, int flags)
        {
            int n;
            if((n = sendto(this->sockfd, data, len, flags, addr, addrlen)) < 0)
            {
                std::string err = std::string("sendto: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }
            return n;
        }

        int InetSocket::ReceiveFrom(byte *buffer, size_t len, sockaddr *addr, socklen_t &addrlen, int flags)
        {
            bzero(buffer, len);
            int n;
            if((n = recvfrom(this->sockfd, buffer, len, flags, addr, &addrlen)) < 0)
            {
                std::string err = std::string("recvfrom: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }
            return n;
        }

        SocketDescriptor InetSocket::Accept(sockaddr *addr, socklen_t &addrlen)
        {
            SocketDescriptor newsockfd;
            if((newsockfd = accept(this->sockfd, addr, &addrlen)) < 0)
            {
                std::string err = std::string("accept: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }

            return newsockfd;
        }


        InetSocket::InetSocket(InternetProtocol ip, SocketType type)
        {
            if(type == TCP || type == UDP)
            {
                this->type = type;
            }
            else
            {
                std::cout << "InetSocket: Invalid socket type" << std::endl;
                exit(EXIT_FAILURE);
            }

            if(ip == IPv4 || ip == IPv6)
            {
                this->domain = ip;
            }
            else
            {
                std::cout << "InetSocket: Invalid Internet Protocol" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        InetSocket::InetSocket(SocketDescriptor sockd)
        {
            this->sockfd = sockd;
        }

        InetSocket::~InetSocket()
        {
            close(this->sockfd);
        }

        bool InetSocket::CreateSocketDescriptor()
        {
            SocketDescriptor sock = socket(this->domain, this->type, this->protocol);
            if(sock < 0)
            {
                return false;
            }

            this->sockfd = sock;
            return true;
        }

        bool InetSocket::Bind(SocketAddress addr)
        {
            char port[6];
            snprintf(port, 6, "%d", addr.port);

            return BindToAddress(addr.host.c_str(), port);
        }

        bool InetSocket::Connect(SocketAddress addr)
        {
            char port[6];
            snprintf(port, 6, "%d", addr.port);

            return ConnectToRemote(addr.host.c_str(), port);
        }

        void InetSocket::Listen(int backlog)
        {
            if(listen(this->sockfd, backlog) < 0)
            {
                std::string err = std::string("listen: ") + std::string(strerror(errno));
                exit(EXIT_FAILURE);
            }
        }

        void InetSocket::Close()
        {
            close(this->sockfd);
        }

        InetSocket InetSocket::AcceptConnection(SocketAddress &ClientAddress)
        {
            SocketDescriptor newsockfd;

            if(this->domain == IPv4)
            {
                sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);

                newsockfd = Accept((sockaddr *)&addr, addrlen);

                char addrstr[INET_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin_addr.s_addr, addrstr, INET_ADDRSTRLEN);
                std::string s(addrstr);

                ClientAddress.host = s;
                ClientAddress.port = ntohs(addr.sin_port);
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 addr;
                socklen_t addrlen = sizeof(addr);

                newsockfd = Accept((sockaddr *)&addr, addrlen);

                char addrstr[INET6_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin6_addr.s6_addr, addrstr, INET6_ADDRSTRLEN);
                std::string s(addrstr);

                ClientAddress.host = s;
                ClientAddress.port = ntohs(addr.sin6_port);
            }

            return InetSocket(newsockfd);
        }

        bool InetSocket::SendBytes(const byte *data, size_t len, int flags)
        {
            return Send(data, len, flags);
        }

        int InetSocket::SendString(const std::string &data, int flags)
        {
            return Send((byte *)data.c_str(), data.length(), flags);
        }

        int InetSocket::ReceiveBytes(byte *buffer, size_t len, int flags)
        {
            return Receive(buffer, len, flags);
        }

        std::string InetSocket::ReceiveString(size_t len, int flags)
        {
            byte buf[len];
            std::string buffer = ""; 
            int result = Receive(buf, len, flags);
            if(result)
            {
                std::string s((const char *)buf);
                buffer = s;
            }
            return buffer;
        }

        int InetSocket::SendBytesTo(byte *data, size_t len, SocketAddress target, int flags)
        {
            char port[6];
            snprintf(port, 6, "%d", target.port);

            if(this->domain == IPv4)
            {
                sockaddr_in *addr = (sockaddr_in *)GetRemoteHostInfo(target.host.c_str(), port);
                socklen_t addrlen = sizeof(sockaddr_in);
                int n = SendTo(data, len, (sockaddr *)addr, addrlen, flags);
                free(addr);
                return n;
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 *addr = (sockaddr_in6 *)GetRemoteHostInfo(target.host.c_str(), port);
                socklen_t addrlen = sizeof(sockaddr_in6);
                int n = SendTo(data, len, (sockaddr *)addr, addrlen, flags);
                free(addr);
                return n;
            }

            return -1;
        }

        int InetSocket::SendStringTo(const std::string &data, SocketAddress target, int flags)
        {
            return SendBytesTo((byte *)data.c_str(), data.length(), target, flags);
        }

        int InetSocket::ReceiveBytesFrom(byte *buffer, size_t len, SocketAddress &source, int flags)
        {
            int n;
            if(this->domain == IPv4)
            {
                sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);
                n = ReceiveFrom(buffer, len, (sockaddr *)&addr, addrlen, flags);

                char addrstr[INET_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin_addr.s_addr, addrstr, INET_ADDRSTRLEN);
                std::string s(addrstr);

                source.host = s;
                source.port = ntohs(addr.sin_port);
            }
            else if(this->domain == IPv6)
            {
                sockaddr_in6 addr;
                socklen_t addrlen = sizeof(addr);
                n = ReceiveFrom(buffer, len, (sockaddr *)&addr, addrlen, flags);

                char addrstr[INET6_ADDRSTRLEN];

                inet_ntop(this->domain, &addr.sin6_addr.s6_addr, addrstr, INET6_ADDRSTRLEN);
                std::string s(addrstr);

                source.host = s;
                source.port = ntohs(addr.sin6_port);
            }

            return n;
        }

        std::string InetSocket::ReceiveStringFrom(size_t len, SocketAddress &source, int flags)
        {
            byte *buf = new byte[len];
            ReceiveBytesFrom(buf, len, source, flags);
            return std::string((char*)buf);
        }

}

#endif