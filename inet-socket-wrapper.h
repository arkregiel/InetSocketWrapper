#pragma once

#include <stdint.h>
#include <string>

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <sys/socket.h>

#endif

namespace InetSocketWrapper
{
    enum SocketType : int
    {
        TCP = SOCK_STREAM,
        UDP = SOCK_DGRAM,
        TransmissionControlProtocol = TCP,
        UserDatagramProtocol = UDP
    };

    enum InternetProtocol : int
    {
        IPv4 = AF_INET,
        IPv6 = AF_INET6
    };

#ifdef _WIN32
    typedef SOCKET SocketDescriptor;

    class WsaReference
    {
        static int wsaReferenced;
        static WSADATA wsaData;
    public:
        WsaReference();
        ~WsaReference();
        WsaReference(const WsaReference&);
    };

#else
    typedef int SocketDescriptor;
#endif

    typedef uint8_t byte;

    struct SocketAddress
    {
        std::string host;
        uint16_t port;

        inline bool operator <(const SocketAddress& other) const
        {
            if (host < other.host)
                return true;
            return port < other.port;
        }
    };

    class InetSocket
    {
        const int protocol = 0;
        InternetProtocol domain;
        SocketType type;

        SocketDescriptor sockfd = -1;
#ifdef _WIN32
        WsaReference wsaReference;
#endif

        // tworzenie gniazda do odbierania
        bool BindToAddress(const char *host, const char *port);

        
        // tworzenie gniazda do wysylania
        bool ConnectToRemote(const char *addr, const char *port);
        

        sockaddr* GetRemoteHostInfo(const char *addr, const char *port);

        
        int Send(const byte *data, size_t len, int flags = 0);

        
        int Receive(byte *buffer, size_t len, int flags = 0);

        
        int SendTo(const byte *data, size_t len, sockaddr *addr, socklen_t addrlen, int flags = 0);


        int ReceiveFrom(byte *buffer, size_t len, sockaddr *addr, socklen_t &addrlen, int flags = 0);


        SocketDescriptor Accept(sockaddr *addr, socklen_t &addrlen);

    public:

        InetSocket(InternetProtocol ip, SocketType type);


        InetSocket(SocketDescriptor sockd);


        ~InetSocket();


        bool CreateSocketDescriptor();


        bool Bind(SocketAddress addr);


        bool Connect(SocketAddress addr);


        void Listen(int backlog);


        void Close();
    

        InetSocket AcceptConnection(SocketAddress &ClientAddress);


        bool SendBytes(const byte *data, size_t len, int flags = 0);
    

        int SendString(const std::string &data, int flags = 0);
    

        int ReceiveBytes(byte *buffer, size_t len, int flags = 0);


        std::string ReceiveString(size_t len, int flags = 0);
        

        int SendBytesTo(byte *data, size_t len, SocketAddress target, int flags = 0);
       

        int SendStringTo(const std::string &data, SocketAddress target, int flags = 0);


        int ReceiveBytesFrom(byte *buffer, size_t len, SocketAddress &source, int flags = 0);
        

        std::string ReceiveStringFrom(size_t len, SocketAddress &source, int flags = 0);

    };
}