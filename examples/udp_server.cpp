#include <iostream>
#include <string>
#include <stdlib.h>

#include "inet-socket-wrapper.h"

using std::cout;
using std::endl;
using std::string;

using namespace InetSocketWrapper;

int main()
{
    SocketAddress addr = { "localhost", 8888 };
    InetSocket sock(IPv4, UDP);
    //InetSocket sock(IPv6, UDP);

    if(!sock.Bind(addr))
    {
        cout << "[!!] Bind failed" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "[*] Listening on [" << addr.host << ':' << addr.port << ']' << endl;

    while(true)
    {
        SocketAddress clientAddress;
        

        string data = sock.ReceiveStringFrom(256, clientAddress);

        cout << "[*] Data from [" << clientAddress.host << ':' << clientAddress.port << "]: " << data << endl;

        sock.SendStringTo(data, clientAddress);

    }

    return 0;
}