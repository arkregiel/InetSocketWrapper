#include <iostream>
#include <string>
#include <stdlib.h>

#include "inet-socket-wrapper.h"

using std::cout;
using std::cin;
using std::endl;
using std::string;

using namespace InetSocketWrapper;

int main()
{
    SocketAddress target = { "localhost", 8888 };
    InetSocket sock(IPv4, UDP);
    //InetSocket sock(IPv6, UDP);

    sock.CreateSocketDescriptor();

    string data;
    cout << "> ";
    cin >> data;

    sock.SendStringTo(data, target);

    SocketAddress remoteAddr;
    string response = sock.ReceiveStringFrom(256, remoteAddr);

    cout << "Echo from [" << remoteAddr.host << ":" << remoteAddr.port << "]: " << response << endl;
}