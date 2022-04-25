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
    InetSocket sock(IPv4, TCP);
    //InetSocket sock(IPv6, TCP);

    if(!sock.Connect(target))
    {
        cout << "[!!] Connect failed" << endl;
        exit(EXIT_FAILURE);
    }

    string data;
    cout << "> ";
    cin >> data;

    sock.SendString(data);

    string response = sock.ReceiveString(256);

    cout << "Echo: " << response << endl;
}