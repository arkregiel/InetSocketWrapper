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
    InetSocket serverSocket(IPv4, TCP);
    //InetSocket serverSocket(IPv6, TCP);

    cout << "[*] Binding... ";
    if(!serverSocket.Bind(addr))
    {
        cout << "ERROR" << endl << "[!!] Bind failed" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "OK" << endl;

    serverSocket.Listen(5);

    cout << "[*] Listening on [" << addr.host << ':' << addr.port << ']' << endl;

    while(true)
    {
        SocketAddress clientAddress;
        auto clientSocket = serverSocket.AcceptConnection(clientAddress);
        cout << "[+] New connection: [" << clientAddress.host << ':';
        cout << clientAddress.port << ']' << endl;

        string data = clientSocket.ReceiveString(256);

        cout << "[*] Data: " << data << endl;

        clientSocket.SendString(data);

        clientSocket.Close();

        cout << "[-] Connection closed" << endl;
    }
    return 0;
}