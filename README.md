# InetSocketWrapper

Ten projekt to opakowanie dla klasycznych funkcji języka C dla gniazd TCP/IP, wykorzustujące programowanie zorientowane obiektowo.

Jego celem są:

- uproszczenie procedury tworzenia (przynajmniej niezbyt skomplikowanych) aplikacji sieciowych w języku C++
- większa przenaszalność między systemami Windows i Linux

Testowane przy użyciu `g++` (Linux) oraz `cl.exe` (Windows 10)

## Typy i stałe

### Typy danych

- `SocketType` - typ gniazda (TCP lub UDP)
- `InternetProtocol` - wersja protokołu IP (IPv4 lub IPv6)
- `SocketDescriptor` - deskryptor gniazda
- `byte` - bajt (`uint8_t`)
- `SocketAddress` - struktura opisująca gniazdo
  - host - nazwa hosta (`std::string`)
  - port - numer portu (`uint16_t`)

### Stałe

- TransmissionControlProtocol, TCP - typ gniazda TCP
- UserDatagramProtocol, UDP - typ gniazda UDP
- IPv4 - domena dla IPv4
- IPv6 - domena dla IPv6

## Metody publiczne klasy `InetSocket`

- `InetSocket(InternetProtocol ip, SocketType type)`
  - konstruktor, przyjmuje argumenty:
    - `ip` - IPv4 lub IPv6
    - `type` - TCP lub UDP


- `InetSocket(SocketDescriptor sockd)`
  - konstruktor wykorzystujący gotowy deskryptor gniazda do utworzenia obiektu


- `~InetSocket()` 
  - destruktor, zamyka deskryptor gniazda


- `bool CreateSocketDescriptor()`
  - tworzy deskryptor gniazda


- `bool Bind(SocketAddress addr)`
  - wiąże gniazdo z adresem IP i portem podanymi w `addr`


- `bool Connect(SocketAddress addr)`
  - łączy się z zdalną usługą opisaną przez adres IP i port w `addr`


- `void Listen(int backlog)`
  - przekształca gniazdo TCP w gniazdo bierne i rozpoczyna nasłuch


- `void Close()`
  - zamyka gniazdo


- `InetSocket AcceptConnection(SocketAddress &ClientAddress)`
  - akceptuje połączenie TCP
  - zwraca obiekt `InetSocket` (gniazdo klienckie)


- `bool SendBytes(const byte *data, size_t len, int flags = 0)`
  - wysyła bajty (`*data`) o podanym rozmiarze (`len`)


- `int SendString(const std::string &data, int flags = 0)`
  - wysyła łańcuch (`std::string`)


- `int ReceiveBytes(byte *buffer, size_t len, int flags = 0)`
  - odbiera podaną liczbę bajtów (`len`) i zapisuje dane w buforze (`*buffer`)


- `std::string ReceiveString(size_t len, int flags = 0)`
  - odbiera łańcuch znaków (`std::string`) o podanej długości (`len`)
  - zwraca otrzymany łańcuch


- `int SendBytesTo(byte *data, size_t len, SocketAddress target, int flags = 0)`
  - wysyła bajty (`*data`) o podanym rozmiarze (`len`) do usługi opisanej przez adres IP i numer portu w `target`


- `int SendStringTo(const std::string &data, SocketAddress target, int flags = 0)`
  - wysyła łańcuch znaków (`std::string data`) do usługi opisanej przez adres IP i numer portu w `target`


- `int ReceiveBytesFrom(byte *buffer, size_t len, SocketAddress &source, int flags = 0)`
  - odbiera podaną liczbę bajtów (`len`) i zapisuje dane w buforze (`*buffer`)
  - zapamiętuje adres IP i numer portu źródła w `source`


- `std::string ReceiveStringFrom(size_t len, SocketAddress &source, int flags = 0)`
  - odbiera łańcuch znaków (`std::string`) o podanej długości (`len`)
  - zapamiętuje adres IP i numer portu źródła w `source`
  - zwraca otrzymany łańcuch