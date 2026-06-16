
#pragma once

#include <windows.h>

class PortMonitor {
public:
    explicit PortMonitor(const int& numberOfProtocol);
    ~PortMonitor();
    void Display();

private:
    int m_NumberOfProtocol;
    void TCP();
    void UDP();
    std::string GetTcpStateString(DWORD state);
    std::string GetProcessName(DWORD processId);
};
