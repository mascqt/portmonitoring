
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
    std::string GetProcessName(DWORD processId, std::string& companyName, std::string& username);

    std::string GetProcessPath(DWORD processId);
    std::string GetAppNameFromExe(const std::string& exePath);

    std::string GetCompanyNameFromExe(const std::string& exePath);
    std::string GetProcessUsername(DWORD processId);
};
