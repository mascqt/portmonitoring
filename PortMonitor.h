
#pragma once

#include <windows.h>
#include <map>

class PortMonitor {
public:
    explicit PortMonitor(const int& numberOfProtocol);
    ~PortMonitor();
    void Display();

private:
    int m_NumberOfProtocol;
    void TCP(const std::map<DWORD, std::pair<std::string, std::string>>& processMap);
    void UDP(const std::map<DWORD, std::pair<std::string, std::string>>& processMap);
    std::string GetTcpStateString(DWORD state);
    std::string GetProcessName(DWORD processId, const std::map<DWORD, std::pair<std::string, std::string>>& processMap, std::string& companyName, std::string& username);

    std::string GetProcessPath(DWORD processId);
    std::string GetAppNameFromExe(const std::string& exePath);

    std::string GetCompanyNameFromExe(const std::string& exePath);
    std::string GetProcessUsername(DWORD processId);
};
