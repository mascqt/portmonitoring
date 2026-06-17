
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <iomanip>
#include <tlhelp32.h>
#include "PortMonitor.h"

PortMonitor::PortMonitor(const int& numberOfProtocol) : m_NumberOfProtocol(numberOfProtocol) {}

PortMonitor::~PortMonitor() = default;

void PortMonitor::Display() {
    std::map<DWORD, std::pair<std::string, std::string>> processMap;

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapShot, &pe32)) {
            do {
                std::string userName = GetProcessUsername(pe32.th32ProcessID);
                processMap[pe32.th32ProcessID] = std::make_pair(pe32.szExeFile, userName);
            } while (Process32Next(hSnapShot, &pe32));
        }
        CloseHandle(hSnapShot);
    }

    switch (m_NumberOfProtocol) {
        case 1:
            TCP(processMap);
            break;
        case 2:
            UDP(processMap);
            break;
        case 3:
            TCP(processMap);
            UDP(processMap);
            break;
        default:
            std::cout << "Invalid selection. Please select a valid protocol number." << std::endl;
    }
}

void PortMonitor::TCP(const std::map<DWORD, std::pair<std::string, std::string>>& processMap) {
    ULONG tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<BYTE> tcpBuffer(tcpSize);
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcpBuffer.data());

    std::cout << std::left;
    std::cout << std::string(143, '=') << std::endl;
    std::cout << " [TCP Ports Table]\n";
    std::cout << std::string(143, '=') << std::endl;
    std::cout << std::setw(10) << "Protocol" << std::setw(18) << "Local IP" << std::setw(10) << "Port"
              << std::setw(22) << "State" << std::setw(8) << "PID"
              << std::setw(25) << "Application Name" << std::setw(25) << "Company" << "User Owner\n";
    std::cout << std::string(143, '-') << std::endl;

    if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
            USHORT localPort = ntohs(static_cast<USHORT>(row.dwLocalPort));

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr, ipStr, INET_ADDRSTRLEN);

            std::string companyName, userName;
            std::string appName = GetProcessName(row.dwOwningPid, processMap, companyName, userName);

            std::cout << std::setw(10) << "TCP" << std::setw(18) << ipStr << std::setw(10) << localPort
                      << std::setw(22) << GetTcpStateString(row.dwState) << std::setw(8) << row.dwOwningPid
                      << std::setw(25) << appName << std::setw(25) << companyName << userName << std::endl;
        }
    }
    std::cout << "\n\n";
}

std::string PortMonitor::GetTcpStateString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING (Open)";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED (In Use)";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                       return "UNKNOWN";
    }
}

std::string PortMonitor::GetProcessName(DWORD processId,const std::map<DWORD, std::pair<std::string, std::string>>& processMap, std::string& companyName, std::string& userName) {
    if (processId == 0) {
        companyName = "Microsoft";
        userName = "NT AUTHORITY\\SYSTEM";
        return "System Idle Process";
    }

    if (processId == 4) {
        companyName = "Microsoft";
        userName = "NT AUTHORITY\\SYSTEM";
        return "System";
    }

    std::string fileName = "Unknown Process";
    userName = "Unknown User";
    companyName = "Unknown Company";

    auto it = processMap.find(processId);
    if (it != processMap.end()) {
        fileName = it->second.first;
        userName = it->second.second;
    }

    std::string exePath = GetProcessPath(processId);
    std::string appName = GetAppNameFromExe(exePath);
    std::string compName = GetCompanyNameFromExe(exePath);

    if (!compName.empty()) companyName = compName;

    return (!appName.empty()) ? appName : fileName;
}

std::string PortMonitor::GetProcessPath(DWORD processId) {
    if (processId == 0 || processId == 4) return "";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return "";

    char pathBuffer[MAX_PATH];
    DWORD size = sizeof(pathBuffer);
    if (QueryFullProcessImageNameA(hProcess, 0, pathBuffer, &size)) {
        CloseHandle(hProcess);
        return std::string(pathBuffer);
    }
    CloseHandle(hProcess);
    return "";
}

std::string PortMonitor::GetAppNameFromExe(const std::string &exePath) {
    if (exePath.empty()) return "";

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeA(exePath.c_str(), &handle);
    if (size == 0) return "";

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoA(exePath.c_str(), 0, size, buffer.data())) return "";

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate = 0;
    if (VerQueryValueA(buffer.data(), "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        char subBlock[256];
        sprintf_s(subBlock, "\\StringFileInfo\\%04x%04x\\ProductName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

        char* productName = nullptr;
        UINT length = 0;
        if (VerQueryValueA(buffer.data(), subBlock, (LPVOID*)&productName, &length) && length > 0) {
            return std::string(productName);
        }
    }
    return "";
}

std::string PortMonitor::GetCompanyNameFromExe(const std::string &exePath) {

    if (exePath.empty()) return "";

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeA(exePath.c_str(), &handle);
    if (size == 0) return "";

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoA(exePath.c_str(), 0, size, buffer.data())) return "";

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate = 0;
    if (VerQueryValueA(buffer.data(), "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        char subBlock[256];

        sprintf_s(subBlock, R"(\StringFileInfo\%04x%04x\CompanyName)", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

        char* companyName = nullptr;
        UINT length = 0;
        if (VerQueryValueA(buffer.data(), subBlock, (LPVOID*)&companyName, &length) && length > 0) {
            return companyName;
        }
    }
    return "";
}

std::string PortMonitor::GetProcessUsername(DWORD processId) {
    if (processId == 0) return "NT AUTHORITY\\SYSTEM";
    if (processId == 4) return "NT AUTHORITY\\SYSTEM";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return "Access Denied";

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "Unknown";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    std::vector<BYTE> tokenBuffer(dwSize);
    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenBuffer.data());

    std::string username = "Unknown";
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        char name[256], domain[256];
        DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
        SID_NAME_USE sidType;

        if (LookupAccountSidA(nullptr, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
            username = std::string(domain) + "\\" + std::string(name); // فرمت: Domain\Username
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return username;
}

void PortMonitor::UDP(const std::map<DWORD, std::pair<std::string, std::string>>& processMap) {
    ULONG udpSize = 0;
    GetExtendedUdpTable(nullptr, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    std::vector<BYTE> udpBuffer(udpSize);
    PMIB_UDPTABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpBuffer.data());

    std::cout << std::left;
    std::cout << std::string(143, '=') << std::endl;
    std::cout << " [UDP Ports Table (No State)]\n";
    std::cout << std::string(143, '=') << std::endl;
    std::cout << std::setw(10) << "Protocol" << std::setw(18) << "Local IP" << std::setw(10) << "Port"
              << std::setw(8) << "PID"
              << std::setw(25) << "Application Name" << std::setw(25) << "Company" << "User Owner\n";
    std::cout << std::string(143, '-') << std::endl;

    if (GetExtendedUdpTable(udpTable, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID row = udpTable->table[i];
            USHORT localPort = ntohs((USHORT)row.dwLocalPort);

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr, ipStr, INET_ADDRSTRLEN);

            std::string companyName, username;
            std::string appName = GetProcessName(row.dwOwningPid, processMap, companyName, username);

            std::cout << std::setw(10) << "UDP" << std::setw(18) << ipStr << std::setw(10) << localPort
                      << std::setw(8) << row.dwOwningPid
                      << std::setw(25) << appName << std::setw(25) << companyName << username << "\n";
        }
    }
    std::cout << "\n\n";
}
