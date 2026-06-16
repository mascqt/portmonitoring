
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
    switch (m_NumberOfProtocol) {
        case 1:
            TCP();
            break;
        case 2:
            UDP();
            break;
        case 3:
            TCP();
            UDP();
            break;
        default:
            std::cout << "Invalid selection. Please select a valid protocol number." << std::endl;
    }
}

void PortMonitor::TCP() {
    // ==================== بخش اول: پورت‌های TCP ====================
    ULONG tcpSize = 0;
    //GetTcpTable(nullptr, &tcpSize, FALSE); // گرفتن سایز بافر
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<BYTE> tcpBuffer(tcpSize);
    //PMIB_TCPTABLE tcpTable = reinterpret_cast<PMIB_TCPTABLE>(tcpBuffer.data());
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcpBuffer.data());

    // تنظیم فرمت چاپ برای مرتب بودن ستون‌ها در کنسول CLion
    std::cout << std::left;
    std::cout << "=====================================================================\n";
    std::cout << " [TCP Ports Table]\n";
    std::cout << "=====================================================================\n";
    std::cout << std::setw(10) << "Protocol"
              << std::setw(18) << "Local IP"
              << std::setw(10) << "Port"
              << std::setw(22) << "State"
              << std::setw(8)  << "PID"
              << "Process Name\n";
    std::cout << "---------------------------------------------------------------------\n";

    if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
            USHORT localPort = ntohs((USHORT)row.dwLocalPort);

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr, ipStr, INET_ADDRSTRLEN);

            std::string procName = GetProcessName(row.dwOwningPid);

            std::cout << std::setw(10) << "TCP"
                      << std::setw(18) << ipStr
                      << std::setw(10) << localPort
                      << std::setw(22) << GetTcpStateString(row.dwState)
                      << std::setw(8)  << row.dwOwningPid
                      << procName << "\n";
        }
    }

    std::cout << "\n\n";
}

// تابعی برای تبدیل وضعیت پورت‌های TCP به متن خوانا
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

std::string PortMonitor::GetProcessName(DWORD processId) {
    // اگر فرآیند سیستم (PID 0) بود، اسمش رو دستی می‌نویسیم
    if (processId == 0) return "System Idle Process";
    if (processId == 4) return "System";

    std::string processName = "Unknown";

    // گرفتن یک عکس (Snapshot) از تمام فرآیندهای در حال اجرای سیستم
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // چرخیدن در بین فرآیندها برای پیدا کردن PID هم‌نام
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == processId) {
                    processName = pe32.szExeFile; // اسم فایل اجرایی (مثلا chrome.exe)
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot); // بستن کپچر برای آزاد شدن حافظه
    }
    return processName;
}

void PortMonitor::UDP() {
    // ==================== بخش دوم: پورت‌های UDP ====================
    ULONG udpSize = 0;
    //GetUdpTable(nullptr, &udpSize, FALSE); // گرفتن سایز بافر
    GetExtendedUdpTable(nullptr, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    std::vector<BYTE> udpBuffer(udpSize);
    //PMIB_UDPTABLE udpTable = reinterpret_cast<PMIB_UDPTABLE>(udpBuffer.data());
    PMIB_UDPTABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpBuffer.data());

    // تنظیم فرمت چاپ برای مرتب بودن ستون‌ها در کنسول CLion
    std::cout << std::left;
    std::cout << "=====================================================================\n";
    std::cout << " [UDP Ports Table (No State)]\n";
    std::cout << "=====================================================================\n";
    std::cout << std::setw(10) << "Protocol"
              << std::setw(18) << "Local IP"
              << std::setw(10) << "Port"
              << std::setw(8)  << "PID"
              << "Process Name\n";
    std::cout << "---------------------------------------------------------------------\n";

    if (GetExtendedUdpTable(udpTable, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID row = udpTable->table[i];
            USHORT localPort = ntohs((USHORT)row.dwLocalPort);

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr, ipStr, INET_ADDRSTRLEN);

            std::string procName = GetProcessName(row.dwOwningPid);

            std::cout << std::setw(10) << "UDP"
                      << std::setw(18) << ipStr
                      << std::setw(10) << localPort
                      << std::setw(8)  << row.dwOwningPid
                      << procName << "\n";
        }
    }
}
