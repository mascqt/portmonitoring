#include <iostream>
#include <thread>
#include <chrono>
#include "PortMonitor.h"

int main() {
    int userChoose;
    std::cout << "Please select which protocol you want to monitor:\n";
    std::cout << "1-TCP  2-UDP  3-Both  4-Exit (Enter the number): ";
    std::cin >> userChoose;

    if (userChoose == 4) {
        return 0;
    }
    else if (userChoose == 1 || userChoose == 2 || userChoose == 3) {
        std::cout << "Starting Real-time Monitoring... Press Ctrl+C to stop.\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));

        while (true) {
            system("cls");

            std::cout << "Monitoring Active... [Press Ctrl+C to Exit]\n\n";
            PortMonitor monitor(userChoose);
            monitor.Display();

            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    else {
        std::cout << "Please enter a valid option!\n";
    }
    return 0;
}