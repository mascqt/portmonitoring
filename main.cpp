#include <iostream>

#include "PortMonitor.h"

int main() {
    bool flag = true;
    while (flag) {
        int userChoose;
        std::cout << "Please select witch protocol you want to monitor:" << std::endl;
        std::cout << "1-TCP  2-UDP  3-Both  4-Exit (Enter the number):";
        std::cin >> userChoose;

        if (userChoose == 1 || userChoose == 2 || userChoose == 3) {
            PortMonitor monitor(userChoose);
            monitor.Display();
        }
        else if (userChoose == 4) {
            flag = false;
        }
        else
            std::cout << "Please enter a valid option!" << std::endl;
    }
    return 0;
}