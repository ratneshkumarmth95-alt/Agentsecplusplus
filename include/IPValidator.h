
#pragma once

#include <string>
#include <sstream>
#include <cctype>

class IPValidator {
public:
    static bool isValidIPv4(const std::string& ip) {
        std::stringstream ss(ip);
        std::string part;
        int count = 0;

        while (std::getline(ss, part, '.')) {
            if (part.empty() || part.size() > 3)
                return false;

            for (char c : part) {
                if (!std::isdigit(static_cast<unsigned char>(c)))
                    return false;
            }

            int value = std::stoi(part);

            if (value > 255)
                return false;

            if (part.size() > 1 && part[0] == '0')
                return false;

            count++;
        }

        return count == 4 && ip.back() != '.';
    }
};
