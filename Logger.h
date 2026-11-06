#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

class ThreatLogger {
private:
    std::string logFileName;

    // Current time get karne ke liye helper function
    std::string getCurrentTimestamp() {
        std::time_t now = std::time(nullptr);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return std::string(buf);
    }

public:
    ThreatLogger(const std::string& filename = "security_audit.txt") {
        logFileName = filename;
    }

    // Yeh function explanation ke sath log save karega (Explainability feature!)
    void logEvent(const std::string& threatLevel, const std::string& description, const std::string& actionTaken) {
        std::string timestamp = getCurrentTimestamp();
        
        // Formatted log message
        std::string logEntry = "[" + timestamp + "] [" + threatLevel + "] " + description + " | Action: " + actionTaken;

        // 1. Console par print karo (Color codes ya simple text)
        std::cout << logEntry << std::endl;

        // 2. File mein save karo
        std::ofstream outFile(logFileName, std::ios::app);
        if (outFile.is_open()) {
            outFile << logEntry << "\n";
            outFile.close();
        } else {
            std::cerr << "Error: Could not open log file!" << std::endl;
        }
    }
};

// --- Test karne ke liye chota sa main function ---
int main() {
    ThreatLogger logger;

    // Simulate Observe -> Analyze -> Decide -> Execute -> Explain -> Log flow
    logger.logEvent("WARNING", "Multiple failed login attempts detected from IP: 192.168.1.45", "Triggered rate-limit check.");
    logger.logEvent("CRITICAL", "Unauthorized root access attempt on port 22.", "Blocked IP and generated audit report.");

    return 0;
}
