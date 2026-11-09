#pragma once
#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };

inline double getSeverityScore(Severity s) {
    switch(s) {
        case Severity::LOW: return 0.25;
        case Severity::MEDIUM: return 0.50;
        case Severity::HIGH: return 0.75;
        case Severity::CRITICAL: return 1.0;
        default: return 0.0;
    }
}

inline std::string severityToString(Severity s) {
    switch(s) {
        case Severity::LOW: return "Low";
        case Severity::MEDIUM: return "Medium";
        case Severity::HIGH: return "High";
        case Severity::CRITICAL: return "Critical";
        default: return "Unknown";
    }
}

class SecurityEvent {
protected:
    std::string timestamp;
    std::string sourceIP;
    Severity severity;
    std::string description;
    std::string eventType;

    std::string generateTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

public:
 SecurityEvent(const std::string& ip, Severity sev, const std::string& desc, const std::string& type)
    : sourceIP(ip), severity(sev), description(desc), eventType(type) {

    if (sourceIP.empty())
        throw std::invalid_argument("Source IP cannot be empty");

    if (description.empty())
        throw std::invalid_argument("Event description cannot be empty");

    if (eventType.empty())
        throw std::invalid_argument("Event type cannot be empty");

    timestamp = generateTimestamp();
}
    virtual ~SecurityEvent() = default;
    
    virtual void display() const {
        std::cout << "[" << timestamp << "] " << eventType 
                  << " | IP: " << sourceIP 
                  << " | Severity: " << severityToString(severity) 
                  << " | " << description << std::endl;
    }
    
    std::string getSourceIP() const { return sourceIP; }
    Severity getSeverity() const { return severity; }
    std::string getDescription() const { return description; }
    std::string getTimestamp() const { return timestamp; }
    std::string getEventType() const { return eventType; }
};

class LoginFailure : public SecurityEvent {
public:
    LoginFailure(const std::string& ip, const std::string& desc = "Multiple failed login attempts") 
        : SecurityEvent(ip, Severity::MEDIUM, desc, "LoginFailure") {}
};

class PortScan : public SecurityEvent {
public:
    PortScan(const std::string& ip, const std::string& desc = "Sequential port scanning detected") 
        : SecurityEvent(ip, Severity::LOW, desc, "PortScan") {}
};

class MalwareAlert : public SecurityEvent {
public:
    MalwareAlert(const std::string& ip, const std::string& desc = "Known malware signature detected") 
        : SecurityEvent(ip, Severity::CRITICAL, desc, "MalwareAlert") {}
};

class FileTampering : public SecurityEvent {
public:
    FileTampering(const std::string& ip, const std::string& desc = "Unauthorized modification of system files") 
        : SecurityEvent(ip, Severity::HIGH, desc, "FileTampering") {}
};
