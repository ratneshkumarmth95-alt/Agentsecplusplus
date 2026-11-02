#pragma once
#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include "Events.h"
#include "Actions.h"

// ---------- Log levels (decided from the DCS score) ----------
enum class LogLevel { INFO, WARN, CRITICAL };

inline std::string levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARN:     return "WARN";
        case LogLevel::CRITICAL: return "CRITICAL";
    }
    return "INFO";
}

// Adjust these thresholds to match your DCS scale
inline LogLevel levelFromDcs(double dcs, double warnAt = 40.0, double criticalAt = 70.0) {
    if (dcs >= criticalAt) return LogLevel::CRITICAL;
    if (dcs >= warnAt)     return LogLevel::WARN;
    return LogLevel::INFO;
}

// Makes reason text safe inside JSON (quotes, backslashes, newlines)
inline std::string escapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

// ---------- Base interface (unchanged signature) ----------
class Logger {
public:
    virtual ~Logger() = default;
    virtual void log(const SecurityEvent& event, const Action& action, double dcs, const std::string& reason) = 0;
};

// ---------- Text file logger ----------
class TextLogger : public Logger {
private:
    std::ofstream file;
public:
    TextLogger(const std::string& filename) {
        file.open(filename, std::ios::app);
        if (!file.is_open()) {
            std::cerr << "Failed to open log file: " << filename << std::endl;
        }
    }
    ~TextLogger() {
        if (file.is_open()) file.close();
    }

    void log(const SecurityEvent& event, const Action& action, double dcs, const std::string& reason) override {
        if (file.is_open()) {
            file << "[" << event.getTimestamp() << "] "
                 << "[" << levelToString(levelFromDcs(dcs)) << "] "
                 << "Event: " << event.getEventType() << " | "
                 << "IP: " << event.getSourceIP() << " | "
                 << "DCS: " << dcs << " | "
                 << "Action: " << action.getName() << " | "
                 << "Details: " << reason << "\n";
            file.flush();  // log is saved even if the program crashes
        }
    }
};

// ---------- JSON file logger ----------
class JSONLogger : public Logger {
private:
    std::ofstream file;
public:
    JSONLogger(const std::string& filename) {
        file.open(filename, std::ios::app);
        if (!file.is_open()) {
            std::cerr << "Failed to open log file: " << filename << std::endl;
        }
    }
    ~JSONLogger() {
        if (file.is_open()) file.close();
    }

    void log(const SecurityEvent& event, const Action& action, double dcs, const std::string& reason) override {
        if (file.is_open()) {
            file << "{\n"
                 << "  \"timestamp\": \"" << event.getTimestamp() << "\",\n"
                 << "  \"level\": \"" << levelToString(levelFromDcs(dcs)) << "\",\n"
                 << "  \"event\": \"" << event.getEventType() << "\",\n"
                 << "  \"ip\": \"" << event.getSourceIP() << "\",\n"
                 << "  \"severity\": \"" << severityToString(event.getSeverity()) << "\",\n"
                 << "  \"dcs\": " << dcs << ",\n"
                 << "  \"action\": \"" << action.getName() << "\",\n"
                 << "  \"reason\": \"" << escapeJson(reason) << "\"\n"
                 << "}\n";
            file.flush();
        }
    }
};

// ---------- NEW: console logger with level prefix ----------
class ConsoleLogger : public Logger {
public:
    void log(const SecurityEvent& event, const Action& action, double dcs, const std::string& reason) override {
        LogLevel level = levelFromDcs(dcs);
        std::ostream& out = (level == LogLevel::CRITICAL) ? std::cerr : std::cout;
        out << "[" << levelToString(level) << "] "
            << event.getEventType() << " from " << event.getSourceIP()
            << " | DCS=" << dcs
            << " | Action=" << action.getName()
            << " | " << reason << "\n";
    }
};

// ---------- NEW: sends one log to many loggers at once ----------
class MultiLogger : public Logger {
private:
    std::vector<std::unique_ptr<Logger>> loggers;
public:
    void addLogger(std::unique_ptr<Logger> logger) {
        loggers.push_back(std::move(logger));
    }

    void log(const SecurityEvent& event, const Action& action, double dcs, const std::string& reason) override {
        for (auto& l : loggers) l->log(event, action, dcs, reason);
    }
};
