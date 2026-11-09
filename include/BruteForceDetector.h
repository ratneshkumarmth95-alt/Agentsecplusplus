
#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class BruteForceDetector {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct Config {
        std::size_t maxAttempts = 5;
        std::chrono::seconds detectionWindow{60};
        std::chrono::seconds lockoutDuration{300};
        std::chrono::seconds historyRetention{3600};
        std::size_t escalationThreshold = 10;
    };

    enum class Status {
        Normal,
        Suspicious,
        BruteForceDetected,
        Locked
    };

    struct Report {
        std::string ip;
        Status status = Status::Normal;
        std::size_t recentFailures = 0;
        std::size_t totalFailures = 0;
        double threatScore = 0.0;
        bool locked = false;
        std::string message;
    };

    struct Statistics {
        std::size_t trackedIPs = 0;
        std::size_t totalFailures = 0;
        std::size_t detectedAttacks = 0;
        std::size_t activeLockouts = 0;
    };

private:
    struct IPRecord {
        std::deque<TimePoint> attempts;
        std::size_t totalFailures = 0;
        std::size_t detectedAttacks = 0;
        TimePoint lastActivity{};
        TimePoint lockedUntil{};
        bool locked = false;
    };

    Config config;
    std::map<std::string, IPRecord> records;
    mutable std::mutex mutex;

    static bool validIPv4(const std::string& ip) {
        std::istringstream stream(ip);
        std::string part;
        int count = 0;

        while (std::getline(stream, part, '.')) {
            if (part.empty() || part.size() > 3)
                return false;

            if (part.size() > 1 && part[0] == '0')
                return false;

            int value = 0;

            for (unsigned char c : part) {
                if (c < '0' || c > '9')
                    return false;

                value = value * 10 + (c - '0');
            }

            if (value > 255)
                return false;

            ++count;
        }

        return count == 4;
    }

    void cleanup(IPRecord& record, TimePoint now) {
        while (!record.attempts.empty() &&
               now - record.attempts.front() >
                   config.detectionWindow) {
            record.attempts.pop_front();
        }

        if (record.locked && now >= record.lockedUntil)
            record.locked = false;
    }

    double calculateThreatScore(
        const IPRecord& record) const {

        const double count = static_cast<double>(
            record.attempts.size());

        const double threshold =
            static_cast<double>(config.maxAttempts);

        return std::min(100.0, (count / threshold) * 100.0);
    }

    Report createReport(
        const std::string& ip,
        const IPRecord& record) const {

        Report report;

        report.ip = ip;
        report.recentFailures = record.attempts.size();
        report.totalFailures = record.totalFailures;
        report.threatScore = calculateThreatScore(record);
        report.locked = record.locked;

        if (record.locked) {
            report.status = Status::Locked;
            report.message = "IP is temporarily locked";
        }
        else if (report.recentFailures >= config.maxAttempts) {
            report.status = Status::BruteForceDetected;
            report.message = "Brute force attack detected";
        }
        else if (report.recentFailures >=
                 config.maxAttempts / 2) {
            report.status = Status::Suspicious;
            report.message = "Suspicious login activity";
        }
        else {
            report.status = Status::Normal;
            report.message = "No brute force activity detected";
        }

        return report;
    }

public:
    explicit BruteForceDetector(
        const Config& settings = Config{})
        : config(settings) {

        if (config.maxAttempts == 0 ||
            config.detectionWindow.count() <= 0 ||
            config.lockoutDuration.count() <= 0 ||
            config.historyRetention.count() <= 0 ||
            config.escalationThreshold == 0) {
            throw std::invalid_argument(
                "Invalid brute force detector configuration");
        }
    }

    Report recordFailure(const std::string& ip) {
        if (!validIPv4(ip))
            throw std::invalid_argument("Invalid IPv4 address");

        std::lock_guard<std::mutex> lock(mutex);

        const auto now = Clock::now();
        auto& record = records[ip];

        cleanup(record, now);

        if (record.locked)
            return createReport(ip, record);

        record.attempts.push_back(now);
        ++record.totalFailures;
        record.lastActivity = now;

        Report report = createReport(ip, record);

        if (record.attempts.size() >= config.maxAttempts) {
            ++record.detectedAttacks;

            if (record.detectedAttacks >=
                    config.escalationThreshold ||
                record.attempts.size() >=
                    config.maxAttempts * 2) {

                record.locked = true;
                record.lockedUntil =
                    now + config.lockoutDuration;
            }

            report = createReport(ip, record);
        }

        return report;
    }

    Report recordSuccess(const std::string& ip) {
        if (!validIPv4(ip))
            throw std::invalid_argument("Invalid IPv4 address");

        std::lock_guard<std::mutex> lock(mutex);

        const auto now = Clock::now();
        auto& record = records[ip];

        cleanup(record, now);

        if (!record.locked)
            record.attempts.clear();

        record.lastActivity = now;

        return createReport(ip, record);
    }

    Report inspect(const std::string& ip) {
        if (!validIPv4(ip))
            throw std::invalid_argument("Invalid IPv4 address");

        std::lock_guard<std::mutex> lock(mutex);

        auto it = records.find(ip);

        if (it == records.end()) {
            Report report;
            report.ip = ip;
            report.message = "IP has no recorded activity";
            return report;
        }

        cleanup(it->second, Clock::now());

        return createReport(ip, it->second);
    }

    bool isLocked(const std::string& ip) {
        if (!validIPv4(ip))
            throw std::invalid_argument("Invalid IPv4 address");

        std::lock_guard<std::mutex> lock(mutex);

        auto it = records.find(ip);

        if (it == records.end())
            return false;

        cleanup(it->second, Clock::now());

        return it->second.locked;
    }

    void resetIP(const std::string& ip) {
        if (!validIPv4(ip))
            throw std::invalid_argument("Invalid IPv4 address");

        std::lock_guard<std::mutex> lock(mutex);
        records.erase(ip);
    }

    void cleanupExpiredRecords() {
        std::lock_guard<std::mutex> lock(mutex);

        const auto now = Clock::now();

        for (auto it = records.begin();
             it != records.end();) {

            cleanup(it->second, now);

            if (!it->second.locked &&
                now - it->second.lastActivity >
                    config.historyRetention) {
                it = records.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    Statistics getStatistics() const {
        std::lock_guard<std::mutex> lock(mutex);

        Statistics stats;
        stats.trackedIPs = records.size();

        for (const auto& entry : records) {
            const auto& record = entry.second;

            stats.totalFailures += record.totalFailures;
            stats.detectedAttacks += record.detectedAttacks;

            if (record.locked &&
                Clock::now() < record.lockedUntil) {
                ++stats.activeLockouts;
            }
        }

        return stats;
    }

    static std::string statusToString(Status status) {
        switch (status) {
            case Status::Normal:
                return "NORMAL";
            case Status::Suspicious:
                return "SUSPICIOUS";
            case Status::BruteForceDetected:
                return "BRUTE FORCE DETECTED";
            case Status::Locked:
                return "LOCKED";
        }

        return "UNKNOWN";
    }

    static std::string formatReport(const Report& report) {
        std::ostringstream output;

        output << "\n========== BRUTE FORCE REPORT ==========\n";
        output << "IP Address: " << report.ip << '\n';
        output << "Status: " << statusToString(report.status) << '\n';
        output << "Recent Failures: " << report.recentFailures << '\n';
        output << "Total Failures: " << report.totalFailures << '\n';
        output << "Threat Score: "
               << std::fixed << std::setprecision(2)
               << report.threatScore << "%\n";
        output << "Locked: "
               << (report.locked ? "YES" : "NO") << '\n';
        output << "Analysis: " << report.message << '\n';
        output << "========================================\n";

        return output.str();
    }
};
