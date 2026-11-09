#pragma once

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <algorithm>
#include <stdexcept>

class ThreatIntelligence {
public:
    enum class Level {
        Trusted,
        Low,
        Medium,
        High,
        Critical
    };

    struct Threat {
        std::string ip;
        Level level = Level::Trusted;
        int score = 100;
        int attackCount = 0;
        std::string lastAttack;
    };

private:
    std::map<std::string, Threat> database;
    mutable std::mutex mutex;

public:
    void addThreat(const std::string& ip,
                   const std::string& attack) {
        if (ip.empty() || attack.empty())
            throw std::invalid_argument("Invalid threat data");

        std::lock_guard<std::mutex> lock(mutex);

        auto& threat = database[ip];

        threat.ip = ip;
        threat.lastAttack = attack;
        threat.attackCount++;

        int penalty = attack == "Malware" ? 30 :
                      attack == "BruteForce" ? 15 : 10;

        threat.score = std::max(0, threat.score - penalty);

        if (threat.score >= 90)
            threat.level = Level::Trusted;
        else if (threat.score >= 70)
            threat.level = Level::Low;
        else if (threat.score >= 40)
            threat.level = Level::Medium;
        else if (threat.score >= 15)
            threat.level = Level::High;
        else
            threat.level = Level::Critical;
    }

    bool isHighRisk(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = database.find(ip);

        return it != database.end() &&
               (it->second.level == Level::High ||
                it->second.level == Level::Critical);
    }

    bool getThreat(const std::string& ip, Threat& result) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = database.find(ip);

        if (it == database.end())
            return false;

        result = it->second;
        return true;
    }

    std::vector<Threat> getAllThreats() const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<Threat> result;

        for (const auto& entry : database)
            result.push_back(entry.second);

        return result;
    }

    bool removeThreat(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex);
        return database.erase(ip) > 0;
    }

    std::size_t totalThreats() const {
        std::lock_guard<std::mutex> lock(mutex);
        return database.size();
    }
};
