#pragma once
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include "Events.h"

class Rule {
public:
    virtual ~Rule() = default;
    // Returns match strength between 0.0 and 1.0
    virtual double evaluate(const SecurityEvent& event) const = 0;
};

class LoginRule : public Rule {
public:
    double evaluate(const SecurityEvent& event) const override {
        if (event.getEventType() == "LoginFailure") {
            return 0.9; // High confidence it's an attack if rule triggers
        }
        return 0.0;
    }
};

class PortScanRule : public Rule {
public:
    double evaluate(const SecurityEvent& event) const override {
        if (event.getEventType() == "PortScan") {
            return 0.7; 
        }
        return 0.0;
    }
};

class MalwareRule : public Rule {
public:
    double evaluate(const SecurityEvent& event) const override {
        if (event.getEventType() == "MalwareAlert") {
            return 1.0; 
        }
        return 0.0;
    }
};

// ---------- NEW RULES ----------

// Any event from a known-bad IP is a full match
class BlacklistRule : public Rule {
private:
    std::set<std::string> blacklist;
public:
    BlacklistRule(std::set<std::string> ips = {"203.0.113.9", "198.51.100.23", "192.0.2.66"})
        : blacklist(std::move(ips)) {}

    void addIP(const std::string& ip) { blacklist.insert(ip); }

    double evaluate(const SecurityEvent& event) const override {
        return blacklist.count(event.getSourceIP()) ? 1.0 : 0.0;
    }
};

// Remembers failed logins per IP: strength grows with every attempt
// 1 failure = 0.2, 2 = 0.4, ... 5 or more = 1.0 (brute force)
class BruteForceRule : public Rule {
private:
    mutable std::map<std::string, int> failures;  // mutable: evaluate() is const
public:
    double evaluate(const SecurityEvent& event) const override {
        if (event.getEventType() != "LoginFailure") return 0.0;
        int count = ++failures[event.getSourceIP()];
        return std::min(1.0, count * 0.2);
    }
};

// Attacker trying to gain admin rights (needs this event type in EventFactory)
class PrivilegeEscalationRule : public Rule {
public:
    double evaluate(const SecurityEvent& event) const override {
        if (event.getEventType() == "PrivilegeEscalation") {
            return 0.85;
        }
        return 0.0;
    }
};
