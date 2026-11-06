#include <iostream>
#include <string>
#include <vector>
#include <memory>

// Base Class (Polymorphism ke liye)
class SecurityRule {
public:
    virtual ~SecurityRule() {}
    virtual bool evaluate(const std::string& inputData) = 0; // Pure virtual function
    virtual std::string getRuleName() const = 0;
};

// Derived Class 1: Brute Force Detector Rule
class BruteForceRule : public SecurityRule {
public:
    bool evaluate(const std::string& inputData) override {
        // Agar input data mein "failed_login" ya "multiple_attempts" hai
        if (inputData.find("failed_login") != std::string::npos) {
            return true; // Threat detected!
        }
        return false;
    }

    std::string getRuleName() const override {
        return "BruteForce_Detection_Rule";
    }
};

// Derived Class 2: Unauthorized Access Rule
class UnauthorizedAccessRule : public SecurityRule {
public:
    bool evaluate(const std::string& inputData) override {
        // Agar input data mein "root_access" ya "unauthorized" hai
        if (inputData.find("root_access") != std::string::npos) {
            return true; // Threat detected!
        }
        return false;
    }

    std::string getRuleName() const override {
        return "Unauthorized_Access_Rule";
    }
};

// Rule Engine jo saare rules ko manage karega
class RuleEngine {
private:
    std::vector<std::unique_ptr<SecurityRule>> rules;

public:
    void addRule(std::unique_ptr<SecurityRule> rule) {
        rules.push_back(std::move(rule));
    }

    // Yeh function data ko saare rules ke through run karega
    void analyzeEvent(const std::string& eventData) {
        std::cout << "\n[Analyzing Event]: " << eventData << std::endl;
        for (const auto& rule : rules) {
            if (rule->evaluate(eventData)) {
                std::cout << " -> [ALERT] Triggered Rule: " << rule->getRuleName() << std::endl;
            } else {
                std::cout << " -> [PASS] Rule passed: " << rule->getRuleName() << std::endl;
            }
        }
    }
};
