#pragma once
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <tuple>
#include "Rules.h"
#include "DecisionStrategy.h"

class DecisionEngine {
private:
    std::vector<std::unique_ptr<Rule>> rules;
    std::unique_ptr<DecisionStrategy> strategy;
    std::map<std::string, int> historicalFrequency;

    double calculateHistoricalFrequencyScore(const std::string& ip) {
        int count = historicalFrequency[ip];
        if (count == 0) return 0.1;
        if (count < 3) return 0.4;
        if (count < 6) return 0.7;
        return 1.0;
    }

    double getSourceReputationScore(const std::string& ip) {
        // Mock threat intel database
        if (ip == "192.168.1.100") return 0.1; // Internal trusted
        if (ip == "45.33.22.11") return 0.9;  // Known bad actor mock
        return 0.5; // Unknown
    }

public:
    DecisionEngine() {
        strategy = std::make_unique<BalancedStrategy>(); // Default
    }

    void addRule(std::unique_ptr<Rule> rule) {
        rules.push_back(std::move(rule));
    }

    void setStrategy(std::unique_ptr<DecisionStrategy> newStrategy) {
    if (newStrategy) {
        strategy = std::move(newStrategy);
    }
}
    }
    
    std::string getStrategyName() const {
        return strategy->getStrategyName();
    }

    // Evaluates event and returns <Action, DCS, Reason>
    std::tuple<std::unique_ptr<Action>, double, std::string> evaluate(const SecurityEvent& event) {
        // Update history
        

        double maxRuleMatch = 0.0;
        for (const auto& rule : rules) {
            double match = rule->evaluate(event);
            if (match > maxRuleMatch) {
                maxRuleMatch = match;
            }
        }

        double severityScore = getSeverityScore(event.getSeverity());
        double historyScore = calculateHistoricalFrequencyScore(event.getSourceIP());
        historicalFrequency[event.getSourceIP()]++;
        double reputationScore = getSourceReputationScore(event.getSourceIP());

        // Calculate Decision Confidence Score (DCS)
        double dcs = (0.35 * severityScore) + 
                     (0.25 * maxRuleMatch) + 
                     (0.20 * historyScore) + 
                     (0.20 * reputationScore);

        std::string reason = "Severity=" + std::to_string(severityScore) + 
                             ", RuleMatch=" + std::to_string(maxRuleMatch) + 
                             ", History=" + std::to_string(historyScore) + 
                             ", Reputation=" + std::to_string(reputationScore);

        return {strategy->decide(dcs), dcs, reason};
    }
};
