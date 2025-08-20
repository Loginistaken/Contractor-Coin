// contractor_coin.cpp

#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdlib>

// Include Crow framework
#include "crow_all.h"

// Include JSON library (e.g., JsonCpp)
#include <json/json.h>
// === Block Structure ===
struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;

 
const double OWNER_VAULT_INITIAL_BALANCE = 10'000'000'000'000'000.0; 1 billion coins with 7 decimals multiply by 1e7
const double USER_VAULT_INITIAL_BALANCE = 60'000'000'000'000'000.0; 6 billion coins with 7 decimals multiply by 1e7



    Block(int idx, const std::vector<Transaction>& txs, const std::string& prev)
        : index(idx), transactions(txs), prevHash(prev), nonce(0) {
        timestamp = std::to_string(std::time(nullptr));
        hash = generateHash();
    }

    std::string generateHash() const {
        std::string toHash = std::to_string(index) + timestamp + prevHash + std::to_string(nonce);
        for (const auto& tx : transactions) {
            toHash += tx.toString();
        }
        
    }

    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = generateHash();
        }
    }
};

// === EL-40 Blockchain Class ===
class EL40_Blockchain {
private:
    std::vector<Block> chain;



    Block createGenesisBlock() {
        return Block(0, {}, "0");
    }

    void addBlock(const std::vector<Transaction>& transactions) {
        std::lock_guard<std::mutex> lock(chainMutex);
        Block last = chain.back();
        Block newBlock(chain.size(), transactions, last.hash);

        int difficulty = chain.size() / 10 + 1; // Adjust difficulty as blockchain grows
        newBlock.mineBlock(difficulty);

        chain.push_back(newBlock);

        for (auto& tx : transactions) {
            ledger[tx.sender] -= tx.amount;
            ledger[tx.receiver] += tx.amount;
        }

        std::cout << "[INFO] Block added with hash: " << newBlock.hash << "\n";
    }

    void displayChain() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        for (const auto& block : chain) {
            std::cout << "Block Index: " << block.index << "\n"
                      << "Timestamp: " << block.timestamp << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Previous Hash: " << block.prevHash << "\n\n";
        }
    }
};
// Define constants
const double MAX_TRANSACTION_AMOUNT = 5000000.0;
const int MAX_TRANSACTION_FREQUENCY = 5000000;
const std::string UNKNOWN_ACCOUNT = "UNKNOWN";

// Transaction structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string timestamp;

    Transaction(const std::string& from, const std::string& to, double amt, const std::string& time)
        : sender(from), receiver(to), amount(amt), timestamp(time) {}
};

// Node structure
struct Node {
    std::string name;
    int load = 0;
    int reputation = 100;
};

// Global variables
std::vector<Transaction> EL40_Blockchain;
std::unordered_map<std::string, double> ledger = {
    {"User1", 5000.0},
    {"User2", 250000000.0},
    {"User3", 2000000.0}
};
std::unordered_map<std::string, std::vector<Transaction>> transactionHistory;
std::unordered_map<std::string, Node> nodes = {
    {"Node1", {"Node1", 0, 100}},
    {"Node2", {"Node2", 0, 100}}
};
std::mutex nodeMutex;

// Function to parse ISO 8601 timestamp to time_point
std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp) {
    std::tm tm = {};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

// Fraud detection function
bool isFraudulent(const Transaction& tx) {
    if (tx.amount > MAX_TRANSACTION_AMOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Amount exceeds maximum allowed.\n";
        return true;
    }

    if (tx.sender == UNKNOWN_ACCOUNT || tx.receiver == UNKNOWN_ACCOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Involves an unknown account.\n";
        return true;
    }

    auto& history = transactionHistory[tx.sender];
    int recentTransactions = 0;
    auto currentTime = std::chrono::system_clock::now();

    for (const auto& pastTx : history) {
        auto pastTime = parseTimestamp(pastTx.timestamp);
        auto duration = std::chrono::duration_cast<std::chrono::hours>(currentTime - pastTime).count();
        if (duration <= 24) {
            recentTransactions++;
        }
    }

    if (recentTransactions > MAX_TRANSACTION_FREQUENCY) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Frequency exceeds maximum allowed.\n";
        return true;
    }

    if (ledger[tx.sender] < tx.amount) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Insufficient funds.\n";
        return true;
    }

    return false;
}

// Function to process a transaction
void processTransaction(const Transaction& tx) {
    std::cout << "[INFO] Processing transaction: " << tx.sender << " -> " << tx.receiver << ": $" << tx.amount << "\n";

    if (isFraudulent(tx)) {
        std::cerr << "[ERROR] Transaction blocked due to fraud detection.\n";
        return;
    }

    ledger[tx.sender] -= tx.amount;
    ledger[tx.receiver] += tx.amount;
    transactionHistory[tx.sender].push_back(tx);
    blockchain.push_back(tx);

    std::cout << "[INFO] Transaction completed successfully.\n";
}

// Function to fetch external transactions
void fetchExternalTransactions() {
    std::ifstream apiOutput("external_transactions.json");
    if (!apiOutput.is_open()) {
        std::cerr << "[ERROR] Failed to open external transaction file.\n";
        return;
    }

    Json::Value transactions;
    apiOutput >> transactions;
    for (const auto& tx : transactions) {
        std::string sender = tx["sender"].asString();
        std::string receiver = tx["receiver"].asString();
        double amount = tx["amount"].asDouble();
        std::string timestamp = tx["timestamp"].asString();
        Transaction newTx(sender, receiver, amount, timestamp);
        processTransaction(newTx);
    }
}

// Function for load balancing
void distributeLoad(const std::string& task) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    Node* bestNode = nullptr;

    for (auto& [name, node] : nodes) {
        if (!bestNode || node.load < bestNode->load) {
            bestNode = &node;
        }
    }

    if (bestNode) {
        bestNode->load++;
        std::cout << "[INFO] Task '" << task << "' assigned to " << bestNode->name << " (Load: " << bestNode->load << ")\n";
    } else {
        std::cerr << "[ERROR] No available nodes to handle the task.\n";
    }
}

// Function to update node reputation
void updateNodeReputation(const std::string& nodeName, int change) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    if (nodes.find(nodeName) != nodes.end()) {
        nodes[nodeName].reputation += change;
        std::cout << "[INFO] Updated reputation for " << nodeName << " to " << nodes[nodeName].reputation << "\n";
    } else {
        std::cerr << "[ERROR] Node not found: " << nodeName << "\n";
    }
}
// Node Connection Agreement
bool nodeAccessAgreement() {
    std::string response;
    std::cout << "Do you accept the node connection agreement? (yes/no): ";
    std::cin >> response;
    if (response == "yes" || response == "Yes") {
        std::cout << "Access granted. Connecting node...\n";
        return true;
    } else {
        std::cout << "Access denied. Exiting application.\n";
        return false;
    }
}
// Function to start the web dashboard
void startWebDashboard() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/stats")([]() {
        Json::Value stats;
        stats["total_blocks"] = static_cast<int>(blockchain.size());
        stats["total_users"] = static_cast<int>(ledger.size());
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, stats));
    });

    CROW_ROUTE(app, "/ledger")([]() {
        Json::Value ledgerJson;
        for (const auto& [user, balance] : ledger) {
            ledgerJson[user] = balance;
        }
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, ledgerJson));
    });

    std::cout << "[INFO] Starting web dashboard on http://localhost:8080\n";
    app.port(8080).multithreaded().run();
}

// Function to simulate mobile app transactions
void simulateMobileApp() {
    std::vector<Transaction> transactions = {
        {"User1", "User2", 50000.0, "2025-04-20T10:00:00Z"},
        {"User1", "User3", 250000000.0, "2025-04-20T10:05:00Z"},
        {"UNKNOWN", "User2", 1000.0, "2025-04-20T10:10:00Z"},
        {"User3", "User2", 20000000.0, "2025-04-20T10:15:00Z"}
    };

    for (const auto& tx : transactions) {
        processTransaction(tx);
    }

    blockchain.push_back({"User2", "User1", 10.0, "2025-04-20T01:00:00Z"});
    std::cout << "[MOBILE APP] Transaction complete. New balance for User1: $" << ledger["User1"] << "\n";
}

// Function to display exit popup with MIT License
void displayExitPopup() {
    std::cout << "\n\n--- Exit Acknowledgment ---\n";
    std::cout << "MIT License\n";
    std::cout << "© 2025 EL-40 Blockchain\n";
    std::cout << "Special thanks to GPT Chat for assistance in the development.\n";
    std::cout << "This software is provided 'as-is' without any express or implied warranty.\n";
    std::cout << "For more information, visit: https://opensource.org/licenses/MIT\n";
    std::cout << "Email: elindau85@gmail.com\n";
    std::cout << "By: EL (El-40 Blockchain)\n";
    std::cout << "--- End of License ---\n";
    std::cout << "\nDDoS Protection Enabled: Network safety is ensured during this operation.\n";
}





// CoinGecko API Integration (for fetching USD value)
double getCoinPriceUSD() {
    // For simplicity, assume we fetch the price (pseudo-code)
    // Ideally, use an HTTP library like libcurl to request CoinGecko API
    double price = 10.5;  // Placeholder value
    return price;
}

// Web Dashboard Setup using Crow
void startWebDashboard() {
    crow::SimpleApp app;


    // Stats Route
    CROW_ROUTE(app, "/stats")([](){
        // Return JSON with blockchain stats (replace with actual data)
        return R"({"blockchainStats": {"totalCoins": 1000000, "activeUsers": 500}})";
    });

    // Ledger Route
    CROW_ROUTE(app, "/ledger")([](){
        // Return JSON with ledger information (replace with actual data)
        return R"({"ledger": {"user1": 100, "user2": 200}})";
    });

    // Secure Purchase Route
    CROW_ROUTE(app, "/purchase")([](){
        return "<html><body><h1>Purchase Contractor Coin</h1>"
               "<p>Enter payment details securely.</p></body></html>";
    });

    // Start Web Server
    app.port(8080).multithreaded().run();
}

int main() {
    // Step 1: Node Connection Agreement
    if (!nodeAccessAgreement()) {
        return 0; // Exit if user doesn't agree
    }

    // Step 2: Start Web Dashboard
    startWebDashboard();

    // You can add further functionalities like Metaverse Integration or Offboard Commands here.
    return 0;
}

        std::cout << "\n\n=== MIT LICENSE AGREEMENT ===\n";
        std::cout << "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
                  << "of this software and associated documentation files (the \"Software\"), to deal\n"
                  << "in the Software without restriction...\n";
        std::cout << "Type 'agree' to proceed: ";

        std::string input;
        std::cin >> input;
        if (input != "agree") {
            std::cout << "License not accepted. Program will terminate.\n";
            exit(0);
        }

        if (!nodeAccessAgreement()) {
            return 0;
        }

        std::thread dashboardThread(startWebDashboard);
        dashboardThread.detach();

        fetchExternalTransactions();

        distributeLoad("Sync Task 1");
        distributeLoad("Sync Task 2");

        updateNodeReputation("Node1", -5);

        simulateMobileApp();

        std::this
::contentReference[oaicite:0]{index=0}
 
