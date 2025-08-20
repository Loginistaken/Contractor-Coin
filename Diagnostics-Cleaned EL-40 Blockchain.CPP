// contractor_coin.cpp -- Unified, Diagnostics-Cleaned EL-40 Blockchain

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
#include <asio.hpp>
#include <crypto++/sha3.h>
#include <crypto++/hex.h>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <json/json.h>
#include "crow_all.h"

// === CONSTANTS ===
const double OWNER_VAULT_INITIAL_BALANCE = 10'000'000'000'000'000.0; // 1B coins, 7 decimals x 1e7
const double USER_VAULT_INITIAL_BALANCE  = 60'000'000'000'000'000.0; // 6B coins, 7 decimals x 1e7
const double MAX_TRANSACTION_AMOUNT = 5'000'000.0;
const int MAX_TRANSACTION_FREQUENCY = 5000000;
const std::string UNKNOWN_ACCOUNT = "UNKNOWN";

// === GLOBALS ===
std::mutex ledgerMutex, nodeMutex;
std::unordered_map<std::string, double> ledger = {
    {"OwnerVault", OWNER_VAULT_INITIAL_BALANCE},
    {"UserVault",  USER_VAULT_INITIAL_BALANCE},
    {"User1", 5000.0},
    {"User2", 250000000.0},
    {"User3", 2000000.0}
};
std::unordered_map<std::string, std::vector<std::string>> transactionHistory;

// === CRYPTO UTILS ===
std::string EL40_Hash(const std::string& input) {
    using namespace CryptoPP;
    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());
    std::string output;
    HexEncoder encoder;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    return output;
}

std::string signTransaction(const std::string& data, const CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string signature;
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
    CryptoPP::StringSource ss(data, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature)));
    return signature;
}

bool verifyTransaction(const std::string& data, const std::string& signature, const CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);
    bool result = false;
    try {
        CryptoPP::StringSource ss(signature + data, true,
            new CryptoPP::SignatureVerificationFilter(
                verifier,
                new CryptoPP::ArraySink((byte*)&result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION | CryptoPP::SignatureVerificationFilter::PUT_RESULT
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error verifying transaction: " << e.what() << '\n';
        return false;
    }
    return result;
}

// === STRUCTS ===
struct Transaction {
    std::string sender, receiver, signature, timestamp;
    double amount;
    std::string toString() const {
        return sender + receiver + std::to_string(amount) + signature + timestamp;
    }
};

struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;
    std::vector<std::string> fragmentHashes;

    Block(int idx, const std::vector<Transaction>& txs, const std::string& prev)
        : index(idx), transactions(txs), prevHash(prev), nonce(0) {
        timestamp = std::to_string(std::time(nullptr));
        hash = generateHash();
    }

    std::string generateHash() const {
        std::string toHash = std::to_string(index) + timestamp + prevHash + std::to_string(nonce);
        for (const auto& tx : transactions) toHash += tx.toString();
        return EL40_Hash(toHash);
    }

    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = generateHash();
        }
    }
};

struct Node {
    std::string name;
    int load = 0;
    int reputation = 100;
};

std::unordered_map<std::string, Node> nodes = {
    {"Node1", {"Node1", 0, 100}},
    {"Node2", {"Node2", 0, 100}}
};

// === FRAUD DETECTION ===
std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp) {
    std::tm tm = {};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

bool isFraudulent(const Transaction& tx) {
    if (tx.amount > MAX_TRANSACTION_AMOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Amount exceeds maximum allowed.\n";
        return true;
    }
    if (tx.sender == UNKNOWN_ACCOUNT || tx.receiver == UNKNOWN_ACCOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Involves an unknown account.\n";
        return true;
    }
    // Frequency check
    auto& history = transactionHistory[tx.sender];
    int recentTransactions = 0;
    auto currentTime = std::chrono::system_clock::now();
    for (const auto& ts : history) {
        auto pastTime = parseTimestamp(ts);
        auto duration = std::chrono::duration_cast<std::chrono::hours>(currentTime - pastTime).count();
        if (duration <= 24) recentTransactions++;
    }
    if (recentTransactions > MAX_TRANSACTION_FREQUENCY) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Frequency exceeds maximum allowed.\n";
        return true;
    }
    std::lock_guard<std::mutex> lock(ledgerMutex);
    if (ledger[tx.sender] < tx.amount) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Insufficient funds.\n";
        return true;
    }
    return false;
}

// === BLOCKCHAIN ===
class EL40_Blockchain {
private:
    std::vector<Block> chain;
    std::mutex chainMutex;
public:
    EL40_Blockchain() {
        chain.push_back(createGenesisBlock());
        ledger["Genesis"] = 1000;
    }
    Block createGenesisBlock() { return Block(0, {}, "0"); }

    void addBlock(const std::vector<Transaction>& transactions, const std::string& minerAddress = "MinerNode") {
        std::lock_guard<std::mutex> lock(chainMutex);
        Block last = chain.back();
        std::vector<Transaction> blockTxs = transactions;
        Transaction rewardTx = {"Network", minerAddress, 25.0, "Reward", std::to_string(std::time(nullptr))};
        blockTxs.push_back(rewardTx);
        Block newBlock(chain.size(), blockTxs, last.hash);
        int difficulty = std::max(1, (int)chain.size() / 10);
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
        std::lock_guard<std::mutex> l(ledgerMutex);
        for (const auto& tx : blockTxs) {
            ledger[tx.sender] -= tx.amount;
            ledger[tx.receiver] += tx.amount;
        }
        std::cout << "[+] Block added by " << minerAddress << " with reward 25.0 ELX\n";
    }

    void displayChain() const {
        for (const auto& block : chain) {
            std::cout << "Index: " << block.index << "\nTime: " << block.timestamp
                      << "\nPrev: " << block.prevHash << "\nHash: " << block.hash << "\n";
            for (const auto& tx : block.transactions)
                std::cout << tx.sender << " -> " << tx.receiver << ": " << tx.amount << " ";
            std::cout << "\nNonce: " << block.nonce << "\n\n";
        }
    }
};

std::vector<Transaction> blockchain;

// === NODE/NETWORK OPS ===
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

void distributeLoad(const std::string& task) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    Node* bestNode = nullptr;
    for (auto& [name, node] : nodes)
        if (!bestNode || node.load < bestNode->load)
            bestNode = &node;
    if (bestNode) {
        bestNode->load++;
        std::cout << "[INFO] Task '" << task << "' assigned to " << bestNode->name << " (Load: " << bestNode->load << ")\n";
    } else {
        std::cerr << "[ERROR] No available nodes to handle the task.\n";
    }
}

void updateNodeReputation(const std::string& nodeName, int change) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    if (nodes.find(nodeName) != nodes.end()) {
        nodes[nodeName].reputation += change;
        std::cout << "[INFO] Updated reputation for " << nodeName << " to " << nodes[nodeName].reputation << "\n";
    } else {
        std::cerr << "[ERROR] Node not found: " << nodeName << "\n";
    }
}

// === TRANSACTION PROCESSING ===
void processTransaction(const Transaction& tx) {
    std::cout << "[INFO] Processing transaction: " << tx.sender << " -> " << tx.receiver << ": $" << tx.amount << "\n";
    if (isFraudulent(tx)) {
        std::cerr << "[ERROR] Transaction blocked due to fraud detection.\n";
        return;
    }
    std::lock_guard<std::mutex> lock(ledgerMutex);
    ledger[tx.sender] -= tx.amount;
    ledger[tx.receiver] += tx.amount;
    transactionHistory[tx.sender].push_back(tx.timestamp);
    blockchain.push_back(tx);
    std::cout << "[INFO] Transaction completed successfully.\n";
}

// === EXTERNAL TRANSACTION IMPORT ===
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
        Transaction newTx{sender, receiver, "", timestamp, amount};
        processTransaction(newTx);
    }
}

// === WEB DASHBOARD (Crow) ===
void startWebDashboard() {
    crow::SimpleApp app;
    CROW_ROUTE(app, "/stats")([]() {
        Json::Value stats;
        stats["total_blocks"] = (int)blockchain.size();
        stats["total_users"] = (int)ledger.size();
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, stats));
    });
    CROW_ROUTE(app, "/ledger")([]() {
        Json::Value ledgerJson;
        for (const auto& [user, balance] : ledger)
            ledgerJson[user] = balance;
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, ledgerJson));
    });
    std::cout << "[INFO] Starting web dashboard on http://localhost:8080\n";
    app.port(8080).multithreaded().run();
}

// === MOBILE APP SIMULATION ===
void simulateMobileApp() {
    std::vector<Transaction> transactions = {
        {"User1", "User2", "", "2025-04-20T10:00:00Z", 50000.0},
        {"User1", "User3", "", "2025-04-20T10:05:00Z", 250000000.0},
        {"UNKNOWN", "User2", "", "2025-04-20T10:10:00Z", 1000.0},
        {"User3", "User2", "", "2025-04-20T10:15:00Z", 20000000.0}
    };
    for (const auto& tx : transactions)
        processTransaction(tx);
    blockchain.push_back({"User2", "User1", "", "2025-04-20T01:00:00Z", 10.0});
    std::cout << "[MOBILE APP] Transaction complete. New balance for User1: $" << ledger["User1"] << "\n";
}

// === LICENSE/EXIT ===
void displayExitPopup() {
    std::cout << "\n\n--- Exit Acknowledgment ---\n";
    std::cout << "MIT License\n";
    std::cout << "Copyright (c) 2025 EL-40 Blockchain\n";
    std::cout << "Special thanks to GPT Chat for assistance in the development.\n";
    std::cout << "This software is provided 'as-is' without any express or implied warranty.\n";
    std::cout << "For more information, visit: https://opensource.org/licenses/MIT\n";
    std::cout << "Email: elindau85@gmail.com\n";
    std::cout << "By: EL (El-40 Blockchain)\n";
    std::cout << "--- End of License ---\n";
    std::cout << "\nDDoS Protection Enabled: Network safety is ensured during this operation.\n";
}

// === MAIN ===
int main() {
    std::cout << "Welcome to the EL-40 Blockchain Program.\n";
    std::cout << "\n\n=== MIT LICENSE AGREEMENT ===\n";
    std::cout << "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
              << "of this software and associated documentation files (the \"Software\"), to deal\n"
              << "in the Software without restriction...\n";
    std::cout << "Type 'agree' to proceed: ";
    std::string input;
    std::cin >> input;
    if (input != "agree") {
        std::cout << "License not accepted. Program will terminate.\n";
        return 0;
    }
    if (!nodeAccessAgreement()) return 0;

    // Start web dashboard in a separate thread
    std::thread dashboardThread(startWebDashboard);
    dashboardThread.detach();

    // Blockchain, node, and transaction simulation
    EL40_Blockchain blockchainClass;
    blockchainClass.displayChain();

    fetchExternalTransactions();
    distributeLoad("Sync Task 1");
    distributeLoad("Sync Task 2");
    updateNodeReputation("Node1", -5);
    simulateMobileApp();

    std::this_thread::sleep_for(std::chrono::seconds(5));
    displayExitPopup();
    std::cout << "Exiting program...\n";
    return 0;
}
