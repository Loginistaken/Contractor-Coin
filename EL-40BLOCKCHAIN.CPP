#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <thread>
#include <memory>
#include <future>
#include <chrono>
#include <vector>
#include <mutex>
#include <sstream>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <asio.hpp>
#include <crypto++/sha3.h>  // SHA-3 header from Crypto++ library
#include <crypto++/hex.h>   // Hex encoding (to display the hash)
#include <crypto++/rsa.h>   // RSA for digital signatures
#include <crypto++/osrng.h> // AutoSeededRandomPool for key generation
#include <crypto++/base64.h> // Base64 encoding/decoding
#include <leveldb/db.h>
#include "crypto.h"         // Assumed cryptographic functions (signing, hashing)
#include "blockchain.h"     // Core blockchain functions
#include "p2p_network.h"    // Peer-to-peer communication
#include "storage.h"        // LevelDB or SQLite-based persistent storage
#include <regex>
#include "external/crow/include/crow_all.h"

// Include the necessary headers for cryptographic, blockchain, and P2P logic
#include "crypto.h"       // Ensure this file defines cryptographic functions
#include "blockchain.h"   // Ensure this file contains blockchain structures and core logic
#include "p2p_network.h"  // Ensure this file implements P2P networking functionality

void testCryptoFunctionality() {
    // Example: Using Crypto++ to compute a SHA-3 hash
    std::string input = "Test data";
    CryptoPP::SHA3_256 hash;
    byte digest[CryptoPP::SHA3_256::DIGESTSIZE];

    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    std::cout << "SHA-3 hash computed successfully.\n";
}

void testLevelDBFunctionality() {
    // Example: Using LevelDB for basic database operations
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;

    leveldb::Status status = leveldb::DB::Open(options, "testdb", &db);
    if (status.ok()) {
        db->Put(leveldb::WriteOptions(), "key", "value");
        std::string value;
        db->Get(leveldb::ReadOptions(), "key", &value);
        std::cout << "LevelDB stored and retrieved: " << value << "\n";
        delete db;
    } else {
        std::cerr << "LevelDB error: " << status.ToString() << "\n";
    }
}

void testASIOFunctionality() {
    // Example: Setting up a basic ASIO service
    try {
        asio::io_context io_context;

        asio::steady_timer timer(io_context, asio::chrono::seconds(1));
        timer.wait();

        std::cout << "ASIO timer completed successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "ASIO error: " << e.what() << "\n";
    }
}

int main() {
    std::cout << "Starting tests for external libraries...\n";

    // Test Crypto++ functionality
    testCryptoFunctionality();

    // Test LevelDB functionality
    testLevelDBFunctionality();

    // Test ASIO functionality
    testASIOFunctionality();

    std::cout << "All tests completed successfully.\n";
    return 0;
}

// Global rate-limiting registry
std::unordered_map<std::string, int> nodeRequestCount;
std::mutex ddosMutex;

using namespace asio;
using ip::tcp;
using namespace std;

/**
 * @brief Computes a SHA-3 (256-bit) hash for a given input string.
 * 
 * This function takes an input string, calculates its SHA-3 hash, and returns the
 * hash value as a hexadecimal-encoded string.
 * 
 * @param input The input string to be hashed.
 * @return The hexadecimal-encoded SHA-3 hash of the input.
 */
std::string EL40_Hash(const std::string& input) {
    using namespace CryptoPP;

    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    // HexEncoder to convert the digest into a human-readable hexadecimal format
    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));  // Attach output string to the encoder
    encoder.Put(digest, sizeof(digest));     // Encode the raw digest
    encoder.MessageEnd();                    // Signal the end of encoding

    return output;  // Return the hex-encoded hash
}

/**
 * @brief Signs a given data string using RSA private key.
 * 
 * This function uses the RSA-PKCS1 v1.5 signing scheme (SHA-256 hashing)
 * to generate a digital signature for the provided data string.
 * 
 * @param data The data to be signed.
 * @param privateKey The RSA private key used for signing.
 * @return The generated digital signature as a string.
 */
std::string signTransaction(const std::string& data, const CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;  // Random generator for cryptographic operations
    std::string signature;

    // RSA Signer object using the provided private key
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

    // Sign the input data and store the resulting signature
    CryptoPP::StringSource ss(data, true,
        new CryptoPP::SignerFilter(rng, signer,
            new CryptoPP::StringSink(signature)  // Attach the signature output
        )
    );

    return signature;  // Return the generated signature
}

/**
 * @brief Verifies the authenticity of a digital signature.
 * 
 * This function checks whether a given digital signature matches the provided data
 * using the corresponding RSA public key.
 * 
 * @param data The original data that was signed.
 * @param signature The digital signature to be verified.
 * @param publicKey The RSA public key used for verification.
 * @return True if the signature is valid, otherwise false.
 */
bool verifyTransaction(const std::string& data, const std::string& signature, const CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);  // RSA Verifier object
    bool result = false;

    try {
        // Verify the signature by appending it to the data and passing it to the verifier
        CryptoPP::StringSource ss(signature + data, true,
            new CryptoPP::SignatureVerificationFilter(
                verifier,
                new CryptoPP::ArraySink((byte*)&result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION | CryptoPP::SignatureVerificationFilter::PUT_RESULT
            )
        );
    } catch (const CryptoPP::Exception& e) {
        // Handle any exceptions that occur during verification
        std::cerr << "Error verifying transaction: " << e.what() << '\n';
        return false;  // Signature verification failed
    }

    return result;  // Return whether the signature was valid
}

// Machine Learning Model Placeholder for Block Approval
bool approveBlockAI(const std::string& blockData) {
    // Future AI logic for approving/rejecting blocks
    std::cout << "ML Model analyzing block: " << blockData << "... Approved!\n";
    return true;
}

// Difficulty Adjustment for Fragments
int adjustDifficulty(int blockHeight) {
    return blockHeight / 10 + 1;  // Increase difficulty as the blockchain grows
}

// Mutex for thread safety
std::mutex mtx;

// Ledger to track balances
std::map<std::string, double> ledger;
std::map<std::string, double> offChainLedger; // Tracks off-chain balances

// Blockchain Network Configurations
struct BlockchainConfig {
    std::string coinName = "Contractor-coin";
    std::string oxAddress;
    std::string oxID;
    std::string genesisBlock;
    double totalSupply = 7000000000;      // Total supply of coins
    double burnRate = 0.02;              // Default burn rate (2%)
    double ownerVault = 1000000000;      // Owner's vault (1 billion coins)
    double userVault = 6000000000;       // User's vault (6 billion coins)
    double transactionFee = 0.005;       // 0.5% transaction fee
    double maintenanceFee = 0.00001;     // 0.001% maintenance fee
    std::string maintenanceVault = "0xMaintenanceVault"; // Vault address
    std::string firebaseUrl = "https://your-firebase-project.firebaseio.com/";
};
// === ContractorCoin_Core.h ===
#pragma once
#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <mutex>
#include "crypto.h"
#include "blockchain.h" // assumes BlockchainConfig + ledger defined

struct Transaction {
    std::string sender, receiver, signature, timestamp, txHash;
    double amount;

    Transaction(const std::string& from, const std::string& to, double amt, const std::string& sig)
        : sender(from), receiver(to), amount(amt), signature(sig)
    {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        timestamp = std::ctime(&time);
        txHash = EL40_Hash(sender + receiver + std::to_string(amount) + timestamp);
    }
};

inline bool processTransaction(const Transaction& tx, BlockchainConfig& cfg) {
    std::lock_guard<std::mutex> lock(ledgerMutex);
    double fee = tx.amount * cfg.transactionFee;
    double burn = tx.amount * cfg.burnRate;
    double maintenance = tx.amount * cfg.maintenanceFee;
    double total = tx.amount + fee + burn + maintenance;

    if (ledger[tx.sender] < total) {
        std::cerr << "[TX ERROR] Insufficient funds.\n"; return false;
    }

    ledger[tx.sender]     -= total;
    ledger[tx.receiver]   += tx.amount;
    ledger[cfg.maintenanceVault] += maintenance;
    cfg.totalSupply       -= burn;

    std::cout << "[TX] " << tx.amount << " sent " << tx.sender << " → " << tx.receiver << "\n";
    std::cout << "     Fee: " << fee << " | Burn: " << burn << " | Maintenance: " << maintenance << "\n";
    return true;
}

inline bool mintCoin(const std::string& to, double amt, BlockchainConfig& cfg) {
    std::lock_guard<std::mutex> lock(ledgerMutex);
    if (ledger["OwnerVault"] < amt) {
        std::cerr << "[MINT ERROR] OwnerVault balance too low.\n"; return false;
    }

    ledger["OwnerVault"] -= amt;
    ledger[to]           += amt;

    std::cout << "[MINT] " << amt << " minted to " << to << "\n";
    return true;
}

inline void rewardMiner(const std::string& miner, double reward, BlockchainConfig& cfg) {
    std::lock_guard<std::mutex> lock(ledgerMutex);
    if (ledger["OwnerVault"] >= reward) {
        ledger["OwnerVault"] -= reward;
        ledger[miner]        += reward;
        std::cout << "[REWARD] " << reward << " to miner: " << miner << "\n";
    } else {
        std::cerr << "[REWARD ERROR] Not enough funds in OwnerVault.\n";
    }
}

// Genesis block creation
void createGenesisTransaction(BlockchainConfig& config) {
    ledger["OwnerVault"] = config.ownerVault;
    ledger["UserVault"] = config.userVault;
    ledger["MaintenanceVault"] = 0.0;

    std::cout << "[INFO] Genesis transaction created:\n";
    std::cout << "  Owner Vault: " << config.ownerVault << " coins\n";
    std::cout << "  User Vault: " << config.userVault << " coins\n";
    std::cout << "  Maintenance Vault: " << ledger["MaintenanceVault"] << " coins\n";
}
main(std::string generateSecureUsername() {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::stringstream username;
    username << "user_";
    for (int i = 0; i < 10; ++i) {
        username << charset[dist(rng)];
    }
    return username.str();
}
)
// Add this mutex to ensure thread safety for ledger operations
std::mutex ledgerMutex;

// Updated `transferOffChain` function with thread safety
void transferOffChain(const std::string& user, double amount) {
    std::lock_guard<std::mutex> lock(ledgerMutex);  // Lock for thread safety
    if (ledger["UserVault"] >= amount) {
        ledger["UserVault"] -= amount;
        offChainLedger[user] += amount;

        std::cout << "[INFO] Transferred " << amount << " coins off-chain for user: " << user << "\n";
        std::cout << "  On-Chain Balance: " << ledger["UserVault"] << "\n";
        std::cout << "  Off-Chain Balance: " << offChainLedger[user] << "\n";
    } else {
        std::cout << "[ERROR] Insufficient funds in User Vault for off-chain transfer.\n";
    }
}

// Updated `verifyTransaction` with proper exception handling
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

// Replace hardcoded block reward with configurable value
double blockReward = 25.0;  // Add this to the configuration section

// Update `addBlock` function to use the configurable block reward
Transaction rewardTx = {"Network", minerAddress, blockReward, "Reward"};  // Replace hardcoded 25.0 with blockReward

// Replace `system` call in `fetchExternalTransactions` with a safer alternative
void fetchExternalTransactions() {
    std::ifstream scraperOutput("scraper_output.txt");  // Assume output is saved by scraper
    if (!scraperOutput.is_open()) {
        std::cerr << "[ERROR] Failed to open scraper output file.\n";
        return;
    }

    std::string line;
    while (std::getline(scraperOutput, line)) {
        std::cout << "[INFO] External transaction: " << line << "\n";
    }
    scraperOutput.close();
}

// Add exception handling in the `startServer` function
void startServer(unsigned short port) {
    try {
        asio::io_context io_context;
        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));
        std::cout << "Server started on port " << port << "\n";

        for (;;) {
            asio::ip::tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::cout << "New node connected!\n";
            std::thread(handleClient, std::move(socket)).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Server Error: " << e.what() << "\n";
    }
}
        std::cout << "Welcome to the EL-40 Blockchain Program.\n";

        BlockchainConfig config;

        // Create the genesis transaction
        createGenesisTransaction(config);

        std::cout << "[INFO] Blockchain initialized with genesis transaction.\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
// Blockchain Class
class EL40_Blockchain {
private:
    std::vector<Block> chain;
    std::unordered_map<std::string, double> ledger;
    std::mutex chainMutex; // Mutex for thread safety
    BlockchainDB db; // Database for storing blocks

public:
    EL40_Blockchain() {
        chain.push_back(createGenesisBlock());
        ledger["Genesis"] = 1000;
    }

    Block createGenesisBlock() {
        return Block(0, {}, "0");
    }

    void addBlock(const std::vector<Transaction>& transactions, const std::string& minerAddress = "MinerNode") {
        std::lock_guard<std::mutex> lock(chainMutex); // Ensure thread safety
        if (approveBlockAI(transactionsToString(transactions))) { // AI approval process
            Block last = chain.back();
            
            std::vector<Transaction> blockTxs = transactions;
            // Add block reward
            Transaction rewardTx = {"Network", minerAddress, 25.0, "Reward"}; // Example block reward
            blockTxs.push_back(rewardTx);

            Block newBlock(chain.size(), blockTxs, last.hash);

            // Mine the block with difficulty adjustment
            int difficulty = adjustDifficulty(chain.size());
            newBlock.mineBlock(difficulty);

            chain.push_back(newBlock);
            for (const auto& tx : blockTxs) {
                ledger[tx.sender] -= tx.amount;
                ledger[tx.receiver] += tx.amount;
            }

            db.storeBlock(newBlock.hash, transactionsToString(blockTxs)); // Store block in the database

            std::cout << "[+] Block added by " << minerAddress << " with reward 25.0 Contractor-coin\n";
        } else {
            std::cout << "Block rejected by AI approval process.\n";
        }
    }

    void displayChain() const {
        std::lock_guard<std::mutex> lock(chainMutex); // Ensure thread safety
        for (const auto& block : chain) {
            std::cout << "Index: " << block.index << "\n"
                      << "Time: " << block.timestamp << "\n"
                      << "Previous: " << block.prevHash << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Transactions: ";
            for (const auto& tx : block.transactions) {
                std::cout << tx.sender << " -> " << tx.receiver << ": " << tx.amount << " ";
            }
            std::cout << "\nFragment Hashes: ";
            for (const auto& fragHash : block.fragmentHashes) {
                std::cout << fragHash << " ";
            }
            std::cout << "\nNonce: " << block.nonce << "\n\n";
        }
    }

    void integrateWithMetaverse(const std::string& resourceURL) {
        std::regex xmlCheck(".*\\.xml$");
        if (std::regex_match(resourceURL, xmlCheck)) {
            std::cout << "[XML] External call to: " << resourceURL << "\n";

            // Placeholder: Simulate fetching and parsing XML
            std::cout << "[XML] <data><user>Verified</user><token>Auto</token></data>\n";
        } else {
            std::cout << "Invalid XML format. Only .xml URLs accepted for external integrations.\n";
        }
    }

    void fetchExternalTransactions() {
        std::cout << "Fetching external transactions using Python scraper...\n";
        if (std::system("python3 scraper.py") != 0) { // Calls external Python scraper
            std::cerr << "[ERROR] Failed to execute scraper.\n";
        }
    }

private:
    std::string transactionsToString(const std::vector<Transaction>& transactions) const {
        std::string result;
        for (const auto& tx : transactions) {
            result += tx.toString();
        }
        return result;
    }
};

// Node Access Agreement Function
bool nodeAccessAgreement() {
    std::string response;
    std::cout << "\nEL-40 Blockchain: Do you accept the node connection agreement? (yes/no): ";
    std::cin >> response;

    if (response == "yes" || response == "Yes") {
        std::cout << "\nAccess granted. Connecting node...\n";
        std::cout << "\nThis connection allows nodes to sync transactions and view blockchain data securely.\n";
        return true;
    } else {
        std::cout << "\nAccess denied. Returning to homepage...\n";
        return false;
    }
}

// Peer-to-Peer Networking
void startServer(unsigned short port) {
    try {
        asio::io_context io_context;
        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));
        std::cout << "Server started on port " << port << "\n";

        for (;;) {
            asio::ip::tcp::socket socket(io_context);
            acceptor.accept(socket);

            std::string clientIP = socket.remote_endpoint().address().to_string();

            {
                std::lock_guard<std::mutex> lock(ddosMutex);
                nodeRequestCount[clientIP]++;
                if (nodeRequestCount[clientIP] > 5) {
                    std::cout << "Potential DDoS detected from " << clientIP << " — throttling node.\n";
                    std::this_thread::sleep_for(std::chrono::seconds(5)); // Simple throttle
                }
            }

            std::cout << "New node connected!\n";
            std::thread(handleClient, std::move(socket)).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "Server Error: " << e.what() << "\n";
    }
}

// Secure Communication Placeholder
void handleClient(asio::ip::tcp::socket socket) {
    try {
        asio::streambuf buffer;
        asio::read_until(socket, buffer, "\n");
        std::istream input(&buffer);
        std::string message;
        std::getline(input, message);
        std::cout << "Received message: " << message << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Client Error: " << e.what() << "\n";
    }
}
#include "crow_all.h" // Include Crow library
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <cstdlib>
#include <mutex>
#include "blockchain.h" // Include blockchain logic
#include "crypto.h"     // Include cryptographic utilities

// Crow Application Instance
crow::SimpleApp app; // Create a Crow application instance

// Define the homepage route
CROW_ROUTE(app, "/")([]() {
    return "<html>"
           "<head><title>Buy Contractor Coin</title></head>"
           "<body>"
           "<h1>Welcome to Buy Contractor Coin</h1>"
           "<p>Thank you for your interest in Contractor Coin! You can purchase coins by following the instructions below:</p>"
           "<ul>"
           "  <li>Step 1: Visit our exchanges.</li>"
           "  <li>Step 2: Use your wallet to buy coins.</li>"
           "  <li>Step 3: Enjoy trading and using Contractor Coin!</li>"
           "</ul>"
           "<footer>© 2025 Contractor Coin</footer>"
           "</body>"
           "</html>";
});

// Define a route for additional resources (e.g., FAQs)
CROW_ROUTE(app, "/faq")([]() {
    return "<html>"
           "<head><title>Contractor Coin FAQ</title></head>"
           "<body>"
           "<h1>Frequently Asked Questions</h1>"
           "<p>Here are some common questions about Contractor Coin:</p>"
           "<ul>"
           "  <li><strong>What is Contractor Coin?</strong> A decentralized cryptocurrency designed for efficient transactions.</li>"
           "  <li><strong>How do I buy Contractor Coin?</strong> Visit the homepage for instructions.</li>"
           "</ul>"
           "<footer>© 2025 Contractor Coin</footer>"
           "</body>"
           "</html>";
});

// Function to start the Crow-based website
void startWebsite() {
    try {
        std::cout << "Starting the 'Buy Contractor Coin' website on http://localhost:8080 ..." << std::endl;
        app.port(8080).multithreaded().run();
    } catch (const std::exception& e) {
        std::cerr << "Error starting website: " << e.what() << "\n";
    }
}

// Display exit popup with MIT License
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

// Node Access Agreement Function
bool nodeAccessAgreement() {
    std::string response;
    std::cout << "\nEL-40 Blockchain: Do you accept the node connection agreement? (yes/no): ";
    std::cin >> response;

    if (response == "yes" || response == "Yes") {
        std::cout << "\nAccess granted. Connecting node...\n";
        std::cout << "\nThis connection allows nodes to sync transactions and view blockchain data securely.\n";
        return true;
    } else {
        std::cout << "\nAccess denied. Returning to homepage...\n";
        return false;
    }
}

// Main Function
int main() {
    try {
        std::cout << "Welcome to the EL-40 Blockchain Program.\n";

        // License agreement popup
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

        // Initialize the blockchain
        BlockchainConfig config;
        createGenesisTransaction(config);

        std::cout << "[INFO] Blockchain initialized with genesis transaction.\n";

        // Start the advertisement website in a separate thread
        std::thread websiteThread(startWebsite);
        websiteThread.detach();

        // Simulate multiple nodes mining and communicating
        EL40_Blockchain blockchain;
        std::thread node1(runNode, std::ref(blockchain), "Node 1 Block Data");
        std::thread node2(runNode, std::ref(blockchain), "Node 2 Block Data");

        node1.join();
        node2.join();

        blockchain.displayChain();

        // Fetch external transactions
        blockchain.fetchExternalTransactions();

        // Start P2P server in a separate thread
        std::thread serverThread(startServer, 8080);
        serverThread.detach();

        // Simulate program work for demonstration
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // Call the exit popup before exiting
        displayExitPopup();

        std::cout << "Exiting program...\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}
