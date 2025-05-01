#include <iostream>
#include <fstream>
#include <string>
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
#include "blockchain.h"     // Core blockchain functions
#include "p2p_network.h"    // Peer-to-peer communication
#include "storage.h"        // LevelDB or SQLite-based persistent storage
#include "external/crow/include/crow_all.h" // Crow web framework
#include <regex>

  

// === Transaction Structure ===

// === Block Structure ===
struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;

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


#include <chrono>

// Utility function to execute shell commands and check for success
bool executeCommand(const std::string &command) {
    int result = std::system(command.c_str());
    if (result != 0) {
        std::cerr << "[ERROR] Command failed: " << command 
                  << " (Error Code: " << result << ")\n";
    }
    return result == 0;
}

bool isPackageInstalled(const std::string &packageName) {
    std::string checkCommand = "dpkg -s " + packageName + " > /dev/null 2>&1";
    return executeCommand(checkCommand);
}

// Function to check if a package is installed


// Function to install LevelDB

    } else {
     // Utility function to execute shell commands and check for success
bool executeCommand(const std::string &command) {
    int result = std::system(command.c_str());
    if (result != 0) {
        std::cerr << "[ERROR] Command failed: " << command 
                  << " (Error Code: " << result << ")\n";
    }
    return result == 0;
}

// Function to check if a package is installed
bool isPackageInstalled(const std::string &packageName) {
    std::string checkCommand = "dpkg -s " + packageName + " > /dev/null 2>&1";
    if (!executeCommand(checkCommand)) {
        std::cout << "[INFO] Package " << packageName << " is not installed.\n";
        return false;
    }
    std::cout << "[INFO] Package " << packageName << " is already installed.\n";
    return true;
}

// Function to install LevelDB
void installLevelDB() {
    std::cout << "[INFO] Checking for LevelDB installation...\n";
    if (!isPackageInstalled("libleveldb-dev")) {
        std::cout << "[INFO] LevelDB not found. Installing LevelDB...\n";
        std::string installCommand = "sudo apt update && sudo apt install -y libleveldb-dev";
        if (executeCommand(installCommand)) {
            std::cout << "[SUCCESS] LevelDB installed successfully.\n";
        } else {
            std::cerr << "[ERROR] Failed to install LevelDB. Please check your package manager logs.\n";
        }
    }
}

// Function to install Asio
void installAsio() {
    std::cout << "[INFO] Checking for Asio installation...\n";
    if (!isPackageInstalled("libasio-dev")) {
        std::cout << "[INFO] Asio not found. Installing Asio...\n";
        std::string installCommand = "sudo apt update && sudo apt install -y libasio-dev";
        if (executeCommand(installCommand)) {
            std::cout << "[SUCCESS] Asio installed successfully.\n";
        } else {
            std::cerr << "[ERROR] Failed to install Asio. Please check your package manager logs.\n";
        }
    }
}

    // Add a delay for better user experience
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Install Asio
    installAsio();

    std::cout << "=== Installation Process Completed ===\n";

    return 0;
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
 
}g EL40_Hash(const std::string& input) {
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

    std::string output;
    HexEncoder encoder(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;
}
std::string signTransaction(const std::string& data, const CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;  // Random generator for cryptographic operations
    std::string signature;

    // RSA Signer object using the provided private key
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

    // Sign the input data and store the resulting signature
    CryptoPP::StringSource ss(data, true,
      auto pastTime = std::chrono::system_clock::from_time_t(std::mktime(&std::tm{})); 
// Replace with actual parsing logic for ISO 8601 format
        )
    );

    return signature;  // Return the generated signature
}

/**
 * @brief Verifies the authenticity of a digital signature.
 * std::tm tm = {};
std::istringstream ss("2025-04-20T10:00:00");
ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
auto pastTime = std::chrono::system_clock::from_time_t(std::mktime(&tm));
 * This function checks whether a given digital signature matches the provided data
 * using the corresponding RSA public key.
 * 
 * @param data The original data that was signed.
 * @param signature The digital signature to be verified.
 * @param publicKey The RSA public key used for verification.
 * @return True if the signature is valid, otherwise false.
 */
// Function to verify the authenticity of a digital signature
bool verifyTransaction(const std::string& data, const std::string& signature, const CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);  // RSA Verifier object
    bool result = false;
bool approveBlockAI(const std::string &blockData) {
    std::cout << "[AI] Analyzing block data...\n";

    // Check for suspicious keywords
    std::vector<std::string> suspiciousKeywords = {"fraud", "invalid", "error", "malicious"};
    for (const auto &keyword : suspiciousKeywords) {
        if (blockData.find(keyword) != std::string::npos) {
            std::cerr << "[AI] Block rejected due to suspicious keyword: " << keyword << "\n";
            return false;
        }
    }

    // Validate block length
    if (blockData.length() < 100 || blockData.length() > 10000) {
        std::cerr << "[AI] Block rejected due to invalid data length.\n";
        return false;
    }

    std::cout << "[AI] Block approved.\n";
    return true;
}

    // Validate block length
    if (blockData.length() < 100 || blockData.length() > 10000) {
        std::cerr << "[AI] Block rejected due to invalid data length.\n";
        return false;
    }

    std::cout << "[AI] Block approved.\n";
    return true;
}
    // Example heuristic: Block data length must meet a minimum threshold
    if (blockData.length() < 100) {
        std::cerr << "[AI] Block rejected due to insufficient data length.\n";
        return false;
    }

    // Simulated success
    std::cout << "[AI] Block approved.\n";
    return true; // Block approved
}
}

/

// Difficulty Adjustment for Fragments
int adjustDifficulty(int blockHeight) {
    return blockHeight / 10 + 1;  // Increase difficulty as the blockchain grows
}

// Mutex for thread safety
std::mutex mtx;

// Ledger to track balances
std::map<std::string, double> ledger;
std::map<std::string, double> offChainLedger; // Tracks off-chain balances

// === Block Structure ===
struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;
#pragma once

const double OWNER_VAULT_INITIAL_BALANCE = 1'000'000'000.0;
const double USER_VAULT_INITIAL_BALANCE = 6'000'000'000.0;
#include "config.h"

ledger["OwnerVault"] = OWNER_VAULT_INITIAL_BALANCE; // Initialize Owner Vault
ledger["UserVault"] = USER_VAULT_INITIAL_BALANCE;  // Initialize User Vault
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

#include <cmath>

class ContractorCoin {
private:
    double value;          // Coin value
    uint64_t sales;        // Number of sales
    uint64_t totalSupply;  // Total coin supply

public:
    ContractorCoin() : value(0.00001), sales(0), totalSupply(0) {}

    void sellCoin(uint64_t numCoins) {
        sales += numCoins;

        // Phase 1: Rapid increase for first 40 sales (starting with 5 decimals)
        if (sales <= 40) {
            value *= pow(10, sales); // Rapid increase for initial transactions
        }
        // Phase 2: Gradual increase until value reaches $0.001
        else if (sales <= 100000) {
            if (value < 0.001) {
                value += 0.00001; // Gradual increase
            }
        }
        // Phase 3: Accelerate the value growth until $1 by 1 million sales
        else if (sales <= 1000000) {
            if (value < 1.0) {
                value += (value * 0.01); // Accelerates until $1
            }
        }
        // Phase 4: Rapid acceleration to $700 between 1 million and 1.1 million sales
        else if (sales <= 1100000) {
            if (value < 700.0) {
                value += (value * 0.5); // Rapid acceleration to $700
            }
        }
        // Phase 5: Slower growth after $700
        else if (sales <= 1200000) {
            value += 1.0; // Slower increase after peaking
        }
void mintCoins(uint64_t numCoins) {
    if (numCoins <= 0) {
        std::cerr << "[ERROR] Number of coins to mint must be positive.\n";
        return;
    }
    if (totalSupply + numCoins < totalSupply) {
     void mintCoins(uint64_t numCoins) {
    if (numCoins <= 0) {
        std::cerr << "[ERROR] Number of coins to mint must be positive.\n";
        return;
    }
    if (totalSupply + numCoins < totalSupply) {
        std::cerr << "[ERROR] Overflow detected in total supply.\n";
        return;
    }
    totalSupply += numCoins;
    std::cout << "Minted " << numCoins << " coins. Total supply: " << totalSupply << std::endl;
}
        // Minting mechanism: Mint 0.5 billion coins after 1 billion sales
        if (sales >= 1000000000) {
            mintCoins(500000000); // Mint 0.5 billion coins
            sales = 0;            // Reset sales counter for the next cycle
        }
    }
void mintCoins(uint64_t numCoins) {
    if (numCoins <= 0) {
        std::cerr << "[ERROR] Number of coins to mint must be positive.\n";
        return;
    }
    if (totalSupply + numCoins < totalSupply) {
        std::cerr << "[ERROR] Overflow detected in total supply.\n";
        return;
    }
    totalSupply += numCoins;
    std::cout << "Minted " << numCoins << " coins. Total supply: " << totalSupply << std::endl;
}

    void displayStatus() {
        std::cout << "Value: $" << value << ", Sales: " << sales << ", Total Supply: " << totalSupply << std::endl;
    }
};

int main() {
    ContractorCoin coin;

    // Simulate sales
    for (int i = 1; i <= 1500000; ++i) {
        coin.sellCoin(1);
        if (i % 10000 == 0) { // Display status every 10,000 sales
            coin.displayStatus();
        }
    }

    return 0;
}
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
std::mutex ledgerMutex;
// Genesis block creation
void createGenesisTransaction(BlockchainConfig& config) {
    ledger["OwnerVault"] = config.ownerVault;
    ledger["UserVault"] = config.userVault;
    ledger["MaintenanceVault"] = 0.0;

    std::cout << "[INFO] Genesis transaction created:\n";
   main(std::string generateSecureUsername() {
std::string generateSecureUsername() {
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
// Add this mutex to ensure thread safety for ledger operations
std::mutex ledgerMutex;

// Updated `transferOffChain` function with thread safety
void transferOffChain(const std::string& user, double amount) {
    std::lock_guard<std::mutex> lock(ledgerMutex);  // Lock for thread safety

    // Check if the User Vault has enough balance
    if (ledger["UserVault"] >= amount) {
        ledger["UserVault"] -= amount;             // Deduct amount from User Vault
        offChainLedger[user] += amount;           // Add amount to the off-chain ledger for the user

        // Logging transaction success
        std::cout << "[INFO] Transferred " << amount << " coins off-chain for user: " << user << "\n"
                  << "  On-Chain Balance: " << ledger["UserVault"] << "\n"
                  << "  Off-Chain Balance: " << offChainLedger[user] << "\n";
    } else {
        // Logging transaction failure
        std::cerr << "[ERROR] Insufficient funds in User Vault for off-chain transfer.\n";
    }
}
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
void fetchExternalTransactions() {
    try {
        std::ifstream scraperOutput("scraper_output.txt");
        if (!scraperOutput.is_open()) {
            throw std::runtime_error("Failed to open scraper output file.");
        }

        std::string line;
        while (std::getline(scraperOutput, line)) {
            std::cout << "[INFO] External transaction: " << line << "\n";
        }
        scraperOutput.close();
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
    }
}
        for (;;) {
            asio::ip::tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::cout << "New node connected!\n";

            // Example of creating a reward transaction for the miner
            Transaction rewardTx = {"Network", minerAddress, 25.0, "Reward"}; // Use minerAddress here
            std::cout << "[INFO] Reward transaction created for miner: " << minerAddress << "\n";

            // Handle the client connection in a separate thread
            std::thread(handleClient, std::move(socket)).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Server Error: " << e.what() << "\n";
    }
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
        Transaction rewardTx = {"Network", minerAddress, 25.0, "Reward"}; // Example block reward
const double DEFAULT_BLOCK_REWARD = 25.0;
Transaction rewardTx = {"Network", minerAddress, DEFAULT_BLOCK_REWARD, "Reward"}; // Configurable block reward
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
void fetchExternalTransactions() {
    try {
        std::ifstream scraperOutput("scraper_output.txt");
        if (!scraperOutput.is_open()) {
            throw std::runtime_error("Failed to open scraper output file.");
        }
void fetchExternalTransactions() {
    try {
        std::ifstream scraperOutput("scraper_output.txt");
        if (!scraperOutput.is_open()) {
            throw std::runtime_error("Failed to open scraper output file.");
        }

        std::string line;
        while (std::getline(scraperOutput, line)) {
            std::cout << "[INFO] External transaction: " << line << "\n";
        }
        scraperOutput.close();
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
    }
}
#include <filesystem>
#include <fstream>


void fetchExternalTransactions() {
    try {
        std::ifstream scraperOutput("scraper_output.txt");
        if (!scraperOutput.is_open()) {
            throw std::runtime_error("Failed to open scraper output file.");
        }

        std::string line;
        while (std::getline(scraperOutput, line)) {
            std::cout << "[INFO] External transaction: " << line << "\n";
        }
        scraperOutput.close();
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
    }
}
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

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

// Mutex to ensure thread safety for agreement logs
std::mutex agreementMutex;

// Function to display the node connection agreement
void displayAgreement() {
    std::cout << "=== Node Connection Agreement ===\n";
    std::cout << "By connecting to this node, you agree to the following terms:\n";
    std::cout << "1. Data regarding cryptocurrency transactions may be viewed for security and compliance purposes.\n";
    std::cout << "2. Your data will be handled in accordance with applicable privacy laws.\n";
    std::cout << "3. You can revoke this agreement at any time by contacting support.\n";
    std::cout << "4. All data will be securely stored and encrypted.\n";
    std::cout << "Do you agree to these terms? (yes/no): ";
}

// Function to log agreement to a file
void logAgreement(const std::string& username, bool agreed) {
    std::lock_guard<std::mutex> lock(agreementMutex); // Thread-safe file access
    std::ofstream logFile("node_agreement_log.txt", std::ios::app);

    if (logFile.is_open()) {
        logFile << "User: " << username << ", Agreement: " << (agreed ? "Accepted" : "Declined") << "\n";
        logFile.close();
    } else {
        std::cerr << "[ERROR] Unable to open agreement log file.\n";
    }
}

// Function to handle node connection agreement
bool nodeAccessAgreement(const std::string& username) {
    displayAgreement();

    std::string response;
    std::cin >> response;

    if (response == "yes" || response == "Yes") {
        std::cout << "\nAccess granted. Connecting node...\n";
        std::cout << "\nThis connection allows nodes to sync transactions and view blockchain data securely.\n";

        logAgreement(username, true); // Log acceptance
        return true;
    } else {
        std::cout << "\nAccess denied. Returning to homepage...\n";

        logAgreement(username, false); // Log denial
        return false;
    }
}

int main() {
    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    if (!nodeAccessAgreement(username)) {
        return 0; // Exit if the user does not agree
    }

    // Proceed with node connection functionality here
    std::cout << "Node connected successfully for user: " << username << "\n";

    return 0;
}
// Function to cancel the node connection agreement
void cancelNodeAgreement(const std::string& username) {
    std::lock_guard<std::mutex> lock(agreementMutex); // Thread-safe access
    std::cout << "[INFO] Canceling node agreement for user: " << username << "\n";

    // Log the cancellation
  void cancelNodeAgreement(const std::string& username) {
    std::lock_guard<std::mutex> lock(agreementMutex); // Thread-safe access
    std::cout << "[INFO] Canceling node agreement for user: " << username << "\n";

    /void cancelNodeAgreement(const std::string& username) {
    std::lock_guard<std::mutex> lock(agreementMutex);
    std::cout << "[INFO] Canceling node agreement for user: " << username << "\n";

    std::ofstream logFile("node_agreement_log.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "[ERROR] Failed to open 'node_agreement_log.txt' for writing.\n";
        return;
    }
    logFile << "User: " << username << ", Agreement: Canceled\n";
    logFile.close();

    authorizedNodes[username] = false;
    std::cout << "[INFO] Node connection disabled for user: " << username << "\n";
}

    // Disable node connection
    authorizedNodes[username] = false; // Mark the node as unauthorized
    std::cout << "[INFO] Node connection disabled for user: " << username << "\n";
}

    // Disable node connection
    authorizedNodes[username] = false; // Mark the node as unauthorized
    std::cout << "[INFO] Node connection disabled for user: " << username << "\n";
}
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <chrono>
#include <asio.hpp>
#include <crypto++/rsa.h>
#include <crypto++/aes.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/modes.h>
#include <crypto++/sha.h>

// Mutex for thread safety
std::mutex nodeMutex;

// Node access control
std::unordered_map<std::string, bool> authorizedNodes = {{"Node1", true}, {"Node2", true}};

// Function to encrypt data using AES
std::string encryptData(const std::string& plainText, const std::string& key) {
    std::string cipherText;
    CryptoPP::AES::Encryption aesEncryption((byte*)key.c_str(), key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (byte*)key.c_str());

    CryptoPP::StringSource encryptor(
        plainText, true,
        new CryptoPP::StreamTransformationFilter(cbcEncryption,
            new CryptoPP::StringSink(cipherText)
        )
    );

    return cipherText;
}

// Function to decrypt data using AES
std::string decryptData(const std::string& cipherText, const std::string& key) {
    std::string plainText;
    CryptoPP::AES::Decryption aesDecryption((byte*)key.c_str(), key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte*)key.c_str());

    CryptoPP::StringSource decryptor(
        cipherText, true,
        new CryptoPP::StreamTransformationFilter(cbcDecryption,
            new CryptoPP::StringSink(plainText)
        )
    );

    return plainText;
}

// Function to validate node access
bool validateNodeAccess(const std::string& nodeName) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    if (authorizedNodes.find(nodeName) != authorizedNodes.end() && authorizedNodes[nodeName]) {
        return true;
    }
    return false;
}

// Function to fetch and process external transactions
void fetchExternalTransactions() {
    std::ifstream scraperOutput("scraper_output.txt");
    if (!scraperOutput.is_open()) {
        std::cerr << "[ERROR] Failed to open scraper output file.\n";
        return;
    }

    std::string line;
    while (std::getline(scraperOutput, line)) {
        std::cout << "[INFO] Processing external transaction: " << line << "\n";
        // Add logic here to integrate external transactions into the blockchain
    }
    scraperOutput.close();
}

// Function to log node activities
void logNodeActivity(const std::string& nodeName, const std::string& activity) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    std::ofstream logFile("node_activity_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "Node: " << nodeName << ", Activity: " << activity << ", Timestamp: " << std::time(nullptr) << "\n";
        logFile.close();
    } else {
        std::cerr << "[ERROR] Unable to open activity log file.\n";
    }
}

// Function to simulate node operations after connection
void nodeOperations(const std::string& nodeName) {
    if (!validateNodeAccess(nodeName)) {
        std::cerr << "[ERROR] Unauthorized node access attempt: " << nodeName << "\n";
        return;
    }

    std::cout << "[INFO] Node " << nodeName << " connected successfully.\n";
    logNodeActivity(nodeName, "Node connected.");

    // Simulate fetching external transactions
    fetchExternalTransactions();
    logNodeActivity(nodeName, "Fetched external transactions.");
}

// Main function
int main() {
    // Simulate node connection
    std::string nodeName;
    std::cout << "Enter node name: ";
    std::cin >> nodeName;

    // Start node operations
    std::thread nodeThread(nodeOperations, nodeName);
    nodeThread.join();

    return 0;
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
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <asio.hpp>
#include <json/json.h> // For JSON parsing (install JSON for Modern C++ library)
#include <crow_all.h>  // Crow library for web integration

// Mutex for thread safety
std::mutex nodeMutex;

// Node Reputation System
struct Node {
    std::string name;
    int reputation;
    int load; // Current load handled by the node
};

// Global node list
std::unordered_map<std::string, Node> nodes = {
    {"Node1", {"Node1", 100, 0}},
    {"Node2", {"Node2", 95, 0}},
    {"Node3", {"Node3", 80, 0}}
};

// Blockchain Mock (For simplicity)
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string timestamp;
};

std::vector<Transaction> blockchain;
std::unordered_map<std::string, double> ledger = {{"User1", 1000.0}, {"User2", 500.0}};

// 1. Cross-Chain Interoperability
void crossChainSync(const std::string& externalBlockchain) {
    std::cout << "[INFO] Syncing with external blockchain: " << externalBlockchain << "\n";
    // Mock: Fetch and integrate data from the external blockchain
    // In a real implementation, this would use APIs or SDKs of the external blockchain
    Transaction tx = {"ExternalUser", "User1", 50.0, "2025-04-20T00:00:00Z"};
    blockchain.push_back(tx);
    ledger["User1"] += 50.0;
    std::cout << "[INFO] Synced transaction: " << tx.sender << " -> " << tx.receiver << ": " << tx.amount << "\n";
}

// 2. External Transaction Sync
void fetchExternalTransactions() {
    std::ifstream apiOutput("external_transactions.json"); // Mock API response
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
        blockchain.push_back({sender, receiver, amount, timestamp});
        ledger[receiver] += amount;
        std::cout << "[INFO] Synced external transaction: " << sender << " -> " << receiver << ": " << amount << "\n";
    }
}

// 3. Load Balancing
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

// 4. Node Reputation System
void updateNodeReputation(const std::string& nodeName, int change) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    if (nodes.find(nodeName) != nodes.end()) {
        nodes[nodeName].reputation += change;
        std::cout << "[INFO] Updated reputation for " << nodeName << " to " << nodes[nodeName].reputation << "\n";
    } else {
        std::cerr << "[ERROR] Node not found: " << nodeName << "\n";
    }
}

// 5. Web Dashboard (Crow Integration)
void startWebDashboard() {
    crow::SimpleApp app;

    // Display blockchain stats
    CROW_ROUTE(app, "/stats")([]() {
        Json::Value stats;
        stats["total_blocks"] = (int)blockchain.size();
        stats["total_users"] = (int)ledger.size();
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, stats));
    });

    // Display ledger
    CROW_ROUTE(app, "/ledger")([]() {
        Json::Value ledgerJson;
        for (const auto& [user, balance] : ledger) {
            ledgerJson[user] = balance;
        }
        Json::StreamWriterBuilder writer;
        return crow::response(Json::writeString(writer, ledgerJson));
    });

    // Start the web dashboard
    std::cout << "[INFO] Starting web dashboard on http://localhost:8080\n";
    app.port(8080).multithreaded().run();
}

// 6. Mobile App Integration
void simulateMobileApp() {
 #include <iostream>
#include <vector>
#include <unordered_map>
#include <cmath>
#include <string>
#include <chrono>

// Define thresholds (adjustable)
const double MAX_TRANSACTION_AMOUNT = 5000000.0;   // Limit for transaction amount
const int MAX_TRANSACTION_FREQUENCY = 1000;       // Limit for transaction frequency
const std::string UNKNOWN_ACCOUNT = "UNKNOWN";    // Flag for unknown accounts

// Transaction structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string timestamp;

    Transaction(const std::string& from, const std::string& to, double amt, const std::string& time)
        : sender(from), receiver(to), amount(amt), timestamp(time) {}
};

// Ledger to store balances
std::unordered_map<std::string, double> ledger = {
    {"User1", 5000.0},
    {"User2", 250000000.0},
    {"User3", 2000000.0}
auto pastTime = std::chrono::system_clock::from_time_t(std::mktime(&std::tm{})); 
// Replace with actual parsing logic for ISO 8601 format timestamps
// Historical transactions
  
std::unordered_map<std::string, std::vector<Transaction>> transactionHistory;
// Proper ISO 8601 timestamp parsing logic
auto pastTime = std::chrono::system_clock::from_time_t(std::mktime(&std::tm{}));
// Fraud detection function
bool isFraudulent(const Transaction& tx) {
    // Check if the transaction amount exceeds the maximum allowed
    if (tx.amount > MAX_TRANSACTION_AMOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Amount exceeds maximum allowed.\n";
        return true;
    }

    // Check if the sender or receiver is flagged as UNKNOWN
    if (tx.sender == UNKNOWN_ACCOUNT || tx.receiver == UNKNOWN_ACCOUNT) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Involves an unknown account.\n";
        return true;
    }

    // Analyze historical transactions for the sender
    auto& history = transactionHistory[tx.sender];
    int recentTransactions = 0;
    auto currentTime = std::chrono::system_clock::now();

    for (const auto& pastTx : history) {
        // Calculate time difference (assume timestamp is in ISO 8601 format: "YYYY-MM-DDTHH:MM:SSZ")
        auto pastTime = std::chrono::system_clock::from_time_t(std::mktime(&std::tm{})); // Placeholder, parse timestamp
        auto duration = std::chrono::duration_cast<std::chrono::hours>(currentTime - pastTime).count();

        // Count transactions within the last 24 hours
        if (duration <= 24) {
            recentTransactions++;
        }
    }

    // Check if the transaction frequency exceeds the maximum allowed
    if (recentTransactions > MAX_TRANSACTION_FREQUENCY) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Frequency exceeds maximum allowed.\n";
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

    // Update ledger and transaction history
    ledger[tx.sender] -= tx.amount;
    ledger[tx.receiver] += tx.amount;
    transactionHistory[tx.sender].push_back(tx);

    std::cout << "[INFO] Transaction completed successfully.\n";
}

// Simulation of transactions
int main() {
    // Example transaction data
    std::vector<Transaction> transactions = {
        {"User1", "User2", 50000.0, "2025-04-20T10:00:00Z"},
        {"User1", "User3", 250000000.0, "2025-04-20T10:05:00Z"}, // Fraudulent: Amount exceeds limit
        {"UNKNOWN", "User2", 1000.0, "2025-04-20T10:10:00Z"}, // Fraudulent: Involves unknown account
        {"User3", "User2", 20000000.0, "2025-04-20T10:15:00Z"}
    };

    for (const auto& tx : transactions) {
        processTransaction(tx);
    }

    return 0;
}
    blockchain.push_back({"User2", "User1", 10.0, "2025-04-20T01:00:00Z"});
    std::cout << "[MOBILE APP] Transaction complete. New balance for User1: $" << ledger["User1"] << "\n";
}

int main() {
    // Start web dashboard in a separate thread
    std::thread dashboardThread(startWebDashboard);
    dashboardThread.detach();

    // Simulate Cross-Chain Interoperability
    crossChainSync("ExternalBlockchain_123");

    // Fetch external transactions
    fetchExternalTransactions();

    // Perform load balancing
    distributeLoad("Sync Task 1");
    distributeLoad("Sync Task 2");

    // Update node reputation
    updateNodeReputation("Node1", -5);

    // Simulate mobile app interaction
    simulateMobileApp();

    return 0;
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
// Basic transaction ledger
std::vector<Transaction> blockchain;
std::unordered_map<std::string, double> userBalances = {
    {"User1", 1000.0},
    {"User2", 500.0},
    {"User3", 200.0}
};

// Fraud Detection Function
bool isFraudulent(const Transaction& tx) {
    // Example ML-inspired fraud detection rules:
    // 1. Transaction amount exceeds a certain threshold.
    // 2. Multiple transactions from the same sender in a short time.
    // 3. Insufficient funds (double spending attempt).

    const double FRAUD_THRESHOLD = 10000.0; // Example threshold

    if (tx.amount > FRAUD_THRESHOLD) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Amount exceeds threshold.\n";
        return true;
    }

    if (userBalances[tx.sender] < tx.amount) {
        std::cerr << "[FRAUD ALERT] Transaction flagged: Insufficient funds.\n";
        return true;
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
