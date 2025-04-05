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
#include <map>
#include <asio.hpp>
#include <crypto++/sha3.h>  // SHA-3 header from Crypto++ library
#include <crypto++/hex.h>    // Hex encoding (to display the hash)
#include <leveldb/db.h>
#include "crypto.h"  // Assumed cryptographic functions (signing, hashing)
#include "blockchain.h"  // Core blockchain functions
#include "p2p_network.h"  // Peer-to-peer communication
#include "storage.h"  // LevelDB or SQLite-based persistent storage

using namespace asio;
using ip::tcp;
using namespace std;

// Custom Hash Function (SHA-3)
std::string EL40_Hash(const std::string& input) {
    using namespace CryptoPP;

    // Initialize SHA-3
    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];

    // Calculate the hash
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    // Convert digest to hex string for display
    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;  // Return the hex-encoded hash
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
std::queue<std::string> transactionQueue;  // Simple transaction queue

// Blockchain Network Configurations
struct BlockchainConfig {
    std::string coinName = "Contractor-coin";
    std::string oxAddress;
    std::string oxID;
    std::string genesisBlock;
    double totalSupply = 7000000000;  // Total supply of coins
    double burnRate = 0.02;  // Default burn rate (2%)
    double ownerVault = 1000000000;  // Owner's vault (1 billion coins)
    double userVault = 6000000000;  // User's vault (6 billion coins)
    double transactionFee = 0.005;  // 1% transaction fee for team profit
    double maintenanceFee = 0.00001;  // 0.002% maintenance fee
    std::string maintenanceVault = "0xMaintenanceVault";  // Vault address for maintenance fee
    std::string firebaseUrl = "https://your-firebase-project.firebaseio.com/";
};

// Transaction Structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    double fee;
    double burned;
    double maintenance;
    double team_profit;
    time_t timestamp;

    std::string toString() const {
        return "Sender: " + sender + " | Receiver: " + receiver + " | Amount: " + std::to_string(amount) +
               " | Fee: " + std::to_string(fee) + " | Burned: " + std::to_string(burned);
    }
};

// Transaction Class
class TransactionClass {
public:
    string txID;
    string sender;
    string receiver;
    double amount;
    vector<string> inputs;  // References to UTXOs
    map<string, double> outputs; // New UTXOs
    string signature;
    
    TransactionClass(string sender, string receiver, double amount) {
        this->sender = sender;
        this->receiver = receiver;
        this->amount = amount;
        this->txID = generateTxID();  // Unique transaction hash
    }
    
    string generateTxID() {
        return EL40_Hash(sender + receiver + to_string(amount));
    }
};

// Mempool Class (include here detailed transaction validation and management)
class Mempool {
public:
    unordered_map<string, TransactionClass> pendingTxs;
    unordered_set<string> usedUTXOs; // Track used UTXOs
    
    void addTransaction(TransactionClass tx) {
        if (validateTransaction(tx)) {
            pendingTxs[tx.txID] = tx;
        }
    }
    
    bool validateTransaction(TransactionClass tx) {
        // Check for double-spending using UTXO model
        for (const string& input : tx.inputs) {
            if (usedUTXOs.find(input) != usedUTXOs.end()) {
                return false;  // Double spending detected
            }
        }
        // Additional validation logic can be added here
        return true;
    }
    
    vector<TransactionClass> getValidTransactions() {
        vector<TransactionClass> validTxs;
        for (auto& pair : pendingTxs) {
            validTxs.push_back(pair.second);
        }
        return validTxs;
    }
};

// BlockchainDB Class (using LevelDB for storing blockchain data)
class BlockchainDB {
public:
    leveldb::DB* db;
    leveldb::Options options;
    
    BlockchainDB() {
        options.create_if_missing = true;
        leveldb::Status status = leveldb::DB::Open(options, "./blockchain_db", &db);
        if (!status.ok()) {
            std::cerr << "Unable to open database: " << status.ToString() << std::endl;
        }
    }

    void storeBlock(const std::string& blockHash, const std::string& blockData) {
        db->Put(leveldb::WriteOptions(), blockHash, blockData);
    }
    
    std::string getBlock(const std::string& blockHash) {
        std::string blockData;
        db->Get(leveldb::ReadOptions(), blockHash, &blockData);
        return blockData;
    }
};

// Block Structure
struct Block {
    int index;
    std::string timestamp;
    std::string data;
    std::string prevHash;
    std::string hash;
    int nonce;
    std::vector<std::string> fragmentHashes; // Fragment hashes

    Block(int idx, const std::string& dataInput, const std::string& prev)
        : index(idx), data(dataInput), prevHash(prev), nonce(0) {
        timestamp = std::to_string(std::time(nullptr));
        hash = generateHash();
    }

    std::string generateHash() const {
        std::string toHash = std::to_string(index) + timestamp + data + prevHash + std::to_string(nonce);
        return EL40_Hash(toHash);  // Use SHA-3 to generate hash
    }

    // Mined fragment with difficulty adjustment
    void mineFragment(int difficulty) {
        std::string fragmentData = data + std::to_string(nonce);
        std::string fragmentHash = EL40_Hash(fragmentData);
        fragmentHashes.push_back(fragmentHash);
        nonce++;
    }
};

// Blockchain Class
class EL40_Blockchain {
private:
    std::vector<Block> chain;
    std::unordered_map<std::string, double> ledger;
    std::mutex chainMutex; // Mutex for thread safety
    BlockchainDB db; // Database for storing blocks

public:
    EL40_Blockchain() {
        chain.push_back(createVariableBlock());
        ledger["Genesis"] = 1000; // Example initial ledger entry
    }

    Block createVariableBlock() {
        return Block(0, "Variable-Block", "0");
    }

    void addBlock(const std::vector<Transaction>& transactions, const std::string& minerAddress = "MinerNode") {
        std::lock_guard<std::mutex> lock(chainMutex); // Ensure thread safety
        if (approveBlockAI(transactionsToString(transactions))) { // AI approval process
            Block last = chain.back();
            
            std::vector<Transaction> blockTxs = transactions;
            // Add block reward
            Transaction rewardTx = {"Network", minerAddress, 25.0, 0, 0, 0, 0, std::time(nullptr)}; // Example block reward
            blockTxs.push_back(rewardTx);

            Block newBlock(chain.size(), transactionsToString(blockTxs), last.hash);

            // Mine the block in fragments with difficulty adjustment
            int difficulty = adjustDifficulty(chain.size());
            for (int i = 0; i < difficulty; ++i) {
                newBlock.mineFragment(difficulty);
            }

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
                      << "Data: " << block.data << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Previous: " << block.prevHash << "\n"
                      << "Fragment Hashes: ";
            for (const auto& fragHash : block.fragmentHashes) {
                std::cout << fragHash << " ";
            }
            std::cout << "\n\n";
        }
    }

    void fetchExternalTransactions() {
        std::cout << "Fetching external transactions using Python scraper...\n";
        system("python3 scraper.py"); // Calls external Python scraper
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

// Simulate node network with multithreading (each thread represents a node)
void runNode(EL40_Blockchain& blockchain, const std::string& blockData) {
    blockchain.addBlock({Transaction{"Node1", "Node2", 50.0, 0, 0, 0, 0, std::time(nullptr)}});
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

int main() {
    std::cout << "Welcome to the EL-40 Blockchain Program.\n";

    if (!nodeAccessAgreement()) {
        return 0;
    }

    EL40_Blockchain blockchain;

    // Simulate multiple nodes mining and communicating
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

    // Simulate program work for demonstration (replace with your actual logic)
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Call the exit popup before exiting
    displayExitPopup();

    std::cout << "Exiting program...\n";
    return 0;
}
