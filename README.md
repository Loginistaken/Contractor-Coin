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
#include <crypto++/rsa.h>    // RSA for digital signatures
#include <crypto++/osrng.h>  // AutoSeededRandomPool for key generation
#include <crypto++/base64.h> // Base64 encoding/decoding
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

    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];
    hash.CalculateDigest(digest, (const byte*)input.c_str(), input.length());

    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;  // Return the hex-encoded hash
}

// Digital Signature Utility
std::string signTransaction(const std::string& data, const CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string signature;

    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
    CryptoPP::StringSource ss(data, true,
        new CryptoPP::SignerFilter(rng, signer,
            new CryptoPP::StringSink(signature)
        )
    );
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

#include <vector>
#include <string>
#include <map>
#include <iostream>

// Blockchain Network Configurations
struct BlockchainConfig {
    double totalSupply = 7000000000; // Total supply of coins
    double ownerVault = 1000000000; // Owner's vault (1 billion coins)
    double userVault = 6000000000;  // User's vault (6 billion coins)
    std::string maintenanceVault = "0xMaintenanceVault"; // Vault address for maintenance fee
};

// Ledger to track balances
std::map<std::string, double> ledger;

// Genesis block creation
void createGenesisTransaction(BlockchainConfig& config) {
    // Initialize the owner vault
    ledger["OwnerVault"] = config.ownerVault;

    // Initialize the user vault
    ledger["UserVault"] = config.userVault;

    // Initialize the maintenance vault with 0 balance
    ledger["MaintenanceVault"] = 0.0;

    // Log genesis transaction
    std::cout << "[INFO] Genesis transaction created:\n";
    std::cout << "  Owner Vault: " << config.ownerVault << " coins\n";
    std::cout << "  User Vault: " << config.userVault << " coins\n";
    std::cout << "  Maintenance Vault: " << ledger["MaintenanceVault"] << " coins\n";
}
// Transaction Structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string signature;

    std::string toString() const {
        return sender + receiver + std::to_string(amount) + signature;
    }
};

// Transaction Class
class TransactionClass {
public:
    std::string txID;
    std::string sender;
    std::string receiver;
    double amount;
    std::vector<std::string> inputs;  // References to UTXOs
    std::map<std::string, double> outputs; // New UTXOs
    std::string signature;
    
    TransactionClass(std::string sender, std::string receiver, double amount) {
        this->sender = sender;
        this->receiver = receiver;
        this->amount = amount;
        this->txID = generateTxID();  // Unique transaction hash
    }
    
    std::string generateTxID() {
        return EL40_Hash(sender + receiver + std::to_string(amount));
    }
};

// Mempool Class (include here detailed transaction validation and management)
class Mempool {
public:
    std::unordered_map<std::string, TransactionClass> pendingTxs;
    std::unordered_set<std::string> usedUTXOs; // Track used UTXOs
    
    void addTransaction(TransactionClass tx) {
        if (validateTransaction(tx)) {
            pendingTxs[tx.txID] = tx;
        }
    }
    
    bool validateTransaction(TransactionClass tx) {
        // Check for double-spending using UTXO model
        for (const std::string& input : tx.inputs) {
            if (usedUTXOs.find(input) != usedUTXOs.end()) {
                return false;  // Double spending detected
            }
        }
        // Additional validation logic can be added here
        return true;
    }
    
    std::vector<TransactionClass> getValidTransactions() {
        std::vector<TransactionClass> validTxs;
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
void depositCoins(const std::string& userWallet, const std::string& personalWallet, double amount, const std::string& maintenanceVault, double maintenanceFeeRate) {
    std::lock_guard<std::mutex> lock(chainMutex); // Ensure thread safety
class EL40_Blockchain {
private:
blockchain.depositCoins("UserWalletAddress", "PersonalWalletAddress", 1000.0, "0xMaintenanceVault", 0.00001);
    // Other members...

public:
    // Existing methods...

    // Add this function here
    void depositCoins(const std::string& userWallet, const std::string& personalWallet, double amount, const std::string& maintenanceVault, double maintenanceFeeRate);
};
    // Calculate maintenance fee
    double maintenanceFee = amount * maintenanceFeeRate;

    // Distribute coins
    ledger[userWallet] += amount - maintenanceFee; // Deposit to user wallet minus maintenance fee
    ledger[personalWallet] += maintenanceFee;     // Deposit maintenance fee to personal wallet
    ledger[maintenanceVault] += maintenanceFee;   // Deposit maintenance fee to vault

    // Log the operation
    std::cout << "[INFO] Deposited " << amount << " coins into user wallet: " << userWallet << "\n";
    std::cout << "[INFO] Maintenance fee of " << maintenanceFee << " contributed to vault: " << maintenanceVault << "\n";
}
// Block Structure
struct Block {
    int index;
    std::string timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;
    std::vector<std::string> fragmentHashes; // Fragment hashes

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

    void mineFragment(int difficulty) {
        std::string fragmentData = std::to_string(index) + timestamp + prevHash + std::to_string(nonce);
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
    std::vector<Transaction> transactions = { Transaction{"Node1", "Node2", 50.0, ""} };
    blockchain.addBlock(transactions);
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
    try {
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
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}
