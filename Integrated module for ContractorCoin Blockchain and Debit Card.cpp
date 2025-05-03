// ContractorCoin.cpp
// Integrated module for ContractorCoin Blockchain and Debit Card functionality

#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <mutex>
#include <sstream>
#include <cmath>
#include <curl/curl.h> // For HTTP calls (e.g., Oracle and APIs)

// Simulated Blockchain and Wallet structures
struct Wallet {
    std::string address;
    double tokenBalance;
};

struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;
    std::string timestamp;

    Transaction(const std::string& from, const std::string& to, double amt)
        : sender(from), receiver(to), amount(amt) {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        timestamp = std::ctime(&time);
    }

    std::string toString() const {
        return sender + " -> " + receiver + ": " + std::to_string(amount) + " @ " + timestamp;
    }
};

class ContractorCoinBlockchain {
private:
    struct Block {
        int index;
        std::vector<Transaction> transactions;
        std::string prevHash;
        std::string hash;
        int nonce;
        std::string timestamp;

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
            return std::to_string(std::hash<std::string>{}(toHash));
        }

        void mineBlock(int difficulty) {
            std::string target(difficulty, '0');
            while (hash.substr(0, difficulty) != target) {
                nonce++;
                hash = generateHash();
            }
        }
    };

    std::vector<Block> chain;
    std::mutex chainMutex;

    Block createGenesisBlock() {
        return Block(0, {}, "0");
    }

public:
    ContractorCoinBlockchain() {
        chain.push_back(createGenesisBlock());
    }

    void addBlock(const std::vector<Transaction>& transactions) {
        std::lock_guard<std::mutex> lock(chainMutex);
        Block last = chain.back();
        Block newBlock(chain.size(), transactions, last.hash);

        int difficulty = chain.size() / 10 + 1; // Adjust difficulty
        newBlock.mineBlock(difficulty);

        chain.push_back(newBlock);
        std::cout << "[INFO] Block added with hash: " << newBlock.hash << "\n";
    }

    void displayChain() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        for (const auto& block : chain) {
            std::cout << "Block Index: " << block.index << "\n"
                      << "Timestamp: " << block.timestamp << "\n"
                      << "Hash: " << block.hash << "\n"
                      << "Previous Hash: " << block.prevHash << "\nTransactions:\n";
            for (const auto& tx : block.transactions) {
                std::cout << "  " << tx.toString();
            }
            std::cout << "\n";
        }
    }
};

// Utility function to simulate fetching the current exchange rate
double fetchUsdExchangeRate() {
    return 0.0012; // Example: 1 ContractorCoin = $0.0012
}

// Simulate token balance checking
double getTokenBalance(const Wallet& wallet) {
    return wallet.tokenBalance;
}

// Simulate token burn (smart contract interaction)
bool burnTokens(Wallet& wallet, double tokensToBurn) {
    if (wallet.tokenBalance >= tokensToBurn) {
        wallet.tokenBalance -= tokensToBurn;
        std::cout << "[Blockchain] Burned " << tokensToBurn << " tokens.\n";
        return true;
    } else {
        std::cout << "[Error] Insufficient balance to burn tokens.\n";
        return false;
    }
}

// Simulate merchant payment via off-chain debit card API
bool processMerchantPayment(const std::string& merchantId, double usdAmount) {
    std::cout << "[API] Authorized payment of $" << usdAmount << " to merchant " << merchantId << ".\n";
    return true;
}

// Authorize and process a purchase using ContractorCoin
bool authorizePurchase(Wallet& wallet, double usdAmount, const std::string& merchantId) {
    double rate = fetchUsdExchangeRate();
    double requiredTokens = usdAmount / rate;

    std::cout << "[Conversion] $" << usdAmount << " = " << requiredTokens << " tokens at rate $" << rate << "/token\n";

    if (burnTokens(wallet, requiredTokens)) {
        return processMerchantPayment(merchantId, usdAmount);
    } else {
        std::cout << "[Transaction Failed] Could not authorize purchase.\n";
        return false;
    }
}

// Main driver: Demonstrate Blockchain and Debit Card Features
int main() {
    // Initialize blockchain
    ContractorCoinBlockchain blockchain;

    // Simulate user wallet
    Wallet userWallet = {"0xEL40UserAddress", 100000.0}; // Start with 100,000 tokens

    // Add some transactions to the blockchain
    std::vector<Transaction> transactions = {
        {"User1", "User2", 50.0},
        {"User2", "User3", 25.0}
    };
    blockchain.addBlock(transactions);

    // Display the blockchain
    blockchain.displayChain();

    // Simulate a purchase
    double usdToSpend = 10.00; // Purchase amount in USD
    std::string merchant = "Merchant_12345";

    std::cout << "[Wallet] Starting token balance: " << userWallet.tokenBalance << "\n";
    authorizePurchase(userWallet, usdToSpend, merchant);
    std::cout << "[Wallet] Ending token balance: " << userWallet.tokenBalance << "\n";

    return 0;
}
