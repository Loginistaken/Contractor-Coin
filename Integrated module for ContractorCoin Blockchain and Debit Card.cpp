// ContractorCoin.cpp
// Integrated module for ContractorCoin Blockchain and Debit Card functionality

#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <mutex>
#include <sstream>
#include <cmath>
#include <thread>
#include <curl/curl.h>   // For HTTP requests to external APIs
#include <json/json.h>   // For parsing JSON responses
#include <crow.h>        // Include the CROW framework

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

double fetchUsdExchangeRate() {
    CURL* curl;
    CURLcode res;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.coingecko.com/api/v3/simple/price?ids=contractorcoin&vs_currencies=usd");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* data, size_t size, size_t nmemb, std::string* writer) -> size_t {
            if (writer) {
                writer->append((char*)data, size * nmemb);
                return size * nmemb;
            }
            return 0;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    // Parse the JSON response to extract the exchange rate
    Json::Reader reader;
    Json::Value jsonData;
    if (reader.parse(response, jsonData)) {
        return jsonData["contractorcoin"]["usd"].asDouble();
    } else {
        std::cerr << "[Error] Failed to parse exchange rate response.\n";
        return 0.0; // Fallback value
    }
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
    if (rate <= 0) {
        std::cout << "[Error] Invalid exchange rate.\n";
        return false;
    }
    double requiredTokens = usdAmount / rate;

    std::cout << "[Conversion] $" << usdAmount << " = " << requiredTokens << " tokens at rate $" << rate << "/token\n";

    if (burnTokens(wallet, requiredTokens)) {
        return processMerchantPayment(merchantId, usdAmount);
    } else {
        std::cout << "[Transaction Failed] Could not authorize purchase.\n";
        return false;
    }
}

// Start the Crow server in a separate thread
void startCrowServer() {
    crow::SimpleApp app;

    // Define a route for fetching live exchange rates
    CROW_ROUTE(app, "/get-exchange-rate")
    ([]() {
        double rate = fetchUsdExchangeRate();
        if (rate > 0) {
            return crow::response(std::to_string(rate));
        } else {
            return crow::response(500, "Failed to fetch exchange rate.");
        }
    });

    // Define a route for processing transactions
    CROW_ROUTE(app, "/process-transaction")
    ([](const crow::request& req) {
        auto jsonBody = crow::json::load(req.body);
        if (!jsonBody) {
            return crow::response(400, "Invalid JSON payload.");
        }

        double usdAmount = jsonBody["usdAmount"].d();
        std::string merchantId = jsonBody["merchantId"].s();

        std::ostringstream response;
        response << "[Transaction] Processed payment of $" << usdAmount << " to merchant " << merchantId;
        return crow::response(response.str());
    });

    // Start the server
    app.port(18080).multithreaded().run();
}

// Main driver: Demonstrate Blockchain and Debit Card Features
int main() {
    // Start the Crow server in a separate thread
    std::thread crowServerThread(startCrowServer);
    crowServerThread.detach();

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

    // Keep the main thread running to allow API server operation
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
