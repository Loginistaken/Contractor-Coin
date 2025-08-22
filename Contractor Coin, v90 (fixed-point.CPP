// contractor_coin.cpp -- EL-40 / Contractor Coin, v90 (fixed-point, sig+nonce mandatory)
// ---------------------------------------------------------------------------------------
// What’s new vs. your merged version:
// - Fixed-point Amount (int64_t) with 7 decimals (UNIT=10,000,000) — no floating drift
// - Mandatory signatures for all non-coinbase transactions (coinbase exempt)
// - Mandatory nonces (strictly last+1 per sender) — replay protection
// - CHAIN_ID included in canonical signing
// - Reward minting logic preserved (no debit from "Network")
// - Merkle root + block validation + target-time difficulty retarget
// - Thread-safe HTTP dashboard; /stats shows real height + mempool
// - Demo: ephemeral RSA keys for User1/User3 + signed sample txs so the program runs
//
// Build example:
//   g++ -std=gnu++17 contractor_coin.cpp -lcryptopp -lpthread -O2
//
// External deps (headers/libs):
//   - Crypto++ (sha3.h, rsa.h, osrng.h, hex.h, base64.h)
//   - Crow (single-header "crow_all.h")
//   - jsoncpp ("json/json.h")
//
// ---------------------------------------------------------------------------------------

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio.hpp>          // kept from your original
#include <crypto++/base64.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>
#include <crypto++/sha3.h>
#include <json/json.h>
#include "crow_all.h"

// ============================== MONEY & CONSTANTS ============================

using Amount = int64_t;                 // fixed-point integer
static constexpr int DECIMALS = 7;      // 7 decimal places
static constexpr Amount UNIT = 10'000'000; // 1 coin = 10,000,000 units

// Convert coin float to fixed-point units (safe rounding)
static inline Amount coins(double c) {
    long double v = static_cast<long double>(c) * static_cast<long double>(UNIT);
    return static_cast<Amount>(llround(v));
}

// Pretty-print Amount
static inline std::string coinString(Amount a) {
    bool neg = (a < 0);
    if (neg) a = -a;
    Amount whole = a / UNIT;
    Amount frac  = a % UNIT;
    std::ostringstream oss;
    if (neg) oss << "-";
    oss << whole << "." << std::setw(DECIMALS) << std::setfill('0') << frac;
    return oss.str();
}

// Economic / policy constants (aligned with your intent)
static const Amount OWNER_VAULT_INITIAL_BALANCE = 1'000'000'000LL * UNIT; // 1B coins
static const Amount USER_VAULT_INITIAL_BALANCE  = 6'000'000'000LL * UNIT; // 6B coins

static const Amount MAX_TRANSACTION_AMOUNT = 5'000'000LL * UNIT; // 5,000,000 coins
static const int    MAX_TRANSACTION_FREQUENCY_24H = 5'000'000;
static const std::string UNKNOWN_ACCOUNT = "UNKNOWN";

// Chain params
static const std::string CHAIN_ID = "EL40-CHAIN-1";
static int   TARGET_BLOCK_SECONDS  = 10;
static int   RETARGET_WINDOW       = 30;
static int   MIN_DIFFICULTY_ZEROS  = 5;

// ============================== TIME HELPERS =================================

static inline std::string isoUtcNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[24];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

static inline std::chrono::system_clock::time_point parseIsoUtc(const std::string& ts) {
    std::tm tm{};
    std::istringstream ss(ts);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (!ss.fail()) {
#if defined(_WIN32)
        time_t tt = _mkgmtime(&tm);
#else
        time_t tt = timegm(&tm);
#endif
        return std::chrono::system_clock::from_time_t(tt);
    }
    if (!ts.empty() && std::all_of(ts.begin(), ts.end(), ::isdigit)) { // epoch seconds
        return std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(ts)));
    }
    return std::chrono::system_clock::now();
}

static inline int64_t toEpochSeconds(const std::string& iso) {
    auto tp = parseIsoUtc(iso);
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

// ============================== CRYPTO HELPERS ================================

static inline std::string HashHex(const std::string& input) {
    using namespace CryptoPP;
    SHA3_256 h;
    byte d[SHA3_256::DIGESTSIZE];
    h.CalculateDigest(d, reinterpret_cast<const byte*>(input.data()), input.size());
    std::string out;
    HexEncoder enc(new CryptoPP::StringSink(out), false); // lowercase
    enc.Put(d, sizeof(d));
    enc.MessageEnd();
    return out;
}

static inline std::string b64encode(const std::string& bin) {
    std::string out;
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(bin.data()), bin.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false)); // no newlines
    return out;
}
static inline std::string b64decode(const std::string& b64) {
    std::string out;
    CryptoPP::StringSource ss(b64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
    return out;
}

// ============================== GLOBAL STATE =================================

std::mutex ledgerMutex, nodeMutex, nonceMutex, pubkeyMutex, mempoolMutex;

std::unordered_map<std::string, Amount> ledger = {
    {"OwnerVault", OWNER_VAULT_INITIAL_BALANCE},
    {"UserVault",  USER_VAULT_INITIAL_BALANCE},
    {"User1",      coins(5000.0)},
    {"User2",      coins(250'000'000.0)},
    {"User3",      coins(2'000'000.0)}
};

std::unordered_map<std::string, std::vector<std::string>> txTimeHistory; // for 24h frequency
std::unordered_map<std::string, uint64_t> lastUsedNonce;

std::unordered_map<std::string, CryptoPP::RSA::PublicKey>  publicKeys;
// (demo only) private keys to sign sample txs so program runs out-of-the-box
std::unordered_map<std::string, CryptoPP::RSA::PrivateKey> privateKeys;

struct Transaction; // fwd
std::vector<Transaction> mempool;      // pending txs (optional)
std::vector<Transaction> txlog;        // original feel: append processed txs

// ============================== TRANSACTIONS =================================

struct Transaction {
    std::string sender;     // "Network" for coinbase
    std::string receiver;
    Amount      amount;     // fixed-point units
    std::string timestamp;  // ISO-8601 UTC
    uint64_t    nonce;      // strictly increasing per sender (except coinbase)
    std::string signature;  // base64 of raw RSA signature

    Transaction() : amount(0), nonce(0) {}
    Transaction(std::string s, std::string r, Amount a, std::string ts, uint64_t n, std::string sig)
        : sender(std::move(s)), receiver(std::move(r)), amount(a),
          timestamp(std::move(ts)), nonce(n), signature(std::move(sig)) {}

    // Canonical preimage to sign (includes CHAIN_ID)
    std::string canonical() const {
        std::ostringstream oss;
        oss << "chain_id=" << CHAIN_ID
            << "&amount=" << amount
            << "&nonce=" << nonce
            << "&receiver=" << receiver
            << "&sender=" << sender
            << "&timestamp=" << timestamp;
        return oss.str();
    }

    // Hash used in Merkle leaves
    std::string leaf() const {
        return HashHex(canonical());
    }
};

static std::string merkleRoot(const std::vector<Transaction>& txs) {
    if (txs.empty()) return HashHex("EMPTY");
    std::vector<std::string> layer;
    layer.reserve(txs.size());
    for (const auto& tx : txs) layer.push_back(tx.leaf());
    while (layer.size() > 1) {
        if (layer.size() % 2 == 1) layer.push_back(layer.back());
        std::vector<std::string> next;
        next.reserve(layer.size()/2);
        for (size_t i = 0; i < layer.size(); i += 2) {
            next.push_back(HashHex(layer[i] + layer[i+1]));
        }
        layer.swap(next);
    }
    return layer.front();
}

// ============================== SIGNATURES ===================================

static bool verifyTxSignature_RSA(const Transaction& tx) {
    if (tx.sender == "Network") return true; // coinbase exempt
    using namespace CryptoPP;

    RSA::PublicKey pub;
    {
        std::lock_guard<std::mutex> lock(pubkeyMutex);
        auto it = publicKeys.find(tx.sender);
        if (it == publicKeys.end()) {
            std::cerr << "[SIG] Missing public key for " << tx.sender << "\n";
            return false;
        }
        pub = it->second;
    }

    RSASSA_PKCS1v15_SHA_Verifier verifier(pub);
    bool ok = false;
    try {
        std::string sig = b64decode(tx.signature);
        StringSource ss(
            sig + tx.canonical(), true,
            new SignatureVerificationFilter(
                verifier,
                new ArraySink(reinterpret_cast<byte*>(&ok), sizeof(ok)),
                SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::PUT_RESULT
            )
        );
    } catch (const Exception& e) {
        std::cerr << "[SIG] Verification exception: " << e.what() << "\n";
        return false;
    }
    return ok;
}

// (demo helper): register/generate keypairs so sample txs can be signed
static void demoEnsureKeypair(const std::string& user) {
    using namespace CryptoPP;
    std::lock_guard<std::mutex> lk(pubkeyMutex);
    if (publicKeys.count(user)) return;
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey priv(params);
    RSA::PublicKey  pub(params);
    publicKeys[user]  = pub;
    {
        std::lock_guard<std::mutex> pk(nonceMutex);
        privateKeys[user] = priv; // demo-only
        if (!lastUsedNonce.count(user)) lastUsedNonce[user] = 0;
    }
}

static std::string demoSign(const std::string& user, const std::string& canonical) {
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    RSASSA_PKCS1v15_SHA_Signer signer(privateKeys[user]);
    std::string sig;
    StringSource ss(canonical, true, new SignerFilter(rng, signer, new StringSink(sig)));
    return b64encode(sig);
}

// ============================== FRAUD / POLICY CHECKS ========================

static bool tooFrequentIn24h(const std::string& sender, const std::string& nowIso) {
    std::lock_guard<std::mutex> lock(ledgerMutex); // ledgerMutex is fine as global guard
    auto& hist = txTimeHistory[sender];
    int recent = 0;
    auto now = parseIsoUtc(nowIso);
    for (const auto& ts : hist) {
        auto past = parseIsoUtc(ts);
        auto hours = std::chrono::duration_cast<std::chrono::hours>(now - past).count();
        if (hours <= 24) recent++;
    }
    return recent > MAX_TRANSACTION_FREQUENCY_24H;
}

static bool validateTxStateless(const Transaction& tx, std::string& why) {
    if (tx.sender != "Network") {
        if (tx.sender == UNKNOWN_ACCOUNT || tx.receiver == UNKNOWN_ACCOUNT) { why="unknown account"; return false; }
        if (tx.amount <= 0) { why="non-positive amount"; return false; }
        if (tx.amount > MAX_TRANSACTION_AMOUNT) { why="amount exceeds maximum"; return false; }
        if (tx.nonce == 0) { why="nonce missing"; return false; }
        // Nonce must be exactly last+1
        {
            std::lock_guard<std::mutex> nlk(nonceMutex);
            uint64_t last = lastUsedNonce[tx.sender];
            if (tx.nonce != last + 1) { std::ostringstream oss; oss<<"bad nonce (expected "<<(last+1)<<")"; why=oss.str(); return false; }
        }
        if (!verifyTxSignature_RSA(tx)) { why="bad signature"; return false; }
        if (tooFrequentIn24h(tx.sender, tx.timestamp)) { why="24h freq exceeded"; return false; }
        // sufficient balance
        {
            std::lock_guard<std::mutex> llk(ledgerMutex);
            Amount bal = ledger.count(tx.sender) ? ledger[tx.sender] : 0;
            if (bal < tx.amount) { why="insufficient funds"; return false; }
        }
    } else {
        if (tx.amount <= 0) { why="coinbase non-positive"; return false; }
        if (tx.nonce != 0) { why="coinbase must have nonce=0"; return false; }
    }
    return true;
}

// ============================== BLOCK & CHAIN ================================

struct Block {
    int index{};
    std::string timestamp;        // ISO-8601 UTC (for retarget)
    std::string prevHash;
    std::string merkle;
    int difficulty{MIN_DIFFICULTY_ZEROS};
    int nonce{0};
    std::vector<Transaction> transactions;
    std::string hash;

    Block() = default;
    Block(int idx, std::string ts, std::string prev, int diff, std::vector<Transaction> txs)
        : index(idx), timestamp(std::move(ts)), prevHash(std::move(prev)),
          difficulty(diff), transactions(std::move(txs)) {
        merkle = merkleRoot(transactions);
        hash = headerHash();
    }

    std::string headerPreimage() const {
        std::ostringstream oss;
        oss << index << "|" << timestamp << "|" << prevHash
            << "|" << merkle << "|" << difficulty << "|" << nonce;
        return oss.str();
    }
    std::string headerHash() const { return HashHex(headerPreimage()); }

    void mine() {
        const std::string target(difficulty, '0');
        while (true) {
            hash = headerHash();
            if (hash.compare(0, difficulty, target) == 0) break;
            ++nonce;
        }
    }
};

class EL40_Blockchain {
private:
    std::vector<Block> chain;
    mutable std::mutex chainMutex;

    int retargetDifficultyLocked() {
        int current = chain.back().difficulty;
        if ((int)chain.size() <= RETARGET_WINDOW + 1) {
            return std::max(MIN_DIFFICULTY_ZEROS, current);
        }
        size_t i = chain.size() - RETARGET_WINDOW;
        int64_t first = toEpochSeconds(chain[i - 1].timestamp);
        int64_t last  = toEpochSeconds(chain.back().timestamp);
        int64_t span  = std::max<int64_t>(1, last - first);
        int64_t ideal = (int64_t)RETARGET_WINDOW * TARGET_BLOCK_SECONDS;

        if (span < ideal / 2) return current + 1;
        if (span > ideal * 2 && current > MIN_DIFFICULTY_ZEROS) return current - 1;
        return current;
    }

    bool validateBlockLocked(const Block& b, const Block& prev, std::string& why) const {
        if (b.index != prev.index + 1) { why="index mismatch"; return false; }
        if (b.prevHash != prev.hash)   { why="prev hash mismatch"; return false; }
        if (b.merkle != merkleRoot(b.transactions)) { why="bad merkle"; return false; }
        const std::string target(b.difficulty, '0');
        if (b.hash.compare(0, b.difficulty, target) != 0) { why="insufficient PoW"; return false; }
        if (b.headerHash() != b.hash) { why="header hash mismatch"; return false; }
        // Stateless tx checks (nonce/sig/amount/etc.)
        for (const auto& tx : b.transactions) {
            std::string r;
            if (!validateTxStateless(tx, r)) { why = "tx invalid: " + r; return false; }
        }
        return true;
    }

    void applyTx(const Transaction& tx) {
        std::lock_guard<std::mutex> llk(ledgerMutex);
        if (!ledger.count(tx.receiver)) ledger[tx.receiver] = 0;
        if (tx.sender != "Network" && !ledger.count(tx.sender)) ledger[tx.sender] = 0;

        if (tx.sender == "Network") {
            // MINT: reward — your exact requirement
            ledger[tx.receiver] += tx.amount;
        } else {
            ledger[tx.sender]  -= tx.amount;
            ledger[tx.receiver] += tx.amount;
            {
                std::lock_guard<std::mutex> nlk(nonceMutex);
                lastUsedNonce[tx.sender] = std::max(lastUsedNonce[tx.sender], tx.nonce);
            }
            txTimeHistory[tx.sender].push_back(tx.timestamp);
        }
        txlog.push_back(tx); // keep your “original log” flavor
    }

public:
    EL40_Blockchain() {
        Block genesis(0, isoUtcNow(), "0", MIN_DIFFICULTY_ZEROS, {});
        genesis.mine();
        std::lock_guard<std::mutex> lock(chainMutex);
        chain.push_back(std::move(genesis));
        // preserve your original spirit: seed a small Genesis balance
        std::lock_guard<std::mutex> l(ledgerMutex);
        ledger["Genesis"] += coins(1000.0);
    }

    int height() const { std::lock_guard<std::mutex> lock(chainMutex); return (int)chain.size() - 1; }
    int totalBlocks() const { std::lock_guard<std::mutex> lock(chainMutex); return (int)chain.size(); }
    std::string tipHash() const { std::lock_guard<std::mutex> lock(chainMutex); return chain.back().hash; }
    int currentDifficulty() const { std::lock_guard<std::mutex> lock(chainMutex); return chain.back().difficulty; }

    // Mine-and-append (pulls from mempool)
    bool mineAndAppend(const std::string& miner, size_t maxTx=100) {
        // gather txs
        std::vector<Transaction> txs;
        {
            std::lock_guard<std::mutex> mlk(mempoolMutex);
            size_t n = std::min(maxTx, mempool.size());
            txs.insert(txs.end(), mempool.begin(), mempool.begin()+n);
            mempool.erase(mempool.begin(), mempool.begin()+n);
        }

        // coinbase (nonce=0, no sig)
        const Amount BLOCK_REWARD = 25 * UNIT;
        txs.emplace_back("Network", miner, BLOCK_REWARD, isoUtcNow(), 0, "");

        // lock chain tip, retarget
        Block prev;
        int diff;
        {
            std::lock_guard<std::mutex> lock(chainMutex);
            prev = chain.back();
            diff = retargetDifficultyLocked();
            diff = std::max(diff, MIN_DIFFICULTY_ZEROS);
        }

        Block b(prev.index+1, isoUtcNow(), prev.hash, diff, txs);
        b.mine();

        // validate & commit
        {
            std::string why;
            std::lock_guard<std::mutex> lock(chainMutex);
            if (!validateBlockLocked(b, chain.back(), why)) {
                std::cerr << "[BLOCK] Rejected: " << why << "\n";
                // return txs to mempool (non-coinbase)
                std::lock_guard<std::mutex> mlk(mempoolMutex);
                for (const auto& t : txs) if (t.sender != "Network") mempool.push_back(t);
                return false;
            }
            chain.push_back(b);
        }
        for (const auto& t : txs) applyTx(t);

        std::cout << "[+] Block " << b.index << " mined (diff=" << b.difficulty
                  << ") hash=" << b.hash.substr(0,16) << "... txs=" << b.transactions.size() << "\n";
        return true;
    }

    // For the dashboard
    std::vector<Block> snapshot(int maxBlocks=50) const {
        std::lock_guard<std::mutex> lock(chainMutex);
        int n = (int)chain.size();
        int start = std::max(0, n - maxBlocks);
        return std::vector<Block>(chain.begin()+start, chain.end());
    }
};

// ============================== NODE OPS (as before) =========================

struct Node { std::string name; int load=0; int reputation=100; };
std::unordered_map<std::string, Node> nodes = { {"Node1",{"Node1",0,100}}, {"Node2",{"Node2",0,100}} };

static bool nodeAccessAgreement() {
    std::string response;
    std::cout << "Do you accept the node connection agreement? (yes/no): ";
    std::cin >> response;
    if (response == "yes" || response == "Yes") { std::cout << "Access granted. Connecting node...\n"; return true; }
    std::cout << "Access denied. Exiting application.\n"; return false;
}
static void distributeLoad(const std::string& task) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    Node* best = nullptr;
    for (auto& [_, n] : nodes) if (!best || n.load < best->load) best = &n;
    if (best) { best->load++; std::cout << "[INFO] Task '"<<task<<"' -> "<<best->name<<" (load "<<best->load<<")\n"; }
    else { std::cerr << "[ERROR] No available nodes.\n"; }
}
static void updateNodeReputation(const std::string& name, int change) {
    std::lock_guard<std::mutex> lock(nodeMutex);
    if (nodes.count(name)) { nodes[name].reputation += change; std::cout << "[INFO] Reputation "<<name<<" -> "<<nodes[name].reputation<<"\n"; }
    else { std::cerr << "[ERROR] Node not found: " << name << "\n"; }
}

// ============================== TX SUBMIT ====================================

static bool submitTransaction(const Transaction& tx, std::string& reason) {
    if (!validateTxStateless(tx, reason)) return false;
    std::lock_guard<std::mutex> mlk(mempoolMutex);
    mempool.push_back(tx);
    return true;
}

// ============================== EXTERNAL TX IMPORT ===========================

static void fetchExternalTransactions(const std::string& path="external_transactions.json") {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "[ERROR] Failed to open external transaction file.\n";
        return;
    }
    Json::Value arr; in >> arr;
    for (const auto& j : arr) {
        std::string sender = j["sender"].asString();
        std::string receiver = j["receiver"].asString();
        Amount      amount  = coins(j["amount"].asDouble()); // interpret as coins
        std::string ts      = j["timestamp"].asString();
        uint64_t    nonce   = j.get("nonce", 0).asUInt64();
        std::string sig     = j.get("signature","").asString();
        Transaction t(sender, receiver, amount, ts, nonce, sig);
        std::string why;
        if (!submitTransaction(t, why)) std::cerr << "[EXT] Rejected tx: " << why << "\n";
    }
}

// ============================== WEB DASHBOARD (Crow) =========================

static EL40_Blockchain* gChain = nullptr;

static void startWebDashboard() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/stats")([] {
        Json::Value s;
        s["height"]     = gChain ? gChain->height() : 0;
        s["difficulty"] = gChain ? gChain->currentDifficulty() : MIN_DIFFICULTY_ZEROS;
        s["tip_hash"]   = gChain ? gChain->tipHash() : "";
        {
            std::lock_guard<std::mutex> l(ledgerMutex);
            s["total_users"] = (int)ledger.size();
        }
        {
            std::lock_guard<std::mutex> l(mempoolMutex);
            s["mempool_size"] = (int)mempool.size();
        }
        Json::StreamWriterBuilder w;
        return crow::response(Json::writeString(w, s));
    });

    CROW_ROUTE(app, "/ledger")([] {
        Json::Value out(Json::objectValue);
        std::lock_guard<std::mutex> l(ledgerMutex);
        for (const auto& [acct, bal] : ledger) out[acct] = coinString(bal);
        Json::StreamWriterBuilder w;
        return crow::response(Json::writeString(w, out));
    });

    CROW_ROUTE(app, "/mempool")([] {
        Json::Value arr(Json::arrayValue);
        std::lock_guard<std::mutex> l(mempoolMutex);
        for (const auto& t : mempool) {
            Json::Value jt;
            jt["sender"]    = t.sender;
            jt["receiver"]  = t.receiver;
            jt["amount"]    = coinString(t.amount);
            jt["timestamp"] = t.timestamp;
            jt["nonce"]     = Json::UInt64(t.nonce);
            arr.append(jt);
        }
        Json::StreamWriterBuilder w;
        return crow::response(Json::writeString(w, arr));
    });

    std::cout << "[INFO] Dashboard on http://localhost:8080\n";
    app.port(8080).multithreaded().run();
}

// ============================== DEMO (Signed Sample TXs) =====================

static void simulateMobileApp() {
    // Prepare demo keys
    demoEnsureKeypair("User1");
    demoEnsureKeypair("User3");
    // Nonce baseline
    {
        std::lock_guard<std::mutex> nlk(nonceMutex);
        if (!lastUsedNonce.count("User1")) lastUsedNonce["User1"] = 0;
        if (!lastUsedNonce.count("User3")) lastUsedNonce["User3"] = 0;
    }

    auto nextNonce = [](const std::string& s) {
        std::lock_guard<std::mutex> nlk(nonceMutex);
        return lastUsedNonce[s] + 1;
    };

    // Build signed txs
    std::vector<Transaction> txs;
    {
        Transaction t("User1","User2", coins(50'000.0), "2025-04-20T10:00:00Z", nextNonce("User1"), "");
        t.signature = demoSign("User1", t.canonical());
        txs.push_back(t);
    }
    {
        Transaction t("User1","User3", coins(250'000'000.0), "2025-04-20T10:05:00Z", nextNonce("User1"), "");
        t.signature = demoSign("User1", t.canonical());
        txs.push_back(t);
    }
    {
        // This one will fail (UNKNOWN), kept to mirror your original flow
        Transaction t("UNKNOWN","User2", coins(1000.0), "2025-04-20T10:10:00Z", 1, "");
        txs.push_back(t);
    }
    {
        Transaction t("User3","User2", coins(20'000'000.0), "2025-04-20T10:15:00Z", nextNonce("User3"), "");
        t.signature = demoSign("User3", t.canonical());
        txs.push_back(t);
    }

    // Submit to mempool
    for (auto& tx : txs) {
        std::string why;
        if (!submitTransaction(tx, why)) std::cerr << "[MOBILE] tx rejected: " << why << "\n";
    }
    std::cout << "[MOBILE] Queued " << txs.size() << " tx(s). Mempool now ";
    {
        std::lock_guard<std::mutex> mlk(mempoolMutex);
        std::cout << mempool.size() << "\n";
    }
}

// ============================== LICENSE / EXIT ===============================

static void displayExitPopup() {
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

// ============================== MAIN =========================================

int main() {
    std::cout << "Welcome to the EL-40 / Contractor Coin Program.\n";
    std::cout << "\n\n=== MIT LICENSE AGREEMENT ===\n";
    std::cout << "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
              << "of this software and associated documentation files (the \"Software\"), to deal\n"
              << "in the Software without restriction...\n";
    std::cout << "Type 'agree' to proceed: ";
    std::string input; std::cin >> input;
    if (input != "agree") { std::cout << "License not accepted. Program will terminate.\n"; return 0; }
    if (!nodeAccessAgreement()) return 0;

    // Instantiate chain and dashboard
    EL40_Blockchain chain;
    gChain = &chain;
    std::thread dashboardThread(startWebDashboard);
    dashboardThread.detach();

    // Node orchestration
    distributeLoad("Sync Task 1");
    distributeLoad("Sync Task 2");
    updateNodeReputation("Node1", -5);

    // External + demo txs
    fetchExternalTransactions(); // optional file
    simulateMobileApp();

    // Mine a couple of blocks
    chain.mineAndAppend("MinerNode", 50);
    chain.mineAndAppend("MinerNode", 50);

    {
        std::lock_guard<std::mutex> l(ledgerMutex);
        std::cout << "[INFO] Balance User1: " << coinString(ledger["User1"]) << " ELX\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(5));
    displayExitPopup();
    std::cout << "Exiting program...\n";
    return 0;
}
