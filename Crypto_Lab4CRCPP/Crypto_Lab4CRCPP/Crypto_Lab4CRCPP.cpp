#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <map>
#include <iomanip>
#include <sha.h>
#include <hex.h>

class SHA256 {
public:
    static std::string hash(const std::string& input) {
        CryptoPP::SHA256 hash;
        std::string digest;

        CryptoPP::StringSource s(input, true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest), false
                )
            )
        );
        return digest;
    }
};

class Transaction {
public:
    std::string fromAddress;
    std::string toAddress;
    int amount;

    Transaction(std::string from, std::string to, int amt):
        fromAddress(from), 
        toAddress(to), 
        amount(amt) 
    {}

    std::string getHash() const {
        std::stringstream ss;
        ss << fromAddress << toAddress << amount;
        return SHA256::hash(ss.str());
    }
};

class Block {
public:
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string merkleRoot;
    std::string hash;
    int nonce;

    Block(std::string prevHash) : previousHash(prevHash), nonce(0) {}

    void addTransaction(const Transaction& tx) {
        transactions.push_back(tx);
    }

    std::string calculateHash() const {
        std::stringstream ss;
        ss << previousHash << merkleRoot << nonce;
        return SHA256::hash(ss.str());
    }

    void mineBlock(int difficulty) {
        merkleRoot = calculateMerkleRoot();
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculateHash();
        }
    }

    std::string calculateMerkleRoot() const {
        if (transactions.empty()) return "";

        std::vector<std::string> hashes;
        for (const auto& tx : transactions) {
            hashes.push_back(tx.getHash());
        }

        while (hashes.size() > 1) {
            if (hashes.size() % 2 != 0) {
                hashes.push_back(hashes.back());
            }

            std::vector<std::string> newHashes;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                newHashes.push_back(SHA256::hash(hashes[i] + hashes[i + 1]));
            }
            hashes = newHashes;
        }

        return hashes[0];
    }
};

class Blockchain {
public:
    Blockchain(int difficulty) : difficulty(difficulty) {
        chain.emplace_back(createGenesisBlock());
    }

    void addBlock(Block newBlock) {
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
    }

    bool isChainValid() const {
        for (size_t i = 1; i < chain.size(); ++i) {
            const Block& currentBlock = chain[i];
            const Block& previousBlock = chain[i - 1];

            if (currentBlock.hash != currentBlock.calculateHash()) {
                return false;
            }

            if (currentBlock.previousHash != previousBlock.hash) {
                return false;
            }

            if (currentBlock.merkleRoot != currentBlock.calculateMerkleRoot()) {
                return false;
            }
        }
        return true;
    }

    void saveToFile(const std::string& filename) const {
        std::ofstream file(filename, std::ios::binary);
        for (const auto& block : chain) {
            file << block.hash << "\n";
            file << block.previousHash << "\n";
            file << block.merkleRoot << "\n";
            file << block.nonce << "\n";
            file << block.transactions.size() << "\n";
            for (const auto& tx : block.transactions) {
                file << tx.fromAddress << " " << tx.toAddress << " " << tx.amount << "\n";
            }
        }
        file.close();
    }

    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        std::string line;
        while (std::getline(file, line)) {
            std::string hash = line;
            std::getline(file, line);
            std::string previousHash = line;
            std::getline(file, line);
            std::string merkleRoot = line;
            std::getline(file, line);
            int nonce = std::stoi(line);
            std::getline(file, line);
            int numTransactions = std::stoi(line);

            Block block(previousHash);
            block.hash = hash;
            block.merkleRoot = merkleRoot;
            block.nonce = nonce;

            for (int i = 0; i < numTransactions; ++i) {
                std::getline(file, line);
                std::istringstream iss(line);
                std::string fromAddress, toAddress;
                int amount;
                iss >> fromAddress >> toAddress >> amount;
                block.addTransaction(Transaction(fromAddress, toAddress, amount));
            }

            chain.push_back(block);
        }
        file.close();
    }

    void printBalances() const {
        std::map<std::string, int> balances;
        for (const auto& block : chain) {
            for (const auto& tx : block.transactions) {
                if (tx.fromAddress != "system") {
                    balances[tx.fromAddress] -= tx.amount;
                }
                balances[tx.toAddress] += tx.amount;
            }
        }

        for (const auto& [address, balance] : balances) {
            std::cout << address << ": " << balance << "\n";
        }
    }

    std::string getLastBlockHash() const {
        return chain.back().hash;
    }

private:
    int difficulty;
    std::vector<Block> chain;

    Block createGenesisBlock() {
        Block genesisBlock("0");
        genesisBlock.mineBlock(difficulty);
        return genesisBlock;
    }
};

int main() {
    Blockchain blockchain(4);

    Block block1 = Block(blockchain.getLastBlockHash());
    block1.addTransaction(Transaction("system", "Alice", 50));
    block1.addTransaction(Transaction("Alice", "Bob", 10));
    blockchain.addBlock(block1);

    Block block2 = Block(blockchain.getLastBlockHash());
    block2.addTransaction(Transaction("system", "Bob", 100));
    block2.addTransaction(Transaction("Bob", "Alice", 20));
    blockchain.addBlock(block2);

    blockchain.saveToFile("blockchain.dat");

    Blockchain newBlockchain(4);
    newBlockchain.loadFromFile("blockchain.dat");

    if (newBlockchain.isChainValid()) {
        std::cout << "Blockchain is valid." << std::endl;
        newBlockchain.printBalances();
    }
    else {
        std::cout << "Blockchain is invalid." << std::endl;
    }

    return 0;
}
