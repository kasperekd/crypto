// blind_voting.cpp
#include "blind_voting.h"
#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

// Реализация VotingBallot
std::string VotingBallot::toString() const {
    std::string voteStr;
    switch (vote) {
        case VoteOption::YES: voteStr = "YES"; break;
        case VoteOption::NO: voteStr = "NO"; break;
        case VoteOption::ABSTAIN: voteStr = "ABSTAIN"; break;
    }
    
    std::ostringstream oss;
    oss << "Ballot ID: " << ballotId << "\n"
        << "Vote: " << voteStr << "\n"
        << "Blinded Message: " << blindedMessage << "\n"
        << "Blinding Factor: " << blindingFactor << "\n"
        << "Signature: " << signature;
    
    return oss.str();
}

// Реализация RSABlindSignature::KeyPair
void RSABlindSignature::KeyPair::generateKeys(int keySize) {
    BigInt p, q;
    do {
        p = generatePrime(keySize / 2);
        q = generatePrime(keySize / 2);
    } while (p == q);
    
    n = p * q;
    BigInt phi = (p - 1) * (q - 1);
    
    // Выбираем стандартное значение e
    e = 65537;
    while (gcd(e, phi) != 1) {
        e += 2;
    }
    
    d = modInverse(e, phi);
    
    std::cout << "=== RSA Key Pair Generated ===" << std::endl;
    std::cout << "Key size: " << keySize << " bits" << std::endl;
    std::cout << "n (modulus): " << n << std::endl;
    std::cout << "e (public exponent): " << e << std::endl;
    std::cout << "d (private exponent): " << d << std::endl;
    std::cout << "=============================" << std::endl;
}

BigInt RSABlindSignature::KeyPair::generatePrime(int bits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    BigInt candidate;
    do {
        candidate = 0;
        for (int i = 0; i < bits; ++i) {
            if (gen() % 2) {
                candidate |= (BigInt(1) << i);
            }
        }
        candidate |= (BigInt(1) << (bits - 1));
        candidate |= 1;
    } while (!boost::multiprecision::miller_rabin_test(candidate, 25));
    
    return candidate;
}

BigInt RSABlindSignature::KeyPair::gcd(BigInt a, BigInt b) {
    while (b != 0) {
        BigInt temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

BigInt RSABlindSignature::KeyPair::modInverse(BigInt a, BigInt m) {
    BigInt m0 = m, x0 = 0, x1 = 1;
    
    if (m == 1) return 0;
    
    while (a > 1) {
        BigInt q = a / m;
        BigInt t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1 < 0) x1 += m0;
    return x1;
}

// Реализация RSABlindSignature
BigInt RSABlindSignature::blindMessage(const BigInt& message, const BigInt& r, const KeyPair& pubKey) {
    // m' = m * r^e mod n
    BigInt re = boost::multiprecision::powm(r, pubKey.e, pubKey.n);
    BigInt blindedMessage = (message * re) % pubKey.n;
    
    std::cout << "\n=== Blinding Operation ===" << std::endl;
    std::cout << "Original message: " << message << std::endl;
    std::cout << "Blinding factor r: " << r << std::endl;
    std::cout << "r^e mod n: " << re << std::endl;
    std::cout << "Blinded message m': " << blindedMessage << std::endl;
    std::cout << "=========================" << std::endl;
    
    return blindedMessage;
}

BigInt RSABlindSignature::blindSign(const BigInt& blindedMessage, const KeyPair& privKey) {
    // s' = (m')^d mod n
    BigInt blindSignature = boost::multiprecision::powm(blindedMessage, privKey.d, privKey.n);
    
    std::cout << "\n=== Blind Signing Operation ===" << std::endl;
    std::cout << "Blinded message: " << blindedMessage << std::endl;
    std::cout << "Blind signature s': " << blindSignature << std::endl;
    std::cout << "===============================" << std::endl;
    
    return blindSignature;
}

BigInt RSABlindSignature::unblindSignature(const BigInt& blindSignature, const BigInt& r, const KeyPair& pubKey) {
    // s = s' * r^(-1) mod n
    BigInt rInv = modInverse(r, pubKey.n);
    BigInt signature = (blindSignature * rInv) % pubKey.n;
    
    std::cout << "\n=== Unblinding Operation ===" << std::endl;
    std::cout << "Blind signature s': " << blindSignature << std::endl;
    std::cout << "Blinding factor r: " << r << std::endl;
    std::cout << "r^(-1) mod n: " << rInv << std::endl;
    std::cout << "Final signature s: " << signature << std::endl;
    std::cout << "============================" << std::endl;
    
    return signature;
}

bool RSABlindSignature::verifySignature(const BigInt& message, const BigInt& signature, const KeyPair& pubKey) {
    // Проверка: s^e ≡ m (mod n)
    BigInt verified = boost::multiprecision::powm(signature, pubKey.e, pubKey.n);
    bool isValid = (verified == message);
    
    std::cout << "\n=== Signature Verification ===" << std::endl;
    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "s^e mod n: " << verified << std::endl;
    std::cout << "Valid: " << (isValid ? "YES" : "NO") << std::endl;
    std::cout << "==============================" << std::endl;
    
    return isValid;
}

BigInt RSABlindSignature::generateBlindingFactor(const KeyPair& pubKey) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    BigInt r;
    do {
        r = 0;
        // Генерируем случайное число размером чуть меньше n
        int bits = boost::multiprecision::msb(pubKey.n) - 10;
        for (int i = 0; i < bits; ++i) {
            if (gen() % 2) {
                r |= (BigInt(1) << i);
            }
        }
        r |= 1; // Делаем нечетным для увеличения вероятности взаимной простоты
    } while (boost::multiprecision::gcd(r, pubKey.n) != 1 || r >= pubKey.n);
    
    return r;
}

BigInt RSABlindSignature::hashMessage(const std::string& message) {
    // Простейшая хеш-функция для демонстрации
    // В реальной системе следует использовать SHA-256
    std::hash<std::string> hasher;
    size_t hash = hasher(message);
    return BigInt(hash);
}

BigInt RSABlindSignature::modInverse(BigInt a, BigInt m) {
    BigInt m0 = m, x0 = 0, x1 = 1;
    
    if (m == 1) return 0;
    
    while (a > 1) {
        BigInt q = a / m;
        BigInt t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1 < 0) x1 += m0;
    return x1;
}

// Реализация VotingClient
VotingClient::VotingClient(const std::string& clientId) : clientId_(clientId) {
    std::cout << "Voting client '" << clientId_ << "' initialized" << std::endl;
}

VotingBallot VotingClient::createBallot(VoteOption vote, const std::string& question) {
    VotingBallot ballot;
    ballot.ballotId = generateBallotId();
    ballot.vote = vote;
    
    // Создаем сообщение для подписи
    std::string voteString;
    switch (vote) {
        case VoteOption::YES: voteString = "YES"; break;
        case VoteOption::NO: voteString = "NO"; break;
        case VoteOption::ABSTAIN: voteString = "ABSTAIN"; break;
    }
    
    std::string fullMessage = ballot.ballotId + ":" + question + ":" + voteString;
    // В реальной системе здесь должно быть хеширование
    ballot.blindedMessage = RSABlindSignature::hashMessage(fullMessage);
    
    ballots_[ballot.ballotId] = ballot;
    
    std::cout << "\n=== Ballot Created ===" << std::endl;
    std::cout << "Client: " << clientId_ << std::endl;
    std::cout << "Ballot ID: " << ballot.ballotId << std::endl;
    std::cout << "Vote: " << voteString << std::endl;
    std::cout << "Message hash: " << ballot.blindedMessage << std::endl;
    std::cout << "======================" << std::endl;
    
    return ballot;
}

BigInt VotingClient::blindBallot(VotingBallot& ballot, const RSABlindSignature::KeyPair& serverPubKey) {
    // Генерируем фактор ослепления
    ballot.blindingFactor = RSABlindSignature::generateBlindingFactor(serverPubKey);
    
    // Ослепляем сообщение
    BigInt blindedMsg = RSABlindSignature::blindMessage(ballot.blindedMessage, 
                                                       ballot.blindingFactor, 
                                                       serverPubKey);
    
    ballot.blindedMessage = blindedMsg;
    ballots_[ballot.ballotId] = ballot;
    
    return blindedMsg;
}

bool VotingClient::unblindSignature(VotingBallot& ballot, const BigInt& blindSignature, 
                                   const RSABlindSignature::KeyPair& serverPubKey) {
    
    // Получаем исходное сообщение
    std::string voteString;
    switch (ballot.vote) {
        case VoteOption::YES: voteString = "YES"; break;
        case VoteOption::NO: voteString = "NO"; break;
        case VoteOption::ABSTAIN: voteString = "ABSTAIN"; break;
    }
    
    std::string fullMessage = ballot.ballotId + ":question:" + voteString;
    BigInt originalMessage = RSABlindSignature::hashMessage(fullMessage);
    
    // Разослепляем подпись
    ballot.signature = RSABlindSignature::unblindSignature(blindSignature, 
                                                          ballot.blindingFactor, 
                                                          serverPubKey);
    
    // Проверяем корректность
    bool valid = RSABlindSignature::verifySignature(originalMessage, ballot.signature, serverPubKey);
    
    if (valid) {
        ballot.blindedMessage = originalMessage; // Сохраняем оригинальное сообщение
        ballots_[ballot.ballotId] = ballot;
    }
    
    return valid;
}

bool VotingClient::verifyBallotSignature(const VotingBallot& ballot, 
                                        const RSABlindSignature::KeyPair& serverPubKey) {
    return RSABlindSignature::verifySignature(ballot.blindedMessage, ballot.signature, serverPubKey);
}

std::string VotingClient::generateBallotId() {
    static int counter = 0;
    std::ostringstream oss;
    oss << clientId_ << "_ballot_" << std::setfill('0') << std::setw(6) << ++counter;
    return oss.str();
}

// Реализация VotingServer
VotingServer::VotingServer(const std::string& question) : question_(question) {
    std::cout << "Voting server initialized for question: '" << question_ << "'" << std::endl;
}

void VotingServer::initialize() {
    keyPair_.generateKeys();
    results_[VoteOption::YES] = 0;
    results_[VoteOption::NO] = 0;
    results_[VoteOption::ABSTAIN] = 0;
    
    std::cout << "Voting server ready to accept registrations and votes" << std::endl;
}

bool VotingServer::registerVoter(const std::string& voterId) {
    if (isVoterRegistered(voterId)) {
        std::cout << "Voter '" << voterId << "' already registered" << std::endl;
        return false;
    }
    
    registeredVoters_.push_back(voterId);
    std::cout << "Voter '" << voterId << "' registered successfully" << std::endl;
    return true;
}

BigInt VotingServer::processBlindBallot(const std::string& voterId, const BigInt& blindedMessage) {
    std::cout << "\n=== Processing Blind Ballot ===" << std::endl;
    std::cout << "Voter ID: " << voterId << std::endl;
    
    // Проверяем право голоса
    if (!isVoterRegistered(voterId)) {
        std::cout << "ERROR: Voter not registered!" << std::endl;
        return 0;
    }
    
    if (hasVoterVoted(voterId)) {
        std::cout << "ERROR: Voter has already voted!" << std::endl;
        return 0;
    }
    
    // Отмечаем, что избиратель проголосовал (для предотвращения повторного голосования)
    markVoterAsVoted(voterId);
    
    // Выполняем слепую подпись
    BigInt blindSignature = RSABlindSignature::blindSign(blindedMessage, keyPair_);
    
    std::cout << "Blind signature issued for voter: " << voterId << std::endl;
    std::cout << "===============================" << std::endl;
    
    return blindSignature;
}

bool VotingServer::submitBallot(const VotingBallot& ballot) {
    std::cout << "\n=== Ballot Submission ===" << std::endl;
    std::cout << "Ballot ID: " << ballot.ballotId << std::endl;
    
    // Проверяем корректность бюллетеня
    if (!validateBallot(ballot)) {
        std::cout << "ERROR: Invalid ballot!" << std::endl;
        return false;
    }
    
    // Проверяем подпись
    if (!RSABlindSignature::verifySignature(ballot.blindedMessage, ballot.signature, keyPair_)) {
        std::cout << "ERROR: Invalid signature!" << std::endl;
        return false;
    }
    
    // Проверяем, не был ли этот бюллетень уже подан
    for (const auto& existingBallot : submittedBallots_) {
        if (existingBallot.ballotId == ballot.ballotId || 
            existingBallot.signature == ballot.signature) {
            std::cout << "ERROR: Duplicate ballot!" << std::endl;
            return false;
        }
    }
    
    // Принимаем бюллетень
    submittedBallots_.push_back(ballot);
    results_[ballot.vote]++;
    
    std::cout << "Ballot accepted and counted" << std::endl;
    std::cout << "=========================" << std::endl;
    
    return true;
}

void VotingServer::tallyVotes() {
    std::cout << "\n=== Vote Tallying ===" << std::endl;
    std::cout << "Total ballots processed: " << submittedBallots_.size() << std::endl;
    
    // Пересчитываем голоса для проверки
    std::map<VoteOption, int> recount;
    recount[VoteOption::YES] = 0;
    recount[VoteOption::NO] = 0;
    recount[VoteOption::ABSTAIN] = 0;
    
    for (const auto& ballot : submittedBallots_) {
        recount[ballot.vote]++;
    }
    
    results_ = recount;
    std::cout << "Vote tally completed" << std::endl;
    std::cout << "====================" << std::endl;
}

void VotingServer::displayResults() {
    std::cout << "\n=== VOTING RESULTS ===" << std::endl;
    std::cout << "Question: " << question_ << std::endl;
    std::cout << "Total votes cast: " << submittedBallots_.size() << std::endl;
    std::cout << std::endl;
    
    std::cout << "YES:     " << std::setw(6) << results_[VoteOption::YES] << " votes" << std::endl;
    std::cout << "NO:      " << std::setw(6) << results_[VoteOption::NO] << " votes" << std::endl;
    std::cout << "ABSTAIN: " << std::setw(6) << results_[VoteOption::ABSTAIN] << " votes" << std::endl;
    
    int totalVotes = results_[VoteOption::YES] + results_[VoteOption::NO] + results_[VoteOption::ABSTAIN];
    if (totalVotes > 0) {
        std::cout << std::endl;
        std::cout << "Percentages:" << std::endl;
        std::cout << "YES:     " << std::fixed << std::setprecision(1) 
                  << (100.0 * results_[VoteOption::YES] / totalVotes) << "%" << std::endl;
        std::cout << "NO:      " << std::fixed << std::setprecision(1) 
                  << (100.0 * results_[VoteOption::NO] / totalVotes) << "%" << std::endl;
        std::cout << "ABSTAIN: " << std::fixed << std::setprecision(1) 
                  << (100.0 * results_[VoteOption::ABSTAIN] / totalVotes) << "%" << std::endl;
    }
    
    std::cout << "======================" << std::endl;
}

void VotingServer::displayAllNumbers() {
    std::cout << "\n=== ALL CRYPTOGRAPHIC NUMBERS ===" << std::endl;
    std::cout << "Server Public Key:" << std::endl;
    std::cout << "n = " << keyPair_.n << std::endl;
    std::cout << "e = " << keyPair_.e << std::endl;
    std::cout << std::endl;
    
    std::cout << "Server Private Key:" << std::endl;
    std::cout << "d = " << keyPair_.d << std::endl;
    std::cout << std::endl;
    
    std::cout << "Processed Ballots:" << std::endl;
    for (size_t i = 0; i < submittedBallots_.size(); ++i) {
        const auto& ballot = submittedBallots_[i];
        std::cout << "Ballot " << (i + 1) << ":" << std::endl;
        std::cout << "  ID: " << ballot.ballotId << std::endl;
        std::cout << "  Message: " << ballot.blindedMessage << std::endl;
        std::cout << "  Signature: " << ballot.signature << std::endl;
        std::cout << std::endl;
    }
    std::cout << "=================================" << std::endl;
}

// Вспомогательные методы VotingServer
bool VotingServer::isVoterRegistered(const std::string& voterId) {
    return std::find(registeredVoters_.begin(), registeredVoters_.end(), voterId) != registeredVoters_.end();
}

bool VotingServer::hasVoterVoted(const std::string& voterId) {
    return std::find(votedVoters_.begin(), votedVoters_.end(), voterId) != votedVoters_.end();
}

void VotingServer::markVoterAsVoted(const std::string& voterId) {
    votedVoters_.push_back(voterId);
}

bool VotingServer::validateBallot(const VotingBallot& ballot) {
    // Проверяем базовую корректность
    return !ballot.ballotId.empty() && 
           ballot.blindedMessage != 0 && 
           ballot.signature != 0;
}

// Реализация VotingSystem
VotingSystem::VotingSystem(const std::string& question) : question_(question) {
    server_ = std::make_unique<VotingServer>(question);
}

void VotingSystem::initializeSystem() {
    std::cout << "\n======================================" << std::endl;
    std::cout << "INITIALIZING ANONYMOUS VOTING SYSTEM" << std::endl;
    std::cout << "======================================" << std::endl;
    
    server_->initialize();
}

void VotingSystem::addClient(const std::string& clientId) {
    auto client = std::make_unique<VotingClient>(clientId);
    clients_.push_back(std::move(client));
    
    // Регистрируем клиента на сервере
    server_->registerVoter(clientId);
}

void VotingSystem::simulateVoting() {
    std::cout << "\n==================================" << std::endl;
    std::cout << "STARTING VOTING SIMULATION" << std::endl;
    std::cout << "==================================" << std::endl;
    
    for (auto& client : clients_) {
        std::cout << "\n--- Processing vote from " << client->getClientId() << " ---" << std::endl;
        
        // 1. Клиент создает бюллетень
        VoteOption vote = getRandomVote();
        VotingBallot ballot = client->createBallot(vote, question_);
        
        // 2. Клиент ослепляет бюллетень
        BigInt blindedMessage = client->blindBallot(ballot, server_->getPublicKey());
        
        // 3. Сервер выдает слепую подпись
        BigInt blindSignature = server_->processBlindBallot(client->getClientId(), blindedMessage);
        
        if (blindSignature != 0) {
            // 4. Клиент разослепляет подпись
            if (client->unblindSignature(ballot, blindSignature, server_->getPublicKey())) {
                // 5. Клиент отправляет подписанный бюллетень на подсчет
                server_->submitBallot(ballot);
            } else {
                std::cout << "ERROR: Failed to unblind signature for " << client->getClientId() << std::endl;
            }
        }
        
        std::cout << "--- Vote processing complete for " << client->getClientId() << " ---\n" << std::endl;
    }
    
    // Подсчет и отображение результатов
    server_->tallyVotes();
    server_->displayResults();
}

void VotingSystem::displayFullProcess() {
    server_->displayAllNumbers();
}

VoteOption VotingSystem::getRandomVote() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 2);
    
    switch (dis(gen)) {
        case 0: return VoteOption::YES;
        case 1: return VoteOption::NO;
        default: return VoteOption::ABSTAIN;
    }
}
