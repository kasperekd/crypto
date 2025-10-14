// blind_voting.h
#ifndef BLIND_VOTING_H
#define BLIND_VOTING_H

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

enum class VoteOption {
    YES,
    NO,
    ABSTAIN
};

struct VotingBallot {
    std::string ballotId;
    VoteOption vote;
    BigInt blindedMessage;
    BigInt blindingFactor;
    BigInt signature;
    
    std::string toString() const;
};

class RSABlindSignature {
public:
    struct KeyPair {
        BigInt n, e, d;
        
        void generateKeys(int keySize = 2048);
        std::string getPublicKeyString() const;
        
    private:
        BigInt generatePrime(int bits);
        BigInt gcd(BigInt a, BigInt b);
        BigInt modInverse(BigInt a, BigInt m);
    };
    
    // Клиентские операции
    static BigInt blindMessage(const BigInt& message, const BigInt& r, const KeyPair& pubKey);
    static BigInt unblindSignature(const BigInt& blindSignature, const BigInt& r, const KeyPair& pubKey);
    static BigInt generateBlindingFactor(const KeyPair& pubKey);
    
    // Серверные операции
    static BigInt blindSign(const BigInt& blindedMessage, const KeyPair& privKey);
    static bool verifySignature(const BigInt& message, const BigInt& signature, const KeyPair& pubKey);
    
    // Вспомогательные функции
    static BigInt hashMessage(const std::string& message);
    static BigInt modInverse(BigInt a, BigInt m);
};

class VotingClient {
public:
    VotingClient(const std::string& clientId);
    
    // Создание бюллетеня
    VotingBallot createBallot(VoteOption vote, const std::string& question);
    
    // Ослепление сообщения
    BigInt blindBallot(VotingBallot& ballot, const RSABlindSignature::KeyPair& serverPubKey);
    
    // Разослепление подписи
    bool unblindSignature(VotingBallot& ballot, const BigInt& blindSignature, 
                         const RSABlindSignature::KeyPair& serverPubKey);
    
    // Проверка подписи
    bool verifyBallotSignature(const VotingBallot& ballot, 
                              const RSABlindSignature::KeyPair& serverPubKey);
    
    const std::string& getClientId() const { return clientId_; }
    
private:
    std::string clientId_;
    std::map<std::string, VotingBallot> ballots_;
    
    std::string generateBallotId();
};

class VotingServer {
public:
    VotingServer(const std::string& question);
    
    // Инициализация сервера
    void initialize();
    
    // Регистрация избирателя
    bool registerVoter(const std::string& voterId);
    
    // Проверка права голоса и выдача слепой подписи
    BigInt processBlindBallot(const std::string& voterId, const BigInt& blindedMessage);
    
    // Прием бюллетеня на подсчет
    bool submitBallot(const VotingBallot& ballot);
    
    // Подсчет голосов
    void tallyVotes();
    
    // Получение результатов
    void displayResults();
    
    // Получение публичного ключа
    const RSABlindSignature::KeyPair& getPublicKey() const { return keyPair_; }
    
    // Отображение всех операций (для демонстрации)
    void displayAllNumbers();

private:
    std::string question_;
    RSABlindSignature::KeyPair keyPair_;
    
    // Реестры
    std::vector<std::string> registeredVoters_;
    std::vector<std::string> votedVoters_;
    std::vector<VotingBallot> submittedBallots_;
    
    // Результаты
    std::map<VoteOption, int> results_;
    
    // Проверка регистрации и права голоса
    bool isVoterRegistered(const std::string& voterId);
    bool hasVoterVoted(const std::string& voterId);
    void markVoterAsVoted(const std::string& voterId);
    
    // Проверка корректности бюллетеня
    bool validateBallot(const VotingBallot& ballot);
};

class VotingSystem {
public:
    VotingSystem(const std::string& question);
    
    // Инициализация системы
    void initializeSystem();
    
    // Добавление клиента
    void addClient(const std::string& clientId);
    
    // Симуляция процесса голосования
    void simulateVoting();
    
    // Отображение всего процесса
    void displayFullProcess();

private:
    std::string question_;
    std::unique_ptr<VotingServer> server_;
    std::vector<std::unique_ptr<VotingClient>> clients_;
    
    VoteOption getRandomVote();
};

#endif // BLIND_VOTING_H
