// mental_poker.h
#ifndef MENTAL_POKER_H
#define MENTAL_POKER_H

#include <vector>
#include <string>
#include <memory>
#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class Card {
public:
    enum Suit { CLUBS, DIAMONDS, HEARTS, SPADES };
    enum Rank { TWO = 2, THREE, FOUR, FIVE, SIX, SEVEN, EIGHT, NINE, TEN, JACK, QUEEN, KING, ACE };
    
    Card(Suit suit, Rank rank) : suit_(suit), rank_(rank) {}
    
    Suit getSuit() const { return suit_; }
    Rank getRank() const { return rank_; }
    std::string toString() const;
    int toInt() const { return rank_ * 4 + suit_; }

private:
    Suit suit_;
    Rank rank_;
};

class SRAKeys {
public:
    BigInt n, e, d;
    
    SRAKeys() = default;
    void generateKeys(int keySize = 1024);
    BigInt encrypt(const BigInt& message) const;
    BigInt decrypt(const BigInt& ciphertext) const;
    
private:
    BigInt generatePrime(int bits);
    BigInt gcd(BigInt a, BigInt b);
    BigInt modInverse(BigInt a, BigInt m);
};

class MentalPokerPlayer {
public:
    MentalPokerPlayer(int playerId);
    
    // Основные операции протокола
    std::vector<BigInt> encryptDeck(const std::vector<int>& deck);
    std::vector<BigInt> shuffleDeck(const std::vector<BigInt>& encryptedDeck);
    BigInt decryptCard(const BigInt& encryptedCard);
    
    // Игровые операции
    void receiveHoleCards(const std::vector<BigInt>& cards);
    void receiveCommunityCard(const BigInt& card);
    
    const SRAKeys& getKeys() const { return keys_; }
    int getPlayerId() const { return playerId_; }
    
private:
    int playerId_;
    SRAKeys keys_;
    std::vector<BigInt> holeCards_;
    std::vector<BigInt> communityCards_;
    
    void shuffleVector(std::vector<BigInt>& vec);
};

class TexasHoldemEngine {
public:
    TexasHoldemEngine(int numPlayers);
    
    void startGame();
    void dealHoleCards();
    void dealFlop();
    void dealTurn();
    void dealRiver();
    
    // Доказательство честности
    bool verifyDeckIntegrity();
    void revealKeys();

private:
    int numPlayers_;
    std::vector<std::unique_ptr<MentalPokerPlayer>> players_;
    std::vector<BigInt> deck_;
    std::vector<BigInt> communityCards_;
    
    // Состояние игры
    enum GamePhase { PREFLOP, FLOP, TURN, RIVER, SHOWDOWN };
    GamePhase currentPhase_;
    
    void initializeDeck();
    BigInt dealCard();
    void validateCard(const BigInt& card);
};

#endif // MENTAL_POKER_H
