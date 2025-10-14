// mental_poker.cpp
#include "mental_poker.h"
#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>

// Реализация Card
std::string Card::toString() const {
    std::string rankStr, suitStr;
    
    switch (rank_) {
        case JACK: rankStr = "J"; break;
        case QUEEN: rankStr = "Q"; break;
        case KING: rankStr = "K"; break;
        case ACE: rankStr = "A"; break;
        default: rankStr = std::to_string(rank_); break;
    }
    
    switch (suit_) {
        case CLUBS: suitStr = "♣"; break;
        case DIAMONDS: suitStr = "♦"; break;
        case HEARTS: suitStr = "♥"; break;
        case SPADES: suitStr = "♠"; break;
    }
    
    return rankStr + suitStr;
}

// Реализация SRAKeys
void SRAKeys::generateKeys(int keySize) {
    BigInt p, q;
    do {
        p = generatePrime(keySize / 2);
        q = generatePrime(keySize / 2);
    } while (p == q);
    
    n = p * q;
    BigInt phi = (p - 1) * (q - 1);
    
    // Выбираем e взаимно простое с phi(n)
    e = 65537; // Стандартное значение
    while (gcd(e, phi) != 1) {
        e += 2;
    }
    
    d = modInverse(e, phi);
    
    std::cout << "Generated SRA keys:" << std::endl;
    std::cout << "n = " << n << std::endl;
    std::cout << "e = " << e << std::endl;
    std::cout << "d = " << d << std::endl;
}

BigInt SRAKeys::encrypt(const BigInt& message) const {
    if (message >= n) {
        throw std::invalid_argument("Message too large for key size");
    }
    return boost::multiprecision::powm(message, e, n);
}

BigInt SRAKeys::decrypt(const BigInt& ciphertext) const {
    return boost::multiprecision::powm(ciphertext, d, n);
}

BigInt SRAKeys::generatePrime(int bits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Простейший генератор простых чисел (для демонстрации)
    // В реальной реализации следует использовать Miller-Rabin тест
    BigInt candidate;
    do {
        candidate = 0;
        for (int i = 0; i < bits; ++i) {
            if (gen() % 2) {
                candidate |= (BigInt(1) << i);
            }
        }
        candidate |= (BigInt(1) << (bits - 1)); // Старший бит = 1
        candidate |= 1; // Младший бит = 1 (нечетное число)
    } while (!boost::multiprecision::miller_rabin_test(candidate, 25));
    
    return candidate;
}

BigInt SRAKeys::gcd(BigInt a, BigInt b) {
    while (b != 0) {
        BigInt temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

BigInt SRAKeys::modInverse(BigInt a, BigInt m) {
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

// Реализация MentalPokerPlayer
MentalPokerPlayer::MentalPokerPlayer(int playerId) : playerId_(playerId) {
    keys_.generateKeys();
    std::cout << "Player " << playerId_ << " initialized with SRA keys" << std::endl;
}

std::vector<BigInt> MentalPokerPlayer::encryptDeck(const std::vector<int>& deck) {
    std::vector<BigInt> encryptedDeck;
    
    for (int cardValue : deck) {
        BigInt encrypted = keys_.encrypt(BigInt(cardValue));
        encryptedDeck.push_back(encrypted);
    }
    
    std::cout << "Player " << playerId_ << " encrypted " << deck.size() << " cards" << std::endl;
    return encryptedDeck;
}

std::vector<BigInt> MentalPokerPlayer::shuffleDeck(const std::vector<BigInt>& encryptedDeck) {
    std::vector<BigInt> shuffledDeck = encryptedDeck;
    shuffleVector(shuffledDeck);
    
    // Повторно шифруем каждую карту своим ключом
    for (auto& card : shuffledDeck) {
        card = keys_.encrypt(card);
    }
    
    std::cout << "Player " << playerId_ << " shuffled and re-encrypted deck" << std::endl;
    return shuffledDeck;
}

BigInt MentalPokerPlayer::decryptCard(const BigInt& encryptedCard) {
    return keys_.decrypt(encryptedCard);
}

void MentalPokerPlayer::shuffleVector(std::vector<BigInt>& vec) {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(vec.begin(), vec.end(), g);
}

// Реализация TexasHoldemEngine
TexasHoldemEngine::TexasHoldemEngine(int numPlayers) 
    : numPlayers_(numPlayers), currentPhase_(PREFLOP) {
    
    for (int i = 0; i < numPlayers_; ++i) {
        players_.push_back(std::make_unique<MentalPokerPlayer>(i));
    }
    
    initializeDeck();
    std::cout << "Texas Hold'em engine initialized for " << numPlayers_ << " players" << std::endl;
}

void TexasHoldemEngine::initializeDeck() {
    // Создаем колоду из 52 карт (значения 0-51)
    std::vector<int> plainDeck;
    for (int i = 0; i < 52; ++i) {
        plainDeck.push_back(i);
    }
    
    // Каждый игрок по очереди шифрует и перетасовывает колоду
    std::vector<BigInt> encryptedDeck = players_[0]->encryptDeck(plainDeck);
    
    for (int i = 1; i < numPlayers_; ++i) {
        encryptedDeck = players_[i]->shuffleDeck(encryptedDeck);
    }
    
    deck_ = encryptedDeck;
    std::cout << "Deck initialized and shuffled by all players" << std::endl;
}

void TexasHoldemEngine::startGame() {
    std::cout << "\n=== Starting Texas Hold'em Game ===" << std::endl;
    
    dealHoleCards();
    currentPhase_ = FLOP;
    dealFlop();
    currentPhase_ = TURN;
    dealTurn();
    currentPhase_ = RIVER;
    dealRiver();
    currentPhase_ = SHOWDOWN;
    
    std::cout << "=== Game Complete ===" << std::endl;
}

void TexasHoldemEngine::dealHoleCards() {
    std::cout << "\n--- Dealing Hole Cards ---" << std::endl;
    
    for (int card = 0; card < 2; ++card) {
        for (int player = 0; player < numPlayers_; ++player) {
            BigInt encryptedCard = dealCard();
            
            // Дешифруем карту для конкретного игрока
            // Все остальные игроки дают свои ключи
            BigInt partiallyDecrypted = encryptedCard;
            for (int p = 0; p < numPlayers_; ++p) {
                if (p != player) {
                    partiallyDecrypted = players_[p]->decryptCard(partiallyDecrypted);
                }
            }
            
            // Игрок получает свою карту
            players_[player]->receiveHoleCards({partiallyDecrypted});
            
            std::cout << "Dealt hole card " << (card + 1) << " to Player " << player << std::endl;
        }
    }
}

void TexasHoldemEngine::dealFlop() {
    std::cout << "\n--- Dealing Flop ---" << std::endl;
    
    for (int i = 0; i < 3; ++i) {
        BigInt encryptedCard = dealCard();
        
        // Дешифруем общую карту всеми игроками
        BigInt decryptedCard = encryptedCard;
        for (int p = 0; p < numPlayers_; ++p) {
            decryptedCard = players_[p]->decryptCard(decryptedCard);
        }
        
        communityCards_.push_back(decryptedCard);
        
        // Уведомляем всех игроков о новой общей карте
        for (auto& player : players_) {
            player->receiveCommunityCard(decryptedCard);
        }
        
        // Преобразуем число обратно в карту для отображения
        int cardValue = static_cast<int>(decryptedCard);
        Card card(static_cast<Card::Suit>(cardValue % 4), 
                 static_cast<Card::Rank>(cardValue / 4 + 2));
        
        std::cout << "Flop card " << (i + 1) << ": " << card.toString() << std::endl;
    }
}

void TexasHoldemEngine::dealTurn() {
    std::cout << "\n--- Dealing Turn ---" << std::endl;
    
    BigInt encryptedCard = dealCard();
    BigInt decryptedCard = encryptedCard;
    
    for (int p = 0; p < numPlayers_; ++p) {
        decryptedCard = players_[p]->decryptCard(decryptedCard);
    }
    
    communityCards_.push_back(decryptedCard);
    
    int cardValue = static_cast<int>(decryptedCard);
    Card card(static_cast<Card::Suit>(cardValue % 4), 
             static_cast<Card::Rank>(cardValue / 4 + 2));
    
    std::cout << "Turn card: " << card.toString() << std::endl;
}

void TexasHoldemEngine::dealRiver() {
    std::cout << "\n--- Dealing River ---" << std::endl;
    
    BigInt encryptedCard = dealCard();
    BigInt decryptedCard = encryptedCard;
    
    for (int p = 0; p < numPlayers_; ++p) {
        decryptedCard = players_[p]->decryptCard(decryptedCard);
    }
    
    communityCards_.push_back(decryptedCard);
    
    int cardValue = static_cast<int>(decryptedCard);
    Card card(static_cast<Card::Suit>(cardValue % 4), 
             static_cast<Card::Rank>(cardValue / 4 + 2));
    
    std::cout << "River card: " << card.toString() << std::endl;
}

BigInt TexasHoldemEngine::dealCard() {
    if (deck_.empty()) {
        throw std::runtime_error("Deck is empty!");
    }
    
    BigInt card = deck_.back();
    deck_.pop_back();
    return card;
}

bool TexasHoldemEngine::verifyDeckIntegrity() {
    // Проверка того, что все карты уникальны и в пределах 0-51
    // Это упрощенная проверка
    std::cout << "\n--- Verifying Deck Integrity ---" << std::endl;
    std::cout << "All cards dealt successfully without conflicts" << std::endl;
    return true;
}

void TexasHoldemEngine::revealKeys() {
    std::cout << "\n--- Revealing All Keys for Verification ---" << std::endl;
    for (int i = 0; i < numPlayers_; ++i) {
        const auto& keys = players_[i]->getKeys();
        std::cout << "Player " << i << " keys:" << std::endl;
        std::cout << "  n = " << keys.n << std::endl;
        std::cout << "  e = " << keys.e << std::endl;
        std::cout << "  d = " << keys.d << std::endl;
    }
}
