// gui.h
#ifndef GUI_H
#define GUI_H

#include "mental_poker.h"
#include "blind_voting.h"
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include <memory>
#include <vector>
#include <string>

class CryptoGUI {
public:
    CryptoGUI();
    ~CryptoGUI();
    
    bool Initialize();
    void Run();
    void Cleanup();

private:
    GLFWwindow* window_;
    
    // State management
    enum ApplicationState {
        MAIN_MENU,
        MENTAL_POKER_SETUP,
        MENTAL_POKER_GAME,
        BLIND_VOTING_SETUP,
        BLIND_VOTING_PROCESS,
        RESULTS_DISPLAY
    };
    
    ApplicationState currentState_;
    
    // Mental Poker components
    std::unique_ptr<TexasHoldemEngine> pokerGame_;
    int numPlayers_;
    bool gameStarted_;
    std::vector<std::string> gameLog_;
    
    // Blind Voting components  
    std::unique_ptr<VotingSystem> votingSystem_;
    std::string votingQuestion_;
    std::vector<std::string> voterIds_;
    std::vector<std::string> votingLog_;
    bool votingStarted_;
    
    // GUI Methods
    void RenderMainMenu();
    void RenderMentalPokerSetup();
    void RenderMentalPokerGame();
    void RenderBlindVotingSetup();
    void RenderBlindVotingProcess();
    void RenderResults();
    
    // Helper methods
    void ShowGameLog(const std::vector<std::string>& log);
    void ShowCryptoNumbers();
    void ShowHelpDialog();
    void AddLogEntry(std::vector<std::string>& log, const std::string& entry);
    
    // UI Components
    void DrawCard(const Card& card, float x, float y, float scale = 1.0f);
    void DrawProgressBar(float progress, const std::string& label);
    void DrawCryptoNumber(const std::string& name, const std::string& value);
    
    // Static callbacks
    static void ErrorCallback(int error, const char* description);
};

#endif // GUI_H
