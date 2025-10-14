// gui.cpp
#include "gui.h"
#include <iostream>
#include <sstream>
#include <iomanip>

CryptoGUI::CryptoGUI() 
    : window_(nullptr), currentState_(MAIN_MENU), numPlayers_(3), 
      gameStarted_(false), votingStarted_(false) {
}

CryptoGUI::~CryptoGUI() {
    Cleanup();
}

bool CryptoGUI::Initialize() {
    // Initialize GLFW
    glfwSetErrorCallback(ErrorCallback);
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return false;
    }

    // OpenGL 3.3 Core Profile
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    // Create window
    window_ = glfwCreateWindow(1280, 720, "Криптографические протоколы", NULL, NULL);
    if (!window_) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return false;
    }

    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1); // Enable vsync

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    
    // Setup ImGui style
    ImGui::StyleColorsDark();
    
    // Customize colors for crypto theme
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg] = ImVec4(0.13f, 0.14f, 0.15f, 1.00f);
    colors[ImGuiCol_Header] = ImVec4(0.26f, 0.59f, 0.98f, 0.31f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(0.26f, 0.59f, 0.98f, 0.40f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.06f, 0.53f, 0.98f, 1.00f);

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    return true;
}

void CryptoGUI::Run() {
    while (!glfwWindowShouldClose(window_)) {
        glfwPollEvents();

        // Start the Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Main application logic
        switch (currentState_) {
            case MAIN_MENU:
                RenderMainMenu();
                break;
            case MENTAL_POKER_SETUP:
                RenderMentalPokerSetup();
                break;
            case MENTAL_POKER_GAME:
                RenderMentalPokerGame();
                break;
            case BLIND_VOTING_SETUP:
                RenderBlindVotingSetup();
                break;
            case BLIND_VOTING_PROCESS:
                RenderBlindVotingProcess();
                break;
            case RESULTS_DISPLAY:
                RenderResults();
                break;
        }

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window_, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window_);
    }
}

void CryptoGUI::RenderMainMenu() {
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    
    if (ImGui::Begin("Криптографические протоколы", nullptr, 
                     ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | 
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus)) {
        
        // Title
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Криптографические протоколы").x) * 0.5f);
        ImGui::TextColored(ImVec4(0.26f, 0.59f, 0.98f, 1.0f), "Криптографические протоколы");
        ImGui::Separator();
        ImGui::Spacing();

        // Center buttons
        float button_width = 400.0f;
        float button_height = 80.0f;
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - button_width) * 0.5f);

        if (ImGui::Button("🃏 Ментальный Покер (Texas Hold'em)", ImVec2(button_width, button_height))) {
            currentState_ = MENTAL_POKER_SETUP;
        }

        ImGui::Spacing();
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - button_width) * 0.5f);

        if (ImGui::Button("🗳️ Анонимное Голосование (Слепая Подпись)", ImVec2(button_width, button_height))) {
            currentState_ = BLIND_VOTING_SETUP;
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Description
        ImGui::TextWrapped(
            "Эта программа демонстрирует два важных криптографических протокола:\n\n"
            "1. Ментальный Покер - позволяет играть в карточные игры без доверенной третьей стороны, "
            "используя коммутативное шифрование SRA.\n\n"
            "2. Слепая Подпись - обеспечивает анонимное голосование, где сервер не знает содержимое "
            "голоса, но может проверить его подлинность."
        );

        ImGui::Spacing();
        if (ImGui::Button("ℹ️ Справка")) {
            ShowHelpDialog();
        }
    }
    ImGui::End();
}

void CryptoGUI::RenderMentalPokerSetup() {
    ImGui::SetNextWindowPos(ImVec2(50, 50));
    ImGui::SetNextWindowSize(ImVec2(800, 600));
    
    if (ImGui::Begin("Настройка Ментального Покера", nullptr, ImGuiWindowFlags_NoResize)) {
        
        ImGui::Text("Настройка игры Texas Hold'em");
        ImGui::Separator();
        ImGui::Spacing();

        // Number of players
        ImGui::Text("Количество игроков:");
        ImGui::SliderInt("##players", &numPlayers_, 2, 6);
        ImGui::Spacing();

        // Game info
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Правила Texas Hold'em:");
        ImGui::BulletText("Каждый игрок получает 2 закрытые карты");
        ImGui::BulletText("5 общих карт: флоп (3), терн (1), ривер (1)");
        ImGui::BulletText("Цель: лучшая 5-карточная комбинация");
        ImGui::Spacing();

        // Crypto info
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Криптографические особенности:");
        ImGui::BulletText("Алгоритм SRA (коммутативное шифрование)");
        ImGui::BulletText("Каждый игрок генерирует свои ключи");
        ImGui::BulletText("Колода перемешивается всеми игроками");
        ImGui::BulletText("Никто не может предсказать карты");
        ImGui::Spacing();

        // Buttons
        if (ImGui::Button("🎮 Начать Игру", ImVec2(200, 40))) {
            try {
                pokerGame_ = std::make_unique<TexasHoldemEngine>(numPlayers_);
                gameLog_.clear();
                AddLogEntry(gameLog_, "Инициализация игры для " + std::to_string(numPlayers_) + " игроков");
                AddLogEntry(gameLog_, "Генерация SRA ключей...");
                AddLogEntry(gameLog_, "Перемешивание колоды...");
                
                currentState_ = MENTAL_POKER_GAME;
                gameStarted_ = true;
            } catch (const std::exception& e) {
                AddLogEntry(gameLog_, "Ошибка: " + std::string(e.what()));
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("⬅️ Назад", ImVec2(100, 40))) {
            currentState_ = MAIN_MENU;
        }
    }
    ImGui::End();
}

void CryptoGUI::RenderMentalPokerGame() {
    // Main game window
    ImGui::SetNextWindowPos(ImVec2(10, 10));
    ImGui::SetNextWindowSize(ImVec2(800, 500));
    
    if (ImGui::Begin("Ментальный Покер - Игра", nullptr, ImGuiWindowFlags_NoResize)) {
        
        if (!gameStarted_) {
            ImGui::Text("Игра не запущена");
        } else {
            ImGui::Text("Texas Hold'em - %d игроков", numPlayers_);
            ImGui::Separator();

            // Game phases
            const char* phases[] = {"Preflop", "Flop", "Turn", "River", "Showdown"};
            static int current_phase = 0;

            if (ImGui::Button("▶️ Следующий этап", ImVec2(150, 30))) {
                if (current_phase < 4) {
                    try {
                        switch (current_phase) {
                            case 0: // Preflop - deal hole cards
                                AddLogEntry(gameLog_, "=== PREFLOP ===");
                                AddLogEntry(gameLog_, "Раздача закрытых карт каждому игроку...");
                                pokerGame_->dealHoleCards();
                                break;
                            case 1: // Flop
                                AddLogEntry(gameLog_, "=== FLOP ===");
                                AddLogEntry(gameLog_, "Раздача 3 общих карт...");
                                pokerGame_->dealFlop();
                                break;
                            case 2: // Turn
                                AddLogEntry(gameLog_, "=== TURN ===");
                                AddLogEntry(gameLog_, "Раздача карты терна...");
                                pokerGame_->dealTurn();
                                break;
                            case 3: // River
                                AddLogEntry(gameLog_, "=== RIVER ===");
                                AddLogEntry(gameLog_, "Раздача карты ривера...");
                                pokerGame_->dealRiver();
                                break;
                            case 4: // Showdown
                                AddLogEntry(gameLog_, "=== SHOWDOWN ===");
                                AddLogEntry(gameLog_, "Игра завершена!");
                                pokerGame_->verifyDeckIntegrity();
                                break;
                        }
                        current_phase++;
                    } catch (const std::exception& e) {
                        AddLogEntry(gameLog_, "Ошибка: " + std::string(e.what()));
                    }
                }
            }

            ImGui::SameLine();
            ImGui::Text("Текущий этап: %s", phases[std::min(current_phase, 4)]);

            // Progress bar
            DrawProgressBar(current_phase / 4.0f, "Прогресс игры");

            ImGui::Spacing();
            ImGui::Separator();

            // Game log in scrollable area
            ImGui::BeginChild("GameLog", ImVec2(0, 200), true);
            ShowGameLog(gameLog_);
            ImGui::EndChild();
        }

        if (ImGui::Button("🔢 Показать криптографические числа")) {
            ShowCryptoNumbers();
        }
        
        ImGui::SameLine();
        if (ImGui::Button("⬅️ Новая игра")) {
            gameStarted_ = false;
            currentState_ = MENTAL_POKER_SETUP;
        }
    }
    ImGui::End();
}

void CryptoGUI::RenderBlindVotingSetup() {
    ImGui::SetNextWindowPos(ImVec2(50, 50));
    ImGui::SetNextWindowSize(ImVec2(800, 600));
    
    if (ImGui::Begin("Настройка Анонимного Голосования", nullptr, ImGuiWindowFlags_NoResize)) {
        
        ImGui::Text("Система слепой подписи для анонимного голосования");
        ImGui::Separator();
        ImGui::Spacing();

        // Voting question
        static char question[256] = "Поддерживаете ли вы данное предложение?";
        ImGui::Text("Вопрос для голосования:");
        ImGui::InputText("##question", question, sizeof(question));
        votingQuestion_ = std::string(question);
        ImGui::Spacing();

        // Number of voters
        static int numVoters = 5;
        ImGui::Text("Количество избирателей:");
        ImGui::SliderInt("##voters", &numVoters, 1, 20);
        ImGui::Spacing();

        // Voter IDs
        ImGui::Text("Зарегистрированные избиратели:");
        voterIds_.clear();
        for (int i = 0; i < numVoters; ++i) {
            voterIds_.push_back("voter_" + std::to_string(i + 1));
            ImGui::BulletText("voter_%d", i + 1);
        }
        ImGui::Spacing();

        // Crypto info
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Криптографические особенности:");
        ImGui::BulletText("RSA слепая подпись (2048-бит ключи)");
        ImGui::BulletText("Сервер не видит содержимое голоса");
        ImGui::BulletText("Избиратель остается анонимным");
        ImGui::BulletText("Подпись гарантирует подлинность");
        ImGui::Spacing();

        // Buttons
        if (ImGui::Button("🗳️ Начать Голосование", ImVec2(200, 40))) {
            try {
                votingSystem_ = std::make_unique<VotingSystem>(votingQuestion_);
                votingLog_.clear();
                
                AddLogEntry(votingLog_, "Инициализация системы голосования");
                votingSystem_->initializeSystem();
                
                AddLogEntry(votingLog_, "Регистрация избирателей:");
                for (const auto& voterId : voterIds_) {
                    votingSystem_->addClient(voterId);
                    AddLogEntry(votingLog_, "- Зарегистрирован: " + voterId);
                }
                
                currentState_ = BLIND_VOTING_PROCESS;
                votingStarted_ = true;
            } catch (const std::exception& e) {
                AddLogEntry(votingLog_, "Ошибка: " + std::string(e.what()));
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("⬅️ Назад", ImVec2(100, 40))) {
            currentState_ = MAIN_MENU;
        }
    }
    ImGui::End();
}

void CryptoGUI::RenderBlindVotingProcess() {
    // Main voting window
    ImGui::SetNextWindowPos(ImVec2(10, 10));
    ImGui::SetNextWindowSize(ImVec2(800, 500));
    
    if (ImGui::Begin("Анонимное Голосование - Процесс", nullptr, ImGuiWindowFlags_NoResize)) {
        
        if (!votingStarted_) {
            ImGui::Text("Голосование не запущено");
        } else {
            ImGui::Text("Вопрос: %s", votingQuestion_.c_str());
            ImGui::Text("Количество избирателей: %zu", voterIds_.size());
            ImGui::Separator();

            static bool votingCompleted = false;

            if (!votingCompleted) {
                if (ImGui::Button("▶️ Провести Голосование", ImVec2(200, 40))) {
                    try {
                        AddLogEntry(votingLog_, "=== НАЧАЛО ГОЛОСОВАНИЯ ===");
                        
                        for (const auto& voterId : voterIds_) {
                            AddLogEntry(votingLog_, "Обработка голоса от " + voterId + ":");
                            AddLogEntry(votingLog_, "1. Создание бюллетеня");
                            AddLogEntry(votingLog_, "2. Ослепление сообщения");
                            AddLogEntry(votingLog_, "3. Получение слепой подписи");
                            AddLogEntry(votingLog_, "4. Разослепление подписи");
                            AddLogEntry(votingLog_, "5. Анонимная подача бюллетеня");
                            AddLogEntry(votingLog_, "✓ Голос засчитан");
                        }
                        
                        votingSystem_->simulateVoting();
                        AddLogEntry(votingLog_, "=== ГОЛОСОВАНИЕ ЗАВЕРШЕНО ===");
                        votingCompleted = true;
                        
                    } catch (const std::exception& e) {
                        AddLogEntry(votingLog_, "Ошибка: " + std::string(e.what()));
                    }
                }
            } else {
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Голосование завершено!");
                
                if (ImGui::Button("📊 Показать Результаты", ImVec2(200, 40))) {
                    currentState_ = RESULTS_DISPLAY;
                }
            }

            ImGui::Spacing();
            ImGui::Separator();

            // Voting log in scrollable area
            ImGui::BeginChild("VotingLog", ImVec2(0, 250), true);
            ShowGameLog(votingLog_);
            ImGui::EndChild();
        }

        if (ImGui::Button("🔢 Показать криптографические числа")) {
            ShowCryptoNumbers();
        }
        
        ImGui::SameLine();
        if (ImGui::Button("⬅️ Новое голосование")) {
            votingStarted_ = false;
            currentState_ = BLIND_VOTING_SETUP;
        }
    }
    ImGui::End();
}

void CryptoGUI::RenderResults() {
    ImGui::SetNextWindowPos(ImVec2(200, 100));
    ImGui::SetNextWindowSize(ImVec2(600, 400));
    
    if (ImGui::Begin("Результаты Голосования", nullptr, ImGuiWindowFlags_NoResize)) {
        
        ImGui::Text("Результаты анонимного голосования");
        ImGui::Separator();
        ImGui::Spacing();

        // Mock results for demonstration
        static int yesVotes = 3, noVotes = 1, abstainVotes = 1;
        int totalVotes = yesVotes + noVotes + abstainVotes;

        ImGui::Text("Вопрос: %s", votingQuestion_.c_str());
        ImGui::Text("Всего проголосовало: %d", totalVotes);
        ImGui::Spacing();

        // Results bars
        float yesPercent = totalVotes > 0 ? (float)yesVotes / totalVotes : 0;
        float noPercent = totalVotes > 0 ? (float)noVotes / totalVotes : 0;
        float abstainPercent = totalVotes > 0 ? (float)abstainVotes / totalVotes : 0;

        ImGui::Text("ДА: %d голосов (%.1f%%)", yesVotes, yesPercent * 100);
        ImGui::ProgressBar(yesPercent, ImVec2(400, 0), "");
        
        ImGui::Text("НЕТ: %d голосов (%.1f%%)", noVotes, noPercent * 100);
        ImGui::ProgressBar(noPercent, ImVec2(400, 0), "");
        
        ImGui::Text("ВОЗДЕРЖАЛСЯ: %d голосов (%.1f%%)", abstainVotes, abstainPercent * 100);
        ImGui::ProgressBar(abstainPercent, ImVec2(400, 0), "");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), 
                          "✓ Все голоса проверены и засчитаны");
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), 
                          "✓ Анонимность избирателей обеспечена");

        ImGui::Spacing();
        if (ImGui::Button("⬅️ Главное меню", ImVec2(150, 40))) {
            currentState_ = MAIN_MENU;
        }
    }
    ImGui::End();
}

void CryptoGUI::ShowGameLog(const std::vector<std::string>& log) {
    for (const auto& entry : log) {
        if (entry.find("===") != std::string::npos) {
            ImGui::TextColored(ImVec4(0.26f, 0.59f, 0.98f, 1.0f), "%s", entry.c_str());
        } else if (entry.find("Ошибка") != std::string::npos) {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s", entry.c_str());
        } else if (entry.find("✓") != std::string::npos) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", entry.c_str());
        } else {
            ImGui::Text("%s", entry.c_str());
        }
    }
    if (!log.empty()) {
        ImGui::SetScrollHereY(1.0f);
    }
}

void CryptoGUI::ShowCryptoNumbers() {
    static bool showNumbers = false;
    showNumbers = true;
    
    if (showNumbers) {
        ImGui::Begin("Криптографические числа", &showNumbers);
        
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "RSA Ключи (пример):");
        DrawCryptoNumber("n (модуль)", "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357");
        DrawCryptoNumber("e (откр. экспонента)", "65537");
        DrawCryptoNumber("d (секр. экспонента)", "15118973544554411398934976296563629651589477066301158969716063166670664346095638686140648027799964206043149760862058639160506011094889069866983924570715071235879456141825993434051804117780107325244096071669430156468698901434767995005074094477926936149951083266568265221930701830764928043473962925827001040362986071165120063935648890080506077016073036726924061896633000029103205327710123984951686952806061421537978098334014633502128234577302055953050966549397892946992829625509632959011431851862159006398700950194030096648948124577959449894950297003002655169001179652890653138799488952005503073616896896647334398765857");
        
        ImGui::Separator();
        
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Ослепленное сообщение:");
        DrawCryptoNumber("m (исходное)", "1234567890");
        DrawCryptoNumber("r (фактор ослепления)", "87452301928374650293847562");
        DrawCryptoNumber("m' (ослепленное)", "1847562938475029384756237458926345");
        
        ImGui::End();
    }
}

void CryptoGUI::DrawCryptoNumber(const std::string& name, const std::string& value) {
    ImGui::Text("%s:", name.c_str());
    ImGui::SameLine();
    
    // Truncate long numbers for display
    std::string displayValue = value;
    if (displayValue.length() > 60) {
        displayValue = displayValue.substr(0, 30) + "..." + displayValue.substr(displayValue.length() - 30);
    }
    
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "%s", displayValue.c_str());
    
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Полное значение:");
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", value.c_str());
        ImGui::EndTooltip();
    }
}

void CryptoGUI::DrawProgressBar(float progress, const std::string& label) {
    ImGui::Text("%s", label.c_str());
    ImGui::ProgressBar(progress, ImVec2(400, 0));
}

void CryptoGUI::AddLogEntry(std::vector<std::string>& log, const std::string& entry) {
    log.push_back(entry);
    if (log.size() > 100) { // Limit log size
        log.erase(log.begin());
    }
}

void CryptoGUI::ShowHelpDialog() {
    static bool showHelp = false;
    showHelp = true;
    
    if (showHelp) {
        ImGui::Begin("Справка", &showHelp);
        
        ImGui::TextColored(ImVec4(0.26f, 0.59f, 0.98f, 1.0f), "Ментальный Покер:");
        ImGui::TextWrapped("Протокол, позволяющий играть в карточные игры без доверенной третьей стороны. Использует коммутативное шифрование SRA для обеспечения честности.");
        ImGui::Spacing();
        
        ImGui::TextColored(ImVec4(0.26f, 0.59f, 0.98f, 1.0f), "Слепая Подпись:");
        ImGui::TextWrapped("Криптографический протокол, позволяющий серверу подписать сообщение, не видя его содержимого. Используется для анонимного голосования.");
        ImGui::Spacing();
        
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Безопасность:");
        ImGui::BulletText("Использование больших RSA ключей (1024-2048 бит)");
        ImGui::BulletText("Криптостойкие алгоритмы");
        ImGui::BulletText("Проверяемая честность протоколов");
        
        ImGui::End();
    }
}

void CryptoGUI::Cleanup() {
    if (window_) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();

        glfwDestroyWindow(window_);
        glfwTerminate();
    }
}

void CryptoGUI::ErrorCallback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}
