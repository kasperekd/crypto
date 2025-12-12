
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <random>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <zmq.hpp>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h> 

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/multiprecision/miller_rabin.hpp>

using BigInt = boost::multiprecision::cpp_int;
using namespace boost::multiprecision;
namespace fs = std::filesystem;

// =============================================================
// Utilities: Logging and Cryptographic Math
// =============================================================

// Thread-safe logger for the GUI
class AppLogger {
    std::vector<std::string> logs;
    std::mutex mtx;
    bool autoScroll = true;
public:
    void AddLog(const std::string& fmt) {
        std::lock_guard<std::mutex> lock(mtx);
        // Add timestamp
        time_t now = time(0);
        tm* ltm = localtime(&now);
        char buf[32];
        strftime(buf, sizeof(buf), "[%H:%M:%S] ", ltm);
        logs.push_back(std::string(buf) + fmt);
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mtx);
        logs.clear();
    }

    void Draw(const char* title) {
        if (ImGui::BeginChild(title, ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), true)) {
            std::lock_guard<std::mutex> lock(mtx);
            for (const auto& item : logs) {
                ImGui::TextUnformatted(item.c_str());
            }
            if (autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();
    }
};

// Key generation and BigInt math helpers
class CryptoUtils {
    static boost::random::mt19937 gen;

public:
    // Generate a prime number using Miller-Rabin test
    static BigInt GeneratePrime(int bits) {
        boost::random::independent_bits_engine<boost::random::mt19937, 256, BigInt> big_gen(gen);
        while (true) {
            BigInt n = big_gen();
            // Ensure the number has the required bit length and is odd
            if (msb(n) < bits - 1) continue; 
            bit_set(n, 0); 
            
            // Miller-Rabin primality test
            if (miller_rabin_test(n, 25, gen)) {
                return n;
            }
        }
    }

    // Generate Key Pair (n, s, v)
    // n = p * q (public modulus)
    // s = secret key (coprime to n)
    // v = s^2 mod n (public key verification value)
    static void GenerateKeyPair(int bits, BigInt& n, BigInt& s, BigInt& v) {
        BigInt p = GeneratePrime(bits / 2);
        BigInt q = GeneratePrime(bits / 2);
        n = p * q;

        // Generate secret 's' such that gcd(s, n) == 1
        boost::random::uniform_int_distribution<BigInt> dist(2, n - 1);
        do {
            s = dist(gen);
        } while (gcd(s, n) != 1);

        // Calculate public v
        v = powm(s, 2, n);
    }

    static BigInt RandomRange(const BigInt& min, const BigInt& max) {
        boost::random::uniform_int_distribution<BigInt> dist(min, max);
        return dist(gen);
    }
};
boost::random::mt19937 CryptoUtils::gen(std::time(0));

// =============================================================
// Server Side Logic
// =============================================================

struct UserData {
    std::string username;
    BigInt n;
    BigInt v;
};

class FiatShamirServer {
    zmq::context_t ctx;
    zmq::socket_t socket;
    std::atomic<bool> running;
    std::thread serverThread;
    
    std::map<std::string, UserData> users;
    const std::string dbFile = "users.json";

public:
    AppLogger logger;

    FiatShamirServer() : ctx(1), socket(ctx, zmq::socket_type::rep), running(false) {
        LoadUsers();
    }

    ~FiatShamirServer() {
        Stop();
    }

    void LoadUsers() {
        if (!fs::exists(dbFile)) return;
        std::ifstream f(dbFile);
        json j;
        f >> j;
        users.clear();
        for (auto& [key, val] : j.items()) {
            UserData u;
            u.username = key;
            u.n = BigInt(val["n"].get<std::string>());
            u.v = BigInt(val["v"].get<std::string>());
            users[key] = u;
        }
        logger.AddLog("User database loaded.");
    }

    void SaveUsers() {
        json j;
        for (const auto& [name, data] : users) {
            j[name] = {
                {"n", data.n.str()},
                {"v", data.v.str()}
            };
        }
        std::ofstream f(dbFile);
        f << j.dump(4);
    }

    void AddUser(const std::string& name, const std::string& n_str, const std::string& v_str) {
        UserData u;
        u.username = name;
        u.n = BigInt(n_str);
        u.v = BigInt(v_str);
        users[name] = u;
        SaveUsers();
        logger.AddLog("User added: " + name);
    }

    const std::map<std::string, UserData>& GetUsers() const { return users; }

    void Start(const std::string& port) {
        if (running) return;
        try {
            socket.bind("tcp://*:" + port);
            running = true;
            logger.AddLog("Server started on port " + port);
            // Thread is started externally via GUI button invoking WorkerLoop_Sequential
        } catch (std::exception& e) {
            logger.AddLog(std::string("Start error: ") + e.what());
        }
    }

    void Stop() {
        if (running) {
            running = false;
            // Shutdown context to break blocking recv calls
            ctx.shutdown(); 
            socket.close();
            if (serverThread.joinable()) {
                serverThread.join();
            }
        }
    }

    // Main Server Loop
    // Handles clients sequentially using the REQ-REP pattern
    void WorkerLoop_Sequential() {
        if (!running) running = true;
        
         while (running) {
            try {
                zmq::message_t request;
                
                // (void) casts to suppress unused result warning
                auto res = socket.recv(request, zmq::recv_flags::none);
                if (!res) continue;
                
                std::string reqStr = request.to_string();
                if (reqStr.empty()) continue;

                json reqJson = json::parse(reqStr);
                
                // 1. Initial Handshake
                if (reqJson["type"] != "hello") {
                    SendJson({{"type", "error"}, {"message", "Expected hello"}});
                    continue;
                }

                std::string user = reqJson["username"];
                int rounds = reqJson.value("rounds", 5);
                
                // 2. User Verification
                if (users.find(user) == users.end()) {
                    logger.AddLog("Unknown user login attempt: " + user);
                    SendJson({{"type", "error"}, {"message", "Unknown user"}});
                    continue;
                }
                
                UserData u = users[user];
                logger.AddLog("Session started: " + user + " (" + std::to_string(rounds) + " rounds)");
                
                // Send public params (N, V) to client
                SendJson({{"type", "params"}, {"n", u.n.str()}, {"v", u.v.str()}});

                bool all_success = true;

                // 3. Interactive Proof Rounds
                for (int i = 0; i < rounds; ++i) {
                    // A. Receive Commitment (x = r^2 mod n)
                    auto resX = socket.recv(request, zmq::recv_flags::none);
                    if (!resX) { all_success = false; break; }

                    json msgX = json::parse(request.to_string());
                    BigInt x(msgX["x"].get<std::string>());
                    logger.AddLog("Round " + std::to_string(i+1) + ": recv x=" + x.str().substr(0,10) + "...");

                    // B. Send Challenge (bit e)
                    int e = CryptoUtils::RandomRange(0, 1).convert_to<int>();
                    SendJson({{"type", "e"}, {"e", e}});
                    logger.AddLog("Round " + std::to_string(i+1) + ": sent challenge e=" + std::to_string(e));

                    // C. Receive Response (y)
                    auto resY = socket.recv(request, zmq::recv_flags::none);
                    if (!resY) { all_success = false; break; }

                    json msgY = json::parse(request.to_string());
                    BigInt y(msgY["y"].get<std::string>());
                    
                    // D. Verification: y^2 == x * v^e (mod n)
                    BigInt left = powm(y, 2, u.n);
                    BigInt right = (x * powm(u.v, e, u.n)) % u.n;
                    
                    bool ok = (left == right);
                    if (!ok) all_success = false;
                    
                    logger.AddLog("Round Result: " + std::string(ok ? "OK" : "FAIL"));
                    
                    SendJson({{"type", "result"}, {"ok", ok}, {"round", i+1}});
                    
                    if (!ok) break; 
                }
                
                // 4. Finalization
                // Wait for client to signal end of rounds to maintain ZMQ frame order
                zmq::message_t finReq;
                (void)socket.recv(finReq, zmq::recv_flags::none); 

                // Send final verdict
                SendJson({{"type", "final"}, {"accepted", all_success}});
                logger.AddLog("Session ended. Verdict: " + std::string(all_success ? "ACCEPTED" : "REJECTED"));

            } 
            catch (zmq::error_t& e) {
                // ETERM means the context was terminated (Application closing)
                if (e.num() == ETERM) {
                    break; 
                }
                logger.AddLog("ZMQ Error: " + std::string(e.what()));
                // Rebind socket to recover from network errors
                if (running) {
                    socket = zmq::socket_t(ctx, zmq::socket_type::rep);
                    try { socket.bind("tcp://*:9000"); } catch(...) {}
                }
            }
            catch (std::exception& e) {
                 logger.AddLog("Session Error: " + std::string(e.what()));
                 if (running) {
                    socket = zmq::socket_t(ctx, zmq::socket_type::rep);
                    try { socket.bind("tcp://*:9000"); } catch(...) {} 
                 }
            }
        }
    }

private:
    void SendJson(const json& j) {
        std::string s = j.dump();
        zmq::message_t reply(s.data(), s.size());
        socket.send(reply, zmq::send_flags::none);
    }
};

// =============================================================
// Client Side Logic
// =============================================================

class FiatShamirClient {
    zmq::context_t ctx;
    zmq::socket_t socket;
    std::string username;
    std::string server_addr;
    
    // Local Keys
    BigInt n, s, v;
    bool hasKeys = false;

public:
    AppLogger logger;

    FiatShamirClient() : ctx(1), socket(ctx, zmq::socket_type::req) {}

    void Setup(const std::string& user, const std::string& addr) {
        username = user;
        server_addr = "tcp://" + addr;
        LoadKeys();
    }

    bool HasKeys() const { return hasKeys; }
    BigInt GetN() const { return n; }
    BigInt GetV() const { return v; }

    void GenerateAndSaveKeys() {
        if (username.empty()) return;
        CryptoUtils::GenerateKeyPair(256, n, s, v);
        
        json j;
        j["n"] = n.str();
        j["s"] = s.str();
        j["v"] = v.str();
        
        std::ofstream f("client_secret_" + username + ".json");
        f << j.dump(4);
        
        hasKeys = true;
        logger.AddLog("Generated new keys (256 bit).");
    }

    void LoadKeys() {
        std::string fname = "client_secret_" + username + ".json";
        if (!fs::exists(fname)) {
            hasKeys = false;
            logger.AddLog("No keys found for " + username);
            return;
        }
        std::ifstream f(fname);
        json j; f >> j;
        n = BigInt(j["n"].get<std::string>());
        s = BigInt(j["s"].get<std::string>());
        v = BigInt(j["v"].get<std::string>());
        hasKeys = true;
        logger.AddLog("Keys loaded from file.");
    }

    // Run the interactive protocol in a separate thread
    void RunProtocolAsync(int rounds) {
        std::thread([this, rounds]() {
            try {
                logger.AddLog("Connecting to " + server_addr + "...");
                socket = zmq::socket_t(ctx, zmq::socket_type::req);
                socket.connect(server_addr);
                socket.set(zmq::sockopt::rcvtimeo, 5000); // 5 sec timeout

                // 1. Send Hello
                json reqHello;
                reqHello["type"] = "hello";
                reqHello["username"] = username;
                reqHello["rounds"] = rounds;
                SendJson(reqHello);

                json resp = RecvJson();

                // Check for server errors
                if (resp.value("type", "") == "error") {
                    throw std::runtime_error("Server Error: " + resp.value("message", "Unknown"));
                }
                
                if (resp["type"] != "params") throw std::runtime_error("Invalid server protocol (no params)");

                BigInt server_n(resp["n"].get<std::string>());
                BigInt server_v(resp["v"].get<std::string>());
                
                logger.AddLog("Received server parameters.");
                logger.AddLog("N: " + server_n.str().substr(0,10) + "...");

                // Security Warning:
                // Check if the server's public key (v) matches our local derived public key (s^2 mod n).
                // If they don't match, authentication will mathematically fail.
                if (server_v != v || server_n != n) {
                     logger.AddLog("WARNING: Server parameters differ from local keys!");
                     logger.AddLog("Authentication will likely fail.");
                }

                // 2. Interactive Loop
                for (int i = 0; i < rounds; ++i) {
                    // A. Commit: Send x = r^2 mod n
                    BigInt r = CryptoUtils::RandomRange(2, n - 1);
                    BigInt x = powm(r, 2, n);
                    
                    logger.AddLog("R" + std::to_string(i+1) + ": Chosen r. Sending x...");
                    SendJson({{"type", "x"}, {"x", x.str()}});

                    // B. Receive Challenge: e (0 or 1)
                    json msgE = RecvJson();
                    int e = msgE["e"].get<int>();
                    logger.AddLog("R" + std::to_string(i+1) + ": Challenge e=" + std::to_string(e));

                    // C. Response: y = r * s^e mod n
                    BigInt y;
                    if (e == 0) y = r;
                    else        y = (r * s) % n;

                    SendJson({{"type", "y"}, {"y", y.str()}});
                    logger.AddLog("R" + std::to_string(i+1) + ": Sent response y.");

                    // D. Round Result
                    json res = RecvJson();
                    if (!res["ok"].get<bool>()) {
                        logger.AddLog("Server rejected round!");
                        return;
                    }
                    logger.AddLog("Server confirmed round.");
                }
                
                // 3. Finalize
                SendJson({{"type", "finalize"}});

                json finalMsg = RecvJson();
                bool accepted = finalMsg["accepted"].get<bool>();
                logger.AddLog("==============================");
                logger.AddLog(accepted ? "AUTHENTICATION SUCCESSFUL" : "ACCESS DENIED");

            } catch (std::exception& e) {
                logger.AddLog("Protocol Error: " + std::string(e.what()));
            }
        }).detach();
    }

private:
    void SendJson(const json& j) {
        std::string s = j.dump();
        socket.send(zmq::buffer(s), zmq::send_flags::none);
    }

    json RecvJson() {
        zmq::message_t msg;
        auto res = socket.recv(msg, zmq::recv_flags::none);
        if (!res) throw std::runtime_error("Timeout or connection lost");
        return json::parse(msg.to_string());
    }
};

// =============================================================
// Main GUI Logic
// =============================================================

// Global instances
FiatShamirServer g_Server;
FiatShamirClient g_Client;

// Input buffers
char buf_server_port[16] = "9000";
char buf_client_login[64] = "user1";
char buf_client_host[64] = "127.0.0.1";
char buf_client_port[16] = "9000";
int  client_rounds = 5;

// Modal buffers
bool show_add_user_modal = false;
char buf_new_login[64] = "";
char buf_new_n[1024] = "";
char buf_new_v[1024] = "";

void RenderApp() {
    // Get window dimensions
    ImGuiIO& io = ImGui::GetIO();
    float width = io.DisplaySize.x;
    float height = io.DisplaySize.y;

    // Window flags for static layout (no move, no resize)
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | 
                                    ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings;

    // Server Window (Left Split)
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(width * 0.5f, height));
    
    ImGui::Begin("Server (Fiat-Shamir)", nullptr, window_flags);
    
    ImGui::InputText("Port", buf_server_port, 16);
    if (ImGui::Button("Start Server")) {
        std::thread([&](){ g_Server.WorkerLoop_Sequential(); }).detach(); 
        g_Server.Start(buf_server_port);
    }
    ImGui::SameLine();
    if (ImGui::Button("Stop")) g_Server.Stop();

    ImGui::Separator();
    ImGui::Text("Registered Users:");
    
    // User List
    ImGui::BeginChild("UserList", ImVec2(0, 150), true);
    auto users = g_Server.GetUsers();
    for (const auto& [name, u] : users) {
        ImGui::Text("%s (n len: %lu)", name.c_str(), u.n.str().length());
        ImGui::SameLine();
        if (ImGui::SmallButton(("Copy keys##" + name).c_str())) {
             ImGui::SetClipboardText(("N: " + u.n.str() + "\nV: " + u.v.str()).c_str());
        }
    }
    ImGui::EndChild();

    if (ImGui::Button("Add Manually")) show_add_user_modal = true;
    ImGui::SameLine();
    if (ImGui::Button("Clear Logs")) g_Server.logger.Clear();

    g_Server.logger.Draw("ServerLogs");
    ImGui::End();

    // Client Window (Right Split)
    ImGui::SetNextWindowPos(ImVec2(width * 0.5f, 0));
    ImGui::SetNextWindowSize(ImVec2(width * 0.5f, height));
    
    ImGui::Begin("Client", nullptr, window_flags);
    
    ImGui::InputText("Host", buf_client_host, 64);
    ImGui::InputText("Server Port", buf_client_port, 16);
    ImGui::InputText("Login", buf_client_login, 64);
    
    if (ImGui::Button("Load / Generate Keys")) {
        g_Client.Setup(buf_client_login, std::string(buf_client_host) + ":" + buf_client_port);
        if (!g_Client.HasKeys()) {
            g_Client.GenerateAndSaveKeys();
        }
    }

    if (g_Client.HasKeys()) {
        ImGui::TextColored(ImVec4(0,1,0,1), "Keys Active");
        // Truncate display of V to avoid GUI breaking
        std::string v_short = g_Client.GetV().str();
        if (v_short.length() > 30) v_short = v_short.substr(0, 30) + "...";
        ImGui::TextWrapped("V: %s", v_short.c_str());
        
        if (ImGui::Button("Register on Server (Demo Hack)")) {
            g_Server.AddUser(buf_client_login, g_Client.GetN().str(), g_Client.GetV().str());
        }
        
        ImGui::SliderInt("Rounds", &client_rounds, 1, 50);
        
        if (ImGui::Button("Authenticate", ImVec2(-1, 0))) {
            g_Client.Setup(buf_client_login, std::string(buf_client_host) + ":" + buf_client_port);
            g_Client.RunProtocolAsync(client_rounds);
        }
    } else {
        ImGui::TextColored(ImVec4(1,0,0,1), "Keys not loaded");
    }

    ImGui::Separator();
    g_Client.logger.Draw("ClientLogs");
    ImGui::End();

    // Modal: Add User Manually
    if (show_add_user_modal) {
        ImGui::OpenPopup("Add User");
        show_add_user_modal = false;
    }

    if (ImGui::BeginPopupModal("Add User", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Login", buf_new_login, 64);
        ImGui::InputText("N", buf_new_n, 1024);
        ImGui::InputText("V", buf_new_v, 1024);

        if (ImGui::Button("Save", ImVec2(120, 0))) {
            g_Server.AddUser(buf_new_login, buf_new_n, buf_new_v);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) { 
            ImGui::CloseCurrentPopup(); 
        }
        ImGui::EndPopup();
    }
}

// =============================================================
// Application Entry Point
// =============================================================
int main(int, char**) {
    if (!glfwInit()) return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Initial window size
    GLFWwindow* window = glfwCreateWindow(1400, 800, "C++ Fiat-Shamir Implementation", NULL, NULL);
    if (!window) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); 

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Font loading: Try to load FiraCode if available, otherwise use default
    std::string fontPath = "./resources/fonts/FiraCode-Regular.ttf";
    if (!std::filesystem::exists(fontPath)) {
        fontPath = "../resources/fonts/FiraCode-Regular.ttf";
    }

    if (std::filesystem::exists(fontPath)) {
        io.Fonts->AddFontFromFileTTF(fontPath.c_str(), 18.0f);
        std::cout << "Font loaded: " << fontPath << std::endl;
    } else {
        io.Fonts->AddFontDefault(); 
    }

    // Main Loop
    while (!glfwWindowShouldClose(window)) {
        // CPU Optimization: Wait for events (mouse/keys) or 0.05s timeout
        glfwWaitEventsTimeout(0.05);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        RenderApp();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // Cleanup
    g_Server.Stop(); // Ensure clean ZMQ shutdown
    
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}