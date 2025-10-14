// main.cpp
#include "gui.h"
#include <iostream>

int main() {
    std::cout << "Запуск криптографических протоколов с GUI..." << std::endl;
    
    CryptoGUI app;
    
    if (!app.Initialize()) {
        std::cerr << "Ошибка инициализации приложения" << std::endl;
        return -1;
    }
    
    app.Run();
    
    return 0;
}
