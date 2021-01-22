#include <iostream>
#include <string>
#include <Windows.h>
#include "auxilary.hpp"


const static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
constexpr static char LIGHT_GREEN = 10;
constexpr static char LIGHT_RED   = 12;
constexpr static char WHITE	   = 7;

void good_message(const std::string& message) noexcept {
	SetConsoleTextAttribute(hConsole, LIGHT_GREEN);
	std::cout << message << std::endl;
	SetConsoleTextAttribute(hConsole, WHITE);
}

void bad_message(const std::string& message) noexcept {
    SetConsoleTextAttribute(hConsole, LIGHT_RED);
    std::cout << message << std::endl;
    SetConsoleTextAttribute(hConsole, WHITE);
}

void print_help() noexcept {
    std::string message =
    "Welcome to Project Cry!\n"
    "\n";
    "Project Cry is a simple file cryptor. "
}
