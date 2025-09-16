#include <ElfReader.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <conio.h>

static void PrintLine(const std::wstring& text) {
    DWORD written = 0;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        WriteConsoleW(hOut, text.c_str(), static_cast<DWORD>(text.size()), &written, nullptr);
        WriteConsoleW(hOut, L"\r\n", 2, &written, nullptr);
    }
}


void __stdcall MyBuildCallback(const callback::BuildEvent* ev) {
    if (ev->message) {
        PrintLine(std::wstring(L"[CALLBACK]") + to_string(ev->result) + ev->message);
    }
}


int wmain()
{
	setlocale(LC_ALL, "Russian");
	PrintLine(L"Введите корневой путь к папке с проектом: ");
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1 || _setmode(_fileno(stdin), _O_U16TEXT) == -1) {
        return 1;
    }

    std::wstring basePath;
    std::getline(std::wcin, basePath);

    std::vector<elfreader::LineEntry> lines;
    std::vector<std::string> linesPOUS = {"POUS.c"};
	elfreader::ElfReader reader(MyBuildCallback);
    auto result = reader.ParseDebugLine(std::filesystem::path(basePath), lines, linesPOUS);

    for (const auto& entry : lines)
    {
        std::wstring message =
            L"Файл: " + std::wstring(entry.file.begin(), entry.file.end()) +
            L", Адрес: " + std::wstring(entry.address.begin(), entry.address.end()) +
            L", Линия: " + std::to_wstring(entry.line) +
            L", is_stmt: " + (entry.is_stmt ? L"true" : L"false") +
            L", basic_block: " + (entry.basic_block ? L"true" : L"false") +
            L", view: " + std::to_wstring(entry.view);

        callback::SendCallback(message.c_str(), Ok, MyBuildCallback);
    }

    PrintLine(L"Завершено успешно с кодом: " + std::to_wstring(result));
    std::wcout << L"Нажмите любую клавишу для выхода..." << std::endl;
    _getch();
}