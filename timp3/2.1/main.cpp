/**
 * @file
 * @brief Главный модуль для тестирования шифра Гронсфельда
 * @details Содержит функции для проверки работы модуля шифрования
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#include <iostream>
#include <locale>
#include "modAlphaCipher.h"

using namespace std;

/**
 * @brief Функция проверки работы шифратора
 * @param [in] Text Исходный текст для проверки
 * @param [in] key Ключ шифрования
 * @param [in] destructCipherText Флаг для порчи зашифрованного текста (по умолчанию false)
 * @throw cipher_error Может возбуждать исключения при ошибках шифрования
 */
void check(const wstring& Text, const wstring& key, bool destructCipherText = false) {
    try {
        wstring cipherText;    /// Зашифрованный текст
        wstring decryptedText; /// Расшифрованный текст
        modAlphaCipher cipher(key); /// Экземпляр шифратора
        
        // Зашифровывание исходного текста
        cipherText = cipher.encrypt(Text);
        
        // Если установлен флаг destructCipherText, портим первый символ зашифрованного текста
        if (destructCipherText) {
            cipherText.front() = towlower(cipherText.front());
        }
        
        // Расшифровывание текста
        decryptedText = cipher.decrypt(cipherText);
        
        // Вывод результатов
        wcout << L"key=" << key << endl;
        wcout << L"Original: " << Text << endl;
        wcout << L"Encrypted: " << cipherText << endl;
        wcout << L"Decrypted: " << decryptedText << endl;
        
        // Проверка корректности расшифровывания
        if (Text == decryptedText)
            wcout << L"Ok\n";
        else
            wcout << L"Err\n";
        wcout << endl;
    } catch (const cipher_error& e) {
        // Обработка исключений шифрования
        wcout << L"Error: " << e.what() << endl << endl;
    }
}

/**
 * @brief Главная функция программы
 * @return Код завершения программы
 * @details Выполняет серию тестов шифрования с различными параметрами
 */
int main() {
    setlocale(LC_ALL, ""); ///< Установка локали для поддержки кириллицы
    
    // Позитивные тесты - корректные данные
    check(L"ААААА", L"МИР");           /// Тест с повторяющимися символами
    check(L"ПРИВЕТ", L"МИР");          /// Тест с обычным текстом
    check(L"привет", L"мир");          /// Тест со строчными буквами
    check(L"доброе утро, ёж", L"Мир"); /// Тест с пробелами, запятой и буквой "ё"
    
    // Тесты с исключениями - некорректные данные
    check(L"ПРИВЕТ", L"");          /// Тест с пустым ключом
    check(L"ПРИВЕТ", L"МИР123");    /// Тест с ключом, содержащим цифры
    check(L"123", L"МИР");          /// Тест с текстом без букв
    check(L"ПРИВЕТ", L"МИР", true); /// Тест с испорченным шифротекстом
    
    return 0; ///< Успешное завершение программы
}
