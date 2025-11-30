/**
 * @file modTableCipher.cpp
 * @brief Реализация класса Table для табличной маршрутной перестановки
 * @details Содержит реализацию всех методов класса Table для шифрования методом табличной маршрутной перестановки
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#include "modTableCipher.h"
#include <algorithm>
#include <vector>
#include <cwctype>

using namespace std;

/**
 * @brief Валидация ключа шифрования
 * @param [in] key Ключ для проверки
 * @return Валидный ключ
 * @throw cipher_error Если ключ невалиден
 */
int Table::getValidKey(const int key)
{
    if (key <= 0)
        throw cipher_error("Invalid key: cannot be zero");
    if (key < 0)
        throw cipher_error("Invalid key: cannot be negative");
    if (key > 100)
        throw cipher_error("Invalid key: too large");
    return key;
}

/**
 * @brief Валидация открытого текста
 * @param [in] s Текст для проверки
 * @return Валидный текст только с русскими буквами в верхнем регистре
 * @throw cipher_error Если текст не содержит валидных русских букв
 */
std::wstring Table::getValidOpenText(const std::wstring& s)
{
    std::wstring tmp;
    std::wstring lower = L"абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    std::wstring upper = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    
    for (auto c : s) {
        if (upper.find(c) != std::wstring::npos) {
            tmp.push_back(c);
        } else {
            size_t pos = lower.find(c);
            if (pos != std::wstring::npos) {
                tmp.push_back(upper[pos]); 
            }
        }
    }
    if (tmp.empty())
        throw cipher_error("Empty text: no valid Russian letters");
    return tmp;
}

/**
 * @brief Валидация зашифрованного текста
 * @param [in] s Зашифрованный текст для проверки
 * @return Валидный зашифрованный текст
 * @throw cipher_error Если текст пустой или содержит не-прописные русские буквы
 */
std::wstring Table::getValidCipherText(const std::wstring& s)
{
    if (s.empty())
        throw cipher_error("Empty cipher text");
    
    std::wstring upper = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    for (auto c : s) {
        if (upper.find(c) == std::wstring::npos)
            throw cipher_error("Invalid cipher text");
    }
    return s;
}

/**
 * @brief Конструктор класса Table
 * @param [in] key Ключ шифрования (количество столбцов)
 * @throw cipher_error Если ключ невалиден
 */
Table::Table(int key)
{
    cols = getValidKey(key);
}

/**
 * @brief Шифрование открытого текста
 * @param [in] plain Открытый текст для шифрования
 * @return Зашифрованный текст
 * @throw cipher_error Если текст невалиден
 */
std::wstring Table::encrypt(const std::wstring& plain)
{
    std::wstring validText = getValidOpenText(plain);
    int n = static_cast<int>(validText.length());
    
    if (n == 0) return L"";
    
    int rows = (n + cols - 1) / cols;
    
    vector<vector<wchar_t>> table(rows, vector<wchar_t>(cols, L' '));
    int index = 0;
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < cols; col++) {
            if (index < n) {
                table[row][col] = validText[index++];
            }
        }
    }
    
    std::wstring result;
    for (int col = cols - 1; col >= 0; col--) {
        for (int row = 0; row < rows; row++) {
            if (table[row][col] != L' ') {
                result += table[row][col];
            }
        }
    }
    
    return result;
}

/**
 * @brief Дешифрование зашифрованного текста
 * @param [in] cipher Зашифрованный текст для дешифрования
 * @return Расшифрованный текст
 * @throw cipher_error Если текст невалиден
 */
std::wstring Table::decrypt(const std::wstring& cipher)
{
    std::wstring validText = getValidCipherText(cipher);
    int n = static_cast<int>(validText.length());
    
    if (n == 0) return L"";
    
    int rows = (n + cols - 1) / cols;
    
    int fullCols = n % cols;
    if (fullCols == 0) fullCols = cols;
    
    vector<vector<wchar_t>> table(rows, vector<wchar_t>(cols, L' '));
    int index = 0;
    
    for (int col = cols - 1; col >= 0; col--) {
        int rowsInCol = rows;
        if (col >= fullCols) {
            rowsInCol = rows - 1;
        }
        
        for (int row = 0; row < rowsInCol; row++) {
            if (index < n) {
                table[row][col] = validText[index++];
            }
        }
    }
    
    std::wstring result;
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < cols; col++) {
            if (table[row][col] != L' ') {
                result += table[row][col];
            }
        }
    }
    
    return result;
}
