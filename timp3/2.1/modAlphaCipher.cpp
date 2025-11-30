/**
 * @file modAlphaCipher.cpp
 * @brief Реализация класса modAlphaCipher для шифрования методом Гронсфельда
 * @details Содержит реализацию всех методов класса modAlphaCipher
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#include "modAlphaCipher.h"
#include <cctype>
#include <algorithm>
#include <cwctype>  /// Для wide character функций

/**
 * @brief Конструктор класса modAlphaCipher
 * @param [in] skey Ключ шифрования
 * @throw cipher_error Если ключ невалиден
 * @details Инициализирует алфавит и преобразует ключ в числовой вектор
 */
modAlphaCipher::modAlphaCipher(const std::wstring& skey) {
    // Инициализация ассоциативного массива "символ-номер"
    for (size_t i = 0; i < numAlpha.size(); ++i) {
        alphaNum[numAlpha[i]] = static_cast<int>(i);
    }
    // Валидация и преобразование ключа
    key = convert(getValidKey(skey));
}

/**
 * @brief Преобразование символа в верхний регистр для русского алфавита
 * @param [in] c Символ для преобразования
 * @return Символ в верхнем регистре
 */
wchar_t modAlphaCipher::toUpper(wchar_t c) {
    // Обработка русских строчных букв
    if (c >= L'а' && c <= L'я') {
        return L'А' + (c - L'а');
    }
    // Обработка буквы "ё"
    if (c == L'ё') {
        return L'Ё';
    }
    // Стандартное преобразование для других символов
    return std::towupper(c);
}

/**
 * @brief Валидация ключа шифрования
 * @param [in] s Ключ для проверки
 * @return Валидный ключ в верхнем регистре
 * @throw cipher_error Если ключ пустой или содержит не-буквенные символы
 */
std::wstring modAlphaCipher::getValidKey(const std::wstring& s) {
    // Проверка на пустой ключ
    if (s.empty()) {
        throw cipher_error("Empty key");
    }
    std::wstring tmp(s);
    // Проверка каждого символа ключа
    for (auto& c : tmp) {
        if (!std::iswalpha(c)) {
            throw cipher_error("Invalid key: non-alphabetic character");
        }
        // Преобразование строчных букв в прописные
        if (std::iswlower(c)) {
            c = toUpper(c);
        }
    }
    return tmp;
}

/**
 * @brief Валидация открытого текста
 * @param [in] s Текст для проверки
 * @return Валидный текст только с буквами в верхнем регистре
 * @throw cipher_error Если текст не содержит букв после очистки
 */
std::wstring modAlphaCipher::getValidOpenText(const std::wstring& s) {
    std::wstring tmp;
    // Фильтрация текста: оставляем только буквы
    for (auto c : s) {
        if (std::iswalpha(c)) {
            // Преобразование строчных букв в прописные
            if (std::iswlower(c)) {
                tmp.push_back(toUpper(c));
            } else {
                tmp.push_back(c);
            }
        }
    }
    // Проверка на пустой текст после фильтрации
    if (tmp.empty()) {
        throw cipher_error("Empty text, no letters");
    }
    return tmp;
}

/**
 * @brief Валидация зашифрованного текста
 * @param [in] s Зашифрованный текст для проверки
 * @return Валидный зашифрованный текст
 * @throw cipher_error Если текст пустой или содержит не-прописные буквы
 */
std::wstring modAlphaCipher::getValidCipherText(const std::wstring& s) {
    // Проверка на пустой зашифрованный текст
    if (s.empty()) {
        throw cipher_error("Empty cipher text");
    }
    // Проверка что все символы - прописные буквы
    for (auto c : s) {
        if (!std::iswupper(c)) {
            throw cipher_error("Incorrect data entry");
        }
    }
    return s;
}

/**
 * @brief Преобразование строки в числовой вектор
 * @param [in] s Строка для преобразования
 * @return Вектор числовых представлений символов
 */
std::vector<int> modAlphaCipher::convert(const std::wstring& s) {
    std::vector<int> result;
    // Преобразование каждого символа в его числовое представление
    for (auto c : s) {
        wchar_t upperC = toUpper(c);
        if (alphaNum.find(upperC) != alphaNum.end()) {
            result.push_back(alphaNum[upperC]);
        }
    }
    return result;
}

/**
 * @brief Преобразование числового вектора в строку
 * @param [in] v Числовой вектор для преобразования
 * @return Строка, восстановленная из числовых представлений
 */
std::wstring modAlphaCipher::convert(const std::vector<int>& v) {
    std::wstring result;
    // Преобразование каждого числа обратно в символ
    for (auto i : v) {
        if (i >= 0 && i < static_cast<int>(numAlpha.size())) {
            result.push_back(numAlpha[i]);
        }
    }
    return result;
}

/**
 * @brief Шифрование открытого текста
 * @param [in] open_text Открытый текст для шифрования
 * @return Зашифрованный текст
 * @throw cipher_error Если текст невалиден
 */
std::wstring modAlphaCipher::encrypt(const std::wstring& open_text) {
    // Преобразование текста в числовой вектор
    std::vector<int> work = convert(getValidOpenText(open_text));
    // Шифрование каждого символа
    for (size_t i = 0; i < work.size(); ++i) {
        work[i] = (work[i] + key[i % key.size()]) % numAlpha.size();
    }
    // Преобразование обратно в строку
    return convert(work);
}

/**
 * @brief Дешифрование зашифрованного текста
 * @param [in] cipher_text Зашифрованный текст для дешифрования
 * @return Расшифрованный текст
 * @throw cipher_error Если текст невалиден
 */
std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text) {
    // Преобразование текста в числовой вектор
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    // Дешифрование каждого символа
    for (size_t i = 0; i < work.size(); ++i) {
        work[i] = (work[i] + numAlpha.size() - key[i % key.size()]) % numAlpha.size();
    }
    // Преобразование обратно в строку
    return convert(work);
}
