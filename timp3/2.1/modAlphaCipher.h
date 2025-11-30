/**
 * @file modAlphaCipher.h
 * @brief Заголовочный файл для класса modAlphaCipher
 * @details Реализация шифра Гронсфельда для русского алфавита
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#pragma once
#include <vector>
#include <string>
#include <map>
#include <stdexcept>
#include <cwctype>  /// Для wide character функций

/**
 * @brief Класс исключений для ошибок шифрования
 * @details Наследуется от std::invalid_argument
 */
class cipher_error : public std::invalid_argument {
public:
    /**
     * @brief Конструктор с строковым параметром
     * @param [in] what_arg Сообщение об ошибке
     */
    explicit cipher_error(const std::string& what_arg) : std::invalid_argument(what_arg) {}
    
    /**
     * @brief Конструктор с C-строкой
     * @param [in] what_arg Сообщение об ошибке
     */
    explicit cipher_error(const char* what_arg) : std::invalid_argument(what_arg) {}
};

/**
 * @brief Класс для шифрования методом Гронсфельда
 * @details Реализует шифрование и дешифрование текста на русском языке
 */
class modAlphaCipher {
private:
    std::wstring numAlpha = L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"; /// Русский алфавит
    std::map<wchar_t, int> alphaNum; /// Ассоциативный массив "символ-номер"
    std::vector<int> key; /// Ключ шифрования в числовом виде

    /**
     * @brief Преобразование строки в числовой вектор
     * @param [in] s Строка для преобразования
     * @return Вектор числовых представлений символов
     */
    std::vector<int> convert(const std::wstring& s);
    
    /**
     * @brief Преобразование числового вектора в строку
     * @param [in] v Числовой вектор для преобразования
     * @return Строка, восстановленная из числовых представлений
     */
    std::wstring convert(const std::vector<int>& v);
    
    /**
     * @brief Преобразование символа в верхний регистр
     * @param [in] c Символ для преобразования
     * @return Символ в верхнем регистре
     */
    static wchar_t toUpper(wchar_t c);
    
    /**
     * @brief Валидация ключа шифрования
     * @param [in] s Ключ для проверки
     * @return Валидный ключ в верхнем регистре
     * @throw cipher_error Если ключ пустой или содержит не-буквенные символы
     */
    std::wstring getValidKey(const std::wstring& s);
    
    /**
     * @brief Валидация открытого текста
     * @param [in] s Текст для проверки
     * @return Валидный текст только с буквами в верхнем регистре
     * @throw cipher_error Если текст не содержит букв после очистки
     */
    std::wstring getValidOpenText(const std::wstring& s);
    
    /**
     * @brief Валидация зашифрованного текста
     * @param [in] s Зашифрованный текст для проверки
     * @return Валидный зашифрованный текст
     * @throw cipher_error Если текст пустой или содержит не-прописные буквы
     */
    std::wstring getValidCipherText(const std::wstring& s);
    
public:
    /**
     * @brief Удаленный конструктор по умолчанию
     * @details Запрещено создание объекта без ключа
     */
    modAlphaCipher() = delete;
    
    /**
     * @brief Конструктор с параметром ключа
     * @param [in] skey Ключ шифрования
     * @throw cipher_error Если ключ невалиден
     */
    modAlphaCipher(const std::wstring& skey);
    
    /**
     * @brief Шифрование открытого текста
     * @param [in] open_text Открытый текст для шифрования
     * @return Зашифрованный текст
     * @throw cipher_error Если текст невалиден
     */
    std::wstring encrypt(const std::wstring& open_text);
    
    /**
     * @brief Дешифрование зашифрованного текста
     * @param [in] cipher_text Зашифрованный текст для дешифрования
     * @return Расшифрованный текст
     * @throw cipher_error Если текст невалиден
     */
    std::wstring decrypt(const std::wstring& cipher_text);
};
