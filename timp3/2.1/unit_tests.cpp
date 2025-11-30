/**
 * @file UnitTest.cpp
 * @brief Модульные тесты для класса modAlphaCipher
 * @details Содержит тестовые сценарии для проверки шифра Гронсфельда
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <iostream>
#include <locale>
#include <codecvt>
#include <string>

using namespace std;

/**
 * @brief Преобразование wide string в UTF-8 string
 * @param [in] ws Строка в формате wstring
 * @return Строка в формате UTF-8
 */
string wideToUtf8(const wstring& ws) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(ws);
}

/**
 * @brief Преобразование UTF-8 string в wide string
 * @param [in] s Строка в формате UTF-8
 * @return Строка в формате wstring
 */
wstring utf8ToWide(const string& s) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.from_bytes(s);
}

/**
 * @brief Макрос для сравнения wide string в тестах
 * @param expected Ожидаемое значение
 * @param actual Фактическое значение
 */
#define CHECK_EQUAL_WS(expected, actual) \
    CHECK_EQUAL(wideToUtf8(expected), wideToUtf8(actual))

/**
 * @brief Фикстура для тестов с ключом "В"
 * @details Создает и уничтожает экземпляр шифратора для группы тестов
 */
struct KeyV_fixture {
    modAlphaCipher* p; /// Указатель на экземпляр шифратора
    
    /**
     * @brief Конструктор фикстуры
     * @details Создает шифратор с ключом "В"
     */
    KeyV_fixture() {
        p = new modAlphaCipher(L"В");
    }
    
    /**
     * @brief Деструктор фикстуры
     * @details Освобождает память шифратора
     */
    ~KeyV_fixture() {
        delete p;
    }
};

/**
 * @brief Test Suite для тестирования ключей
 * @details Проверяет различные сценарии работы с ключами шифрования
 */
SUITE(KeyTest)
{
    /**
     * @brief Тест валидного ключа
     * @details Проверяет работу с корректным ключом
     */
    TEST(ValidKey) {
        CHECK_EQUAL_WS(L"МИРМИ", modAlphaCipher(L"МИР").encrypt(L"ААААА"));
    }
    
    /**
     * @brief Тест длинного ключа
     * @details Проверяет работу с ключом длиннее текста
     */
    TEST(LongKey) {
        CHECK_EQUAL_WS(L"ДЛИНН", modAlphaCipher(L"ДЛИННЫЙКЛЮЧ").encrypt(L"ААААА"));
    }
    
    /**
     * @brief Тест ключа в нижнем регистре
     * @details Проверяет автоматическое преобразование регистра ключа
     */
    TEST(LowCaseKey) {
        CHECK_EQUAL_WS(L"МИРМИ", modAlphaCipher(L"мир").encrypt(L"ААААА"));
    }
    
    /**
     * @brief Тест ключа с цифрами
     * @details Проверяет возбуждение исключения при цифрах в ключе
     */
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР123"), cipher_error);
    }
    
    /**
     * @brief Тест ключа с пунктуацией
     * @details Проверяет возбуждение исключения при знаках препинания в ключе
     */
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР,МИР"), cipher_error);
    }
    
    /**
     * @brief Тест ключа с пробелами
     * @details Проверяет возбуждение исключения при пробелах в ключе
     */
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР МИР"), cipher_error);
    }
    
    /**
     * @brief Тест пустого ключа
     * @details Проверяет возбуждение исключения при пустом ключе
     */
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(L""), cipher_error);
    }
    
    /**
     * @brief Тест слабого ключа
     * @details Проверяет работу с ключом из одинаковых символов
     */
    TEST(WeakKey) {
        modAlphaCipher cipher(L"А");
        wstring encrypted = cipher.encrypt(L"ТЕСТ");
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_EQUAL_WS(L"ТЕСТ", decrypted);
    }
}

/**
 * @brief Test Suite для тестирования шифрования
 * @details Проверяет различные сценарии шифрования текста
 */
SUITE(EncryptTest)
{
    /**
     * @brief Тест шифрования строки в верхнем регистре
     * @details Проверяет шифрование текста из прописных букв
     */
    TEST_FIXTURE(KeyV_fixture, UpCaseString) {
        CHECK_EQUAL_WS(L"СТКДЖФ", p->encrypt(L"ПРИВЕТ"));
    }
    
    /**
     * @brief Тест шифрования строки в нижнем регистре
     * @details Проверяет автоматическое преобразование регистра при шифровании
     */
    TEST_FIXTURE(KeyV_fixture, LowCaseString) {
        CHECK_EQUAL_WS(L"СТКДЖФ", p->encrypt(L"привет"));
    }
    
    /**
     * @brief Тест шифрования строки с пробелами и пунктуацией
     * @details Проверяет фильтрацию не-буквенных символов при шифровании
     */
    TEST_FIXTURE(KeyV_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL_WS(L"СТКДЖФОКТ", p->encrypt(L"ПРИВЕТ, МИР!"));
    }
    
    /**
     * @brief Тест шифрования строки с цифрами
     * @details Проверяет удаление цифр при шифровании
     */
    TEST_FIXTURE(KeyV_fixture, StringWithNumbers) {
        CHECK_EQUAL_WS(L"ФЖУФ", p->encrypt(L"ТЕСТ123"));
    }
    
    /**
     * @brief Тест шифрования пустой строки
     * @details Проверяет возбуждение исключения при пустом тексте
     */
    TEST_FIXTURE(KeyV_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    /**
     * @brief Тест шифрования строки без букв
     * @details Проверяет возбуждение исключения при отсутствии букв в тексте
     */
    TEST_FIXTURE(KeyV_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    
    /**
     * @brief Тест шифрования с максимальным сдвигом
     * @details Проверяет шифрование с ключом "Я" (максимальный сдвиг)
     */
    TEST(MaxShiftKey) {
        CHECK_EQUAL_WS(L"ОПЗБДС", modAlphaCipher(L"Я").encrypt(L"ПРИВЕТ"));
    }
}

/**
 * @brief Test Suite для тестирования дешифрования
 * @details Проверяет различные сценарии дешифрования текста
 */
SUITE(DecryptTest)
{
    /**
     * @brief Тест дешифрования строки в верхнем регистре
     * @details Проверяет корректное дешифрование валидного текста
     */
    TEST_FIXTURE(KeyV_fixture, UpCaseString) {
        CHECK_EQUAL_WS(L"ПРИВЕТ", p->decrypt(L"СТКДЖФ"));
    }
    
    /**
     * @brief Тест дешифрования строки с строчными буквами
     * @details Проверяет возбуждение исключения при строчных буквах в шифротексте
     */
    TEST_FIXTURE(KeyV_fixture, LowCaseString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        encrypted[0] = towlower(encrypted[0]);
        CHECK_THROW(p->decrypt(encrypted), cipher_error);
    }
    
    /**
     * @brief Тест дешифрования строки с пробелами
     * @details Проверяет возбуждение исключения при пробелах в шифротексте
     */
    TEST_FIXTURE(KeyV_fixture, WhitespaceString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = encrypted + L" ";
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    /**
     * @brief Тест дешифрования строки с цифрами
     * @details Проверяет возбуждение исключения при цифрах в шифротексте
     */
    TEST_FIXTURE(KeyV_fixture, DigitsString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = encrypted + L"123";
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    /**
     * @brief Тест дешифрования строки с пунктуацией
     * @details Проверяет возбуждение исключения при знаках препинания в шифротексте
     */
    TEST_FIXTURE(KeyV_fixture, PunctString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = L"!" + encrypted;
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    /**
     * @brief Тест дешифрования пустой строки
     * @details Проверяет возбуждение исключения при пустом шифротексте
     */
    TEST_FIXTURE(KeyV_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    
    /**
     * @brief Тест дешифрования с максимальным сдвигом
     * @details Проверяет дешифрование с ключом "Я" (максимальный сдвиг)
     */
    TEST(MaxShiftKey) {
        CHECK_EQUAL_WS(L"ПРИВЕТ", modAlphaCipher(L"Я").decrypt(L"ОПЗБДС"));
    }
}

/**
 * @brief Главная функция запуска тестов
 * @return Код завершения тестирования
 * @details Устанавливает локаль и запускает все тесты
 */
int main() {
    setlocale(LC_ALL, ""); /// Установка локали для поддержки кириллицы
    return UnitTest::RunAllTests(); /// Запуск всех тестов
}
