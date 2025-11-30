/**
 * @file UnitTest.cpp
 * @brief Модульные тесты для класса Table
 * @details Содержит тестовые сценарии для проверки табличной маршрутной перестановки
 * @author Искоркин Андрей
 * @version 1.0
 * @date 30.11.2025
 */

#include <UnitTest++/UnitTest++.h>
#include <string>
#include <locale>
#include <codecvt>
#include "modTableCipher.h"

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
 */
#define CHECK_WIDE_EQUAL(expected, actual) \
    CHECK_EQUAL(wideToUtf8(expected), wideToUtf8(actual))

/**
 * @brief Test Suite для тестирования конструктора
 */
SUITE(ConstructorTest)
{
    /**
     * @brief Тест валидного ключа
     */
    TEST(ValidKey) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    /**
     * @brief Тест длинного ключа
     */
    TEST(LongKey) {
        Table cipher(10);
        CHECK_WIDE_EQUAL(L"ТЕВИРП", cipher.encrypt(L"ПРИВЕТ"));
    }

    /**
     * @brief Тест ключа равного длине сообщения
     */
    TEST(KeyEqualsMessageLength) {
        Table cipher(9);
        CHECK_WIDE_EQUAL(L"РИМТЕВИРП", cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    /**
     * @brief Тест отрицательного ключа
     */
    TEST(NegativeKey) {
        CHECK_THROW(Table cipher(-3), cipher_error);
    }

    /**
     * @brief Тест нулевого ключа
     */
    TEST(ZeroKey) {
        CHECK_THROW(Table cipher(0), cipher_error);
    }
}

/**
 * @brief Фикстура для тестов с ключом 3
 */
struct Key3Fixture {
    Table* cipher;
    
    /**
     * @brief Конструктор фикстуры
     */
    Key3Fixture() {
        cipher = new Table(3);
    }
    
    /**
     * @brief Деструктор фикстуры
     */
    ~Key3Fixture() {
        delete cipher;
    }
};

/**
 * @brief Фикстура для тестов с ключом 1
 */
struct Key1Fixture {
    Table* cipher;
    
    /**
     * @brief Конструктор фикстуры
     */
    Key1Fixture() {
        cipher = new Table(1);
    }
    
    /**
     * @brief Деструктор фикстуры
     */
    ~Key1Fixture() {
        delete cipher;
    }
};

/**
 * @brief Test Suite для тестирования шифрования
 */
SUITE(EncryptTest)
{
    /**
     * @brief Тест шифрования строки в верхнем регистре
     */
    TEST_FIXTURE(Key3Fixture, UpperCaseString) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТМИР"));
    }
    
    /**
     * @brief Тест шифрования строки в нижнем регистре
     */
    TEST_FIXTURE(Key3Fixture, LowerCaseString) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"приветмир"));
    }

    /**
     * @brief Тест шифрования строки с пробелами
     */
    TEST_FIXTURE(Key3Fixture, StringWithWhitespace) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТ МИР"));
    }
    
    /**
     * @brief Тест шифрования строки с цифрами
     */
    TEST_FIXTURE(Key3Fixture, StringWithNumbers) {
        CHECK_WIDE_EQUAL(L"ИТРЕПВ", cipher->encrypt(L"ПРИВЕТ2024"));
    }

    /**
     * @brief Тест шифрования строки без букв
     */
    TEST_FIXTURE(Key3Fixture, NoLetters) {
        CHECK_THROW(cipher->encrypt(L"1234"), cipher_error);
    }
    
    /**
     * @brief Тест шифрования пустой строки
     */
    TEST_FIXTURE(Key3Fixture, EmptyString) {
        CHECK_THROW(cipher->encrypt(L""), cipher_error);
    }
    
    /**
     * @brief Тест шифрования с ключом 1
     */
    TEST_FIXTURE(Key1Fixture, KeyEqualsOne) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->encrypt(L"ПРИВЕТМИР"));
    }

    /**
     * @brief Тест шифрования строки с пунктуацией
     */
    TEST_FIXTURE(Key3Fixture, StringWithPunctuation) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТ, МИР"));
    }
    
    /**
     * @brief Тест шифрования с ключом не кратным длине текста
     */
    TEST(NonMultipleKey) {
        Table cipher(4);
        wstring original = L"АБВГД";
        wstring encrypted = cipher.encrypt(original);
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_WIDE_EQUAL(original, decrypted);
    }

    /**
     * @brief Тест шифрования короткого текста
     */
    TEST(ShortText) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"А", cipher.encrypt(L"А"));
    }
}

/**
 * @brief Test Suite для тестирования дешифрования
 */
SUITE(DecryptTest)
{
    /**
     * @brief Тест дешифрования строки в верхнем регистре
     */
    TEST_FIXTURE(Key3Fixture, UpperCaseString) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ИТРРЕИПВМ"));
    }

    /**
     * @brief Тест дешифрования строки с строчными буквами
     */
    TEST_FIXTURE(Key3Fixture, LowerCaseString) {
        CHECK_THROW(cipher->decrypt(L"итереиПВМ"), cipher_error);
    }

    /**
     * @brief Тест дешифрования строки с пробелами
     */
    TEST_FIXTURE(Key3Fixture, WhitespaceString) {
        CHECK_THROW(cipher->decrypt(L"ИТР РЕИ ПВМ"), cipher_error);
    }

    /**
     * @brief Тест дешифрования строки с цифрами
     */
    TEST_FIXTURE(Key3Fixture, DigitsString) {
        CHECK_THROW(cipher->decrypt(L"ИТРЕПВ2024"), cipher_error);
    }

    /**
     * @brief Тест дешифрования строки без букв
     */
    TEST_FIXTURE(Key3Fixture, NoLettersDecrypt) {
        CHECK_THROW(cipher->decrypt(L"1234"), cipher_error);
    }

    /**
     * @brief Тест дешифрования пустой строки
     */
    TEST_FIXTURE(Key3Fixture, EmptyStringDecrypt) {
        CHECK_THROW(cipher->decrypt(L""), cipher_error);
    }

    /**
     * @brief Тест дешифрования с ключом 1
     */
    TEST_FIXTURE(Key1Fixture, KeyEqualsOneDecrypt) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ПРИВЕТМИР"));
    }

    /**
     * @brief Тест дешифрования валидного шифротекста
     */
    TEST_FIXTURE(Key3Fixture, ValidCipherText) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ИТРРЕИПВМ"));
    }

    /**
     * @brief Тест дешифрования короткой строки
     */
    TEST(ShortString) {
        Table cipher(5);
        wstring original = L"А";
        wstring encrypted = cipher.encrypt(original);
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_WIDE_EQUAL(original, decrypted);
    }

    /**
     * @brief Тест дешифрования короткого шифротекста
     */
    TEST(ShortCipherText) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"А", cipher.decrypt(L"А"));
    }
}

/**
 * @brief Главная функция запуска тестов
 * @return Код завершения тестирования
 */
int main(int argc, char** argv)
{
    locale::global(locale(""));
    return UnitTest::RunAllTests();
}
