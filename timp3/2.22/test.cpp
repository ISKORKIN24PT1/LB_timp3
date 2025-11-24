
#include <UnitTest++/UnitTest++.h>
#include <string>
#include <locale>
#include <codecvt>
#include "modTableCipher.h"

using namespace std;

// Функции для преобразования широких строк в UTF-8
string wideToUtf8(const wstring& ws) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(ws);
}

wstring utf8ToWide(const string& s) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.from_bytes(s);
}

// Макрос для сравнения широких строк
#define CHECK_WIDE_EQUAL(expected, actual) \
    CHECK_EQUAL(wideToUtf8(expected), wideToUtf8(actual))

// ===== ТАБЛИЦА 1: ТЕСТИРОВАНИЕ КОНСТРУКТОРА =====
SUITE(ConstructorTest)
{
    // 1.1 Верный ключ
    TEST(ValidKey) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    // 1.2 Ключ длиннее сообщения
    TEST(LongKey) {
        Table cipher(10);
        CHECK_WIDE_EQUAL(L"ТЕВИРП", cipher.encrypt(L"ПРИВЕТ"));
    }
    
    // 1.3 Ключ равен длине сообщения
    TEST(KeyEqualsMessageLength) {
        Table cipher(9);
        CHECK_WIDE_EQUAL(L"РИМТЕВИРП", cipher.encrypt(L"ПРИВЕТМИР"));
    }
    
    // 1.4 Отрицательный ключ
    TEST(NegativeKey) {
        CHECK_THROW(Table cipher(-3), cipher_error);
    }
    
    // 1.5 Нулевой ключ
    TEST(ZeroKey) {
        CHECK_THROW(Table cipher(0), cipher_error);
    }
}

// Фикстура для ключа 3
struct Key3Fixture {
    Table* cipher;
    
    Key3Fixture() {
        cipher = new Table(3);
    }
    
    ~Key3Fixture() {
        delete cipher;
    }
};

// Фикстура для ключа 1
struct Key1Fixture {
    Table* cipher;
    
    Key1Fixture() {
        cipher = new Table(1);
    }
    
    ~Key1Fixture() {
        delete cipher;
    }
};

// ===== ТАБЛИЦА 2: ТЕСТИРОВАНИЕ МЕТОДА ENCRYPT =====
SUITE(EncryptTest)
{
    // 2.1 Строка из прописных
    TEST_FIXTURE(Key3Fixture, UpperCaseString) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТМИР"));
    }
    
    // 2.2 Есть строчные
    TEST_FIXTURE(Key3Fixture, LowerCaseString) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"приветмир"));
    }
    
    // 2.3 Есть пробелы
    TEST_FIXTURE(Key3Fixture, StringWithWhitespace) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТ МИР"));
    }
    
    // 2.4 Есть цифры
    TEST_FIXTURE(Key3Fixture, StringWithNumbers) {
        CHECK_WIDE_EQUAL(L"ИТРЕПВ", cipher->encrypt(L"ПРИВЕТ2024"));
    }
    
    // 2.5 Нет букв
    TEST_FIXTURE(Key3Fixture, NoLetters) {
        CHECK_THROW(cipher->encrypt(L"1234"), cipher_error);
    }
    
    // 2.6 Пустой текст
    TEST_FIXTURE(Key3Fixture, EmptyString) {
        CHECK_THROW(cipher->encrypt(L""), cipher_error);
    }
    
    // 2.7 Ключ=1
    TEST_FIXTURE(Key1Fixture, KeyEqualsOne) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->encrypt(L"ПРИВЕТМИР"));
    }
    
    // 2.8 Есть знаки препинания
    TEST_FIXTURE(Key3Fixture, StringWithPunctuation) {
        CHECK_WIDE_EQUAL(L"ИТРРЕИПВМ", cipher->encrypt(L"ПРИВЕТ, МИР"));
    }
    
    // 2.9 Тест на некратный ключ
    TEST(NonMultipleKey) {
        Table cipher(4);
        wstring original = L"АБВГД"; // 5 символов, ключ 4
        wstring encrypted = cipher.encrypt(original);
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_WIDE_EQUAL(original, decrypted);
    }
    
    // 2.10 Тест с коротким текстом
    TEST(ShortText) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"А", cipher.encrypt(L"А"));
    }
}

// ===== ТАБЛИЦА 3: ТЕСТИРОВАНИЕ МЕТОДА DECRYPT =====
SUITE(DecryptTest)
{
    // 3.1 Строка из прописных
    TEST_FIXTURE(Key3Fixture, UpperCaseString) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ИТРРЕИПВМ"));
    }
    
    // 3.2 Есть строчные
    TEST_FIXTURE(Key3Fixture, LowerCaseString) {
        CHECK_THROW(cipher->decrypt(L"итереиПВМ"), cipher_error);
    }
    
    // 3.3 Есть пробелы
    TEST_FIXTURE(Key3Fixture, WhitespaceString) {
        CHECK_THROW(cipher->decrypt(L"ИТР РЕИ ПВМ"), cipher_error);
    }
    
    // 3.4 Есть цифры
    TEST_FIXTURE(Key3Fixture, DigitsString) {
        CHECK_THROW(cipher->decrypt(L"ИТРЕПВ2024"), cipher_error);
    }
    
    // 3.5 Нет букв
    TEST_FIXTURE(Key3Fixture, NoLettersDecrypt) {
        CHECK_THROW(cipher->decrypt(L"1234"), cipher_error);
    }
    
    // 3.6 Пустой текст
    TEST_FIXTURE(Key3Fixture, EmptyStringDecrypt) {
        CHECK_THROW(cipher->decrypt(L""), cipher_error);
    }
    
    // 3.7 Ключ=1
    TEST_FIXTURE(Key1Fixture, KeyEqualsOneDecrypt) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ПРИВЕТМИР"));
    }
    
    // 3.8 Есть знаки препинания
    TEST_FIXTURE(Key3Fixture, ValidCipherText) {
        CHECK_WIDE_EQUAL(L"ПРИВЕТМИР", cipher->decrypt(L"ИТРРЕИПВМ"));
    }
    
    // 3.9 Тест на короткую строку
    TEST(ShortString) {
        Table cipher(5);
        wstring original = L"А"; // 1 символ, ключ 5
        wstring encrypted = cipher.encrypt(original);
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_WIDE_EQUAL(original, decrypted);
    }
    
    // 3.10 Тест с коротким шифротекстом
    TEST(ShortCipherText) {
        Table cipher(3);
        CHECK_WIDE_EQUAL(L"А", cipher.decrypt(L"А"));
    }
}

int main(int argc, char** argv)
{
    locale::global(locale(""));
    return UnitTest::RunAllTests();
}

