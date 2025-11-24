#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <iostream>
#include <locale>
#include <codecvt>
#include <string>

using namespace std;

string wideToUtf8(const wstring& ws) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(ws);
}

wstring utf8ToWide(const string& s) {
    wstring_convert<codecvt_utf8<wchar_t>> conv;
    return conv.from_bytes(s);
}

#define CHECK_EQUAL_WS(expected, actual) \
    CHECK_EQUAL(wideToUtf8(expected), wideToUtf8(actual))

struct KeyV_fixture {
    modAlphaCipher* p;
    KeyV_fixture() {
        p = new modAlphaCipher(L"В");
    }
    ~KeyV_fixture() {
        delete p;
    }
};

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL_WS(L"МИРМИ", modAlphaCipher(L"МИР").encrypt(L"ААААА"));
    }
    
    TEST(LongKey) {
        CHECK_EQUAL_WS(L"ДЛИНН", modAlphaCipher(L"ДЛИННЫЙКЛЮЧ").encrypt(L"ААААА"));
    }
    
    TEST(LowCaseKey) {
        CHECK_EQUAL_WS(L"МИРМИ", modAlphaCipher(L"мир").encrypt(L"ААААА"));
    }
    
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР123"), cipher_error);
    }
    
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР,МИР"), cipher_error);
    }
    
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp(L"МИР МИР"), cipher_error);
    }
    
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(L""), cipher_error);
    }
    
    TEST(WeakKey) {
        modAlphaCipher cipher(L"А");
        wstring encrypted = cipher.encrypt(L"ТЕСТ");
        wstring decrypted = cipher.decrypt(encrypted);
        CHECK_EQUAL_WS(L"ТЕСТ", decrypted);
    }
}

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyV_fixture, UpCaseString) {
        CHECK_EQUAL_WS(L"СТКДЖФ", p->encrypt(L"ПРИВЕТ"));
    }
    
    TEST_FIXTURE(KeyV_fixture, LowCaseString) {
        CHECK_EQUAL_WS(L"СТКДЖФ", p->encrypt(L"привет"));
    }
    
    TEST_FIXTURE(KeyV_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL_WS(L"СТКДЖФОКТ", p->encrypt(L"ПРИВЕТ, МИР!"));
    }
    
    TEST_FIXTURE(KeyV_fixture, StringWithNumbers) {
        CHECK_EQUAL_WS(L"ФЖУФ", p->encrypt(L"ТЕСТ123"));
    }
    
    TEST_FIXTURE(KeyV_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    
    TEST_FIXTURE(KeyV_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        CHECK_EQUAL_WS(L"ОПЗБДС", modAlphaCipher(L"Я").encrypt(L"ПРИВЕТ"));
    }
}

SUITE(DecryptTest)
{
    TEST_FIXTURE(KeyV_fixture, UpCaseString) {
        CHECK_EQUAL_WS(L"ПРИВЕТ", p->decrypt(L"СТКДЖФ"));
    }
    
    TEST_FIXTURE(KeyV_fixture, LowCaseString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        encrypted[0] = towlower(encrypted[0]);
        CHECK_THROW(p->decrypt(encrypted), cipher_error);
    }
    
    TEST_FIXTURE(KeyV_fixture, WhitespaceString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = encrypted + L" ";
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    TEST_FIXTURE(KeyV_fixture, DigitsString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = encrypted + L"123";
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    TEST_FIXTURE(KeyV_fixture, PunctString) {
        wstring encrypted = p->encrypt(L"ПРИВЕТ");
        wstring corrupted = L"!" + encrypted;
        CHECK_THROW(p->decrypt(corrupted), cipher_error);
    }
    
    TEST_FIXTURE(KeyV_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    
    TEST(MaxShiftKey) {
        CHECK_EQUAL_WS(L"ПРИВЕТ", modAlphaCipher(L"Я").decrypt(L"ОПЗБДС"));
    }
}

int main() {
    setlocale(LC_ALL, "");
    return UnitTest::RunAllTests();
}
