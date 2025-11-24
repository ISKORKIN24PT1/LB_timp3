#include <iostream>
#include <locale>
#include "modAlphaCipher.h"

using namespace std;

void check(const wstring& Text, const wstring& key, bool destructCipherText = false) {
    try {
        wstring cipherText;
        wstring decryptedText;
        modAlphaCipher cipher(key);
        cipherText = cipher.encrypt(Text);
        
        if (destructCipherText) {
            cipherText.front() = towlower(cipherText.front());
        }
        
        decryptedText = cipher.decrypt(cipherText);
        wcout << L"key=" << key << endl;
        wcout << L"Original: " << Text << endl;
        wcout << L"Encrypted: " << cipherText << endl;
        wcout << L"Decrypted: " << decryptedText << endl;
        if (Text == decryptedText)
            wcout << L"Ok\n";
        else
            wcout << L"Err\n";
        wcout << endl;
    } catch (const cipher_error& e) {
        wcout << L"Error: " << e.what() << endl << endl;
    }
}

int main() {
    setlocale(LC_ALL, "");
    
    // Позитивные тесты
    check(L"ААААА", L"МИР");
    check(L"ПРИВЕТ", L"МИР");
    check(L"привет", L"мир");
    check(L"доброе утро, ёж", L"Мир");
    
    // Тесты с исключениями
    check(L"ПРИВЕТ", L""); // Пустой ключ
    check(L"ПРИВЕТ", L"МИР123"); // Ключ с цифрами
    check(L"123", L"МИР"); // Текст без букв
    check(L"ПРИВЕТ", L"МИР", true); // Испорченный шифротекст
    
    return 0;
}
