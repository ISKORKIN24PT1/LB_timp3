#include "modAlphaCipher.h"
#include <cctype>
#include <algorithm>
#include <cwctype>  // Добавлен для wide character функций

modAlphaCipher::modAlphaCipher(const std::wstring& skey) {
    for (size_t i = 0; i < numAlpha.size(); ++i) {
        alphaNum[numAlpha[i]] = static_cast<int>(i);
    }
    key = convert(getValidKey(skey));
}

wchar_t modAlphaCipher::toUpper(wchar_t c) {
    if (c >= L'а' && c <= L'я') {
        return L'А' + (c - L'а');
    }
    if (c == L'ё') {
        return L'Ё';
    }
    return std::towupper(c);  // Исправлено на towupper
}

std::wstring modAlphaCipher::getValidKey(const std::wstring& s) {
    if (s.empty()) {
        throw cipher_error("Empty key");
    }
    std::wstring tmp(s);
    for (auto& c : tmp) {
        if (!std::iswalpha(c)) {  // Исправлено на std::iswalpha
            throw cipher_error("Invalid key: non-alphabetic character");
        }
        if (std::iswlower(c)) {   // Исправлено на std::iswlower
            c = toUpper(c);
        }
    }
    return tmp;
}

std::wstring modAlphaCipher::getValidOpenText(const std::wstring& s) {
    std::wstring tmp;
    for (auto c : s) {
        if (std::iswalpha(c)) {   // Исправлено на std::iswalpha
            if (std::iswlower(c)) { // Исправлено на std::iswlower
                tmp.push_back(toUpper(c));
            } else {
                tmp.push_back(c);
            }
        }
    }
    if (tmp.empty()) {
        throw cipher_error("Empty text, no letters");
    }
    return tmp;
}

std::wstring modAlphaCipher::getValidCipherText(const std::wstring& s) {
    if (s.empty()) {
        throw cipher_error("Empty cipher text");
    }
    for (auto c : s) {
        if (!std::iswupper(c)) {  // Исправлено на std::iswupper
            throw cipher_error("Incorrect data entry");
        }
    }
    return s;
}

std::vector<int> modAlphaCipher::convert(const std::wstring& s) {
    std::vector<int> result;
    for (auto c : s) {
        wchar_t upperC = toUpper(c);
        if (alphaNum.find(upperC) != alphaNum.end()) {
            result.push_back(alphaNum[upperC]);
        }
    }
    return result;
}

std::wstring modAlphaCipher::convert(const std::vector<int>& v) {
    std::wstring result;
    for (auto i : v) {
        if (i >= 0 && i < static_cast<int>(numAlpha.size())) {
            result.push_back(numAlpha[i]);
        }
    }
    return result;
}

std::wstring modAlphaCipher::encrypt(const std::wstring& open_text) {
    std::vector<int> work = convert(getValidOpenText(open_text));
    for (size_t i = 0; i < work.size(); ++i) {
        work[i] = (work[i] + key[i % key.size()]) % numAlpha.size();
    }
    return convert(work);
}

std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text) {
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    for (size_t i = 0; i < work.size(); ++i) {
        work[i] = (work[i] + numAlpha.size() - key[i % key.size()]) % numAlpha.size();
    }
    return convert(work);
}
