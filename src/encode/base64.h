#ifndef MDICT_BASE64_H
#define MDICT_BASE64_H

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

constexpr char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string encode_base64(const std::vector<uint8_t> &data) {
  std::string output;
  output.reserve((data.size() + 2) / 3 * 4);

  for (size_t i = 0; i < data.size(); i += 3) {
    uint32_t val = (uint32_t)data[i] << 16;
    if (i + 1 < data.size())
      val |= (uint32_t)data[i + 1] << 8;
    if (i + 2 < data.size())
      val |= (uint32_t)data[i + 2];

    output.push_back(b64_chars[(val >> 18) & 0x3F]);
    output.push_back(b64_chars[(val >> 12) & 0x3F]);
    output.push_back(i + 1 < data.size() ? b64_chars[(val >> 6) & 0x3F] : '=');
    output.push_back(i + 2 < data.size() ? b64_chars[val & 0x3F] : '=');
  }
  return output;
}

inline std::vector<uint8_t> decode_base64(const std::string &input) {
  static const std::vector<int> b64_index = []() {
    std::vector<int> index(256, -1);
    for (int i = 0; i < 64; i++)
      index[(unsigned char)b64_chars[i]] = i;
    return index;
  }();

  std::vector<uint8_t> output;
  int val = 0, valb = -8;
  for (unsigned char c : input) {
    if (b64_index[c] == -1)
      continue;
    val = (val << 6) | b64_index[c];
    valb += 6;
    if (valb >= 0) {
      output.push_back((uint8_t)((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return output;
}

inline std::string base64_from_hex(const std::string &hex_str) {
  auto hex_to_bytes = [](const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
      bytes.push_back(byte);
    }
    return bytes;
  };
  return encode_base64(hex_to_bytes(hex_str));
}

#endif // MDICT_BASE64_H