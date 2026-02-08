/*
 * Copyright (c) 2025-Present
 * All rights reserved.
 *
 * This code is licensed under the BSD 3-Clause License.
 * See the LICENSE file for details.
 */

#include "include/binutils.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <locale> // For std::wstring_convert
// #include "deps/miniz/miniz.h"
#include <CoreFoundation/CoreFoundation.h>
#include <zlib.h>

#include <string>
#include <vector>

using namespace std;

std::string convert_encoding(const char *bytes, unsigned long offset,
                             unsigned long len, const char *from_encoding) {
  if (len == 0)
    return "";

  CFStringEncoding encoding;
  std::string enc_name(from_encoding);
  if (enc_name == "GB18030" || enc_name == "GBK") {
    encoding = kCFStringEncodingGB_18030_2000;
  } else if (enc_name == "GB2312") {
    encoding = kCFStringEncodingEUC_CN;
  } else if (enc_name == "BIG5") {
    encoding = kCFStringEncodingBig5;
  } else {
    return std::string(bytes + offset, len);
  }

  CFStringRef cf_str = CFStringCreateWithBytes(
      NULL, (const UInt8 *)(bytes + offset), len, encoding, false);
  if (!cf_str) {
    return std::string(bytes + offset, len);
  }

  CFIndex utf8_len;
  CFStringGetBytes(cf_str, CFRangeMake(0, CFStringGetLength(cf_str)),
                   kCFStringEncodingUTF8, 0, false, NULL, 0, &utf8_len);

  std::string result(utf8_len, '\0');
  CFStringGetBytes(cf_str, CFRangeMake(0, CFStringGetLength(cf_str)),
                   kCFStringEncodingUTF8, 0, false, (UInt8 *)&result[0],
                   utf8_len, NULL);

  CFRelease(cf_str);
  return result;
}

char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

uint32_t be_bin_to_u32(const unsigned char *bin /* 4 bytes char array  */) {
  uint32_t n = 0;
  for (int i = 0; i < 3; i++) {
    n = n | (unsigned int)bin[i];
    n = n << 8;
  }
  n = n | (unsigned int)bin[3];
  return n;
}

uint64_t be_bin_to_u64(const unsigned char *bin /* 8 bytes char array  */) {
  uint64_t n = 0;
  for (int i = 0; i < 7; i++) {
    n = n | (unsigned int)bin[i];
    n = n << 8;
  }
  n = n | (unsigned int)bin[7];
  return n;
}

uint16_t be_bin_to_u16(const unsigned char *bin /* 8 bytes char array  */) {
  uint16_t n = 0;

  for (int i = 0; i < 1; i++) {
    n = n | (uint16_t)bin[i];
    n = n << 8;
  }
  n = n | (uint16_t)bin[1];
  return n;
}

uint8_t be_bin_to_u8(const unsigned char *bin /* 8 bytes char array  */) {
  return bin[0] & 255;
}

void putbytes(const char *bytes, int len, bool hex = true,
              unsigned long startofset) {
  int maxlen = 100;
  if (hex) {
    std::printf("<Buffer ");
    for (int i = 0; i < ((len - 1) > maxlen ? maxlen : (len - 1)); i++) {
      std::printf("%02x ", bytes[i] & 255);
      //        std::printf("%02x(%d) ", bytes[i] & 255,bytes[i] & 255);
    }
    std::printf("%02x", bytes[len - 1] & 255);

    std::printf("> (%ld,%d)\n", startofset, len);
    //    std::printf(">\n");
  } else {
    std::printf("<Buffer ");
    for (int i = 0; i < len - 1; i++) {
      std::printf("%d ", bytes[i] & 255);
    }
    std::printf("%d", bytes[len - 1] & 255);
    std::printf("> (%d)\n", len);
  }
}

/*****************************************************************
 *                                                               *
 *                        ENCODING METHODS                       *
 *                                                               *
 *****************************************************************/

// 工具包装器，用于字符转换 为wstring/wbuffer适配绑定到 locale 的平面
template <class Facet> struct usable_facet : public Facet {
public:
  using Facet::Facet; // inherit constructors
  ~usable_facet() {}

  // workaround for compilers without inheriting constructors:
  // template <class ...Args> usable_facet(Args&& ...args) :
  // Facet(std::forward<Args>(args)...) {}
};

template <typename internT, typename externT, typename stateT>
using facet_codecvt = usable_facet<std::codecvt<internT, externT, stateT>>;

/*************************************************
 * little-endian binary to utf16 to utf8 string   *
 **************************************************/

// Helper function to convert UTF-16 to UTF-8 with surrogate pair support and
// error handling
std::string utf16_to_utf8(const std::u16string &utf16) {
  std::string utf8;
  utf8.reserve(utf16.length() * 3);

  for (size_t i = 0; i < utf16.length(); ++i) {
    char16_t c = utf16[i];

    // Check for surrogate pairs
    if (c >= 0xD800 && c <= 0xDBFF) {
      // High surrogate
      if (i + 1 < utf16.length()) {
        char16_t low = utf16[i + 1];
        if (low >= 0xDC00 && low <= 0xDFFF) {
          // Valid surrogate pair
          uint32_t codepoint = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
          utf8.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
          utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
          utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
          utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
          ++i; // Skip low surrogate
          continue;
        }
      }
      // Invalid surrogate (lone high surrogate or invalid low surrogate)
      // Replace with replacement character U+FFFD (EF BF BD)
      utf8.push_back('\xEF');
      utf8.push_back('\xBF');
      utf8.push_back('\xBD');
      continue;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      // Lone low surrogate
      // Replace with replacement character U+FFFD (EF BF BD)
      utf8.push_back('\xEF');
      utf8.push_back('\xBF');
      utf8.push_back('\xBD');
      continue;
    }

    if (c <= 0x7F) {
      utf8.push_back(static_cast<char>(c));
    } else if (c <= 0x7FF) {
      utf8.push_back(static_cast<char>(0xC0 | (c >> 6)));
      utf8.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
      utf8.push_back(static_cast<char>(0xE0 | (c >> 12)));
      utf8.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
      utf8.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
  return utf8;
}

// binary to utf16->utf8
std::string le_bin_utf16_to_utf8(const char *bytes, int offset, int len) {
  if (len <= 0)
    return "";

  // Create a copy to ensure null termination for u16string if needed,
  // though u16string constructor with length is safer.
  std::vector<char16_t> wcbytes(len / 2);
  std::memcpy(wcbytes.data(), bytes + offset, (len / 2) * 2);

  std::u16string u16(wcbytes.data(), len / 2);
  return utf16_to_utf8(u16);
}

// big-endian binary to utf16 to utf8 string
std::string be_bin_utf16_to_utf8(const char *bytes, int offset, int len) {
  if (len <= 0)
    return "";

  std::vector<char16_t> wcbytes(len / 2);
  const unsigned char *src =
      reinterpret_cast<const unsigned char *>(bytes + offset);

  for (int i = 0; i < len / 2; ++i) {
    // Swap bytes: BE to Host (assuming Host is LE)
    wcbytes[i] = (static_cast<char16_t>(src[i * 2]) << 8) |
                 static_cast<char16_t>(src[i * 2 + 1]);
  }

  std::u16string u16(wcbytes.data(), len / 2);
  return utf16_to_utf8(u16);
}

std::string be_bin_to_utf8(const char *bytes, unsigned long offset,
                           unsigned long len) {
  std::string u8(bytes + offset * sizeof(char), len);
  return u8;
}

std::string be_bin_to_utf16(const char *bytes, unsigned long offset,
                            unsigned long len) {
  std::string su8(bytes + offset * sizeof(char), len);
  char *hex_target = (char *)calloc(2 * len + 1, sizeof(char));
  bintohex(bytes + offset * sizeof(char), len, hex_target);
  std::string u16(hex_target, 2 * len + 1);
  free(hex_target);

  return u16;
}

// slice srcByte to distByte
// ensure srcByte.length > len
int bin_slice(const char *srcByte, int srcByteLen, int offset, int len,
              char *distByte) {
  if (offset < 0 || offset > srcByteLen - 1) {
    return -1;
  }
  if (offset + len > srcByteLen) {
    // invalid offset & length
    return -2;
  }
  // ensure distByte has malloced
  for (int i = 0; i < len; ++i) {
    (distByte)[i] = srcByte[i + offset];
  }
  return 0;
}

// char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
// '9', 'A', 'B', 'C', 'D', 'E', 'F' };

int bintohex(const char *bin, unsigned long len, char *target) {
  unsigned long i = 0;
  for (i = 0; i < len; i++) {
    char const byte = bin[i];

    target[2 * i] = hex_chars[(byte & 0xF0) >> 4];
    target[2 * i + 1] = hex_chars[(byte & 0x0F)];
  }
  return i;
}
