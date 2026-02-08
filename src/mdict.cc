/*
 * Copyright (c) 2025-Present
 * All rights reserved.
 *
 * This code is licensed under the BSD 3-Clause License.
 * See the LICENSE file for details.
 */

#include "include/mdict.h"

#include "encode/api.h"
#include "encode/base64.h"

#include "include/adler32.h"
#include "include/binutils.h"
#include "include/lzo_wrapper.h"
#include "include/mdict_extern.h"
#include "include/xmlutils.h"
#include "include/zlib_wrapper.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>

// Removed regex pattern as it's causing issues in some environments
// const std::regex re_pattern("(\\s|:|\\.|,|-|_|'|\\(|\\)|#|<|>|!)");

namespace mdict {

// constructor
Mdict::Mdict(std::string fn) noexcept : filename(std::move(fn)) {
  if (endsWith(filename, ".mdd")) {
    this->filetype = MDDTYPE;
  } else {
    this->filetype = MDXTYPE;
  }
}

// distructor
Mdict::~Mdict() {
  // close instream
  instream.close();
}

/**
 * transform word into comparable string
 * @param word
 * @return
 */
std::string _s(std::string word) {
  std::string s;
  s.reserve(word.size());
  for (unsigned char c : word) {
    if (std::isspace(c) || c == ':' || c == '.' || c == ',' || c == '-' ||
        c == '_' || c == '\'' || c == '(' || c == ')' || c == '#' || c == '<' ||
        c == '>' || c == '!') {
      continue;
    }
    s += static_cast<char>(std::tolower(c));
  }
  return s;
}

/***************************************
 *             private part            *
 ***************************************/

/**
 * read header
 */
void Mdict::read_header() {
  // -----------------------------------------
  // 1. [0:4] dictionary header length 4 byte
  // -----------------------------------------

  // header size buffer
  char *head_size_buf = (char *)std::calloc(4, sizeof(char));
  readfile(0, 4, head_size_buf);

  // header byte size convert
  uint32_t header_bytes_size =
      be_bin_to_u32((const unsigned char *)head_size_buf);
  std::free(head_size_buf);
  // assign key block start offset
  this->header_bytes_size = header_bytes_size;
  // key_block_start_offset will be assigned after version parsing
  /// passed

  // -----------------------------------------
  // 2. [4: header_bytes_size+4], header buffer
  // -----------------------------------------

  // header buffer
  unsigned char *head_buffer =
      (unsigned char *)std::calloc(header_bytes_size, sizeof(unsigned char));
  readfile(4, header_bytes_size, (char *)head_buffer);
  /// passed

  // 3. alder32 checksum
  // -----------------------------------------

  // TODO  version < 2.0 needs to checksum?
  // alder32 checksum buffer
  char *head_checksum_buffer = (char *)std::calloc(4, sizeof(char));
  readfile(header_bytes_size + 4, 4, head_checksum_buffer);
  /// passed

  // TODO skip head checksum for now
  std::free(head_checksum_buffer);

  // -----------------------------------------
  // 4. convert header buffer into utf16 text
  // -----------------------------------------

  // header text utf16

  std::string utf8_temp;
  if (!utf16_to_utf8_header(head_buffer, header_bytes_size, utf8_temp)) {
    std::cout << "this mdx file is invalid len:" << header_bytes_size
              << std::endl;
    return;
  }

  unsigned char *utf8_buffer = reinterpret_cast<unsigned char *>(&utf8_temp[0]);
  int utf8_len = static_cast<int>(utf8_temp.size());

  this->header_buffer = std::move(utf8_temp);

  std::string header_text(reinterpret_cast<char *>(utf8_buffer), utf8_len);
  std::map<std::string, std::string> headinfo;
  parse_xml_header(header_text, headinfo);
  /// passed

  // -----------------------------------------
  // 5. extract title
  // -----------------------------------------
  if (headinfo.find("Title") != headinfo.end()) {
    this->title = headinfo["Title"];
  }

  // -----------------------------------------
  // 6. handle header message, set flags
  // -----------------------------------------

  // encrypted flag
  // 0x00 - no encryption
  // 0x01 - encrypt record block
  // 0x02 - encrypt key info block
  if (headinfo.find("Encrypted") == headinfo.end() ||
      headinfo["Encrypted"].empty() || headinfo["Encrypted"] == "No") {
    this->encrypt = ENCRYPT_NO_ENC;
  } else if (headinfo["Encrypted"] == "Yes") {
    this->encrypt = ENCRYPT_RECORD_ENC;
  } else {
    std::string s = headinfo["Encrypted"];
    if (s.at(0) == '2') {
      this->encrypt = ENCRYPT_KEY_INFO_ENC;
    } else if (s.at(0) == '1') {
      this->encrypt = ENCRYPT_RECORD_ENC;
    } else {
      this->encrypt = ENCRYPT_NO_ENC;
    }
  }
  /// passed

  // -------- stylesheet ----------
  // stylesheet attribute if present takes from of:
  // style_number # 1-255
  // style_begin # or ''
  // style_end # or ''
  // TODO: splitstyle info

  // header_info['_stylesheet'] = {}
  // if header_tag.get('StyleSheet'):
  //   lines = header_tag['StyleSheet'].splitlines()
  //   for i in range(0, len(lines), 3):
  //        header_info['_stylesheet'][lines[i]] = (lines[i + 1], lines[i + 2])

  // ---------- version ------------
  // before version 2.0, number is 4 bytes integer
  // version 2.0 and above use 8 bytes
  std::string sver;
  if (headinfo.find("GeneratedByEngineVersion") != headinfo.end()) {
    sver = headinfo["GeneratedByEngineVersion"];
  } else if (headinfo.find("EngineVersion") != headinfo.end()) {
    sver = headinfo["EngineVersion"];
  } else if (headinfo.find("Version") != headinfo.end()) {
    sver = headinfo["Version"];
  }
  std::string::size_type sz;

  auto parse_version = [](const std::string &s,
                          float fallback = 0.0f) -> float {
    float v = fallback;
    size_t i = 0;

    // skip leading whitespace
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
      ++i;
    if (i == s.size())
      return fallback;

    // parse digits before decimal
    float int_part = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
      int_part = int_part * 10 + (s[i] - '0');
      ++i;
    }

    float frac_part = 0;
    if (i < s.size() && s[i] == '.') {
      ++i;
      float divisor = 10.0f;
      while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        frac_part += (s[i] - '0') / divisor;
        divisor *= 10.0f;
        ++i;
      }
    }

    v = int_part + frac_part;
    return v;
  };

  // we fallback to less than 2.
  this->version = parse_version(sver, 0.0f); // default < 2.0

  if (this->version >= 2.0) {
    this->number_width = 8;
    this->number_format = NUMFMT_BE_8BYTESQ;
    this->key_block_start_offset = this->header_bytes_size + 8;
    this->key_block_info_start_offset = this->key_block_start_offset + 40 + 4;
  } else {
    this->number_format = NUMFMT_BE_4BYTESI;
    this->number_width = 4;
    this->key_block_start_offset = this->header_bytes_size + 8;
    this->key_block_info_start_offset = this->key_block_start_offset + 16;
  }

  // ---------- encoding ------------
  // ---------- encoding ------------
  if (headinfo.find("Encoding") != headinfo.end() &&
      !headinfo["Encoding"].empty()) {
    std::string enc = headinfo["Encoding"];
    if (enc == "UTF-8" || enc == "utf8") {
      this->encoding = ENCODING_UTF8;
    } else if (enc == "GBK" || enc == "GB2312" || enc == "GB18030") {
      this->encoding = ENCODING_GB18030;
    } else if (enc == "Big5" || enc == "BIG5") {
      this->encoding = ENCODING_BIG5;
    } else if (enc == "utf16" || enc == "utf-16" || enc == "UTF-16") {
      this->encoding = ENCODING_UTF16;
    } else {
      this->encoding = (this->version < 2.0) ? ENCODING_UTF16 : ENCODING_UTF8;
    }
  } else {
    this->encoding = (this->version < 2.0) ? ENCODING_UTF16 : ENCODING_UTF8;
  }
  // FIX mdd
  if (this->filetype == "MDD") {
    this->encoding = ENCODING_UTF16;
  }
  std::cerr << "[Mdict] Dictionary '" << this->title
            << "' Encoding: " << this->encoding << " Version: " << this->version
            << std::endl;
}

/**
 * read key block header, key block header contains a serials number, including
 *
 * key block header info struct:
 * [0:8]/[0:4]   - number of key blocks
 * [8:16]/[4:8]  - number of entries
 * [16:24]/nil - key block info decompressed size (if version >= 2.0,
 * otherwise, this section does not exist)
 * [24:32]/[8:12] - key block info size
 * [32:40][12:16] - key block size
 * note: if version <2.0, the key info buffer size is 4 * 4
 *       otherwise, ths key info buffer size is 5 * 8
 * <2.0  the order of number is same
 */
void Mdict::read_key_block_header() {
  // key block header part
  int key_block_info_bytes_num = 0;
  if (this->version >= 2.0) {
    key_block_info_bytes_num = 8 * 5;
  } else {
    key_block_info_bytes_num = 4 * 4;
  }

  // key block info buffer
  char *key_block_info_buffer = (char *)calloc(
      static_cast<size_t>(key_block_info_bytes_num), sizeof(char));
  // read buffer
  this->readfile(this->key_block_start_offset,
                 static_cast<uint64_t>(key_block_info_bytes_num),
                 key_block_info_buffer);
  //  putbytes(key_block_info_buffer,key_block_info_bytes_num, true);
  /// PASSED

  // TODO key block info encrypted file not support yet
  if (this->encrypt == ENCRYPT_RECORD_ENC) {
    std::cout << "user identification is needed to read encrypted file"
              << std::endl;
    if (key_block_info_buffer)
      std::free(key_block_info_buffer);
    throw std::invalid_argument("invalid encrypted file");
  }

  // key block header info struct:
  // [0:8]/[0:4]   - number of key blocks
  // [8:16]/[4:8]  - number of entries
  // [16:24]/nil - key block info decompressed size (if version >= 2.0,
  // otherwise, this section does not exist)
  // [24:32]/[8:12] - key block info size
  // [32:40][12:16] - key block size
  // note: if version <2.0, the key info buffer size is 4 * 4
  //       otherwise, ths key info buffer size is 5 * 8
  // <2.0  the order of number is same

  // 1. [0:8]([0:4]) number of key blocks
  char *key_block_nums_bytes =
      (char *)calloc(static_cast<size_t>(this->number_width), sizeof(char));
  int eno = bin_slice(key_block_info_buffer, key_block_info_bytes_num, 0,
                      this->number_width, key_block_nums_bytes);
  if (eno != 0) {
    if (key_block_info_buffer)
      std::free(key_block_info_buffer);
    if (key_block_nums_bytes)
      std::free(key_block_nums_bytes);
    std::cout << "eno: " << eno << std::endl;
    throw std::logic_error("get key block bin slice failed");
  }
  /// passed

  uint64_t key_block_num = 0;
  if (this->number_width == 8)
    key_block_num = be_bin_to_u64((const unsigned char *)key_block_nums_bytes);
  else if (this->number_width == 4)
    key_block_num = be_bin_to_u32((const unsigned char *)key_block_nums_bytes);
  if (key_block_nums_bytes)
    std::free(key_block_nums_bytes);
  /// passed

  // 2. [8:16]  - number of entries
  char *entries_num_bytes =
      (char *)calloc(static_cast<size_t>(this->number_width), sizeof(char));
  eno = bin_slice(key_block_info_buffer, key_block_info_bytes_num,
                  this->number_width, this->number_width, entries_num_bytes);
  if (eno != 0) {
    if (key_block_info_buffer)
      std::free(key_block_info_buffer);
    if (entries_num_bytes)
      std::free(entries_num_bytes);
    throw std::logic_error("get key block bin slice failed");
  }
  /// passed

  uint64_t entries_num = 0;
  if (this->number_width == 8)
    entries_num = be_bin_to_u64((const unsigned char *)entries_num_bytes);
  else if (this->number_width == 4)
    entries_num = be_bin_to_u32((const unsigned char *)entries_num_bytes);
  if (entries_num_bytes)
    std::free(entries_num_bytes);
  /// passed

  int key_block_info_size_start_offset = 0;

  // 3. [16:24] - key block info decompressed size (if version >= 2.0,
  // otherwise, this section does not exist)
  if (this->version >= 2.0) {
    char *key_block_info_decompress_size_bytes =
        (char *)calloc(static_cast<size_t>(this->number_width), sizeof(char));
    eno = bin_slice(key_block_info_buffer, key_block_info_bytes_num,
                    this->number_width * 2, this->number_width,
                    key_block_info_decompress_size_bytes);
    if (eno != 0) {
      if (key_block_info_buffer)
        std::free(key_block_info_buffer);
      if (key_block_info_decompress_size_bytes)
        std::free(key_block_info_decompress_size_bytes);
      throw std::logic_error("decode key block decompress size failed");
    }
    /// passed

    uint64_t key_block_info_decompress_size = 0;
    if (this->number_width == 8)
      key_block_info_decompress_size = be_bin_to_u64(
          (const unsigned char *)key_block_info_decompress_size_bytes);
    else if (this->number_width == 4)
      key_block_info_decompress_size = be_bin_to_u32(
          (const unsigned char *)key_block_info_decompress_size_bytes);
    this->key_block_info_decompress_size = key_block_info_decompress_size;
    if (key_block_info_decompress_size_bytes)
      std::free(key_block_info_decompress_size_bytes);
    /// passed

    // key block info size (number) start at 24 ([24:32])
    key_block_info_size_start_offset = this->number_width * 3;
  } else {
    // key block info size (number) start at 24 ([8:12])
    key_block_info_size_start_offset = this->number_width * 2;
  }

  // 4. [24:32] - key block info size
  char *key_block_info_size_buffer =
      (char *)calloc(static_cast<size_t>(this->number_width), sizeof(char));
  eno = bin_slice(key_block_info_buffer, key_block_info_bytes_num,
                  key_block_info_size_start_offset, this->number_width,
                  key_block_info_size_buffer);
  if (eno != 0) {
    if (key_block_info_buffer != nullptr)
      std::free(key_block_info_buffer);
    if (key_block_info_size_buffer != nullptr)
      std::free(key_block_info_size_buffer);
    throw std::logic_error("decode key block info size failed");
  }

  uint64_t key_block_info_size = 0;
  if (this->number_width == 8)
    key_block_info_size =
        be_bin_to_u64((const unsigned char *)key_block_info_size_buffer);
  else if (this->number_width == 4)
    key_block_info_size =
        be_bin_to_u32((const unsigned char *)key_block_info_size_buffer);
  if (key_block_info_size_buffer != nullptr)
    std::free(key_block_info_size_buffer);
  /// passed

  // 5. [32:40] - key block size
  char *key_block_size_buffer =
      (char *)calloc(static_cast<size_t>(this->number_width), sizeof(char));
  eno = bin_slice(key_block_info_buffer, key_block_info_bytes_num,
                  key_block_info_size_start_offset + this->number_width,
                  this->number_width, key_block_size_buffer);
  if (eno != 0) {
    if (key_block_info_buffer)
      std::free(key_block_info_buffer);
    if (key_block_size_buffer)
      std::free(key_block_size_buffer);
    throw std::logic_error("decode key block size failed");
  }
  /// passed

  uint64_t key_block_size = 0;
  if (this->number_width == 8)
    key_block_size =
        be_bin_to_u64((const unsigned char *)key_block_size_buffer);
  else if (this->number_width == 4)
    key_block_size =
        be_bin_to_u32((const unsigned char *)key_block_size_buffer);
  if (key_block_size_buffer)
    std::free(key_block_size_buffer);
  /// passed

  // 6. [40:44] - 4bytes checksum
  // TODO if version > 2.0, skip 4bytes checksum

  // free key block info buffer
  if (key_block_info_buffer != nullptr)
    std::free(key_block_info_buffer);

  this->key_block_num = key_block_num;
  this->entries_num = entries_num;
  this->key_block_info_size = key_block_info_size;
  this->key_block_size = key_block_size;
  if (this->version >= 2.0) {
    this->key_block_info_start_offset = this->key_block_start_offset + 40 + 4;
  } else {
    this->key_block_info_start_offset = this->key_block_start_offset + 16;
  }
}

/**
 * read key block info
 *
 * it will decode the key block info, and set the key block info list
 * it contains:
 * first key
 * last key
 * comp size
 * decomp size
 * offset
 */
void Mdict::read_key_block_info() {
  // start at this->key_block_info_start_offset
  char *key_block_info_buffer = (char *)calloc(
      static_cast<size_t>(this->key_block_info_size), sizeof(char));

  readfile(this->key_block_info_start_offset, this->key_block_info_size,
           key_block_info_buffer);

  // ------------------------------------
  // decode key_block_info
  // ------------------------------------
  decode_key_block_info(key_block_info_buffer, this->key_block_info_size,
                        this->key_block_num, this->entries_num);

  // key block compressed start offset = this->key_block_info_start_offset +
  // key_block_info_size
  this->key_block_compressed_start_offset = static_cast<uint32_t>(
      this->key_block_info_start_offset + this->key_block_info_size);

  /// passed

  char *key_block_compressed_buffer =
      (char *)calloc(static_cast<size_t>(this->key_block_size), sizeof(char));

  readfile(this->key_block_compressed_start_offset,
           static_cast<int>(this->key_block_size), key_block_compressed_buffer);

  // ------------------------------------
  // decode key_block_compressed
  // ------------------------------------
  unsigned long kb_len = this->key_block_size;
  //  putbytes(key_block_compressed_buffer,this->key_block_size, true);

  int err =
      decode_key_block((unsigned char *)key_block_compressed_buffer, kb_len);
  if (err != 0) {
    throw std::runtime_error("decode key block error");
  }

  if (key_block_info_buffer != nullptr)
    std::free(key_block_info_buffer);
  if (key_block_compressed_buffer != nullptr)
    std::free(key_block_compressed_buffer);
}

/**
 * use ripemd128 as decrypt key, and decrypt the key info data
 * @param data the data which needs to decrypt
 * @param k the decrypt key
 * @param data_len data length
 * @param key_len key length
 */
void fast_decrypt(byte *data, const byte *k, int data_len, int key_len) {
  const byte *key = k;
  //      putbytes((char*)data, 16, true);
  byte *b = data;
  byte previous = 0x36;

  for (int i = 0; i < data_len; ++i) {
    byte t = static_cast<byte>(((b[i] >> 4) | (b[i] << 4)) & 0xff);
    t = t ^ previous ^ ((byte)(i & 0xff)) ^ key[i % key_len];
    previous = b[i];
    b[i] = t;
  }
}

/**
 *
 * decrypt the data, this is a helper function to invoke the fast_decrypt
 * note: don't forget free comp_block !!
 *
 * @param comp_block compressed block buffer
 * @param comp_block_len compressed block buffer size
 * @return the decrypted compressed block
 */
byte *mdx_decrypt(byte *comp_block, const int comp_block_len) {
  byte *key_buffer = (byte *)calloc(8, sizeof(byte));
  memcpy(key_buffer, comp_block + 4 * sizeof(char), 4 * sizeof(char));
  key_buffer[4] = 0x95; // comp_block[4:8] + [0x95,0x36,0x00,0x00]
  key_buffer[5] = 0x36;

  byte *key = ripemd128bytes(key_buffer, 8);

  fast_decrypt(comp_block + 8 * sizeof(byte), key, comp_block_len - 8,
               16 /* key length*/);

  // finally
  std::free(key_buffer);
  return comp_block;
  /// passed
}

/**
 * split key block into key block list
 *
 * this is for key block (not key block info)
 *
 * @param key_block key block buffer
 * @param key_block_len key block length
 */
std::vector<key_list_item *> Mdict::split_key_block(unsigned char *key_block,
                                                    unsigned long key_block_len,
                                                    unsigned long block_id) {
  // TODO assert checksum
  // uint32_t adlchk = adler32checksum(key_block, key_block_len);
  //  std::cout<<"adler32 chksum: "<<adlchk<<std::endl;
  int key_start_idx = 0;
  int key_end_idx = 0;
  std::vector<key_list_item *> inner_key_list;

  if (!key_block) {
    std::cerr << "[Error] split_key_block called with NULL key_block"
              << std::endl;
    return inner_key_list;
  }

  while (key_start_idx < key_block_len) {
    // # the corresponding record's offset in record block
    unsigned long record_start = 0;
    int width = 0;
    if (key_start_idx + number_width > key_block_len) {
      std::cerr << "[Error] Key block buffer overflow in split_key_block"
                << std::endl;
      break;
    }
    if (this->version >= 2.0) {
      record_start = be_bin_to_u64(key_block + key_start_idx);
    } else {
      record_start = be_bin_to_u32(key_block + key_start_idx);
    }

    if (this->encoding == 1 /* utf16 */) {
      width = 2;
    } else {
      width = 1;
    }

    // key text ends with '\x00' (or '\x00\x00' for UTF-16)
    int i = key_start_idx + number_width;
    bool found = false;
    while (static_cast<size_t>(i + (width - 1)) < key_block_len) {
      if (encoding == 1 /*ENCODING_UTF16*/) {
        if (i + 1 < key_block_len && key_block[i] == 0 &&
            key_block[i + 1] == 0) {
          key_end_idx = i;
          found = true;
          break;
        }
      } else {
        if (key_block[i] == 0) {
          key_end_idx = i;
          found = true;
          break;
        }
      }
      i += width;
    }

    if (!found) {
      key_end_idx = static_cast<int>(key_block_len);
    }

    const char *src_ptr =
        (const char *)key_block + (key_start_idx + this->number_width);
    unsigned long key_len = static_cast<unsigned long>(
        key_end_idx - key_start_idx - this->number_width);
    std::string key_text = decode_key_text(src_ptr, key_len);
    inner_key_list.push_back(
        new key_list_item(record_start, key_text, _s(key_text)));

    key_start_idx = key_end_idx + width;
  }
  return inner_key_list;
}

/**
 * decode key block info by block id use with reduce function
 * @param block_id key_block id
 * @return return key list item
 */
std::vector<key_list_item *>
Mdict::decode_key_block_by_block_id(unsigned long block_id) {
  // ------------------------------------
  // decode key_block_compressed
  // ------------------------------------

  unsigned long idx = block_id;

  unsigned long comp_size = this->key_block_info_list[idx]->key_block_comp_size;
  unsigned long decomp_size =
      this->key_block_info_list[idx]->key_block_decomp_size;
  unsigned long start_ofset =
      this->key_block_info_list[idx]->key_block_comp_accumulator +
      this->key_block_compressed_start_offset;

  char *key_block_buffer = (char *)malloc(comp_size);
  if (!key_block_buffer) {
    throw std::runtime_error("Failed to allocate key_block_buffer");
  }

  readfile(start_ofset, static_cast<int>(comp_size), key_block_buffer);

  // Data blocks usually start with a 4-byte info (LE) and 4-byte checksum (BE).
  uint32_t info = 0;
  if (comp_size >= 4) {
    info = (unsigned char)key_block_buffer[0] |
           ((unsigned char)key_block_buffer[1] << 8) |
           ((unsigned char)key_block_buffer[2] << 16) |
           ((unsigned char)key_block_buffer[3] << 24);
  }
  uint32_t comp_type = info & 0x0F;

  unsigned char *key_block = nullptr;
  std::vector<uint8_t> kb_uncompressed;

  auto try_decompress = [&](const unsigned char *src, size_t len, size_t d_size,
                            int method) -> std::vector<uint8_t> {
    if (method == 1) { // LZO
      std::vector<uint8_t> res = lzo_raw_uncompress(src, len, d_size);
      if (!res.empty())
        return res;
      return lzo_mdict_uncompress(src, len, d_size);
    } else if (method == 2) { // ZLIB
      return zlib_mem_uncompress(src, len, d_size);
    }
    return {};
  };

  if (comp_type == 1 || comp_type == 2) {
    kb_uncompressed = try_decompress((unsigned char *)key_block_buffer + 8,
                                     comp_size - 8, decomp_size, comp_type);
    if (!kb_uncompressed.empty())
      key_block = kb_uncompressed.data();
  }

  if (!key_block && this->version < 2.0 && comp_size != decomp_size) {
    kb_uncompressed = try_decompress((unsigned char *)key_block_buffer,
                                     comp_size, decomp_size, 1);
    if (!kb_uncompressed.empty())
      key_block = kb_uncompressed.data();
  }

  if (!key_block) {
    if (comp_size == decomp_size) {
      key_block = (unsigned char *)key_block_buffer;
      if (comp_type != 0 && this->version >= 2.0)
        key_block += 8;
    } else {
      free(key_block_buffer);
      throw std::runtime_error("key block decompress failed");
    }
  }

  std::vector<key_list_item *> tlist =
      split_key_block(key_block, decomp_size, idx);
  free(key_block_buffer);
  return tlist;
}

/**
 * decode the key block decode function, will invoke split key block
 *
 * this is for key block (not key block info)
 *
 * @param key_block_buffer
 * @param kb_buff_len
 * @return
 */
int Mdict::decode_key_block(unsigned char *key_block_buffer,
                            unsigned long kb_buff_len) {
  int i = 0;

  for (long idx = 0; idx < static_cast<long>(this->key_block_info_list.size());
       idx++) {
    unsigned long comp_size =
        this->key_block_info_list[idx]->key_block_comp_size;
    unsigned long decomp_size =
        this->key_block_info_list[idx]->key_block_decomp_size;
    unsigned long start_ofset = i;

    if (start_ofset + 8 > kb_buff_len) {
      std::cerr << "[DEBUG] Block " << idx << " start_ofset=" << start_ofset
                << " > kb_buff_len=" << kb_buff_len << std::endl;
    } else {
      std::cerr << "[DEBUG] Block " << idx << " start_ofset=" << start_ofset
                << " comp_size=" << comp_size << " decomp_size=" << decomp_size
                << " first4=" << std::hex << (int)key_block_buffer[start_ofset]
                << " " << (int)key_block_buffer[start_ofset + 1] << " "
                << (int)key_block_buffer[start_ofset + 2] << " "
                << (int)key_block_buffer[start_ofset + 3] << std::dec
                << std::endl;
    }

    unsigned char *key_block = nullptr;
    std::vector<uint8_t> kb_uncompressed;

    // Use a unified try logic for decompression
    auto try_decompress = [&](const unsigned char *src, size_t len,
                              size_t d_size,
                              int method) -> std::vector<uint8_t> {
      if (method == 1) { // LZO
        // Try raw MiniLZO decompression
        std::vector<uint8_t> res = lzo_raw_uncompress(src, len, d_size);
        if (!res.empty()) {
          std::cerr << "[DEBUG] LZO raw decompression successful." << std::endl;
          return res;
        }
        // Try with MDict 5-byte header if raw failed (just in case some
        // versions needed it)
        res = lzo_mdict_uncompress(src, len, d_size);
        if (!res.empty()) {
          std::cerr << "[DEBUG] LZO MDict header decompression successful."
                    << std::endl;
        }
        return res;
      } else if (method == 2) { // ZLIB
        std::vector<uint8_t> res = zlib_mem_uncompress(src, len, d_size);
        if (!res.empty()) {
          std::cerr << "[DEBUG] ZLIB decompression successful." << std::endl;
        }
        return res;
      }
      return {};
    };

    // Data blocks (key and record) usually start with a 4-byte info (LE) and
    // 4-byte checksum (BE).
    uint32_t info = 0;
    if (start_ofset + 4 <= kb_buff_len) {
      info = (unsigned char)key_block_buffer[start_ofset] |
             ((unsigned char)key_block_buffer[start_ofset + 1] << 8) |
             ((unsigned char)key_block_buffer[start_ofset + 2] << 16) |
             ((unsigned char)key_block_buffer[start_ofset + 3] << 24);
    }
    uint32_t comp_type = info & 0x0F;

    if (comp_type == 1 || comp_type == 2) {
      // Try with 8-byte header skip
      std::cerr
          << "[DEBUG] Attempting decompression with 8-byte header skip. Type: "
          << comp_type << std::endl;
      kb_uncompressed = try_decompress(key_block_buffer + start_ofset + 8,
                                       comp_size - 8, decomp_size, comp_type);
      if (!kb_uncompressed.empty())
        key_block = kb_uncompressed.data();
    }

    // Fallback for v1.x: try without header skip if it's LZO or unknown
    if (!key_block && this->version < 2.0 && comp_size != decomp_size) {
      std::cerr << "[DEBUG] Fallback for v1.x: attempting raw LZO from start."
                << std::endl;
      // Try LZO raw from the very start
      kb_uncompressed = try_decompress(key_block_buffer + start_ofset,
                                       comp_size, decomp_size, 1);
      if (!kb_uncompressed.empty()) {
        key_block = kb_uncompressed.data();
        std::cerr << "[DEBUG] Block " << idx
                  << " successfully decompressed with v1.x raw LZO fallback"
                  << std::endl;
      }
    }

    if (!key_block) {
      if (comp_size == decomp_size) {
        std::cerr << "[DEBUG] Block " << idx
                  << " is uncompressed. comp=" << comp_size
                  << " decomp=" << decomp_size << std::endl;
        key_block = (unsigned char *)(key_block_buffer + start_ofset);
        if (comp_type != 0 && this->version >= 2.0) {
          key_block += 8; // Skip header anyway if version >= 2.0
          std::cerr << "[DEBUG] Block " << idx
                    << " uncompressed, skipping 8-byte header for v2.0+."
                    << std::endl;
        }
      } else {
        std::cerr << "[ERROR] Block " << idx
                  << " decompression failed. comp=" << comp_size
                  << " decomp=" << decomp_size << " type=" << comp_type
                  << std::endl;
        throw std::runtime_error("key block decompress failed");
      }
    }

    // split key
    std::vector<key_list_item *> tlist =
        split_key_block(key_block, decomp_size, idx);
    key_list.insert(key_list.end(), tlist.begin(), tlist.end());

    // next round
    i += comp_size;
  }
  assert(key_list.size() == this->entries_num);
  /// passed

  this->record_block_info_offset = this->key_block_info_start_offset +
                                   this->key_block_info_size +
                                   this->key_block_size;
  /// passed

  return 0;
}

// note: kb_info_buff_len == key_block_info_compressed_size

/**
 * decode the record block
 * @param record_block_buffer
 * @param rb_len record block buffer length
 * @return
 */
int Mdict::read_record_block_header() {
  /**
   * record block info section
   * decode the record block info section
   * [0:8/4]    - record blcok number
   * [8:16/4:8] - num entries the key-value entries number
   * [16:24/8:12] - record block info size
   * [24:32/12:16] - record block size
   */
  if (this->version >= 2.0) {
    record_block_info_size = 4 * 8;
  } else {
    record_block_info_size = 4 * 4;
  }

  char *record_info_buffer =
      (char *)calloc(record_block_info_size, sizeof(char));

  this->readfile(record_block_info_offset, record_block_info_size,
                 record_info_buffer);

  if (this->version >= 2.0) {
    record_block_number = be_bin_to_u64((unsigned char *)record_info_buffer);
    record_block_entries_number = be_bin_to_u64(
        (unsigned char *)record_info_buffer + number_width * sizeof(char));
    record_block_header_size = be_bin_to_u64(
        (unsigned char *)record_info_buffer + 2 * number_width * sizeof(char));
    record_block_size = be_bin_to_u64((unsigned char *)record_info_buffer +
                                      3 * number_width * sizeof(char));
  } else {
    record_block_number = be_bin_to_u32((unsigned char *)record_info_buffer);
    record_block_entries_number = be_bin_to_u32(
        (unsigned char *)record_info_buffer + number_width * sizeof(char));
    record_block_header_size = be_bin_to_u32(
        (unsigned char *)record_info_buffer + 2 * number_width * sizeof(char));
    record_block_size = be_bin_to_u32((unsigned char *)record_info_buffer +
                                      3 * number_width * sizeof(char));
  }

  free(record_info_buffer);
  assert(record_block_entries_number == entries_num);
  /// passed

  /**
   * record_block_header_list:
   * {
   *     compressed size
   *     decompressed size
   * }
   */

  char *record_header_buffer =
      (char *)calloc(record_block_header_size, sizeof(char));

  this->readfile(this->record_block_info_offset + record_block_info_size,
                 record_block_header_size, record_header_buffer);

  unsigned long comp_size = 0l;
  unsigned long uncomp_size = 0l;
  unsigned long size_counter = 0l;

  unsigned long comp_accu = 0l;
  unsigned long decomp_accu = 0l;

  for (unsigned long i = 0; i < record_block_number; ++i) {
    if (this->version >= 2.0) {
      comp_size =
          be_bin_to_u64((unsigned char *)(record_header_buffer + size_counter));
      size_counter += number_width;
      uncomp_size =
          be_bin_to_u64((unsigned char *)(record_header_buffer + size_counter));
      size_counter += number_width;

      this->record_header.push_back(new record_header_item(
          i, comp_size, uncomp_size, comp_accu, decomp_accu));
      // ensure after push
      comp_accu += comp_size;
      decomp_accu += uncomp_size;
    } else {
      comp_size =
          be_bin_to_u32((unsigned char *)(record_header_buffer + size_counter));
      size_counter += number_width;
      uncomp_size =
          be_bin_to_u32((unsigned char *)(record_header_buffer + size_counter));
      size_counter += number_width;

      this->record_header.push_back(new record_header_item(
          i, comp_size, uncomp_size, comp_accu, decomp_accu));

      comp_accu += comp_size;
      decomp_accu += uncomp_size;
    }
  }

  free(record_header_buffer);
  assert(this->record_header.size() == this->record_block_number);
  assert(size_counter == this->record_block_header_size);

  record_block_offset = record_block_info_offset + record_block_info_size +
                        record_block_header_size;
  /// passed
  return 0;
}

std::vector<uint8_t>
Mdict::decode_record_block_buffer_by_rid(unsigned long rid) {
  uint64_t record_offset = this->record_block_offset;
  std::vector<uint8_t> record_block_uncompressed_v;
  unsigned long idx = rid;

  if (idx >= record_header.size()) {
    return {};
  }

  uint64_t comp_size = record_header[idx]->compressed_size;
  uint64_t uncomp_size = record_header[idx]->decompressed_size;
  uint64_t comp_accu = record_header[idx]->compressed_size_accumulator;

  char *record_block_cmp_buffer = (char *)malloc(comp_size);
  if (!record_block_cmp_buffer) {
    throw std::runtime_error("Failed to allocate record_block_cmp_buffer");
  }

  this->readfile(record_offset + comp_accu, comp_size, record_block_cmp_buffer);

  uint32_t info = 0;
  if (comp_size >= 8) {
    info = (unsigned char)record_block_cmp_buffer[0] |
           ((unsigned char)record_block_cmp_buffer[1] << 8) |
           ((unsigned char)record_block_cmp_buffer[2] << 16) |
           ((unsigned char)record_block_cmp_buffer[3] << 24);
  }
  uint32_t comp_type = info & 0x0F;

  auto try_decompress = [&](const unsigned char *src, size_t len, size_t d_size,
                            int method) -> std::vector<uint8_t> {
    if (method == 1) { // LZO
      std::vector<uint8_t> res = lzo_raw_uncompress(src, len, d_size);
      if (!res.empty())
        return res;
      return lzo_mdict_uncompress(src, len, d_size);
    } else if (method == 2) { // ZLIB
      return zlib_mem_uncompress(src, len, d_size);
    }
    return {};
  };

  if (comp_type == 1 || comp_type == 2) {
    record_block_uncompressed_v =
        try_decompress((unsigned char *)record_block_cmp_buffer + 8,
                       comp_size - 8, uncomp_size, comp_type);
  }

  if (record_block_uncompressed_v.empty() && this->version < 2.0 &&
      comp_size != uncomp_size) {
    record_block_uncompressed_v = try_decompress(
        (unsigned char *)record_block_cmp_buffer, comp_size, uncomp_size, 1);
  }

  if (record_block_uncompressed_v.empty()) {
    if (comp_size == uncomp_size) {
      record_block_uncompressed_v.assign(record_block_cmp_buffer,
                                         record_block_cmp_buffer + comp_size);
      if (comp_type != 0 && this->version >= 2.0 &&
          record_block_uncompressed_v.size() >= 8) {
        // Skip 8-byte header if present in uncompressed block
        record_block_uncompressed_v.erase(record_block_uncompressed_v.begin(),
                                          record_block_uncompressed_v.begin() +
                                              8);
      }
    } else {
      free(record_block_cmp_buffer);
      throw std::runtime_error("record block decompress failed");
    }
  }

  free(record_block_cmp_buffer);
  return record_block_uncompressed_v;
}

std::vector<std::pair<std::string, std::string>>
Mdict::decode_record_block_by_rid(unsigned long rid /* record id */) {
  // key list index counter
  unsigned long i = 0l;
  unsigned long idx = rid;

  if (idx >= record_header.size())
    return {};

  uint64_t uncomp_size = record_header[idx]->decompressed_size;
  uint64_t decomp_accu = record_header[idx]->decompressed_size_accumulator;
  uint64_t previous_end = 0;
  uint64_t previous_uncomp_size = 0;
  if (idx > 0) {
    previous_end = record_header[idx - 1]->decompressed_size_accumulator;
    previous_uncomp_size = record_header[idx - 1]->decompressed_size;
  }

  std::vector<uint8_t> record_block_uncompressed_v =
      decode_record_block_buffer_by_rid(rid);
  if (record_block_uncompressed_v.empty())
    return {};

  unsigned char *record_block = record_block_uncompressed_v.data();
  /**
   * 请注意，block 是会有很多个的，而每个block都可能会被压缩
   * 而 key_list中的 record_start,
   * key_text是相对每一个block而言的，end是需要每次解析的时候算出来的
   * 所有的record_start/length/end都是针对解压后的block而言的
   */

  std::vector<std::pair<std::string, std::string>> vec;

  while (i < this->key_list.size()) {
    // TODO OPTIMISE
    unsigned long record_start = key_list[i]->record_start;

    std::string key_text = key_list[i]->key_word;
    // start, skip the keys which not includes in record block
    if (record_start < decomp_accu) {
      i++;
      continue;
    }

    // end important: the condition should be lgt, because, the end bound will
    // be equal to uncompressed size
    // this part ensures the record match to key list bound
    if (record_start - decomp_accu >= uncomp_size) {
      break;
    }

    unsigned long upbound = uncomp_size; // - this->key_list[i]->record_start;
    unsigned long expect_end = 0;
    auto expect_start = this->key_list[i]->record_start - decomp_accu;
    if (i < this->key_list.size() - 1) {
      expect_end =
          this->key_list[i + 1]->record_start - this->key_list[i]->record_start;
      expect_start = this->key_list[i]->record_start - decomp_accu;
    } else {
      // 前一个的 end + size 等于当前这个的开始
      expect_end =
          this->record_block_size - (previous_end + previous_uncomp_size);
    }
    upbound = expect_end < upbound ? expect_end : upbound;

    std::string def;
    if (this->filetype == "MDD") {
      def = be_bin_to_utf16((char *)record_block, expect_start,
                            upbound /* to delete null character*/);
    } else {
      if (this->encoding == 1 /* ENCODING_UTF16 */) {
        def = le_bin_utf16_to_utf8((char *)record_block + expect_start, 0,
                                   upbound);
      } else {
        def = be_bin_to_utf8((char *)record_block, expect_start,
                             upbound /* to delete null character*/);
      }
    }
    std::pair<std::string, std::string> vp(key_text, def);
    vec.push_back(vp);
    i++;
  }

  //  assert(size_counter == record_block_size);
  return vec;
}

// this function is used to decode the record block, it will read the record
// block from the file, avoid use this function
int Mdict::decode_record_block() {
  // record block start offset: record_block_offset
  uint64_t record_offset = this->record_block_offset;

  uint64_t size_counter = 0l;

  // key list index counter
  unsigned long i = 0l;

  // record offset
  unsigned long offset = 0l;

  std::vector<uint8_t> record_block_uncompressed_v;
  unsigned char *record_block_uncompressed_b;
  uint64_t checksum = 0l;
  for (int idx = 0; idx < static_cast<int>(this->record_header.size()); idx++) {
    uint64_t comp_size = record_header[idx]->compressed_size;
    uint64_t uncomp_size = record_header[idx]->decompressed_size;
    char *record_block_cmp_buffer = (char *)calloc(comp_size, sizeof(char));
    this->readfile(record_offset, comp_size, record_block_cmp_buffer);
    //    putbytes(record_block_cmp_buffer, 8, true);
    // 4 bytes, compress type
    char *comp_type_b = (char *)calloc(4, sizeof(char));
    memcpy(comp_type_b, record_block_cmp_buffer, 4 * sizeof(char));
    //    putbytes(comp_type_b, 4, true);
    int comp_type = comp_type_b[0] & 0xff;
    // 4 bytes adler32 checksum
    char *checksum_b = (char *)calloc(4, sizeof(char));
    memcpy(checksum_b, record_block_cmp_buffer + 4, 4 * sizeof(char));
    checksum = be_bin_to_u32((unsigned char *)checksum_b);
    free(checksum_b);

    if (comp_type == 0 /* not compressed TODO*/) {
      throw std::runtime_error("uncompress block not support yet");
    } else {
      char *record_block_decrypted_buff;
      if (this->encrypt == ENCRYPT_RECORD_ENC /* record block encrypted */) {
        // TODO
        throw std::runtime_error("record encrypted not support yet");
      }
      record_block_decrypted_buff = record_block_cmp_buffer + 8 * sizeof(char);
      // decompress
      if (comp_type == 1 /* lzo */) {
        record_block_uncompressed_v = lzo_mdict_uncompress(
            record_block_decrypted_buff, comp_size - 8, uncomp_size);
        if (record_block_uncompressed_v.empty() ||
            record_block_uncompressed_v.size() == 0) {
          throw std::runtime_error("record block decompress failed (LZO)");
        }
        record_block_uncompressed_b = record_block_uncompressed_v.data();
        uint32_t adler32cs = adler32checksum(
            record_block_uncompressed_b, static_cast<uint32_t>(uncomp_size));
        assert(adler32cs == checksum);
        assert(record_block_uncompressed_v.size() == uncomp_size);
      } else if (comp_type == 2) {
        // zlib compress
        record_block_uncompressed_v =
            zlib_mem_uncompress(record_block_decrypted_buff, comp_size - 8);
        if (record_block_uncompressed_v.empty()) {
          throw std::runtime_error("record block decompress failed size == 0");
        }
        record_block_uncompressed_b = record_block_uncompressed_v.data();
        uint32_t adler32cs = adler32checksum(
            record_block_uncompressed_b, static_cast<uint32_t>(uncomp_size));
        assert(adler32cs == checksum);
        assert(record_block_uncompressed_v.size() == uncomp_size);
      } else {
        throw std::runtime_error(
            "cannot determine the record block compress type");
      }
    }

    free(comp_type_b);
    free(record_block_cmp_buffer);
    //    free(record_block_uncompressed_b); /* ensure not free twice*/

    // unsigned char* record_block = record_block_uncompressed_b;
    /**
     * 请注意，block 是会有很多个的，而每个block都可能会被压缩
     * 而 key_list中的 record_start,
     * key_text是相对每一个block而言的，end是需要每次解析的时候算出来的
     * 所有的record_start/length/end都是针对解压后的block而言的
     */
    while (i < this->key_list.size()) {
      unsigned long record_start = key_list[i]->record_start;
      std::string key_text = key_list[i]->key_word;
      if (record_start - offset >= uncomp_size) {
        // overflow
        break;
      }
      unsigned long record_end;
      if (i < this->key_list.size() - 1) {
        record_end = this->key_list[i + 1]->record_start;
      } else {
        record_end = uncomp_size + offset;
      }

      this->key_data.push_back(new record(
          key_text, key_list[i]->record_start, this->encoding, record_offset,
          comp_size, uncomp_size, comp_type, (this->encrypt == 1),
          record_start - offset, record_end - offset));
      i++;
    }
    // offset += record_block.length
    offset += uncomp_size;
    size_counter += comp_size;
    record_offset += comp_size;

    //    break;
  }
  assert(size_counter == record_block_size);
  return 0;
}

/**
 * decode the key block info
 * @param key_block_info_buffer the key block info buffer
 * @param kb_info_buff_len the key block buffer length
 * @param key_block_num the key block number
 * @param entries_num the entries number
 * @return
 */
int Mdict::decode_key_block_info(char *key_block_info_buffer,
                                 unsigned long kb_info_buff_len,
                                 int key_block_num, int entries_num) {
  char *kb_info_buff = key_block_info_buffer;

  // key block info offset indicator
  unsigned long data_offset = 0;

  std::vector<uint8_t> decompress_buff;
  uint8_t *info_data_ptr = nullptr;
  unsigned long info_data_len = 0;

  if (this->version >= 2.0) {
    // if version >= 2.0, use zlib compression
    if (kb_info_buff_len < 4 || kb_info_buff[0] != 2) {
      throw std::runtime_error("Invalid or unsupported key block info header");
    }

    byte *kb_info_decrypted = (unsigned char *)key_block_info_buffer;
    if (this->encrypt == ENCRYPT_KEY_INFO_ENC) {
      kb_info_decrypted = mdx_decrypt((byte *)kb_info_buff, kb_info_buff_len);
    }

    // version 2.0: compressed by zlib
    // note: we should uncompress key_block_info_buffer[8:] data, so we need
    // (decrypted + 8, and length -8)
    decompress_buff =
        zlib_mem_uncompress(kb_info_decrypted + 8, kb_info_buff_len - 8,
                            this->key_block_info_decompress_size);

    if (decompress_buff.size() != this->key_block_info_decompress_size) {
      throw std::runtime_error("Key block info decompression size mismatch");
    }
    info_data_ptr = decompress_buff.data();
    info_data_len = decompress_buff.size();
  } else {
    // Version < 2.0: check if compressed
    // Check if it starts with compression type byte (0=none, 1=lzo, 2=zlib)
    if (kb_info_buff_len > 8 &&
        (kb_info_buff[0] == 1 || kb_info_buff[0] == 2)) {
      // Try to decompress
      if (kb_info_buff[0] == 2) {
        // zlib
        decompress_buff = zlib_mem_uncompress((unsigned char *)kb_info_buff + 8,
                                              kb_info_buff_len - 8);
        info_data_ptr = decompress_buff.data();
        info_data_len = decompress_buff.size();
      } else if (kb_info_buff[0] == 1) {
        // LZO - need decompressed size
        uint32_t decomp_size = be_bin_to_u32((unsigned char *)kb_info_buff + 4);
        decompress_buff =
            lzo_mdict_uncompress((unsigned char *)kb_info_buff + 8,
                                 kb_info_buff_len - 8, decomp_size);
        info_data_ptr = decompress_buff.data();
        info_data_len = decompress_buff.size();
      }
    } else {
      info_data_ptr = (uint8_t *)key_block_info_buffer;
      info_data_len = kb_info_buff_len;
    }
  }

  /// entries summary, every block has a lot of entries, the sum of entries
  /// should equals entries_number
  unsigned long num_entries_counter = 0;
  // key number counter
  unsigned long counter = 0;

  // current block entries
  unsigned long current_entries = 0;
  unsigned long previous_start_offset = 0;

  // v1.x uses 1 byte, v2.0 uses 2 bytes for key length
  int byte_width = (this->version >= 2.0f) ? 2 : 1;
  int text_term = (this->version >= 2.0f) ? 1 : 0;

  unsigned long comp_acc = 0l;
  unsigned long decomp_acc = 0l;
  while (counter < this->key_block_num) {
    if (data_offset + this->number_width > info_data_len) {
      break;
    }
    if (this->version >= 2.0) {
      auto bin_pointer = info_data_ptr + data_offset;
      current_entries = be_bin_to_u64(bin_pointer);
    } else {
      auto bin_pointer = info_data_ptr + data_offset;
      current_entries = be_bin_to_u32(bin_pointer);
    }
    num_entries_counter += current_entries;

    // move offset
    data_offset += this->number_width;

    // first key size
    unsigned long first_key_size = 0;

    if (this->version >= 2.0f) {
      first_key_size = be_bin_to_u16(info_data_ptr + data_offset);
    } else {
      first_key_size = be_bin_to_u8(info_data_ptr + data_offset);
    }
    data_offset += byte_width;

    // step_gap means first key start offset to first key end;
    int step_gap = 0;

    if (this->encoding == 1 /* ENCODING_UTF16 */) {
      step_gap = (first_key_size + text_term) * 2;
    } else {
      step_gap = first_key_size + text_term;
    }

    // DECODE first CODE
    unsigned long first_key_len =
        (unsigned long)step_gap - (text_term * (this->encoding == 1 ? 2 : 1));
    std::string first_key =
        decode_key_text((char *)(info_data_ptr + data_offset), first_key_len);

    // move forward
    data_offset += step_gap;

    // the last key
    unsigned long last_key_size = 0;

    if (data_offset + byte_width > info_data_len) {
      break;
    }

    if (this->version >= 2.0f) {
      last_key_size = be_bin_to_u16(info_data_ptr + data_offset);
    } else {
      last_key_size = be_bin_to_u8(info_data_ptr + data_offset);
    }
    data_offset += byte_width;

    if (this->encoding == 1 /* ENCODING_UTF16 */) {
      step_gap = (last_key_size + text_term) * 2;
    } else {
      step_gap = last_key_size + text_term;
    }

    unsigned long last_key_len =
        (unsigned long)step_gap - (text_term * (this->encoding == 1 ? 2 : 1));
    std::string last_key =
        decode_key_text((char *)(info_data_ptr + data_offset), last_key_len);

    // move forward
    data_offset += step_gap;

    // ------------
    // key block part
    // ------------

    uint64_t key_block_compress_size = 0;
    if (version >= 2.0) {
      key_block_compress_size = be_bin_to_u64(info_data_ptr + data_offset);
    } else {
      key_block_compress_size = be_bin_to_u32(info_data_ptr + data_offset);
    }
    data_offset += this->number_width;

    uint64_t key_block_decompress_size = 0;
    if (version >= 2.0) {
      key_block_decompress_size = be_bin_to_u64(info_data_ptr + data_offset);
    } else {
      key_block_decompress_size = be_bin_to_u32(info_data_ptr + data_offset);
    }
    data_offset += this->number_width;

    key_block_info *kbinfo = new key_block_info(
        first_key, last_key, previous_start_offset, key_block_compress_size,
        key_block_decompress_size, comp_acc, decomp_acc);

    kbinfo->first_key_normalized = _s(first_key);
    kbinfo->last_key_normalized = _s(last_key);

    // Sanity check: reject blocks with suspiciously large sizes
    if (key_block_compress_size > 100000000 ||
        key_block_decompress_size > 100000000) {
      delete kbinfo;
      break;
    }

    // adjust offset
    previous_start_offset += key_block_compress_size;
    key_block_info_list.push_back(kbinfo);

    // key block counter
    counter += 1;
    // accumulate
    comp_acc += key_block_compress_size;
    decomp_acc += key_block_decompress_size;

    // Boundary check for next iteration
    if (data_offset + this->number_width * 2 > info_data_len &&
        counter + 1 < this->key_block_num) {
      break;
    }
  }

  // Update key_block_num to the actual number of blocks we successfully
  // parsed
  if (counter != this->key_block_num) {
    this->key_block_num = counter;
  }

  if (num_entries_counter != this->entries_num) {
  }

  this->key_block_body_start =
      this->key_block_info_start_offset + this->key_block_info_size;
  /// passed
  return 0;
}

/**
 * read in the file from the file stream
 * @param offset the file start offset
 * @param len the byte length needs to read
 * @param buf the target buffer
 */
void Mdict::readfile(uint64_t offset, uint64_t len, char *buf) {
  instream.seekg(offset);
  instream.read(buf, static_cast<std::streamsize>(len));
}

/***************************************
 *             public part             *
 ***************************************/

/**
 * init the dictionary file
 */
void Mdict::init() {
  // Init LZO
  if (lzo_init() != LZO_E_OK) {
    throw std::runtime_error("LZO initialization failed");
  }

  this->instream = std::ifstream(filename, std::ios::binary);
  if (!this->instream.is_open()) {
    throw std::runtime_error("Failed to open file: " + filename);
  }

  /* indexing... */
  this->read_header();
  this->read_key_block_header();
  this->read_key_block_info();
  this->read_record_block_header();
  //  this->decode_record_block(); // don't use this function, it's too slow
}

/**
 * find the key word includes in which block
 * @param phrase
 * @param start
 * @param end
 * @return
 */
long Mdict::reduce_key_info_block(
    std::string phrase, unsigned long start,
    unsigned long end) { // non-recursive reduce implements
  for (size_t i = 0; i < end; ++i) {
    if (phrase.compare(this->key_block_info_list[i]->first_key_normalized) >=
            0 &&
        phrase.compare(this->key_block_info_list[i]->last_key_normalized) <=
            0) {
      return i;
    }
  }
  return -1;
}

long Mdict::reduce_key_info_block_items_vector(
    std::vector<key_list_item *> wordlist,
    std::string phrase) { // non-recursive reduce implements
  unsigned long left = 0;
  unsigned long right = wordlist.size() - 1;
  unsigned long mid = 0;
  std::string word = _s(std::move(phrase));

  int comp = 0;
  while (left <= right) {
    mid = left + ((right - left) >> 1);
    std::string mid_word_norm = _s(wordlist[mid]->key_word);
    comp = word.compare(mid_word_norm);

    if (comp == 0) {
      return mid;
    } else if (comp > 0) {
      left = mid + 1;
    } else {
      if (mid == 0)
        break;
      right = mid - 1;
    }
  }
  return -1;
}

/**
 *
 * @param wordlist
 * @param phrase
 * @return
 */
long Mdict::reduce_record_block_offset(
    unsigned long record_start) { // non-recursive reduce implements
  // TODO OPTIMISE
  unsigned long left = 0l;
  unsigned long right = this->record_header.size() - 1;
  unsigned long mid = 0;
  while (left <= right) {
    mid = left + ((right - left) >> 1);
    if (record_start >=
        this->record_header[mid]->decompressed_size_accumulator) {
      left = mid + 1;
    } else if (record_start <
               this->record_header[mid]->decompressed_size_accumulator) {
      right = mid - 1;
    }
  }
  return left - 1;
  return 0;
}

std::string Mdict::reduce_particial_keys_vector(
    std::vector<std::pair<std::string, std::string>> &vec, std::string phrase) {
  unsigned int left = 0;
  unsigned int right = vec.size() - 1;
  unsigned int mid = 0;
  unsigned int result = 0;
  while (left < right) {
    mid = left + ((right - left) >> 1);
    const auto first_word = _s(phrase);
    const auto second_word = _s(vec[mid].first);
    if (first_word.compare(second_word) > 0) {
      left = mid + 1;
    } else if (first_word.compare(second_word) == 0) {
      left = mid;
      break;
    } else {
      right = mid > 1 ? mid - 1 : mid;
    }
  }
  result = left;

  return vec[result].second;
}

std::string Mdict::locate(const std::string resource_name,
                          mdict_encoding_t encoding) {
  // find key item in key list
  auto it = std::find_if(this->key_list.begin(), this->key_list.end(),
                         [&](const key_list_item *item) {
                           return item->key_word == resource_name;
                         });
  if (it != this->key_list.end()) {
    std::string key_word = (*it)->key_word;
    if (key_word == resource_name) {
      if ((*it)->record_start >= 0) {
        // reduce search the record block index by word record start offset
        unsigned long record_block_idx =
            reduce_record_block_offset((*it)->record_start);
        // decode recode by record index
        auto vec = decode_record_block_by_rid(record_block_idx);
        // reduce the definition by word
        std::string def = reduce_particial_keys_vector(vec, resource_name);

        auto treated_output = trim_nulls(def);

        if (encoding == MDICT_ENCODING_HEX) {
          return treated_output; // Return raw hex string
        } else {
          return base64_from_hex(
              treated_output); // Return base64 encoded string
        }
      }
      return std::string("");
    }
  }
  return std::string("");
}

std::string Mdict::lookup0(const std::string word) {
  try {

    auto it = std::find_if(
        this->key_list.begin(), this->key_list.end(),
        [&](const key_list_item *item) { return item->key_word == word; });
    if (it != this->key_list.end()) {
      std::string key_word = (*it)->key_word;
      if (key_word == word) {
        if ((*it)->record_start >= 0) {
          // reduce search the record block index by word record start offset
          unsigned long record_block_idx =
              reduce_record_block_offset((*it)->record_start);
          // decode recode by record index
          auto vec = decode_record_block_by_rid(record_block_idx);
          // reduce the definition by word
          std::string def = reduce_particial_keys_vector(vec, word);

          auto treated_output = trim_nulls(def);

          return treated_output;
        }
        return std::string("");
      }
    }
    return std::string("");

  } catch (std::exception &e) {
    std::cout << "lookup error: " << e.what() << std::endl;
  }
  return std::string();
}

/**
 * look the file by word
 * @param word the searching word
 * @return
 */
std::string Mdict::lookup(const std::string word) {
  try {
    std::string normalized_query = _s(word);

    // search word in key block info list
    long idx = this->reduce_key_info_block(normalized_query, 0,
                                           this->key_block_info_list.size());
    if (idx >= 0) {
      // decode key block by block id
      std::vector<key_list_item *> tlist =
          this->decode_key_block_by_block_id(idx);

      // reduce word id from key list item vector to get the word index of key
      // list
      long word_id =
          reduce_key_info_block_items_vector(tlist, normalized_query);
      if (word_id >= 0) {
        // reduce search the record block index by word record start offset
        unsigned long record_block_idx =
            reduce_record_block_offset(tlist[word_id]->record_start);

        // decode recode by record index
        auto vec = decode_record_block_by_rid(record_block_idx);
        // reduce the definition by word
        std::string def = reduce_particial_keys_vector(vec, normalized_query);

        return def;
      } else {
      }
    } else {
    }
  } catch (std::exception &e) {
    std::cerr << "lookup error: " << e.what() << std::endl;
  }
  return std::string();
}

std::string Mdict::parse_definition(const std::string word,
                                    unsigned long record_start) {
  // reduce search the record block index by word record start offset
  long record_block_idx = reduce_record_block_offset(record_start);
  if (record_block_idx < 0)
    return "";

  // decode record block buffer
  std::vector<uint8_t> buffer =
      decode_record_block_buffer_by_rid(record_block_idx);
  if (buffer.empty())
    return "";

  // Find exact offset in global key_list to determine length
  // Binary search for record_start in key_list
  auto it = std::lower_bound(
      this->key_list.begin(), this->key_list.end(), record_start,
      [](key_list_item *a, unsigned long b) { return a->record_start < b; });

  if (it == this->key_list.end() || (*it)->record_start != record_start) {
    // Fallback: If exact offset not found (rare), use word-based search in
    // block
    std::vector<std::pair<std::string, std::string>> vec;
    // Re-populate vec for this block
    unsigned long i = 0;
    uint64_t decomp_accu =
        record_header[record_block_idx]->decompressed_size_accumulator;
    uint64_t uncomp_size = record_header[record_block_idx]->decompressed_size;

    while (i < this->key_list.size()) {
      if (key_list[i]->record_start < decomp_accu) {
        i++;
        continue;
      }
      if (key_list[i]->record_start - decomp_accu >= uncomp_size)
        break;
      // ... (simplified loop code for fallback)
      i++;
    }
    return reduce_particial_keys_vector(vec, word);
  }

  unsigned long start_in_block =
      record_start -
      this->record_header[record_block_idx]->decompressed_size_accumulator;
  unsigned long end_in_block;

  if (std::next(it) != this->key_list.end()) {
    end_in_block =
        (*std::next(it))->record_start -
        this->record_header[record_block_idx]->decompressed_size_accumulator;
  } else {
    end_in_block = this->record_header[record_block_idx]->decompressed_size;
  }

  // Safety clamps
  if (end_in_block > buffer.size())
    end_in_block = buffer.size();
  if (start_in_block >= end_in_block)
    return "";

  unsigned long len = end_in_block - start_in_block;

  std::string def;
  if (this->filetype == "MDD") {
    def = be_bin_to_utf16((char *)buffer.data(), start_in_block, len);
  } else {
    def = decode_key_text((const char *)buffer.data() + start_in_block, len);
  }
  return def;
}
std::string Mdict::decode_key_text(const char *data, size_t len) {
  if (this->encoding == 1 /* ENCODING_UTF16 */) {
    if (len >= 2 && data[0] == 0 && data[1] != 0) {
      return be_bin_utf16_to_utf8(data, 0, (int)len);
    }
    return le_bin_utf16_to_utf8(data, 0, (int)len);
  } else if (this->encoding == 0 /* ENCODING_UTF8 */) {
    return std::string(data, len);
  } else if (this->encoding == 3 /* ENCODING_GBK */ ||
             this->encoding == 5 /* ENCODING_GB18030 */) {
    return convert_encoding(data, 0, (unsigned long)len, "GB18030");
  } else if (this->encoding == 4 /* ENCODING_GB2312 */) {
    return convert_encoding(data, 0, (unsigned long)len, "GB2312");
  } else if (this->encoding == 2 /* ENCODING_BIG5 */) {
    return convert_encoding(data, 0, (unsigned long)len, "BIG5");
  }
  return std::string(data, len);
}

/**
 * look the file by word
 * @param word the searching word
 * @return
 */
std::vector<key_list_item *> Mdict::keyList() { return this->key_list; }

std::vector<key_list_item *> Mdict::search(const std::string query, int method,
                                           int max_results) {
  std::vector<key_list_item *> hits;
  std::string q_norm = _s(query);

  for (auto *item : this->key_list) {
    if (!item)
      continue;
    const std::string &k_norm = item->key_word_normalized;

    bool isMatch = false;
    switch (method) {
    case 0: // Exact
      isMatch = (k_norm == q_norm);
      break;
    case 1: // Forward
      isMatch = (k_norm.find(q_norm) == 0);
      break;
    case 2: // Backward
      if (k_norm.length() >= q_norm.length()) {
        isMatch = (k_norm.compare(k_norm.length() - q_norm.length(),
                                  q_norm.length(), q_norm) == 0);
      }
      break;
    default: // Contain
      isMatch = (k_norm.find(q_norm) != std::string::npos);
      break;
    }

    if (isMatch) {
      hits.push_back(item);
      if (hits.size() >= (size_t)max_results)
        break;
    }
  }
  return hits;
}
bool Mdict::endsWith(std::string const &fullString, std::string const &ending) {
  if (fullString.length() >= ending.length()) {
    return (0 == fullString.compare(fullString.length() - ending.length(),
                                    ending.length(), ending));
  } else {
    return false;
  }
}
} // namespace mdict
