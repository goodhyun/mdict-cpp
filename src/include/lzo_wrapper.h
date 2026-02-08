/*
 * Copyright (c) 2025-Present
 * All rights reserved.
 *
 * This code is licensed under the BSD 3-Clause License.
 * See the LICENSE file for details.
 */

#pragma once
#include "../../deps/minilzo/minilzo.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

/**
 * Decompresses raw LZO-compressed data (no header)
 */
inline std::vector<uint8_t> lzo_raw_uncompress(const void *source,
                                               size_t sourceLen,
                                               size_t decompressedLen) {
  if (decompressedLen == 0)
    return std::vector<uint8_t>();

  std::vector<uint8_t> buffer(decompressedLen);
  lzo_uint destLen = (lzo_uint)decompressedLen;

  int err = lzo1x_decompress_safe(
      reinterpret_cast<const lzo_bytep>(source), (lzo_uint)sourceLen,
      reinterpret_cast<lzo_bytep>(buffer.data()), &destLen, NULL);

  if (err == LZO_E_OK) {
    if (destLen != (lzo_uint)decompressedLen) {
      buffer.resize(destLen);
    }
    return buffer;
  }

  // Do not print error here, let the caller handle it or try fallback
  return std::vector<uint8_t>();
}

inline std::vector<uint8_t> lzo_mem_uncompress(const void *source,
                                               size_t sourceLen,
                                               size_t decompressedLen) {
  return lzo_raw_uncompress(source, sourceLen, decompressedLen);
}

/**
 * Decompresses MDict LZO-compressed data (requires 5-byte header: 0xF0 + size)
 *
 * @param source Pointer to the compressed data (without header)
 * @param sourceLen Length of the compressed data in bytes
 * @param decompressedLen Expected size of decompressed data
 * @return std::vector<uint8_t> The decompressed data, or empty vector if
 * decompression fails
 */
inline std::vector<uint8_t> lzo_mdict_uncompress(const void *source,
                                                 size_t sourceLen,
                                                 size_t decompressedLen) {
  if (decompressedLen == 0)
    return std::vector<uint8_t>();

  // MDict LZO format requires a 5-byte header: 0xF0 + 4-byte big-endian size
  std::vector<uint8_t> headerData(5 + sourceLen);
  headerData[0] = 0xF0;
  // Big-endian 32-bit size
  headerData[1] = (decompressedLen >> 24) & 0xFF;
  headerData[2] = (decompressedLen >> 16) & 0xFF;
  headerData[3] = (decompressedLen >> 8) & 0xFF;
  headerData[4] = decompressedLen & 0xFF;
  // Copy compressed data after header
  std::memcpy(headerData.data() + 5, source, sourceLen);

  std::vector<uint8_t> buffer(decompressedLen);
  lzo_uint destLen = (lzo_uint)decompressedLen;

  int err = lzo1x_decompress_safe(
      reinterpret_cast<const lzo_bytep>(headerData.data()),
      (lzo_uint)(5 + sourceLen), reinterpret_cast<lzo_bytep>(buffer.data()),
      &destLen, NULL);

  if (err == LZO_E_OK) {
    if (destLen != (lzo_uint)decompressedLen) {
      buffer.resize(destLen);
    }
    return buffer;
  }

  fprintf(stderr, "LZO MDict Error: %d\n", err);
  return std::vector<uint8_t>();
}
