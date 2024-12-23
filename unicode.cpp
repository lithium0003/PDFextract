// https://github.com/nodec-project/nodec/blob/main/include/nodec/unicode.cpp

#include "unicode.hpp"

namespace nodec {
/*
 * Unicode
 *   "
 *       The Unicode Standard defines a codespace of numerical values
 *       ranging from 0 through 10FFFF, called code points and
 *       denoted as U+0000 through U+10FFFF respectively.
 *       <https://en.wikipedia.org/wiki/Unicode>
 *   "
 *
 */
namespace unicode {

namespace details {

/**
 * UTF-8
 *   The x characters are replaced by the bits of the code point.
 *
 *   |UTF-8 Number of bytes |  Byte 1   |  Byte 2   |  Byte 3   |  Byte 4   |
 *   +----------------------+-----------+-----------+-----------+-----------+
 *   |           1          | 0xxx xxxx |           |           |           |
 *   |           2          | 110x xxxx | 10xx xxxx |           |           |
 *   |           3          | 111x xxxx | 10xx xxxx | 10xx xxxx |           |
 *   |           4          | 1111 0xxx | 10xx xxxx | 10xx xxxx | 10xx xxxx |
 *
 *   <https://en.wikipedia.org/wiki/UTF-8>
 */

/**
 * UTF-16
 *   U+0000 to U+D7FF and U+E000 to U+FFFF
 *       Both UTF-16 and UCS-2 encode code points in this range as single 16-bit code units
 *       that are numerically equal to the corresponding code points.
 *   Code points from U+010000 to U+10FFFF
 *       U' = yyyyyyyyyyxxxxxxxxxx  // U - 0x10000
 *       W1 = 110110yyyyyyyyyy      // 0xD800 + yyyyyyyyyy
 *       W2 = 110111xxxxxxxxxx      // 0xDC00 + xxxxxxxxxx
 *   U+D800 to U+DFFF
 *       The Unicode standard permanently reserves these code point values
 *       for UTF-16 encoding of the high and low surrogates,
 *       and they will never be assigned a character,
 *       so there should be no reason to encode them.
 *
 *   | U+0000   |
 *   |   ~      |
 *   | U+D7FF   |
 *   | U+D800   | high_begin
 *   |   ~      |
 *   | U+DBFF   | hight_end
 *   | U+DC00   | low_begin
 *   |   ~      |
 *   | U+DFFF   | low_end
 *   | U+E000   |
 *   |   ~      |
 *   | U+FFFF   | max_bmp
 *   |   ~      |
 *   | U+10FFFF |
 *
 *   <https://en.wikipedia.org/wiki/UTF-16>
 */

const std::array<uint8_t, 7> FIRST_BYTE_MARK = {
    0x00, // 0: 0000 0000
    0x00, // 1: 0000 0000
    0xC0, // 2: 1100 0000
    0xE0, // 3: 1110 0000
    0xF0, // 4: 1111 0000
    0xF8, // 5: 1111 1000
    0xFC  // 6: 1111 1100
};

const std::array<uint8_t, 256> UTF8_BYTES = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0000 0000 ~
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0010 0000 ~
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0100 0000 ~
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0110 0000 ~
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1000 0000 ~
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1010 0000 ~
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 1100 0000 ~
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,                                                 // 1110 0000 ~
    3, 3, 3, 3, 3, 3, 3, 3,                                                                         // 1111 0000 ~
    4, 4, 4, 4,                                                                                     // 1111 1000 ~
    5, 5, 5, 5                                                                                      // 1111 1100 ~ 1111 1111
};

const std::array<uint32_t, 6> UTF8_OFFSETS = {
    0x00000000UL, // 0: 0000 0000 0000 0000 0000 0000 0000 0000
    0x00003080UL, // 1: 0000 0000 0000 0000 0011 0000 1000 0000
    0x000E2080UL, // 2: 0000 0000 0000 1110 0010 0000 1000 0000
    0x03C82080UL, // 3: 0000 0011 1100 1000 0010 0000 1000 0000
    0xFA082080UL, // 4: 1111 1010 0000 1000 0010 0000 1000 0000
    0x82082080UL  // 5: 1000 0010 0000 1000 0010 0000 1000 0000
};

uint32_t check_strict(bool strict) {
    /**
     * Specials is a short Unicode block allocated at the very end of the Basic Multilingual Plane, at U+FFF0-FFFF.
     * U+FFFD REPLACEMENT CHARACTER used to replace an unknown, unrecognized or unrepresentable character
     */
    constexpr uint32_t replacement = 0x0000FFFD;
    if (strict) {
        details::throw_illegal_character_exception(__FILE__, __LINE__);
    }
    return replacement;
}

} // namespace details

} // namespace unicode
} // namespace nodec