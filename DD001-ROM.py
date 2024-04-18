# Incomplete and full of bugs. Do not use for serious work.

import struct
import traceback

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_debug, log_info, log_alert, log_warn, log_to_stderr, log_to_stdout
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.enums import SectionSemantics
from binaryninja import Settings
from binaryninja import PluginCommand
from binaryninja.types import Type

from inspect import currentframe, getframeinfo # for getting line nr

class PETSCII():
    # Unicode tables as defined by
    # https://dflund.se/~triad/krad/recode/petscii.html
    lower_table = {
        0x00 : 0,	#UNDEFINED
        0x01 : 0,	#UNDEFINED
        0x02 : 0,	#UNDEFINED
        0x03 : 0,	#UNDEFINED
        0x04 : 0,	#UNDEFINED
        0x05 : 0xF100,	#WHITE COLOR SWITCH (CUS)
        0x06 : 0,	#UNDEFINED
        0x07 : 0,	#UNDEFINED
        0x08 : 0xF118,	#DISABLE CHARACTER SET SWITCHING (CUS)
        0x09 : 0xF119,	#ENABLE CHARACTER SET SWITCHING (CUS)
        0x0A : 0,	#UNDEFINED
        0x0B : 0,	#UNDEFINED
        0x0C : 0,	#UNDEFINED
        0x0D : 0x000D,	#CARRIAGE RETURN
        0x0E : 0x000E,	#SHIFT OUT
        0x0F : 0,	#UNDEFINED
        0x10 : 0,	#UNDEFINED
        0x11 : 0xF11C,	#CURSOR DOWN (CUS)
        0x12 : 0xF11A,	#REVERSE VIDEO ON (CUS)
        0x13 : 0xF120,	#HOME (CUS)
        0x14 : 0x007F,	#DELETE
        0x15 : 0,	#UNDEFINED
        0x16 : 0,	#UNDEFINED
        0x17 : 0,	#UNDEFINED
        0x18 : 0,	#UNDEFINED
        0x19 : 0,	#UNDEFINED
        0x1A : 0,	#UNDEFINED
        0x1B : 0,	#UNDEFINED
        0x1C : 0xF101,	#RED COLOR SWITCH (CUS)
        0x1D : 0xF11D,	#CURSOR RIGHT (CUS)
        0x1E : 0xF102,	#GREEN COLOR SWITCH (CUS)
        0x1F : 0xF103,	#BLUE COLOR SWITCH (CUS)
        0x20 : 0x0020,	#SPACE
        0x21 : 0x0021,	#EXCLAMATION MARK
        0x22 : 0x0022,	#QUOTATION MARK
        0x23 : 0x0023,	#NUMBER SIGN
        0x24 : 0x0024,	#DOLLAR SIGN
        0x25 : 0x0025,	#PERCENT SIGN
        0x26 : 0x0026,	#AMPERSAND
        0x27 : 0x0027,	#APOSTROPHE
        0x28 : 0x0028,	#LEFT PARENTHESIS
        0x29 : 0x0029,	#RIGHT PARENTHESIS
        0x2A : 0x002A,	#ASTERISK
        0x2B : 0x002B,	#PLUS SIGN
        0x2C : 0x002C,	#COMMA
        0x2D : 0x002D,	#HYPHEN-MINUS
        0x2E : 0x002E,	#FULL STOP
        0x2F : 0x002F,	#SOLIDUS
        0x30 : 0x0030,	#DIGIT ZERO
        0x31 : 0x0031,	#DIGIT ONE
        0x32 : 0x0032,	#DIGIT TWO
        0x33 : 0x0033,	#DIGIT THREE
        0x34 : 0x0034,	#DIGIT FOUR
        0x35 : 0x0035,	#DIGIT FIVE
        0x36 : 0x0036,	#DIGIT SIX
        0x37 : 0x0037,	#DIGIT SEVEN
        0x38 : 0x0038,	#DIGIT EIGHT
        0x39 : 0x0039,	#DIGIT NINE
        0x3A : 0x003A,	#COLON
        0x3B : 0x003B,	#SEMICOLON
        0x3C : 0x003C,	#LESS-THAN SIGN
        0x3D : 0x003D,	#EQUALS SIGN
        0x3E : 0x003E,	#GREATER-THAN SIGN
        0x3F : 0x003F,	#QUESTION MARK
        0x40 : 0x0040,	#COMMERCIAL AT
        0x41 : 0x0061,	#LATIN SMALL LETTER A
        0x42 : 0x0062,	#LATIN SMALL LETTER B
        0x43 : 0x0063,	#LATIN SMALL LETTER C
        0x44 : 0x0064,	#LATIN SMALL LETTER D
        0x45 : 0x0065,	#LATIN SMALL LETTER E
        0x46 : 0x0066,	#LATIN SMALL LETTER F
        0x47 : 0x0067,	#LATIN SMALL LETTER G
        0x48 : 0x0068,	#LATIN SMALL LETTER H
        0x49 : 0x0069,	#LATIN SMALL LETTER I
        0x4A : 0x006A,	#LATIN SMALL LETTER J
        0x4B : 0x006B,	#LATIN SMALL LETTER K
        0x4C : 0x006C,	#LATIN SMALL LETTER L
        0x4D : 0x006D,	#LATIN SMALL LETTER M
        0x4E : 0x006E,	#LATIN SMALL LETTER N
        0x4F : 0x006F,	#LATIN SMALL LETTER O
        0x50 : 0x0070,	#LATIN SMALL LETTER P
        0x51 : 0x0071,	#LATIN SMALL LETTER Q
        0x52 : 0x0072,	#LATIN SMALL LETTER R
        0x53 : 0x0073,	#LATIN SMALL LETTER S
        0x54 : 0x0074,	#LATIN SMALL LETTER T
        0x55 : 0x0075,	#LATIN SMALL LETTER U
        0x56 : 0x0076,	#LATIN SMALL LETTER V
        0x57 : 0x0077,	#LATIN SMALL LETTER W
        0x58 : 0x0078,	#LATIN SMALL LETTER X
        0x59 : 0x0079,	#LATIN SMALL LETTER Y
        0x5A : 0x007A,	#LATIN SMALL LETTER Z
        0x5B : 0x005B,	#LEFT SQUARE BRACKET
        0x5C : 0x00A3,	#POUND SIGN
        0x5D : 0x005D,	#RIGHT SQUARE BRACKET
        0x5E : 0x2191,	#UPWARDS ARROW
        0x5F : 0x2190,	#LEFTWARDS ARROW
        0x60 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0x61 : 0x0041,	#LATIN CAPITAL LETTER A
        0x62 : 0x0042,	#LATIN CAPITAL LETTER B
        0x63 : 0x0043,	#LATIN CAPITAL LETTER C
        0x64 : 0x0044,	#LATIN CAPITAL LETTER D
        0x65 : 0x0045,	#LATIN CAPITAL LETTER E
        0x66 : 0x0046,	#LATIN CAPITAL LETTER F
        0x67 : 0x0047,	#LATIN CAPITAL LETTER G
        0x68 : 0x0048,	#LATIN CAPITAL LETTER H
        0x69 : 0x0049,	#LATIN CAPITAL LETTER I
        0x6A : 0x004A,	#LATIN CAPITAL LETTER J
        0x6B : 0x004B,	#LATIN CAPITAL LETTER K
        0x6C : 0x004C,	#LATIN CAPITAL LETTER L
        0x6D : 0x004D,	#LATIN CAPITAL LETTER M
        0x6E : 0x004E,	#LATIN CAPITAL LETTER N
        0x6F : 0x004F,	#LATIN CAPITAL LETTER O
        0x70 : 0x0050,	#LATIN CAPITAL LETTER P
        0x71 : 0x0051,	#LATIN CAPITAL LETTER Q
        0x72 : 0x0052,	#LATIN CAPITAL LETTER R
        0x73 : 0x0053,	#LATIN CAPITAL LETTER S
        0x74 : 0x0054,	#LATIN CAPITAL LETTER T
        0x75 : 0x0055,	#LATIN CAPITAL LETTER U
        0x76 : 0x0056,	#LATIN CAPITAL LETTER V
        0x77 : 0x0057,	#LATIN CAPITAL LETTER W
        0x78 : 0x0058,	#LATIN CAPITAL LETTER X
        0x79 : 0x0059,	#LATIN CAPITAL LETTER Y
        0x7A : 0x005A,	#LATIN CAPITAL LETTER Z
        0x7B : 0x253C,	#BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
        0x7C : 0xF12E,	#LEFT HALF BLOCK MEDIUM SHADE (CUS)
        0x7D : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0x7E : 0x2592,	#MEDIUM SHADE
        0x7F : 0xF139,	#MEDIUM SHADE SLASHED LEFT (CUS)
        0x80 : 0,	#UNDEFINED
        0x81 : 0xF104,	#ORANGE COLOR SWITCH (CUS)
        0x82 : 0,	#UNDEFINED
        0x83 : 0,	#UNDEFINED
        0x84 : 0,	#UNDEFINED
        0x85 : 0xF110,	#FUNCTION KEY 1 (CUS)
        0x86 : 0xF112,	#FUNCTION KEY 3 (CUS)
        0x87 : 0xF114,	#FUNCTION KEY 5 (CUS)
        0x88 : 0xF116,	#FUNCTION KEY 7 (CUS)
        0x89 : 0xF111,	#FUNCTION KEY 2 (CUS)
        0x8A : 0xF113,	#FUNCTION KEY 4 (CUS)
        0x8B : 0xF115,	#FUNCTION KEY 6 (CUS)
        0x8C : 0xF117,	#FUNCTION KEY 8 (CUS)
        0x8D : 0x000A,	#LINE FEED
        0x8E : 0x000F,	#SHIFT IN
        0x8F : 0,	#UNDEFINED
        0x90 : 0xF105,	#BLACK COLOR SWITCH (CUS)
        0x91 : 0xF11E,	#CURSOR UP (CUS)
        0x92 : 0xF11B,	#REVERSE VIDEO OFF (CUS)
        0x93 : 0x000C,	#FORM FEED
        0x94 : 0xF121,	#INSERT (CUS)
        0x95 : 0xF106,	#BROWN COLOR SWITCH (CUS)
        0x96 : 0xF107,	#LIGHT RED COLOR SWITCH (CUS)
        0x97 : 0xF108,	#GRAY 1 COLOR SWITCH (CUS)
        0x98 : 0xF109,	#GRAY 2 COLOR SWITCH (CUS)
        0x99 : 0xF10A,	#LIGHT GREEN COLOR SWITCH (CUS)
        0x9A : 0xF10B,	#LIGHT BLUE COLOR SWITCH (CUS)
        0x9B : 0xF10C,	#GRAY 3 COLOR SWITCH (CUS)
        0x9C : 0xF10D,	#PURPLE COLOR SWITCH (CUS)
        0x9D : 0xF11D,	#CURSOR LEFT (CUS)
        0x9E : 0xF10E,	#YELLOW COLOR SWITCH (CUS)
        0x9F : 0xF10F,	#CYAN COLOR SWITCH (CUS)
        0xA0 : 0x00A0,	#NO-BREAK SPACE
        0xA1 : 0x258C,	#LEFT HALF BLOCK
        0xA2 : 0x2584,	#LOWER HALF BLOCK
        0xA3 : 0x2594,	#UPPER ONE EIGHTH BLOCK
        0xA4 : 0x2581,	#LOWER ONE EIGHTH BLOCK
        0xA5 : 0x258F,	#LEFT ONE EIGHTH BLOCK
        0xA6 : 0x2592,	#MEDIUM SHADE
        0xA7 : 0x2595,	#RIGHT ONE EIGHTH BLOCK
        0xA8 : 0xF12F,	#LOWER HALF BLOCK MEDIUM SHADE (CUS)
        0xA9 : 0xF13A,	#MEDIUM SHADE SLASHED RIGHT (CUS)
        0xAA : 0xF130,	#RIGHT ONE QUARTER BLOCK (CUS)
        0xAB : 0x251C,	#BOX DRAWINGS LIGHT VERTICAL AND RIGHT
        0xAC : 0xF134,	#BLACK SMALL SQUARE LOWER RIGHT (CUS)
        0xAD : 0x2514,	#BOX DRAWINGS LIGHT UP AND RIGHT
        0xAE : 0x2510,	#BOX DRAWINGS LIGHT DOWN AND LEFT
        0xAF : 0x2582,	#LOWER ONE QUARTER BLOCK
        0xB0 : 0x250C,	#BOX DRAWINGS LIGHT DOWN AND RIGHT
        0xB1 : 0x2534,	#BOX DRAWINGS LIGHT UP AND HORIZONTAL
        0xB2 : 0x252C,	#BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
        0xB3 : 0x2524,	#BOX DRAWINGS LIGHT VERTICAL AND LEFT
        0xB4 : 0x258E,	#LEFT ONE QUARTER BLOCK
        0xB5 : 0x258D,	#LEFT THREE EIGTHS BLOCK
        0xB6 : 0xF131,	#RIGHT THREE EIGHTHS BLOCK (CUS)
        0xB7 : 0xF132,	#UPPER ONE QUARTER BLOCK (CUS)
        0xB8 : 0xF133,	#UPPER THREE EIGHTS BLOCK (CUS)
        0xB9 : 0x2583,	#LOWER THREE EIGHTHS BLOCK
        0xBA : 0x2713,	#CHECK MARK
        0xBB : 0xF135,	#BLACK SMALL SQUARE LOWER LEFT (CUS)
        0xBC : 0xF136,	#BLACK SMALL SQUARE UPPER RIGHT (CUS)
        0xBD : 0x2518,	#BOX DRAWINGS LIGHT UP AND LEFT
        0xBE : 0xF137,	#BLACK SMALL SQUARE UPPER LEFT (CUS)
        0xBF : 0xF138,	#TWO SMALL BLACK SQUARES DIAGONAL LEFT TO RIGHT (CUS)
        0xC0 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0xC1 : 0x0041,	#LATIN CAPITAL LETTER A
        0xC2 : 0x0042,	#LATIN CAPITAL LETTER B
        0xC3 : 0x0043,	#LATIN CAPITAL LETTER C
        0xC4 : 0x0044,	#LATIN CAPITAL LETTER D
        0xC5 : 0x0045,	#LATIN CAPITAL LETTER E
        0xC6 : 0x0046,	#LATIN CAPITAL LETTER F
        0xC7 : 0x0047,	#LATIN CAPITAL LETTER G
        0xC8 : 0x0048,	#LATIN CAPITAL LETTER H
        0xC9 : 0x0049,	#LATIN CAPITAL LETTER I
        0xCA : 0x004A,	#LATIN CAPITAL LETTER J
        0xCB : 0x004B,	#LATIN CAPITAL LETTER K
        0xCC : 0x004C,	#LATIN CAPITAL LETTER L
        0xCD : 0x004D,	#LATIN CAPITAL LETTER M
        0xCE : 0x004E,	#LATIN CAPITAL LETTER N
        0xCF : 0x004F,	#LATIN CAPITAL LETTER O
        0xD0 : 0x0050,	#LATIN CAPITAL LETTER P
        0xD1 : 0x0051,	#LATIN CAPITAL LETTER Q
        0xD2 : 0x0052,	#LATIN CAPITAL LETTER R
        0xD3 : 0x0053,	#LATIN CAPITAL LETTER S
        0xD4 : 0x0054,	#LATIN CAPITAL LETTER T
        0xD5 : 0x0055,	#LATIN CAPITAL LETTER U
        0xD6 : 0x0056,	#LATIN CAPITAL LETTER V
        0xD7 : 0x0057,	#LATIN CAPITAL LETTER W
        0xD8 : 0x0058,	#LATIN CAPITAL LETTER X
        0xD9 : 0x0059,	#LATIN CAPITAL LETTER Y
        0xDA : 0x005A,	#LATIN CAPITAL LETTER Z
        0xDB : 0x253C,	#BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
        0xDC : 0xF12E,	#LEFT HALF BLOCK MEDIUM SHADE (CUS)
        0xDD : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0xDE : 0x2592,	#MEDIUM SHADE
        0xDF : 0xF139,	#MEDIUM SHADE SLASHED LEFT (CUS)
        0xE0 : 0x00A0,	#NO-BREAK SPACE
        0xE1 : 0x258C,	#LEFT HALF BLOCK
        0xE2 : 0x2584,	#LOWER HALF BLOCK
        0xE3 : 0x2594,	#UPPER ONE EIGHTH BLOCK
        0xE4 : 0x2581,	#LOWER ONE EIGHTH BLOCK
        0xE5 : 0x258F,	#LEFT ONE EIGHTH BLOCK
        0xE6 : 0x2592,	#MEDIUM SHADE
        0xE7 : 0x2595,	#RIGHT ONE EIGHTH BLOCK
        0xE8 : 0xF12F,	#LOWER HALF BLOCK MEDIUM SHADE (CUS)
        0xE9 : 0xF13A,	#MEDIUM SHADE SLASHED RIGHT (CUS)
        0xEA : 0xF130,	#RIGHT ONE QUARTER BLOCK (CUS)
        0xEB : 0x251C,	#BOX DRAWINGS LIGHT VERTICAL AND RIGHT
        0xEC : 0xF134,	#BLACK SMALL SQUARE LOWER RIGHT (CUS)
        0xED : 0x2514,	#BOX DRAWINGS LIGHT UP AND RIGHT
        0xEE : 0x2510,	#BOX DRAWINGS LIGHT DOWN AND LEFT
        0xEF : 0x2582,	#LOWER ONE QUARTER BLOCK
        0xF0 : 0x250C,	#BOX DRAWINGS LIGHT DOWN AND RIGHT
        0xF1 : 0x2534,	#BOX DRAWINGS LIGHT UP AND HORIZONTAL
        0xF2 : 0x252C,	#BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
        0xF3 : 0x2524,	#BOX DRAWINGS LIGHT VERTICAL AND LEFT
        0xF4 : 0x258E,	#LEFT ONE QUARTER BLOCK
        0xF5 : 0x258D,	#LEFT THREE EIGTHS BLOCK
        0xF6 : 0xF131,	#RIGHT THREE EIGHTHS BLOCK (CUS)
        0xF7 : 0xF132,	#UPPER ONE QUARTER BLOCK (CUS)
        0xF8 : 0xF133,	#UPPER THREE EIGHTS BLOCK (CUS)
        0xF9 : 0x2583,	#LOWER THREE EIGHTHS BLOCK
        0xFA : 0x2713,	#CHECK MARK
        0xFB : 0xF135,	#BLACK SMALL SQUARE LOWER LEFT (CUS)
        0xFC : 0xF136,	#BLACK SMALL SQUARE UPPER RIGHT (CUS)
        0xFD : 0x2518,	#BOX DRAWINGS LIGHT UP AND LEFT
        0xFE : 0xF137,	#BLACK SMALL SQUARE UPPER LEFT (CUS)
        0xFF : 0x2592,	#MEDIUM SHADE
    }

    upper_table = {
        0x00 : 0,	#UNDEFINED
        0x01 : 0,	#UNDEFINED
        0x02 : 0,	#UNDEFINED
        0x03 : 0,	#UNDEFINED
        0x04 : 0,	#UNDEFINED
        0x05 : 0xF100,	#WHITE COLOR SWITCH (CUS)
        0x06 : 0,	#UNDEFINED
        0x07 : 0,	#UNDEFINED
        0x08 : 0xF118,	#DISABLE CHARACTER SET SWITCHING (CUS)
        0x09 : 0xF119,	#ENABLE CHARACTER SET SWITCHING (CUS)
        0x0A : 0,	#UNDEFINED
        0x0B : 0,	#UNDEFINED
        0x0C : 0,	#UNDEFINED
        0x0D : 0x000D,	#CARRIAGE RETURN
        0x0E : 0x000E,	#SHIFT OUT
        0x0F : 0,	#UNDEFINED
        0x10 : 0,	#UNDEFINED
        0x11 : 0xF11C,	#CURSOR DOWN (CUS)
        0x12 : 0xF11A,	#REVERSE VIDEO ON (CUS)
        0x13 : 0xF120,	#HOME (CUS)
        0x14 : 0x007F,	#DELETE
        0x15 : 0,	#UNDEFINED
        0x16 : 0,	#UNDEFINED
        0x17 : 0,	#UNDEFINED
        0x18 : 0,	#UNDEFINED
        0x19 : 0,	#UNDEFINED
        0x1A : 0,	#UNDEFINED
        0x1B : 0,	#UNDEFINED
        0x1C : 0xF101,	#RED COLOR SWITCH (CUS)
        0x1D : 0xF11D,	#CURSOR RIGHT (CUS)
        0x1E : 0xF102,	#GREEN COLOR SWITCH (CUS)
        0x1F : 0xF103,	#BLUE COLOR SWITCH (CUS)
        0x20 : 0x0020,	#SPACE
        0x21 : 0x0021,	#EXCLAMATION MARK
        0x22 : 0x0022,	#QUOTATION MARK
        0x23 : 0x0023,	#NUMBER SIGN
        0x24 : 0x0024,	#DOLLAR SIGN
        0x25 : 0x0025,	#PERCENT SIGN
        0x26 : 0x0026,	#AMPERSAND
        0x27 : 0x0027,	#APOSTROPHE
        0x28 : 0x0028,	#LEFT PARENTHESIS
        0x29 : 0x0029,	#RIGHT PARENTHESIS
        0x2A : 0x002A,	#ASTERISK
        0x2B : 0x002B,	#PLUS SIGN
        0x2C : 0x002C,	#COMMA
        0x2D : 0x002D,	#HYPHEN-MINUS
        0x2E : 0x002E,	#FULL STOP
        0x2F : 0x002F,	#SOLIDUS
        0x30 : 0x0030,	#DIGIT ZERO
        0x31 : 0x0031,	#DIGIT ONE
        0x32 : 0x0032,	#DIGIT TWO
        0x33 : 0x0033,	#DIGIT THREE
        0x34 : 0x0034,	#DIGIT FOUR
        0x35 : 0x0035,	#DIGIT FIVE
        0x36 : 0x0036,	#DIGIT SIX
        0x37 : 0x0037,	#DIGIT SEVEN
        0x38 : 0x0038,	#DIGIT EIGHT
        0x39 : 0x0039,	#DIGIT NINE
        0x3A : 0x003A,	#COLON
        0x3B : 0x003B,	#SEMICOLON
        0x3C : 0x003C,	#LESS-THAN SIGN
        0x3D : 0x003D,	#EQUALS SIGN
        0x3E : 0x003E,	#GREATER-THAN SIGN
        0x3F : 0x003F,	#QUESTION MARK
        0x40 : 0x0040,	#COMMERCIAL AT
        0x41 : 0x0041,	#LATIN CAPITAL LETTER A
        0x42 : 0x0042,	#LATIN CAPITAL LETTER B
        0x43 : 0x0043,	#LATIN CAPITAL LETTER C
        0x44 : 0x0044,	#LATIN CAPITAL LETTER D
        0x45 : 0x0045,	#LATIN CAPITAL LETTER E
        0x46 : 0x0046,	#LATIN CAPITAL LETTER F
        0x47 : 0x0047,	#LATIN CAPITAL LETTER G
        0x48 : 0x0048,	#LATIN CAPITAL LETTER H
        0x49 : 0x0049,	#LATIN CAPITAL LETTER I
        0x4A : 0x004A,	#LATIN CAPITAL LETTER J
        0x4B : 0x004B,	#LATIN CAPITAL LETTER K
        0x4C : 0x004C,	#LATIN CAPITAL LETTER L
        0x4D : 0x004D,	#LATIN CAPITAL LETTER M
        0x4E : 0x004E,	#LATIN CAPITAL LETTER N
        0x4F : 0x004F,	#LATIN CAPITAL LETTER O
        0x50 : 0x0050,	#LATIN CAPITAL LETTER P
        0x51 : 0x0051,	#LATIN CAPITAL LETTER Q
        0x52 : 0x0052,	#LATIN CAPITAL LETTER R
        0x53 : 0x0053,	#LATIN CAPITAL LETTER S
        0x54 : 0x0054,	#LATIN CAPITAL LETTER T
        0x55 : 0x0055,	#LATIN CAPITAL LETTER U
        0x56 : 0x0056,	#LATIN CAPITAL LETTER V
        0x57 : 0x0057,	#LATIN CAPITAL LETTER W
        0x58 : 0x0058,	#LATIN CAPITAL LETTER X
        0x59 : 0x0059,	#LATIN CAPITAL LETTER Y
        0x5A : 0x005A,	#LATIN CAPITAL LETTER Z
        0x5B : 0x005B,	#LEFT SQUARE BRACKET
        0x5C : 0x00A3,	#POUND SIGN
        0x5D : 0x005D,	#RIGHT SQUARE BRACKET
        0x5E : 0x2191,	#UPWARDS ARROW
        0x5F : 0x2190,	#LEFTWARDS ARROW
        0x60 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0x61 : 0x2660,	#BLACK SPADE SUIT
        0x62 : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0x63 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0x64 : 0xF122,	#BOX DRAWINGS LIGHT HORIZONTAL ONE QUARTER UP (CUS)
        0x65 : 0xF123,	#BOX DRAWINGS LIGHT HORIZONTAL TWO QUARTERS UP (CUS)
        0x66 : 0xF124,	#BOX DRAWINGS LIGHT HORIZONTAL ONE QUARTER DOWN (CUS)
        0x67 : 0xF126,	#BOX DRAWINGS LIGHT VERTICAL ONE QUARTER LEFT (CUS)
        0x68 : 0xF128,	#BOX DRAWINGS LIGHT VERTICAL ONE QUARTER RIGHT (CUS)
        0x69 : 0x256E,	#BOX DRAWINGS LIGHT ARC DOWN AND LEFT
        0x6A : 0x2570,	#BOX DRAWINGS LIGHT ARC UP AND RIGHT
        0x6B : 0x256F,	#BOX DRAWINGS LIGHT ARC UP AND LEFT
        0x6C : 0xF12A,	#ONE EIGHTH BLOCK UP AND RIGHT (CUS)
        0x6D : 0x2572,	#BOX DRAWINGS LIGHT DIAGONAL UPPER LEFT TO LOWER RIGHT
        0x6E : 0x2571,	#BOX DRAWINGS LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT
        0x6F : 0xF12B,	#ONE EIGHTH BLOCK DOWN AND RIGHT (CUS)
        0x70 : 0xF12C,	#ONE EIGHTH BLOCK DOWN AND LEFT (CUS)
        0x71 : 0x25CF,	#BLACK CIRCLE
        0x72 : 0xF125,	#BOX DRAWINGS LIGHT HORIZONTAL TWO QUARTERS DOWN (CUS)
        0x73 : 0x2665,	#BLACK HEART SUIT
        0x74 : 0xF127,	#BOX DRAWINGS LIGHT VERTICAL TWO QUARTERS LEFT (CUS)
        0x75 : 0x256D,	#BOX DRAWINGS LIGHT ARC DOWN AND RIGHT
        0x76 : 0x2573,	#BOX DRAWINGS LIGHT DIAGONAL CROSS
        0x77 : 0x25CB,	#WHITE CIRCLE
        0x78 : 0x2663,	#BLACK CLUB SUIT
        0x79 : 0xF129,	#BOX DRAWINGS LIGHT VERTICAL TWO QUARTERS RIGHT (CUS)
        0x7A : 0x2666,	#BLACK DIAMOND SUIT
        0x7B : 0x253C,	#BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
        0x7C : 0xF12E,	#LEFT HALF BLOCK MEDIUM SHADE (CUS)
        0x7D : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0x7E : 0x03C0,	#GREEK SMALL LETTER PI
        0x7F : 0x25E5,	#BLACK UPPER RIGHT TRIANGLE
        0x80 : 0,	#UNDEFINED
        0x81 : 0xF104,	#ORANGE COLOR SWITCH (CUS)
        0x82 : 0,	#UNDEFINED
        0x83 : 0,	#UNDEFINED
        0x84 : 0,	#UNDEFINED
        0x85 : 0xF110,	#FUNCTION KEY 1 (CUS)
        0x86 : 0xF112,	#FUNCTION KEY 3 (CUS)
        0x87 : 0xF114,	#FUNCTION KEY 5 (CUS)
        0x88 : 0xF116,	#FUNCTION KEY 7 (CUS)
        0x89 : 0xF111,	#FUNCTION KEY 2 (CUS)
        0x8A : 0xF113,	#FUNCTION KEY 4 (CUS)
        0x8B : 0xF115,	#FUNCTION KEY 6 (CUS)
        0x8C : 0xF117,	#FUNCTION KEY 8 (CUS)
        0x8D : 0x000A,	#LINE FEED
        0x8E : 0x000F,	#SHIFT IN
        0x8F : 0,	#UNDEFINED
        0x90 : 0xF105,	#BLACK COLOR SWITCH (CUS)
        0x91 : 0xF11E,	#CURSOR UP (CUS)
        0x92 : 0xF11B,	#REVERSE VIDEO OFF (CUS)
        0x93 : 0x000C,	#FORM FEED
        0x94 : 0xF121,	#INSERT (CUS)
        0x95 : 0xF106,	#BROWN COLOR SWITCH (CUS)
        0x96 : 0xF107,	#LIGHT RED COLOR SWITCH (CUS)
        0x97 : 0xF108,	#GRAY 1 COLOR SWITCH (CUS)
        0x98 : 0xF109,	#GRAY 2 COLOR SWITCH (CUS)
        0x99 : 0xF10A,	#LIGHT GREEN COLOR SWITCH (CUS)
        0x9A : 0xF10B,	#LIGHT BLUE COLOR SWITCH (CUS)
        0x9B : 0xF10C,	#GRAY 3 COLOR SWITCH (CUS)
        0x9C : 0xF10D,	#PURPLE COLOR SWITCH (CUS)
        0x9D : 0xF11D,	#CURSOR LEFT (CUS)
        0x9E : 0xF10E,	#YELLOW COLOR SWITCH (CUS)
        0x9F : 0xF10F,	#CYAN COLOR SWITCH (CUS)
        0xA0 : 0x00A0,	#NO-BREAK SPACE
        0xA1 : 0x258C,	#LEFT HALF BLOCK
        0xA2 : 0x2584,	#LOWER HALF BLOCK
        0xA3 : 0x2594,	#UPPER ONE EIGHTH BLOCK
        0xA4 : 0x2581,	#LOWER ONE EIGHTH BLOCK
        0xA5 : 0x258F,	#LEFT ONE EIGHTH BLOCK
        0xA6 : 0x2592,	#MEDIUM SHADE
        0xA7 : 0x2595,	#RIGHT ONE EIGHTH BLOCK
        0xA8 : 0xF12F,	#LOWER HALF BLOCK MEDIUM SHADE (CUS)
        0xA9 : 0x25E4,	#BLACK UPPER LEFT TRIANGLE
        0xAA : 0xF130,	#RIGHT ONE QUARTER BLOCK (CUS)
        0xAB : 0x251C,	#BOX DRAWINGS LIGHT VERTICAL AND RIGHT
        0xAC : 0xF134,	#BLACK SMALL SQUARE LOWER RIGHT (CUS)
        0xAD : 0x2514,	#BOX DRAWINGS LIGHT UP AND RIGHT
        0xAE : 0x2510,	#BOX DRAWINGS LIGHT DOWN AND LEFT
        0xAF : 0x2582,	#LOWER ONE QUARTER BLOCK
        0xB0 : 0x250C,	#BOX DRAWINGS LIGHT DOWN AND RIGHT
        0xB1 : 0x2534,	#BOX DRAWINGS LIGHT UP AND HORIZONTAL
        0xB2 : 0x252C,	#BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
        0xB3 : 0x2524,	#BOX DRAWINGS LIGHT VERTICAL AND LEFT
        0xB4 : 0x258E,	#LEFT ONE QUARTER BLOCK
        0xB5 : 0x258D,	#LEFT THREE EIGTHS BLOCK
        0xB6 : 0xF131,	#RIGHT THREE EIGHTHS BLOCK (CUS)
        0xB7 : 0xF132,	#UPPER ONE QUARTER BLOCK (CUS)
        0xB8 : 0xF133,	#UPPER THREE EIGHTS BLOCK (CUS)
        0xB9 : 0x2583,	#LOWER THREE EIGHTHS BLOCK
        0xBA : 0xF12D,	#ONE EIGHTH BLOCK UP AND LEFT (CUS)
        0xBB : 0xF135,	#BLACK SMALL SQUARE LOWER LEFT (CUS)
        0xBC : 0xF136,	#BLACK SMALL SQUARE UPPER RIGHT (CUS)
        0xBD : 0x2518,	#BOX DRAWINGS LIGHT UP AND LEFT
        0xBE : 0xF137,	#BLACK SMALL SQUARE UPPER LEFT (CUS)
        0xBF : 0xF138,	#TWO SMALL BLACK SQUARES DIAGONAL LEFT TO RIGHT (CUS)
        0xC0 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0xC1 : 0x2660,	#BLACK SPADE SUIT
        0xC2 : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0xC3 : 0x2501,	#BOX DRAWINGS LIGHT HORIZONTAL
        0xC4 : 0xF122,	#BOX DRAWINGS LIGHT HORIZONTAL ONE QUARTER UP (CUS)
        0xC5 : 0xF123,	#BOX DRAWINGS LIGHT HORIZONTAL TWO QUARTERS UP (CUS)
        0xC6 : 0xF124,	#BOX DRAWINGS LIGHT HORIZONTAL ONE QUARTER DOWN (CUS)
        0xC7 : 0xF126,	#BOX DRAWINGS LIGHT VERTICAL ONE QUARTER LEFT (CUS)
        0xC8 : 0xF128,	#BOX DRAWINGS LIGHT VERTICAL ONE QUARTER RIGHT (CUS)
        0xC9 : 0x256E,	#BOX DRAWINGS LIGHT ARC DOWN AND LEFT
        0xCA : 0x2570,	#BOX DRAWINGS LIGHT ARC UP AND RIGHT
        0xCB : 0x256F,	#BOX DRAWINGS LIGHT ARC UP AND LEFT
        0xCC : 0xF12A,	#ONE EIGHTH BLOCK UP AND RIGHT (CUS)
        0xCD : 0x2572,	#BOX DRAWINGS LIGHT DIAGONAL UPPER LEFT TO LOWER RIGHT
        0xCE : 0x2571,	#BOX DRAWINGS LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT
        0xCF : 0xF12B,	#ONE EIGHTH BLOCK DOWN AND RIGHT (CUS)
        0xD0 : 0xF12C,	#ONE EIGHTH BLOCK DOWN AND LEFT (CUS)
        0xD1 : 0x25CF,	#BLACK CIRCLE
        0xD2 : 0xF125,	#BOX DRAWINGS LIGHT HORIZONTAL TWO QUARTERS DOWN (CUS)
        0xD3 : 0x2665,	#BLACK HEART SUIT
        0xD4 : 0xF127,	#BOX DRAWINGS LIGHT VERTICAL TWO QUARTERS LEFT (CUS)
        0xD5 : 0x256D,	#BOX DRAWINGS LIGHT ARC DOWN AND LEFT
        0xD6 : 0x2573,	#BOX DRAWINGS LIGHT DIAGONAL CROSS
        0xD7 : 0x25CB,	#WHITE CIRCLE
        0xD8 : 0x2663,	#BLACK CLUB SUIT
        0xD9 : 0xF129,	#BOX DRAWINGS LIGHT VERTICAL TWO QUARTERS RIGHT (CUS)
        0xDA : 0x2666,	#BLACK DIAMOND SUIT
        0xDB : 0x253C,	#BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
        0xDC : 0xF12E,	#LEFT HALF BLOCK MEDIUM SHADE (CUS)
        0xDD : 0x2502,	#BOX DRAWINGS LIGHT VERTICAL
        0xDE : 0x03C0,	#GREEK SMALL LETTER PI
        0xDF : 0x25E5,	#BLACK UPPER RIGHT TRIANGLE
        0xE0 : 0x00A0,	#NO-BREAK SPACE
        0xE1 : 0x258C,	#LEFT HALF BLOCK
        0xE2 : 0x2584,	#LOWER HALF BLOCK
        0xE3 : 0x2594,	#UPPER ONE EIGHTH BLOCK
        0xE4 : 0x2581,	#LOWER ONE EIGHTH BLOCK
        0xE5 : 0x258F,	#LEFT ONE EIGHTH BLOCK
        0xE6 : 0x2592,	#MEDIUM SHADE
        0xE7 : 0x2595,	#RIGHT ONE EIGHTH BLOCK
        0xE8 : 0xF12F,	#LOWER HALF BLOCK MEDIUM SHADE (CUS)
        0xE9 : 0x25E4,	#BLACK UPPER LEFT TRIANGLE
        0xEA : 0xF130,	#RIGHT ONE QUARTER BLOCK (CUS)
        0xEB : 0x251C,	#BOX DRAWINGS LIGHT VERTICAL AND RIGHT
        0xEC : 0xF134,	#BLACK SMALL SQUARE LOWER RIGHT (CUS)
        0xED : 0x2514,	#BOX DRAWINGS LIGHT UP AND RIGHT
        0xEE : 0x2510,	#BOX DRAWINGS LIGHT DOWN AND LEFT
        0xEF : 0x2582,	#LOWER ONE QUARTER BLOCK
        0xF0 : 0x250C,	#BOX DRAWINGS LIGHT DOWN AND RIGHT
        0xF1 : 0x2534,	#BOX DRAWINGS LIGHT UP AND HORIZONTAL
        0xF2 : 0x252C,	#BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
        0xF3 : 0x2524,	#BOX DRAWINGS LIGHT VERTICAL AND LEFT
        0xF4 : 0x258E,	#LEFT ONE QUARTER BLOCK
        0xF5 : 0x258D,	#LEFT THREE EIGTHS BLOCK
        0xF6 : 0xF131,	#RIGHT THREE EIGHTHS BLOCK (CUS)
        0xF7 : 0xF132,	#UPPER ONE QUARTER BLOCK (CUS)
        0xF8 : 0xF133,	#UPPER THREE EIGHTS BLOCK (CUS)
        0xF9 : 0x2583,	#LOWER THREE EIGHTHS BLOCK
        0xFA : 0xF12D,	#ONE EIGHTH BLOCK UP AND LEFT (CUS)
        0xFB : 0xF135,	#BLACK SMALL SQUARE LOWER LEFT (CUS)
        0xFC : 0xF136,	#BLACK SMALL SQUARE UPPER RIGHT (CUS)
        0xFD : 0x2518,	#BOX DRAWINGS LIGHT UP AND LEFT
        0xFE : 0xF137,	#BLACK SMALL SQUARE UPPER LEFT (CUS)
        0xFF : 0x03C0,	#GREEK SMALL LETTER PI
    }

    def _2unicode(self, table, petstring):
        if (type(petstring) == str):
            log_info("petstring is string")
        elif (type(petstring) == bytes):
            log_info("petstring is bytes")
        else:
            log_info("petstring type is UNKNOWN!")
            
        ret = ""
        for char in petstring:
            log_info("Looking up 0x%x" % char)
            if(table.get(char, 0) == 0):
                log_warn("0x%x is undefined in PETSCII" % char)
                return ret
            else:
                ret += chr(table[char])
        return ret
    
    def lower2unicode(self, petstring):
        return self._2unicode(self.lower_table, petstring)
    
    def upper2unicode(self, petstring):
        # FIXME: Deal with bytes directly until lookup
        if (type(petstring) != str): # Python 3 now gives bytes
            log_info("Converting bytes to string")
            petstring = str(petstring, "iso-8859-1")
        ret = ""
        for char in petstring:
            # ret += unichr(self.upper_table[ord(char)]) # Python2
            ret += chr(self.upper_table[ord(char)])
        return ret

class DD001View(BinaryView):
    name = "DD001 ROM"
    long_name = "C64 DD001 ROM"
    cart_name = 0
    
    # FIXME: Just here for debugging, Python 3 only
    @classmethod
    def register(self):
        log_info("Registered DD001View")
        super().register() # Python 3 syntax
    
    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['6502'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        HDR_SIZE = 9  # reset_vector*2 + PETSCII("CBM80")
        hdr = data.read(0x0, HDR_SIZE)
        if len(hdr) < HDR_SIZE:
            return False
        magic = PETSCII().lower2unicode( hdr[4:9] )
        if magic == "CBM80":
            log_info("Cart autoboot signature: "+ magic)
            # FIXME: identify by reset vectors, not the most uniq
            if   hdr[0:4] == b'\x87\x80\xe5\x8d':
                self.cart_name = "DD001 1.0"
            elif hdr[0:4] == b'\x87\x80\xe7\x8d':
                self.cart_name = "DD001 1.1"
            else:
                log_info("Unknown C64 cart")
                self.cart_name = "unknown"
        else:
            log_info("Not C64 cart")
            return False
        log_info("C64 cartridge identified: "+ self.cart_name)
        return True

    # fixme: obviously useless
    def log_line(self):
        frameinfo = getframeinfo(currentframe())
        #log_info(frameinfo.filename)
        log_info(str(frameinfo.lineno))

    def init(self):
        try:
            # This one is working one. Disabled to see if it avoids
            # resetting to the non-dev channel
            ### Settings().set_bool('analysis.linearSweep.autorun', False, self)
 
            # add_auto_segment(start, length,
            #                  data_offset, data_length, flags)
                        
            r__  = SegmentFlag.SegmentReadable
            rw_  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable)
            rwx  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable |
                    SegmentFlag.SegmentExecutable)
            r_x  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable )
            r_xc = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable |
                    SegmentFlag.SegmentContainsCode)

            # Address map from http://sta.c64.org/cbm1541mem.html
            # self.add_auto_segment(0x0, 0x100, 0, 0, rwx)
            # self.add_auto_section("Zero page", 0x0, 0x100)

            # self.add_auto_segment(0x100, 0x100, 0, 0, rwx)
            # self.add_auto_section("Processor stack", 0x100, 0x100)

            # self.add_auto_segment(0x200, 0x100, 0, 0, rwx)
            # self.add_auto_section("Misc workareas", 0x200, 0x100)

            # self.add_auto_segment(0x300, 0x100, 0, 0, rwx)
            # self.add_auto_section("Data Buffers", 0x300, 0x100)

            # self.add_auto_segment(0x1800, 0x10, 0, 0, rwx)
            # self.add_auto_section("VIA #1; serial bus access", 0x1800, 0x10)

            # self.add_auto_segment(0x1c00, 0x10, 0, 0, rwx)
            # self.add_auto_section("VIA #2; drive control", 0x1c00, 0x10)

            self.add_auto_segment(0x8000, 0x2000, 0, 0x2000, r_xc)
            self.add_user_section("ROM", 0x8000, 0x2000, SectionSemantics.ReadOnlyCodeSectionSemantics)
            # self.add_auto_section("ROM", 0xe000, 0x2000)

            # If $8004 = PETSCII("CBM80") then use $8000
            # as coldboot vector and $8002 as warmboot
            # vector
            # Ref: http://blog.worldofjani.com/?p=879
            magic = self.read(0x8004, 5)
            magic = PETSCII().lower2unicode( magic )
            if magic == "CBM80":
                log_info("Cart autoboot signature: "+ magic)
                self.define_auto_symbol(Symbol(
                    SymbolType.DataSymbol,
                    0x8004, "cart_magic"))
                type = self.parse_type_string("struct {uint8_t magic[5];}");
                self.define_data_var(0x8004, type[0])
                self.set_comment_at(0x8004, "PETSCII: "+ magic)

            self.coldreset = struct.unpack('<H', self.read(0x8000, 2))[0]
            self.warmreset = struct.unpack('<H', self.read(0x8002, 2))[0]
            log_info("cold reset vector: 0x%X" % self.coldreset)
            log_info("warn reset vector: 0x%X" % self.warmreset)
            # FIXME: needs to be defined as uint16 ptr
            self.define_auto_symbol(Symbol(
                SymbolType.DataSymbol,
                0x8000, "cold_reset_vector"))
            self.define_auto_symbol(Symbol(
                SymbolType.DataSymbol,
                0x8002, "warm_reset_vector"))
            type = Type.pointer(self.arch, self.parse_type_string('void')[0])
            self.define_data_var(0x8000, type)
            self.define_data_var(0x8002, type)

            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.coldreset, "_coldreset"))                        
            self.create_user_function(self.coldreset);

            if (self.warmreset < self.start) or (self.warmreset > self.end):
                log_warn("The cartridge warm reset vector is outside the cartridge: 0x%X" % self.warmreset)
            else:
                self.create_user_function(self.warmreset); 
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.warmreset, "_warmreset")) # FIXME: define this unconditionally?

            self.add_entry_point(self.coldreset)

            PluginCommand.register('C64: Name jump targets',
                                   'Workaround for completion event not working',
                                   self.name_entry_points)

            PluginCommand.register('C64 PETSCII (lower): show at point',
                                   'log_info lowercase PETSCII at point',
                                   self.log_petscii_lower)

            PluginCommand.register('C64 PETSCII (lower): comment at point',
                                   'lowercase PETSCII at point set as comment',
                                   self.comment_petscii_lower)

            PluginCommand.register('C64 PETSCII (upper): show at point',
                                   'log_info uppercase PETSCII at point',
                                   self.log_petscii_upper)

            PluginCommand.register('C64 PETSCII (upper): comment at point',
                                   'uppercase PETSCII at point set as comment',
                                   self.comment_petscii_upper)

            # Run function namer after analysis or the
            # jump finder wont work. FIXME: still doesn't
            self.add_analysis_completion_event(lambda _:self.name_entry_points())
                                
            return True
        except:
            log_error(traceback.format_exc())
            return False

    def _get_petscii_at(self, offset, PETSCIIfunc):
        # log_info("Getting PETSCII at: 0x%X" % offset)
        self.MAX_PETSCII_LEN = 40
        tmp = b''
        for i in range(self.MAX_PETSCII_LEN):
            char = int.from_bytes(self.read(offset+i, 1), byteorder='big')
            # FIXME: check if char is invalid petscii and escape at that instead
            if (char == 0):
                return PETSCIIfunc(tmp)
            tmp += bytes( [char] )
            text = "PETSCII: '%s'" % PETSCIIfunc(tmp)
            log_info(text)
        log_warn("PETSCII string exceeded maxlen (%d)" % self.MAX_PETSCII_LEN)
        return PETSCIIfunc(tmp)
        

    def get_petscii_lower_at(self, offset):
        return self._get_petscii_at(offset, PETSCII().lower2unicode)

    def get_petscii_upper_at(self, offset):
        return self._get_petscii_at(offset, PETSCII().upper2unicode)
              
        return PETSCII().upper2unicode( tmp )

    MAX_PETSCII_LEN = 40
    def log_petscii_lower(self, dummy):
        text = "PETSCII (lower): '%s'" % self.get_petscii_lower_at(self.offset)
        log_info(text)

    def log_petscii_upper(self, dummy):
        text = "PETSCII (upper): '%s'" % self.get_petscii_upper_at(self.offset)
        log_info(text)

    def comment_petscii_lower(self, dummy):
        text = "PETSCII: '%s' (lower)" % self.get_petscii_lower_at(self.offset)
        self.set_comment_at(self.offset, text)
                
    def comment_petscii_upper(self, dummy):
        text = "PETSCII: '%s' (upper)" % self.get_petscii_upper_at(self.offset)
        self.set_comment_at(self.offset, text)
                
    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.coldreset

    def name_entry_points(self, dummy=None):
        # jump table from the DD001 manual
        functions = {
            0x8009: "LOADFILE",
            0x800c: "SAVEFILE",
            0x800f: "FORMATDISK",
            0x8012: "DISPLAYDIR",
            0x8015: "READSEC",
            0x8018: "WATCHDOG",
            0x801b: "READSECTORS",
            0x801e: "WRTESEC",
            0x8021: "READSTAT",
            0x8024: "SCRATCH",
            0x8027: "RENAME",
            0x802a: "FORMAT",
            0x802d: "INIT",
            0x8030: "SETUPSEC",
            0x8033: "SPECIFY",
            0x8036: "RECAL",
            0x8039: "SETSOACE",
            0x803c: "GETNEXTCLUS",
            0x803f: "ENFILE",
            0x8042: "MARKFAT",
            0x8045: "FINDFAT",
            0x8048: "FINDNEXTFAT",
            0x804b: "WRITEFATS",
            0x804e: "CLEARFATS",
            0x8051: "CALCFIRST",
            0x8054: "GETFATS",
            0x8057: "SEEK",
            0x805a: "FINDFILE",
            0x805d: "WRITEDIR",
            0x8060: "READDIR",
            0x8066: "SAVERLOC",
            0x8069: "SHOWERR",
            0x806c: "SHOWBYTESFREE",
            0x806f: "BN2DEC",
            0x8072: "STRIPSP",
            0x8075: "SEARCH",
            0x8078: "FINDBLANK",
            0x807b: "PADOUT",
            0x807e: "WOFF",
        }
        if (self.cart_name == "DD001 1.0" or self.cart_name == "DD001 1.1"):
            for addr in functions:
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, functions[addr]));
                self.create_user_function(addr);
                self.name_jump_target(addr, functions[addr])
        else:
            log_warn("No function table for "+ self.cart_name)
        
    # this works if run in the console, not from the callback
    def name_jump_target(self, addr, name):
        # FIXME: just [0]? If we get more than one block we
        # don't want it
        # log_info("Naming subtarget of %s (0x%x)" % (name, addr))
        for block in self.get_basic_blocks_at(addr):
            log_info("meep")
            arch = block.function.arch
            info = arch.get_instruction_info(self.read(addr, 16), addr)
            if len(info.branches) == 0:
                log_warning("Unable to find jump at address 0x%x" % addr)
                return
            target = info.branches[0].target
            log_info("Jump at 0x%x to 0x%x" % (addr, target))
            # FIXME: verify that target is within bv.start - bv.end
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, target, "_"+name));
        
DD001View.register()
