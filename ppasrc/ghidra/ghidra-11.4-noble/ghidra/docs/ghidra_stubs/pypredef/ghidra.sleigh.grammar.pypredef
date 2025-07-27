from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.semantics
import ghidra.pcodeCPort.slgh_compile
import ghidra.pcodeCPort.slghpatexpress
import ghidra.pcodeCPort.slghsymbol
import ghidra.program.model.pcode
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import org.antlr.runtime # type: ignore
import org.antlr.runtime.tree # type: ignore


class SleighPreprocessor(ExpressionEnvironment):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, definitions: ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions, inputFile: jpype.protocol.SupportsPath):
        ...

    def isCompatible(self) -> bool:
        ...

    def process(self, writer: LineArrayListWriter):
        ...

    def scanForTimestamp(self) -> int:
        ...

    def setCompatible(self, compatible: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def compatible(self) -> jpype.JBoolean:
        ...

    @compatible.setter
    def compatible(self, value: jpype.JBoolean):
        ...


class RadixBigInteger(java.math.BigInteger):

    class_: typing.ClassVar[java.lang.Class]
    location: typing.Final[Location]

    @typing.overload
    def __init__(self, location: Location, val: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def __init__(self, location: Location, val: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, location: Location, signum: typing.Union[jpype.JInt, int], magnitude: jpype.JArray[jpype.JByte]):
        ...

    @typing.overload
    def __init__(self, location: Location, val: typing.Union[java.lang.String, str], radix: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, location: Location, numBits: typing.Union[jpype.JInt, int], rnd: java.util.Random):
        ...

    @typing.overload
    def __init__(self, location: Location, bitLength: typing.Union[jpype.JInt, int], certainty: typing.Union[jpype.JInt, int], rnd: java.util.Random):
        ...

    def getPreferredRadix(self) -> int:
        ...

    def setPreferredRadix(self, preferredRadix: typing.Union[jpype.JInt, int]):
        ...

    @property
    def preferredRadix(self) -> jpype.JInt:
        ...

    @preferredRadix.setter
    def preferredRadix(self, value: jpype.JInt):
        ...


class PreprocessorException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str], filename: typing.Union[java.lang.String, str], lineno: typing.Union[jpype.JInt, int], overall: typing.Union[jpype.JInt, int], line: typing.Union[java.lang.String, str]):
        ...


class ANTLRUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def debugNodeStream(nodes: org.antlr.runtime.tree.BufferedTreeNodeStream, out: java.io.PrintStream):
        ...

    @staticmethod
    def debugTokenStream(tokens: org.antlr.runtime.CommonTokenStream, out: java.io.PrintStream):
        ...

    @staticmethod
    def debugTree(tree: org.antlr.runtime.tree.Tree, out: java.io.PrintStream):
        ...

    @staticmethod
    def generateArrow(charPositionInLine: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getLine(reader: java.io.Reader, lineno: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getLine(writer: LineArrayListWriter, lineno: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def tabCompensate(line: typing.Union[java.lang.String, str], charPositionInLine: typing.Union[jpype.JInt, int]) -> int:
        ...


class Location(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    INTERNALLY_DEFINED: typing.Final[Location]
    filename: typing.Final[java.lang.String]
    lineno: typing.Final[jpype.JInt]

    def __init__(self, filename: typing.Union[java.lang.String, str], lineno: typing.Union[jpype.JInt, int]):
        ...


class LocationUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def maximum(locations: java.util.List[Location]) -> Location:
        ...

    @staticmethod
    def minimum(locations: java.util.List[Location]) -> Location:
        ...


class SleighToken(org.antlr.runtime.CommonToken):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, type: typing.Union[jpype.JInt, int], channel: typing.Union[jpype.JInt, int], start: typing.Union[jpype.JInt, int], stop: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, type: typing.Union[jpype.JInt, int], text: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, type: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, type: typing.Union[jpype.JInt, int], line: typing.Union[jpype.JInt, int], charPos: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, oldToken: org.antlr.runtime.Token):
        ...

    def getLocation(self) -> Location:
        ...

    def setLocation(self, location: Location):
        ...

    @property
    def location(self) -> Location:
        ...

    @location.setter
    def location(self, value: Location):
        ...


class ExpressionEnvironment(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, lhs: typing.Union[java.lang.String, str], rhs: typing.Union[java.lang.String, str]) -> bool:
        ...

    def lookup(self, variable: typing.Union[java.lang.String, str]) -> str:
        ...

    def reportError(self, msg: typing.Union[java.lang.String, str]):
        ...


class BooleanExpressionLexer(org.antlr.runtime.Lexer):

    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    T__20: typing.Final = 20
    T__21: typing.Final = 21
    ALPHA: typing.Final = 4
    DIGIT: typing.Final = 5
    ESCAPE: typing.Final = 6
    HEXDIGIT: typing.Final = 7
    IDENTIFIER: typing.Final = 8
    KEY_DEFINED: typing.Final = 9
    OCTAL_ESCAPE: typing.Final = 10
    OP_AND: typing.Final = 11
    OP_EQ: typing.Final = 12
    OP_NEQ: typing.Final = 13
    OP_NOT: typing.Final = 14
    OP_OR: typing.Final = 15
    OP_XOR: typing.Final = 16
    QSTRING: typing.Final = 17
    UNICODE_ESCAPE: typing.Final = 18
    WS: typing.Final = 19

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def getDelegates(self) -> jpype.JArray[org.antlr.runtime.Lexer]:
        ...

    def mALPHA(self):
        ...

    def mDIGIT(self):
        ...

    def mESCAPE(self):
        ...

    def mHEXDIGIT(self):
        ...

    def mIDENTIFIER(self):
        ...

    def mKEY_DEFINED(self):
        ...

    def mOCTAL_ESCAPE(self):
        ...

    def mOP_AND(self):
        ...

    def mOP_EQ(self):
        ...

    def mOP_NEQ(self):
        ...

    def mOP_NOT(self):
        ...

    def mOP_OR(self):
        ...

    def mOP_XOR(self):
        ...

    def mQSTRING(self):
        ...

    def mT__20(self):
        ...

    def mT__21(self):
        ...

    def mUNICODE_ESCAPE(self):
        ...

    def mWS(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[org.antlr.runtime.Lexer]:
        ...


class BaseRecognizerOverride(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: jpype.JArray[java.lang.String], writer: LineArrayListWriter) -> str:
        ...

    def getTokenErrorDisplay(self, t: org.antlr.runtime.Token) -> str:
        ...

    @property
    def tokenErrorDisplay(self) -> java.lang.String:
        ...


class SourceFileIndexer(java.lang.Object):
    """
    This class is used to index source files in a SLEIGH language module.
    The SLEIGH compiler records the index of the source file for a constructor rather
    than the file name.  This is an optimization to avoid repeating the file name in
    the .sla files.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a {code SourceFileIndexer} object with an empty index.
        """

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        """
        Decode an index from a stream
        
        :param ghidra.program.model.pcode.Decoder decoder: is the stream
        :raises DecoderException: for errors in the encoding
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode the index to a stream
        
        :param ghidra.program.model.pcode.Encoder encoder: stream to write to
        :raises IOException: for errors writing to the stream
        """

    def getFileName(self, index: typing.Union[java.lang.Integer, int]) -> str:
        """
        Returns the file name at a given index
        
        :param java.lang.Integer or int index: index
        :return: file name or ``null`` if there is no file with that index
        :rtype: str
        """

    def getIndex(self, filename: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the index for a filename
        
        :param java.lang.String or str filename: file
        :return: index or ``null`` if ``filename`` is not in the index.
        :rtype: int
        """

    def index(self, loc: Location) -> int:
        """
        Adds the filename of a location to the index if it is not already present.
        
        :param Location loc: location containing filename to add
        :return: index associated with filename, or ``null`` if a ``null`` :obj:`Location`
        or a :obj:`Location` with a ``null`` filename was provided as input.
        :rtype: int
        """

    @property
    def fileName(self) -> java.lang.String:
        ...


class SleighCompiler(org.antlr.runtime.tree.TreeParser):

    @typing.type_check_only
    class Return_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Block_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Jump_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class tokendef_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class fielddef_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class contextdef_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class spacedef_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class macrodef_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class id_or_nil_return(org.antlr.runtime.tree.TreeRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]
        value: java.lang.String
        tree: org.antlr.runtime.tree.Tree

        def __init__(self):
            ...


    @typing.type_check_only
    class ctorstart_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class semantic_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class code_block_scope(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class identifier_return(org.antlr.runtime.tree.TreeRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]
        value: java.lang.String
        tree: org.antlr.runtime.tree.Tree

        def __init__(self):
            ...


    @typing.type_check_only
    class DFA52(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    @typing.type_check_only
    class DFA57(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    @typing.type_check_only
    class DFA58(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    tokenNames: typing.Final[jpype.JArray[java.lang.String]]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    FOLLOW_endiandef_in_root80: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_definition_in_root86: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlike_in_root92: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ENDIAN_in_endiandef109: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_endiandef113: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BIG_in_endian131: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LITTLE_in_endian141: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_aligndef_in_definition155: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_tokendef_in_definition160: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextdef_in_definition165: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacedef_in_definition170: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnodedef_in_definition175: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrangedef_in_definition180: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pcodeopdef_in_definition185: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valueattach_in_definition190: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_nameattach_in_definition195: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varattach_in_definition200: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ALIGNMENT_in_aligndef215: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_aligndef219: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TOKEN_in_tokendef245: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_identifier_in_tokendef249: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef254: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef258: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TOKEN_ENDIAN_in_tokendef267: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_identifier_in_tokendef271: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef276: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_tokendef280: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef284: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELDDEFS_in_fielddefs297: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddef_in_fielddefs299: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELDDEF_in_fielddef325: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_fielddef329: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef334: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef338: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmods_in_fielddef342: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELD_MODS_in_fieldmods357: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmod_in_fieldmods359: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NO_FIELD_MOD_in_fieldmods366: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIGNED_in_fieldmod382: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOFLOW_in_fieldmod394: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_HEX_in_fieldmod406: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEC_in_fieldmod418: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_specific_identifier440: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_specific_identifier454: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_unbound_identifier473: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_unbound_identifier487: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_varnode_symbol506: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_varnode_symbol520: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_value_symbol539: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_value_symbol553: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_operand_symbol572: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_operand_symbol586: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_space_symbol605: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_space_symbol619: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_specific_symbol638: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_specific_symbol652: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_family_symbol671: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_family_symbol685: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONTEXT_in_contextdef710: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_symbol_in_contextdef714: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_contextdef719: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SPACE_in_spacedef743: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_spacedef747: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemods_in_spacedef754: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SPACEMODS_in_spacemods769: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemod_in_spacemods771: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_typemod_in_spacemod784: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizemod_in_spacemod789: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_wordsizemod_in_spacemod794: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEFAULT_in_spacemod799: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TYPE_in_typemod813: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_identifier_in_typemod817: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIZE_in_sizemod833: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizemod837: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WORDSIZE_in_wordsizemod852: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_wordsizemod856: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VARNODE_in_varnodedef871: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_varnodedef875: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef880: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef884: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varnodedef888: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist919: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_identifierlist927: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_identifierlist943: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist971: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringorident_in_stringoridentlist976: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_stringorident999: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_qstring_in_stringorident1008: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGES_in_bitrangedef1022: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sbitrange_in_bitrangedef1024: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE_in_sbitrange1038: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_sbitrange1041: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_symbol_in_sbitrange1050: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sbitrange1055: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sbitrange1059: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODEOP_in_pcodeopdef1074: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_pcodeopdef1078: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VALUES_in_valueattach1099: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valuelist_in_valueattach1103: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intblist_in_valueattach1108: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INTBLIST_in_intblist1133: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intbpart_in_intblist1138: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_intbpart1161: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_intbpart1169: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_intbpart1173: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_intbpart1183: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NAMES_in_nameattach1203: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valuelist_in_nameattach1207: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringoridentlist_in_nameattach1212: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VARIABLES_in_varattach1233: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valuelist_in_varattach1237: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varlist_in_varattach1242: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_LIST_in_valuelist1275: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_value_symbol_in_valuelist1280: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_LIST_in_varlist1311: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_symbol_in_varlist1316: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_macrodef_in_constructorlike1334: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_withblock_in_constructorlike1341: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructor_in_constructorlike1348: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MACRO_in_macrodef1373: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_macrodef1377: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_arguments_in_macrodef1382: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semantic_in_macrodef1388: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ARGUMENTS_in_arguments1420: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_arguments1424: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EMPTY_LIST_in_arguments1439: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WITH_in_withblock1451: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_id_or_nil_in_withblock1455: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpat_or_nil_in_withblock1459: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextblock_in_withblock1463: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlikelist_in_withblock1469: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_id_or_nil1491: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NIL_in_id_or_nil1498: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpattern_in_bitpat_or_nil1517: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NIL_in_bitpat_or_nil1524: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CTLIST_in_constructorlikelist1538: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_definition_in_constructorlikelist1542: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlike_in_constructorlikelist1546: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONSTRUCTOR_in_constructor1563: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorstart_in_constructor1567: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpattern_in_constructor1571: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextblock_in_constructor1575: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorsemantic_in_constructor1579: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODE_in_ctorsemantic1602: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semantic_in_ctorsemantic1606: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODE_in_ctorsemantic1616: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_UNIMPL_in_ctorsemantic1618: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BIT_PATTERN_in_bitpattern1637: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_bitpattern1641: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUBTABLE_in_ctorstart1673: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_ctorstart1677: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_ctorstart1691: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1698: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TABLE_in_ctorstart1710: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1716: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DISPLAY_in_display1733: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pieces_in_display1737: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_printpiece_in_pieces1751: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_printpiece1772: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_whitespace_in_printpiece1786: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONCATENATE_in_printpiece1793: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_string_in_printpiece1800: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WHITESPACE_in_whitespace1818: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_STRING_in_string1841: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_QSTRING_in_string1854: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_OR_in_pequation1885: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1889: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1893: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SEQUENCE_in_pequation1904: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1908: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1912: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_AND_in_pequation1923: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1927: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1931: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ELLIPSIS_in_pequation1943: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1947: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1958: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1962: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EQUAL_in_pequation1974: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_or_operand_symbol_in_pequation1978: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1983: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOTEQUAL_in_pequation1994: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_symbol_in_pequation1998: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation2003: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESS_in_pequation2014: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_symbol_in_pequation2018: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation2023: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESSEQUAL_in_pequation2034: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_symbol_in_pequation2038: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation2043: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREAT_in_pequation2054: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_symbol_in_pequation2058: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation2063: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREATEQUAL_in_pequation2074: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_family_symbol_in_pequation2078: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation2083: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_symbol_in_pequation2094: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_pequation2103: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation2107: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_family_or_operand_symbol2128: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_family_or_operand_symbol2142: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_pequation_symbol2161: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_pequation_symbol2175: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_pexpression2195: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2199: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2203: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_pexpression2214: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2218: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2222: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_pexpression2233: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2237: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2241: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LEFT_in_pexpression2252: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2256: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2260: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RIGHT_in_pexpression2271: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2275: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2279: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADD_in_pexpression2290: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2294: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2298: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUB_in_pexpression2309: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2313: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2317: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MULT_in_pexpression2328: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2332: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2336: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DIV_in_pexpression2347: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2351: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2355: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_pexpression2367: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2371: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INVERT_in_pexpression2382: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2386: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pattern_symbol_in_pexpression2398: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_pexpression2408: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_pexpression2416: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression2420: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_pexpression22441: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22445: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22449: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_pexpression22460: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22464: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22468: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_pexpression22479: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22483: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22487: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LEFT_in_pexpression22498: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22502: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22506: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RIGHT_in_pexpression22517: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22521: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22525: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADD_in_pexpression22536: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22540: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22544: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUB_in_pexpression22555: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22559: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22563: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MULT_in_pexpression22574: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22578: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22582: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DIV_in_pexpression22593: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22597: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22601: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_pexpression22613: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22617: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INVERT_in_pexpression22628: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22632: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pattern_symbol2_in_pexpression22644: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_pexpression22654: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_pexpression22662: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression22666: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_pattern_symbol2686: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_pattern_symbol2700: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_pattern_symbol22719: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_pattern_symbol22733: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONTEXT_BLOCK_in_contextblock2751: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_cstatements_in_contextblock2755: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock2763: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_cstatement_in_cstatements2785: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_cstatement2800: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_cstatement2803: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_cstatement2812: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_APPLY_in_cstatement2821: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_cstatement2824: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_cstatement2832: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_cstatement2840: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SEMANTIC_in_semantic2884: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_code_block_in_semantic2888: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statements_in_code_block2939: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOP_in_code_block2944: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statement_in_statements2955: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_assignment_in_statement2987: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_declaration_in_statement2999: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_funcall_in_statement3011: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_build_stmt_in_statement3028: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_crossbuild_stmt_in_statement3042: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_goto_stmt_in_statement3051: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_cond_stmt_in_statement3066: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_call_stmt_in_statement3081: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_return_stmt_in_statement3096: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_statement3109: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_export_in_statement3118: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_section_label_in_statement3128: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_declaration3142: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_declaration3146: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_declaration3151: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_declaration3160: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_declaration3164: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LABEL_in_label3184: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_label3188: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_label3204: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SECTION_LABEL_in_section_label3224: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_section_label3228: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_section_label3244: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_section_symbol3265: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_section_symbol3279: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3305: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE_in_assignment3308: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_assignment3312: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_assignment3317: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_assignment3321: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3326: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3337: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3340: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_assignment3344: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_assignment3349: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3354: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_assignment3363: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3367: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3370: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_assignment3374: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_assignment3379: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3384: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_assignment3393: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3397: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unbound_identifier_in_assignment3401: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3406: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3417: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_assignment3420: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3429: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3438: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_assignment3442: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3446: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment3457: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_assignment3461: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment3465: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE_in_bitrange3486: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_bitrange3490: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_bitrange3495: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_bitrange3499: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar3532: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_sizedstar3536: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizedstar3541: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar3545: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar3556: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_sizedstar3560: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar3565: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar3576: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizedstar3580: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar3584: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar3595: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar3599: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstarv3632: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_sizedstarv3636: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizedstarv3641: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_sizedstarv3645: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstarv3657: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_sizedstarv3661: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_sizedstarv3666: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstarv3678: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizedstarv3682: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_sizedstarv3686: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstarv3698: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_sizedstarv3702: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_funcall3729: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BUILD_in_build_stmt3755: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_operand_symbol_in_build_stmt3759: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt3787: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_crossbuild_stmt3791: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_section_symbol_in_crossbuild_stmt3795: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GOTO_in_goto_stmt3835: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_goto_stmt3839: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_jump_symbol3860: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_jump_symbol3874: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest3895: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jump_symbol_in_jumpdest3899: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest3911: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_jumpdest3915: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest3926: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_jumpdest3930: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest3941: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_jumpdest3945: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_space_symbol_in_jumpdest3949: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest3961: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_jumpdest3965: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IF_in_cond_stmt3992: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_cond_stmt3996: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GOTO_in_cond_stmt3999: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_cond_stmt4003: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CALL_in_call_stmt4044: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_call_stmt4048: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RETURN_in_return_stmt4076: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_return_stmt4080: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EXPORT_in_export4102: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstarv_in_export4106: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EXPORT_in_export4117: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_export4121: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_OR_in_expr4142: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4146: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4150: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_XOR_in_expr4161: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4165: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4169: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_AND_in_expr4180: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4184: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4188: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_expr4200: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4204: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4208: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_expr4219: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4223: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4227: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_expr4238: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4242: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4246: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EQUAL_in_expr4258: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4262: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4266: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOTEQUAL_in_expr4277: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4281: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4285: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FEQUAL_in_expr4296: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4300: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4304: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FNOTEQUAL_in_expr4315: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4319: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4323: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESS_in_expr4335: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4339: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4343: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREATEQUAL_in_expr4354: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4358: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4362: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESSEQUAL_in_expr4373: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4377: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4381: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREAT_in_expr4392: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4396: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4400: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SLESS_in_expr4411: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4415: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4419: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SGREATEQUAL_in_expr4430: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4434: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4438: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SLESSEQUAL_in_expr4449: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4453: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4457: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SGREAT_in_expr4468: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4472: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4476: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FLESS_in_expr4487: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4491: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4495: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FGREATEQUAL_in_expr4506: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4510: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4514: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FLESSEQUAL_in_expr4525: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4529: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4533: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FGREAT_in_expr4544: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4548: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4552: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LEFT_in_expr4564: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4568: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4572: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RIGHT_in_expr4583: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4587: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4591: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SRIGHT_in_expr4602: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4606: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4610: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADD_in_expr4622: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4626: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4630: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUB_in_expr4641: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4645: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4649: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FADD_in_expr4660: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4664: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4668: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FSUB_in_expr4679: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4683: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4687: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MULT_in_expr4699: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4703: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4707: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DIV_in_expr4718: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4722: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4726: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_REM_in_expr4737: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4741: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4745: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SDIV_in_expr4756: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4760: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4764: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SREM_in_expr4775: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4779: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4783: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FMULT_in_expr4794: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4798: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4802: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FDIV_in_expr4813: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4817: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4821: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOT_in_expr4833: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4837: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INVERT_in_expr4848: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4852: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_expr4863: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4867: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FNEGATE_in_expr4878: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4882: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_expr4892: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_expr4902: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_or_bitsym_in_expr4911: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrange_in_expr4921: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_expr4930: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_expr4938: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr4942: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE2_in_expr4954: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_expr4958: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_expr4963: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_varnode_or_bitsym4985: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_adorned_in_varnode_or_bitsym4999: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_varnode_or_bitsym5008: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_APPLY_in_expr_apply5034: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_expr_apply5039: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_operands_in_expr_apply5048: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_APPLY_in_expr_apply5059: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_expr_apply5063: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_operands_in_expr_apply5067: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_operands5100: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TRUNCATION_SIZE_in_varnode_adorned5122: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnode_adorned5126: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnode_adorned5130: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5139: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIZING_SIZE_in_varnode_adorned5142: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnode_adorned5146: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode_adorned5151: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADDRESS_OF_in_varnode_adorned5160: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode_adorned5164: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_specific_symbol_in_varnode5184: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_adorned_in_varnode5194: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_QSTRING_in_qstring5212: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_identifier5235: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_identifier5249: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_HEX_CONSTANT_in_integer5267: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEC_CONSTANT_in_integer5280: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BIN_CONSTANT_in_integer5293: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.tree.TreeNodeStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.tree.TreeNodeStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def aligndef(self):
        ...

    def arguments(self) -> generic.stl.Pair[generic.stl.VectorSTL[java.lang.String], generic.stl.VectorSTL[Location]]:
        ...

    def assignment(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def bitpat_or_nil(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def bitpattern(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def bitrange(self) -> ghidra.pcodeCPort.slgh_compile.ExprTree:
        ...

    def bitrangedef(self):
        ...

    def build_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def call_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def code_block(self, startingPoint: Location) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def cond_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def constructor(self):
        ...

    def constructorlike(self):
        ...

    def constructorlikelist(self):
        ...

    def contextblock(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange]:
        ...

    def contextdef(self):
        ...

    def crossbuild_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def cstatement(self, r: generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange]):
        ...

    def cstatements(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.ContextChange]:
        ...

    def ctorsemantic(self, ctor: ghidra.pcodeCPort.slghsymbol.Constructor) -> ghidra.pcodeCPort.slgh_compile.SectionVector:
        ...

    def ctorstart(self) -> ghidra.pcodeCPort.slghsymbol.Constructor:
        ...

    def declaration(self):
        ...

    def definition(self):
        ...

    def display(self, ct: ghidra.pcodeCPort.slghsymbol.Constructor):
        ...

    def endian(self) -> int:
        ...

    def endiandef(self):
        ...

    def export(self, rtl: ghidra.pcodeCPort.semantics.ConstructTpl) -> ghidra.pcodeCPort.semantics.ConstructTpl:
        ...

    def expr(self) -> ghidra.pcodeCPort.slgh_compile.ExprTree:
        ...

    def expr_apply(self) -> java.lang.Object:
        ...

    def expr_operands(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.slgh_compile.ExprTree]:
        ...

    def family_or_operand_symbol(self, purpose: typing.Union[java.lang.String, str]) -> org.antlr.runtime.tree.Tree:
        ...

    def family_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.FamilySymbol:
        ...

    def fielddef(self):
        ...

    def fielddefs(self):
        ...

    def fieldmod(self):
        ...

    def fieldmods(self):
        ...

    def funcall(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def getDelegates(self) -> jpype.JArray[org.antlr.runtime.tree.TreeParser]:
        ...

    def getErrorHeader(self, e: org.antlr.runtime.RecognitionException) -> str:
        ...

    def getErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: jpype.JArray[java.lang.String]) -> str:
        ...

    def getTokenErrorDisplay(self, t: org.antlr.runtime.Token) -> str:
        ...

    def goto_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def id_or_nil(self) -> SleighCompiler.id_or_nil_return:
        ...

    def identifier(self) -> SleighCompiler.identifier_return:
        ...

    def identifierlist(self) -> generic.stl.Pair[generic.stl.VectorSTL[java.lang.String], generic.stl.VectorSTL[Location]]:
        ...

    def intblist(self) -> generic.stl.VectorSTL[java.lang.Long]:
        ...

    def intbpart(self) -> java.math.BigInteger:
        ...

    def integer(self) -> RadixBigInteger:
        ...

    def jump_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def jumpdest(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slgh_compile.ExprTree:
        ...

    def label(self) -> generic.stl.Pair[Location, ghidra.pcodeCPort.slghsymbol.LabelSymbol]:
        ...

    def macrodef(self):
        ...

    def nameattach(self):
        ...

    def operand_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.OperandSymbol:
        ...

    def pattern_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...

    def pattern_symbol2(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...

    def pcodeopdef(self):
        ...

    def pequation(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def pequation_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation:
        ...

    def pexpression(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...

    def pexpression2(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression:
        ...

    def pieces(self, ct: ghidra.pcodeCPort.slghsymbol.Constructor):
        ...

    def printpiece(self, ct: ghidra.pcodeCPort.slghsymbol.Constructor):
        ...

    def qstring(self) -> str:
        ...

    def return_stmt(self) -> generic.stl.VectorSTL[ghidra.pcodeCPort.semantics.OpTpl]:
        ...

    def root(self, pe: ParsingEnvironment, sc: ghidra.pcodeCPort.slgh_compile.SleighCompile) -> int:
        ...

    def sbitrange(self):
        ...

    def section_label(self) -> generic.stl.Pair[Location, ghidra.pcodeCPort.slghsymbol.SectionSymbol]:
        ...

    def section_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SectionSymbol:
        ...

    def semantic(self, pe: ParsingEnvironment, containerLoc: Location, pcode: ghidra.pcodeCPort.slgh_compile.PcodeCompile, where: org.antlr.runtime.tree.Tree, sectionsAllowed: typing.Union[jpype.JBoolean, bool], isMacroParse: typing.Union[jpype.JBoolean, bool]) -> ghidra.pcodeCPort.slgh_compile.SectionVector:
        ...

    def sizedstar(self) -> generic.stl.Pair[ghidra.pcodeCPort.slgh_compile.StarQuality, ghidra.pcodeCPort.slgh_compile.ExprTree]:
        ...

    def sizedstarv(self) -> generic.stl.Pair[ghidra.pcodeCPort.slgh_compile.StarQuality, ghidra.pcodeCPort.semantics.VarnodeTpl]:
        ...

    def sizemod(self):
        ...

    def space_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SpaceSymbol:
        ...

    def spacedef(self):
        ...

    def spacemod(self):
        ...

    def spacemods(self):
        ...

    def specific_identifier(self, purpose: typing.Union[java.lang.String, str]) -> org.antlr.runtime.tree.Tree:
        ...

    def specific_symbol(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slghsymbol.SpecificSymbol:
        ...

    def statement(self):
        ...

    def statements(self):
        ...

    def string(self) -> str:
        ...

    def stringorident(self) -> str:
        ...

    def stringoridentlist(self) -> generic.stl.VectorSTL[java.lang.String]:
        ...

    def tokendef(self):
        ...

    def typemod(self):
        ...

    def unbound_identifier(self, purpose: typing.Union[java.lang.String, str]) -> org.antlr.runtime.tree.Tree:
        ...

    def value_symbol(self, purpose: typing.Union[java.lang.String, str]) -> generic.stl.Pair[ghidra.pcodeCPort.slghsymbol.ValueSymbol, Location]:
        ...

    def valueattach(self):
        ...

    def valuelist(self, purpose: typing.Union[java.lang.String, str]) -> generic.stl.Pair[generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol], generic.stl.VectorSTL[Location]]:
        ...

    def varattach(self):
        ...

    def varlist(self, purpose: typing.Union[java.lang.String, str]) -> generic.stl.VectorSTL[ghidra.pcodeCPort.slghsymbol.SleighSymbol]:
        ...

    def varnode(self) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def varnode_adorned(self) -> ghidra.pcodeCPort.semantics.VarnodeTpl:
        ...

    def varnode_or_bitsym(self, purpose: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.slgh_compile.ExprTree:
        ...

    def varnode_symbol(self, purpose: typing.Union[java.lang.String, str], noWildcards: typing.Union[jpype.JBoolean, bool]) -> ghidra.pcodeCPort.slghsymbol.VarnodeSymbol:
        ...

    def varnodedef(self):
        ...

    def whitespace(self) -> str:
        ...

    def withblock(self):
        ...

    def wordsizemod(self):
        ...

    @property
    def tokenErrorDisplay(self) -> java.lang.String:
        ...

    @property
    def delegates(self) -> jpype.JArray[org.antlr.runtime.tree.TreeParser]:
        ...

    @property
    def errorHeader(self) -> java.lang.String:
        ...


class DisplayLexer(AbstractSleighLexer):

    @typing.type_check_only
    class DFA2(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gBaseLexer: DisplayLexer_BaseLexer

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...

    def mDISPCHAR(self):
        ...

    def mLINECOMMENT(self):
        ...

    def mRES_IS(self):
        ...

    def mWS(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...


class BailoutException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class SleighParserRun(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class SleighParser_SemanticParser(AbstractSleighParser):

    class semanticbody_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class semantic_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class code_block_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class statements_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class label_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class section_def_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class statement_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class outererror_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class assignment_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class declaration_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class lvalue_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class sembitrange_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class sizedstar_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class funcall_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class build_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class crossbuild_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class goto_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class jumpdest_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class cond_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class call_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class return_stmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class sizedexport_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class export_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_boolor_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_boolor_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_booland_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class booland_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_or_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_or_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_xor_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_xor_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_and_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_and_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_eq_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class eq_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_comp_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class compare_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_shift_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class shift_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_add_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class add_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_mult_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class mult_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_unary_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class unary_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_func_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_apply_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_operands_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class expr_term_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class varnode_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constant_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class DFA3(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gSleighParser: SleighParser
    gParent: SleighParser
    FOLLOW_LBRACE_in_semanticbody30: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semantic_in_semanticbody34: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACE_in_semanticbody36: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_code_block_in_semantic53: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statements_in_code_block72: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statement_in_statements95: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESS_in_label109: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_label111: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREAT_in_label113: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LEFT_in_section_def135: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_section_def137: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RIGHT_in_section_def139: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_assignment_in_statement167: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_declaration_in_statement173: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_funcall_in_statement179: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_build_stmt_in_statement185: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_crossbuild_stmt_in_statement191: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_goto_stmt_in_statement197: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_cond_stmt_in_statement203: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_call_stmt_in_statement209: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_export_in_statement215: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_return_stmt_in_statement221: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_statement235: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_statement243: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_section_def_in_statement248: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_outererror_in_statement253: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EQUAL_in_outererror267: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_NOTEQUAL_in_outererror274: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FEQUAL_in_outererror281: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FNOTEQUAL_in_outererror288: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESSEQUAL_in_outererror295: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREATEQUAL_in_outererror302: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLESS_in_outererror309: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SGREAT_in_outererror316: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLESSEQUAL_in_outererror323: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SGREATEQUAL_in_outererror330: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FLESS_in_outererror337: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FGREAT_in_outererror344: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FLESSEQUAL_in_outererror351: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FGREATEQUAL_in_outererror358: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_outererror365: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_outererror372: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_outererror379: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_outererror386: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_OR_in_outererror393: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_XOR_in_outererror400: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_AND_in_outererror407: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PIPE_in_outererror414: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_CARET_in_outererror421: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_outererror428: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SRIGHT_in_outererror435: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PLUS_in_outererror442: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_outererror449: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FPLUS_in_outererror456: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FMINUS_in_outererror463: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLASH_in_outererror470: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PERCENT_in_outererror477: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SDIV_in_outererror484: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SREM_in_outererror491: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FMULT_in_outererror498: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FDIV_in_outererror505: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_TILDE_in_outererror512: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_outererror519: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_outererror526: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LOCAL_in_assignment542: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_lvalue_in_assignment544: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_assignment548: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment550: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_lvalue_in_assignment569: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_assignment573: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment575: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LOCAL_in_declaration599: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_declaration601: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_declaration605: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_declaration607: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LOCAL_in_declaration625: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_declaration627: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sembitrange_in_lvalue647: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_lvalue652: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_lvalue656: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_lvalue658: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_lvalue674: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_lvalue679: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_lvalue682: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sembitrange693: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_sembitrange697: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sembitrange701: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_sembitrange703: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sembitrange707: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_sembitrange709: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_sizedstar737: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_sizedstar739: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sizedstar741: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_sizedstar743: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_sizedstar745: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sizedstar747: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_sizedstar765: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_sizedstar767: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sizedstar769: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_sizedstar771: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_sizedstar802: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_sizedstar833: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sizedstar835: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_sizedstar851: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_funcall913: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BUILD_in_build_stmt926: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_build_stmt928: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CROSSBUILD_in_crossbuild_stmt950: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_crossbuild_stmt952: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_crossbuild_stmt954: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_crossbuild_stmt956: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_GOTO_in_goto_stmt979: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_goto_stmt981: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_jumpdest1001: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_jumpdest1014: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_jumpdest1016: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_jumpdest1018: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_jumpdest1031: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_jumpdest1044: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_jumpdest1046: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_jumpdest1048: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_jumpdest1050: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_jumpdest1065: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RES_IF_in_cond_stmt1086: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_cond_stmt1088: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_goto_stmt_in_cond_stmt1090: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CALL_in_call_stmt1114: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_call_stmt1116: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_RETURN_in_return_stmt1138: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_return_stmt1140: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_return_stmt1142: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_return_stmt1144: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_sizedexport1164: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sizedexport1167: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_EXPORT_in_export1180: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedexport_in_export1182: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_EXPORT_in_export1198: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_export1200: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_boolor_in_expr1220: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_booland_in_expr_boolor1231: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_boolor_op_in_expr_boolor1235: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_booland_in_expr_boolor1238: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_OR_in_expr_boolor_op1254: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_or_in_expr_booland1272: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_booland_op_in_expr_booland1276: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_or_in_expr_booland1279: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_AND_in_booland_op1295: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_XOR_in_booland_op1309: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_xor_in_expr_or1327: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_or_op_in_expr_or1331: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_xor_in_expr_or1334: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PIPE_in_expr_or_op1350: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_and_in_expr_xor1368: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_xor_op_in_expr_xor1372: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_and_in_expr_xor1375: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_CARET_in_expr_xor_op1391: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_eq_in_expr_and1409: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_and_op_in_expr_and1413: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_eq_in_expr_and1416: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_expr_and_op1432: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_comp_in_expr_eq1450: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_eq_op_in_expr_eq1454: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_comp_in_expr_eq1457: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EQUAL_in_eq_op1473: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_NOTEQUAL_in_eq_op1487: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FEQUAL_in_eq_op1501: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FNOTEQUAL_in_eq_op1515: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_shift_in_expr_comp1533: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_compare_op_in_expr_comp1537: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_shift_in_expr_comp1540: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESS_in_compare_op1556: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREATEQUAL_in_compare_op1570: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESSEQUAL_in_compare_op1584: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREAT_in_compare_op1598: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLESS_in_compare_op1612: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SGREATEQUAL_in_compare_op1626: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLESSEQUAL_in_compare_op1640: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SGREAT_in_compare_op1654: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FLESS_in_compare_op1668: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FGREATEQUAL_in_compare_op1682: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FLESSEQUAL_in_compare_op1696: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FGREAT_in_compare_op1710: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_add_in_expr_shift1728: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_shift_op_in_expr_shift1732: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_add_in_expr_shift1735: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LEFT_in_shift_op1751: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RIGHT_in_shift_op1765: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SRIGHT_in_shift_op1779: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_mult_in_expr_add1797: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_add_op_in_expr_add1801: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_mult_in_expr_add1804: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PLUS_in_add_op1820: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_add_op1834: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FPLUS_in_add_op1848: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FMINUS_in_add_op1862: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_unary_in_expr_mult1880: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_mult_op_in_expr_mult1884: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_unary_in_expr_mult1887: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_mult_op1903: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLASH_in_mult_op1917: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PERCENT_in_mult_op1931: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SDIV_in_mult_op1945: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SREM_in_mult_op1959: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FMULT_in_mult_op1973: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FDIV_in_mult_op1987: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_unary_op_in_expr_unary2005: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_func_in_expr_unary2010: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EXCLAIM_in_unary_op2023: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_TILDE_in_unary_op2037: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_unary_op2051: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_FMINUS_in_unary_op2065: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_unary_op2077: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_expr_func2088: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_term_in_expr_func2093: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_expr_apply2104: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_operands_in_expr_apply2106: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_expr_operands2128: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_operands2132: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_expr_operands2135: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_operands2138: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_expr_operands2145: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_expr_term2157: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sembitrange_in_expr_term2162: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_expr_term2169: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_term2171: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_expr_term2173: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnode2193: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_varnode2198: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnode2203: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_varnode2207: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_varnode2209: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_varnode2225: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_varnode2229: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_varnode2231: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_varnode2249: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_varnode2253: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_varnode2255: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode2257: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_varnode2280: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode2282: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_constant2302: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, gSleighParser: SleighParser):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, state: org.antlr.runtime.RecognizerSharedState, gSleighParser: SleighParser):
        ...

    def add_op(self) -> SleighParser_SemanticParser.add_op_return:
        ...

    def assignment(self) -> SleighParser_SemanticParser.assignment_return:
        ...

    def booland_op(self) -> SleighParser_SemanticParser.booland_op_return:
        ...

    def build_stmt(self) -> SleighParser_SemanticParser.build_stmt_return:
        ...

    def call_stmt(self) -> SleighParser_SemanticParser.call_stmt_return:
        ...

    def code_block(self) -> SleighParser_SemanticParser.code_block_return:
        ...

    def compare_op(self) -> SleighParser_SemanticParser.compare_op_return:
        ...

    def cond_stmt(self) -> SleighParser_SemanticParser.cond_stmt_return:
        ...

    def constant(self) -> SleighParser_SemanticParser.constant_return:
        ...

    def crossbuild_stmt(self) -> SleighParser_SemanticParser.crossbuild_stmt_return:
        ...

    def declaration(self) -> SleighParser_SemanticParser.declaration_return:
        ...

    def eq_op(self) -> SleighParser_SemanticParser.eq_op_return:
        ...

    def export(self) -> SleighParser_SemanticParser.export_return:
        ...

    def expr(self) -> SleighParser_SemanticParser.expr_return:
        ...

    def expr_add(self) -> SleighParser_SemanticParser.expr_add_return:
        ...

    def expr_and(self) -> SleighParser_SemanticParser.expr_and_return:
        ...

    def expr_and_op(self) -> SleighParser_SemanticParser.expr_and_op_return:
        ...

    def expr_apply(self) -> SleighParser_SemanticParser.expr_apply_return:
        ...

    def expr_booland(self) -> SleighParser_SemanticParser.expr_booland_return:
        ...

    def expr_boolor(self) -> SleighParser_SemanticParser.expr_boolor_return:
        ...

    def expr_boolor_op(self) -> SleighParser_SemanticParser.expr_boolor_op_return:
        ...

    def expr_comp(self) -> SleighParser_SemanticParser.expr_comp_return:
        ...

    def expr_eq(self) -> SleighParser_SemanticParser.expr_eq_return:
        ...

    def expr_func(self) -> SleighParser_SemanticParser.expr_func_return:
        ...

    def expr_mult(self) -> SleighParser_SemanticParser.expr_mult_return:
        ...

    def expr_operands(self) -> SleighParser_SemanticParser.expr_operands_return:
        ...

    def expr_or(self) -> SleighParser_SemanticParser.expr_or_return:
        ...

    def expr_or_op(self) -> SleighParser_SemanticParser.expr_or_op_return:
        ...

    def expr_shift(self) -> SleighParser_SemanticParser.expr_shift_return:
        ...

    def expr_term(self) -> SleighParser_SemanticParser.expr_term_return:
        ...

    def expr_unary(self) -> SleighParser_SemanticParser.expr_unary_return:
        ...

    def expr_xor(self) -> SleighParser_SemanticParser.expr_xor_return:
        ...

    def expr_xor_op(self) -> SleighParser_SemanticParser.expr_xor_op_return:
        ...

    def funcall(self) -> SleighParser_SemanticParser.funcall_return:
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...

    def getTreeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    def goto_stmt(self) -> SleighParser_SemanticParser.goto_stmt_return:
        ...

    def jumpdest(self) -> SleighParser_SemanticParser.jumpdest_return:
        ...

    def label(self) -> SleighParser_SemanticParser.label_return:
        ...

    def lvalue(self) -> SleighParser_SemanticParser.lvalue_return:
        ...

    def mult_op(self) -> SleighParser_SemanticParser.mult_op_return:
        ...

    def outererror(self) -> SleighParser_SemanticParser.outererror_return:
        ...

    def return_stmt(self) -> SleighParser_SemanticParser.return_stmt_return:
        ...

    def section_def(self) -> SleighParser_SemanticParser.section_def_return:
        ...

    def semantic(self) -> SleighParser_SemanticParser.semantic_return:
        ...

    def semanticbody(self) -> SleighParser_SemanticParser.semanticbody_return:
        ...

    def sembitrange(self) -> SleighParser_SemanticParser.sembitrange_return:
        ...

    def setTreeAdaptor(self, adaptor: org.antlr.runtime.tree.TreeAdaptor):
        ...

    def shift_op(self) -> SleighParser_SemanticParser.shift_op_return:
        ...

    def sizedexport(self) -> SleighParser_SemanticParser.sizedexport_return:
        ...

    def sizedstar(self) -> SleighParser_SemanticParser.sizedstar_return:
        ...

    def statement(self) -> SleighParser_SemanticParser.statement_return:
        ...

    def statements(self) -> SleighParser_SemanticParser.statements_return:
        ...

    def unary_op(self) -> SleighParser_SemanticParser.unary_op_return:
        ...

    def varnode(self) -> SleighParser_SemanticParser.varnode_return:
        ...

    @property
    def treeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    @treeAdaptor.setter
    def treeAdaptor(self, value: org.antlr.runtime.tree.TreeAdaptor):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...


class SleighParser(AbstractSleighParser):

    class spec_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class endiandef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class endian_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class definition_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class aligndef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class tokendef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class fielddefs_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class fielddef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class fieldmods_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class fieldmod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextfielddefs_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextfielddef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextfieldmods_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextfieldmod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextdef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class spacedef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class spacemods_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class spacemod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class typemod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class type_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class sizemod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class wordsizemod_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class varnodedef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class bitrangedef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class bitranges_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class bitrange_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pcodeopdef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class valueattach_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class nameattach_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class varattach_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class identifierlist_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class stringoridentlist_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class stringorident_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class intblist_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class intbpart_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class neginteger_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constructorlike_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class macrodef_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class arguments_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class oplist_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class withblock_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class id_or_nil_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class bitpat_or_nil_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class def_or_conslike_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constructorlikelist_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constructor_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctorsemantic_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class bitpattern_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctorstart_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class contextblock_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctxstmts_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctxstmt_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctxassign_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class ctxlval_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pfuncall_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_or_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_or_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_seq_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_seq_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_and_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_and_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_ellipsis_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_ellipsis_right_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pequation_atomic_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constraint_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class constraint_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_or_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_or_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_xor_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_xor_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_and_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_and_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_shift_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_shift_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_add_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_add_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_mult_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_mult_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_unary_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_unary_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_func_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_apply_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_operands_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression_term_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_or_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_or_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_xor_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_xor_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_and_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_and_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_shift_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_shift_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_add_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_add_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_mult_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_mult_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_unary_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_unary_op_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_func_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_apply_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_operands_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pexpression2_term_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class qstring_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class id_or_wild_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class wildcard_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class identifier_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class key_as_id_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class strict_id_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class integer_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    tokenNames: typing.Final[jpype.JArray[java.lang.String]]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gDisplayParser: SleighParser_DisplayParser
    gSemanticParser: SleighParser_SemanticParser
    FOLLOW_endiandef_in_spec78: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_definition_in_spec84: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlike_in_spec90: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EOF_in_spec97: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_endiandef110: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ENDIAN_in_endiandef112: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_endiandef114: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_endiandef116: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_endiandef118: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BIG_in_endian140: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LITTLE_in_endian152: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_aligndef_in_definition169: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_tokendef_in_definition174: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextdef_in_definition179: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacedef_in_definition184: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnodedef_in_definition189: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrangedef_in_definition194: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pcodeopdef_in_definition199: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valueattach_in_definition204: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_nameattach_in_definition209: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varattach_in_definition214: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_definition217: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_aligndef231: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ALIGNMENT_in_aligndef233: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_aligndef235: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_aligndef237: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_tokendef259: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_TOKEN_in_tokendef261: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_tokendef263: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_tokendef265: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef267: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_tokendef271: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef273: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_tokendef296: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_TOKEN_in_tokendef298: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_tokendef300: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_tokendef302: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef304: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_tokendef306: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ENDIAN_in_tokendef310: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_tokendef312: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_tokendef314: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef316: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddef_in_fielddefs344: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_strict_id_in_fielddef366: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_fielddef370: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_fielddef372: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef376: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_fielddef378: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef382: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_fielddef386: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmods_in_fielddef388: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmod_in_fieldmods418: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIGNED_in_fieldmod455: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_HEX_in_fieldmod472: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEC_in_fieldmod489: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextfielddef_in_contextfielddefs509: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_contextfielddef531: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_contextfielddef535: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_contextfielddef537: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_contextfielddef541: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_contextfielddef543: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_contextfielddef547: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_contextfielddef551: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextfieldmods_in_contextfielddef553: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextfieldmod_in_contextfieldmods588: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIGNED_in_contextfieldmod633: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_NOFLOW_in_contextfieldmod650: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_HEX_in_contextfieldmod667: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEC_in_contextfieldmod684: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_contextdef705: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CONTEXT_in_contextdef709: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_contextdef711: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextfielddefs_in_contextdef713: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_spacedef738: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SPACE_in_spacedef740: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_spacedef742: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemods_in_spacedef744: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemod_in_spacemods768: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_typemod_in_spacemod790: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizemod_in_spacemod795: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_wordsizemod_in_spacemod800: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFAULT_in_spacemod807: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_TYPE_in_typemod825: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_typemod827: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_type_in_typemod829: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_type849: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIZE_in_sizemod862: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_sizemod864: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizemod866: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_WORDSIZE_in_wordsizemod888: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_wordsizemod890: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_wordsizemod892: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_varnodedef914: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_varnodedef916: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_OFFSET_in_varnodedef918: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_varnodedef920: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef924: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIZE_in_varnodedef926: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_varnodedef930: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef934: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varnodedef936: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_bitrangedef969: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BITRANGE_in_bitrangedef971: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitranges_in_bitrangedef973: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrange_in_bitranges993: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_bitrange1007: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_bitrange1011: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_bitrange1015: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_bitrange1017: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_bitrange1021: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_bitrange1023: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_bitrange1027: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_bitrange1029: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_pcodeopdef1061: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_PCODEOP_in_pcodeopdef1065: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_pcodeopdef1067: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ATTACH_in_valueattach1090: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_VALUES_in_valueattach1094: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_valueattach1096: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intblist_in_valueattach1099: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ATTACH_in_nameattach1124: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_NAMES_in_nameattach1128: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_nameattach1132: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringoridentlist_in_nameattach1137: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ATTACH_in_varattach1164: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_VARIABLES_in_varattach1168: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varattach1172: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varattach1177: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_identifierlist1203: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_id_or_wild_in_identifierlist1205: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_identifierlist1208: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_id_or_wild_in_identifierlist1223: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_stringoridentlist1244: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringorident_in_stringoridentlist1246: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_stringoridentlist1249: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringorident_in_stringoridentlist1264: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_id_or_wild_in_stringorident1284: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_qstring_in_stringorident1289: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_intblist1301: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intbpart_in_intblist1303: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_intblist1306: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_neginteger_in_intblist1321: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_neginteger_in_intbpart1341: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_UNDERSCORE_in_intbpart1348: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_neginteger1364: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_neginteger1371: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_neginteger1373: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_macrodef_in_constructorlike1393: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_withblock_in_constructorlike1398: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructor_in_constructorlike1403: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_MACRO_in_macrodef1416: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_macrodef1418: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_macrodef1422: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_arguments_in_macrodef1424: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_macrodef1427: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semanticbody_in_macrodef1429: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_oplist_in_arguments1454: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_oplist1484: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_oplist1487: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_oplist1490: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RES_WITH_in_withblock1505: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_id_or_nil_in_withblock1507: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_withblock1509: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpat_or_nil_in_withblock1511: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextblock_in_withblock1513: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACE_in_withblock1515: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlikelist_in_withblock1517: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACE_in_withblock1519: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_id_or_nil1548: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpattern_in_bitpat_or_nil1568: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_definition_in_def_or_conslike1588: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlike_in_def_or_conslike1593: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_def_or_conslike_in_constructorlikelist1604: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorstart_in_constructor1626: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpattern_in_constructor1628: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextblock_in_constructor1630: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorsemantic_in_constructor1632: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semanticbody_in_ctorsemantic1657: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_UNIMPL_in_ctorsemantic1672: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_bitpattern1693: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_ctorstart1712: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1714: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1729: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_contextblock1750: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctxstmts_in_contextblock1752: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_contextblock1754: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctxstmt_in_ctxstmts1783: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctxassign_in_ctxstmt1795: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_ctxstmt1797: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pfuncall_in_ctxstmt1803: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_ctxstmt1805: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctxlval_in_ctxassign1817: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_ctxassign1821: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_ctxassign1823: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_ctxlval1845: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_apply_in_pfuncall1856: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_or_in_pequation1867: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_seq_in_pequation_or1878: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_or_op_in_pequation_or1882: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_seq_in_pequation_or1885: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PIPE_in_pequation_or_op1901: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_and_in_pequation_seq1919: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_seq_op_in_pequation_seq1923: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_and_in_pequation_seq1926: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_pequation_seq_op1942: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_ellipsis_in_pequation_and1960: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_and_op_in_pequation_and1964: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_ellipsis_in_pequation_and1967: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_pequation_and_op1983: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ELLIPSIS_in_pequation_ellipsis2003: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2005: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis2019: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_atomic_in_pequation_ellipsis_right2037: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ELLIPSIS_in_pequation_ellipsis_right2041: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_atomic_in_pequation_ellipsis_right2055: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constraint_in_pequation_atomic2067: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_pequation_atomic2074: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation_atomic2076: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_pequation_atomic2078: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_constraint2098: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constraint_op_in_constraint2101: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_constraint2104: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_constraint_op2119: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_NOTEQUAL_in_constraint_op2133: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESS_in_constraint_op2147: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESSEQUAL_in_constraint_op2161: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREAT_in_constraint_op2175: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREATEQUAL_in_constraint_op2189: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_or_in_pexpression2207: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_xor_in_pexpression_or2218: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_or_op_in_pexpression_or2221: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_xor_in_pexpression_or2224: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PIPE_in_pexpression_or_op2239: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_OR_in_pexpression_or_op2253: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_and_in_pexpression_xor2271: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_xor_op_in_pexpression_xor2274: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_and_in_pexpression_xor2277: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_CARET_in_pexpression_xor_op2292: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_XOR_in_pexpression_xor_op2306: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_shift_in_pexpression_and2324: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_and_op_in_pexpression_and2327: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_shift_in_pexpression_and2330: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_pexpression_and_op2345: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_AND_in_pexpression_and_op2359: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_add_in_pexpression_shift2377: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_shift_op_in_pexpression_shift2380: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_add_in_pexpression_shift2383: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LEFT_in_pexpression_shift_op2398: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RIGHT_in_pexpression_shift_op2412: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_mult_in_pexpression_add2430: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_add_op_in_pexpression_add2433: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_mult_in_pexpression_add2436: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PLUS_in_pexpression_add_op2451: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_pexpression_add_op2465: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_unary_in_pexpression_mult2483: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_mult_op_in_pexpression_mult2486: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_unary_in_pexpression_mult2489: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_pexpression_mult_op2504: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLASH_in_pexpression_mult_op2518: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_unary_op_in_pexpression_unary2536: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_term_in_pexpression_unary2539: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_func_in_pexpression_unary2544: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_pexpression_unary_op2557: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_TILDE_in_pexpression_unary_op2571: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_apply_in_pexpression_func2589: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_term_in_pexpression_func2594: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression_apply2605: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_operands_in_pexpression_apply2607: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_pexpression_operands2629: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression_operands2633: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_pexpression_operands2636: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression_operands2639: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_pexpression_operands2646: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression_term2658: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_pexpression_term2663: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_pexpression_term2670: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression_in_pexpression_term2672: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_pexpression_term2674: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_or_in_pexpression22694: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_xor_in_pexpression2_or2705: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_or_op_in_pexpression2_or2708: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_xor_in_pexpression2_or2711: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_OR_in_pexpression2_or_op2726: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_and_in_pexpression2_xor2744: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_xor_op_in_pexpression2_xor2747: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_and_in_pexpression2_xor2750: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_XOR_in_pexpression2_xor_op2765: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_shift_in_pexpression2_and2783: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_and_op_in_pexpression2_and2786: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_shift_in_pexpression2_and2789: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_AND_in_pexpression2_and_op2804: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_add_in_pexpression2_shift2822: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_shift_op_in_pexpression2_shift2825: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_add_in_pexpression2_shift2828: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LEFT_in_pexpression2_shift_op2843: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RIGHT_in_pexpression2_shift_op2857: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_mult_in_pexpression2_add2875: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_add_op_in_pexpression2_add2878: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_mult_in_pexpression2_add2881: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PLUS_in_pexpression2_add_op2896: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_pexpression2_add_op2910: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_unary_in_pexpression2_mult2928: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_mult_op_in_pexpression2_mult2931: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_unary_in_pexpression2_mult2934: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_pexpression2_mult_op2949: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLASH_in_pexpression2_mult_op2963: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_unary_op_in_pexpression2_unary2981: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_term_in_pexpression2_unary2984: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_func_in_pexpression2_unary2989: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_pexpression2_unary_op3002: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_TILDE_in_pexpression2_unary_op3016: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_apply_in_pexpression2_func3034: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_term_in_pexpression2_func3039: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression2_apply3050: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_operands_in_pexpression2_apply3052: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_pexpression2_operands3074: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression2_operands3078: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_pexpression2_operands3081: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression2_operands3084: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_pexpression2_operands3091: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression2_term3103: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_pexpression2_term3108: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_pexpression2_term3115: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression2_term3117: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_pexpression2_term3119: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_QSTRING_in_qstring3141: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_id_or_wild3161: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_wildcard_in_id_or_wild3166: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_UNDERSCORE_in_wildcard3179: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_strict_id_in_identifier3196: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_key_as_id_in_identifier3201: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ALIGNMENT_in_key_as_id3214: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ATTACH_in_key_as_id3230: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BIG_in_key_as_id3247: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BITRANGE_in_key_as_id3265: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_BUILD_in_key_as_id3282: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CALL_in_key_as_id3299: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CONTEXT_in_key_as_id3318: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_CROSSBUILD_in_key_as_id3335: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEC_in_key_as_id3351: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFAULT_in_key_as_id3370: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINE_in_key_as_id3387: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_ENDIAN_in_key_as_id3404: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_EXPORT_in_key_as_id3421: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_GOTO_in_key_as_id3438: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_HEX_in_key_as_id3456: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LITTLE_in_key_as_id3474: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_LOCAL_in_key_as_id3491: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_MACRO_in_key_as_id3508: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_NAMES_in_key_as_id3525: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_NOFLOW_in_key_as_id3542: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_OFFSET_in_key_as_id3559: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_PCODEOP_in_key_as_id3576: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_RETURN_in_key_as_id3593: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIGNED_in_key_as_id3610: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SIZE_in_key_as_id3627: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_SPACE_in_key_as_id3645: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_TOKEN_in_key_as_id3662: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_TYPE_in_key_as_id3679: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_UNIMPL_in_key_as_id3697: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_VALUES_in_key_as_id3714: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_VARIABLES_in_key_as_id3731: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_WORDSIZE_in_key_as_id3747: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_IDENTIFIER_in_strict_id3770: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_HEX_INT_in_integer3793: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_DEC_INT_in_integer3809: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BIN_INT_in_integer3825: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_atomic_in_synpred1_SleighParser2031: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ELLIPSIS_in_synpred1_SleighParser2033: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def add_op(self) -> SleighParser_SemanticParser.add_op_return:
        ...

    def aligndef(self) -> SleighParser.aligndef_return:
        ...

    def arguments(self, lc: org.antlr.runtime.Token) -> SleighParser.arguments_return:
        ...

    def assignment(self) -> SleighParser_SemanticParser.assignment_return:
        ...

    def bitpat_or_nil(self) -> SleighParser.bitpat_or_nil_return:
        ...

    def bitpattern(self) -> SleighParser.bitpattern_return:
        ...

    def bitrange(self) -> SleighParser.bitrange_return:
        ...

    def bitrangedef(self) -> SleighParser.bitrangedef_return:
        ...

    def bitranges(self) -> SleighParser.bitranges_return:
        ...

    def booland_op(self) -> SleighParser_SemanticParser.booland_op_return:
        ...

    def build_stmt(self) -> SleighParser_SemanticParser.build_stmt_return:
        ...

    def call_stmt(self) -> SleighParser_SemanticParser.call_stmt_return:
        ...

    def code_block(self) -> SleighParser_SemanticParser.code_block_return:
        ...

    def compare_op(self) -> SleighParser_SemanticParser.compare_op_return:
        ...

    def concatenate(self) -> SleighParser_DisplayParser.concatenate_return:
        ...

    def cond_stmt(self) -> SleighParser_SemanticParser.cond_stmt_return:
        ...

    def constant(self) -> SleighParser_SemanticParser.constant_return:
        ...

    def constraint(self) -> SleighParser.constraint_return:
        ...

    def constraint_op(self) -> SleighParser.constraint_op_return:
        ...

    def constructor(self) -> SleighParser.constructor_return:
        ...

    def constructorlike(self) -> SleighParser.constructorlike_return:
        ...

    def constructorlikelist(self) -> SleighParser.constructorlikelist_return:
        ...

    def contextblock(self) -> SleighParser.contextblock_return:
        ...

    def contextdef(self) -> SleighParser.contextdef_return:
        ...

    def contextfielddef(self) -> SleighParser.contextfielddef_return:
        ...

    def contextfielddefs(self, lc: org.antlr.runtime.Token) -> SleighParser.contextfielddefs_return:
        ...

    def contextfieldmod(self) -> SleighParser.contextfieldmod_return:
        ...

    def contextfieldmods(self, it: org.antlr.runtime.Token) -> SleighParser.contextfieldmods_return:
        ...

    def crossbuild_stmt(self) -> SleighParser_SemanticParser.crossbuild_stmt_return:
        ...

    def ctorsemantic(self) -> SleighParser.ctorsemantic_return:
        ...

    def ctorstart(self) -> SleighParser.ctorstart_return:
        ...

    def ctxassign(self) -> SleighParser.ctxassign_return:
        ...

    def ctxlval(self) -> SleighParser.ctxlval_return:
        ...

    def ctxstmt(self) -> SleighParser.ctxstmt_return:
        ...

    def ctxstmts(self) -> SleighParser.ctxstmts_return:
        ...

    def declaration(self) -> SleighParser_SemanticParser.declaration_return:
        ...

    def def_or_conslike(self) -> SleighParser.def_or_conslike_return:
        ...

    def definition(self) -> SleighParser.definition_return:
        ...

    def display(self) -> SleighParser_DisplayParser.display_return:
        ...

    def endian(self) -> SleighParser.endian_return:
        ...

    def endiandef(self) -> SleighParser.endiandef_return:
        ...

    def eq_op(self) -> SleighParser_SemanticParser.eq_op_return:
        ...

    def export(self) -> SleighParser_SemanticParser.export_return:
        ...

    def expr(self) -> SleighParser_SemanticParser.expr_return:
        ...

    def expr_add(self) -> SleighParser_SemanticParser.expr_add_return:
        ...

    def expr_and(self) -> SleighParser_SemanticParser.expr_and_return:
        ...

    def expr_and_op(self) -> SleighParser_SemanticParser.expr_and_op_return:
        ...

    def expr_apply(self) -> SleighParser_SemanticParser.expr_apply_return:
        ...

    def expr_booland(self) -> SleighParser_SemanticParser.expr_booland_return:
        ...

    def expr_boolor(self) -> SleighParser_SemanticParser.expr_boolor_return:
        ...

    def expr_boolor_op(self) -> SleighParser_SemanticParser.expr_boolor_op_return:
        ...

    def expr_comp(self) -> SleighParser_SemanticParser.expr_comp_return:
        ...

    def expr_eq(self) -> SleighParser_SemanticParser.expr_eq_return:
        ...

    def expr_func(self) -> SleighParser_SemanticParser.expr_func_return:
        ...

    def expr_mult(self) -> SleighParser_SemanticParser.expr_mult_return:
        ...

    def expr_operands(self) -> SleighParser_SemanticParser.expr_operands_return:
        ...

    def expr_or(self) -> SleighParser_SemanticParser.expr_or_return:
        ...

    def expr_or_op(self) -> SleighParser_SemanticParser.expr_or_op_return:
        ...

    def expr_shift(self) -> SleighParser_SemanticParser.expr_shift_return:
        ...

    def expr_term(self) -> SleighParser_SemanticParser.expr_term_return:
        ...

    def expr_unary(self) -> SleighParser_SemanticParser.expr_unary_return:
        ...

    def expr_xor(self) -> SleighParser_SemanticParser.expr_xor_return:
        ...

    def expr_xor_op(self) -> SleighParser_SemanticParser.expr_xor_op_return:
        ...

    def fielddef(self) -> SleighParser.fielddef_return:
        ...

    def fielddefs(self, lc: org.antlr.runtime.Token) -> SleighParser.fielddefs_return:
        ...

    def fieldmod(self) -> SleighParser.fieldmod_return:
        ...

    def fieldmods(self, it: org.antlr.runtime.Token) -> SleighParser.fieldmods_return:
        ...

    def funcall(self) -> SleighParser_SemanticParser.funcall_return:
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...

    def getTreeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    def goto_stmt(self) -> SleighParser_SemanticParser.goto_stmt_return:
        ...

    def id_or_nil(self) -> SleighParser.id_or_nil_return:
        ...

    def id_or_wild(self) -> SleighParser.id_or_wild_return:
        ...

    def identifier(self) -> SleighParser.identifier_return:
        ...

    def identifierlist(self, lc: org.antlr.runtime.Token) -> SleighParser.identifierlist_return:
        ...

    def intblist(self, lc: org.antlr.runtime.Token) -> SleighParser.intblist_return:
        ...

    def intbpart(self) -> SleighParser.intbpart_return:
        ...

    def integer(self) -> SleighParser.integer_return:
        ...

    def jumpdest(self) -> SleighParser_SemanticParser.jumpdest_return:
        ...

    def key_as_id(self) -> SleighParser.key_as_id_return:
        ...

    def label(self) -> SleighParser_SemanticParser.label_return:
        ...

    def lvalue(self) -> SleighParser_SemanticParser.lvalue_return:
        ...

    def macrodef(self) -> SleighParser.macrodef_return:
        ...

    def mult_op(self) -> SleighParser_SemanticParser.mult_op_return:
        ...

    def nameattach(self) -> SleighParser.nameattach_return:
        ...

    def neginteger(self) -> SleighParser.neginteger_return:
        ...

    def oplist(self) -> SleighParser.oplist_return:
        ...

    def outererror(self) -> SleighParser_SemanticParser.outererror_return:
        ...

    def pcodeopdef(self) -> SleighParser.pcodeopdef_return:
        ...

    def pequation(self) -> SleighParser.pequation_return:
        ...

    def pequation_and(self) -> SleighParser.pequation_and_return:
        ...

    def pequation_and_op(self) -> SleighParser.pequation_and_op_return:
        ...

    def pequation_atomic(self) -> SleighParser.pequation_atomic_return:
        ...

    def pequation_ellipsis(self) -> SleighParser.pequation_ellipsis_return:
        ...

    def pequation_ellipsis_right(self) -> SleighParser.pequation_ellipsis_right_return:
        ...

    def pequation_or(self) -> SleighParser.pequation_or_return:
        ...

    def pequation_or_op(self) -> SleighParser.pequation_or_op_return:
        ...

    def pequation_seq(self) -> SleighParser.pequation_seq_return:
        ...

    def pequation_seq_op(self) -> SleighParser.pequation_seq_op_return:
        ...

    def pexpression(self) -> SleighParser.pexpression_return:
        ...

    def pexpression2(self) -> SleighParser.pexpression2_return:
        ...

    def pexpression2_add(self) -> SleighParser.pexpression2_add_return:
        ...

    def pexpression2_add_op(self) -> SleighParser.pexpression2_add_op_return:
        ...

    def pexpression2_and(self) -> SleighParser.pexpression2_and_return:
        ...

    def pexpression2_and_op(self) -> SleighParser.pexpression2_and_op_return:
        ...

    def pexpression2_apply(self) -> SleighParser.pexpression2_apply_return:
        ...

    def pexpression2_func(self) -> SleighParser.pexpression2_func_return:
        ...

    def pexpression2_mult(self) -> SleighParser.pexpression2_mult_return:
        ...

    def pexpression2_mult_op(self) -> SleighParser.pexpression2_mult_op_return:
        ...

    def pexpression2_operands(self) -> SleighParser.pexpression2_operands_return:
        ...

    def pexpression2_or(self) -> SleighParser.pexpression2_or_return:
        ...

    def pexpression2_or_op(self) -> SleighParser.pexpression2_or_op_return:
        ...

    def pexpression2_shift(self) -> SleighParser.pexpression2_shift_return:
        ...

    def pexpression2_shift_op(self) -> SleighParser.pexpression2_shift_op_return:
        ...

    def pexpression2_term(self) -> SleighParser.pexpression2_term_return:
        ...

    def pexpression2_unary(self) -> SleighParser.pexpression2_unary_return:
        ...

    def pexpression2_unary_op(self) -> SleighParser.pexpression2_unary_op_return:
        ...

    def pexpression2_xor(self) -> SleighParser.pexpression2_xor_return:
        ...

    def pexpression2_xor_op(self) -> SleighParser.pexpression2_xor_op_return:
        ...

    def pexpression_add(self) -> SleighParser.pexpression_add_return:
        ...

    def pexpression_add_op(self) -> SleighParser.pexpression_add_op_return:
        ...

    def pexpression_and(self) -> SleighParser.pexpression_and_return:
        ...

    def pexpression_and_op(self) -> SleighParser.pexpression_and_op_return:
        ...

    def pexpression_apply(self) -> SleighParser.pexpression_apply_return:
        ...

    def pexpression_func(self) -> SleighParser.pexpression_func_return:
        ...

    def pexpression_mult(self) -> SleighParser.pexpression_mult_return:
        ...

    def pexpression_mult_op(self) -> SleighParser.pexpression_mult_op_return:
        ...

    def pexpression_operands(self) -> SleighParser.pexpression_operands_return:
        ...

    def pexpression_or(self) -> SleighParser.pexpression_or_return:
        ...

    def pexpression_or_op(self) -> SleighParser.pexpression_or_op_return:
        ...

    def pexpression_shift(self) -> SleighParser.pexpression_shift_return:
        ...

    def pexpression_shift_op(self) -> SleighParser.pexpression_shift_op_return:
        ...

    def pexpression_term(self) -> SleighParser.pexpression_term_return:
        ...

    def pexpression_unary(self) -> SleighParser.pexpression_unary_return:
        ...

    def pexpression_unary_op(self) -> SleighParser.pexpression_unary_op_return:
        ...

    def pexpression_xor(self) -> SleighParser.pexpression_xor_return:
        ...

    def pexpression_xor_op(self) -> SleighParser.pexpression_xor_op_return:
        ...

    def pfuncall(self) -> SleighParser.pfuncall_return:
        ...

    def pieces(self) -> SleighParser_DisplayParser.pieces_return:
        ...

    def printpiece(self) -> SleighParser_DisplayParser.printpiece_return:
        ...

    def qstring(self) -> SleighParser.qstring_return:
        ...

    def return_stmt(self) -> SleighParser_SemanticParser.return_stmt_return:
        ...

    def section_def(self) -> SleighParser_SemanticParser.section_def_return:
        ...

    def semantic(self) -> SleighParser_SemanticParser.semantic_return:
        ...

    def semanticbody(self) -> SleighParser_SemanticParser.semanticbody_return:
        ...

    def sembitrange(self) -> SleighParser_SemanticParser.sembitrange_return:
        ...

    def setTreeAdaptor(self, adaptor: org.antlr.runtime.tree.TreeAdaptor):
        ...

    def shift_op(self) -> SleighParser_SemanticParser.shift_op_return:
        ...

    def sizedexport(self) -> SleighParser_SemanticParser.sizedexport_return:
        ...

    def sizedstar(self) -> SleighParser_SemanticParser.sizedstar_return:
        ...

    def sizemod(self) -> SleighParser.sizemod_return:
        ...

    def spacedef(self) -> SleighParser.spacedef_return:
        ...

    def spacemod(self) -> SleighParser.spacemod_return:
        ...

    def spacemods(self, lc: org.antlr.runtime.Token) -> SleighParser.spacemods_return:
        ...

    def spec(self) -> SleighParser.spec_return:
        ...

    def special(self) -> SleighParser_DisplayParser.special_return:
        ...

    def statement(self) -> SleighParser_SemanticParser.statement_return:
        ...

    def statements(self) -> SleighParser_SemanticParser.statements_return:
        ...

    def strict_id(self) -> SleighParser.strict_id_return:
        ...

    def stringorident(self) -> SleighParser.stringorident_return:
        ...

    def stringoridentlist(self, lc: org.antlr.runtime.Token) -> SleighParser.stringoridentlist_return:
        ...

    def synpred1_SleighParser(self) -> bool:
        ...

    def synpred1_SleighParser_fragment(self):
        ...

    def tokendef(self) -> SleighParser.tokendef_return:
        ...

    def type(self) -> SleighParser.type_return:
        ...

    def typemod(self) -> SleighParser.typemod_return:
        ...

    def unary_op(self) -> SleighParser_SemanticParser.unary_op_return:
        ...

    def valueattach(self) -> SleighParser.valueattach_return:
        ...

    def varattach(self) -> SleighParser.varattach_return:
        ...

    def varnode(self) -> SleighParser_SemanticParser.varnode_return:
        ...

    def varnodedef(self) -> SleighParser.varnodedef_return:
        ...

    def whitespace(self) -> SleighParser_DisplayParser.whitespace_return:
        ...

    def wildcard(self) -> SleighParser.wildcard_return:
        ...

    def withblock(self) -> SleighParser.withblock_return:
        ...

    def wordsizemod(self) -> SleighParser.wordsizemod_return:
        ...

    @property
    def treeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    @treeAdaptor.setter
    def treeAdaptor(self, value: org.antlr.runtime.tree.TreeAdaptor):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...


class BooleanExpressionParser(org.antlr.runtime.Parser):

    class_: typing.ClassVar[java.lang.Class]
    tokenNames: typing.Final[jpype.JArray[java.lang.String]]
    EOF: typing.Final = -1
    T__20: typing.Final = 20
    T__21: typing.Final = 21
    ALPHA: typing.Final = 4
    DIGIT: typing.Final = 5
    ESCAPE: typing.Final = 6
    HEXDIGIT: typing.Final = 7
    IDENTIFIER: typing.Final = 8
    KEY_DEFINED: typing.Final = 9
    OCTAL_ESCAPE: typing.Final = 10
    OP_AND: typing.Final = 11
    OP_EQ: typing.Final = 12
    OP_NEQ: typing.Final = 13
    OP_NOT: typing.Final = 14
    OP_OR: typing.Final = 15
    OP_XOR: typing.Final = 16
    QSTRING: typing.Final = 17
    UNICODE_ESCAPE: typing.Final = 18
    WS: typing.Final = 19
    env: ExpressionEnvironment
    FOLLOW_expr_in_expression85: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EOF_in_expression87: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_or_in_expr106: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_xor_in_expr_or125: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_expr_or130: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_xor_in_expr_or134: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_and_in_expr_xor155: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_expr_xor160: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_and_in_expr_xor164: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_not_in_expr_and185: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_expr_and190: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_not_in_expr_and194: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOT_in_expr_not213: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_paren_in_expr_not217: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_paren_in_expr_not226: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_eq_in_expr_not242: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_KEY_DEFINED_in_expr_not259: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_20_in_expr_not261: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_IDENTIFIER_in_expr_not265: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_21_in_expr_not267: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_20_in_expr_paren284: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_paren288: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_21_in_expr_paren290: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_term_in_expr_eq309: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EQ_in_expr_eq311: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_term_in_expr_eq315: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_term_in_expr_eq325: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEQ_in_expr_eq327: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_term_in_expr_eq331: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_IDENTIFIER_in_expr_term350: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_QSTRING_in_expr_term359: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def expr(self) -> bool:
        ...

    def expr_and(self) -> bool:
        ...

    def expr_eq(self) -> bool:
        ...

    def expr_not(self) -> bool:
        ...

    def expr_or(self) -> bool:
        ...

    def expr_paren(self) -> bool:
        ...

    def expr_term(self) -> str:
        ...

    def expr_xor(self) -> bool:
        ...

    def expression(self) -> bool:
        ...

    def getDelegates(self) -> jpype.JArray[org.antlr.runtime.Parser]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @property
    def delegates(self) -> jpype.JArray[org.antlr.runtime.Parser]:
        ...


class SleighEcho(org.antlr.runtime.tree.TreeParser):

    class endian_return(org.antlr.runtime.tree.TreeRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class DFA32(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    @typing.type_check_only
    class DFA34(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    tokenNames: typing.Final[jpype.JArray[java.lang.String]]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    out: java.io.PrintStream
    FOLLOW_endiandef_in_root42: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_definition_in_root48: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructorlike_in_root54: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ENDIAN_in_endiandef71: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_endiandef75: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_aligndef_in_definition106: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_tokendef_in_definition111: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextdef_in_definition116: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacedef_in_definition121: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnodedef_in_definition126: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrangedef_in_definition131: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pcodeopdef_in_definition136: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_valueattach_in_definition141: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_nameattach_in_definition146: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varattach_in_definition151: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ALIGNMENT_in_aligndef166: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_aligndef170: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TOKEN_in_tokendef185: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_tokendef189: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef193: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef197: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TOKEN_ENDIAN_in_tokendef206: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_tokendef210: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_tokendef214: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_endian_in_tokendef218: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_tokendef222: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELDDEFS_in_fielddefs235: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddef_in_fielddefs237: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELDDEF_in_fielddef253: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_fielddef257: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef261: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_fielddef265: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmods_in_fielddef269: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FIELD_MODS_in_fieldmods294: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fieldmod_in_fieldmods301: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NO_FIELD_MOD_in_fieldmods318: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIGNED_in_fieldmod343: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOFLOW_in_fieldmod355: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_HEX_in_fieldmod367: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEC_in_fieldmod379: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONTEXT_in_contextdef396: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_contextdef400: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_fielddefs_in_contextdef404: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SPACE_in_spacedef417: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_spacedef421: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemods_in_spacedef425: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SPACEMODS_in_spacemods449: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_spacemod_in_spacemods454: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_typemod_in_spacemod476: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizemod_in_spacemod485: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_wordsizemod_in_spacemod494: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEFAULT_in_spacemod501: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TYPE_in_typemod519: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_type_in_typemod523: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_type543: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIZE_in_sizemod561: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sizemod565: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WORDSIZE_in_wordsizemod584: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_wordsizemod588: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VARNODE_in_varnodedef603: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_varnodedef607: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef611: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_varnodedef615: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varnodedef619: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist638: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_identifierlist645: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist669: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringorident_in_stringoridentlist676: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_stringorident701: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_qstring_in_stringorident710: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGES_in_bitrangedef724: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitranges_in_bitrangedef728: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sbitrange_in_bitranges748: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE_in_sbitrange769: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sbitrange773: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_sbitrange777: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sbitrange781: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_sbitrange785: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODEOP_in_pcodeopdef800: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_pcodeopdef804: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VALUES_in_valueattach819: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_valueattach823: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intblist_in_valueattach827: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INTBLIST_in_intblist846: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_intbpart_in_intblist853: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_intbpart876: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_intbpart884: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_intbpart888: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_intbpart898: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NAMES_in_nameattach912: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_nameattach916: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_stringoridentlist_in_nameattach920: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_VARIABLES_in_varattach935: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varattach939: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifierlist_in_varattach943: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_macrodef_in_constructorlike957: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constructor_in_constructorlike962: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MACRO_in_macrodef974: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_macrodef978: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_arguments_in_macrodef982: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semantic_in_macrodef986: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ARGUMENTS_in_arguments1003: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_oplist_in_arguments1007: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EMPTY_LIST_in_arguments1015: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_oplist1040: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONSTRUCTOR_in_constructor1056: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorstart_in_constructor1060: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitpattern_in_constructor1064: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_contextblock_in_constructor1068: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ctorsemantic_in_constructor1070: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODE_in_ctorsemantic1083: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_semantic_in_ctorsemantic1085: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PCODE_in_ctorsemantic1092: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_UNIMPL_in_ctorsemantic1094: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BIT_PATTERN_in_bitpattern1113: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_bitpattern1117: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUBTABLE_in_ctorstart1136: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_ctorstart1140: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1144: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TABLE_in_ctorstart1153: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_display_in_ctorstart1157: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DISPLAY_in_display1176: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pieces_in_display1180: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_printpiece_in_pieces1206: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_printpiece1227: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_whitespace_in_printpiece1236: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONCATENATE_in_printpiece1243: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_string_in_printpiece1252: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WHITESPACE_in_whitespace1270: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_STRING_in_string1293: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_QSTRING_in_string1306: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_OR_in_pequation1329: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1333: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1337: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SEQUENCE_in_pequation1346: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1350: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1354: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_AND_in_pequation1363: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1367: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1371: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ELLIPSIS_in_pequation1381: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1385: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1394: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1398: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EQUAL_in_pequation1408: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1412: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1416: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOTEQUAL_in_pequation1425: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1429: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1433: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESS_in_pequation1442: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1446: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1450: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESSEQUAL_in_pequation1459: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1463: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1467: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREAT_in_pequation1476: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1480: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1484: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREATEQUAL_in_pequation1493: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1497: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pequation1501: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pequation1512: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_pequation1520: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pequation_in_pequation1524: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_pexpression21544: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21548: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21552: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_pexpression21561: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21565: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21569: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_pexpression21578: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21582: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21586: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LEFT_in_pexpression21595: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21599: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21603: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RIGHT_in_pexpression21612: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21616: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21620: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADD_in_pexpression21629: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21633: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21637: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUB_in_pexpression21646: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21650: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21654: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MULT_in_pexpression21663: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21667: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21671: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DIV_in_pexpression21680: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21684: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21688: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_pexpression21698: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21702: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INVERT_in_pexpression21711: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21715: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_APPLY_in_pexpression21725: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression21729: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_operands_in_pexpression21733: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_pexpression21743: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_pexpression21752: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_pexpression21760: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression21764: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pexpression2_in_pexpression2_operands1790: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CONTEXT_BLOCK_in_contextblock1806: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statements_in_contextblock1810: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock1818: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SEMANTIC_in_semantic1830: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_code_block_in_semantic1834: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statements_in_code_block1849: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOP_in_code_block1854: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_statement_in_statements1869: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LABEL_in_label1887: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_label1891: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SECTION_LABEL_in_section_label1910: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_section_label1914: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_assignment_in_statement1928: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_declaration_in_statement1933: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_funcall_in_statement1938: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_build_stmt_in_statement1943: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_crossbuild_stmt_in_statement1948: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_goto_stmt_in_statement1953: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_cond_stmt_in_statement1958: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_call_stmt_in_statement1963: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_export_in_statement1968: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_return_stmt_in_statement1973: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_statement1980: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_section_label_in_statement1989: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment2003: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_lvalue_in_assignment2007: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment2011: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_assignment2020: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ASSIGN_in_assignment2022: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_lvalue_in_assignment2026: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_assignment2030: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_declaration2045: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_declaration2049: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_declaration2053: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LOCAL_in_declaration2062: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_declaration2066: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrange_in_lvalue2097: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DECLARATIVE_SIZE_in_lvalue2105: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_lvalue2109: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_lvalue2113: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_lvalue2123: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_lvalue2132: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE_in_bitrange2150: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_bitrange2154: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_bitrange2158: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_bitrange2162: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar2181: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_sizedstar2185: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sizedstar2189: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar2193: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar2202: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_sizedstar2206: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar2210: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar2219: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_sizedstar2223: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar2227: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEREFERENCE_in_sizedstar2236: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_sizedstar2240: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_funcall2256: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BUILD_in_build_stmt2270: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_build_stmt2274: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt2289: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_crossbuild_stmt2293: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_crossbuild_stmt2297: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GOTO_in_goto_stmt2312: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_goto_stmt2316: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest2335: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_jumpdest2339: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest2348: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_jumpdest2352: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest2361: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_jumpdest2365: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest2374: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_jumpdest2378: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_variable_in_jumpdest2382: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest2391: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_label_in_jumpdest2395: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IF_in_cond_stmt2410: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_cond_stmt2414: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_goto_stmt_in_cond_stmt2418: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_CALL_in_call_stmt2431: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_jumpdest_in_call_stmt2435: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RETURN_in_return_stmt2450: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_return_stmt2454: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RETURN_in_return_stmt2462: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EXPORT_in_export2476: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_export2480: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_OR_in_expr2499: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2503: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2507: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_XOR_in_expr2516: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2520: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2524: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BOOL_AND_in_expr2533: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2537: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2541: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_OR_in_expr2551: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2555: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2559: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_XOR_in_expr2568: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2572: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2576: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_AND_in_expr2585: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2589: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2593: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_EQUAL_in_expr2603: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2607: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2611: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOTEQUAL_in_expr2620: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2624: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2628: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FEQUAL_in_expr2637: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2641: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2645: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FNOTEQUAL_in_expr2654: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2658: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2662: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESS_in_expr2672: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2676: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2680: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREATEQUAL_in_expr2689: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2693: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2697: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LESSEQUAL_in_expr2706: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2710: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2714: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_GREAT_in_expr2723: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2727: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2731: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SLESS_in_expr2740: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2744: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2748: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SGREATEQUAL_in_expr2757: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2761: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2765: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SLESSEQUAL_in_expr2774: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2778: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2782: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SGREAT_in_expr2791: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2795: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2799: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FLESS_in_expr2808: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2812: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2816: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FGREATEQUAL_in_expr2825: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2829: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2833: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FLESSEQUAL_in_expr2842: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2846: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2850: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FGREAT_in_expr2859: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2863: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2867: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_LEFT_in_expr2877: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2881: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2885: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_RIGHT_in_expr2894: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2898: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2902: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SRIGHT_in_expr2911: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2915: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2919: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADD_in_expr2929: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2933: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2937: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SUB_in_expr2946: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2950: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2954: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FADD_in_expr2963: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2967: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2971: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FSUB_in_expr2980: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2984: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr2988: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_MULT_in_expr2998: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3002: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3006: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DIV_in_expr3016: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3020: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3024: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_REM_in_expr3033: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3037: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3041: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SDIV_in_expr3050: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3054: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3058: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SREM_in_expr3067: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3071: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3075: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FMULT_in_expr3084: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3088: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3092: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FDIV_in_expr3101: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3105: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3109: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NOT_in_expr3119: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3123: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_INVERT_in_expr3132: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3136: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_NEGATE_in_expr3145: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3149: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_FNEGATE_in_expr3158: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3162: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_sizedstar_in_expr3172: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_apply_in_expr3182: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_expr3191: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_bitrange_in_expr3200: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_PARENTHESIZED_in_expr3208: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr3212: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BITRANGE2_in_expr3221: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_expr3225: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_expr3229: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_APPLY_in_expr_apply3248: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_expr_apply3252: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_operands_in_expr_apply3256: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_expr_in_expr_operands3283: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_symbol_in_varnode3304: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_TRUNCATION_SIZE_in_varnode3312: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_symbol_in_varnode3316: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_varnode3320: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADDRESS_OF_in_varnode3329: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_SIZING_SIZE_in_varnode3332: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_constant_in_varnode3336: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode3341: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_ADDRESS_OF_in_varnode3350: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_varnode_in_varnode3354: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_symbol3374: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_symbol3383: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_variable3402: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_integer_in_constant3421: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_QSTRING_in_qstring3439: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_IDENTIFIER_in_identifier3462: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_WILDCARD_in_identifier3474: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_HEX_CONSTANT_in_integer3492: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_DEC_CONSTANT_in_integer3505: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_OP_BIN_CONSTANT_in_integer3518: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.tree.TreeNodeStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.tree.TreeNodeStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def aligndef(self):
        ...

    def arguments(self) -> str:
        ...

    def assignment(self):
        ...

    def bitpattern(self) -> str:
        ...

    def bitrange(self) -> str:
        ...

    def bitrangedef(self):
        ...

    def bitranges(self):
        ...

    def build_stmt(self):
        ...

    def call_stmt(self):
        ...

    def code_block(self):
        ...

    def cond_stmt(self):
        ...

    def constant(self) -> str:
        ...

    def constructor(self):
        ...

    def constructorlike(self):
        ...

    def contextblock(self):
        ...

    def contextdef(self):
        ...

    def crossbuild_stmt(self):
        ...

    def ctorsemantic(self):
        ...

    def ctorstart(self) -> str:
        ...

    def declaration(self):
        ...

    def definition(self):
        ...

    def display(self) -> str:
        ...

    def endian(self) -> SleighEcho.endian_return:
        ...

    def endiandef(self):
        ...

    def export(self):
        ...

    def expr(self) -> str:
        ...

    def expr_apply(self) -> str:
        ...

    def expr_operands(self) -> str:
        ...

    def fielddef(self):
        ...

    def fielddefs(self):
        ...

    def fieldmod(self) -> str:
        ...

    def fieldmods(self) -> str:
        ...

    def funcall(self):
        ...

    def getDelegates(self) -> jpype.JArray[org.antlr.runtime.tree.TreeParser]:
        ...

    def goto_stmt(self):
        ...

    def identifier(self) -> str:
        ...

    def identifierlist(self) -> str:
        ...

    def intblist(self) -> str:
        ...

    def intbpart(self) -> str:
        ...

    def integer(self) -> str:
        ...

    def jumpdest(self) -> str:
        ...

    def label(self) -> str:
        ...

    def lvalue(self) -> str:
        ...

    def macrodef(self):
        ...

    def nameattach(self):
        ...

    def oplist(self) -> str:
        ...

    def pcodeopdef(self):
        ...

    def pequation(self) -> str:
        ...

    def pexpression2(self) -> str:
        ...

    def pexpression2_operands(self) -> str:
        ...

    def pieces(self) -> str:
        ...

    def printpiece(self) -> str:
        ...

    def qstring(self) -> str:
        ...

    def return_stmt(self):
        ...

    def root(self):
        ...

    def sbitrange(self) -> str:
        ...

    def section_label(self) -> str:
        ...

    def semantic(self):
        ...

    def sizedstar(self) -> str:
        ...

    def sizemod(self) -> str:
        ...

    def spacedef(self):
        ...

    def spacemod(self) -> str:
        ...

    def spacemods(self) -> str:
        ...

    def statement(self):
        ...

    def statements(self):
        ...

    def string(self) -> str:
        ...

    def stringorident(self) -> str:
        ...

    def stringoridentlist(self) -> str:
        ...

    def symbol(self) -> str:
        ...

    def tokendef(self):
        ...

    def type(self) -> str:
        ...

    def typemod(self) -> str:
        ...

    def valueattach(self):
        ...

    def varattach(self):
        ...

    def variable(self) -> str:
        ...

    def varnode(self) -> str:
        ...

    def varnodedef(self):
        ...

    def whitespace(self) -> str:
        ...

    def wordsizemod(self) -> str:
        ...

    @property
    def delegates(self) -> jpype.JArray[org.antlr.runtime.tree.TreeParser]:
        ...


class SleighParser_DisplayParser(AbstractSleighParser):

    class display_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class pieces_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class printpiece_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class whitespace_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class concatenate_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class special_return(org.antlr.runtime.ParserRuleReturnScope):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gSleighParser: SleighParser
    gParent: SleighParser
    FOLLOW_COLON_in_display32: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_pieces_in_display34: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RES_IS_in_display36: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_printpiece_in_pieces57: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_identifier_in_printpiece69: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_whitespace_in_printpiece74: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_concatenate_in_printpiece79: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_qstring_in_printpiece84: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_special_in_printpiece89: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_WS_in_whitespace102: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_CARET_in_concatenate126: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_DISPCHAR_in_special168: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LINECOMMENT_in_special186: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACE_in_special204: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACE_in_special222: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LBRACKET_in_special240: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RBRACKET_in_special258: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LPAREN_in_special276: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RPAREN_in_special294: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ELLIPSIS_in_special312: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EQUAL_in_special330: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_NOTEQUAL_in_special348: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESS_in_special366: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREAT_in_special385: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LESSEQUAL_in_special403: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_GREATEQUAL_in_special420: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASSIGN_in_special437: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COLON_in_special455: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_COMMA_in_special473: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_ASTERISK_in_special491: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_OR_in_special509: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_XOR_in_special527: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BOOL_AND_in_special545: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PIPE_in_special563: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_AMPERSAND_in_special582: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_LEFT_in_special599: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_RIGHT_in_special618: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PLUS_in_special636: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_MINUS_in_special655: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SLASH_in_special673: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_PERCENT_in_special691: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_EXCLAIM_in_special709: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_TILDE_in_special727: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SEMI_in_special745: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_OR_in_special764: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_AND_in_special782: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_SPEC_XOR_in_special800: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_DEC_INT_in_special818: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_HEX_INT_in_special836: typing.Final[org.antlr.runtime.BitSet]
    FOLLOW_BIN_INT_in_special854: typing.Final[org.antlr.runtime.BitSet]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, gSleighParser: SleighParser):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, state: org.antlr.runtime.RecognizerSharedState, gSleighParser: SleighParser):
        ...

    def concatenate(self) -> SleighParser_DisplayParser.concatenate_return:
        ...

    def display(self) -> SleighParser_DisplayParser.display_return:
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...

    def getTreeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    def pieces(self) -> SleighParser_DisplayParser.pieces_return:
        ...

    def printpiece(self) -> SleighParser_DisplayParser.printpiece_return:
        ...

    def setTreeAdaptor(self, adaptor: org.antlr.runtime.tree.TreeAdaptor):
        ...

    def special(self) -> SleighParser_DisplayParser.special_return:
        ...

    def whitespace(self) -> SleighParser_DisplayParser.whitespace_return:
        ...

    @property
    def treeAdaptor(self) -> org.antlr.runtime.tree.TreeAdaptor:
        ...

    @treeAdaptor.setter
    def treeAdaptor(self, value: org.antlr.runtime.tree.TreeAdaptor):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighParser]:
        ...


class AbstractSleighLexer(org.antlr.runtime.Lexer, SleighRecognizerConstants):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def setEnv(self, env: ParsingEnvironment):
        ...


@typing.type_check_only
class FakeLineArrayListWriter(LineArrayListWriter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ConditionalHelper(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class BaseLexer(AbstractSleighLexer):

    @typing.type_check_only
    class DFA13(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...

    def mALPHA(self):
        ...

    def mALPHAUP(self):
        ...

    def mAMPERSAND(self):
        ...

    def mASSIGN(self):
        ...

    def mASTERISK(self):
        ...

    def mBINDIGIT(self):
        ...

    def mBIN_INT(self):
        ...

    def mBOOL_AND(self):
        ...

    def mBOOL_OR(self):
        ...

    def mBOOL_XOR(self):
        ...

    def mCARET(self):
        ...

    def mCOLON(self):
        ...

    def mCOMMA(self):
        ...

    def mCPPCOMMENT(self):
        ...

    def mDEC_INT(self):
        ...

    def mDIGIT(self):
        ...

    def mELLIPSIS(self):
        ...

    def mEOL(self):
        ...

    def mEQUAL(self):
        ...

    def mESCAPE(self):
        ...

    def mEXCLAIM(self):
        ...

    def mGREAT(self):
        ...

    def mGREATEQUAL(self):
        ...

    def mHEXDIGIT(self):
        ...

    def mHEX_INT(self):
        ...

    def mIDENTIFIER(self):
        ...

    def mKEY_ALIGNMENT(self):
        ...

    def mKEY_ATTACH(self):
        ...

    def mKEY_BIG(self):
        ...

    def mKEY_BITRANGE(self):
        ...

    def mKEY_BUILD(self):
        ...

    def mKEY_CALL(self):
        ...

    def mKEY_CONTEXT(self):
        ...

    def mKEY_CROSSBUILD(self):
        ...

    def mKEY_DEC(self):
        ...

    def mKEY_DEFAULT(self):
        ...

    def mKEY_DEFINE(self):
        ...

    def mKEY_ENDIAN(self):
        ...

    def mKEY_EXPORT(self):
        ...

    def mKEY_GOTO(self):
        ...

    def mKEY_HEX(self):
        ...

    def mKEY_LITTLE(self):
        ...

    def mKEY_LOCAL(self):
        ...

    def mKEY_MACRO(self):
        ...

    def mKEY_NAMES(self):
        ...

    def mKEY_NOFLOW(self):
        ...

    def mKEY_OFFSET(self):
        ...

    def mKEY_PCODEOP(self):
        ...

    def mKEY_RETURN(self):
        ...

    def mKEY_SIGNED(self):
        ...

    def mKEY_SIZE(self):
        ...

    def mKEY_SPACE(self):
        ...

    def mKEY_TOKEN(self):
        ...

    def mKEY_TYPE(self):
        ...

    def mKEY_UNIMPL(self):
        ...

    def mKEY_VALUES(self):
        ...

    def mKEY_VARIABLES(self):
        ...

    def mKEY_WORDSIZE(self):
        ...

    def mLBRACE(self):
        ...

    def mLBRACKET(self):
        ...

    def mLEFT(self):
        ...

    def mLESS(self):
        ...

    def mLESSEQUAL(self):
        ...

    def mLINECOMMENT(self):
        ...

    def mLPAREN(self):
        ...

    def mMINUS(self):
        ...

    def mNOTEQUAL(self):
        ...

    def mOCTAL_ESCAPE(self):
        ...

    def mPERCENT(self):
        ...

    def mPIPE(self):
        ...

    def mPLUS(self):
        ...

    def mPP_ESCAPE(self):
        ...

    def mPP_POSITION(self):
        ...

    def mQSTRING(self):
        ...

    def mRBRACE(self):
        ...

    def mRBRACKET(self):
        ...

    def mRES_WITH(self):
        ...

    def mRIGHT(self):
        ...

    def mRPAREN(self):
        ...

    def mSEMI(self):
        ...

    def mSLASH(self):
        ...

    def mSPEC_AND(self):
        ...

    def mSPEC_OR(self):
        ...

    def mSPEC_XOR(self):
        ...

    def mTILDE(self):
        ...

    def mUNDERSCORE(self):
        ...

    def mUNICODE_ESCAPE(self):
        ...

    def mUNKNOWN(self):
        ...

    def mWS(self):
        ...

    def synpred1_BaseLexer(self) -> bool:
        ...

    def synpred1_BaseLexer_fragment(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...


class DisplayLexer_BaseLexer(AbstractSleighLexer):

    @typing.type_check_only
    class DFA13(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gDisplayLexer: DisplayLexer
    gParent: DisplayLexer

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, gDisplayLexer: DisplayLexer):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState, gDisplayLexer: DisplayLexer):
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...

    def mALPHA(self):
        ...

    def mALPHAUP(self):
        ...

    def mAMPERSAND(self):
        ...

    def mASSIGN(self):
        ...

    def mASTERISK(self):
        ...

    def mBINDIGIT(self):
        ...

    def mBIN_INT(self):
        ...

    def mBOOL_AND(self):
        ...

    def mBOOL_OR(self):
        ...

    def mBOOL_XOR(self):
        ...

    def mCARET(self):
        ...

    def mCOLON(self):
        ...

    def mCOMMA(self):
        ...

    def mCPPCOMMENT(self):
        ...

    def mDEC_INT(self):
        ...

    def mDIGIT(self):
        ...

    def mELLIPSIS(self):
        ...

    def mEOL(self):
        ...

    def mEQUAL(self):
        ...

    def mESCAPE(self):
        ...

    def mEXCLAIM(self):
        ...

    def mGREAT(self):
        ...

    def mGREATEQUAL(self):
        ...

    def mHEXDIGIT(self):
        ...

    def mHEX_INT(self):
        ...

    def mIDENTIFIER(self):
        ...

    def mKEY_ALIGNMENT(self):
        ...

    def mKEY_ATTACH(self):
        ...

    def mKEY_BIG(self):
        ...

    def mKEY_BITRANGE(self):
        ...

    def mKEY_BUILD(self):
        ...

    def mKEY_CALL(self):
        ...

    def mKEY_CONTEXT(self):
        ...

    def mKEY_CROSSBUILD(self):
        ...

    def mKEY_DEC(self):
        ...

    def mKEY_DEFAULT(self):
        ...

    def mKEY_DEFINE(self):
        ...

    def mKEY_ENDIAN(self):
        ...

    def mKEY_EXPORT(self):
        ...

    def mKEY_GOTO(self):
        ...

    def mKEY_HEX(self):
        ...

    def mKEY_LITTLE(self):
        ...

    def mKEY_LOCAL(self):
        ...

    def mKEY_MACRO(self):
        ...

    def mKEY_NAMES(self):
        ...

    def mKEY_NOFLOW(self):
        ...

    def mKEY_OFFSET(self):
        ...

    def mKEY_PCODEOP(self):
        ...

    def mKEY_RETURN(self):
        ...

    def mKEY_SIGNED(self):
        ...

    def mKEY_SIZE(self):
        ...

    def mKEY_SPACE(self):
        ...

    def mKEY_TOKEN(self):
        ...

    def mKEY_TYPE(self):
        ...

    def mKEY_UNIMPL(self):
        ...

    def mKEY_VALUES(self):
        ...

    def mKEY_VARIABLES(self):
        ...

    def mKEY_WORDSIZE(self):
        ...

    def mLBRACE(self):
        ...

    def mLBRACKET(self):
        ...

    def mLEFT(self):
        ...

    def mLESS(self):
        ...

    def mLESSEQUAL(self):
        ...

    def mLPAREN(self):
        ...

    def mMINUS(self):
        ...

    def mNOTEQUAL(self):
        ...

    def mOCTAL_ESCAPE(self):
        ...

    def mPERCENT(self):
        ...

    def mPIPE(self):
        ...

    def mPLUS(self):
        ...

    def mPP_ESCAPE(self):
        ...

    def mPP_POSITION(self):
        ...

    def mQSTRING(self):
        ...

    def mRBRACE(self):
        ...

    def mRBRACKET(self):
        ...

    def mRES_WITH(self):
        ...

    def mRIGHT(self):
        ...

    def mRPAREN(self):
        ...

    def mSEMI(self):
        ...

    def mSLASH(self):
        ...

    def mSPEC_AND(self):
        ...

    def mSPEC_OR(self):
        ...

    def mSPEC_XOR(self):
        ...

    def mTILDE(self):
        ...

    def mUNDERSCORE(self):
        ...

    def mUNICODE_ESCAPE(self):
        ...

    def mUNKNOWN(self):
        ...

    def synpred1_BaseLexer(self) -> bool:
        ...

    def synpred1_BaseLexer_fragment(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...


class Locator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLocation(self, expandedLineNo: typing.Union[jpype.JInt, int]) -> Location:
        ...

    def registerLocation(self, expandedLineNo: typing.Union[jpype.JInt, int], realLocation: Location):
        ...

    @property
    def location(self) -> Location:
        ...


class LineArrayListWriter(java.io.Writer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLines(self) -> java.util.ArrayList[java.lang.String]:
        ...

    def newLine(self):
        ...

    @property
    def lines(self) -> java.util.ArrayList[java.lang.String]:
        ...


class LexerMultiplexer(org.antlr.runtime.TokenSource):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, *modes: org.antlr.runtime.TokenSource):
        ...

    def channelOff(self, channel: typing.Union[jpype.JInt, int]):
        ...

    def channelOn(self, channel: typing.Union[jpype.JInt, int]):
        ...

    def popMode(self) -> int:
        ...

    def pushMode(self, mode: typing.Union[jpype.JInt, int]):
        ...

    def setMode(self, mode: typing.Union[jpype.JInt, int]):
        ...


class TokenExtractor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class SleighLexer(LexerMultiplexer, SleighRecognizerConstants):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, input: org.antlr.runtime.CharStream):
        ...

    def setEnv(self, env: ParsingEnvironment):
        ...


class SemanticLexer_BaseLexer(AbstractSleighLexer):

    @typing.type_check_only
    class DFA13(org.antlr.runtime.DFA):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, recognizer: org.antlr.runtime.BaseRecognizer):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gSemanticLexer: SemanticLexer
    gParent: SemanticLexer

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, gSemanticLexer: SemanticLexer):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState, gSemanticLexer: SemanticLexer):
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...

    def mALPHA(self):
        ...

    def mALPHAUP(self):
        ...

    def mAMPERSAND(self):
        ...

    def mASSIGN(self):
        ...

    def mASTERISK(self):
        ...

    def mBINDIGIT(self):
        ...

    def mBIN_INT(self):
        ...

    def mBOOL_AND(self):
        ...

    def mBOOL_OR(self):
        ...

    def mBOOL_XOR(self):
        ...

    def mCARET(self):
        ...

    def mCOLON(self):
        ...

    def mCOMMA(self):
        ...

    def mCPPCOMMENT(self):
        ...

    def mDEC_INT(self):
        ...

    def mDIGIT(self):
        ...

    def mELLIPSIS(self):
        ...

    def mEOL(self):
        ...

    def mEQUAL(self):
        ...

    def mESCAPE(self):
        ...

    def mEXCLAIM(self):
        ...

    def mGREAT(self):
        ...

    def mGREATEQUAL(self):
        ...

    def mHEXDIGIT(self):
        ...

    def mHEX_INT(self):
        ...

    def mIDENTIFIER(self):
        ...

    def mKEY_ALIGNMENT(self):
        ...

    def mKEY_ATTACH(self):
        ...

    def mKEY_BIG(self):
        ...

    def mKEY_BITRANGE(self):
        ...

    def mKEY_BUILD(self):
        ...

    def mKEY_CALL(self):
        ...

    def mKEY_CONTEXT(self):
        ...

    def mKEY_CROSSBUILD(self):
        ...

    def mKEY_DEC(self):
        ...

    def mKEY_DEFAULT(self):
        ...

    def mKEY_DEFINE(self):
        ...

    def mKEY_ENDIAN(self):
        ...

    def mKEY_EXPORT(self):
        ...

    def mKEY_GOTO(self):
        ...

    def mKEY_HEX(self):
        ...

    def mKEY_LITTLE(self):
        ...

    def mKEY_LOCAL(self):
        ...

    def mKEY_MACRO(self):
        ...

    def mKEY_NAMES(self):
        ...

    def mKEY_NOFLOW(self):
        ...

    def mKEY_OFFSET(self):
        ...

    def mKEY_PCODEOP(self):
        ...

    def mKEY_RETURN(self):
        ...

    def mKEY_SIGNED(self):
        ...

    def mKEY_SIZE(self):
        ...

    def mKEY_SPACE(self):
        ...

    def mKEY_TOKEN(self):
        ...

    def mKEY_TYPE(self):
        ...

    def mKEY_UNIMPL(self):
        ...

    def mKEY_VALUES(self):
        ...

    def mKEY_VARIABLES(self):
        ...

    def mKEY_WORDSIZE(self):
        ...

    def mLBRACE(self):
        ...

    def mLBRACKET(self):
        ...

    def mLEFT(self):
        ...

    def mLESS(self):
        ...

    def mLESSEQUAL(self):
        ...

    def mLINECOMMENT(self):
        ...

    def mLPAREN(self):
        ...

    def mMINUS(self):
        ...

    def mNOTEQUAL(self):
        ...

    def mOCTAL_ESCAPE(self):
        ...

    def mPERCENT(self):
        ...

    def mPIPE(self):
        ...

    def mPLUS(self):
        ...

    def mPP_ESCAPE(self):
        ...

    def mPP_POSITION(self):
        ...

    def mQSTRING(self):
        ...

    def mRBRACE(self):
        ...

    def mRBRACKET(self):
        ...

    def mRES_WITH(self):
        ...

    def mRIGHT(self):
        ...

    def mRPAREN(self):
        ...

    def mSEMI(self):
        ...

    def mSLASH(self):
        ...

    def mSPEC_AND(self):
        ...

    def mSPEC_OR(self):
        ...

    def mSPEC_XOR(self):
        ...

    def mTILDE(self):
        ...

    def mUNDERSCORE(self):
        ...

    def mUNICODE_ESCAPE(self):
        ...

    def mUNKNOWN(self):
        ...

    def mWS(self):
        ...

    def synpred1_BaseLexer(self) -> bool:
        ...

    def synpred1_BaseLexer_fragment(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...


class SemanticLexer(AbstractSleighLexer):

    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = -1
    ALPHA: typing.Final = 4
    ALPHAUP: typing.Final = 5
    AMPERSAND: typing.Final = 6
    ASSIGN: typing.Final = 7
    ASTERISK: typing.Final = 8
    BINDIGIT: typing.Final = 9
    BIN_INT: typing.Final = 10
    BOOL_AND: typing.Final = 11
    BOOL_OR: typing.Final = 12
    BOOL_XOR: typing.Final = 13
    CARET: typing.Final = 14
    COLON: typing.Final = 15
    COMMA: typing.Final = 16
    CPPCOMMENT: typing.Final = 17
    DEC_INT: typing.Final = 18
    DIGIT: typing.Final = 19
    DISPCHAR: typing.Final = 20
    ELLIPSIS: typing.Final = 21
    EOL: typing.Final = 22
    EQUAL: typing.Final = 23
    ESCAPE: typing.Final = 24
    EXCLAIM: typing.Final = 25
    FDIV: typing.Final = 26
    FEQUAL: typing.Final = 27
    FGREAT: typing.Final = 28
    FGREATEQUAL: typing.Final = 29
    FLESS: typing.Final = 30
    FLESSEQUAL: typing.Final = 31
    FMINUS: typing.Final = 32
    FMULT: typing.Final = 33
    FNOTEQUAL: typing.Final = 34
    FPLUS: typing.Final = 35
    GREAT: typing.Final = 36
    GREATEQUAL: typing.Final = 37
    HEXDIGIT: typing.Final = 38
    HEX_INT: typing.Final = 39
    IDENTIFIER: typing.Final = 40
    KEY_ALIGNMENT: typing.Final = 41
    KEY_ATTACH: typing.Final = 42
    KEY_BIG: typing.Final = 43
    KEY_BITRANGE: typing.Final = 44
    KEY_BUILD: typing.Final = 45
    KEY_CALL: typing.Final = 46
    KEY_CONTEXT: typing.Final = 47
    KEY_CROSSBUILD: typing.Final = 48
    KEY_DEC: typing.Final = 49
    KEY_DEFAULT: typing.Final = 50
    KEY_DEFINE: typing.Final = 51
    KEY_ENDIAN: typing.Final = 52
    KEY_EXPORT: typing.Final = 53
    KEY_GOTO: typing.Final = 54
    KEY_HEX: typing.Final = 55
    KEY_LITTLE: typing.Final = 56
    KEY_LOCAL: typing.Final = 57
    KEY_MACRO: typing.Final = 58
    KEY_NAMES: typing.Final = 59
    KEY_NOFLOW: typing.Final = 60
    KEY_OFFSET: typing.Final = 61
    KEY_PCODEOP: typing.Final = 62
    KEY_RETURN: typing.Final = 63
    KEY_SIGNED: typing.Final = 64
    KEY_SIZE: typing.Final = 65
    KEY_SPACE: typing.Final = 66
    KEY_TOKEN: typing.Final = 67
    KEY_TYPE: typing.Final = 68
    KEY_UNIMPL: typing.Final = 69
    KEY_VALUES: typing.Final = 70
    KEY_VARIABLES: typing.Final = 71
    KEY_WORDSIZE: typing.Final = 72
    LBRACE: typing.Final = 73
    LBRACKET: typing.Final = 74
    LEFT: typing.Final = 75
    LESS: typing.Final = 76
    LESSEQUAL: typing.Final = 77
    LINECOMMENT: typing.Final = 78
    LPAREN: typing.Final = 79
    MINUS: typing.Final = 80
    NOTEQUAL: typing.Final = 81
    OCTAL_ESCAPE: typing.Final = 82
    OP_ADD: typing.Final = 83
    OP_ADDRESS_OF: typing.Final = 84
    OP_ALIGNMENT: typing.Final = 85
    OP_AND: typing.Final = 86
    OP_APPLY: typing.Final = 87
    OP_ARGUMENTS: typing.Final = 88
    OP_ASSIGN: typing.Final = 89
    OP_BIG: typing.Final = 90
    OP_BIN_CONSTANT: typing.Final = 91
    OP_BITRANGE: typing.Final = 92
    OP_BITRANGE2: typing.Final = 93
    OP_BITRANGES: typing.Final = 94
    OP_BIT_PATTERN: typing.Final = 95
    OP_BOOL_AND: typing.Final = 96
    OP_BOOL_OR: typing.Final = 97
    OP_BOOL_XOR: typing.Final = 98
    OP_BUILD: typing.Final = 99
    OP_CALL: typing.Final = 100
    OP_CONCATENATE: typing.Final = 101
    OP_CONSTRUCTOR: typing.Final = 102
    OP_CONTEXT: typing.Final = 103
    OP_CONTEXT_BLOCK: typing.Final = 104
    OP_CROSSBUILD: typing.Final = 105
    OP_CTLIST: typing.Final = 106
    OP_DEC: typing.Final = 107
    OP_DECLARATIVE_SIZE: typing.Final = 108
    OP_DEC_CONSTANT: typing.Final = 109
    OP_DEFAULT: typing.Final = 110
    OP_DEREFERENCE: typing.Final = 111
    OP_DISPLAY: typing.Final = 112
    OP_DIV: typing.Final = 113
    OP_ELLIPSIS: typing.Final = 114
    OP_ELLIPSIS_RIGHT: typing.Final = 115
    OP_EMPTY_LIST: typing.Final = 116
    OP_ENDIAN: typing.Final = 117
    OP_EQUAL: typing.Final = 118
    OP_EXPORT: typing.Final = 119
    OP_FADD: typing.Final = 120
    OP_FDIV: typing.Final = 121
    OP_FEQUAL: typing.Final = 122
    OP_FGREAT: typing.Final = 123
    OP_FGREATEQUAL: typing.Final = 124
    OP_FIELDDEF: typing.Final = 125
    OP_FIELDDEFS: typing.Final = 126
    OP_FIELD_MODS: typing.Final = 127
    OP_FLESS: typing.Final = 128
    OP_FLESSEQUAL: typing.Final = 129
    OP_FMULT: typing.Final = 130
    OP_FNEGATE: typing.Final = 131
    OP_FNOTEQUAL: typing.Final = 132
    OP_FSUB: typing.Final = 133
    OP_GOTO: typing.Final = 134
    OP_GREAT: typing.Final = 135
    OP_GREATEQUAL: typing.Final = 136
    OP_HEX: typing.Final = 137
    OP_HEX_CONSTANT: typing.Final = 138
    OP_IDENTIFIER: typing.Final = 139
    OP_IDENTIFIER_LIST: typing.Final = 140
    OP_IF: typing.Final = 141
    OP_INTBLIST: typing.Final = 142
    OP_INVERT: typing.Final = 143
    OP_JUMPDEST_ABSOLUTE: typing.Final = 144
    OP_JUMPDEST_DYNAMIC: typing.Final = 145
    OP_JUMPDEST_LABEL: typing.Final = 146
    OP_JUMPDEST_RELATIVE: typing.Final = 147
    OP_JUMPDEST_SYMBOL: typing.Final = 148
    OP_LABEL: typing.Final = 149
    OP_LEFT: typing.Final = 150
    OP_LESS: typing.Final = 151
    OP_LESSEQUAL: typing.Final = 152
    OP_LITTLE: typing.Final = 153
    OP_LOCAL: typing.Final = 154
    OP_MACRO: typing.Final = 155
    OP_MULT: typing.Final = 156
    OP_NAMES: typing.Final = 157
    OP_NEGATE: typing.Final = 158
    OP_NIL: typing.Final = 159
    OP_NOFLOW: typing.Final = 160
    OP_NOP: typing.Final = 161
    OP_NOT: typing.Final = 162
    OP_NOTEQUAL: typing.Final = 163
    OP_NOT_DEFAULT: typing.Final = 164
    OP_NO_CONTEXT_BLOCK: typing.Final = 165
    OP_NO_FIELD_MOD: typing.Final = 166
    OP_OR: typing.Final = 167
    OP_PARENTHESIZED: typing.Final = 168
    OP_PCODE: typing.Final = 169
    OP_PCODEOP: typing.Final = 170
    OP_QSTRING: typing.Final = 171
    OP_REM: typing.Final = 172
    OP_RETURN: typing.Final = 173
    OP_RIGHT: typing.Final = 174
    OP_SDIV: typing.Final = 175
    OP_SECTION_LABEL: typing.Final = 176
    OP_SEMANTIC: typing.Final = 177
    OP_SEQUENCE: typing.Final = 178
    OP_SGREAT: typing.Final = 179
    OP_SGREATEQUAL: typing.Final = 180
    OP_SIGNED: typing.Final = 181
    OP_SIZE: typing.Final = 182
    OP_SIZING_SIZE: typing.Final = 183
    OP_SLESS: typing.Final = 184
    OP_SLESSEQUAL: typing.Final = 185
    OP_SPACE: typing.Final = 186
    OP_SPACEMODS: typing.Final = 187
    OP_SREM: typing.Final = 188
    OP_SRIGHT: typing.Final = 189
    OP_STRING: typing.Final = 190
    OP_STRING_OR_IDENT_LIST: typing.Final = 191
    OP_SUB: typing.Final = 192
    OP_SUBTABLE: typing.Final = 193
    OP_TABLE: typing.Final = 194
    OP_TOKEN: typing.Final = 195
    OP_TOKEN_ENDIAN: typing.Final = 196
    OP_TRUNCATION_SIZE: typing.Final = 197
    OP_TYPE: typing.Final = 198
    OP_UNIMPL: typing.Final = 199
    OP_VALUES: typing.Final = 200
    OP_VARIABLES: typing.Final = 201
    OP_VARNODE: typing.Final = 202
    OP_WHITESPACE: typing.Final = 203
    OP_WILDCARD: typing.Final = 204
    OP_WITH: typing.Final = 205
    OP_WORDSIZE: typing.Final = 206
    OP_XOR: typing.Final = 207
    PERCENT: typing.Final = 208
    PIPE: typing.Final = 209
    PLUS: typing.Final = 210
    PP_ESCAPE: typing.Final = 211
    PP_POSITION: typing.Final = 212
    QSTRING: typing.Final = 213
    RBRACE: typing.Final = 214
    RBRACKET: typing.Final = 215
    RES_IF: typing.Final = 216
    RES_IS: typing.Final = 217
    RES_WITH: typing.Final = 218
    RIGHT: typing.Final = 219
    RPAREN: typing.Final = 220
    SDIV: typing.Final = 221
    SEMI: typing.Final = 222
    SGREAT: typing.Final = 223
    SGREATEQUAL: typing.Final = 224
    SLASH: typing.Final = 225
    SLESS: typing.Final = 226
    SLESSEQUAL: typing.Final = 227
    SPEC_AND: typing.Final = 228
    SPEC_OR: typing.Final = 229
    SPEC_XOR: typing.Final = 230
    SREM: typing.Final = 231
    SRIGHT: typing.Final = 232
    TILDE: typing.Final = 233
    Tokens: typing.Final = 234
    UNDERSCORE: typing.Final = 235
    UNICODE_ESCAPE: typing.Final = 236
    UNKNOWN: typing.Final = 237
    WS: typing.Final = 238
    gBaseLexer: SemanticLexer_BaseLexer

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.CharStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def getDelegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...

    def mFDIV(self):
        ...

    def mFEQUAL(self):
        ...

    def mFGREAT(self):
        ...

    def mFGREATEQUAL(self):
        ...

    def mFLESS(self):
        ...

    def mFLESSEQUAL(self):
        ...

    def mFMINUS(self):
        ...

    def mFMULT(self):
        ...

    def mFNOTEQUAL(self):
        ...

    def mFPLUS(self):
        ...

    def mRES_IF(self):
        ...

    def mSDIV(self):
        ...

    def mSGREAT(self):
        ...

    def mSGREATEQUAL(self):
        ...

    def mSLESS(self):
        ...

    def mSLESSEQUAL(self):
        ...

    def mSREM(self):
        ...

    def mSRIGHT(self):
        ...

    @property
    def delegates(self) -> jpype.JArray[AbstractSleighLexer]:
        ...


class AbstractSleighParser(org.antlr.runtime.Parser, SleighRecognizerConstants):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream):
        ...

    @typing.overload
    def __init__(self, input: org.antlr.runtime.TokenStream, state: org.antlr.runtime.RecognizerSharedState):
        ...

    def setEnv(self, env: ParsingEnvironment):
        ...

    def setLexer(self, lexer: SleighLexer):
        ...


class SleighRecognizerConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    COMMENT: typing.Final = 1
    PREPROC: typing.Final = 2
    BASE: typing.Final = 0
    DISPLAY: typing.Final = 1
    SEMANTIC: typing.Final = 2


class ParsingEnvironment(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, env: ParsingEnvironment):
        ...

    @typing.overload
    def __init__(self, writer: LineArrayListWriter):
        ...

    def format(self, be: BailoutException) -> str:
        ...

    def getErrorHeader(self, e: org.antlr.runtime.RecognitionException) -> str:
        ...

    def getErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: jpype.JArray[java.lang.String], mywriter: LineArrayListWriter) -> str:
        ...

    def getLexerErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: jpype.JArray[java.lang.String]) -> str:
        ...

    def getLexingErrors(self) -> int:
        ...

    def getLocator(self) -> Locator:
        ...

    def getParserErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: jpype.JArray[java.lang.String]) -> str:
        ...

    def getParsingErrors(self) -> int:
        ...

    def getTokenErrorDisplay(self, t: org.antlr.runtime.Token) -> str:
        ...

    def getWriter(self) -> LineArrayListWriter:
        ...

    def lexingError(self):
        ...

    def parsingError(self):
        ...

    @property
    def tokenErrorDisplay(self) -> java.lang.String:
        ...

    @property
    def lexingErrors(self) -> jpype.JInt:
        ...

    @property
    def writer(self) -> LineArrayListWriter:
        ...

    @property
    def parsingErrors(self) -> jpype.JInt:
        ...

    @property
    def locator(self) -> Locator:
        ...

    @property
    def errorHeader(self) -> java.lang.String:
        ...


class HashMapPreprocessorDefinitionsAdapter(ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SleighPreprocessor", "RadixBigInteger", "PreprocessorException", "ANTLRUtil", "Location", "LocationUtil", "SleighToken", "ExpressionEnvironment", "BooleanExpressionLexer", "BaseRecognizerOverride", "SourceFileIndexer", "SleighCompiler", "DisplayLexer", "BailoutException", "SleighParserRun", "SleighParser_SemanticParser", "SleighParser", "BooleanExpressionParser", "SleighEcho", "SleighParser_DisplayParser", "AbstractSleighLexer", "FakeLineArrayListWriter", "ConditionalHelper", "BaseLexer", "DisplayLexer_BaseLexer", "Locator", "LineArrayListWriter", "LexerMultiplexer", "TokenExtractor", "SleighLexer", "SemanticLexer_BaseLexer", "SemanticLexer", "AbstractSleighParser", "SleighRecognizerConstants", "ParsingEnvironment", "HashMapPreprocessorDefinitionsAdapter"]
