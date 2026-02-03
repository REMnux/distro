from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class TokenMgrError(java.lang.Error):
    """
    Token Manager Error.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        No arg constructor.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], reason: typing.Union[jpype.JInt, int]):
        """
        Constructor with message and reason.
        """

    @typing.overload
    def __init__(self, EOFSeen: typing.Union[jpype.JBoolean, bool], lexState: typing.Union[jpype.JInt, int], errorLine: typing.Union[jpype.JInt, int], errorColumn: typing.Union[jpype.JInt, int], errorAfter: typing.Union[java.lang.String, str], curChar: typing.Union[jpype.JChar, int, str], reason: typing.Union[jpype.JInt, int]):
        """
        Full Constructor.
        """

    def getMessage(self) -> str:
        """
        You can also modify the body of this method to customize your error messages.
        For example, cases like LOOP_DETECTED and INVALID_LEXICAL_STATE are not
        of end-users concern, so you can return something like :
        
            "Internal Error : Please file a bug report .... "
        
        from this method for such cases in the release version of your parser.
        """

    @property
    def message(self) -> java.lang.String:
        ...


class DefineTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def containsKey(self, def_: typing.Union[java.lang.String, str]) -> bool:
        """
        See if the define table contains a definition
        
        :param java.lang.String or str def: 
        :return: 
        :rtype: bool
        """

    @typing.overload
    def expand(self, image: typing.Union[java.lang.String, str], join: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        do the final expansion of "##" concats in the define strings that protect normal macro substitution.
        
        :param java.lang.String or str image: 
        :param jpype.JBoolean or bool join: 
        :return: 
        :rtype: str
        """

    @typing.overload
    def expand(self, image: typing.Union[java.lang.String, str], join: typing.Union[jpype.JBoolean, bool], list: java.util.ArrayList[java.lang.String]) -> str:
        """
        do the final expansion of "##" concats in the define strings that protect normal macro substitution.
        
        :param java.lang.String or str image: 
        :param jpype.JBoolean or bool join: 
        :param java.util.ArrayList[java.lang.String] list: of defines not to re-replace, stops recursive replacement on a define
        :return: 
        :rtype: str
        """

    def expandDefine(self, defName: typing.Union[java.lang.String, str]) -> str:
        ...

    def get(self, string: typing.Union[java.lang.String, str]) -> PreProcessor.PPToken:
        """
        
        
        :param java.lang.String or str string: 
        :return: 
        :rtype: PreProcessor.PPToken
        """

    def getArgs(self, currKey: typing.Union[java.lang.String, str]) -> java.util.Vector[PreProcessor.PPToken]:
        """
        
        
        :param java.lang.String or str currKey: 
        :return: 
        :rtype: java.util.Vector[PreProcessor.PPToken]
        """

    @staticmethod
    def getCValue(strValue: typing.Union[java.lang.String, str]) -> int:
        """
        Parse a C format integer value
        
        :param java.lang.String or str strValue: value to parse
        :return: long value if parsable as an integer, null otherwise
        :rtype: int
        """

    def getDefineAt(self, buf: java.lang.StringBuffer, pos: typing.Union[jpype.JInt, int]) -> str:
        """
        
        
        :param java.lang.StringBuffer buf: the buffer containing the define
        :param jpype.JInt or int pos: the position of the define
        :return: the define
        :rtype: str
        """

    def getDefineNames(self) -> java.util.Iterator[java.lang.String]:
        """
        
        
        :return: an iterator over the defined string names
        :rtype: java.util.Iterator[java.lang.String]
        """

    def getDefinitionPath(self, defName: typing.Union[java.lang.String, str]) -> str:
        ...

    def getParams(self, buf: java.lang.StringBuffer, start: typing.Union[jpype.JInt, int], endChar: typing.Union[jpype.JChar, int, str]) -> str:
        """
        
        
        :param java.lang.StringBuffer buf: the buffer containing the parameters
        :param jpype.JInt or int start: the starting index of the parameters in the buffer
        :param jpype.JChar or int or str endChar: the delimiter for the parameters
        :return: the parameters
        :rtype: str
        """

    def getValue(self, defName: typing.Union[java.lang.String, str]) -> str:
        ...

    def isArg(self, string: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if a define has args.
        
        :param java.lang.String or str string: name of define
        :return: 
        :rtype: bool
        """

    def isNumeric(self, defName: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the token that defined this define was numeric
        
        :param java.lang.String or str defName: 
        :return: 
        :rtype: bool
        """

    def populateDefineEquate(self, openDTMgrs: jpype.JArray[ghidra.program.model.data.DataTypeManager], dtMgr: ghidra.program.model.data.DataTypeManager, category: typing.Union[java.lang.String, str], prefix: typing.Union[java.lang.String, str], defName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    def populateDefineEquates(self, openDTMgrs: jpype.JArray[ghidra.program.model.data.DataTypeManager], dtMgr: ghidra.program.model.data.DataTypeManager):
        """
        Given a data type manager, populate defines with constant values as Enums
        """

    def put(self, string: typing.Union[java.lang.String, str], val: PreProcessor.PPToken):
        """
        Associate a define "name" with a Preprocessor parser token match.
        
        :param java.lang.String or str string: - name of define
        :param PreProcessor.PPToken val: - token value from parsing
        """

    def putArg(self, string: typing.Union[java.lang.String, str], val: java.util.Vector[PreProcessor.PPToken]):
        """
        Add an args definition for a define with arguments
            #define bubba(a,b)   (a or b)
        
        :param java.lang.String or str string: name of define
        :param java.util.Vector[PreProcessor.PPToken] val: set of arg token names
        """

    def remove(self, string: typing.Union[java.lang.String, str]) -> PreProcessor.PPToken:
        """
        Remove a definition from the known defines.
        
        :param java.lang.String or str string: name of define
        :return: return the defined token for the named define.
        :rtype: PreProcessor.PPToken
        """

    def removeArg(self, string: typing.Union[java.lang.String, str]) -> java.util.Vector[PreProcessor.PPToken]:
        """
        Get rid of args for a define
        
        :param java.lang.String or str string: name of define
        :return: 
        :rtype: java.util.Vector[PreProcessor.PPToken]
        """

    def size(self) -> int:
        """
        Size of the define table.
        
        :return: 
        :rtype: int
        """

    def toString(self, string: typing.Union[java.lang.String, str]) -> str:
        """
        display a string for the named define.
        
        :param java.lang.String or str string: named define
        :return: 
        :rtype: str
        """

    @property
    def args(self) -> java.util.Vector[PreProcessor.PPToken]:
        ...

    @property
    def defineNames(self) -> java.util.Iterator[java.lang.String]:
        ...

    @property
    def definitionPath(self) -> java.lang.String:
        ...

    @property
    def arg(self) -> jpype.JBoolean:
        ...

    @property
    def numeric(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> java.lang.String:
        ...


class PreProcessorConstants(java.lang.Object):
    """
    Token literal values and constants.
    Generated by org.javacc.parser.OtherFilesGen#start()
    """

    class_: typing.ClassVar[java.lang.Class]
    EOF: typing.Final = 0
    """
    End of File.
    """

    _BOM: typing.Final = 1
    """
    RegularExpression Id.
    """

    _CTRL: typing.Final = 2
    """
    RegularExpression Id.
    """

    _XSYM: typing.Final = 3
    """
    RegularExpression Id.
    """

    _BLANKLINE: typing.Final = 4
    """
    RegularExpression Id.
    """

    _LCMT: typing.Final = 5
    """
    RegularExpression Id.
    """

    _CMT: typing.Final = 6
    """
    RegularExpression Id.
    """

    EOLCMNTNL: typing.Final = 7
    """
    RegularExpression Id.
    """

    CMNTNL: typing.Final = 9
    """
    RegularExpression Id.
    """

    _EQ: typing.Final = 11
    """
    RegularExpression Id.
    """

    _NEQ: typing.Final = 12
    """
    RegularExpression Id.
    """

    _LT: typing.Final = 13
    """
    RegularExpression Id.
    """

    _GT: typing.Final = 14
    """
    RegularExpression Id.
    """

    _LE: typing.Final = 15
    """
    RegularExpression Id.
    """

    _GE: typing.Final = 16
    """
    RegularExpression Id.
    """

    _AND: typing.Final = 17
    """
    RegularExpression Id.
    """

    _LOG_AND: typing.Final = 18
    """
    RegularExpression Id.
    """

    _OR: typing.Final = 19
    """
    RegularExpression Id.
    """

    _XOR: typing.Final = 20
    """
    RegularExpression Id.
    """

    _LOG_OR: typing.Final = 21
    """
    RegularExpression Id.
    """

    _LSH: typing.Final = 22
    """
    RegularExpression Id.
    """

    _RSH: typing.Final = 23
    """
    RegularExpression Id.
    """

    _MINUS: typing.Final = 24
    """
    RegularExpression Id.
    """

    _PERCENT: typing.Final = 25
    """
    RegularExpression Id.
    """

    _PLUS: typing.Final = 26
    """
    RegularExpression Id.
    """

    _QMARK: typing.Final = 27
    """
    RegularExpression Id.
    """

    _COLON: typing.Final = 28
    """
    RegularExpression Id.
    """

    DIR: typing.Final = 29
    """
    RegularExpression Id.
    """

    XSYM: typing.Final = 30
    """
    RegularExpression Id.
    """

    CMT: typing.Final = 31
    """
    RegularExpression Id.
    """

    ECMT: typing.Final = 32
    """
    RegularExpression Id.
    """

    ENDCMT: typing.Final = 33
    """
    RegularExpression Id.
    """

    STARTCMT: typing.Final = 34
    """
    RegularExpression Id.
    """

    COD: typing.Final = 35
    """
    RegularExpression Id.
    """

    ENDL: typing.Final = 36
    """
    RegularExpression Id.
    """

    UNDIR: typing.Final = 37
    """
    RegularExpression Id.
    """

    UNDIRALL: typing.Final = 38
    """
    RegularExpression Id.
    """

    DEFD: typing.Final = 39
    """
    RegularExpression Id.
    """

    OPTD: typing.Final = 40
    """
    RegularExpression Id.
    """

    ENDREL: typing.Final = 41
    """
    RegularExpression Id.
    """

    CP: typing.Final = 42
    """
    RegularExpression Id.
    """

    OP: typing.Final = 43
    """
    RegularExpression Id.
    """

    NOPAR: typing.Final = 44
    """
    RegularExpression Id.
    """

    WSP: typing.Final = 45
    """
    RegularExpression Id.
    """

    STD: typing.Final = 46
    """
    RegularExpression Id.
    """

    REL: typing.Final = 47
    """
    RegularExpression Id.
    """

    NOTENDL: typing.Final = 48
    """
    RegularExpression Id.
    """

    NOTENDLC: typing.Final = 49
    """
    RegularExpression Id.
    """

    NOTENDLSTAR: typing.Final = 50
    """
    RegularExpression Id.
    """

    NOTCMT: typing.Final = 51
    """
    RegularExpression Id.
    """

    NOTCMTCOD: typing.Final = 52
    """
    RegularExpression Id.
    """

    NOTWS: typing.Final = 53
    """
    RegularExpression Id.
    """

    NOTWSQ: typing.Final = 54
    """
    RegularExpression Id.
    """

    NOTWQC: typing.Final = 55
    """
    RegularExpression Id.
    """

    NOTWWSQLT: typing.Final = 56
    """
    RegularExpression Id.
    """

    NOTWSQLT: typing.Final = 57
    """
    RegularExpression Id.
    """

    NOTVALCMT: typing.Final = 58
    """
    RegularExpression Id.
    """

    INTEGER_LITERAL: typing.Final = 59
    """
    RegularExpression Id.
    """

    CHAR_LITERAL: typing.Final = 60
    """
    RegularExpression Id.
    """

    DECIMAL_LITERAL: typing.Final = 61
    """
    RegularExpression Id.
    """

    HEX_LITERAL: typing.Final = 62
    """
    RegularExpression Id.
    """

    HEX_DIGIT: typing.Final = 63
    """
    RegularExpression Id.
    """

    OCTAL_LITERAL: typing.Final = 64
    """
    RegularExpression Id.
    """

    FP_LITERAL: typing.Final = 65
    """
    RegularExpression Id.
    """

    EXPONENT: typing.Final = 66
    """
    RegularExpression Id.
    """

    NOTCHR: typing.Final = 67
    """
    RegularExpression Id.
    """

    WS: typing.Final = 68
    """
    RegularExpression Id.
    """

    OUTER_TEXT: typing.Final = 69
    """
    RegularExpression Id.
    """

    NEWLINE: typing.Final = 70
    """
    RegularExpression Id.
    """

    OTHER_TEXT: typing.Final = 71
    """
    RegularExpression Id.
    """

    QUOTED_TEXT: typing.Final = 72
    """
    RegularExpression Id.
    """

    _WSP0: typing.Final = 83
    """
    RegularExpression Id.
    """

    _COD1: typing.Final = 84
    """
    RegularExpression Id.
    """

    _WSP2: typing.Final = 85
    """
    RegularExpression Id.
    """

    COMMA: typing.Final = 86
    """
    RegularExpression Id.
    """

    _LCMT0: typing.Final = 87
    """
    RegularExpression Id.
    """

    _CMT0: typing.Final = 88
    """
    RegularExpression Id.
    """

    IF: typing.Final = 89
    """
    RegularExpression Id.
    """

    ELIF: typing.Final = 90
    """
    RegularExpression Id.
    """

    ELSE: typing.Final = 91
    """
    RegularExpression Id.
    """

    ENDIF: typing.Final = 92
    """
    RegularExpression Id.
    """

    IFDEFED: typing.Final = 93
    """
    RegularExpression Id.
    """

    IFNDEFED: typing.Final = 94
    """
    RegularExpression Id.
    """

    NOT: typing.Final = 95
    """
    RegularExpression Id.
    """

    DEFINED: typing.Final = 96
    """
    RegularExpression Id.
    """

    HASINCLUDE: typing.Final = 97
    """
    RegularExpression Id.
    """

    HASINCLUDENEXT: typing.Final = 98
    """
    RegularExpression Id.
    """

    OPTIONED: typing.Final = 99
    """
    RegularExpression Id.
    """

    EQ: typing.Final = 100
    """
    RegularExpression Id.
    """

    NEQ: typing.Final = 101
    """
    RegularExpression Id.
    """

    LT: typing.Final = 102
    """
    RegularExpression Id.
    """

    GT: typing.Final = 103
    """
    RegularExpression Id.
    """

    LE: typing.Final = 104
    """
    RegularExpression Id.
    """

    GE: typing.Final = 105
    """
    RegularExpression Id.
    """

    AND: typing.Final = 106
    """
    RegularExpression Id.
    """

    OR: typing.Final = 107
    """
    RegularExpression Id.
    """

    XOR: typing.Final = 108
    """
    RegularExpression Id.
    """

    LOG_OR: typing.Final = 109
    """
    RegularExpression Id.
    """

    LOG_AND: typing.Final = 110
    """
    RegularExpression Id.
    """

    LSH: typing.Final = 111
    """
    RegularExpression Id.
    """

    RSH: typing.Final = 112
    """
    RegularExpression Id.
    """

    MINUS: typing.Final = 113
    """
    RegularExpression Id.
    """

    PLUS: typing.Final = 114
    """
    RegularExpression Id.
    """

    DIVIDE: typing.Final = 115
    """
    RegularExpression Id.
    """

    MOD: typing.Final = 116
    """
    RegularExpression Id.
    """

    TIMES: typing.Final = 117
    """
    RegularExpression Id.
    """

    QMARK: typing.Final = 118
    """
    RegularExpression Id.
    """

    COLON: typing.Final = 119
    """
    RegularExpression Id.
    """

    NUMERIC: typing.Final = 120
    """
    RegularExpression Id.
    """

    FP_NUMERIC: typing.Final = 121
    """
    RegularExpression Id.
    """

    CHAR_NUMERIC: typing.Final = 122
    """
    RegularExpression Id.
    """

    ITEM: typing.Final = 123
    """
    RegularExpression Id.
    """

    BEGITEM: typing.Final = 124
    """
    RegularExpression Id.
    """

    ENDITEM: typing.Final = 125
    """
    RegularExpression Id.
    """

    DIRLINE: typing.Final = 126
    """
    RegularExpression Id.
    """

    _TOEOL: typing.Final = 127
    """
    RegularExpression Id.
    """

    _LCMT11: typing.Final = 128
    """
    RegularExpression Id.
    """

    _CMT11: typing.Final = 129
    """
    RegularExpression Id.
    """

    _INCCOD: typing.Final = 130
    """
    RegularExpression Id.
    """

    _INCWSP: typing.Final = 131
    """
    RegularExpression Id.
    """

    _INCCP: typing.Final = 132
    """
    RegularExpression Id.
    """

    _INCOP: typing.Final = 133
    """
    RegularExpression Id.
    """

    _INCSTANDARD: typing.Final = 134
    """
    RegularExpression Id.
    """

    _HEX: typing.Final = 135
    """
    RegularExpression Id.
    """

    _XSYMENDL: typing.Final = 136
    """
    RegularExpression Id.
    """

    EXPATH: typing.Final = 137
    """
    RegularExpression Id.
    """

    XSYMLINKPATH: typing.Final = 138
    """
    RegularExpression Id.
    """

    INCLINE: typing.Final = 139
    """
    RegularExpression Id.
    """

    MACEXPPATH: typing.Final = 140
    """
    RegularExpression Id.
    """

    _COD: typing.Final = 141
    """
    RegularExpression Id.
    """

    _WSP: typing.Final = 142
    """
    RegularExpression Id.
    """

    __LT: typing.Final = 143
    """
    RegularExpression Id.
    """

    _QTE: typing.Final = 144
    """
    RegularExpression Id.
    """

    _ECMT_INC: typing.Final = 145
    """
    RegularExpression Id.
    """

    _ECMT_INCLUDE_ns: typing.Final = 146
    """
    RegularExpression Id.
    """

    _ECMT_INCLUDE_s: typing.Final = 147
    """
    RegularExpression Id.
    """

    _ECMT_INCLUDE_es: typing.Final = 148
    """
    RegularExpression Id.
    """

    _ECMT_INCLUDE_eo: typing.Final = 149
    """
    RegularExpression Id.
    """

    _ECMT_INCLUDE_e: typing.Final = 150
    """
    RegularExpression Id.
    """

    ESTD: typing.Final = 151
    """
    RegularExpression Id.
    """

    STANDARD: typing.Final = 152
    """
    RegularExpression Id.
    """

    _ENDREL: typing.Final = 153
    """
    RegularExpression Id.
    """

    RELATIVE: typing.Final = 154
    """
    RegularExpression Id.
    """

    PRAGMA_EXPRN: typing.Final = 155
    """
    RegularExpression Id.
    """

    PRAGLINE: typing.Final = 156
    """
    RegularExpression Id.
    """

    _LCMTPRAG: typing.Final = 157
    """
    RegularExpression Id.
    """

    _SCMT_PRAG: typing.Final = 158
    """
    RegularExpression Id.
    """

    _COD_WSP: typing.Final = 159
    """
    RegularExpression Id.
    """

    _COD_PRAG: typing.Final = 160
    """
    RegularExpression Id.
    """

    IFDEF_EXPRN: typing.Final = 161
    """
    RegularExpression Id.
    """

    IFDLINE: typing.Final = 162
    """
    RegularExpression Id.
    """

    _LCMT20: typing.Final = 163
    """
    RegularExpression Id.
    """

    _WSP3: typing.Final = 164
    """
    RegularExpression Id.
    """

    IFNDEF_EXPRN: typing.Final = 165
    """
    RegularExpression Id.
    """

    IFNDLINE: typing.Final = 166
    """
    RegularExpression Id.
    """

    _LCMT21: typing.Final = 167
    """
    RegularExpression Id.
    """

    _WSP4: typing.Final = 168
    """
    RegularExpression Id.
    """

    ERROR_EXPRN: typing.Final = 169
    """
    RegularExpression Id.
    """

    ERRLINE: typing.Final = 170
    """
    RegularExpression Id.
    """

    _WSP5: typing.Final = 171
    """
    RegularExpression Id.
    """

    WARNING_EXPRN: typing.Final = 172
    """
    RegularExpression Id.
    """

    WARNLINE: typing.Final = 173
    """
    RegularExpression Id.
    """

    _WSP6: typing.Final = 174
    """
    RegularExpression Id.
    """

    INFO_EXPRN: typing.Final = 175
    """
    RegularExpression Id.
    """

    INFOLINE: typing.Final = 176
    """
    RegularExpression Id.
    """

    _WSP_INFO: typing.Final = 177
    """
    RegularExpression Id.
    """

    _LEADIN1: typing.Final = 178
    """
    RegularExpression Id.
    """

    CONSTITUENT: typing.Final = 179
    """
    RegularExpression Id.
    """

    UNDLINE: typing.Final = 180
    """
    RegularExpression Id.
    """

    _LEADIN2: typing.Final = 181
    """
    RegularExpression Id.
    """

    _WSP7: typing.Final = 184
    """
    RegularExpression Id.
    """

    _CODC: typing.Final = 185
    """
    RegularExpression Id.
    """

    MANIFEST: typing.Final = 186
    """
    RegularExpression Id.
    """

    CONLINE: typing.Final = 187
    """
    RegularExpression Id.
    """

    LINLINE: typing.Final = 188
    """
    RegularExpression Id.
    """

    LINEINFO: typing.Final = 189
    """
    RegularExpression Id.
    """

    _ECMT_COMMENT_ns: typing.Final = 190
    """
    RegularExpression Id.
    """

    _ECMT_COMMENT_s: typing.Final = 191
    """
    RegularExpression Id.
    """

    _ECMT_COMMENT_es: typing.Final = 192
    """
    RegularExpression Id.
    """

    _ECMT_COMMENT_eo: typing.Final = 193
    """
    RegularExpression Id.
    """

    _ECMT_COMMENT_e: typing.Final = 194
    """
    RegularExpression Id.
    """

    _CMT3: typing.Final = 195
    """
    RegularExpression Id.
    """

    _ECMT_DIRECTIVECOMMENT_ns: typing.Final = 196
    """
    RegularExpression Id.
    """

    _ECMT_DIRECTIVECOMMENT_s: typing.Final = 197
    """
    RegularExpression Id.
    """

    _ECMT_DIRECTIVECOMMENT_es: typing.Final = 198
    """
    RegularExpression Id.
    """

    _ECMT_DIRECTIVECOMMENT_eo: typing.Final = 199
    """
    RegularExpression Id.
    """

    _ECMT_DIRECTIVECOMMENT_e: typing.Final = 200
    """
    RegularExpression Id.
    """

    _LCMT4: typing.Final = 201
    """
    RegularExpression Id.
    """

    _CMT4: typing.Final = 202
    """
    RegularExpression Id.
    """

    _QTE0: typing.Final = 203
    """
    RegularExpression Id.
    """

    _WSP8: typing.Final = 204
    """
    RegularExpression Id.
    """

    _COD2: typing.Final = 205
    """
    RegularExpression Id.
    """

    RVSLINE: typing.Final = 206
    """
    RegularExpression Id.
    """

    VALUES: typing.Final = 207
    """
    RegularExpression Id.
    """

    VALUESCMT: typing.Final = 208
    """
    RegularExpression Id.
    """

    MOREVAL: typing.Final = 209
    """
    RegularExpression Id.
    """

    _ECMT_RVALUES_ns: typing.Final = 210
    """
    RegularExpression Id.
    """

    _ECMT_RVALUES_s: typing.Final = 211
    """
    RegularExpression Id.
    """

    _ECMT_RVALUES_es: typing.Final = 212
    """
    RegularExpression Id.
    """

    _ECMT_RVALUES_eo: typing.Final = 213
    """
    RegularExpression Id.
    """

    _ECMT_RVALUES_e: typing.Final = 214
    """
    RegularExpression Id.
    """

    _EQT: typing.Final = 215
    """
    RegularExpression Id.
    """

    QUOTED_VALUE: typing.Final = 216
    """
    RegularExpression Id.
    """

    MACROMV: typing.Final = 217
    """
    RegularExpression Id.
    """

    MACROMVTAG: typing.Final = 218
    """
    RegularExpression Id.
    """

    MACROARGSEND: typing.Final = 219
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGS: typing.Final = 220
    """
    RegularExpression Id.
    """

    _CMT_MACROARGS: typing.Final = 221
    """
    RegularExpression Id.
    """

    _MWSP: typing.Final = 222
    """
    RegularExpression Id.
    """

    _COD3: typing.Final = 223
    """
    RegularExpression Id.
    """

    _MACWSP: typing.Final = 224
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGSns: typing.Final = 225
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGSs: typing.Final = 226
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGSes: typing.Final = 227
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGSeo: typing.Final = 228
    """
    RegularExpression Id.
    """

    _ECMT_MACROARGSe: typing.Final = 229
    """
    RegularExpression Id.
    """

    MOREARG: typing.Final = 231
    """
    RegularExpression Id.
    """

    MACRORV: typing.Final = 232
    """
    RegularExpression Id.
    """

    MACRORVCMT: typing.Final = 233
    """
    RegularExpression Id.
    """

    _LCMT7: typing.Final = 234
    """
    RegularExpression Id.
    """

    _COD4: typing.Final = 235
    """
    RegularExpression Id.
    """

    _ECMT8: typing.Final = 236
    """
    RegularExpression Id.
    """

    _QTE1: typing.Final = 237
    """
    RegularExpression Id.
    """

    MCVLINE: typing.Final = 238
    """
    RegularExpression Id.
    """

    LEADIN3: typing.Final = 239
    """
    RegularExpression Id.
    """

    _EQT1: typing.Final = 240
    """
    RegularExpression Id.
    """

    MQUOTED_VALUE: typing.Final = 241
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_ns: typing.Final = 242
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_s: typing.Final = 243
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_es: typing.Final = 244
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_eo: typing.Final = 245
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_e: typing.Final = 246
    """
    RegularExpression Id.
    """

    _ECMT_MACROVALS_ew: typing.Final = 247
    """
    RegularExpression Id.
    """

    DEFAULT: typing.Final = 0
    """
    Lexical state.
    """

    SpecialEOLComment: typing.Final = 1
    """
    Lexical state.
    """

    SpecialBlockComment: typing.Final = 2
    """
    Lexical state.
    """

    DIRECTIVE: typing.Final = 3
    """
    Lexical state.
    """

    IGNORETOEOL: typing.Final = 4
    """
    Lexical state.
    """

    INCDEF: typing.Final = 5
    """
    Lexical state.
    """

    XSYMLINK: typing.Final = 6
    """
    Lexical state.
    """

    XSYMPATH: typing.Final = 7
    """
    Lexical state.
    """

    INCLUDE: typing.Final = 8
    """
    Lexical state.
    """

    INCLUDE_COMMENT: typing.Final = 9
    """
    Lexical state.
    """

    INCLUDE_COMMENT_END: typing.Final = 10
    """
    Lexical state.
    """

    STDPATH: typing.Final = 11
    """
    Lexical state.
    """

    RELPATH: typing.Final = 12
    """
    Lexical state.
    """

    PRAGMA: typing.Final = 13
    """
    Lexical state.
    """

    IFDEF: typing.Final = 14
    """
    Lexical state.
    """

    IFNDEF: typing.Final = 15
    """
    Lexical state.
    """

    ERROR: typing.Final = 16
    """
    Lexical state.
    """

    WARNING: typing.Final = 17
    """
    Lexical state.
    """

    INFO: typing.Final = 18
    """
    Lexical state.
    """

    UNDEFINE: typing.Final = 19
    """
    Lexical state.
    """

    DEFINE: typing.Final = 20
    """
    Lexical state.
    """

    CONSTANT: typing.Final = 21
    """
    Lexical state.
    """

    LINE: typing.Final = 22
    """
    Lexical state.
    """

    COMMENT: typing.Final = 23
    """
    Lexical state.
    """

    COMMENT_END: typing.Final = 24
    """
    Lexical state.
    """

    LINECOMMENT: typing.Final = 25
    """
    Lexical state.
    """

    DIRECTIVECOMMENT: typing.Final = 26
    """
    Lexical state.
    """

    DIRECTIVECOMMENT_END: typing.Final = 27
    """
    Lexical state.
    """

    RVALUES: typing.Final = 28
    """
    Lexical state.
    """

    RVALUES_COMMENT: typing.Final = 29
    """
    Lexical state.
    """

    RVALUES_COMMENT_END: typing.Final = 30
    """
    Lexical state.
    """

    QUOTED_VAL: typing.Final = 31
    """
    Lexical state.
    """

    MACROARGS: typing.Final = 32
    """
    Lexical state.
    """

    MACROARGSCOMMENT: typing.Final = 33
    """
    Lexical state.
    """

    MACROARGSCOMMENT_END: typing.Final = 34
    """
    Lexical state.
    """

    CONTARG: typing.Final = 35
    """
    Lexical state.
    """

    MACROVALS: typing.Final = 36
    """
    Lexical state.
    """

    MQUOTED_VAL: typing.Final = 37
    """
    Lexical state.
    """

    MACROVALS_COMMENT: typing.Final = 38
    """
    Lexical state.
    """

    MACROVALS_COMMENT_END: typing.Final = 39
    """
    Lexical state.
    """

    tokenImage: typing.Final[jpype.JArray[java.lang.String]]
    """
    Literal token values.
    """



class SimpleCharStream(java.lang.Object):
    """
    An implementation of interface CharStream, where the stream is assumed to
    contain only ASCII characters (without unicode processing).
    """

    class_: typing.ClassVar[java.lang.Class]
    staticFlag: typing.Final = False
    """
    Whether parser is static.
    """

    bufpos: jpype.JInt
    """
    Position in buffer.
    """


    @typing.overload
    def __init__(self, dstream: java.io.Reader, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.Reader, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.Reader):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str], startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str], startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str]):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, dstream: java.io.InputStream):
        """
        Constructor.
        """

    def BeginToken(self) -> str:
        """
        Start.
        """

    def Done(self):
        """
        Reset buffer when finished.
        """

    def GetImage(self) -> str:
        """
        Get token literal value.
        """

    def GetSuffix(self, len: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JChar]:
        """
        Get the suffix.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.Reader, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.Reader, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.Reader):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str], startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int], buffersize: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream, encoding: typing.Union[java.lang.String, str], startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, dstream: java.io.InputStream, startline: typing.Union[jpype.JInt, int], startcolumn: typing.Union[jpype.JInt, int]):
        """
        Reinitialise.
        """

    def adjustBeginLineColumn(self, newLine: typing.Union[jpype.JInt, int], newCol: typing.Union[jpype.JInt, int]):
        """
        Method to adjust line and column numbers for the start of a token.
        """

    def backup(self, amount: typing.Union[jpype.JInt, int]):
        """
        Backup a number of characters.
        """

    def getBeginColumn(self) -> int:
        """
        Get token beginning column number.
        """

    def getBeginLine(self) -> int:
        """
        Get token beginning line number.
        """

    def getColumn(self) -> int:
        ...

    def getEndColumn(self) -> int:
        """
        Get token end column number.
        """

    def getEndLine(self) -> int:
        """
        Get token end line number.
        """

    def getLine(self) -> int:
        ...

    def readChar(self) -> str:
        """
        Read a character.
        """

    @property
    def endLine(self) -> jpype.JInt:
        ...

    @property
    def endColumn(self) -> jpype.JInt:
        ...

    @property
    def beginColumn(self) -> jpype.JInt:
        ...

    @property
    def line(self) -> jpype.JInt:
        ...

    @property
    def beginLine(self) -> jpype.JInt:
        ...

    @property
    def column(self) -> jpype.JInt:
        ...


class PreProcessorTokenManager(PreProcessorConstants):
    """
    Token Manager.
    """

    class_: typing.ClassVar[java.lang.Class]
    debugStream: java.io.PrintStream
    """
    Debug output.
    """

    jjstrLiteralImages: typing.Final[jpype.JArray[java.lang.String]]
    """
    Token literal values.
    """

    lexStateNames: typing.Final[jpype.JArray[java.lang.String]]
    """
    Lexer state names.
    """

    jjnewLexState: typing.Final[jpype.JArray[jpype.JInt]]
    """
    Lex State array.
    """


    @typing.overload
    def __init__(self, stream: SimpleCharStream):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, stream: SimpleCharStream, lexState: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        """

    @typing.overload
    def ReInit(self, stream: SimpleCharStream):
        """
        Reinitialise parser.
        """

    @typing.overload
    def ReInit(self, stream: SimpleCharStream, lexState: typing.Union[jpype.JInt, int]):
        """
        Reinitialise parser.
        """

    def SwitchTo(self, lexState: typing.Union[jpype.JInt, int]):
        """
        Switch to specified lex state.
        """

    def getNextToken(self) -> Token:
        """
        Get the next Token.
        """

    def setDebugStream(self, ds: java.io.PrintStream):
        """
        Set debug output.
        """

    @property
    def nextToken(self) -> Token:
        ...


class Token(java.io.Serializable):
    """
    Describes the input token stream.
    """

    class_: typing.ClassVar[java.lang.Class]
    kind: jpype.JInt
    """
    An integer that describes the kind of this token.  This numbering
    system is determined by JavaCCParser, and a table of these numbers is
    stored in the file ...Constants.java.
    """

    beginLine: jpype.JInt
    """
    The line number of the first character of this Token.
    """

    beginColumn: jpype.JInt
    """
    The column number of the first character of this Token.
    """

    endLine: jpype.JInt
    """
    The line number of the last character of this Token.
    """

    endColumn: jpype.JInt
    """
    The column number of the last character of this Token.
    """

    image: java.lang.String
    """
    The string image of the token.
    """

    next: Token
    """
    A reference to the next regular (non-special) token from the input
    stream.  If this is the last token from the input stream, or if the
    token manager has not read tokens beyond this one, this field is
    set to null.  This is true only if this token is also a regular
    token.  Otherwise, see below for a description of the contents of
    this field.
    """

    specialToken: Token
    """
    This field is used to access special tokens that occur prior to this
    token, but after the immediately preceding regular (non-special) token.
    If there are no such special tokens, this field is set to null.
    When there are more than one such special token, this field refers
    to the last of these special tokens, which in turn refers to the next
    previous special token through its specialToken field, and so on
    until the first special token (whose specialToken field is null).
    The next fields of special tokens refer to other special tokens that
    immediately follow it (without an intervening regular token).  If there
    is no such token, this field is null.
    """


    @typing.overload
    def __init__(self):
        """
        No-argument constructor
        """

    @typing.overload
    def __init__(self, kind: typing.Union[jpype.JInt, int]):
        """
        Constructs a new token for the specified Image.
        """

    @typing.overload
    def __init__(self, kind: typing.Union[jpype.JInt, int], image: typing.Union[java.lang.String, str]):
        """
        Constructs a new token for the specified Image and Kind.
        """

    def getValue(self) -> java.lang.Object:
        """
        An optional attribute value of the Token.
        Tokens which are not used as syntactic sugar will often contain
        meaningful values that will be used later on by the compiler or
        interpreter. This attribute value is often different from the image.
        Any subclass of Token that actually wants to return a non-null value can
        override this method as appropriate.
        """

    @staticmethod
    @typing.overload
    def newToken(ofKind: typing.Union[jpype.JInt, int], image: typing.Union[java.lang.String, str]) -> Token:
        """
        Returns a new Token object, by default. However, if you want, you
        can create and return subclass objects based on the value of ofKind.
        Simply add the cases to the switch for all those special cases.
        For example, if you have a subclass of Token called IDToken that
        you want to create if ofKind is ID, simply add something like :
        
            case MyParserConstants.ID : return new IDToken(ofKind, image);
        
        to the following switch statement. Then you can cast matchedToken
        variable to the appropriate type and use sit in your lexical actions.
        """

    @staticmethod
    @typing.overload
    def newToken(ofKind: typing.Union[jpype.JInt, int]) -> Token:
        ...

    def toString(self) -> str:
        """
        Returns the image.
        """

    @property
    def value(self) -> java.lang.Object:
        ...


class ParseException(java.lang.Exception):
    """
    This exception is thrown when parse errors are encountered.
    You can explicitly create objects of this exception type by
    calling the method generateParseException in the generated
    parser.
    
    You can modify this class to customize your error reporting
    mechanisms so long as you retain the public fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    currentToken: Token
    """
    This is the last token that has been consumed successfully.  If
    this object has been created due to a parse error, the token
    followng this token will (therefore) be the first error token.
    """

    expectedTokenSequences: jpype.JArray[jpype.JArray[jpype.JInt]]
    """
    Each entry in this array is an array of integers.  Each array
    of integers represents a sequence of tokens (by their ordinal
    values) that is expected at this point of the parse.
    """

    tokenImage: jpype.JArray[java.lang.String]
    """
    This is a reference to the "tokenImage" array of the generated
    parser within which the parse error occurred.  This array is
    defined in the generated ...Constants interface.
    """


    @typing.overload
    def __init__(self, currentTokenVal: Token, expectedTokenSequencesVal: jpype.JArray[jpype.JArray[jpype.JInt]], tokenImageVal: jpype.JArray[java.lang.String]):
        """
        This constructor is used by the method "generateParseException"
        in the generated parser.  Calling this constructor generates
        a new object of this type with the fields "currentToken",
        "expectedTokenSequences", and "tokenImage" set.
        """

    @typing.overload
    def __init__(self):
        """
        The following constructors are for use by you for whatever
        purpose you can think of.  Constructing the exception in this
        manner makes the exception behave in the normal way - i.e., as
        documented in the class "Throwable".  The fields "errorToken",
        "expectedTokenSequences", and "tokenImage" do not contain
        relevant information.  The JavaCC generated code does not use
        these constructors.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructor with message.
        """


class PreProcessor(PreProcessorConstants):

    @typing.type_check_only
    class PPToken(Token):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, ptk: PreProcessor.PPToken):
            ...

        @typing.overload
        def __init__(self, tk: Token):
            ...

        @typing.overload
        def __init__(self, tk: Token, truth: typing.Union[jpype.JBoolean, bool]):
            ...

        @typing.overload
        def __init__(self, val: typing.Union[java.lang.String, str]):
            ...

        def equals(self, t: java.lang.Object) -> bool:
            ...


    @typing.type_check_only
    class LookaheadSuccess(java.lang.Error):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class JJCalls(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    token_source: PreProcessorTokenManager
    """
    Generated Token Manager.
    """

    token: Token
    """
    Current token.
    """

    jj_nt: Token
    """
    Next token.
    """


    @typing.overload
    def __init__(self, args: jpype.JArray[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, filename: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, stream: java.io.InputStream):
        """
        Constructor with InputStream.
        """

    @typing.overload
    def __init__(self, stream: java.io.InputStream, encoding: typing.Union[java.lang.String, str]):
        """
        Constructor with InputStream and supplied encoding
        """

    @typing.overload
    def __init__(self, stream: java.io.Reader):
        """
        Constructor.
        """

    @typing.overload
    def __init__(self, tm: PreProcessorTokenManager):
        """
        Constructor with generated Token Manager.
        """

    def ANDExpression(self) -> PreProcessor.PPToken:
        ...

    def AdditiveExpression(self) -> PreProcessor.PPToken:
        ...

    def Assertion(self) -> PreProcessor.PPToken:
        ...

    def CompoundAndExpression(self) -> PreProcessor.PPToken:
        ...

    def CompoundConditionalExpression(self) -> PreProcessor.PPToken:
        ...

    def CompoundOrExpression(self) -> PreProcessor.PPToken:
        ...

    def ConditionalExpression(self) -> PreProcessor.PPToken:
        ...

    def ControlLine(self) -> PreProcessor.PPToken:
        ...

    def Define(self) -> PreProcessor.PPToken:
        ...

    def ElIf(self) -> PreProcessor.PPToken:
        ...

    def Else(self) -> PreProcessor.PPToken:
        ...

    def ElseIfCondition(self) -> PreProcessor.PPToken:
        ...

    def ElseMark(self) -> PreProcessor.PPToken:
        ...

    def EndIf(self) -> PreProcessor.PPToken:
        ...

    def EqualTo(self) -> PreProcessor.PPToken:
        ...

    def EqualityExpression(self) -> PreProcessor.PPToken:
        ...

    def Error(self) -> PreProcessor.PPToken:
        ...

    def ExclusiveORExpression(self) -> PreProcessor.PPToken:
        ...

    def Expression(self) -> PreProcessor.PPToken:
        ...

    def GreaterThan(self) -> PreProcessor.PPToken:
        ...

    def GreaterThanExpression(self) -> PreProcessor.PPToken:
        ...

    def GreaterThanOrEqual(self) -> PreProcessor.PPToken:
        ...

    def GreaterThanOrEqualExpression(self) -> PreProcessor.PPToken:
        ...

    def Group(self) -> PreProcessor.PPToken:
        ...

    def GroupPart(self) -> PreProcessor.PPToken:
        ...

    def IFGroup(self) -> PreProcessor.PPToken:
        ...

    def IFSection(self) -> PreProcessor.PPToken:
        ...

    def If(self) -> PreProcessor.PPToken:
        ...

    def IfCondition(self) -> PreProcessor.PPToken:
        ...

    def IfDef(self) -> PreProcessor.PPToken:
        ...

    def IfDefExpr(self) -> PreProcessor.PPToken:
        ...

    def IfNDef(self) -> PreProcessor.PPToken:
        ...

    def IfNDefExpr(self) -> PreProcessor.PPToken:
        ...

    def InEqualityExpression(self) -> PreProcessor.PPToken:
        ...

    def Include(self) -> PreProcessor.PPToken:
        ...

    def InclusiveORExpression(self) -> PreProcessor.PPToken:
        ...

    def Info(self) -> PreProcessor.PPToken:
        ...

    def Input(self):
        ...

    def LessExpression(self) -> PreProcessor.PPToken:
        ...

    def LessThan(self) -> PreProcessor.PPToken:
        ...

    def LessThanOrEqual(self) -> PreProcessor.PPToken:
        ...

    def LessThanOrEqualExpression(self) -> PreProcessor.PPToken:
        ...

    def LineInfo(self) -> PreProcessor.PPToken:
        ...

    def LogAnd(self) -> PreProcessor.PPToken:
        ...

    def LogNegation(self) -> PreProcessor.PPToken:
        ...

    def LogOr(self) -> PreProcessor.PPToken:
        ...

    def LogicalAndExpression(self) -> PreProcessor.PPToken:
        ...

    def LogicalOrExpression(self) -> PreProcessor.PPToken:
        ...

    def MacroArgs(self) -> PreProcessor.PPToken:
        ...

    def MacroVals(self) -> PreProcessor.PPToken:
        ...

    def MultiplicativeExpression(self) -> PreProcessor.PPToken:
        ...

    def NewLines(self) -> PreProcessor.PPToken:
        ...

    def NoMas(self):
        ...

    def NotEqualTo(self) -> PreProcessor.PPToken:
        ...

    def Pragma(self) -> PreProcessor.PPToken:
        ...

    def Qmark(self) -> PreProcessor.PPToken:
        ...

    def QuotedText(self) -> PreProcessor.PPToken:
        ...

    def QuotedValue(self) -> PreProcessor.PPToken:
        ...

    @typing.overload
    def ReInit(self, stream: java.io.InputStream):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, stream: java.io.InputStream, encoding: typing.Union[java.lang.String, str]):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, stream: java.io.Reader):
        """
        Reinitialise.
        """

    @typing.overload
    def ReInit(self, tm: PreProcessorTokenManager):
        """
        Reinitialise.
        """

    def RelationalExpression(self) -> PreProcessor.PPToken:
        ...

    def ShiftExpression(self) -> PreProcessor.PPToken:
        ...

    def Text(self) -> PreProcessor.PPToken:
        ...

    def TranslationUnit(self) -> PreProcessor.PPToken:
        ...

    def UnDef(self) -> PreProcessor.PPToken:
        ...

    def UnaryExpression(self) -> PreProcessor.PPToken:
        ...

    def ValueExpression(self) -> PreProcessor.PPToken:
        ...

    def Values(self) -> PreProcessor.PPToken:
        ...

    def Warning(self) -> PreProcessor.PPToken:
        ...

    def addIncludePath(self, path: typing.Union[java.lang.String, str]):
        ...

    def addIncludePaths(self, paths: jpype.JArray[java.lang.String]):
        ...

    def curFileStackTop(self) -> str:
        ...

    def didParseSucceed(self) -> bool:
        ...

    def disable_tracing(self):
        """
        Disable tracing.
        """

    def enable_tracing(self):
        """
        Enable tracing.
        """

    def generateParseException(self) -> ParseException:
        """
        Generate ParseException.
        """

    @typing.overload
    def getDef(self, def_: PreProcessor.PPToken) -> PreProcessor.PPToken:
        ...

    @typing.overload
    def getDef(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    def getDefinitions(self) -> DefineTable:
        ...

    def getDoubleValue(self, val: typing.Union[java.lang.String, str]) -> float:
        ...

    def getNextToken(self) -> Token:
        """
        Get the next Token.
        """

    def getNumericType(self, val: typing.Union[java.lang.String, str]) -> int:
        ...

    def getParseMessages(self) -> str:
        ...

    def getToken(self, index: typing.Union[jpype.JInt, int]) -> Token:
        """
        Get the specific Token.
        """

    def isArg(self, arg: PreProcessor.PPToken) -> bool:
        ...

    def isDef(self, def_: PreProcessor.PPToken) -> bool:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def parse(self, filename: typing.Union[java.lang.String, str]) -> bool:
        ...

    def setArgs(self, args: jpype.JArray[java.lang.String]):
        ...

    def setMonitor(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def setOutputStream(self, fos: java.io.OutputStream):
        ...

    def verboseLevel(self) -> int:
        ...

    @property
    def def_(self) -> PreProcessor.PPToken:
        ...

    @property
    def nextToken(self) -> Token:
        ...

    @property
    def arg(self) -> jpype.JBoolean:
        ...

    @property
    def parseMessages(self) -> java.lang.String:
        ...

    @property
    def numericType(self) -> jpype.JInt:
        ...

    @property
    def doubleValue(self) -> jpype.JDouble:
        ...

    @property
    def definitions(self) -> DefineTable:
        ...



__all__ = ["TokenMgrError", "DefineTable", "PreProcessorConstants", "SimpleCharStream", "PreProcessorTokenManager", "Token", "ParseException", "PreProcessor"]
