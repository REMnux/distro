from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.program.model.pcode
import ghidra.sleigh.grammar
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore


class AddressUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def unsignedAdd(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def unsignedCompare(v1: typing.Union[jpype.JLong, int], v2: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def unsignedSubtract(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...


class MessageFormattingUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def format(location: ghidra.sleigh.grammar.Location, message: java.lang.CharSequence) -> str:
        """
        Format a log message.
        
        :param ghidra.sleigh.grammar.Location location: Referenced file location
        :param java.lang.CharSequence message: Message
        :return: Formatted string with location prepended to message.
        :rtype: str
        """


class SlaFormat(java.lang.Object):
    """
    Encoding values for the .sla file format
    """

    class_: typing.ClassVar[java.lang.Class]
    FORMAT_VERSION: typing.Final = 4
    """
    FORMAT_VERSION will be incremented whenever the format of the .sla
    files change.
     
    
    Version 4: Compressed and packed file format
    Version 3: January 2021: added source file information for each constructor. 
    
    Version 2: April 2019: Changed numbering of Overlay spaces.
    
    Version 1: Initial version.
    """

    MAX_FILE_SIZE: typing.Final = 16777216
    """
    Absolute limit on the number of bytes in a .sla file
    """

    ATTRIB_VAL: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_ID: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SPACE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_S: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_OFF: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_CODE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_MASK: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_INDEX: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_NONZERO: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_PIECE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_NAME: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SCOPE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_STARTBIT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SIZE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_TABLE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_CT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_MINLEN: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_BASE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_NUMBER: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_CONTEXT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_PARENT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SUBSYM: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_LINE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SOURCE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_LENGTH: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_FIRST: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_PLUS: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SHIFT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_ENDBIT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SIGNBIT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_ENDBYTE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_STARTBYTE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_VERSION: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_BIGENDIAN: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_ALIGN: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_UNIQBASE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_MAXDELAY: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_UNIQMASK: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_NUMSECTIONS: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_DEFAULTSPACE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_DELAY: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_WORDSIZE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_PHYSICAL: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SCOPESIZE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SYMBOLSIZE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_VARNODE: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_LOW: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_HIGH: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_FLOW: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_CONTAIN: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_I: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_NUMCT: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_SECTION: typing.Final[ghidra.program.model.pcode.AttributeId]
    ATTRIB_LABELS: typing.Final[ghidra.program.model.pcode.AttributeId]
    ELEM_CONST_REAL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VARNODE_TPL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_SPACEID: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_HANDLE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OP_TPL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_MASK_WORD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_PAT_BLOCK: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_PRINT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_PAIR: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONTEXT_PAT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NULL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OPERAND_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OPERAND_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OPERAND_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OPER: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_DECISION: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OPPRINT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_INSTRUCT_PAT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_COMBINE_PAT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONSTRUCTOR: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONSTRUCT_TPL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SCOPE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VARNODE_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VARNODE_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_USEROP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_USEROP_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_TOKENFIELD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VAR: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONTEXTFIELD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_HANDLE_TPL: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_RELATIVE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONTEXT_OP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SLEIGH: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SPACES: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SOURCEFILES: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SOURCEFILE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SPACE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SYMBOL_TABLE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VALUE_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VALUE_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONTEXT_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONTEXT_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_END_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_END_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SPACE_OTHER: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SPACE_UNIQUE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_AND_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_DIV_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_LSHIFT_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_MINUS_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_MULT_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NOT_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OR_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_PLUS_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_RSHIFT_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SUB_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_XOR_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_INTB: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_END_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NEXT2_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_START_EXP: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_EPSILON_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_EPSILON_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NAME_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NAME_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NAMETAB: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NEXT2_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_NEXT2_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_START_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_START_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SUBTABLE_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_SUBTABLE_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VALUEMAP_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VALUEMAP_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VALUETAB: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VARLIST_SYM: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_VARLIST_SYM_HEAD: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_OR_PAT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_COMMIT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_START: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_NEXT: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_NEXT2: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_CURSPACE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_CURSPACE_SIZE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_FLOWREF: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_FLOWREF_SIZE: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_FLOWDEST: typing.Final[ghidra.program.model.pcode.ElementId]
    ELEM_CONST_FLOWDEST_SIZE: typing.Final[ghidra.program.model.pcode.ElementId]

    def __init__(self):
        ...

    @staticmethod
    def buildDecoder(sleighFile: generic.jar.ResourceFile) -> ghidra.program.model.pcode.PackedDecode:
        """
        Build the decoder for decompressing and decoding the .sla file (as a stream).
        The given file is opened and the header bytes are checked.  The returned
        decoder is immediately ready to read.
        
        :param generic.jar.ResourceFile sleighFile: is the given .sla file
        :return: the decoder
        :rtype: ghidra.program.model.pcode.PackedDecode
        :raises IOException: if the header is invalid or there are problems reading the file
        """

    @staticmethod
    def buildEncoder(sleighFile: generic.jar.ResourceFile) -> ghidra.program.model.pcode.PackedEncode:
        """
        Build the encoder for compressing and encoding a .sla file (as a stream).
        The given file is opened and a header is immediately written.  The returned
        encoder is ready immediately to receive the .sla elements and attributes.
        
        :param generic.jar.ResourceFile sleighFile: is the .sla file (to be created)
        :return: the encoder
        :rtype: ghidra.program.model.pcode.PackedEncode
        :raises IOException: for any problems opening or writing to the file
        """

    @staticmethod
    def isSlaFormat(stream: java.io.InputStream) -> bool:
        """
        Try to read the header bytes of the .sla format from the given stream. If the header bytes
        and the version byte match, \b true is returned, and the stream can be passed to the decoder.
        
        :param java.io.InputStream stream: is the given stream
        :return: true if the .sla header bytes are found
        :rtype: bool
        :raises IOException: for any errors reading from the stream
        """

    @staticmethod
    def writeSlaHeader(stream: java.io.OutputStream):
        """
        Write a .sla file header,including the format version number to the given stream.
        
        :param java.io.OutputStream stream: is the given stream
        :raises IOException: for problems writing to the stream
        """


class Utils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    endl: typing.Final[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def bigIntegerToBytes(val: java.math.BigInteger, size: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...

    @staticmethod
    def byte_swap(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def bytesToBigInteger(byteBuf: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        ...

    @staticmethod
    def bytesToLong(byteBuf: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        ...

    @staticmethod
    def calc_bigmask(size: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        ...

    @staticmethod
    def calc_mask(size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def convertToSignedValue(val: java.math.BigInteger, byteSize: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        ...

    @staticmethod
    def convertToUnsignedValue(val: java.math.BigInteger, byteSize: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        ...

    @staticmethod
    def longToBytes(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...

    @staticmethod
    def sign_extend(in_: typing.Union[jpype.JLong, int], sizein: typing.Union[jpype.JInt, int], sizeout: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def signbit_negative(val: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def uintb_negate(in_: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def zzz_sign_extend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def zzz_zero_extend(val: typing.Union[jpype.JLong, int], bit: typing.Union[jpype.JInt, int]) -> int:
        ...



__all__ = ["AddressUtils", "MessageFormattingUtils", "SlaFormat", "Utils"]
