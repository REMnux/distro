from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format
import java.lang # type: ignore
import java.util # type: ignore


class MzExecutable(java.lang.Object):
    """
    A class to manage loading old-style DOS MZ executables
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Constructs a new instance of an old-style MZ executable
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes
        :raises IOException: if an I/O error occurs
        """

    def getBinaryReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the underlying binary reader
        
        :return: the underlying binary reader
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getHeader(self) -> OldDOSHeader:
        """
        Returns the DOS Header from this old-style MZ executable
        
        :return: the DOS Header from this old-style MZ executable
        :rtype: OldDOSHeader
        """

    def getRelocations(self) -> java.util.List[MzRelocation]:
        """
        Returns the old-style MZ relocations
        
        :return: the old-style MZ relocations
        :rtype: java.util.List[MzRelocation]
        """

    @property
    def header(self) -> OldDOSHeader:
        ...

    @property
    def binaryReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def relocations(self) -> java.util.List[MzRelocation]:
        ...


class OldDOSHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.Writeable):
    """
    This class represents a DOS Header
     
    
     
        WORD   e_magic;                     // Magic number                                // MANDATORY
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "OLD_IMAGE_DOS_HEADER"
    """
    The name to use when converting into a structure data type.
    """

    IMAGE_DOS_SIGNATURE: typing.Final = 23117

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Constructs a new DOS header.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :raises IOException: if there was an IO-related error
        """

    def e_cblp(self) -> int:
        """
        Returns the number of bytes on the last page of file.
        
        :return: the number of bytes on the last page of the file
        :rtype: int
        """

    def e_cp(self) -> int:
        """
        Returns the number of pages in the file.
        
        :return: the number of pages in the file
        :rtype: int
        """

    def e_cparhdr(self) -> int:
        """
        Returns the size of header in paragraphs.
        
        :return: the size of header in paragraphs
        :rtype: int
        """

    def e_crlc(self) -> int:
        """
        Returns the number of relocations.
        
        :return: the number of relocations
        :rtype: int
        """

    def e_cs(self) -> int:
        """
        Returns the initial (relative) CS value.
        
        :return: the initial (relative) CS value
        :rtype: int
        """

    def e_csum(self) -> int:
        """
        Returns the checksum.
        
        :return: the checksum
        :rtype: int
        """

    def e_ip(self) -> int:
        """
        Returns the initial IP value.
        
        :return: the initial IP value
        :rtype: int
        """

    def e_lfarlc(self) -> int:
        """
        Returns the file address of relocation table.
        
        :return: the file address of relocation table
        :rtype: int
        """

    def e_magic(self) -> int:
        """
        Returns the magic number.
        
        :return: the magic number
        :rtype: int
        """

    def e_maxalloc(self) -> int:
        """
        Returns the maximum extra paragraphs needed.
        
        :return: the maximum extra paragraphs needed
        :rtype: int
        """

    def e_minalloc(self) -> int:
        """
        Returns the minimum extra paragraphs needed.
        
        :return: the minimum extra paragraphs needed
        :rtype: int
        """

    def e_ovno(self) -> int:
        """
        Returns the overlay number.
        
        :return: the overlay number
        :rtype: int
        """

    def e_sp(self) -> int:
        """
        Returns the initial SP value.
        
        :return: the initial SP value
        :rtype: int
        """

    def e_ss(self) -> int:
        """
        Returns the initial (relative) SS value.
        
        :return: the initial (relative) SS value
        :rtype: int
        """

    def getProcessorName(self) -> str:
        """
        Returns the processor name.
        
        :return: the processor name
        :rtype: str
        """

    def hasNewExeHeader(self) -> bool:
        """
        Returns true if a new EXE header exists.
        
        :return: true if a new EXE header exists
        :rtype: bool
        """

    def hasPeHeader(self) -> bool:
        """
        Returns true if a PE header exists.
        
        :return: true if a PE header exists
        :rtype: bool
        """

    def isDosSignature(self) -> bool:
        """
        Returns true if the DOS magic number is correct
        
        :return: true if the DOS magic number is correct
        :rtype: bool
        """

    @property
    def processorName(self) -> java.lang.String:
        ...

    @property
    def dosSignature(self) -> jpype.JBoolean:
        ...


class DOSHeader(OldDOSHeader):
    """
    This class represents the ``IMAGE_DOS_HEADER`` struct
    as defined in **``winnt.h``**.
     
    
     
    typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
        WORD   e_magic;                     // Magic number                                // MANDATORY
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words                            // MANDATORY
        LONG   e_lfanew;                    // File address of new exe header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "IMAGE_DOS_HEADER"
    """
    The name to use when converting into a structure data type.
    """

    SIZEOF_DOS_HEADER: typing.Final = 64

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Constructs a new DOS header.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader
        :raises IOException: if there was an IO-related error
        """

    def decrementStub(self, start: typing.Union[jpype.JInt, int]):
        ...

    def e_lfanew(self) -> int:
        """
        Returns the file address of new EXE header.
        
        :return: the file address of new EXE header
        :rtype: int
        """

    def e_oemid(self) -> int:
        """
        Returns the OEM identifier (for e_oeminfo).
        
        :return: the OEM identifier (for e_oeminfo)
        :rtype: int
        """

    def e_oeminfo(self) -> int:
        """
        Returns the OEM information; e_oemid specific.
        
        :return: the OEM information; e_oemid specific
        :rtype: int
        """

    def e_res(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the reserved words.
        
        :return: the reserved words
        :rtype: jpype.JArray[jpype.JShort]
        """

    def e_res2(self) -> jpype.JArray[jpype.JShort]:
        """
        Returns the reserved words (2).
        
        :return: the reserved words (2)
        :rtype: jpype.JArray[jpype.JShort]
        """

    def getName(self) -> str:
        """
        Helper to override the value of name
        
        :return: The name of the header
        :rtype: str
        """

    def getProgramLen(self) -> int:
        """
        Returns the length (in bytes) of the DOS
        program.
         
        
        In other words:
        ``e_lfanew() - SIZEOF_DOS_HEADER``
        
        :return: the length (in bytes)
        :rtype: int
        """

    def hasNewExeHeader(self) -> bool:
        """
        Returns true if a new EXE header exists.
        
        :return: true if a new EXE header exists
        :rtype: bool
        """

    def hasPeHeader(self) -> bool:
        """
        Returns true if a PE header exists.
        
        :return: true if a PE header exists
        :rtype: bool
        """

    @property
    def programLen(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class MzRelocation(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "OLD_IMAGE_DOS_RELOC"
    """
    The name to use when converting into a structure data type.
    """


    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Constructs a new old-style MZ relocation
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the relocation
        :raises IOException: if there was an IO-related error
        """

    def getOffset(self) -> int:
        """
        Gets the offset
        
        :return: The offset
        :rtype: int
        """

    def getSegment(self) -> int:
        """
        Gets the segment
        
        :return: The segment
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def segment(self) -> jpype.JInt:
        ...



__all__ = ["MzExecutable", "OldDOSHeader", "DOSHeader", "MzRelocation"]
