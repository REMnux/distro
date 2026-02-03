from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class CodeSignatureConstants(java.lang.Object):
    """
    Code Signature constants
    
    
    .. seealso::
    
        | `osfmk/kern/cs_blobs.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    CSMAGIC_REQUIREMENT: typing.Final = -86111232
    CSMAGIC_REQUIREMENTS: typing.Final = -86111231
    CSMAGIC_CODEDIRECTORY: typing.Final = -86111230
    CSMAGIC_EMBEDDED_SIGNATURE: typing.Final = -86111040
    CSMAGIC_EMBEDDED_SIGNATURE_OLD: typing.Final = -86111486
    CSMAGIC_EMBEDDED_ENTITLEMENTS: typing.Final = -86085263
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: typing.Final = -86085262
    CSMAGIC_DETACHED_SIGNATURE: typing.Final = -86111039
    CSMAGIC_BLOBWRAPPER: typing.Final = -86111487
    CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: typing.Final = -86081151

    def __init__(self):
        ...


class CodeSignatureSuperBlob(CodeSignatureGenericBlob):
    """
    Represents a CS_SuperBlob structure
    
    
    .. seealso::
    
        | `osfmk/kern/cs_blobs.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CodeSignatureSuperBlob`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getCount(self) -> int:
        """
        :return: the number of index entries
        :rtype: int
        """

    def getIndexBlobs(self) -> java.util.List[CodeSignatureGenericBlob]:
        """
        :return: the index blobs
        :rtype: java.util.List[CodeSignatureGenericBlob]
        """

    def getIndexEntries(self) -> java.util.List[CodeSignatureBlobIndex]:
        """
        :return: the index entries
        :rtype: java.util.List[CodeSignatureBlobIndex]
        """

    @property
    def indexEntries(self) -> java.util.List[CodeSignatureBlobIndex]:
        ...

    @property
    def indexBlobs(self) -> java.util.List[CodeSignatureGenericBlob]:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...


class CodeSignatureBlobIndex(ghidra.app.util.bin.StructConverter):
    """
    Represents a CS_BlobIndex structure
    
    
    .. seealso::
    
        | `osfmk/kern/cs_blobs.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CodeSignatureBlobIndex`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getOffset(self) -> int:
        """
        :return: the offset
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the type
        :rtype: int
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class CodeSignatureBlobParser(java.lang.Object):
    """
    Class to parse Code Signature blobs
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def parse(reader: ghidra.app.util.bin.BinaryReader) -> CodeSignatureGenericBlob:
        """
        Parses a new Code Signature blob
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of a Code Signature blob
        :return: A new Code Signature blob
        :rtype: CodeSignatureGenericBlob
        :raises IOException: if there was an IO-related error parsing the blob
        """


class CodeSignatureCodeDirectory(CodeSignatureGenericBlob):
    """
    Represents a CS_BlobIndex structure
    
    
    .. seealso::
    
        | `osfmk/kern/cs_blobs.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CodeSignatureCodeDirectory`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """


class CodeSignatureGenericBlob(ghidra.app.util.bin.StructConverter):
    """
    Represents a CS_GenericBlob structure
    
    
    .. seealso::
    
        | `osfmk/kern/cs_blobs.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new :obj:`CodeSignatureGenericBlob`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the structure
        :raises IOException: if there was an IO-related problem creating the structure
        """

    def getLength(self) -> int:
        """
        :return: the length
        :rtype: int
        """

    def getMagic(self) -> int:
        """
        :return: the magic
        :rtype: int
        """

    def markup(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, header: ghidra.app.util.bin.format.macho.MachHeader, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Marks up this :obj:`CodeSignatureGenericBlob` data with data structures and comments
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to mark up
        :param ghidra.program.model.address.Address address: The :obj:`Address` of the blob
        :param ghidra.app.util.bin.format.macho.MachHeader header: The Mach-O header
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises CancelledException: if the user cancelled the operation
        """

    @property
    def magic(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...



__all__ = ["CodeSignatureConstants", "CodeSignatureSuperBlob", "CodeSignatureBlobIndex", "CodeSignatureBlobParser", "CodeSignatureCodeDirectory", "CodeSignatureGenericBlob"]
