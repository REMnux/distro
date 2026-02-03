from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.pe.cli.streams
import java.lang # type: ignore
import java.util # type: ignore


class CliStreamHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    A structure used by a :obj:`CliMetadataRoot` describe a :obj:`CliAbstractStream`.
     
    
    Note that this type of "header" isn't found at the start of the stream, but as
    elements of a list of headers at the end of a :obj:`CliMetadataRoot`.  They 
    are kind of like PE section headers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, metadataRoot: CliMetadataRoot, reader: ghidra.app.util.bin.BinaryReader):
        """
        Constructs a new CLI Stream Header datatype.
        
        :param CliMetadataRoot metadataRoot: the metadata root.
        :param ghidra.app.util.bin.BinaryReader reader: A binary reader set to start reading at the start of this header.
        :raises IOException: if there is a problem reading the header.
        """

    def getMetadataRoot(self) -> CliMetadataRoot:
        """
        Gets the :obj:`CliMetadataRoot` that contains us.
        
        :return: The :obj:`CliMetadataRoot` that contains us.
        :rtype: CliMetadataRoot
        """

    def getName(self) -> str:
        """
        Gets the name of this header's stream.
        
        :return: The name of this header's stream.
        :rtype: str
        """

    def getNameLength(self) -> int:
        """
        Gets the name length.
         
        
        The name length may be larger than necessary because the name string is must
        be aligned to the next 4-byte boundary.
        
        :return: The name length.
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        Gets the offset.  This is not a file offset, but an offset that gets added to 
        the metadata header's offset to obtain a file offset.
        
        :return: The offset.
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Gets the size of this header's stream.
        
        :return: The size of this header's stream.
        :rtype: int
        """

    def getStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream:
        """
        Gets the :obj:`CliAbstractStream` that this is a header for.
        
        :return: The :obj:`CliAbstractStream` that this is a header for.  Could be null if we
        don't support the stream type.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def nameLength(self) -> jpype.JInt:
        ...

    @property
    def metadataRoot(self) -> CliMetadataRoot:
        ...

    @property
    def stream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class CliMetadataDirectory(ghidra.app.util.bin.format.pe.DataDirectory, ghidra.app.util.bin.StructConverter):
    """
    The Metadata directory pointed found in :obj:`ImageCor20Header`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ntHeader: ghidra.app.util.bin.format.pe.NTHeader, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getMetadataRoot(self) -> CliMetadataRoot:
        """
        Gets the Metadata root.
        
        :return: header The Metadata root.
        :rtype: CliMetadataRoot
        """

    @property
    def metadataRoot(self) -> CliMetadataRoot:
        ...


class CliMetadataRoot(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    The header of a :obj:`CliMetadataDirectory`.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "CLI_METADATA_HEADER"
    PATH: typing.Final = "/PE/CLI"

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JInt, int]):
        """
        Constructs a new CLI Metadata Root datatype. Matches ISO 23271 II.24.2.
        
        :param ghidra.app.util.bin.BinaryReader reader: A binary reader set to start reading at the start of this header.
        :param jpype.JInt or int rva: The RVA of this header.
        :raises IOException: if there is a problem reading the header.
        """

    def getBlobOffsetAtIndex(self, index: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getBlobStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamBlob:
        """
        Gets the blob stream.
        
        :return: The blob stream.  Could be null if it did not parse correctly.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliStreamBlob
        """

    def getFileOffset(self) -> int:
        """
        Gets the file offset of this header.
        
        :return: The file offset of this header.
        :rtype: int
        """

    def getFlags(self) -> int:
        """
        Gets the flags.
         
        
        Should always be 0.
        
        :return: The flags.
        :rtype: int
        """

    def getGuidStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamGuid:
        """
        Gets the GUID stream.
        
        :return: The GUID stream.  Could be null if it did not parse correctly.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliStreamGuid
        """

    def getMajorVersion(self) -> int:
        """
        Gets the major version.
        
        :return: The major version.
        :rtype: int
        """

    def getMetadataStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata:
        """
        Gets the Metadata stream.
        
        :return: The Metadata stream.  Could be null if it did not parse correctly.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata
        """

    def getMinorVersion(self) -> int:
        """
        Gets the minor version.
        
        :return: The minor version.
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        Gets the reserved field.  
         
        
        Should always be 0.
        
        :return: The reserved field.
        :rtype: int
        """

    def getRva(self) -> int:
        """
        Gets the relative virtual address of this header.
        
        :return: The relative virtual address of this header.
        :rtype: int
        """

    def getSignature(self) -> int:
        """
        Gets the signature.  
         
        
        Should always be 0x424a5342.
        
        :return: The signature.
        :rtype: int
        """

    def getStreamHeader(self, name: typing.Union[java.lang.String, str]) -> CliStreamHeader:
        """
        Gets the stream header with the given name.
        
        :param java.lang.String or str name: The name of the stream header to get.
        :return: The stream header that matches the given name, or null if it wasn't found.
        :rtype: CliStreamHeader
        """

    def getStreamHeaders(self) -> java.util.Collection[CliStreamHeader]:
        """
        Gets the stream headers.
        
        :return: A collection of stream headers.
        :rtype: java.util.Collection[CliStreamHeader]
        """

    def getStreamsCount(self) -> int:
        """
        Gets the number of streams present in the metadata.
        
        :return: The number of streams present in the metadata.
        :rtype: int
        """

    def getStringsStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamStrings:
        """
        Gets the strings stream.
        
        :return: The strings stream.  Could be null if it did not parse correctly.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliStreamStrings
        """

    def getUserStringsStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamUserStrings:
        """
        Gets the user strings stream.
        
        :return: The user strings stream.  Could be null if it did not parse correctly.
        :rtype: ghidra.app.util.bin.format.pe.cli.streams.CliStreamUserStrings
        """

    def getVersion(self) -> str:
        """
        Gets the version string.
        
        :return: The version string.  Could be null if the version length appeared
        too long during parsing of the header.
        :rtype: str
        """

    def getVersionLength(self) -> int:
        """
        Gets the length of the version string that follows the length field.
        
        :return: The length of the version string that follows the length field.
        :rtype: int
        """

    def parse(self) -> bool:
        ...

    @property
    def userStringsStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamUserStrings:
        ...

    @property
    def streamsCount(self) -> jpype.JShort:
        ...

    @property
    def signature(self) -> jpype.JInt:
        ...

    @property
    def blobStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamBlob:
        ...

    @property
    def flags(self) -> jpype.JShort:
        ...

    @property
    def fileOffset(self) -> jpype.JLong:
        ...

    @property
    def metadataStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata:
        ...

    @property
    def majorVersion(self) -> jpype.JShort:
        ...

    @property
    def version(self) -> java.lang.String:
        ...

    @property
    def guidStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamGuid:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def streamHeader(self) -> CliStreamHeader:
        ...

    @property
    def blobOffsetAtIndex(self) -> jpype.JInt:
        ...

    @property
    def versionLength(self) -> jpype.JInt:
        ...

    @property
    def stringsStream(self) -> ghidra.app.util.bin.format.pe.cli.streams.CliStreamStrings:
        ...

    @property
    def streamHeaders(self) -> java.util.Collection[CliStreamHeader]:
        ...

    @property
    def rva(self) -> jpype.JInt:
        ...

    @property
    def minorVersion(self) -> jpype.JShort:
        ...


class CliRepresentable(java.lang.Object):
    """
    Describes the methods necessary to get a long and short representation, with or without an metadata stream.
    This is used in the token analyzer to cut down on duplication across modules.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getRepresentation(self) -> str:
        ...

    @typing.overload
    def getRepresentation(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata) -> str:
        ...

    @typing.overload
    def getShortRepresentation(self) -> str:
        ...

    @typing.overload
    def getShortRepresentation(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata) -> str:
        ...

    @property
    def shortRepresentation(self) -> java.lang.String:
        ...

    @property
    def representation(self) -> java.lang.String:
        ...



__all__ = ["CliStreamHeader", "CliMetadataDirectory", "CliMetadataRoot", "CliRepresentable"]
