from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.datatype.microsoft
import ghidra.framework.options
import java.lang # type: ignore


class PdbParserConstants(java.lang.Object):
    """
    Program Information options related to PDB data.  All option keys specified
    by this constants file are children of the Program Information options.  Example:
     
        Options options = program.getOptions(:obj:`Program.PROGRAM_INFO`);
        boolean isPdbLoaded = options.getBoolean(:obj:`.PDB_LOADED`, false);
    """

    class_: typing.ClassVar[java.lang.Class]
    PDB_LOADED: typing.Final = "PDB Loaded"
    """
    Option key which indicates if PDB has been loaded/applied to program (Boolean).
    """

    PDB_FILE: typing.Final = "PDB File"
    """
    Option key which indicates PDB filename or path as specified by loaded program (String).
    """

    PDB_AGE: typing.Final = "PDB Age"
    """
    Option key which indicates PDB Age as specified by loaded program (String, hex value without 0x prefix).
    """

    PDB_SIGNATURE: typing.Final = "PDB Signature"
    """
    Option key which indicates PDB Signature as specified by loaded program (String).
    """

    PDB_VERSION: typing.Final = "PDB Version"
    """
    Option key which indicates PDB Version as specified by loaded program (String).
    """

    PDB_GUID: typing.Final = "PDB GUID"
    """
    Option key which indicates PDB GUID as specified by loaded program (String).
    """


    def __init__(self):
        ...


class PdbInfo(java.lang.Object):
    """
    Bag of information about a Pdb symbol file, usually extracted from information present in a PE
    binary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isValid(self) -> bool:
        """
        Returns true if this instance is valid.
        
        :return: boolean true if valid (magic signature matches and fields have valid data)
        :rtype: bool
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, offset: typing.Union[jpype.JLong, int]) -> PdbInfo:
        """
        Read either a :obj:`PdbInfoCodeView` object or a :obj:`PdbInfoDotNet` object
        from the BinaryReader of a PE binary.
        
        :param ghidra.app.util.bin.BinaryReader reader: BinaryReader
        :param jpype.JLong or int offset: position of the debug info
        :return: new PdbInfoCodeView or PdbInfoDotNet object
        :rtype: PdbInfo
        :raises IOException: if error
        """

    def serializeToOptions(self, options: ghidra.framework.options.Options):
        """
        Writes the various PDB info fields to a program's options.
        
        :param ghidra.framework.options.Options options: Options of a Program to write to
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...


class PdbInfoDotNet(ghidra.app.util.bin.StructConverter, PdbInfo):
    """
    Newer style pdb information, using a GUID to link the pdb to its binary.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def fromValues(pdbPath: typing.Union[java.lang.String, str], age: typing.Union[jpype.JInt, int], guid: ghidra.app.util.datatype.microsoft.GUID) -> PdbInfoDotNet:
        """
        Creates an instance from explicit values.
        
        :param java.lang.String or str pdbPath: String path / filename of the pdb file
        :param jpype.JInt or int age: age
        :param ghidra.app.util.datatype.microsoft.GUID guid: :obj:`GUID`
        :return: new instance, never null
        :rtype: PdbInfoDotNet
        """

    @staticmethod
    def isMatch(reader: ghidra.app.util.bin.BinaryReader, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the pdb information at the specified offset is a :obj:`PdbInfoDotNet`
        type (based on the signature at that offset).
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader`
        :param jpype.JLong or int offset: offset of the Pdb information
        :return: boolean true if it is a :obj:`PdbInfoDotNet` type
        :rtype: bool
        :raises IOException: if error reading data
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, offset: typing.Union[jpype.JLong, int]) -> PdbInfoDotNet:
        """
        Reads an instance from the stream.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` to read from
        :param jpype.JLong or int offset: position of the pdb info
        :return: new instance, never null
        :rtype: PdbInfoDotNet
        :raises IOException: if IO error or data format error
        """


class PdbInfoCodeView(ghidra.app.util.bin.StructConverter, PdbInfo):
    """
    Older style pdb information, using a simple 32bit hash to link the pdb to its binary.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def isMatch(reader: ghidra.app.util.bin.BinaryReader, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Returns true if the pdb information at the specified offset is a :obj:`PdbInfoCodeView`
        type (based on the signature at that offset).
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader`
        :param jpype.JLong or int offset: offset of the Pdb information
        :return: boolean true if it is a :obj:`PdbInfoCodeView` type
        :rtype: bool
        :raises IOException: if error reading data
        """

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, offset: typing.Union[jpype.JLong, int]) -> PdbInfoCodeView:
        """
        Reads the pdb information from a PE binary.
        
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader`
        :param jpype.JLong or int offset: offset of the Pdb information
        :return: new :obj:`PdbInfoCodeView` instance, never null
        :rtype: PdbInfoCodeView
        :raises IOException: if error reading data
        """



__all__ = ["PdbParserConstants", "PdbInfo", "PdbInfoDotNet", "PdbInfoCodeView"]
