from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.elf
import ghidra.program.model.address
import ghidra.util
import java.io # type: ignore
import java.lang # type: ignore
import java.util.function # type: ignore


class MemoryLoadable(java.lang.Object):
    """
    ``MemoryLoadable`` serves as both a marker interface which identifies a memory 
    loadable portion of a binary file (supports use as a :obj:`Hashtable` key).  In addition,
    it serves to supply the neccessary input stream to create a :obj:`MemoryBlock`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address, dataLength: typing.Union[jpype.JLong, int], errorConsumer: java.util.function.BiConsumer[java.lang.String, java.lang.Throwable]) -> java.io.InputStream:
        """
        Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
        See :meth:`hasFilteredLoadInputStream(ElfLoadHelper, Address) <.hasFilteredLoadInputStream>`.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: ELF load helper
        :param ghidra.program.model.address.Address start: memory load address
        :param jpype.JLong or int dataLength: the in-memory data length in bytes (actual bytes read from dataInput may be more)
        :param java.util.function.BiConsumer[java.lang.String, java.lang.Throwable] errorConsumer: consumer that will accept errors which may occur during stream
        decompression, if null Msg.error() will be used.
        :return: filtered input stream or original input stream
        :rtype: java.io.InputStream
        :raises IOException: if error initializing filtered input stream
        """

    def getRawInputStream(self) -> java.io.InputStream:
        """
        :return: raw data input stream associated with this loadable object.
        :rtype: java.io.InputStream
        
        
        :raises IOException: if error initializing input stream
        """

    def hasFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the use of input stream decompression or filtering via an extension is neccessary. 
        If this method returns true and a 
        :meth:`filtered stream <.getFilteredLoadInputStream>` 
        is required and will prevent the use of a direct mapping to file bytes for affected memory 
        regions.
        
        :param ghidra.app.util.bin.format.elf.ElfLoadHelper elfLoadHelper: ELF load helper
        :param ghidra.program.model.address.Address start: memory load address
        :return: true if the use of a filtered input stream is required
        :rtype: bool
        """

    @property
    def rawInputStream(self) -> java.io.InputStream:
        ...


class Writeable(java.lang.Object):
    """
    An interface for writing out class state information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def write(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter):
        """
        Writes this object to the specified random access file using
        the data converter to handle endianness.
        
        :param java.io.RandomAccessFile raf: the random access file
        :param ghidra.util.DataConverter dc: the data converter
        :raises IOException: if an I/O error occurs
        """


class RelocationException(java.lang.Exception):
    """
    ``RelocationException`` thrown when a supported relocation encounters an
    unexpected error during processing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new exception with the specified detail message.
        
        :param java.lang.String or str message: the detail message (required).
        """



__all__ = ["MemoryLoadable", "Writeable", "RelocationException"]
