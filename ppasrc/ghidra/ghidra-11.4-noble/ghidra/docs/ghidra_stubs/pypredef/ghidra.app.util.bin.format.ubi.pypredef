from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import java.lang # type: ignore
import java.util # type: ignore


class FatHeader(java.lang.Object):
    """
    Represents a fat_header structure.
    
    
    .. seealso::
    
        | `mach-o/fat.h <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h>`_
    
        | `mach/machine.h <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h>`_
    """

    class_: typing.ClassVar[java.lang.Class]
    FAT_MAGIC: typing.Final = -889275714
    FAT_CIGAM: typing.Final = -1095041334

    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def getArchitectures(self) -> java.util.List[FatArch]:
        ...

    def getFatArchitectureCount(self) -> int:
        ...

    def getMachHeaders(self) -> java.util.List[ghidra.app.util.bin.format.macho.MachHeader]:
        ...

    def getMachSizes(self) -> java.util.List[java.lang.Long]:
        ...

    def getMachStarts(self) -> java.util.List[java.lang.Long]:
        ...

    def getMagic(self) -> int:
        ...

    @property
    def magic(self) -> jpype.JInt:
        ...

    @property
    def machSizes(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def architectures(self) -> java.util.List[FatArch]:
        ...

    @property
    def machStarts(self) -> java.util.List[java.lang.Long]:
        ...

    @property
    def machHeaders(self) -> java.util.List[ghidra.app.util.bin.format.macho.MachHeader]:
        ...

    @property
    def fatArchitectureCount(self) -> jpype.JInt:
        ...


class UbiException(java.lang.Exception):
    """
    An exception class to handle encountering
    invalid UBI Headers.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs a new exception with the specified detail message.
        
        :param java.lang.String or str message: the detail message.
        """

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        """
        Constructs a new exception with the specified cause and a detail message.
        
        :param java.lang.Exception cause: the cause (which is saved for later retrieval by the method
        """


class FatArch(java.lang.Object):
    """
    Represents a fat_arch structure.
    
    
    .. seealso::
    
        | `mach-o/fat.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html>`_
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getAlign(self) -> int:
        """
        Returns the alignment as a power of 2.
        
        :return: the alignment as a power of 2
        :rtype: int
        """

    def getCpuSubType(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`CpuSubTypes`
        """

    def getCpuType(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`CpuTypes`
        """

    def getOffset(self) -> int:
        """
        Returns the file offset to this object file.
        
        :return: the file offset to this object file
        :rtype: int
        """

    def getSize(self) -> int:
        """
        Returns the size of this object file.
        
        :return: the size of this object file
        :rtype: int
        """

    @property
    def cpuType(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def cpuSubType(self) -> jpype.JInt:
        ...

    @property
    def align(self) -> jpype.JInt:
        ...



__all__ = ["FatHeader", "UbiException", "FatArch"]
