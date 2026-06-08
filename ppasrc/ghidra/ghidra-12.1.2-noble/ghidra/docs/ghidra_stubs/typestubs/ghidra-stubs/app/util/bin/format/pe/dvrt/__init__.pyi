from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import java.lang # type: ignore
import java.util # type: ignore


class ImageArm64XDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_ARM64X_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageArm64XDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the data
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getPageRelativeOffset(self) -> int:
        """
        :return: the page relative offset
        :rtype: int
        """

    def getType(self) -> int:
        """
        :return: the type
        :rtype: int
        """

    @property
    def pageRelativeOffset(self) -> jpype.JInt:
        ...

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...


class ImageImportControlTransfer(AbstractImageDynamicRelocationHeader):
    """
    Contains a list of :obj:`ImageImportControlTransferDynamicRelocation`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageIndirControlTransfer`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getRelocs(self) -> java.util.List[ImageImportControlTransferDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`ImageImportControlTransferDynamicRelocation`s
        :rtype: java.util.List[ImageImportControlTransferDynamicRelocation]
        """

    def getSizeOfBlock(self) -> int:
        """
        :return: the size of the block
        :rtype: int
        """

    def getVirualAddress(self) -> int:
        """
        :return: the virtual address
        :rtype: int
        """

    @property
    def virualAddress(self) -> jpype.JInt:
        ...

    @property
    def sizeOfBlock(self) -> jpype.JInt:
        ...

    @property
    def relocs(self) -> java.util.List[ImageImportControlTransferDynamicRelocation]:
        ...


class ImageBddInfo(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_BDD_INFO`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageBddInfo`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getBddSize(self) -> int:
        """
        :return: the BDD size
        :rtype: int
        """

    def getVersion(self) -> int:
        """
        :return: the BDD version
        :rtype: int
        """

    @property
    def bddSize(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class DvrtType(java.lang.Enum[DvrtType], ghidra.app.util.bin.StructConverter):
    """
    Defined symbol dynamic relocation entries
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_IMPORT_CONTROL_TRANSFER: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_INDIR_CONTROL_TRANSFER: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_SWITCHABLE_BRANCH: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_ARM64X: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER: typing.Final[DvrtType]
    IMAGE_DYNAMIC_RELOCATION_UNKNOWN: typing.Final[DvrtType]

    def changeSize(self, n: typing.Union[jpype.JInt, int]) -> DvrtType:
        """
        Changes the size of this :obj:`DvrtType` to the given number of bytes
        
        :param jpype.JInt or int n: The new size in bytes
        :return: This :obj:`DvrtType`, with the new size applied
        :rtype: DvrtType
        """

    def getValue(self) -> int:
        """
        :return: the type's defined value
        :rtype: int
        """

    @staticmethod
    def type4(reader: ghidra.app.util.bin.BinaryReader) -> DvrtType:
        """
        Reads a 4-byte :obj:`DvrtType`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the type value
        :return: The type that was read, or :obj:`.IMAGE_DYNAMIC_RELOCATION_UNKNOWN` if the value 
        read does not correspond to a known type
        :rtype: DvrtType
        :raises IOException: if there was an IO-related error
        """

    @staticmethod
    def type8(reader: ghidra.app.util.bin.BinaryReader) -> DvrtType:
        """
        Reads an 8-byte :obj:`DvrtType`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the type value
        :return: The type that was read, or :obj:`.IMAGE_DYNAMIC_RELOCATION_UNKNOWN` if the value 
        read does not correspond to a known type
        :rtype: DvrtType
        :raises IOException: if there was an IO-related error
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DvrtType:
        ...

    @staticmethod
    def values() -> jpype.JArray[DvrtType]:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class ImageDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int], is64bit: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Creates a new :obj:`ImageDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :param jpype.JBoolean or bool is64bit: True if 64-bit; otherwise, false
        :raises IOException: if there was an IO-related error
        """

    def getBaseRelocSize(self) -> int:
        """
        :return: the size in bytes of the relocation
        :rtype: int
        """

    def getSymbol(self) -> DvrtType:
        """
        :return: the relocation "symbol", which is really a :obj:`type <DvrtType>`
        :rtype: DvrtType
        """

    @property
    def symbol(self) -> DvrtType:
        ...

    @property
    def baseRelocSize(self) -> jpype.JInt:
        ...


class ImageImportControlTransferDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageImportControlTransferDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :obj:`DVRT entry <ImageDynamicRelocation>`
        :raises IOException: if there was an IO-related error
        """

    def getIatIndex(self) -> int:
        """
        :return: the IAT index
        :rtype: int
        """

    def getPageRelativeOffset(self) -> int:
        """
        :return: the page relative offset
        :rtype: int
        """

    def isIndirectCall(self) -> bool:
        """
        :return: whether or not it's an indirect call
        :rtype: bool
        """

    @property
    def pageRelativeOffset(self) -> jpype.JInt:
        ...

    @property
    def iatIndex(self) -> jpype.JInt:
        ...

    @property
    def indirectCall(self) -> jpype.JBoolean:
        ...


class AbstractImageDynamicRelocationHeader(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    An abstract dynamic value relocation header
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`AbstractImageDynamicRelocationHeader`
        
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """


class ImageSwitchtableBranch(AbstractImageDynamicRelocationHeader):
    """
    Contains a list of :obj:`ImageSwitchtableBranchDynamicRelocation`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageSwitchtableBranch`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getRelocs(self) -> java.util.List[ImageSwitchtableBranchDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`ImageIndirControlTransferDynamicRelocation`s
        :rtype: java.util.List[ImageSwitchtableBranchDynamicRelocation]
        """

    def getSizeOfBlock(self) -> int:
        """
        :return: the size of the block
        :rtype: int
        """

    def getVirualAddress(self) -> int:
        """
        :return: the virtual address
        :rtype: int
        """

    @property
    def virualAddress(self) -> jpype.JInt:
        ...

    @property
    def sizeOfBlock(self) -> jpype.JInt:
        ...

    @property
    def relocs(self) -> java.util.List[ImageSwitchtableBranchDynamicRelocation]:
        ...


class ImageBddDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_BDD_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageBddInfo`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getLeft(self) -> int:
        """
        :return: the index of the FALSE edge in the BDD array
        :rtype: int
        """

    def getRight(self) -> int:
        """
        :return: the index of the TRUE edge in the BDD array
        :rtype: int
        """

    def getValue(self) -> int:
        """
        :return: either the feature number or index in RVAs array
        :rtype: int
        """

    @property
    def left(self) -> jpype.JInt:
        ...

    @property
    def right(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class ImageIndirControlTransfer(AbstractImageDynamicRelocationHeader):
    """
    Contains a list of :obj:`ImageIndirControlTransferDynamicRelocation`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageIndirControlTransfer`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getRelocs(self) -> java.util.List[ImageIndirControlTransferDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`ImageIndirControlTransferDynamicRelocation`s
        :rtype: java.util.List[ImageIndirControlTransferDynamicRelocation]
        """

    def getSizeOfBlock(self) -> int:
        """
        :return: the size of the block
        :rtype: int
        """

    def getVirualAddress(self) -> int:
        """
        :return: the virtual address
        :rtype: int
        """

    @property
    def virualAddress(self) -> jpype.JInt:
        ...

    @property
    def sizeOfBlock(self) -> jpype.JInt:
        ...

    @property
    def relocs(self) -> java.util.List[ImageIndirControlTransferDynamicRelocation]:
        ...


class ImageArm64X(AbstractImageDynamicRelocationHeader):
    """
    Contains a list of :obj:`ImageArm64XDynamicRelocation`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageIndirControlTransfer`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getRelocs(self) -> java.util.List[ImageArm64XDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`ImageArm64XDynamicRelocation`s
        :rtype: java.util.List[ImageArm64XDynamicRelocation]
        """

    def getSizeOfBlock(self) -> int:
        """
        :return: the size of the block
        :rtype: int
        """

    def getVirualAddress(self) -> int:
        """
        :return: the virtual address
        :rtype: int
        """

    @property
    def virualAddress(self) -> jpype.JInt:
        ...

    @property
    def sizeOfBlock(self) -> jpype.JInt:
        ...

    @property
    def relocs(self) -> java.util.List[ImageArm64XDynamicRelocation]:
        ...


class ImageSwitchtableBranchDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageSwitchtableBranchDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :obj:`DVRT entry <ImageDynamicRelocation>`
        :raises IOException: if there was an IO-related error
        """

    def getPageRelativeOffset(self) -> int:
        """
        :return: the page relative offset
        :rtype: int
        """

    def getRegisterNumber(self) -> int:
        """
        :return: the register number
        :rtype: int
        """

    @property
    def pageRelativeOffset(self) -> jpype.JInt:
        ...

    @property
    def registerNumber(self) -> jpype.JInt:
        ...


class ImageIndirControlTransferDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageIndirControlTransferDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getPageRelativeOffset(self) -> int:
        """
        :return: the page relative offset
        :rtype: int
        """

    def getReserved(self) -> int:
        """
        :return: the reserved bit
        :rtype: int
        """

    def isCfgCheck(self) -> bool:
        """
        :return: whether or not it's a CFG check
        :rtype: bool
        """

    def isIndirectCall(self) -> bool:
        """
        :return: whether or not it's an indirect call
        :rtype: bool
        """

    def isRexWPrefix(self) -> bool:
        """
        :return: whether or not there is a rexw prefix
        :rtype: bool
        """

    @property
    def cfgCheck(self) -> jpype.JBoolean:
        ...

    @property
    def pageRelativeOffset(self) -> jpype.JInt:
        ...

    @property
    def reserved(self) -> jpype.JInt:
        ...

    @property
    def rexWPrefix(self) -> jpype.JBoolean:
        ...

    @property
    def indirectCall(self) -> jpype.JBoolean:
        ...


class ImageUnsupportedRelocationHeader(AbstractImageDynamicRelocationHeader):
    """
    Represents an unsupported dynamic value relocation header
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> None:
        """
        Creates a new :obj:`ImageUnsupportedRelocationHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :param jpype.JInt or int size: The size in bytes of this header's data
        :raises IOException: if there was an IO-related error
        """

    def getData(self) -> jpype.JArray[jpype.JByte]:
        """
        :return: the data associated with the unknown header
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def data(self) -> jpype.JArray[jpype.JByte]:
        ...


class ImageFunctionOverrideHeader(AbstractImageDynamicRelocationHeader):
    """
    Represents a ``IMAGE_FUNCTION_OVERRIDE_HEADER`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int], dvrtEntrySize: typing.Union[jpype.JInt, int]) -> None:
        """
        Creates a new :obj:`ImageFunctionOverrideHeader`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :param jpype.JInt or int dvrtEntrySize: The size in bytes of this header's 
        :obj:`DVRT entry <ImageDynamicRelocation>`
        :raises IOException: if there was an IO-related error
        """

    def getBddInfo(self) -> java.util.List[ImageBddInfo]:
        """
        :return: the :obj:`List` of :obj:`ImageBddInfo`s
        :rtype: java.util.List[ImageBddInfo]
        """

    def getFuncOverrideInfo(self) -> java.util.List[ImageFunctionOverrideDynamicRelocation]:
        """
        :return: the :obj:`List` of :obj:`ImageFunctionOverrideDynamicRelocation`s
        :rtype: java.util.List[ImageFunctionOverrideDynamicRelocation]
        """

    def getFuncOverrideSize(self) -> int:
        """
        :return: the function override size
        :rtype: int
        """

    @property
    def funcOverrideInfo(self) -> java.util.List[ImageFunctionOverrideDynamicRelocation]:
        ...

    @property
    def bddInfo(self) -> java.util.List[ImageBddInfo]:
        ...

    @property
    def funcOverrideSize(self) -> jpype.JInt:
        ...


class ImageFunctionOverrideDynamicRelocation(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int]) -> None:
        """
        Creates a new :obj:`ImageFunctionOverrideDynamicRelocation`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :raises IOException: if there was an IO-related error
        """

    def getBaseRelocSize(self) -> int:
        """
        :return: the size in bytes taken by BaseRelocs
        :rtype: int
        """

    def getBaseRelocs(self) -> java.util.List[ghidra.app.util.bin.format.pe.BaseRelocation]:
        """
        :return: the :obj:`List` of :obj:`BaseRelocation`s
        :rtype: java.util.List[ghidra.app.util.bin.format.pe.BaseRelocation]
        """

    def getBddOffset(self) -> int:
        """
        :return: the offset into the BDD region
        :rtype: int
        """

    def getOriginalRva(self) -> int:
        """
        :return: the relative virtual address of the original function
        :rtype: int
        """

    def getRvaSize(self) -> int:
        """
        :return: the size in bytes taken by relative virtual addresses
        :rtype: int
        """

    @property
    def baseRelocs(self) -> java.util.List[ghidra.app.util.bin.format.pe.BaseRelocation]:
        ...

    @property
    def bddOffset(self) -> jpype.JInt:
        ...

    @property
    def baseRelocSize(self) -> jpype.JInt:
        ...

    @property
    def originalRva(self) -> jpype.JInt:
        ...

    @property
    def rvaSize(self) -> jpype.JInt:
        ...


class ImageDynamicRelocationTable(ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    Represents a ``IMAGE_DYNAMIC_RELOCATION_TABLE`` structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, rva: typing.Union[jpype.JLong, int], is64bit: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Creates a new :obj:`ImageDynamicRelocationTable`
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` that points to the start of the structure
        :param jpype.JLong or int rva: The relative virtual address of the structure
        :param jpype.JBoolean or bool is64bit: True if 64-bit; otherwise, false
        :raises IOException: if there was an IO-related error
        """

    def getSize(self) -> int:
        """
        :return: the size in bytes of the dynamic value relocation table
        :rtype: int
        """

    def getVersion(self) -> int:
        """
        :return: the dynamic value relocation table version
        :rtype: int
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...



__all__ = ["ImageArm64XDynamicRelocation", "ImageImportControlTransfer", "ImageBddInfo", "DvrtType", "ImageDynamicRelocation", "ImageImportControlTransferDynamicRelocation", "AbstractImageDynamicRelocationHeader", "ImageSwitchtableBranch", "ImageBddDynamicRelocation", "ImageIndirControlTransfer", "ImageArm64X", "ImageSwitchtableBranchDynamicRelocation", "ImageIndirControlTransferDynamicRelocation", "ImageUnsupportedRelocationHeader", "ImageFunctionOverrideHeader", "ImageFunctionOverrideDynamicRelocation", "ImageDynamicRelocationTable"]
