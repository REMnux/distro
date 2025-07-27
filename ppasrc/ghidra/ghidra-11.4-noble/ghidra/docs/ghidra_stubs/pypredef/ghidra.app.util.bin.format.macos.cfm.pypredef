from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class CFragSymbolClass(java.lang.Enum[CFragSymbolClass]):

    class_: typing.ClassVar[java.lang.Class]
    kCodeCFragSymbol: typing.Final[CFragSymbolClass]
    kDataCFragSymbol: typing.Final[CFragSymbolClass]
    kTVectorCFragSymbol: typing.Final[CFragSymbolClass]
    kTOCCFragSymbol: typing.Final[CFragSymbolClass]
    kGlueCFragSymbol: typing.Final[CFragSymbolClass]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CFragSymbolClass:
        ...

    @staticmethod
    def values() -> jpype.JArray[CFragSymbolClass]:
        ...


class CFragResource(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getMemberCount(self) -> int:
        ...

    def getMembers(self) -> java.util.List[CFragResourceMember]:
        ...

    def getVersion(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def members(self) -> java.util.List[CFragResourceMember]:
        ...

    @property
    def memberCount(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...


class CodeFragmentManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CFragUsage2Union(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    kNoAppSubFolder: typing.Final = 0

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getApplicationSubdirectoryID(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def applicationSubdirectoryID(self) -> jpype.JShort:
        ...


class CFragLocatorKind(java.lang.Enum[CFragLocatorKind]):
    """
    Values for type CFragLocatorKind.
    """

    class_: typing.ClassVar[java.lang.Class]
    kMemoryCFragLocator: typing.Final[CFragLocatorKind]
    """
    Container is in memory.
    """

    kDataForkCFragLocator: typing.Final[CFragLocatorKind]
    """
    Container is in a file's data fork.
    """

    kResourceCFragLocator: typing.Final[CFragLocatorKind]
    """
    Container is in a file's resource fork.
    """

    kNamedFragmentCFragLocator: typing.Final[CFragLocatorKind]
    """
    Reserved for possible future use.
    """

    kCFBundleCFragLocator: typing.Final[CFragLocatorKind]
    """
    Container is in the executable of a CFBundle.
    """

    kCFBundlePreCFragLocator: typing.Final[CFragLocatorKind]
    """
    Passed to init routines in lieu of kCFBundleCFragLocator.
    """


    @staticmethod
    def get(reader: ghidra.app.util.bin.BinaryReader) -> CFragLocatorKind:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CFragLocatorKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[CFragLocatorKind]:
        ...


class CFragWhere2Union(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getReserved(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def reserved(self) -> jpype.JShort:
        ...


class CFragResourceMember(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]
    kNullCFragVersion: typing.Final = 0
    kWildcardCFragVersion: typing.Final = -1

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getArchitecture(self) -> str:
        ...

    def getCurrentVersion(self) -> int:
        ...

    def getExtensionCount(self) -> int:
        ...

    def getLength(self) -> int:
        ...

    def getMemberSize(self) -> int:
        ...

    def getName(self) -> str:
        ...

    def getOffset(self) -> int:
        ...

    def getOldDefVersion(self) -> int:
        ...

    def getUUsage1(self) -> CFragUsage1Union:
        ...

    def getUUsage2(self) -> CFragUsage2Union:
        ...

    def getUWhere1(self) -> CFragWhere1Union:
        ...

    def getUWhere2(self) -> CFragWhere2Union:
        ...

    def getUpdateLevel(self) -> int:
        ...

    def getUsage(self) -> CFragUsage:
        ...

    def getWhere(self) -> CFragLocatorKind:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def uUsage2(self) -> CFragUsage2Union:
        ...

    @property
    def uUsage1(self) -> CFragUsage1Union:
        ...

    @property
    def updateLevel(self) -> jpype.JByte:
        ...

    @property
    def oldDefVersion(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def usage(self) -> CFragUsage:
        ...

    @property
    def uWhere1(self) -> CFragWhere1Union:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def extensionCount(self) -> jpype.JInt:
        ...

    @property
    def currentVersion(self) -> jpype.JInt:
        ...

    @property
    def memberSize(self) -> jpype.JInt:
        ...

    @property
    def uWhere2(self) -> CFragWhere2Union:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def where(self) -> CFragLocatorKind:
        ...

    @property
    def architecture(self) -> java.lang.String:
        ...


class CFragWhere1Union(ghidra.app.util.bin.StructConverter):

    class_: typing.ClassVar[java.lang.Class]

    def getSpaceID(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def spaceID(self) -> jpype.JInt:
        ...


class CFragUpdateLevel(java.lang.Enum[CFragUpdateLevel]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CFragUpdateLevel:
        ...

    @staticmethod
    def values() -> jpype.JArray[CFragUpdateLevel]:
        ...


class CFragArchitecture(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    kPowerPCCFragArch: typing.Final = "pwpc"
    kMotorola68KCFragArch: typing.Final = "m68k"
    kAnyCFragArch: typing.Final = "????"

    def __init__(self):
        ...


class CFM_Util(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def alignToFour(aValue: typing.Union[jpype.JInt, int]) -> int:
        ...


class CFragUsage1Union(ghidra.app.util.bin.StructConverter):
    """
    If the fragment is an application, appStackSize indicates 
    the application stack size. 
    Typically appStackSize has the value kDefaultStackSize.
    """

    class_: typing.ClassVar[java.lang.Class]
    kDefaultStackSize: typing.Final = 0

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def getAppStackSize(self) -> int:
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def appStackSize(self) -> jpype.JInt:
        ...


class CFragUsage(java.lang.Enum[CFragUsage]):
    """
    Values for type CFragUsage
    """

    class_: typing.ClassVar[java.lang.Class]
    kImportLibraryCFrag: typing.Final[CFragUsage]
    """
    Standard CFM import library.
    """

    kApplicationCFrag: typing.Final[CFragUsage]
    """
    MacOS application.
    """

    kDropInAdditionCFrag: typing.Final[CFragUsage]
    """
    Application or library private extension/plug-in.
    """

    kStubLibraryCFrag: typing.Final[CFragUsage]
    """
    Import library used for linking only.
    """

    kWeakStubLibraryCFrag: typing.Final[CFragUsage]
    """
    Import library used for linking only and will be automatically weak linked.
    """


    @staticmethod
    def get(reader: ghidra.app.util.bin.BinaryReader) -> CFragUsage:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CFragUsage:
        ...

    @staticmethod
    def values() -> jpype.JArray[CFragUsage]:
        ...



__all__ = ["CFragSymbolClass", "CFragResource", "CodeFragmentManager", "CFragUsage2Union", "CFragLocatorKind", "CFragWhere2Union", "CFragResourceMember", "CFragWhere1Union", "CFragUpdateLevel", "CFragArchitecture", "CFM_Util", "CFragUsage1Union", "CFragUsage"]
