from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class MachoPrelinkConstants(java.lang.Object):
    """
    Taken from:
    http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/libkern/libkern/prelink.h
    """

    class_: typing.ClassVar[java.lang.Class]
    TITLE: typing.Final = "iOS Prelink"
    kPrelinkSegment_iOS_1x: typing.Final = "__PRELINK"
    kPrelinkTextSegment: typing.Final = "__PRELINK_TEXT"
    kPrelinkTextSection: typing.Final = "__text"
    kPrelinkStateSegment: typing.Final = "__PRELINK_STATE"
    kPrelinkKernelLinkStateSection: typing.Final = "__kernel"
    kPrelinkKextsLinkStateSection: typing.Final = "__kexts"
    kPrelinkInfoSegment: typing.Final = "__PRELINK_INFO"
    kPrelinkInfoSection: typing.Final = "__info"
    kPrelinkBundlePathKey: typing.Final = "_PrelinkBundlePath"
    kPrelinkExecutableKey: typing.Final = "_PrelinkExecutable"
    kPrelinkExecutableLoadKey: typing.Final = "_PrelinkExecutableLoadAddr"
    kPrelinkExecutableSourceKey: typing.Final = "_PrelinkExecutableSourceAddr"
    kPrelinkExecutableSizeKey: typing.Final = "_PrelinkExecutableSize"
    kPrelinkInfoDictionaryKey: typing.Final = "_PrelinkInfoDictionary"
    kPrelinkInterfaceUUIDKey: typing.Final = "_PrelinkInterfaceUUID"
    kPrelinkKmodInfoKey: typing.Final = "_PrelinkKmodInfo"
    kPrelinkLinkStateKey: typing.Final = "_PrelinkLinkState"
    kPrelinkLinkStateSizeKey: typing.Final = "_PrelinkLinkStateSize"
    kPrelinkPersonalitiesKey: typing.Final = "_PrelinkPersonalities"
    kPrelinkModuleIndexKey: typing.Final = "ModuleIndex"

    def __init__(self):
        ...


class MachoPrelinkMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getPrelinkBundlePath(self) -> str:
        ...

    def getPrelinkExecutable(self) -> int:
        ...

    def getPrelinkExecutableLoadAddr(self) -> int:
        ...

    def getPrelinkExecutableSize(self) -> int:
        ...

    def getPrelinkKmodInfo(self) -> int:
        ...

    def getPrelinkModuleIndex(self) -> int:
        ...

    def getPrelinkUUID(self) -> str:
        ...

    @typing.overload
    def put(self, key: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def put(self, key: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def put(self, key: typing.Union[java.lang.String, str], value: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def put(self, key: typing.Union[java.lang.String, str], value: MachoPrelinkMap):
        ...

    @property
    def prelinkExecutable(self) -> jpype.JLong:
        ...

    @property
    def prelinkExecutableLoadAddr(self) -> jpype.JLong:
        ...

    @property
    def prelinkUUID(self) -> java.lang.String:
        ...

    @property
    def prelinkModuleIndex(self) -> jpype.JLong:
        ...

    @property
    def prelinkKmodInfo(self) -> jpype.JLong:
        ...

    @property
    def prelinkExecutableSize(self) -> jpype.JLong:
        ...

    @property
    def prelinkBundlePath(self) -> java.lang.String:
        ...


class MachoPrelinkParser(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mainHeader: ghidra.app.util.bin.format.macho.MachHeader, provider: ghidra.app.util.bin.ByteProvider):
        ...

    def parse(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MachoPrelinkMap]:
        ...


class NoPreLinkSectionException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...



__all__ = ["MachoPrelinkConstants", "MachoPrelinkMap", "MachoPrelinkParser", "NoPreLinkSectionException"]
