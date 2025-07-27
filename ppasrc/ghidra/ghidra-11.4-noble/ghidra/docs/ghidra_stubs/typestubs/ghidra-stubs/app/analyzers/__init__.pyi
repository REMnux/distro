from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task


class CoffAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AppleSingleDoubleAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MachoAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CoffArchiveAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PefAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CondenseFillerBytesAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractBinaryFormatAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        ...

    def canAnalyze(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def getDefaultEnablement(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    @property
    def defaultEnablement(self) -> jpype.JBoolean:
        ...


class PortableExecutableAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ElfAnalyzer(AbstractBinaryFormatAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["CoffAnalyzer", "AppleSingleDoubleAnalyzer", "MachoAnalyzer", "CoffArchiveAnalyzer", "PefAnalyzer", "CondenseFillerBytesAnalyzer", "AbstractBinaryFormatAnalyzer", "PortableExecutableAnalyzer", "ElfAnalyzer"]
