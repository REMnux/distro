from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.analysis
import ghidra.framework.cmd
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.listing


class CoffBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ElfBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class AppleSingleDoubleBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CoffArchiveBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class PortableExecutableBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class PefBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class MachoBinaryAnalysisCommand(ghidra.program.flatapi.FlatProgramAPI, ghidra.framework.cmd.BinaryAnalysisCommand, ghidra.app.plugin.core.analysis.AnalysisWorker):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, module: ghidra.program.model.listing.ProgramModule) -> None:
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, isRelativeToAddress: typing.Union[jpype.JBoolean, bool], module: ghidra.program.model.listing.ProgramModule) -> None:
        ...



__all__ = ["CoffBinaryAnalysisCommand", "ElfBinaryAnalysisCommand", "AppleSingleDoubleBinaryAnalysisCommand", "CoffArchiveBinaryAnalysisCommand", "PortableExecutableBinaryAnalysisCommand", "PefBinaryAnalysisCommand", "MachoBinaryAnalysisCommand"]
