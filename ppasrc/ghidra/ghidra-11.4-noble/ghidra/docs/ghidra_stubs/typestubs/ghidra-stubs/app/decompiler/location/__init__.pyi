from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.decompiler
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class FunctionNameDecompilerLocation(ghidra.program.util.FunctionNameFieldLocation, ghidra.app.decompiler.DecompilerLocation):
    """
    A location created when a function name is clicked in the Decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, funcionName: typing.Union[java.lang.String, str], info: ghidra.app.decompiler.DecompilerLocationInfo):
        ...

    @typing.overload
    def __init__(self):
        ...


class DefaultDecompilerLocation(ghidra.program.util.ProgramLocation, ghidra.app.decompiler.DecompilerLocation):
    """
    The default location handed out when the user clicks inside of the Decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, info: ghidra.app.decompiler.DecompilerLocationInfo):
        ...

    @typing.overload
    def __init__(self):
        ...


class VariableDecompilerLocation(ghidra.program.util.VariableLocFieldLocation, ghidra.app.decompiler.DecompilerLocation):
    """
    A location created when a function variable is clicked in the Decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, info: ghidra.app.decompiler.DecompilerLocationInfo):
        ...

    @typing.overload
    def __init__(self):
        ...



__all__ = ["FunctionNameDecompilerLocation", "DefaultDecompilerLocation", "VariableDecompilerLocation"]
