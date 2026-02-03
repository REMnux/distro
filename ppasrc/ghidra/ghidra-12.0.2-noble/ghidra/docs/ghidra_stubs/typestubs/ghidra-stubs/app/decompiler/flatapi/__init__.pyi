from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.decompiler
import ghidra.program.flatapi
import ghidra.program.model.listing
import ghidra.util
import java.lang # type: ignore


class FlatDecompilerAPI(ghidra.util.Disposable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Initializes without a provided FlatProgramAPI instance...this must be set before
        using the FlatDecompilerAPI!
        """

    @typing.overload
    def __init__(self, flatProgramAPI: ghidra.program.flatapi.FlatProgramAPI):
        """
        Initializes with a provided FlatProgramAPI instance.
        
        :param ghidra.program.flatapi.FlatProgramAPI flatProgramAPI: the FlatProgramAPI instance.
        """

    @typing.overload
    def decompile(self, function: ghidra.program.model.listing.Function) -> str:
        """
        Decompiles the specified function and returns a
        string containing the decompilation.
        This call does not impose a timeout.
        
        :param ghidra.program.model.listing.Function function: the function to decompile
        :return: a string containing the decompilation
        :rtype: str
        """

    @typing.overload
    def decompile(self, function: ghidra.program.model.listing.Function, timeoutSecs: typing.Union[jpype.JInt, int]) -> str:
        """
        Decompiles the specified function and returns a
        string containing the decompilation.
        
        :param ghidra.program.model.listing.Function function: the function to decompile
        :param jpype.JInt or int timeoutSecs: maximum time allowed for decompile to complete.
        :return: a string containing the decompilation
        :rtype: str
        """

    def dispose(self):
        """
        Disposes of the decompiler resources by calling currentDecompiler.dispose().
        """

    def getDecompiler(self) -> ghidra.app.decompiler.DecompInterface:
        """
        Gets the actual decompiler (may be null if not initialized).
        
        :return: the decompiler
        :rtype: ghidra.app.decompiler.DecompInterface
        """

    def initialize(self):
        """
        Initializes the decompiler instance.
        """

    @property
    def decompiler(self) -> ghidra.app.decompiler.DecompInterface:
        ...



__all__ = ["FlatDecompilerAPI"]
