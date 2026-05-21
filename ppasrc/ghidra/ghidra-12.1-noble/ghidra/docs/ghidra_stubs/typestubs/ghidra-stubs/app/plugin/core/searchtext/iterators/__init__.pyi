from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang # type: ignore


class SearchAddressIterator(java.lang.Object):
    """
    A simple interface for searching that will allow for iteration over addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        ...

    def next(self) -> ghidra.program.model.address.Address:
        ...


class CommentSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, commentIterator: ghidra.program.model.address.AddressIterator) -> None:
        ...


class DataSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataIterator: ghidra.program.model.listing.DataIterator, forward: typing.Union[jpype.JBoolean, bool]) -> None:
        ...


class FunctionSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, functionIterator: ghidra.program.model.listing.FunctionIterator) -> None:
        ...


class InstructionSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instructionIterator: ghidra.program.model.listing.InstructionIterator) -> None:
        ...


class LabelSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, labelIterator: ghidra.program.model.symbol.SymbolIterator) -> None:
        ...



__all__ = ["SearchAddressIterator", "CommentSearchAddressIterator", "DataSearchAddressIterator", "FunctionSearchAddressIterator", "InstructionSearchAddressIterator", "LabelSearchAddressIterator"]
