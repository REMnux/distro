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


class CommentSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, commentIterator: ghidra.program.model.address.AddressIterator):
        ...


class FunctionSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, functionIterator: ghidra.program.model.listing.FunctionIterator):
        ...


class InstructionSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instructionIterator: ghidra.program.model.listing.InstructionIterator):
        ...


class SearchAddressIterator(java.lang.Object):
    """
    A simple interface for searching that will allow for iteration over addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        ...

    def next(self) -> ghidra.program.model.address.Address:
        ...


class LabelSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, labelIterator: ghidra.program.model.symbol.SymbolIterator):
        ...


class DataSearchAddressIterator(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataIterator: ghidra.program.model.listing.DataIterator, forward: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["CommentSearchAddressIterator", "FunctionSearchAddressIterator", "InstructionSearchAddressIterator", "SearchAddressIterator", "LabelSearchAddressIterator", "DataSearchAddressIterator"]
