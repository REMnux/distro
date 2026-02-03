from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.dnd
import ghidra.program.model.symbol
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class SymbolTransferData(java.lang.Object):
    """
    A simple object to transfer a list of symbols along with the source of the transfer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: java.awt.Component, symbols: java.util.List[ghidra.program.model.symbol.Symbol]):
        ...

    def getSource(self) -> java.awt.Component:
        ...

    def getSymbols(self) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        ...

    @property
    def source(self) -> java.awt.Component:
        ...

    @property
    def symbols(self) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        ...


class SymbolTransferable(java.awt.datatransfer.Transferable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: java.awt.Component, symbols: java.util.List[ghidra.program.model.symbol.Symbol]):
        ...


class SymbolDataFlavor(docking.dnd.GenericDataFlavor):
    """
    A simple data flavor for :obj:`Symbol` objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_FLAVOR: typing.Final[java.awt.datatransfer.DataFlavor]

    def __init__(self):
        ...



__all__ = ["SymbolTransferData", "SymbolTransferable", "SymbolDataFlavor"]
