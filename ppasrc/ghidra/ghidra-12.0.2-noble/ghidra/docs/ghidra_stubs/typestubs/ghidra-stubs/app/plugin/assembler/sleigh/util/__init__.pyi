from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.symbol
import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class TableEntryKey(java.lang.Comparable[TableEntryKey]):
    """
    A key in a (sparse) LR(0) transition table or LALR(1) action/goto table
    
    
    .. seealso::
    
        | :obj:`AssemblyParseTransitionTable`
    
        | :obj:`AssemblyParseActionGotoTable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: typing.Union[jpype.JInt, int], sym: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol):
        """
        Create a new key for the given state and symbol
        
        :param jpype.JInt or int state: the row
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol sym: the column
        """

    def getState(self) -> int:
        """
        Get the state (row) of the key in the table
        
        :return: the state
        :rtype: int
        """

    def getSym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        """
        Get the symbol (column) of the entry in the table
        
        :return: the symbol
        :rtype: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol
        """

    @property
    def sym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol:
        ...

    @property
    def state(self) -> jpype.JInt:
        ...


class TableEntry(TableEntryKey, typing.Generic[T]):
    """
    An entry in a (sparse) LR(0) transition table or LALR(1) action/goto table
    
    
    .. seealso::
    
        | :obj:`AssemblyParseTransitionTable`
    
        | :obj:`AssemblyParseActionGotoTable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: typing.Union[jpype.JInt, int], sym: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol, value: T):
        """
        Create a new table entry with the given value at the given state and symbol
        
        :param jpype.JInt or int state: the row
        :param ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol sym: the column
        :param T value: the value
        """

    def getValue(self) -> T:
        """
        Get the value of the entry
        
        :return: the value
        :rtype: T
        """

    @property
    def value(self) -> T:
        ...


class AsmUtil(java.lang.Object):
    """
    Utilities for the Assembler
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def compareArrays(a: jpype.JArray[jpype.JByte], b: jpype.JArray[jpype.JByte]) -> int:
        """
        Compare two byte arrays by their corresponding entries
         
         
        
        If the two arrays have differing lengths, the shorter precedes the longer. Otherwise, they
        are compared as in C's ``memcmp``, except that Java ``byte``s are signed.
        
        :param jpype.JArray[jpype.JByte] a: the first array
        :param jpype.JArray[jpype.JByte] b: the second array
        :return: a comparison result as in :meth:`Comparable.compareTo(Object) <Comparable.compareTo>`
        :rtype: int
        """

    @staticmethod
    def compareInOrder(a: collections.abc.Sequence, b: collections.abc.Sequence) -> int:
        """
        Compare two collections by their corresponding elements in order
         
         
        
        If the collections have differing sizes, the ordering does not matter. The smaller collection
        precedes the larger. Otherwise, each corresponding pair of elements are compared. Once an
        unequal pair is found, the collections are ordered by those elements. This is analogous to
        :obj:`String` comparison.
        
        :param collections.abc.Sequence a: the first set
        :param collections.abc.Sequence b: the second set
        :return: a comparison result as in :meth:`Comparable.compareTo(Object) <Comparable.compareTo>`
        :rtype: int
        """

    @staticmethod
    def extendList(list: java.util.List[T], ext: T) -> java.util.List[T]:
        """
        Extend a list with the given item
         
         
        
        Used in functional style when the list is immutable.
        
        :param T: the type of elements:param java.util.List[T] list: the list
        :param T ext: the additional item
        :return: an immutable copy of the list with the given item appended
        :rtype: java.util.List[T]
        """



__all__ = ["TableEntryKey", "TableEntry", "AsmUtil"]
