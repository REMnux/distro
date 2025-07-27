from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.symbol
import java.io # type: ignore
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


class DbgTimer(java.io.PrintStream):
    """
    A debugging, timing, and diagnostic tool
     
     
    
    TODO: I should probably remove this and rely on the Msg.trace() method, or at the very least,
    refactor this to use that.
    """

    class TabbingOutputStream(java.io.OutputStream):
        """
        A (rather slow) output stream that indents every line of its output
        """

        class_: typing.ClassVar[java.lang.Class]


    class DbgCtx(java.lang.AutoCloseable):
        """
        A context for idiomatic use of the :obj:`DbgTimer` in a try-with-resources block
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ACTIVE: typing.Final[DbgTimer]
    """
    An instance that prints to standard out
    """

    INACTIVE: typing.Final[DbgTimer]
    """
    An instance that prints to /dev/null
    """


    @typing.overload
    def __init__(self, out: java.io.OutputStream):
        """
        Create a new debugging timer, wrapping the given output stream
        
        :param java.io.OutputStream out: the stream
        """

    @typing.overload
    def __init__(self):
        """
        Create a new debugging timer, wrapping standard out
        """

    def resetOutputStream(self, s: DbgTimer.TabbingOutputStream) -> DbgTimer.TabbingOutputStream:
        """
        Put the original tabbing stream back
        
        :param DbgTimer.TabbingOutputStream s: the original wrapped stream
        :return: the replacement stream, wrapped in a tabbing stream
        :rtype: DbgTimer.TabbingOutputStream
        
        .. seealso::
        
            | :obj:`.setOutputStream(OutputStream)`
        """

    def setOutputStream(self, s: java.io.OutputStream) -> DbgTimer.TabbingOutputStream:
        """
        Replace the wrapped output stream (usually temporarily)
        
        :param java.io.OutputStream s: the replacement stream
        :return: the original stream, wrapped in a tabbing stream
        :rtype: DbgTimer.TabbingOutputStream
        
        .. seealso::
        
            | :obj:`.resetOutputStream(TabbingOutputStream)`
        """

    def start(self, message: java.lang.Object) -> DbgTimer.DbgCtx:
        """
        Start a new, possibly long-running, task
         
        This is meant to be used idiomatically, as in a try-with-resources block:
         
         
        try (DbgCtx dc = dbg.start("Twiddling the frobs:")) {
            // do some classy twiddling
        } // this will automatically print done and the time elapsed within the try block
         
         
        This idiom is preferred because the task will be stopped even if an error occurs, if the
        method returns from within the block, etc.
        
        :param java.lang.Object message: the message to print when the task begins
        :return: a context to close when the task ends
        :rtype: DbgTimer.DbgCtx
        """

    def stop(self):
        """
        Stop the current task
         
         
        
        This will print done and the elapsed time since the start of the task. The "current task" is
        determined from the stack.
        """



__all__ = ["TableEntryKey", "TableEntry", "AsmUtil", "DbgTimer"]
