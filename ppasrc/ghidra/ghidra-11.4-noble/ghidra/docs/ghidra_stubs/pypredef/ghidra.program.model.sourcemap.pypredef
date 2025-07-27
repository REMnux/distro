from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.database.sourcemap
import ghidra.program.model.address
import java.lang # type: ignore
import java.util # type: ignore


class SourcePathTransformer(java.lang.Object):
    """
    SourcePathTransformers are used to transform :obj:`SourceFile` paths.  The intended use is
    to transform the path of a :obj:`SourceFile` in a programs's :obj:`SourceFileManager`
    before sending the path to an IDE.
    
     
    
    There are two types of transformations: file and directory.  File transforms
    map a particular :obj:`SourceFile` to an absolute file path. Directory transforms
    transform an initial segment of a path.  For example, the directory transforms
    "/c:/users/" -> "/src/test/" sends "/c:/users/dir/file1.c" to "/src/test/dir/file1.c"
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDirectoryTransform(self, sourceDir: typing.Union[java.lang.String, str], targetDir: typing.Union[java.lang.String, str]):
        """
        Adds a new directory transform.  Any existing directory transform for ``sourceDir``
        is overwritten.  ``sourceDir`` and ``targetDir`` must be valid, normalized
        directory paths (with forward slashes).
        
        :param java.lang.String or str sourceDir: source directory
        :param java.lang.String or str targetDir: target directory
        """

    def addFileTransform(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, path: typing.Union[java.lang.String, str]):
        """
        Adds a new file transform.  Any existing file transform for ``sourceFile`` is 
        overwritten.  ``path`` must be a valid, normalized file path (with forward slashes).
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file (can't be null).
        :param java.lang.String or str path: new path
        """

    def getTransformRecords(self) -> java.util.List[SourcePathTransformRecord]:
        """
        Returns a list of all :obj:`SourcePathTransformRecord`s
        
        :return: transform records
        :rtype: java.util.List[SourcePathTransformRecord]
        """

    def getTransformedPath(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, useExistingAsDefault: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the transformed path for ``sourceFile``.  The transformed path is determined as
        follows:
        
        - If there is a file transform for ``sourceFile``, the file transform is applied.
        
        - Otherwise, the most specific directory transform (i.e., longest source directory string) 
        is applied.
        
        - If no directory transform applies, the value of ``useExistingAsDefault`` determines
        whether the path of ``sourceFile`` or ``null`` is returned.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file to transform
        :param jpype.JBoolean or bool useExistingAsDefault: whether to return sourceFile's path if no transform applies
        :return: transformed path or null
        :rtype: str
        """

    def removeDirectoryTransform(self, sourceDir: typing.Union[java.lang.String, str]):
        """
        Removes any directory transform associated with ``sourceDir``
        
        :param java.lang.String or str sourceDir: source directory
        """

    def removeFileTransform(self, sourceFile: ghidra.program.database.sourcemap.SourceFile):
        """
        Removes any file transform for ``sourceFile``.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        """

    @property
    def transformRecords(self) -> java.util.List[SourcePathTransformRecord]:
        ...


class SourceMapEntry(java.lang.Comparable[SourceMapEntry]):
    """
    A SourceMapEntry consists of a :obj:`SourceFile`, a line number, a base address, 
    and a length. If the length is positive, the base address and the length determine
    an :obj:`AddressRange`. In this case, the length of a ``SourceMapEntry`` is the
    length of the associated :obj:`AddressRange`, i.e., the number of :obj:`Address`es in 
    the range (see :meth:`AddressRange.getLength() <AddressRange.getLength>`).  The intent is that the range 
    contains all of the bytes corresponding to a given line of source. The length of a
    ``SourceMapEntry`` can be 0, in which case the associated range is null. Negative 
    lengths are not allowed.
     
    
    The baseAddress of a range must occur within a memory block of the program, as must each
    address within the range of a ``SourceMapEntry``.  A range may span multiple 
    (contiguous) memory blocks.
     
    
    If the ranges of two entries (with non-zero lengths) intersect, then the ranges must be
    identical. The associated :obj:`SourceFile`s and/or line numbers can be different.
     
    
    Entries with length zero do not conflict with other entries and may occur within the
    range of another entry.
     
    
    For a fixed source file, line number, base address, and length, there must be only one
    SourceMapEntry.
     
    
    SourceMapEntry objects are created using the :obj:`SourceFileManager` for a program, 
    which must enforce the restrictions listed above.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the base address of the entry
        
        :return: base address
        :rtype: ghidra.program.model.address.Address
        """

    def getLength(self) -> int:
        """
        Returns the length of the range (number of addresses)
        
        :return: length
        :rtype: int
        """

    def getLineNumber(self) -> int:
        """
        Returns the line number.
        
        :return: line number
        :rtype: int
        """

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns the address range, or null for length 0 entries
        
        :return: address range or null
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getSourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        """
        Returns the source file
        
        :return: source file
        :rtype: ghidra.program.database.sourcemap.SourceFile
        """

    @property
    def baseAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def sourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...


class SourcePathTransformRecord(java.lang.Record):
    """
    A container for a source path transformation.  No validation is performed on the inputs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str], sourceFile: ghidra.program.database.sourcemap.SourceFile, target: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isDirectoryTransform(self) -> bool:
        ...

    def source(self) -> str:
        ...

    def sourceFile(self) -> ghidra.program.database.sourcemap.SourceFile:
        ...

    def target(self) -> str:
        ...

    def toString(self) -> str:
        ...

    @property
    def directoryTransform(self) -> jpype.JBoolean:
        ...


class SourceFileManager(java.lang.Object):
    """
    This interface defines methods for managing :obj:`SourceFile`s and :obj:`SourceMapEntry`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[SourceFileManager]

    def addSourceFile(self, sourceFile: ghidra.program.database.sourcemap.SourceFile) -> bool:
        """
        Adds a :obj:`SourceFile` to this manager.  A SourceFile must be added before it can be 
        associated with any source map information.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file to add (can't be null)
        :return: true if this manager did not already contain sourceFile
        :rtype: bool
        :raises LockException: if invoked without exclusive access
        """

    @typing.overload
    def addSourceMapEntry(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, lineNumber: typing.Union[jpype.JInt, int], range: ghidra.program.model.address.AddressRange) -> SourceMapEntry:
        """
        Adds a :obj:`SourceMapEntry` with :obj:`SourceFile` ``sourceFile``,
        line number ``lineNumber``, and :obj:`AddressRange` ``range`` to the program 
        database.
         
        
        Entries with non-zero lengths must either cover the same address range or be disjoint.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :param jpype.JInt or int lineNumber: line number
        :param ghidra.program.model.address.AddressRange range: address range
        :return: created SourceMapEntry
        :rtype: SourceMapEntry
        :raises LockException: if invoked without exclusive access
        :raises IllegalArgumentException: if the range of the new entry intersects, but does
        not equal, the range of an existing entry or if sourceFile was not previously added
        to the program.
        :raises AddressOutOfBoundsException: if the range of the new entry contains addresses
        that are not in a defined memory block
        """

    @typing.overload
    def addSourceMapEntry(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, lineNumber: typing.Union[jpype.JInt, int], baseAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> SourceMapEntry:
        """
        Creates a :obj:`SourceMapEntry` with :obj:`SourceFile` ``sourceFile``,
        line number ``lineNumber``, and non-negative length ``length`` and
        adds it to the program database.
         
        
        Entries with non-zero lengths must either cover the same address range or be disjoint.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :param jpype.JInt or int lineNumber: line number
        :param ghidra.program.model.address.Address baseAddr: minimum address of range
        :param jpype.JLong or int length: number of addresses in range
        :return: created SourceMapEntry
        :rtype: SourceMapEntry
        :raises AddressOverflowException: if baseAddr + length-1 overflows
        :raises LockException: if invoked without exclusive access
        :raises IllegalArgumentException: if the range of the new entry intersects, but does
        not equal, the range of an existing entry or if sourceFile was not previously added to the 
        program.
        :raises AddressOutOfBoundsException: if the range of the new entry contains addresses
        that are not in a defined memory block
        """

    def containsSourceFile(self, sourceFile: ghidra.program.database.sourcemap.SourceFile) -> bool:
        """
        Returns true precisely when this manager contains ``sourceFile``.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :return: true if source file already added
        :rtype: bool
        """

    def getAllSourceFiles(self) -> java.util.List[ghidra.program.database.sourcemap.SourceFile]:
        """
        Returns a :obj:`List` containing all :obj:`SourceFile`s of the program.
        
        :return: source file list
        :rtype: java.util.List[ghidra.program.database.sourcemap.SourceFile]
        """

    def getMappedSourceFiles(self) -> java.util.List[ghidra.program.database.sourcemap.SourceFile]:
        """
        Returns a :obj:`List` containing :obj:`SourceFile`s which are
        mapped to at least one address in the program
        
        :return: mapped source file list
        :rtype: java.util.List[ghidra.program.database.sourcemap.SourceFile]
        """

    @typing.overload
    def getSourceMapEntries(self, addr: ghidra.program.model.address.Address) -> java.util.List[SourceMapEntry]:
        """
        Returns a sorted list of :obj:`SourceMapEntry`s associated with an address ``addr``.
        
        :param ghidra.program.model.address.Address addr: address
        :return: line number
        :rtype: java.util.List[SourceMapEntry]
        """

    @typing.overload
    def getSourceMapEntries(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, minLine: typing.Union[jpype.JInt, int], maxLine: typing.Union[jpype.JInt, int]) -> java.util.List[SourceMapEntry]:
        """
        Returns the sorted list of :obj:`SourceMapEntry`s for ``sourceFile`` with line number
        between ``minLine`` and ``maxLine``, inclusive.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :param jpype.JInt or int minLine: minimum line number
        :param jpype.JInt or int maxLine: maximum line number
        :return: source map entries
        :rtype: java.util.List[SourceMapEntry]
        """

    @typing.overload
    def getSourceMapEntries(self, sourceFile: ghidra.program.database.sourcemap.SourceFile, lineNumber: typing.Union[jpype.JInt, int]) -> java.util.List[SourceMapEntry]:
        """
        Returns the sorted list of :obj:`SourceMapEntry`s for ``sourceFile`` with line number 
        equal to ``lineNumber``.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :param jpype.JInt or int lineNumber: line number
        :return: source map entries
        :rtype: java.util.List[SourceMapEntry]
        """

    @typing.overload
    def getSourceMapEntries(self, sourceFile: ghidra.program.database.sourcemap.SourceFile) -> java.util.List[SourceMapEntry]:
        """
        Returns a sorted of list all :obj:`SourceMapEntry`s in the program corresponding to
        ``sourceFile``.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file
        :return: source map entries
        :rtype: java.util.List[SourceMapEntry]
        """

    def getSourceMapEntryIterator(self, address: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> SourceMapEntryIterator:
        """
        Returns a :obj:`SourceMapEntryIterator` starting at ``address``.
        
        :param ghidra.program.model.address.Address address: starting address
        :param jpype.JBoolean or bool forward: direction of iterator (true = forward)
        :return: iterator
        :rtype: SourceMapEntryIterator
        """

    def intersectsSourceMapEntry(self, addrs: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Returns ``true`` precisely when at least one :obj:`Address` in ``addrs`` has
        source map information.
        
        :param ghidra.program.model.address.AddressSetView addrs: addresses to check
        :return: true when at least one address has source map info
        :rtype: bool
        """

    def removeSourceFile(self, sourceFile: ghidra.program.database.sourcemap.SourceFile) -> bool:
        """
        Removes a :obj:`SourceFile` from this manager.  Any associated :obj:`SourceMapEntry`s will
        also be removed.
        
        :param ghidra.program.database.sourcemap.SourceFile sourceFile: source file to remove
        :return: true if sourceFile was in the manager
        :rtype: bool
        :raises LockException: if invoked without exclusive access
        """

    def removeSourceMapEntry(self, entry: SourceMapEntry) -> bool:
        """
        Removes a :obj:`SourceMapEntry` from this manager.
        
        :param SourceMapEntry entry: entry to remove
        :return: true if entry was in the manager
        :rtype: bool
        :raises LockException: if invoked without exclusive access
        """

    def transferSourceMapEntries(self, source: ghidra.program.database.sourcemap.SourceFile, target: ghidra.program.database.sourcemap.SourceFile):
        """
        Changes the source map so that any :obj:`SourceMapEntry` associated with ``source``
        is associated with ``target`` instead. Any entries associated with
        ``target`` before invocation will still be associated with
        ``target`` after invocation.  ``source`` will not be associated
        with any entries after invocation (unless ``source`` and ``target``
        are the same). Line number information is not changed.
        
        :param ghidra.program.database.sourcemap.SourceFile source: source file to get info from
        :param ghidra.program.database.sourcemap.SourceFile target: source file to move info to
        :raises LockException: if invoked without exclusive access
        :raises IllegalArgumentException: if source or target has not been added previously
        """

    @property
    def allSourceFiles(self) -> java.util.List[ghidra.program.database.sourcemap.SourceFile]:
        ...

    @property
    def mappedSourceFiles(self) -> java.util.List[ghidra.program.database.sourcemap.SourceFile]:
        ...

    @property
    def sourceMapEntries(self) -> java.util.List[SourceMapEntry]:
        ...


class SourceMapEntryIterator(java.util.Iterator[SourceMapEntry], java.lang.Iterable[SourceMapEntry]):
    """
    Interface for iterating over :obj:`SourceMapEntry`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ITERATOR: typing.Final[SourceMapEntryIterator]


class DummySourceFileManager(SourceFileManager):
    """
    A "dummy" implementation of :obj:`SourceFileManager`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SourcePathTransformer", "SourceMapEntry", "SourcePathTransformRecord", "SourceFileManager", "SourceMapEntryIterator", "DummySourceFileManager"]
