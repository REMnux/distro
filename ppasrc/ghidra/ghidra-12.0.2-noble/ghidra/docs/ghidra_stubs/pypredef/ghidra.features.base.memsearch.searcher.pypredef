from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.features.base.memsearch.bytesource
import ghidra.features.base.memsearch.matcher
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.datastruct
import ghidra.util.task
import java.lang # type: ignore
import java.util.function # type: ignore


class AlignmentFilter(java.util.function.Predicate[MemoryMatch]):
    """
    Search filter that can test a search result and determine if that result is at an address
    whose offset matches the given alignment (i.e. its offset is a multiple of the alignment value)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, alignment: typing.Union[jpype.JInt, int]):
        ...


class CodeUnitFilter(java.util.function.Predicate[MemoryMatch]):
    """
    Search filter that can test a search result and determine if that result starts at or inside
    a code unit that matches one of the selected types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, includeInstructions: typing.Union[jpype.JBoolean, bool], includeDefinedData: typing.Union[jpype.JBoolean, bool], includeUndefinedData: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program to get code units from for testing its type
        :param jpype.JBoolean or bool includeInstructions: if true, accept matches that are in an instruction
        :param jpype.JBoolean or bool includeDefinedData: if true, accept matches that are in defined data
        :param jpype.JBoolean or bool includeUndefinedData: if true, accept matches that are in undefined data
        """


class MemorySearcher(java.lang.Object):
    """
    Class for searching bytes from a byteSource (memory) using a :obj:`ByteMatcher`. It handles
    breaking the search down into a series of searches, handling gaps in the address set and
    breaking large address ranges down into manageable sizes.
     
    
    It is created with a specific byte source, matcher, address set, and search limit. Clients can
    then either call the :meth:`findAll(Accumulator, TaskMonitor) <.findAll>` method or use it to incrementally
    search using :meth:`findNext(Address, TaskMonitor) <.findNext>`, 
    :meth:`findPrevious(Address, TaskMonitor) <.findPrevious>`, or :meth:`findOnce(Address, boolean, TaskMonitor) <.findOnce>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, matcher: ghidra.features.base.memsearch.matcher.ByteMatcher, addresses: ghidra.program.model.address.AddressSetView, searchLimit: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.features.base.memsearch.bytesource.AddressableByteSource byteSource: the source of the bytes to be searched
        :param ghidra.features.base.memsearch.matcher.ByteMatcher matcher: the matcher that can find matches in a byte sequence
        :param ghidra.program.model.address.AddressSetView addresses: the address in the byte source to search
        :param jpype.JInt or int searchLimit: the max number of hits before stopping
        """

    @typing.overload
    def __init__(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, matcher: ghidra.features.base.memsearch.matcher.ByteMatcher, addresses: ghidra.program.model.address.AddressSetView, searchLimit: typing.Union[jpype.JInt, int], chunkSize: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.features.base.memsearch.bytesource.AddressableByteSource byteSource: the source of the bytes to be searched
        :param ghidra.features.base.memsearch.matcher.ByteMatcher matcher: the matcher that can find matches in a byte sequence
        :param ghidra.program.model.address.AddressSetView addresses: the address in the byte source to search
        :param jpype.JInt or int searchLimit: the max number of hits before stopping
        :param jpype.JInt or int chunkSize: the maximum number of bytes to feed to the matcher at any one time.
        """

    def findAll(self, accumulator: ghidra.util.datastruct.Accumulator[MemoryMatch], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Searches all the addresses in this search's :obj:`AddressSetView` using the byte matcher to
        find matches. As each match is found (and passes any filters), the match is given to the 
        accumulator. The search continues until either the entire address set has been search or
        the search limit has been reached.
        
        :param ghidra.util.datastruct.Accumulator[MemoryMatch] accumulator: the accumulator for found matches
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the search completed searching through the entire address set.
        :rtype: bool
        """

    def findNext(self, start: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> MemoryMatch:
        """
        Searches forwards starting at the given address until a match is found or
        the end of the address set is reached. It does not currently wrap the search.
        
        :param ghidra.program.model.address.Address start: the address to start searching
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the first match found or null if no match found.
        :rtype: MemoryMatch
        """

    def findOnce(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> MemoryMatch:
        """
        Searches forwards or backwards starting at the given address until a match is found or
        the start or end of the address set is reached. It does not currently wrap the search.
        
        :param ghidra.program.model.address.Address start: the address to start searching
        :param jpype.JBoolean or bool forward: if true, search forward, otherwise, search backwards.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the first match found or null if no match found.
        :rtype: MemoryMatch
        """

    def findPrevious(self, start: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> MemoryMatch:
        """
        Searches backwards starting at the given address until a match is found or
        the beginning of the address set is reached. It does not currently wrap the search.
        
        :param ghidra.program.model.address.Address start: the address to start searching
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the first match found or null if no match found.
        :rtype: MemoryMatch
        """

    def setMatchFilter(self, filter: java.util.function.Predicate[MemoryMatch]):
        """
        Sets any match filters. The filter can be used to exclude matches that don't meet some
        criteria that is not captured in the byte matcher such as alignment and code unit type.
        
        :param java.util.function.Predicate[MemoryMatch] filter: the predicate to use to filter search results
        """


class MemoryMatch(java.lang.Comparable[MemoryMatch]):
    """
    A class that represents a memory search hit at an address. Matches can also be updated with
    new byte values (from a scan or refresh action). The original bytes that matched the original
    search are maintained in addition to the "refreshed" bytes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], matcher: ghidra.features.base.memsearch.matcher.ByteMatcher):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getByteMatcher(self) -> ghidra.features.base.memsearch.matcher.ByteMatcher:
        ...

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getLength(self) -> int:
        ...

    def getPreviousBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def isChanged(self) -> bool:
        ...

    def updateBytes(self, newBytes: jpype.JArray[jpype.JByte]):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def byteMatcher(self) -> ghidra.features.base.memsearch.matcher.ByteMatcher:
        ...

    @property
    def previousBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...



__all__ = ["AlignmentFilter", "CodeUnitFilter", "MemorySearcher", "MemoryMatch"]
