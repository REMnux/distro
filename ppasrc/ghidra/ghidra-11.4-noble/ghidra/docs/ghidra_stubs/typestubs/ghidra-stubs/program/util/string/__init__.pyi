from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.ascii
import ghidra.util.task
import java.lang # type: ignore


class FoundStringCallback(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def stringFound(self, foundString: FoundString):
        ...


class StringSearcher(AbstractStringSearcher):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, minimumStringSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], allCharSizes: typing.Union[jpype.JBoolean, bool], requireNullTermination: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, charSet: ghidra.util.ascii.CharSetRecognizer, minimumStringSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], allCharSizes: typing.Union[jpype.JBoolean, bool], requireNullTermination: typing.Union[jpype.JBoolean, bool]):
        ...


class FoundString(java.lang.Comparable[FoundString]):

    class DefinedState(java.lang.Enum[FoundString.DefinedState]):

        class_: typing.ClassVar[java.lang.Class]
        NOT_DEFINED: typing.Final[FoundString.DefinedState]
        DEFINED: typing.Final[FoundString.DefinedState]
        PARTIALLY_DEFINED: typing.Final[FoundString.DefinedState]
        CONFLICTS: typing.Final[FoundString.DefinedState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FoundString.DefinedState:
            ...

        @staticmethod
        def values() -> jpype.JArray[FoundString.DefinedState]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType, definedState: FoundString.DefinedState):
        ...

    def conflicts(self) -> bool:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDataInstance(self, memory: ghidra.program.model.mem.Memory) -> ghidra.program.model.data.StringDataInstance:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getDefinedState(self) -> FoundString.DefinedState:
        ...

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getLength(self) -> int:
        ...

    def getString(self, memory: ghidra.program.model.mem.Memory) -> str:
        ...

    def getStringLength(self, mem: ghidra.program.model.mem.Memory) -> int:
        ...

    def isDefined(self) -> bool:
        ...

    def isPartiallyDefined(self) -> bool:
        ...

    def isPascall(self) -> bool:
        ...

    def isUndefined(self) -> bool:
        ...

    def setAddress(self, address: ghidra.program.model.address.Address):
        ...

    def setDefinedState(self, newState: FoundString.DefinedState):
        ...

    def setLength(self, length: typing.Union[jpype.JInt, int]):
        ...

    @property
    def pascall(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @address.setter
    def address(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @length.setter
    def length(self, value: jpype.JInt):
        ...

    @property
    def stringLength(self) -> jpype.JInt:
        ...

    @property
    def dataInstance(self) -> ghidra.program.model.data.StringDataInstance:
        ...

    @property
    def defined(self) -> jpype.JBoolean:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def definedState(self) -> FoundString.DefinedState:
        ...

    @definedState.setter
    def definedState(self, value: FoundString.DefinedState):
        ...

    @property
    def undefined(self) -> jpype.JBoolean:
        ...

    @property
    def partiallyDefined(self) -> jpype.JBoolean:
        ...


class PascalUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def findPascalSequence(buf: ghidra.program.model.mem.MemBuffer, sequence: ghidra.util.ascii.Sequence, alignment: typing.Union[jpype.JInt, int]) -> ghidra.util.ascii.Sequence:
        """
        Looks for Pascal strings given a sequence of bytes that represent a sequence of ascii chars.
        
        :param ghidra.program.model.mem.MemBuffer buf: the Memory buffer containing the bytes that make up the string.
        :param ghidra.util.ascii.Sequence sequence: the sequence that specifies the start, end, and type of ascii sequence (i.e. ascii,
        unicode16).  This method looks for both 2 byte and 1 byte leading pascal lengths both before
        and at the beginning of the given sequence.
        :return: a new sequence that has been adjusted  to represent a pascal string or null if
        a pascal string was not found.
        :rtype: ghidra.util.ascii.Sequence
        """


class PascalStringSearcher(AbstractStringSearcher):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, minimumStringSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], includePascalUnicode: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, charSet: ghidra.util.ascii.CharSetRecognizer, minimumStringSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], includePascalUnicode: typing.Union[jpype.JBoolean, bool]):
        ...


class AbstractStringSearcher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAlignment(self) -> int:
        ...

    def search(self, addressSet: ghidra.program.model.address.AddressSetView, callback: FoundStringCallback, searchLoadedMemoryBlocksOnly: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Searches the given addressSet for strings. 
         
        
        Note: The address set searched will be modified before searching in the following ways:
         
        *  if the given set is null, it will be re-initialized to encompass all of program memory
        *  the set will be further culled to only include loaded memory blocks, if specified
        
        
        :param ghidra.program.model.address.AddressSetView addressSet: the address set to search over; if null, will initialized to all memory
        :param FoundStringCallback callback: the callback invoked when a string is found
        :param jpype.JBoolean or bool searchLoadedMemoryBlocksOnly: if true, will exclude unloaded memory blocks from the search
        :param ghidra.util.task.TaskMonitor monitor: the user monitor
        :return: the updated address set used for the search
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def updateAddressesToSearch(self, addressSet: ghidra.program.model.address.AddressSetView, useLoadedBlocksOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Returns a new address set that is the intersection of the given set with the
        desired memory block addresses (loaded or unloaded).
         
        
        Note: This desired set of memory blocks is known by inspecting the 
        :meth:`StringTableOptions.useLoadedBlocksOnly() <StringTableOptions.useLoadedBlocksOnly>` attribute set by the user.
        
        :param ghidra.program.model.address.AddressSetView addressSet: the address set to update
        :param jpype.JBoolean or bool useLoadedBlocksOnly: if true, only return addresses in loaded memory blocks
        :return: new the new address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @property
    def alignment(self) -> jpype.JInt:
        ...



__all__ = ["FoundStringCallback", "StringSearcher", "FoundString", "PascalUtil", "PascalStringSearcher", "AbstractStringSearcher"]
