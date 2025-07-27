from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


class ProgramSearchRegion(java.lang.Enum[ProgramSearchRegion], SearchRegion):
    """
    An enum specifying the selectable regions within a :obj:`Program` that users can select for
    searching memory.
    """

    class_: typing.ClassVar[java.lang.Class]
    LOADED: typing.Final[ProgramSearchRegion]
    OTHER: typing.Final[ProgramSearchRegion]
    ALL: typing.Final[java.util.List[SearchRegion]]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramSearchRegion:
        ...

    @staticmethod
    def values() -> jpype.JArray[ProgramSearchRegion]:
        ...


class EmptyByteSource(java.lang.Enum[EmptyByteSource], AddressableByteSource):
    """
    Implementation for an empty :obj:`AddressableByteSource`
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[EmptyByteSource]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EmptyByteSource:
        ...

    @staticmethod
    def values() -> jpype.JArray[EmptyByteSource]:
        ...


class ProgramByteSource(AddressableByteSource):
    """
    :obj:`AddressableByteSource` implementation for a Ghidra :obj:`Program`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class SearchRegion(java.lang.Object):
    """
    Interface to specify a named region within a byte source (Program) that users can select to
    specify :obj:`AddressSetView`s that can be searched.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddresses(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses from a specific program that is associated with this region.
        
        :param ghidra.program.model.listing.Program program: the program that determines the specific addresses for a named region
        :return: the set of addresses for this region as applied to the given program
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getDescription(self) -> str:
        """
        Returns a description of the region.
        
        :return: a description of the region
        :rtype: str
        """

    def getName(self) -> str:
        """
        The name of the region.
        
        :return: the name of the region
        :rtype: str
        """

    def isDefault(self) -> bool:
        """
        Returns true if this region should be included in the default selection of which regions to
        search.
        
        :return: true if this region should be selected by default
        :rtype: bool
        """

    @property
    def default(self) -> jpype.JBoolean:
        ...

    @property
    def addresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class AddressableByteSource(java.lang.Object):
    """
    Interface for reading bytes from a program. This provides a level of indirection for reading the
    bytes of a program so that the provider of the bytes can possibly do more than just reading the
    bytes from the static program. For example, a debugger would have the opportunity to refresh the
    bytes first.
     
    
    This interface also provides methods for determining what regions of memory can be queried and
    what addresses sets are associated with those regions. This would allow client to present choices
    about what areas of memory they are interested in AND are valid to be examined.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBytes(self, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], length: typing.Union[jpype.JInt, int]) -> int:
        """
        Retrieves the byte values for an address range.
        
        :param ghidra.program.model.address.Address address: The address of the first byte in the range
        :param jpype.JArray[jpype.JByte] bytes: the byte array to store the retrieved byte values
        :param jpype.JInt or int length: the number of bytes to retrieve
        :return: the number of bytes actually retrieved
        :rtype: int
        """

    def getSearchableRegions(self) -> java.util.List[SearchRegion]:
        """
        Returns a list of memory regions where each region has an associated address set of valid
        addresses that can be read.
        
        :return: a list of readable regions
        :rtype: java.util.List[SearchRegion]
        """

    def invalidate(self):
        """
        Invalidates any caching of byte values. This intended to provide a hint in debugging scenario
        that we are about to issue a sequence of byte value requests where we are re-acquiring
        previous requested byte values to look for changes.
        """

    @property
    def searchableRegions(self) -> java.util.List[SearchRegion]:
        ...



__all__ = ["ProgramSearchRegion", "EmptyByteSource", "ProgramByteSource", "SearchRegion", "AddressableByteSource"]
