from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.emulator.state
import ghidra.pcode.loadimage
import ghidra.pcode.memstate
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore


class MemoryLoadImage(ghidra.pcode.loadimage.LoadImage):

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self) -> None:
        ...

    def writeBack(self, bytes: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, offset: typing.Union[jpype.JInt, int]) -> None:
        ...


class CompositeLoadImage(MemoryLoadImage):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def addProvider(self, provider: MemoryLoadImage, view: ghidra.program.model.address.AddressSetView) -> None:
        ...


class ProgramLoadImage(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, faultHandler: ghidra.pcode.memstate.MemoryFaultHandler) -> None:
        ...

    def dispose(self) -> None:
        ...

    def getInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def read(self, bytes: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, offset: typing.Union[jpype.JInt, int], generateInitializedMask: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...

    def write(self, bytes: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, offset: typing.Union[jpype.JInt, int]) -> None:
        ...

    @property
    def initializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...


@deprecated("Please use PcodeEmulator instead. We generally expect the image to be\n             manually loaded into the emulator, though you can use PcodeEmulationCallbacks\n             to load an image lazily.")
class MemoryImage(ghidra.pcode.memstate.MemoryBank):
    """
    A kind of MemoryBank which retrieves its data from an underlying LoadImage
     
    
    Any bytes requested on the bank which lie in the LoadImage are retrieved from the LoadImage.
    Other addresses in the space are filled in with zero. This bank cannot be written to.
    
    
    .. deprecated::
    
    Please use :obj:`PcodeEmulator` instead. We generally expect the image to be
                manually loaded into the emulator, though you can use :obj:`PcodeEmulationCallbacks`
                to load an image lazily.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.AddressSpace, isBigEndian: typing.Union[jpype.JBoolean, bool], ps: typing.Union[jpype.JInt, int], ld: MemoryLoadImage, faultHandler: ghidra.pcode.memstate.MemoryFaultHandler) -> None:
        """
        A MemoryImage needs everything a basic memory bank needs and is needs to know the underlying
        LoadImage object to forward read requests to.
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space associated with the memory bank
        :param jpype.JBoolean or bool isBigEndian: 
        :param jpype.JInt or int ps: is the number of bytes in a page (must be power of 2)
        :param MemoryLoadImage ld: is the underlying LoadImage
        :param ghidra.pcode.memstate.MemoryFaultHandler faultHandler:
        """

    def getPage(self, addr: typing.Union[jpype.JLong, int]) -> ghidra.pcode.memstate.MemoryPage:
        """
        Retrieve an aligned page from the bank. First an attempt is made to retrieve the page from
        the LoadImage, which may do its own zero filling. If the attempt fails, the page is entirely
        filled in with zeros.
        """

    @property
    def page(self) -> ghidra.pcode.memstate.MemoryPage:
        ...


class EmulatorLoadData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getInitialRegisterState(self) -> ghidra.app.emulator.state.RegisterState:
        ...

    def getMemoryLoadImage(self) -> MemoryLoadImage:
        ...

    def getView(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def initialRegisterState(self) -> ghidra.app.emulator.state.RegisterState:
        ...

    @property
    def view(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def memoryLoadImage(self) -> MemoryLoadImage:
        ...


class ProgramMappedLoadImage(MemoryLoadImage):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memory: ProgramMappedMemory) -> None:
        ...


class ProgramMappedMemory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, faultHandler: ghidra.pcode.memstate.MemoryFaultHandler) -> None:
        ...

    def dispose(self) -> None:
        ...

    def getInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def read(self, bytes: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, offset: typing.Union[jpype.JInt, int], generateInitializedMask: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JByte]:
        ...

    def write(self, bytes: jpype.JArray[jpype.JByte], size: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, offset: typing.Union[jpype.JInt, int]) -> None:
        ...

    @property
    def initializedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...



__all__ = ["MemoryLoadImage", "CompositeLoadImage", "ProgramLoadImage", "MemoryImage", "EmulatorLoadData", "ProgramMappedLoadImage", "ProgramMappedMemory"]
