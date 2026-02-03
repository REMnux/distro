from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.pcodeCPort.address
import ghidra.pcodeCPort.error
import ghidra.pcodeCPort.pcoderaw
import ghidra.pcodeCPort.space
import java.io # type: ignore
import java.lang # type: ignore


class BasicSpaceProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getConstantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Pcode represents constant values within an operation as
        offsets within a special constant address space. 
        (See ConstantSpace)
        
        :return: a pointer to the constant space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getDefaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Most processors have a main address bus, on which the bulk
        of the processor's RAM is mapped.  Everything referenced
        with this address bus should be modeled in pcode with a
        single address space, referred to as the default space.
        
        :return: a pointer to the default space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    @property
    def defaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def constantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...


class BadDataError(ghidra.pcodeCPort.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, string: typing.Union[java.lang.String, str]):
        ...


class UnimplError(ghidra.pcodeCPort.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]
    instruction_length: jpype.JInt

    def __init__(self, string: typing.Union[java.lang.String, str], instruction_length: typing.Union[jpype.JInt, int]):
        ...


class Translate(BasicSpaceProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addSpacebase(self, basespace: ghidra.pcodeCPort.space.AddrSpace, spc: ghidra.pcodeCPort.space.AddrSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
        """
        Associate a particular register or memory location with an address space
        The canonical example is the stack pointer and the stack space.
        The basespace is the so-called stack space, which is really a
        virtual space typically contained by ram space.  The spacebase
        register effectively hides the true location of its basespace with
        its containing space and facilitates addressing in the virtual space
        by providing a base offset into the containing space.
        
        :param ghidra.pcodeCPort.space.AddrSpace basespace: is the virtual address space
        :param ghidra.pcodeCPort.space.AddrSpace spc: is the address space of the register
        :param jpype.JLong or int offset: is the offset of the register
        :param jpype.JInt or int size: is the size of the register
        """

    def assignShortcut(self, tp: ghidra.pcodeCPort.space.spacetype) -> str:
        ...

    def createConstFromSpace(self, spc: ghidra.pcodeCPort.space.AddrSpace) -> ghidra.pcodeCPort.address.Address:
        """
        This routine is used to encode a pointer to an address space
        as a constant Address, for use in LOAD and STORE
        operations.  This is used internally and is slightly more
        efficient than storing the formal index of the space
        
        :param ghidra.pcodeCPort.space.AddrSpace spc: is the space pointer to be encoded
        :return: the encoded Address
        :rtype: ghidra.pcodeCPort.address.Address
        """

    def dispose(self):
        ...

    @deprecated("use getDefaultSize() instead")
    def getAddrSize(self) -> int:
        """
        This routine is intended to return a global address size for the processor.
        
        :return: the size of addresses in bytes
        :rtype: int
        
        .. deprecated::
        
        use :meth:`getDefaultSize() <.getDefaultSize>` instead
        """

    def getConstant(self, val: typing.Union[jpype.JLong, int]) -> ghidra.pcodeCPort.address.Address:
        """
        This routine encodes a specific value as a constant
        address. I.e. the address space of the resulting Address
        will be the constant space, and the offset will be the
        value.
        
        :param jpype.JLong or int val: is the constant value to encode
        :return: the constant address
        :rtype: ghidra.pcodeCPort.address.Address
        """

    def getConstantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Pcode represents constant values within an operation as
        offsets within a special constant address space. 
        (See ConstantSpace)
        
        :return: a pointer to the constant space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getDefaultSize(self) -> int:
        """
        Return the size of addresses for the processor's official
        default space. This space is usually the main RAM databus.
        
        :return: the size of an address in bytes
        :rtype: int
        """

    def getDefaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Most processors have a main address bus, on which the bulk
        of the processor's RAM is mapped.  Everything referenced
        with this address bus should be modeled in pcode with a
        single address space, referred to as the default space.
        
        :return: a pointer to the default space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getFspecSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        There is a special address space reserved for encoding pointers
        to the FuncCallSpecs object as addresses. This allows direct
        pointers to be hidden within an operation, when manipulating
        pcode internally. (See FspecSpace)
        
        :return: a pointer to the address space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getIopSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        There is a special address space reserved for encoding pointers
        to pcode operations as addresses.  This allows a direct pointer
        to be hidden within an operation, when manipulating pcode
        internally. (See IopSpace)
        
        :return: a pointer to the address space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getNextSpaceInOrder(self, spc: ghidra.pcodeCPort.space.AddrSpace) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getRegister(self, nm: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.pcoderaw.VarnodeData:
        ...

    def getRegisterName(self, base: ghidra.pcodeCPort.space.AddrSpace, off: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> str:
        ...

    def getSpace(self, i: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        This retrieves a specific address space via its formal index.
        All spaces have an index, and in conjunction with the numSpaces
        method, this method can be used to iterate over all spaces.
        
        :param jpype.JInt or int i: is the index of the address space
        :return: a pointer to the desired space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getSpaceByName(self, nm: typing.Union[java.lang.String, str]) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getSpaceByShortcut(self, sc: typing.Union[jpype.JChar, int, str]) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getSpaceBySpacebase(self, loc: ghidra.pcodeCPort.address.Address, size: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    def getSpacebase(self, basespace: ghidra.pcodeCPort.space.AddrSpace, i: typing.Union[jpype.JInt, int]) -> ghidra.pcodeCPort.pcoderaw.VarnodeData:
        """
        Retrieve a particular spacebase register associated with the virtual address space
        basespace.  This register serves as a base offset to anchor basespace within
        its containing space.
        
        :param ghidra.pcodeCPort.space.AddrSpace basespace: is the virtual space to find a spacebase register for
        :param jpype.JInt or int i: is the index of the particular spacebase register
        :return: a reference to the spacebase register
        :rtype: ghidra.pcodeCPort.pcoderaw.VarnodeData
        """

    def getStackSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Most processors have registers and instructions that are
        reserved for implementing a stack. In the pcode translation,
        these are translated into locations and operations on a
        dedicated stack address space. (See SpacebaseSpace)
        
        :return: a pointer to the stack space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getUniqueBase(self) -> int:
        """
        This routine gets the base offset, within the unique
        temporary register space, where new registers can be
        allocated for the simplification process.  Locations before
        this offset are reserved registers needed by the pcode
        translation engine.
        
        :return: the first allocatable offset
        :rtype: int
        """

    def getUniqueSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        """
        Both the pcode translation process and the simplification
        process need access to a pool of temporary registers that
        can be used for moving data around without affecting the
        address spaces used to formally model the processor's RAM
        and registers.  These temporary locations are all allocated
        from a dedicated address space, referred to as the unique
        space. (See UniqueSpace)
        
        :return: a pointer to the unique space
        :rtype: ghidra.pcodeCPort.space.AddrSpace
        """

    def getUserOpNames(self, res: generic.stl.VectorSTL[java.lang.String]):
        ...

    def highPtrPossible(self, loc: ghidra.pcodeCPort.address.Address, size: typing.Union[jpype.JInt, int]) -> bool:
        """
        The Translate object keep tracks of address ranges for which
        it is effectively impossible to have a pointer into. This is
        used for pointer aliasing calculations.  This routine returns
        true if it is possible to have pointers into the indicated
        range.
        
        :param ghidra.pcodeCPort.address.Address loc: is the starting address of the range
        :param jpype.JInt or int size: is the size of the range in bytes
        :return: true if pointers are possible
        :rtype: bool
        """

    def insertSpace(self, spc: ghidra.pcodeCPort.space.AddrSpace):
        ...

    def instructionLength(self, baseaddr: ghidra.pcodeCPort.address.Address) -> int:
        ...

    def isBigEndian(self) -> bool:
        """
        Processors can usually be described as using a big endian
        encoding or a little endian encoding. This routine returns
        true if the processor globally uses big endian encoding.
        
        :return: true if big endian
        :rtype: bool
        """

    def numSpacebase(self, basespace: ghidra.pcodeCPort.space.AddrSpace) -> int:
        """
        If basespace is a virtual space, it has one (or more) registers or memory locations
        associated with it that serve as base offsets, anchoring the virtual space in a physical space
        
        :param ghidra.pcodeCPort.space.AddrSpace basespace: is the virtual space to check
        :return: the number of spacebase registers
        :rtype: int
        """

    def numSpaces(self) -> int:
        """
        This returns the total number of address spaces used by the
        processor, including all special spaces, like the constant
        space and the iop space.
        
        :return: the number of spaces
        :rtype: int
        """

    def printAssembly(self, s: java.io.PrintStream, size: typing.Union[jpype.JInt, int], baseaddr: ghidra.pcodeCPort.address.Address) -> int:
        ...

    def setDefaultSpace(self, index: typing.Union[jpype.JInt, int]):
        ...

    def setLanguage(self, processorFile: typing.Union[java.lang.String, str]):
        ...

    @property
    def spaceByShortcut(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def addrSize(self) -> jpype.JInt:
        ...

    @property
    def constant(self) -> ghidra.pcodeCPort.address.Address:
        ...

    @property
    def stackSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def fspecSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def uniqueBase(self) -> jpype.JLong:
        ...

    @property
    def spaceByName(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def constantSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def space(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def iopSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def nextSpaceInOrder(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def uniqueSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def defaultSize(self) -> jpype.JInt:
        ...

    @property
    def defaultSpace(self) -> ghidra.pcodeCPort.space.AddrSpace:
        ...

    @property
    def register(self) -> ghidra.pcodeCPort.pcoderaw.VarnodeData:
        ...



__all__ = ["BasicSpaceProvider", "BadDataError", "UnimplError", "Translate"]
