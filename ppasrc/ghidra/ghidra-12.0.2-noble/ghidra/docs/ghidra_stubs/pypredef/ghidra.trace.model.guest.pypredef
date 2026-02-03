from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.data
import ghidra.trace.model.symbol
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.target.schema
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class TraceGuestPlatform(TracePlatform):
    """
    A guest platform in a trace
    """

    class_: typing.ClassVar[java.lang.Class]

    def addMappedRange(self, hostStart: ghidra.program.model.address.Address, guestStart: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> TraceGuestPlatformMappedRange:
        """
        Add an address mapping from host to guest
        
        :param ghidra.program.model.address.Address hostStart: the starting host address (mapped to guestStart)
        :param ghidra.program.model.address.Address guestStart: the starting guest address (mapped to hostStart)
        :param jpype.JLong or int length: the length of the range to map
        :return: the mapped range
        :rtype: TraceGuestPlatformMappedRange
        :raises AddressOverflowException: if length is too long for either start
        """

    def addMappedRegisterRange(self) -> TraceGuestPlatformMappedRange:
        """
        Add an address mapping from host register space to guest register space
         
         
        
        In guest space, the mapping is placed at 0 and has length large enough to accommodate all
        registers in the guest language. In host space, the mapping is placed after every other
        register mapping for every platform.
        
        :return: the mapped range
        :rtype: TraceGuestPlatformMappedRange
        :raises AddressOverflowException: if host register space was exhausted
        """

    def delete(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Remove the mapped language, including all code units of the language
        
        :param ghidra.util.task.TaskMonitor monitor: to monitor task progress
        :raises CancelledException: if the task is cancelled by the monitor
        """


class TraceGuestPlatformMappedRange(java.lang.Object):
    """
    A range of mapped memory from guest platform to host platform
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Delete this mapping entry
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cleaning up dependent objects, e.g., code units
        :raises CancelledException: if the user cancels via the monitor
        """

    def getGuestPlatform(self) -> TraceGuestPlatform:
        """
        Get the guest platform
        
        :return: the guest platform
        :rtype: TraceGuestPlatform
        """

    def getGuestRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range in the guest
        
        :return: the guest range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getHostPlatform(self) -> TracePlatform:
        """
        Get the host platform
        
        :return: the host platform
        :rtype: TracePlatform
        """

    def getHostRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range in the host
        
        :return: the host range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def mapGuestToHost(self, guestAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate an address from guest to host, if in the guest range
        
        :param ghidra.program.model.address.Address guestAddress: the guest address
        :return: the host address, or null
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def mapGuestToHost(self, guestRange: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        """
        Translate an address range from guest to host, if wholly contained in the guest range
        
        :param ghidra.program.model.address.AddressRange guestRange: the guest range
        :return: the host range, or null
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def mapHostToGuest(self, hostAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate an address from host to guest, if in the host range
        
        :param ghidra.program.model.address.Address hostAddress: the host address
        :return: the guest address, or null
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def mapHostToGuest(self, hostRange: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        """
        Translate an address range from host to guest, if wholly contained in the host range
        
        :param ghidra.program.model.address.AddressRange hostRange: the host range
        :return: the guest range, or null
        :rtype: ghidra.program.model.address.AddressRange
        """

    @property
    def guestPlatform(self) -> TraceGuestPlatform:
        ...

    @property
    def hostPlatform(self) -> TracePlatform:
        ...

    @property
    def hostRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def guestRange(self) -> ghidra.program.model.address.AddressRange:
        ...


class TracePlatform(java.lang.Object):
    """
    A platform within a trace
     
     
    
    Traces can model systems where multiple processors or languages are involved. Every trace has a
    "host" platform. There may also be zero or more "guest" platforms. The guest platforms' memories
    and registers must be mapped into the host platform to be used in the trace. This class provides
    access to the properties of a platform and a mechanisms for translating addresses between this
    and the host platform. If this is the host platform, the translation methods are the identity
    function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addRegisterMapOverride(self, register: ghidra.program.model.lang.Register, objectName: typing.Union[java.lang.String, str]) -> ghidra.trace.model.symbol.TraceLabelSymbol:
        """
        Add a label the conventionally maps the value of a :obj:`TraceRegister` in the object
        manager to a register from this platform
        
        :param ghidra.program.model.lang.Register register: the language register
        :param java.lang.String or str objectName: the name of the :obj:`TraceRegister` in the object tree
        :return: the label
        :rtype: ghidra.trace.model.symbol.TraceLabelSymbol
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Get the address factory of the guest platform
        
        :return: the factory
        :rtype: ghidra.program.model.address.AddressFactory
        """

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        """
        Get the compiler of the guest platform
        
        :return: the compiler specification
        :rtype: ghidra.program.model.lang.CompilerSpec
        """

    def getConventionalRegisterObjectNames(self, register: ghidra.program.model.lang.Register) -> java.util.Collection[java.lang.String]:
        """
        Get the names or indices of the register object for the given platform register
         
         
        
        This will check for a label in the host physical space, allowing a mapper to specify an
        alternative register object name. See :meth:`addRegisterMapOverride(Register, String) <.addRegisterMapOverride>`. If
        one exists, then only that name is returned. Otherwise, the given register's names and
        aliases are all returned as defined and in all-upper and all-lower case.
        
        :param ghidra.program.model.lang.Register register: the platform register
        :return: the mapped name
        :rtype: java.util.Collection[java.lang.String]
        """

    @typing.overload
    def getConventionalRegisterPath(self, schema: ghidra.trace.model.target.schema.TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath, names: collections.abc.Sequence) -> ghidra.trace.model.target.path.PathFilter:
        """
        Get the expected path where an object defining the register value would be
        
        :param ghidra.trace.model.target.schema.TraceObjectSchema schema: the schema of the register container
        :param ghidra.trace.model.target.path.KeyPath path: the path to the register container
        :param collections.abc.Sequence names: the possible names of the register on the target
        :return: the path matcher, possibly empty
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    @typing.overload
    def getConventionalRegisterPath(self, schema: ghidra.trace.model.target.schema.TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath, register: ghidra.program.model.lang.Register) -> ghidra.trace.model.target.path.PathFilter:
        """
        Get the expected path where an object defining the register value would be
         
         
        
        This will check for a label in the host physical space, allowing a mapper to specify an
        alternative register object name. See :meth:`addRegisterMapOverride(Register, String) <.addRegisterMapOverride>`.
        
        :param ghidra.trace.model.target.schema.TraceObjectSchema schema: the schema of the register container
        :param ghidra.trace.model.target.path.KeyPath path: the path to the register container
        :param ghidra.program.model.lang.Register register: the platform register
        :return: the path matcher, possibly empty
        :rtype: ghidra.trace.model.target.path.PathFilter
        """

    @typing.overload
    def getConventionalRegisterPath(self, container: ghidra.trace.model.target.TraceObject, register: ghidra.program.model.lang.Register) -> ghidra.trace.model.target.path.PathFilter:
        """
        Get the expected path where an object defining the register value would be
        
        :param ghidra.trace.model.target.TraceObject container: the register container
        :param ghidra.program.model.lang.Register register: the platform register
        :return: that path matcher, possibly empty, or null if the trace has no root schema
        :rtype: ghidra.trace.model.target.path.PathFilter
        
        .. seealso::
        
            | :obj:`.getConventionalRegisterPath(TraceObjectSchema, KeyPath, Register)`
        """

    @typing.overload
    def getConventionalRegisterPath(self, overlay: ghidra.program.model.address.AddressSpace, register: ghidra.program.model.lang.Register) -> ghidra.trace.model.target.path.PathFilter:
        """
        Get the expected path where an object defining the register value would be
        
        :param ghidra.program.model.address.AddressSpace overlay: the overlay space allocated for a thread or frame
        :param ghidra.program.model.lang.Register register: the platform register
        :return: the path matcher, or null if there is no root schema
        :rtype: ghidra.trace.model.target.path.PathFilter
        
        .. seealso::
        
            | :obj:`.getConventionalRegisterPath(TraceObjectSchema, KeyPath, Register)`
        """

    def getConventionalRegisterRange(self, overlay: ghidra.program.model.address.AddressSpace, register: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRange:
        """
        Translate the given platform register to the given host overlay space
        
        :param ghidra.program.model.address.AddressSpace overlay: the overlay space, usually that allocated for a thread or frame
        :param ghidra.program.model.lang.Register register: the platform register
        :return: the host range
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getDataTypeManager(self) -> ghidra.trace.model.data.TraceBasedDataTypeManager:
        """
        Get the data type manager for this platform.
        
        :return: the data type manager
        :rtype: ghidra.trace.model.data.TraceBasedDataTypeManager
        """

    def getGuestAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses in the guest which are mapped to somehere in the host
        
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getHostAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the addresses in the host which are mapped to somewhere in the guest
        
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of the guest platform
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getMappedMemBuffer(self, snap: typing.Union[jpype.JLong, int], guestAddress: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemBuffer:
        """
        Get a memory buffer, which presents the host bytes in the guest address space
         
         
        
        This, with pseudo-disassembly, is the primary mechanism for adding instructions in the guest
        language.
        
        :param jpype.JLong or int snap: the snap, up to which the most recent memory changes are presented
        :param ghidra.program.model.address.Address guestAddress: the starting address in the guest space
        :return: the mapped memory buffer
        :rtype: ghidra.program.model.mem.MemBuffer
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isGuest(self) -> bool:
        """
        Check if this is a guest platform
        
        :return: true for guest, false for host
        :rtype: bool
        """

    def isHost(self) -> bool:
        """
        Check if this is the host platform
        
        :return: true for host, false for guest
        :rtype: bool
        """

    def mapGuestInstructionAddressesToHost(self, set: ghidra.program.model.lang.InstructionSet) -> ghidra.program.model.lang.InstructionSet:
        """
        Copy the given instruction set, but with addresses mapped from the guest space to the host
        space
         
         
        
        Instructions which do not map are silently ignored. If concerned, the caller ought to examine
        the resulting instruction set and/or the resulting address set after it is added to the
        trace. A single instruction cannot span two mapped ranges, even if the comprised bytes are
        consecutive in the guest space. Mapping such an instruction back into the host space would
        cause the instruction to be split in the middle, which is not possible. Thus, such
        instructions are silently ignored.
        
        :param ghidra.program.model.lang.InstructionSet set: the instruction set in the guest space
        :return: the instruction set in the host space
        :rtype: ghidra.program.model.lang.InstructionSet
        """

    @typing.overload
    def mapGuestToHost(self, guestAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate an address from guest to host
        
        :param ghidra.program.model.address.Address guestAddress: the guest address
        :return: the host address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def mapGuestToHost(self, guestRange: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        """
        Translate a range from guest to host
         
         
        
        The entire range must be mapped to a single range.
        
        :param ghidra.program.model.address.AddressRange guestRange: the guest range
        :return: the host range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def mapGuestToHost(self, guestSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        """
        Translate a set from guest to host
         
         
        
        Only those ranges (or parts of ranges) that mapped are included.
        
        :param ghidra.program.model.address.AddressSetView guestSet: the guest set
        :return: the host set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def mapHostToGuest(self, hostAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Translate an address from host to guest
        
        :param ghidra.program.model.address.Address hostAddress: the host address
        :return: the guest address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def mapHostToGuest(self, hostRange: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        """
        Translate a range from host to guest
         
         
        
        The entire range must be mapped to a single range.
        
        :param ghidra.program.model.address.AddressRange hostRange: the host range
        :return: the guest range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @typing.overload
    def mapHostToGuest(self, hostSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        """
        Translate a set from host to guest
         
         
        
        Only those ranges (or parts of ranges) that mapped are included.
        
        :param ghidra.program.model.address.AddressSetView hostSet: the host set
        :return: the guest set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def guestAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def host(self) -> jpype.JBoolean:
        ...

    @property
    def guest(self) -> jpype.JBoolean:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def hostAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def dataTypeManager(self) -> ghidra.trace.model.data.TraceBasedDataTypeManager:
        ...

    @property
    def conventionalRegisterObjectNames(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class TracePlatformManager(java.lang.Object):
    """
    Allows the addition of "guest platforms" for disassembling in multiple languages.
     
     
    
    TODO: Allow the placement of data units with alternative data organization.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addGuestPlatform(self, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> TraceGuestPlatform:
        """
        Add a guest platform
        
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compiler spec, which cannot be the base compiler spec
        :return: the new platform
        :rtype: TraceGuestPlatform
        """

    def getGuestPlatforms(self) -> java.util.Collection[TraceGuestPlatform]:
        """
        Get all guest platforms
        
        :return: the collection of platforms
        :rtype: java.util.Collection[TraceGuestPlatform]
        """

    def getHostPlatform(self) -> TracePlatform:
        """
        Get a platform representing the trace's base language and compiler spec
        
        :return: the host platform
        :rtype: TracePlatform
        """

    def getOrAddPlatform(self, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> TracePlatform:
        """
        Get or add a platform for the given compiler spec
        
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compiler spec
        :return: the new or existing platform
        :rtype: TracePlatform
        """

    def getPlatform(self, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> TracePlatform:
        """
        Get the platform for the given compiler spec
        
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compiler spec
        :return: the platform, if found, or null
        :rtype: TracePlatform
        """

    @property
    def orAddPlatform(self) -> TracePlatform:
        ...

    @property
    def guestPlatforms(self) -> java.util.Collection[TraceGuestPlatform]:
        ...

    @property
    def hostPlatform(self) -> TracePlatform:
        ...

    @property
    def platform(self) -> TracePlatform:
        ...



__all__ = ["TraceGuestPlatform", "TraceGuestPlatformMappedRange", "TracePlatform", "TracePlatformManager"]
