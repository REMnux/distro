from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.app.util.bin.format.objc.objc1
import ghidra.app.util.bin.format.objc.objc2
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class ObjcMethodList(ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def getMethods(self) -> java.util.List[ObjcMethod]:
        ...

    @property
    def methods(self) -> java.util.List[ObjcMethod]:
        ...


class ObjcUtils(java.lang.Object):
    """
    Objective-C utilities
    """

    class_: typing.ClassVar[java.lang.Class]
    OBJC_COMPILER: typing.Final = "objc"
    """
    The Objective-C compiler name, used by :meth:`Program.setCompiler(String) <Program.setCompiler>`
    """

    OBJC_MSGSEND_STUBS_CC: typing.Final = "__objc_msgSend_stub"
    """
    The Objective-C ``_objc_msgSend`` stub calling convention name (added with processor
    extension)
    """

    OBJC_CLASS_SYMBOL_PREFIX: typing.Final = "_OBJC_CLASS_$_"
    """
    String that prefixes Objective-C class symbols
    """

    OBJC_META_CLASS_SYMBOL_PREFIX: typing.Final = "_OBJC_METACLASS_$_"
    """
    String that prefixes Objective-C meta-class symbols
    """


    def __init__(self) -> None:
        ...

    @staticmethod
    def addExtensions(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Adds Objective-C processor extensions to the :obj:`Program`, which include:
         
        * A special calling convention used by objc_msgSend stubs
        * Call fixups to clear out a lot of Objective-C Automatic Reference Counting (ARC) clutter
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to add the extensions to
        :param ghidra.util.task.TaskMonitor monitor: A cancelable task monitor
        :return: The number of extensions successfully added
        :rtype: int
        :raises IOException: if an IO-related error occurred
        
        .. seealso::
        
            | `Heros in Action: Analyzing Objective-C Binaries through Decompilation and IFDS <https://doi.org/10.1109/STATIC66697.2025.00005>`_
        
            | `RE//verse 2025: Langs Beyond The C <https://youtu.be/ojXI7Gio8Pg?si=zcAaZ2KGeBFcAabn>`_
        """

    @staticmethod
    def createData(program: ghidra.program.model.listing.Program, dt: ghidra.program.model.data.DataType, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Applies the data type at the specified address
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.data.DataType dt: The :obj:`DataType` to apply
        :param ghidra.program.model.address.Address address: The :obj:`Address` to apply the data type at
        :return: The :obj:`Data`
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if data creation failed
        """

    @staticmethod
    def createMethods(program: ghidra.program.model.listing.Program, state: ObjcState, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Creates methods
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ObjcState state: The :obj:`state <ObjcState>`
        :param ghidra.app.util.importer.MessageLog log: The :obj:`log <MessageLog>`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        """

    @staticmethod
    def createNamespace(program: ghidra.program.model.listing.Program, *namespacePath: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        :return: a newly created namespace hierarchy formed from the list of given strings
        :rtype: ghidra.program.model.symbol.Namespace
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param jpype.JArray[java.lang.String] namespacePath: The namespace path
        :raises DuplicateNameException: if another label exists with the given name
        :raises InvalidInputException: if the given name is invalid
        """

    @staticmethod
    def createString(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> str:
        """
        Creates a string data type at the given address
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address address: The :obj:`Address` where to create the string at
        :return: The string, or ``null`` if it didn't get created
        :rtype: str
        """

    @staticmethod
    def createSymbol(program: ghidra.program.model.listing.Program, parentNamespace: ghidra.program.model.symbol.Namespace, symbolName: typing.Union[java.lang.String, str], symbolAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        :return: a newly created primary :obj:`Symbol`
        :rtype: ghidra.program.model.symbol.Symbol
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.symbol.Namespace parentNamespace: The parent namespace
        :param java.lang.String or str symbolName: The symbol name
        :param ghidra.program.model.address.Address symbolAddress: The symbol :obj:`Address`
        :raises InvalidInputException: if the given name is invalid
        """

    @staticmethod
    def dereferenceAsciiString(reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        :return: the string referenced at the next read pointer, or ``null`` if the pointer is
        0
        :rtype: str
        
         
        
        If ``is32bit`` is true, then 4 bytes will be read to form the pointer. Otherwise, 8 bytes
        will be read to form the pointer.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the string pointer to read
        :param jpype.JBoolean or bool is32bit: True if the string pointer is 32-bit; false if 64-bit;
        :raises IOException: if an IO-related error occurred
        """

    @staticmethod
    def fixupReferences(sectionNames: java.util.List[java.lang.String], program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Removes references to the NULL address and adjusts THUMB references to no longer be offcut
        
        :param java.util.List[java.lang.String] sectionNames: The names of the sections to fix
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        """

    @staticmethod
    def getClassNamespace(program: ghidra.program.model.listing.Program, parentNamespace: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        :return: the class inside the given parent namespace, or a newly created one if it
        doesn't exist
        :rtype: ghidra.program.model.symbol.Namespace
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.symbol.Namespace parentNamespace: The parent namespace
        :param java.lang.String or str namespaceName: The name of the class namespace to get/create
        :raises DuplicateNameException: if another label exists with the given name
        :raises InvalidInputException: if the given name is invalid
        """

    @staticmethod
    def getObjcBlocks(section: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.mem.MemoryBlock]:
        """
        :return: a :obj:`List` of :obj:`MemoryBlock`s that match the given section name
        :rtype: java.util.List[ghidra.program.model.mem.MemoryBlock]
        
        
        :param java.lang.String or str section: The section name
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        """

    @staticmethod
    @typing.overload
    def isObjc(program: ghidra.program.model.listing.Program) -> bool:
        """
        :return: true if the given :obj:`Program` is an Objective-C program; otherwise, false
        :rtype: bool
        
         
        
        NOTE: This method only identifies Mach-O Objective-C programs. ELF Objective-C programs
        produced with GCC use different section names.
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` to check
        """

    @staticmethod
    @typing.overload
    def isObjc(sectionNames: java.util.List[java.lang.String]) -> bool:
        """
        :return: true if the given :obj:`List` of section names contains an Objective-C section 
        name; otherwise, false
        :rtype: bool
        
         
        
        NOTE: This method only identifies Mach-O Objective-C programs. ELF Objective-C programs
        produced with GCC use different section names.
        
        :param java.util.List[java.lang.String] sectionNames: The :obj:`List` of section names to check
        """

    @staticmethod
    @typing.overload
    def isThumb(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> bool:
        """
        :return: whether or not the given address is THUMB code
        :rtype: bool
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.program.model.address.Address address: The :obj:`Address` to check
        """

    @staticmethod
    @typing.overload
    def isThumb(program: ghidra.program.model.listing.Program, address: typing.Union[jpype.JLong, int]) -> bool:
        """
        :return: whether or not the given address is THUMB code
        :rtype: bool
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param jpype.JLong or int address: The address to check
        """

    @staticmethod
    def readNextIndex(reader: ghidra.app.util.bin.BinaryReader, is32bit: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        :return: the next read index value
        :rtype: int
        
         
        
        If ``is32bit`` is true, then 4 bytes will be read to form the index. Otherwise, 8 bytes
        will be read to form the index.
        
        :param ghidra.app.util.bin.BinaryReader reader: A :obj:`BinaryReader` positioned at the start of the index to read
        :param jpype.JBoolean or bool is32bit: True if the index is 32-bit; false if 64-bit;
        :raises IOException: if an IO-related error occurred
        """

    @staticmethod
    def setBlocksReadOnly(memory: ghidra.program.model.mem.Memory, blockNames: java.util.List[java.lang.String]) -> None:
        """
        Sets the given block names as read-only
        
        :param ghidra.program.model.mem.Memory memory: The :obj:`Memory`
        :param java.util.List[java.lang.String] blockNames: A :obj:`List` of block names to set as read-only
        """

    @staticmethod
    def setThumbBit(program: ghidra.program.model.listing.Program, state: ObjcState, address: ghidra.program.model.address.Address) -> None:
        """
        If needed, sets the TMode bit at the specified address
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ObjcState state: The :obj:`state <ObjcState>`
        :param ghidra.program.model.address.Address address: The :obj:`Address` to set
        """

    @staticmethod
    def stripClassPrefix(name: typing.Union[java.lang.String, str]) -> str:
        """
        :return: the given name with any Objective-C class prefixes stripped off
        :rtype: str
        
        
        :param java.lang.String or str name: The name to strip
        
        .. seealso::
        
            | :obj:`.OBJC_CLASS_SYMBOL_PREFIX`
        
            | :obj:`.OBJC_META_CLASS_SYMBOL_PREFIX`
        """

    @staticmethod
    def toAddress(program: ghidra.program.model.listing.Program, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        :return: an :obj:`Address` that corresponds to the given offset in the default address 
        space
        :rtype: ghidra.program.model.address.Address
        
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param jpype.JLong or int offset: The offset to convert to an :obj:`Address`
        """


class ObjcTypeMetadataStructure(ghidra.app.util.bin.StructConverter):
    """
    Implemented by all Objective-C type metadata structures
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_TYPE_CATEGORY: typing.Final = "/ObjcTypeMetadata"

    def __init__(self, program: ghidra.program.model.listing.Program, state: ObjcState, base: typing.Union[jpype.JLong, int]) -> None:
        ...

    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Applies this :obj:`ObjcTypeMetadataStructure` to the program
        
        :param ghidra.program.model.symbol.Namespace namespace: An optional :obj:`Namespace` to apply to
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :raises java.lang.Exception: if an error occurred
        """

    def getBase(self) -> int:
        """
        :return: the base "address" of this :obj:`ObjcTypeMetadataStructure`
        :rtype: int
        """

    def getPointerSize(self) -> int:
        """
        :return: the generic pointer size used by this :obj:`ObjcTypeMetadataStructure`
        :rtype: int
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        :return: the :obj:`Program` associated with this :obj:`ObjcTypeMetadataStructure`
        :rtype: ghidra.program.model.listing.Program
        """

    def getState(self) -> ObjcState:
        """
        :return: the :obj:`state <ObjcState>` of this :obj:`ObjcTypeMetadataStructure`
        :rtype: ObjcState
        """

    def is32bit(self) -> bool:
        """
        :return: whether or not the pointer size is 32-bit
        :rtype: bool
        """

    def isArm(self) -> bool:
        """
        :return: whether or not this :obj:`ObjcTypeMetadataStructure` is for the ARM-processor
        :rtype: bool
        """

    @property
    def state(self) -> ObjcState:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def arm(self) -> jpype.JBoolean:
        ...

    @property
    def pointerSize(self) -> jpype.JInt:
        ...

    @property
    def base(self) -> jpype.JLong:
        ...


class AbstractObjcTypeMetadata(java.io.Closeable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ObjcState, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Creates a new :obj:`AbstractObjcTypeMetadata`
        
        :param ObjcState state: The :obj:`state <ObjcState>`
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :param ghidra.util.task.TaskMonitor monitor: A cancellable task monitor
        :param ghidra.app.util.importer.MessageLog log: The log
        :raises IOException: if there was an IO-related error
        :raises CancelledException: if the user cancelled the operation
        """

    def applyTo(self) -> None:
        """
        Applies the type metadata to the program
        """

    @typing.overload
    def log(self, message: typing.Union[java.lang.String, str]) -> None:
        """
        Convenience method to perform logging
        
        :param java.lang.String or str message: The message to log
        """

    @typing.overload
    def log(self, message: typing.Union[java.lang.String, str], e: java.lang.Exception) -> None:
        """
        Convenience method to perform logging (with exception)
        
        :param java.lang.String or str message: The message to log
        :param java.lang.Exception e: The exception to log
        """


class ObjcMethod(ObjcTypeMetadataStructure):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, state: ObjcState, reader: ghidra.app.util.bin.BinaryReader, methodType: ObjcMethodType) -> None:
        ...

    def getImplementation(self) -> int:
        ...

    def getMethodType(self) -> ObjcMethodType:
        ...

    def getName(self) -> str:
        ...

    def getTypes(self) -> str:
        ...

    @property
    def types(self) -> java.lang.String:
        ...

    @property
    def methodType(self) -> ObjcMethodType:
        ...

    @property
    def implementation(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class ObjcMethodType(java.lang.Enum[ObjcMethodType]):

    class_: typing.ClassVar[java.lang.Class]
    CLASS: typing.Final[ObjcMethodType]
    INSTANCE: typing.Final[ObjcMethodType]

    def getIndicator(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ObjcMethodType:
        ...

    @staticmethod
    def values() -> jpype.JArray[ObjcMethodType]:
        ...

    @property
    def indicator(self) -> jpype.JChar:
        ...


class ObjcState(java.io.Closeable):

    class_: typing.ClassVar[java.lang.Class]
    beenApplied: typing.Final[java.util.Set[java.lang.Long]]
    """
    If an index is contained in this set, then the corresponding data structure has been applied 
    to the program.
    """

    methodMap: typing.Final[java.util.Map[ghidra.program.model.address.Address, ObjcMethod]]
    """
    A map of method addresses to mangled signature strings.
    """

    thumbCodeLocations: typing.Final[java.util.Set[ghidra.program.model.address.Address]]
    """
    If an address is contained in this set, then it is thumb code.
    """

    classIndexMap: typing.Final[java.util.Map[java.lang.Long, ghidra.app.util.bin.format.objc.objc2.Objc2Class]]
    """
    A map of the index where the class structure was defined to instantiated class object.
    """

    variableMap: typing.Final[java.util.Map[ghidra.program.model.address.Address, ghidra.app.util.bin.format.objc.objc2.Objc2InstanceVariable]]
    """
    A map of instance variable addresses to mangled type strings.
    """

    libObjcOptimization: ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization
    """
    The dyld_shared_cache libobjc objc_opt_t structure, if it exists
    """

    encodings: typing.Final[ghidra.app.util.bin.format.objc.objc1.Objc1TypeEncodings]

    def __init__(self, program: ghidra.program.model.listing.Program, categoryPath: ghidra.program.model.data.CategoryPath) -> None:
        ...



__all__ = ["ObjcMethodList", "ObjcUtils", "ObjcTypeMetadataStructure", "AbstractObjcTypeMetadata", "ObjcMethod", "ObjcMethodType", "ObjcState"]
