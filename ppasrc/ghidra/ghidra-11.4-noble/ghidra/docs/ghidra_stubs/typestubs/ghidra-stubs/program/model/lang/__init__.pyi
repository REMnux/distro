from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.template
import ghidra.pcodeCPort.semantics
import ghidra.pcodeCPort.sleighbase
import ghidra.pcodeCPort.slgh_compile
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.program.model.util
import ghidra.program.util
import ghidra.sleigh.grammar
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.exception
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


class LanguageDescription(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getCompatibleCompilerSpecDescriptions(self) -> java.util.Collection[CompilerSpecDescription]:
        ...

    def getCompilerSpecDescriptionByID(self, compilerSpecID: CompilerSpecID) -> CompilerSpecDescription:
        ...

    def getDescription(self) -> str:
        ...

    def getEndian(self) -> Endian:
        ...

    def getExternalNames(self, externalTool: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Returns external names for this language associated with other tools.  For example, x86
        languages are usually referred to as "metapc" by IDA-PRO.  So, getExternalNames("IDA-PRO")
        will return "metapc" for most x86 languages.
        
        :param java.lang.String or str externalTool: external tool for looking up external tool names
        :return: external names for this language associated with tool 'key' -- null if there are no results
        :rtype: java.util.List[java.lang.String]
        """

    def getInstructionEndian(self) -> Endian:
        ...

    def getLanguageID(self) -> LanguageID:
        ...

    def getMinorVersion(self) -> int:
        ...

    def getProcessor(self) -> Processor:
        ...

    def getSize(self) -> int:
        ...

    def getVariant(self) -> str:
        ...

    def getVersion(self) -> int:
        ...

    def isDeprecated(self) -> bool:
        ...

    @property
    def externalNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def instructionEndian(self) -> Endian:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def deprecated(self) -> jpype.JBoolean:
        ...

    @property
    def variant(self) -> java.lang.String:
        ...

    @property
    def languageID(self) -> LanguageID:
        ...

    @property
    def compilerSpecDescriptionByID(self) -> CompilerSpecDescription:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def compatibleCompilerSpecDescriptions(self) -> java.util.Collection[CompilerSpecDescription]:
        ...

    @property
    def minorVersion(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def processor(self) -> Processor:
        ...

    @property
    def endian(self) -> Endian:
        ...


class InjectPayloadJumpAssist(InjectPayloadSleigh):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bName: typing.Union[java.lang.String, str], sourceName: typing.Union[java.lang.String, str]):
        ...


class OldLanguageMappingService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def lookupMagicString(magicString: typing.Union[java.lang.String, str], languageReplacementOK: typing.Union[jpype.JBoolean, bool]) -> LanguageCompilerSpecPair:
        """
        Check for a mapping of an old language-name magicString to a LanguageID/CompilerSpec pair.
        If returnLanguageReplacement is false, the returned LanguageID/CompilerSpec pair may no 
        longer exist and may require use of an OldLanguage and translation process.
        
        :param java.lang.String or str magicString: old language name magic string
        :param jpype.JBoolean or bool languageReplacementOK: if true the LanguageID/CompilerSpec pair corresponding to the
        latest language implementation will be returned if found, otherwise the a deprecated LanguageID/CompilerSpec pair
        may be returned.  This parameter should be false if there is a sensitivity to the language implementation 
        (e.g., instruction prototypes, etc.)
        :return: LanguageID/CompilerSpec pair or null if entry not found.
        :rtype: LanguageCompilerSpecPair
        """

    @staticmethod
    def processXmlLanguageString(languageString: typing.Union[java.lang.String, str]) -> LanguageCompilerSpecPair:
        """
        Parse the language string from an XML language name into the most appropriate LanguageID/CompilerSpec pair.
        The language name may either be an old name (i.e., magicString) or a new ``<language-id>:<compiler-spec-id>`` string.
        If an old language name magic-string is provided, its replacement language will be returned if known.
        The returned pair may or may not be available based upon available language implementations.
        
        :param java.lang.String or str languageString: old or new language string
        :return: LanguageID/CompilerSpec pair or null if no old name mapping could be found.
        :rtype: LanguageCompilerSpecPair
        """


class Language(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def applyContextSettings(self, ctx: ghidra.program.model.listing.DefaultProgramContext):
        """
        Apply context settings to the ProgramContext as specified by the
        configuration
        
        :param ghidra.program.model.listing.DefaultProgramContext ctx: is the default program context
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Get the AddressFactory for this language. The returned Address factory will allow
        addresses associated with physical, constant and unique spaces to be instantiated.  
        NOTE! this factory does not know about compiler or program specified spaces.  
        Spaces such as stack and overlay spaces are not defined by the language - 
        if these are needed, Program.getAddressFactory() should be used instead.
        
        :return: the AddressFactory for this language.
        :rtype: ghidra.program.model.address.AddressFactory
        
        .. seealso::
        
            | :obj:`Program.getAddressFactory()`
        """

    def getCompatibleCompilerSpecDescriptions(self) -> java.util.List[CompilerSpecDescription]:
        """
        Returns a list of all compatible compiler spec descriptions.
        The first item in the list is the default.
        
        :return: list of all compatible compiler specifications descriptions
        :rtype: java.util.List[CompilerSpecDescription]
        """

    def getCompilerSpecByID(self, compilerSpecID: CompilerSpecID) -> CompilerSpec:
        """
        Returns the compiler spec associated with a given CompilerSpecID.
        
        :param CompilerSpecID compilerSpecID: the compiler spec id
        :return: the compiler spec associated with the given id
        :rtype: CompilerSpec
        :raises CompilerSpecNotFoundException: if no such compiler spec exists
        """

    def getContextBaseRegister(self) -> Register:
        """
        Returns processor context base register or null if one has not been defined by the
        language.
        
        :return: base context register or Register.NO_CONTEXT if not defined
        :rtype: Register
        """

    def getContextRegisters(self) -> java.util.List[Register]:
        """
        Get an unsorted unmodifiable list of processor context registers that this language defines
        (includes context base register and its context field registers).
        
        :return: unmodifiable list of processor registers.
        :rtype: java.util.List[Register]
        """

    def getDefaultCompilerSpec(self) -> CompilerSpec:
        """
        Returns the default compiler spec for this language, which is used
        when a loader cannot determine the compiler spec or for upgrades when a
        program had no compiler spec registered (seriously old program, like
        Ghidra 4.1 or earlier).  NOTE: this has NOTHING to do with the
        compiler spec registered for a program.  Use Program.getCompilerSpec()
        for that!
        
        :return: the default compiler spec for this language
        :rtype: CompilerSpec
        """

    def getDefaultDataSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the preferred data space used by loaders for data sections.
        
        :return: default data address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getDefaultMemoryBlocks(self) -> jpype.JArray[ghidra.app.plugin.processors.generic.MemoryBlockDefinition]:
        """
        Returns the default memory blocks for this language.
        
        :return: the default memory blocks for this language
        :rtype: jpype.JArray[ghidra.app.plugin.processors.generic.MemoryBlockDefinition]
        """

    def getDefaultSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the default memory/code space.
        
        :return: default address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getDefaultSymbols(self) -> java.util.List[AddressLabelInfo]:
        """
        Returns the default symbols for this language.  This list does not 
        contain registers.
        
        :return: the default symbols for this language
        :rtype: java.util.List[AddressLabelInfo]
        """

    def getInstructionAlignment(self) -> int:
        """
        Get instruction alignment in terms of bytes.
        
        :return: instruction alignment
        :rtype: int
        """

    def getLanguageDescription(self) -> LanguageDescription:
        """
        Returns the LanguageDescription of this language, which contains useful
        information about the characteristics of the language.
        
        :return: the LanguageDescription of this language
        :rtype: LanguageDescription
        """

    def getLanguageID(self) -> LanguageID:
        """
        Returns the LanguageID of this language, which is used as a primary key to
        find the language when Ghidra loads it.
        
        :return: the LanguageID of this language
        :rtype: LanguageID
        """

    def getManualEntry(self, instructionMnemonic: typing.Union[java.lang.String, str]) -> ghidra.util.ManualEntry:
        """
        Get the ManualEntry for the given instruction mnemonic.
        
        :param java.lang.String or str instructionMnemonic: the instruction mnemonic
        :return: the ManualEntry or null.  A default manual entry will be returned if 
        an instruction can not be found within the index and a manual exists.
        :rtype: ghidra.util.ManualEntry
        """

    def getManualException(self) -> java.lang.Exception:
        """
        Returns the exception generated trying to load the manual, or null if it succeeded.
        
        :return: the exception generated trying to load the manual, or null if it succeeded
        :rtype: java.lang.Exception
        """

    def getManualInstructionMnemonicKeys(self) -> java.util.Set[java.lang.String]:
        """
        Returns a read-only set view of the instruction mnemonic keys defined on
        this language.
        
        :return: read-only set of instruction mnemonic keys
        :rtype: java.util.Set[java.lang.String]
        """

    def getMinorVersion(self) -> int:
        """
        Returns the minor version for this language. Returning a minor version
        number different than before could cause the program to try and "update"
        itself. Those languages which do not support this feature may always
        return a constant value of 0.
        
        :return: the language minor version number
        :rtype: int
        """

    def getNumberOfUserDefinedOpNames(self) -> int:
        """
        Get the total number of user defined pcode names.
         
        Note: only works for Pcode based languages
        
        :return: number of user defined pcodeops
        :rtype: int
        """

    def getParallelInstructionHelper(self) -> ParallelInstructionLanguageHelper:
        """
        Returns a parallel instruction helper for this language or null
        if one has not been defined.
        
        :return: parallel instruction helper or null if not applicable
        :rtype: ParallelInstructionLanguageHelper
        """

    def getProcessor(self) -> Processor:
        """
        Returns the processor name on which this language is based.
         
        For example, 30386, Pentium, 68010, etc.
        
        :return: the processor name
        :rtype: Processor
        """

    def getProgramCounter(self) -> Register:
        """
        Get the default program counter register for this language if there is
        one.
        
        :return: default program counter register.
        :rtype: Register
        """

    @typing.overload
    def getProperty(self, key: typing.Union[java.lang.String, str], defaultString: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the value of a property as a String, returning defaultString if undefined.
        
        :param java.lang.String or str key: the property key
        :param java.lang.String or str defaultString: the default value to return if property is undefined
        :return: the property value as a String, or the default value if undefined
        :rtype: str
        """

    @typing.overload
    def getProperty(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        Gets a property defined for this language, or null if that property isn't defined.
        
        :param java.lang.String or str key: the property key
        :return: the property value, or null if not defined
        :rtype: str
        """

    def getPropertyAsBoolean(self, key: typing.Union[java.lang.String, str], defaultBoolean: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Gets the value of a property as a boolean, returning defaultBoolean if undefined.
        
        :param java.lang.String or str key: the property key
        :param jpype.JBoolean or bool defaultBoolean: the default value to return if property is undefined
        :return: the property value as a boolean, or the default value if undefined
        :rtype: bool
        """

    def getPropertyAsInt(self, key: typing.Union[java.lang.String, str], defaultInt: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the value of a property as an int, returning defaultInt if undefined.
        
        :param java.lang.String or str key: the property key
        :param jpype.JInt or int defaultInt: the default value to return if property is undefined
        :return: the property value as an int, or the default value if undefined
        :rtype: int
        """

    def getPropertyKeys(self) -> java.util.Set[java.lang.String]:
        """
        Returns a read-only set view of the property keys defined on this language.
        
        :return: read-only set of property keys
        :rtype: java.util.Set[java.lang.String]
        """

    @typing.overload
    def getRegister(self, addrspc: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> Register:
        """
        Get a register given the address space it is in, its offset in the space
        and its size.
        
        :param ghidra.program.model.address.AddressSpace addrspc: address space the register is in
        :param jpype.JLong or int offset: offset of the register in the space
        :param jpype.JInt or int size: size of the register in bytes
        :return: the register
        :rtype: Register
        """

    @typing.overload
    def getRegister(self, name: typing.Union[java.lang.String, str]) -> Register:
        """
        Get a register given the name of the register
        
        :param java.lang.String or str name: Register name
        :return: the register
        :rtype: Register
        """

    @typing.overload
    def getRegister(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> Register:
        """
        Get a register given it's underlying address location and size.
        
        :param ghidra.program.model.address.Address addr: location of the register in its address space
        :param jpype.JInt or int size: the size of the register (in bytes).  A value of 0 will return the 
                    largest register at the specified addr
        :return: the register
        :rtype: Register
        """

    def getRegisterAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns address set of all registers.
        
        :return: the address set.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getRegisterNames(self) -> java.util.List[java.lang.String]:
        """
        Get an alphabetical sorted unmodifiable list of original register names 
        (including context registers).  Names correspond to orignal register
        name and not aliases which may be defined.
        
        :return: alphabetical sorted unmodifiable list of original register names.
        :rtype: java.util.List[java.lang.String]
        """

    @typing.overload
    def getRegisters(self, address: ghidra.program.model.address.Address) -> jpype.JArray[Register]:
        """
        Returns all the registers (each different size is a different register)
        for an address.
        
        :param ghidra.program.model.address.Address address: the register address for which to return all registers.
        :return: all the registers (each different size is a different register)
                for an address.
        :rtype: jpype.JArray[Register]
        """

    @typing.overload
    def getRegisters(self) -> java.util.List[Register]:
        """
        Get an unsorted unmodifiable list of Register objects that this language defines
        (including context registers).
        
        :return: unmodifiable list of processor registers.
        :rtype: java.util.List[Register]
        """

    def getSegmentedSpace(self) -> str:
        """
        Returns the name of the segmented space for this language, or the
        empty string if the memory model for this language is not
        segmented.
        
        :return: the name of the segmented space or ""
        :rtype: str
        """

    def getSortedVectorRegisters(self) -> java.util.List[Register]:
        """
        Returns an unmodifiable list of vector registers, sorted first by size and then by name.
        
        :return: unmodifiable list of vector registers.
        :rtype: java.util.List[Register]
        """

    def getUserDefinedOpName(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the user define name for a given index. Certain pcode has operations
        defined only by name that when the pcode returns, only the index is
        known.
         
        Note: only works for Pcode based languages
        
        :param jpype.JInt or int index: user defined pcodeop index
        :return: pcodeop name or null if not defined
        :rtype: str
        """

    def getVersion(self) -> int:
        """
        Returns the major version for this language. Returning a version number
        different than before could cause the program to try and "update" itself.
        Those languages which do not support this feature may always return a
        constant value of 1.
        
        :return: the language version number
        :rtype: int
        """

    def getVolatileAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns an AddressSetView of the volatile addresses for this language
        
        :return: an AddressSetView of the volatile addresses for this language
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def hasManual(self) -> bool:
        """
        Returns whether the language has a valid manual defined.
        
        :return: if the language has a manual
        :rtype: bool
        """

    def hasProperty(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns whether this lanugage has a property defined.
        
        :param java.lang.String or str key: the property key
        :return: if the property is defined
        :rtype: bool
        """

    def isBigEndian(self) -> bool:
        """
        get the Endian type for this language. (If a language supports both, then
        this returns an initial or default value.)
        
        :return: true for BigEndian, false for LittleEndian.
        :rtype: bool
        """

    def isVolatile(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the language has defined the specified location as
        volatile.
        
        :param ghidra.program.model.address.Address addr: location address
        :return: true if specified address is within a volatile range
        :rtype: bool
        """

    def parse(self, buf: ghidra.program.model.mem.MemBuffer, context: ProcessorContext, inDelaySlot: typing.Union[jpype.JBoolean, bool]) -> InstructionPrototype:
        """
        Get the InstructionPrototype that matches the bytes presented by the
        MemBuffer object.
        
        :param ghidra.program.model.mem.MemBuffer buf: the MemBuffer that presents the bytes in Memory at some
                    address as if they were an array of bytes starting at index 0.
        :param ProcessorContext context: the processor context at the address to be disassembled
        :param jpype.JBoolean or bool inDelaySlot: true if this instruction should be parsed as if it were in a
                    delay slot
        :return: the InstructionPrototype that matches the bytes in buf.
        :rtype: InstructionPrototype
        :raises InsufficientBytesException: thrown if there are not enough bytes in memory to satisfy
                        a legal instruction.
        :raises UnknownInstructionException: thrown if the byte pattern does not match any legal
                        instruction.
        """

    def reloadLanguage(self, taskMonitor: ghidra.util.task.TaskMonitor):
        """
        Refreshes the definition of this language if possible.  Use of this method is 
        intended for development purpose only since stale references to prior
        language resources (e.g., registers) may persist.
        
        :param ghidra.util.task.TaskMonitor taskMonitor: monitor for progress back to the user
        :raises IOException: if error occurs while reloading language spec file(s)
        """

    def supportsPcode(self) -> bool:
        """
        Return true if the instructions in this language support Pcode.
        
        :return: true if language supports the use of pcode
        :rtype: bool
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def numberOfUserDefinedOpNames(self) -> jpype.JInt:
        ...

    @property
    def manualEntry(self) -> ghidra.util.ManualEntry:
        ...

    @property
    def segmentedSpace(self) -> java.lang.String:
        ...

    @property
    def sortedVectorRegisters(self) -> java.util.List[Register]:
        ...

    @property
    def userDefinedOpName(self) -> java.lang.String:
        ...

    @property
    def languageID(self) -> LanguageID:
        ...

    @property
    def registerNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def compatibleCompilerSpecDescriptions(self) -> java.util.List[CompilerSpecDescription]:
        ...

    @property
    def compilerSpecByID(self) -> CompilerSpec:
        ...

    @property
    def volatileAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def defaultSymbols(self) -> java.util.List[AddressLabelInfo]:
        ...

    @property
    def languageDescription(self) -> LanguageDescription:
        ...

    @property
    def defaultSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def registers(self) -> jpype.JArray[Register]:
        ...

    @property
    def defaultDataSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def propertyKeys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def contextRegisters(self) -> java.util.List[Register]:
        ...

    @property
    def programCounter(self) -> Register:
        ...

    @property
    def parallelInstructionHelper(self) -> ParallelInstructionLanguageHelper:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @property
    def instructionAlignment(self) -> jpype.JInt:
        ...

    @property
    def contextBaseRegister(self) -> Register:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def processor(self) -> Processor:
        ...

    @property
    def manualException(self) -> java.lang.Exception:
        ...

    @property
    def registerAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def defaultCompilerSpec(self) -> CompilerSpec:
        ...

    @property
    def manualInstructionMnemonicKeys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def defaultMemoryBlocks(self) -> jpype.JArray[ghidra.app.plugin.processors.generic.MemoryBlockDefinition]:
        ...

    @property
    def minorVersion(self) -> jpype.JInt:
        ...

    @property
    def register(self) -> Register:
        ...


class CompilerSpec(java.lang.Object):
    """
    Interface for requesting specific information about the compiler used to
    build a Program being analyzed.  Major elements that can be queried include:
    - AddressSpaces from the Language plus compiler specific ones like "stack"
    - DataOrganization describing size and alignment of primitive data-types: int, long, pointers, etc.
    - PrototypeModels describing calling conventions used by the compiler: __stdcall, __thiscall, etc.
    - InjectPayloads or p-code that can used for
        - Call-fixups, substituting p-code for compiler bookkeeping functions during analysis.
        - Callother-fixups, substituting p-code for user-defined p-code operations.
    - Memory ranges that the compiler treats as global
    - Context and register values known to the compiler over specific memory ranges
    """

    class EvaluationModelType(java.lang.Enum[CompilerSpec.EvaluationModelType]):
        """
        Labels for PrototypeModels that are used by default for various analysis/evaluation
        use-cases, when the true model isn't known.  The CompilerSpec maintains a specific
        default PrototypeModel to be used for each use-case label.
        """

        class_: typing.ClassVar[java.lang.Class]
        EVAL_CURRENT: typing.Final[CompilerSpec.EvaluationModelType]
        EVAL_CALLED: typing.Final[CompilerSpec.EvaluationModelType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CompilerSpec.EvaluationModelType:
            ...

        @staticmethod
        def values() -> jpype.JArray[CompilerSpec.EvaluationModelType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CALLING_CONVENTION_unknown: typing.Final = "unknown"
    CALLING_CONVENTION_default: typing.Final = "default"
    CALLING_CONVENTION_cdecl: typing.Final = "__cdecl"
    CALLING_CONVENTION_pascal: typing.Final = "__pascal"
    CALLING_CONVENTION_thiscall: typing.Final = "__thiscall"
    CALLING_CONVENTION_stdcall: typing.Final = "__stdcall"
    CALLING_CONVENTION_fastcall: typing.Final = "__fastcall"
    CALLING_CONVENTION_vectorcall: typing.Final = "__vectorcall"
    CALLING_CONVENTION_rustcall: typing.Final = "__rustcall"

    def applyContextSettings(self, ctx: ghidra.program.model.listing.DefaultProgramContext):
        """
        Apply context settings to the ProgramContext
        as specified by the configuration
        
        :param ghidra.program.model.listing.DefaultProgramContext ctx: is the ProgramContext
        """

    def doesCDataTypeConversions(self) -> bool:
        """
        Return true if function prototypes respect the C-language data-type conversion conventions.
        This amounts to converting array data-types to pointer-to-element data-types.
        In C, arrays are passed by reference (structures are still passed by value)
        
        :return: if the prototype does C-language data-type conversions
        :rtype: bool
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode this entire specification to a stream.  A document is written with
        root element ``<compiler_spec>``.
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for errors writing to the underlying stream
        """

    def findBestCallingConvention(self, params: jpype.JArray[ghidra.program.model.listing.Parameter]) -> PrototypeModel:
        """
        Find the best guess at a calling convention model from this compiler spec
        given an ordered list of (potential) parameters with storage assignments.
        
        :param jpype.JArray[ghidra.program.model.listing.Parameter] params: is the ordered list of parameters
        :return: prototype model corresponding to the specified function signature
        :rtype: PrototypeModel
        """

    def getAddressSpace(self, spaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSpace:
        """
        Get an address space by name.  This can be value added over the normal AddressFactory.getAddressSpace
        routine because the compiler spec can refer to special internal spaces like the stack space
        
        :param java.lang.String or str spaceName: is the name of the address space
        :return: the corresponding AddressSpace object
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getAllModels(self) -> jpype.JArray[PrototypeModel]:
        """
        
        
        :return: all possible PrototypeModels, including calling conventions and merge models
        :rtype: jpype.JArray[PrototypeModel]
        """

    def getCallingConvention(self, name: typing.Union[java.lang.String, str]) -> PrototypeModel:
        """
        Returns the Calling Convention Model with the given name.
        
        :param java.lang.String or str name: the name of the calling convention to retrieve
        :return: the calling convention with the given name or null if there is none with that name.
        :rtype: PrototypeModel
        """

    def getCallingConventions(self) -> jpype.JArray[PrototypeModel]:
        """
        
        
        :return: an array of the prototype models. Each prototype model specifies a calling convention.
        :rtype: jpype.JArray[PrototypeModel]
        """

    def getCompilerSpecDescription(self) -> CompilerSpecDescription:
        """
        
        
        :return: a brief description of the compiler spec
        :rtype: CompilerSpecDescription
        """

    def getCompilerSpecID(self) -> CompilerSpecID:
        """
        
        
        :return: the id string associated with this compiler spec;
        :rtype: CompilerSpecID
        """

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization:
        ...

    def getDecompilerOutputLanguage(self) -> DecompilerLanguage:
        """
        Get the language that the decompiler produces
        
        :return: an enum specifying the language
        :rtype: DecompilerLanguage
        """

    def getDefaultCallingConvention(self) -> PrototypeModel:
        """
        Returns the prototype model that is the default calling convention or else null.
        
        :return: the default calling convention or null.
        :rtype: PrototypeModel
        """

    def getLanguage(self) -> Language:
        """
        Get the Language this compiler spec is based on.  Note that
        compiler specs may be reused across multiple languages in the
        cspec files on disk, but once loaded in memory are actually
        separate objects.  (M:N on disk, 1:N in memory)
        
        :return: the language this compiler spec is based on
        :rtype: Language
        """

    def getPcodeInjectLibrary(self) -> PcodeInjectLibrary:
        ...

    @typing.overload
    def getProperty(self, key: typing.Union[java.lang.String, str], defaultString: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the value of a property as a String, returning defaultString if undefined.
        
        :param java.lang.String or str key: the property key
        :param java.lang.String or str defaultString: the default value to return if property is undefined
        :return: the property value as a String, or the default value if undefined
        :rtype: str
        """

    @typing.overload
    def getProperty(self, key: typing.Union[java.lang.String, str]) -> str:
        """
        Gets a property defined for this language, or null if that property isn't defined.
        
        :param java.lang.String or str key: the property key
        :return: the property value, or null if not defined
        :rtype: str
        """

    def getPropertyAsBoolean(self, key: typing.Union[java.lang.String, str], defaultBoolean: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Gets the value of a property as a boolean, returning defaultBoolean if undefined.
        
        :param java.lang.String or str key: the property key
        :param jpype.JBoolean or bool defaultBoolean: the default value to return if property is undefined
        :return: the property value as a boolean, or the default value if undefined
        :rtype: bool
        """

    def getPropertyAsInt(self, key: typing.Union[java.lang.String, str], defaultInt: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the value of a property as an int, returning defaultInt if undefined.
        
        :param java.lang.String or str key: the property key
        :param jpype.JInt or int defaultInt: the default value to return if property is undefined
        :return: the property value as an int, or the default value if undefined
        :rtype: int
        """

    def getPropertyKeys(self) -> java.util.Set[java.lang.String]:
        """
        Returns a read-only set view of the property keys defined on this language.
        
        :return: read-only set of property keys
        :rtype: java.util.Set[java.lang.String]
        """

    def getPrototypeEvaluationModel(self, modelType: CompilerSpec.EvaluationModelType) -> PrototypeModel:
        """
        Get the evaluation model matching the given type.
        If analysis needs to apply a PrototypeModel to a function but a specific model
        is not known, then this method can be used to select a putative PrototypeModel
        based on the analysis use-case:
            - EVAL_CURRENT indicates the model to use for the "current function" being analyzed
            - EVAL_CALLED indicates the model to use for a function called by the current function
        
        :param CompilerSpec.EvaluationModelType modelType: is the type of evaluation model
        :return: prototype evaluation model
        :rtype: PrototypeModel
        """

    def getStackBaseSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the physical space used for stack data storage
        
        :return: address space which contains the stack
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getStackPointer(self) -> Register:
        """
        Get the default Stack Pointer register for this language if there is one.
        
        :return: default stack pointer register.
        :rtype: Register
        """

    def getStackSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the stack address space defined by this specification
        
        :return: stack address space
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def hasProperty(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns whether this language has a property defined.
        
        :param java.lang.String or str key: the property key
        :return: if the property is defined
        :rtype: bool
        """

    def isEquivalent(self, obj: CompilerSpec) -> bool:
        """
        Determine if this CompilerSpec is equivalent to another specified instance
        
        :param CompilerSpec obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isGlobal(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        
        
        :param ghidra.program.model.address.Address addr: is the (start of the) storage location
        :return: true if the specified storage location has been designated "global" in scope
        :rtype: bool
        """

    def isStackRightJustified(self) -> bool:
        """
        Indicates whether variables are right-justified within the 
        stack alignment.
        
        :return: true if right stack justification applies.
        :rtype: bool
        """

    @staticmethod
    def isUnknownCallingConvention(callingConventionName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the specified calling convention name is treated as the unknown calling
        convention (blank or {code "unknown"}).  Other unrecognized names will return false.
        This static method does not assume any specific compiler specification.
        
        :param java.lang.String or str callingConventionName: calling convention name or null
        :return: true if specified name is blank or {code "unknown"}
        :rtype: bool
        """

    def matchConvention(self, conventionName: typing.Union[java.lang.String, str]) -> PrototypeModel:
        """
        Get the PrototypeModel which corresponds to the given calling convention name.
        If no match is found the default prototype model is returned.
        
        :param java.lang.String or str conventionName: calling convention name.
        :return: the matching model or the defaultModel if nothing matches
        :rtype: PrototypeModel
        """

    def stackGrowsNegative(self) -> bool:
        """
        
        
        :return: true if the stack grows with negative offsets
        :rtype: bool
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def prototypeEvaluationModel(self) -> PrototypeModel:
        ...

    @property
    def callingConvention(self) -> PrototypeModel:
        ...

    @property
    def defaultCallingConvention(self) -> PrototypeModel:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def compilerSpecID(self) -> CompilerSpecID:
        ...

    @property
    def stackSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def global_(self) -> jpype.JBoolean:
        ...

    @property
    def compilerSpecDescription(self) -> CompilerSpecDescription:
        ...

    @property
    def dataOrganization(self) -> ghidra.program.model.data.DataOrganization:
        ...

    @property
    def stackRightJustified(self) -> jpype.JBoolean:
        ...

    @property
    def decompilerOutputLanguage(self) -> DecompilerLanguage:
        ...

    @property
    def allModels(self) -> jpype.JArray[PrototypeModel]:
        ...

    @property
    def stackPointer(self) -> Register:
        ...

    @property
    def stackBaseSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def pcodeInjectLibrary(self) -> PcodeInjectLibrary:
        ...

    @property
    def propertyKeys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def callingConventions(self) -> jpype.JArray[PrototypeModel]:
        ...


class InvalidPrototype(InstructionPrototype, ParserContext):
    """
    Class to represent an invalid instruction prototype.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lang: Language):
        """
        Construct a new invalid instruction prototype.
        
        :param Language lang: is the Language for which the invalid instruction is discovered
        """

    def getOpRepresentation(self, opIndex: typing.Union[jpype.JInt, int], buf: ghidra.program.model.mem.MemBuffer, context: ProcessorContextView, label: typing.Union[java.lang.String, str]) -> str:
        ...


class ReadOnlyProcessorContext(ProcessorContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: ProcessorContextView):
        ...


class RegisterValue(java.lang.Object):
    """
    Class for representing register values that keep track of which bits are actually set.  
    Values are stored as big-endian: MSB of mask is stored at bytes index 0,
    MSB of value is stored at (bytes.length/2).
     
    Bytes storage example for 4-byte register:
        Index:  0   1   2   3   4   5   6   7
            |MSB|   |   |LSB|MSB|   |   |LSB|
            | ----MASK----- | ----VALUE---- |
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, register: Register):
        """
        Creates a new RegisterValue for a register that has no value (all mask bits are 0);
        
        :param Register register: the register associated with this value.
        """

    @typing.overload
    def __init__(self, register: Register, value: java.math.BigInteger):
        """
        Constructs a new RegisterValue object for the given register and value.
        
        :param java.math.BigInteger value: the value to set. All mask bits for the given register are set to "valid" (on).
        """

    @typing.overload
    def __init__(self, register: Register, value: java.math.BigInteger, mask: java.math.BigInteger):
        """
        Constructs a new RegisterValue using a specified value and mask
        
        :param Register register: 
        :param java.math.BigInteger value: value corresponding to specified register
        :param java.math.BigInteger mask: value mask identifying which value bits are valid
        """

    @typing.overload
    def __init__(self, register: Register, bytes: jpype.JArray[jpype.JByte]):
        """
        Constructs a new RegisterValue object for the given register and the mask/value byte array
        
        :param Register register: the register associated with this value.  The register specifies which bits
        int the total mask/value arrays are used for this register which may be a sub-register of
        some larger register.  The byte[] always is sized for the largest Register that contains
        the given register.
        :param jpype.JArray[jpype.JByte] bytes: the mask/value array - the first n/2 bytes are the mask and the last n/2 bytes
        are the value bits.
        """

    @typing.overload
    def assign(self, subRegister: Register, value: RegisterValue) -> RegisterValue:
        """
        Assign the value to a portion of this register value
        
        :param Register subRegister: identifies a piece of this register value to be assigned
        :param RegisterValue value: new value
        :return: new register value after assignment
        :rtype: RegisterValue
        """

    @typing.overload
    def assign(self, subRegister: Register, value: java.math.BigInteger) -> RegisterValue:
        """
        Assign the value to a portion of this register value
        
        :param Register subRegister: identifies a piece of this register value to be assigned
        :param java.math.BigInteger value: new value
        :return: new register value after assignment
        :rtype: RegisterValue
        """

    def clearBitValues(self, mask: jpype.JArray[jpype.JByte]) -> RegisterValue:
        """
        Clears the value bits corresponding to the "ON" bits in the given mask.
        
        :param jpype.JArray[jpype.JByte] mask: the byte array containing the mask bits to clear.
        :return: a new MaskedBytes object containg the original value bits and mask bits cleared 
        where the passed in mask bits were "on".
        :rtype: RegisterValue
        """

    def combineValues(self, otherValue: RegisterValue) -> RegisterValue:
        """
        Creates a new RegisterValue. 
        The resulting value is a combination of this RegisterValue and the given RegisterValue,
        where the given RegisterValue's value bits take precedence over this RegisterValue's value. 
         
        Each value bit is determined as follows: 
        If the mask bit in ``otherValue`` is "ON", then ``otherValue``'s value bit is used. Otherwise,
        ``this`` value bit used.
         
        The mask bits are OR'd together to form the new mask bits.
        
        :param RegisterValue otherValue: the currently stored mask and value bytes.  The base register must match the base register 
        of this register value.
        :return: a new RegisterValue object containing the original value bits where the new array 
        mask bits are "OFF" and the new value bits where the new array mask bits are "ON".
        If the registers differ the resulting register value will be relative to the base register.
        :rtype: RegisterValue
        """

    def getBaseRegisterValue(self) -> RegisterValue:
        """
        Returns this register value in terms of the base register
        """

    def getBaseValueMask(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the value mask that indicates which bits relative to the base register have a
        valid value.
        """

    def getRegister(self) -> Register:
        """
        Returns the register used in this register value object.
        
        :return: the register used in this register value object
        :rtype: Register
        """

    def getRegisterValue(self, newRegister: Register) -> RegisterValue:
        ...

    def getSignedValue(self) -> java.math.BigInteger:
        """
        Returns the signed value for this register if all the appropriate mask bits are "ON". Otherwise,
        null is return.
        
        :return: the signed value for this register if all the appropriate mask bits are "ON". Otherwise,
        returns null.
        :rtype: java.math.BigInteger
        """

    def getSignedValueIgnoreMask(self) -> java.math.BigInteger:
        """
        Returns the signed value for this register regardless of the mask bits.  Bits that have "OFF" mask
        bits will have the value of 0.
        
        :return: the signed value for this register regardless of the mask bits.  Bits that have "OFF" mask
        bits will have the value of 0.
        :rtype: java.math.BigInteger
        """

    def getUnsignedValue(self) -> java.math.BigInteger:
        """
        Returns the unsigned value for this register if all the appropriate mask bits are "ON". Otherwise,
        null is return.
        
        :return: the value for this register if all the appropriate mask bits are "ON". Otherwise,
        returns null.
        :rtype: java.math.BigInteger
        """

    def getUnsignedValueIgnoreMask(self) -> java.math.BigInteger:
        """
        Returns the unsigned value for this register regardless of the mask bits.  Bits that have "OFF" mask
        bits will have the value of 0.
        
        :return: the unsigned value for this register regardless of the mask bits.  Bits that have "OFF" mask
        bits will have the value of 0.
        :rtype: java.math.BigInteger
        """

    def getValueMask(self) -> java.math.BigInteger:
        """
        Returns a value mask which is sized based upon the register
        """

    def hasAnyValue(self) -> bool:
        ...

    def hasValue(self) -> bool:
        """
        Tests if this RegisterValue contains valid value bits for the entire register.  In otherwords
        getSignedValue() or getUnsignedValue will not return null.
        
        :return: true if all mask bits for the associated register are "ON".
        :rtype: bool
        """

    def toBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the mask/value bytes for this register value.
        
        :return: the mask/value bytes for this register value.
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def baseRegisterValue(self) -> RegisterValue:
        ...

    @property
    def valueMask(self) -> java.math.BigInteger:
        ...

    @property
    def baseValueMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def unsignedValueIgnoreMask(self) -> java.math.BigInteger:
        ...

    @property
    def unsignedValue(self) -> java.math.BigInteger:
        ...

    @property
    def signedValueIgnoreMask(self) -> java.math.BigInteger:
        ...

    @property
    def signedValue(self) -> java.math.BigInteger:
        ...

    @property
    def registerValue(self) -> RegisterValue:
        ...

    @property
    def register(self) -> Register:
        ...


class CompilerSpecNotFoundException(java.io.IOException):
    """
    Exception class used when the named compiler spec cannot be found.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, languageId: LanguageID, compilerSpecID: CompilerSpecID):
        ...

    @typing.overload
    def __init__(self, languageId: LanguageID, compilerSpecID: CompilerSpecID, resourceFileName: typing.Union[java.lang.String, str], e: java.lang.Throwable):
        ...


class LanguageVersionException(ghidra.util.exception.VersionException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], upgradable: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a language version exception
        
        :param java.lang.String or str msg: condition detail
        :param jpype.JBoolean or bool upgradable: true indicates that an upgrade is possible.
        """

    @typing.overload
    def __init__(self, oldLanguage: Language, languageTranslator: ghidra.program.util.LanguageTranslator):
        """
        Construct a major upgradeable language version exception
        
        :param Language oldLanguage: old language stub
        :param ghidra.program.util.LanguageTranslator languageTranslator: language transalator
        """

    @staticmethod
    def check(language: Language, languageVersion: typing.Union[jpype.JInt, int], languageMinorVersion: typing.Union[jpype.JInt, int]) -> LanguageVersionException:
        """
        Check language against required version information.  If not a match or upgradeable
        a :obj:`LanguageNotFoundException` will be thrown.  If an upgradeable :obj:`LanguageVersionException`
        is returned, a major version change will also include the appropriate Old-Language stub and
        :obj:`LanguageTranslator` required to facilitate a language upgrade.
        
        :param Language language: language corresponding to desired language ID
        :param jpype.JInt or int languageVersion: required major language version
        :param jpype.JInt or int languageMinorVersion: required minor language version.  A negative minor version will be ignored.
        :return: null if language matches, otherwise an upgradeable :obj:`LanguageVersionException`.
        :rtype: LanguageVersionException
        :raises LanguageNotFoundException: if language is a mismatch and is not upgradeable.
        """

    @staticmethod
    def checkForLanguageChange(e: LanguageNotFoundException, languageID: LanguageID, languageVersion: typing.Union[jpype.JInt, int]) -> LanguageVersionException:
        """
        Determine if a missing language resulting in a :obj:`LanguageNotFoundException` can be 
        upgraded to a replacement language via a language translation.
        
        :param LanguageNotFoundException e: original :obj:`LanguageNotFoundException`
        :param LanguageID languageID: language ID of original language requested
        :param jpype.JInt or int languageVersion: original language major version
        :return: upgradeable :obj:`LanguageVersionException`
        :rtype: LanguageVersionException
        :raises LanguageNotFoundException: original exception if a language transaltion is not available
        """

    def getLanguageTranslator(self) -> ghidra.program.util.LanguageTranslator:
        """
        Old language upgrade translator if language translation required
        
        :return: language upgrade translator or null
        :rtype: ghidra.program.util.LanguageTranslator
        """

    def getOldLanguage(self) -> Language:
        """
        Old language stub if language translation required
        
        :return: Old language stub or null
        :rtype: Language
        """

    @property
    def languageTranslator(self) -> ghidra.program.util.LanguageTranslator:
        ...

    @property
    def oldLanguage(self) -> Language:
        ...


class InstructionPrototype(java.lang.Object):
    """
    InstructionPrototype is designed to describe one machine level instruction.
    A language parser can return the same InstructionProtoype object for the 
    same type node. Prototypes for instructions will normally be fixed for a node.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID_DEPTH_CHANGE: typing.Final = 16777216

    def getAddress(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> ghidra.program.model.address.Address:
        """
        If the indicated operand is an address, this gets the address value for 
        that operand
        
        :param jpype.JInt or int opIndex: index of the operand.
        :param InstructionContext context: the instruction context.
        :return: the address indicated by the operand
        :rtype: ghidra.program.model.address.Address
        """

    def getDelaySlotByteCount(self) -> int:
        """
        
        
        :return: the number of delay-slot instruction bytes which correspond
        to this prototype.
        :rtype: int
        """

    def getDelaySlotDepth(self, context: InstructionContext) -> int:
        """
        Get the number of delay slot instructions for this
        argument. This should be 0 for instructions which don't have a
        delay slot.  This is used to support the delay slots found on
        some RISC processors such as SPARC and the PA-RISC. This
        returns an integer instead of a boolean in case some other
        processor executes more than one instruction from a delay slot.
        
        :param InstructionContext context: the instruction context
        :return: the number of delay slot instructions for this instruction.
        :rtype: int
        """

    def getFallThrough(self, context: InstructionContext) -> ghidra.program.model.address.Address:
        """
        Get the Address for default flow after instruction.
        
        :param InstructionContext context: the instruction context
        :return: Address of fall through flow or null if flow
        does not fall through this instruction.
        :rtype: ghidra.program.model.address.Address
        """

    def getFallThroughOffset(self, context: InstructionContext) -> int:
        """
        Get the byte offset to the default flow after instruction.
        If this instruction does not have a fall-through due to flow
        behavior, this method will still return an offset which accounts for 
        the instruction length including delay slotted instructions if 
        applicable.
        
        :param InstructionContext context: the instruction context
        :return: int how much to add to the current address to get
        the fall through address.
        :rtype: int
        """

    def getFlowType(self, context: InstructionContext) -> ghidra.program.model.symbol.FlowType:
        """
        Get the flow type of this instruction. Used
        for analysis purposes. i.e., how this
        instruction flows to the next instruction.
        
        :param InstructionContext context: the instruction context
        :return: flow type.
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getFlows(self, context: InstructionContext) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get an array of Address objects for all flows other than
        a fall-through, null if no flows.
        
        :param InstructionContext context: the instruction context.
        :return: an array of Address objects for all flows other than
        a fall-through, null if no flows.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def getInputObjects(self, context: InstructionContext) -> jpype.JArray[java.lang.Object]:
        """
        Get the Result objects produced/affected by this instruction
        These would probably only be Register or Address
        
        :param InstructionContext context: the instruction context
        :return: an array of objects that are used by this instruction
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getInstructionMask(self) -> Mask:
        """
        Get a Mask that describe which bits of this instruction determine
        the opcode.
        
        :return: a Mask for the opcode bits or null if unknown.
        :rtype: Mask
        """

    def getLanguage(self) -> Language:
        """
        Get processor language module associated with this prototype.
        
        :return: language module
        :rtype: Language
        """

    def getLength(self) -> int:
        """
        Get the length of this CodeProtoype.
        
        :return: the length of this CodeProtoype.
        :rtype: int
        """

    def getMnemonic(self, context: InstructionContext) -> str:
        """
        Get the mnemonic for this CodeProtype.  Examples: "MOV" and
        "CALL" for instructions and "DB" and "DA" for data.
        
        :param InstructionContext context: the instruction context
        :return: the mnemonic for this CodePrototype.
        :rtype: str
        """

    def getNumOperands(self) -> int:
        """
        Return the number of operands in this instruction.
        """

    def getOpObjects(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> jpype.JArray[java.lang.Object]:
        """
        Get objects used by this operand (Address, Scalar, Register ...)
        
        :param jpype.JInt or int opIndex: the index of the operand. (zero based)
        :param InstructionContext context: the instruction context
        :return: an array of objects found at this operand.
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getOpRepresentationList(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> java.util.ArrayList[java.lang.Object]:
        """
        Get a List of Objects that can be used to render an operands representation.
        
        :param jpype.JInt or int opIndex: operand to get the Representation List
        :param InstructionContext context: the instruction context
        :return: ArrayList of Register, Address, Scalar, VariableOffset and Character objects
                of null if the operation isn't supported
        :rtype: java.util.ArrayList[java.lang.Object]
        """

    def getOpType(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> int:
        """
        Get the type of a specific operand.
        
        :param jpype.JInt or int opIndex: the index of the operand. (zero based)
        :param InstructionContext context: the instruction context.
        :return: the type of the operand.
        :rtype: int
        """

    def getOperandRefType(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext, override: ghidra.program.model.pcode.PcodeOverride) -> ghidra.program.model.symbol.RefType:
        """
        Get the suggested operand reference type.
        
        :param jpype.JInt or int opIndex: the index of the operand. (zero based)
        :param InstructionContext context: the instruction context
        :param ghidra.program.model.pcode.PcodeOverride override: if not null, steers local overrides of pcode generation
        :return: reference type.
        :rtype: ghidra.program.model.symbol.RefType
        """

    def getOperandValueMask(self, operandIndex: typing.Union[jpype.JInt, int]) -> Mask:
        """
        Get a Mask that describe which bits of this instruction determine
        the operand value.
        
        :return: a Mask for the operand bits or null if unknown.
        :rtype: Mask
        """

    def getParserContext(self, buf: ghidra.program.model.mem.MemBuffer, processorContext: ProcessorContextView) -> ParserContext:
        """
        Get a new instance of a ParserContext.
        
        :param ghidra.program.model.mem.MemBuffer buf: 
        :param ProcessorContextView processorContext: 
        :return: instruction ParserContext
        :rtype: ParserContext
        :raises MemoryAccessException:
        """

    @typing.overload
    def getPcode(self, context: InstructionContext, override: ghidra.program.model.pcode.PcodeOverride) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Get an array of PCode operations (micro code) that this instruction
        performs.
        
        :param InstructionContext context: the instruction context
        :param ghidra.program.model.pcode.PcodeOverride override: if not null, may indicate that different elements of the pcode generation are overridden
        :return: array of PCODE,
                zero length array if language doesn't support PCODE for this instruction
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    @typing.overload
    def getPcode(self, context: InstructionContext, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Get an array of PCode operations (micro code) that a particular operand
        performs to compute its value.
        
        :param InstructionContext context: the instruction context
        :param jpype.JInt or int opIndex: the index of the operand for which to get PCode.
        :return: array of PCODE,
                zero length array if language doesn't support PCODE for this instruction
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    def getPcodePacked(self, encoder: ghidra.program.model.pcode.PatchEncoder, context: InstructionContext, override: ghidra.program.model.pcode.PcodeOverride):
        """
        Same as getPcode but emits the operations directly to an encoder to optimize transfer to other processes
        
        :param ghidra.program.model.pcode.PatchEncoder encoder: is the encoder receiving the operations
        :param InstructionContext context: the instruction context
        :param ghidra.program.model.pcode.PcodeOverride override: if not null, may indicate that different elements of the pcode generation are overridden
        :raises IOException: for errors writing to any stream underlying the encoder
        """

    def getPseudoParserContext(self, addr: ghidra.program.model.address.Address, buffer: ghidra.program.model.mem.MemBuffer, processorContext: ProcessorContextView) -> ParserContext:
        """
        Get a ParserContext by parsing bytes outside of the normal disassembly process
        
        :param ghidra.program.model.address.Address addr: where the ParserContext is needed
        :param ghidra.program.model.mem.MemBuffer buffer: of actual bytes
        :param ProcessorContextView processorContext: 
        :return: 
        :rtype: ParserContext
        :raises InsufficientBytesException: 
        :raises UnknownInstructionException: 
        :raises UnknownContextException: 
        :raises MemoryAccessException:
        """

    def getRegister(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> Register:
        """
        If the indicated operand is a register, this gets the register value 
        for that operand
        
        :param jpype.JInt or int opIndex: index of the operand.
        :param InstructionContext context: the instruction context
        :return: a register description for the indicated operand
        :rtype: Register
        """

    def getResultObjects(self, context: InstructionContext) -> jpype.JArray[java.lang.Object]:
        """
        Get the Result objects produced/affected by this instruction
        These would probably only be Register or Address
        
        :param InstructionContext context: the instruction context
        :return: an array of objects that are affected by this instruction
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getScalar(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> ghidra.program.model.scalar.Scalar:
        """
        If the indicated operand is a scalar, this gets the scalar value for 
        that operand
        
        :param jpype.JInt or int opIndex: index of the operand.
        :param InstructionContext context: the instruction context
        :return: the scalar for the indicated operand
        :rtype: ghidra.program.model.scalar.Scalar
        """

    def getSeparator(self, opIndex: typing.Union[jpype.JInt, int], context: InstructionContext) -> str:
        """
        Get the separator strings between an operand.
         
        The separator string for 0 are the characters before the first operand.
        The separator string for numOperands+1 are the characters after the last operand.
        
        :param jpype.JInt or int opIndex: valid values are 0 thru numOperands+1
        :param InstructionContext context: the instruction context
        :return: separator string, or null if there is no string
        :rtype: str
        """

    def hasCrossBuildDependency(self) -> bool:
        """
        
        
        :return: true if instruction semantics have a CrossBuild instruction
        dependency which may require a robust InstructionContext with access
        to preceding instructions
        :rtype: bool
        """

    def hasDelaySlots(self) -> bool:
        """
        
        
        :return: true if instruction prototype expects one or more delay slotted
        instructions to exist.
        :rtype: bool
        """

    def hasDelimeter(self, opIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the operand at opIndex should have a delimiter following it.
        
        :param jpype.JInt or int opIndex: the index of the operand to test for having a delimiter.
        """

    def isInDelaySlot(self) -> bool:
        """
        Return true if this prototype was disassembled in a delay slot.
        """

    @property
    def instructionMask(self) -> Mask:
        ...

    @property
    def fallThrough(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def delaySlotDepth(self) -> jpype.JInt:
        ...

    @property
    def delaySlotByteCount(self) -> jpype.JInt:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def inDelaySlot(self) -> jpype.JBoolean:
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...

    @property
    def fallThroughOffset(self) -> jpype.JInt:
        ...

    @property
    def operandValueMask(self) -> Mask:
        ...

    @property
    def inputObjects(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def flows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def resultObjects(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class BasicCompilerSpec(CompilerSpec):
    """
    BasicCompilerSpec implements the CompilerSpec interface based on static information
    from a particular .cspec file.  Typically the .cspec file is read in once by a Language
    object whenever a new or opened Program indicates a particular language and compiler.
    The BasicCompilerSpec is owned by the Language and (parts of it) may be reused by
    multiple Programs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, description: CompilerSpecDescription, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, stream: java.io.InputStream):
        """
        Construct the specification from an XML stream.  This is currently only used for testing.
        
        :param CompilerSpecDescription description: is the .ldefs description matching this specification
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: is the language that owns the specification
        :param java.io.InputStream stream: is the XML stream
        :raises XmlParseException: for badly formed XML
        :raises SAXException: for syntax errors in the XML
        :raises IOException: for errors accessing the stream
        :raises DuplicateNameException: if there exists more than one PrototypeModel with the same name
        """

    @typing.overload
    def __init__(self, description: CompilerSpecDescription, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, cspecFile: generic.jar.ResourceFile):
        """
        Read in the specification from an XML file.
        
        :param CompilerSpecDescription description: is the .ldefs description associated with the specification
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: is the language owning the specification
        :param generic.jar.ResourceFile cspecFile: is the XML file
        :raises CompilerSpecNotFoundException: for any form of error preventing the specification from being loaded.
        """

    @typing.overload
    def __init__(self, op2: BasicCompilerSpec):
        """
        Clone the spec so that program can safely extend it without affecting the base
        spec from Language.
        
        :param BasicCompilerSpec op2: is the spec to clone
        """


class ParamListStandard(ParamList):
    """
    Standard analysis for parameter lists
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def assignAddress(self, dt: ghidra.program.model.data.DataType, proto: PrototypePieces, pos: typing.Union[jpype.JInt, int], dtManager: ghidra.program.model.data.DataTypeManager, status: jpype.JArray[jpype.JInt], res: ParameterPieces) -> int:
        """
        Fill in the Address and other details for the given parameter
         
        Attempt to apply a ModelRule first. If these do not succeed, use the fallback assignment algorithm.
        
        :param ghidra.program.model.data.DataType dt: is the data-type assigned to the parameter
        :param PrototypePieces proto: is the description of the function prototype
        :param jpype.JInt or int pos: is the position of the parameter to assign (pos=-1 for output, pos >=0 for input)
        :param ghidra.program.model.data.DataTypeManager dtManager: is the data-type manager for (possibly) transforming the parameter's data-type
        :param jpype.JArray[jpype.JInt] status: is the consumed resource status array
        :param ParameterPieces res: is parameter description to be filled in
        :return: the response code
        :rtype: int
        """

    def assignAddressFallback(self, resource: StorageClass, tp: ghidra.program.model.data.DataType, matchExact: typing.Union[jpype.JBoolean, bool], status: jpype.JArray[jpype.JInt], param: ParameterPieces) -> int:
        """
        Assign storage for given parameter class, using the fallback assignment algorithm
         
        Given a resource list, a data-type, and the status of previously allocated slots,
        select the storage location for the parameter.  The status array is
        indexed by group: a positive value indicates how many slots have been allocated
        from that group, and a -1 indicates the group/resource is fully consumed.
        If an Address can be assigned to the parameter, it and other details are passed back in the
        ParameterPieces object and the SUCCESS code is returned.  Otherwise, the FAIL code is returned.
        
        :param StorageClass resource: is the resource list to allocate from
        :param ghidra.program.model.data.DataType tp: is the data-type of the parameter
        :param jpype.JBoolean or bool matchExact: is false if TYPECLASS_GENERAL is considered a match for any storage class
        :param jpype.JArray[jpype.JInt] status: is an array marking how many slots have already been consumed in a group
        :param ParameterPieces param: will hold the address and other details of the assigned parameter
        :return: either SUCCESS or FAIL
        :rtype: int
        """

    def extractStack(self) -> ParamEntry:
        """
        If there is a ParamEntry corresponding to the stack resource in this list, return it.
        
        :return: the stack ParamEntry or null
        :rtype: ParamEntry
        """

    def extractTiles(self, resType: StorageClass) -> jpype.JArray[ParamEntry]:
        """
        Extract all ParamEntry that have the given storage class and are single registers.
        
        :param StorageClass resType: is the given storage class
        :return: the array of registers
        :rtype: jpype.JArray[ParamEntry]
        """

    def getEntry(self, index: typing.Union[jpype.JInt, int]) -> ParamEntry:
        """
        Within this list, get the ParamEntry at the given index
        
        :param jpype.JInt or int index: is the given index
        :return: the selected ParamEntry
        :rtype: ParamEntry
        """

    def getNumParamEntry(self) -> int:
        """
        
        
        :return: the number of ParamEntry objets in this list
        :rtype: int
        """

    @property
    def entry(self) -> ParamEntry:
        ...

    @property
    def numParamEntry(self) -> jpype.JInt:
        ...


class LanguageService(java.lang.Object):
    """
    Service that provides a Language given a name, and 
    information about the language.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDefaultLanguage(self, processor: Processor) -> Language:
        """
        Returns the default Language to use for the given processor;
        
        :param Processor processor: the processor for which to get a language.
        :raises LanguageNotFoundException: if there is no languages at all for the given processor.
        """

    def getLanguage(self, languageID: LanguageID) -> Language:
        """
        Returns the language with the given language ID
        
        :param LanguageID languageID: the ID of language to retrieve
        :return: the :obj:`Language` matching the given ID
        :rtype: Language
        :raises LanguageNotFoundException: if no language can be found for the given ID
        """

    @typing.overload
    def getLanguageCompilerSpecPairs(self, query: LanguageCompilerSpecQuery) -> java.util.List[LanguageCompilerSpecPair]:
        """
        Returns all known language/compiler spec pairs which satisfy the criteria
        identify by the non-null parameters. A null value implies a don't-care
        wildcard value.  OMITS DEPRECATED LANGUAGES.
        
        :param LanguageCompilerSpecQuery query: TODO
        :return: 
        :rtype: java.util.List[LanguageCompilerSpecPair]
        """

    @typing.overload
    def getLanguageCompilerSpecPairs(self, query: ExternalLanguageCompilerSpecQuery) -> java.util.List[LanguageCompilerSpecPair]:
        """
        Returns all known language/compiler spec pairs which satisfy the criteria
        identify by the non-null parameters. A null value implies a don't-care
        wildcard value.  OMITS DEPRECATED LANGUAGES.
        This uses an ExternalLanguageCompilerSpecQuery rather than a
        LanguageCompilerSpecQuery.
        
        :param ExternalLanguageCompilerSpecQuery query: 
        :return: 
        :rtype: java.util.List[LanguageCompilerSpecPair]
        """

    def getLanguageDescription(self, languageID: LanguageID) -> LanguageDescription:
        """
        Get language information for the given language ID.
        
        :param LanguageID languageID: the id for the language.
        :return: language information for the given language ID.
        :rtype: LanguageDescription
        :raises LanguageNotFoundException: if there is no language for the given ID.
        """

    @typing.overload
    def getLanguageDescriptions(self, includeDeprecatedLanguages: typing.Union[jpype.JBoolean, bool]) -> java.util.List[LanguageDescription]:
        """
        Returns all known language Descriptions
        
        :param jpype.JBoolean or bool includeDeprecatedLanguages: TODO
        :return: all know language Descriptions.
        :rtype: java.util.List[LanguageDescription]
        """

    @typing.overload
    @deprecated("use getLanguageDescriptions(Processor) instead")
    def getLanguageDescriptions(self, processor: Processor, endianness: Endian, size: typing.Union[java.lang.Integer, int], variant: typing.Union[java.lang.String, str]) -> java.util.List[LanguageDescription]:
        """
        Returns all known language descriptions which satisfy the criteria identify by the
        non-null parameters.  A null value implies a don't-care wildcard value.
        
        :param Processor processor: the processor for which to get a language
        :param Endian endianness: big or little
        :param java.lang.Integer or int size: processor address space size (in bits)
        :param java.lang.String or str variant: the processor version (usually 'default')
        :return: the language descriptions that fit the parameters
        :rtype: java.util.List[LanguageDescription]
        
        .. deprecated::
        
        use :meth:`getLanguageDescriptions(Processor) <.getLanguageDescriptions>` instead
        """

    @typing.overload
    def getLanguageDescriptions(self, processor: Processor) -> java.util.List[LanguageDescription]:
        """
        Returns all language Descriptions associated with the given processor.
        
        :param Processor processor: the processor for which to retrieve all know language descriptions.
        """

    @property
    def languageDescriptions(self) -> java.util.List[LanguageDescription]:
        ...

    @property
    def defaultLanguage(self) -> Language:
        ...

    @property
    def languageDescription(self) -> LanguageDescription:
        ...

    @property
    def languageCompilerSpecPairs(self) -> java.util.List[LanguageCompilerSpecPair]:
        ...

    @property
    def language(self) -> Language:
        ...


class ParamListStandardOut(ParamListStandard):
    """
    A list of resources describing possible storage locations for a function's return value,
    and a strategy for selecting a storage location based on data-types in a function signature.
     
    Similar to the parent class, when assigning storage, the first entry that matches the data-type
    is chosen.  But if this instance fails to find a match (because the return value data-type is too
    big) the data-type is converted to a pointer and storage is assigned based on that pointer.
    Additionally, if configured, this instance will signal that a hidden input parameter is required
    to fully model where the large return value is stored.
     
    The resource list is checked to ensure entries are distinguishable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ContextSetting(java.lang.Object):
    """
    Class for context configuration information as
    part of the compiler configuration (CompilerSpec)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, register: Register, value: java.math.BigInteger, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    @staticmethod
    def encodeContextData(encoder: ghidra.program.model.pcode.Encoder, ctxList: java.util.List[ContextSetting]):
        ...

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getRegister(self) -> Register:
        ...

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getValue(self) -> java.math.BigInteger:
        ...

    def isEquivalent(self, obj: ContextSetting) -> bool:
        """
        Determine if this ContextSetting is equivalent to another specified instance
        
        :param ContextSetting obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    @staticmethod
    def parseContextData(resList: java.util.List[ContextSetting], parser: ghidra.xml.XmlPullParser, cspec: CompilerSpec):
        ...

    @staticmethod
    def parseContextSet(resList: java.util.List[ContextSetting], parser: ghidra.xml.XmlPullParser, cspec: CompilerSpec):
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def register(self) -> Register:
        ...


class InjectPayloadSleigh(InjectPayload):
    """
    ``InjectPayloadSleigh`` defines an InjectPayload of p-code which is defined via
    a String passed to the sleigh compiler
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, nm: typing.Union[java.lang.String, str], tp: typing.Union[jpype.JInt, int], sourceName: typing.Union[java.lang.String, str]):
        """
        Provide basic form,  restoreXml fills in the rest
        
        :param java.lang.String or str nm: must provide formal name
        :param jpype.JInt or int tp: must provide type
        :param java.lang.String or str sourceName: is a description of the source of this payload
        """

    @staticmethod
    def getDummyPcode(addrFactory: ghidra.program.model.address.AddressFactory) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        """
        Build a dummy p-code sequence to use in place of a normal parsed payload.
        A ConstructTpl is built out of Varnode and PcodeOp templates that can
        be assigned directly to the pcodeTemplate field of the payload.
        The sequence itself is non-empty, consisting of a single operation:
            tmp = tmp + 0;
        
        :param ghidra.program.model.address.AddressFactory addrFactory: is used to construct temp and constant Varnodes
        :return: the final dummy template
        :rtype: ghidra.app.plugin.processors.sleigh.template.ConstructTpl
        """


class ProcessorContext(ProcessorContextView):
    """
    Defines the interface for an object containing the state
    of all processor registers relative to a specific address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearRegister(self, register: Register):
        """
        Clears the register within this context.
        
        :param Register register: register to be cleared.
        :raises ContextChangeException: an illegal attempt to change context was made
        """

    def setRegisterValue(self, value: RegisterValue):
        """
        Sets the specified register value within this context.
        
        :param RegisterValue value: register value
        :raises ContextChangeException: an illegal attempt to change context was made
        """

    def setValue(self, register: Register, value: java.math.BigInteger):
        """
        Sets the value for a Register.
        
        :param Register register: the register to have its value set
        :param java.math.BigInteger value: the value for the register (null is not permitted).
        :raises ContextChangeException: an illegal attempt to change context was made
        """


class ProcessorContextView(java.lang.Object):
    """
    Defines the interface for an object containing the state
    of all processor registers relative to a specific address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def dumpContextValue(value: RegisterValue, indent: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    @typing.overload
    def dumpContextValue(value: RegisterValue, indent: typing.Union[java.lang.String, str], buf: java.lang.StringBuilder):
        ...

    def getBaseContextRegister(self) -> Register:
        """
        
        
        :return: the base processor context register or null if one
        has not been defined
        :rtype: Register
        """

    def getRegister(self, name: typing.Union[java.lang.String, str]) -> Register:
        """
        Get a Register given the name of a register
        
        :param java.lang.String or str name: the name of the register.
        :return: The register with the given name.
        :rtype: Register
        """

    def getRegisterValue(self, register: Register) -> RegisterValue:
        """
        Get the RegisterValue for the given register.
        
        :param Register register: register to get the value for
        :return: RegisterValue object containing the value of the register if a value exists,
        otherwise null.
        :rtype: RegisterValue
        """

    def getRegisters(self) -> java.util.List[Register]:
        """
        Returns all the Registers for the processor as an unmodifiable list
        
        :return: all the Registers for the processor
        :rtype: java.util.List[Register]
        """

    def getValue(self, register: Register, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Get the contents of a processor register as a BigInteger object
        
        :param Register register: register to get the value for
        :return: a BigInteger object containing the value of the register if a value exists,
        otherwise null.
        :rtype: java.math.BigInteger
        """

    def hasValue(self, register: Register) -> bool:
        """
        Returns true if a value is defined for the given register.
        
        :param Register register: the register to check for a value.
        :return: true if the given register has a value.
        :rtype: bool
        """

    @property
    def registers(self) -> java.util.List[Register]:
        ...

    @property
    def registerValue(self) -> RegisterValue:
        ...

    @property
    def register(self) -> Register:
        ...

    @property
    def baseContextRegister(self) -> Register:
        ...


class InstructionBlockFlow(java.lang.Comparable[InstructionBlockFlow]):

    class Type(java.lang.Enum[InstructionBlockFlow.Type]):

        class_: typing.ClassVar[java.lang.Class]
        PRIORITY: typing.Final[InstructionBlockFlow.Type]
        """
        ``PRIORITY`` is the highest priority flow start
        """

        BRANCH: typing.Final[InstructionBlockFlow.Type]
        """
        ``BRANCH`` is a normal block branch flow within an InstructionSet
        """

        CALL_FALLTHROUGH: typing.Final[InstructionBlockFlow.Type]
        """
        ``CALL_FALLTHROUGH`` is fall-through flow from a CALL instruction
        which must be deferred until all branch flows are processed.
        """

        CALL: typing.Final[InstructionBlockFlow.Type]
        """
        ``CALL`` is a call flow which always starts a new InstructionSet.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> InstructionBlockFlow.Type:
            ...

        @staticmethod
        def values() -> jpype.JArray[InstructionBlockFlow.Type]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address, flowFrom: ghidra.program.model.address.Address, type: InstructionBlockFlow.Type):
        ...

    def getDestinationAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the flow destination address
        
        :return: flow destination address
        :rtype: ghidra.program.model.address.Address
        """

    def getFlowFromAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the flow from address
        
        :return: flow from address (may be null)
        :rtype: ghidra.program.model.address.Address
        """

    def getType(self) -> InstructionBlockFlow.Type:
        """
        
        
        :return: flow type
        :rtype: InstructionBlockFlow.Type
        """

    @property
    def destinationAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def flowFromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def type(self) -> InstructionBlockFlow.Type:
        ...


class LanguageID(java.lang.Comparable[LanguageID]):
    """
    Represents an opinion's processor language (x86:LE:32:default, 8051:BE:16:default, etc).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[java.lang.String, str]):
        """
        Creates a new language ID.
        
        :param java.lang.String or str id: The language ID (x86:LE:32:default, 8051:BE:16:default, etc).
        :raises IllegalArgumentException: if the language ID is null or empty.
        """

    def getIdAsString(self) -> str:
        """
        Gets the compiler spec ID as a string.
        
        :return: The compilers spec ID as a string.
        :rtype: str
        :raises IllegalArgumentException: if the compiler spec ID is not null or empty.
        """

    @property
    def idAsString(self) -> java.lang.String:
        ...


class PrototypeModel(java.lang.Object):
    """
    A function calling convention model.
    Formal specification of how a compiler passes
    arguments between functions.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN_EXTRAPOP: typing.Final = 32768

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], model: PrototypeModel):
        """
        Create a named alias of another PrototypeModel.
        All elements of the original model are copied except:
        1) The name
        2) The generic calling convention (which is based on name)
        3) The hasThis property (which allows __thiscall to alias something else)
        4) The "fact of" the model being an alias
        
        :param java.lang.String or str name: is the name of the alias
        :param PrototypeModel model: is the other PrototypeModel
        """

    @typing.overload
    def __init__(self):
        ...

    def assignParameterStorage(self, proto: PrototypePieces, dtManager: ghidra.program.model.data.DataTypeManager, res: java.util.ArrayList[ParameterPieces], addAutoParams: typing.Union[jpype.JBoolean, bool]):
        """
        Calculate input and output storage locations given a function prototype
         
        The data-types of the function prototype are passed in. Based on this model, a
        location is selected for each (input and output) parameter and passed back to the
        caller.  The passed back storage locations are ordered with the output storage
        as the first entry, followed by the input storage locations.  The model has the option
        of inserting a hidden return value pointer in the input storage locations.
         
        If the model cannot assign storage, the ParameterPieces will have a null Address.
        
        :param PrototypePieces proto: is the function prototype parameter data-types
        :param ghidra.program.model.data.DataTypeManager dtManager: is the manager used to create indirect data-types
        :param java.util.ArrayList[ParameterPieces] res: will hold the storage addresses for each parameter
        :param jpype.JBoolean or bool addAutoParams: is true if auto parameters (like the this pointer) should be processed
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder, injectLibrary: PcodeInjectLibrary):
        """
        Encode this object to an output stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :param PcodeInjectLibrary injectLibrary: is a library containing any inject payloads associated with the model
        :raises IOException: for errors writing to the underlying stream
        """

    def getAliasParent(self) -> PrototypeModel:
        """
        If this is an alias of another model, return that model.  Otherwise null is returned.
        
        :return: the parent model or null
        :rtype: PrototypeModel
        """

    def getArgLocation(self, argIndex: typing.Union[jpype.JInt, int], params: jpype.JArray[ghidra.program.model.listing.Parameter], dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the preferred parameter location for a specified index,
        which will be added/inserted within the set of existing function params.
        If existing parameters use custom storage, this method should not be used.
         
        
        Note: storage will not be assigned to the :obj:`default undefined <DataType.DEFAULT>` datatype,
        zero-length datatype, or any subsequent parameter following such a parameter.
         
        
        Warning: The use of this method with a null ``params`` argument, or incorrect
        datatypes, is highly discouraged since it will produce inaccurate results.
        It is recommended that a complete function signature be used in
        conjunction with the :meth:`getStorageLocations(Program, DataType[], boolean) <.getStorageLocations>`
        method.  Parameter storage allocation may be affected by the return datatype
        specified (e.g., hidden return storage parameter).
        
        :param jpype.JInt or int argIndex: is the index (0: return storage, 1..n: parameter storage)
        :param jpype.JArray[ghidra.program.model.listing.Parameter] params: existing set parameters to which the parameter specified by
        argIndex will be added/inserted be appended. Element-0 corresponds to the return
        datatype. Parameter elements prior to the argIndex are required for an accurate 
        storage determination to be made.  Any preceeding parameters not specified will be assumed 
        as a 1-byte integer type which could cause an erroneous storage result to be returned.  
        A null params list will cause all preceeding params to be assumed in a similar fashion.
        :param ghidra.program.model.data.DataType dataType: dataType associated with next parameter location or null
        for a default undefined type.
        :param ghidra.program.model.listing.Program program: is the Program
        :return: parameter location or :obj:`VariableStorage.UNASSIGNED_STORAGE` if
        unable to determine suitable location
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    def getExtrapop(self) -> int:
        """
        Returns the number of extra bytes popped from the stack when a function that uses
        this model returns to its caller. This is usually just the number of bytes used to
        store the return value, but some conventions may do additional clean up of stack parameters.
        A special value of UNKNOWN_EXTRAPOP indicates that the number of bytes is unknown.
        
        :return: the number of extra bytes popped
        :rtype: int
        """

    def getInputListType(self) -> InputListType:
        """
        
        
        :return: the allocation strategy for this model
        :rtype: InputListType
        """

    def getInternalStorage(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: list of registers used to store internal compiler constants
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getKilledByCallList(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: list of registers definitely affected by called functions
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getLikelyTrash(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: list of registers whose input value is likely meaningless
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getName(self) -> str:
        """
        
        
        :return: the formal name of the model
        :rtype: str
        """

    def getNextArgLocation(self, params: jpype.JArray[ghidra.program.model.listing.Parameter], dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the preferred parameter location for a new parameter which will appended
        to the end of an existing set of params.  If existing parameters use custom
        storage, this method should not be used.
         
        
        Note: storage will not be assigned to the :obj:`default undefined <DataType.DEFAULT>` datatype,
        zero-length datatype, or any subsequent parameter following such a parameter.
         
        
        Warning: The use of this method with a null ``params`` argument, or incorrect
        datatypes, is highly discouraged since it will produce inaccurate results.
        It is recommended that a complete function signature be used in
        conjunction with the :meth:`getStorageLocations(Program, DataType[], boolean) <.getStorageLocations>`
        method.  Parameter storage allocation may be affected by the return datatype
        specified (e.g., hidden return storage parameter).
        
        :param jpype.JArray[ghidra.program.model.listing.Parameter] params: existing set parameters to which the next parameter will
        be appended (may be null). Element-0 corresponds to the return datatype.
        :param ghidra.program.model.data.DataType dataType: dataType associated with next parameter location or null
        for a default undefined type.  If null the speculative first parameter storage
        is returned.
        :param ghidra.program.model.listing.Program program: is the Program
        :return: next parameter location or :obj:`VariableStorage.UNASSIGNED_STORAGE` if
        unable to determine suitable location
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    def getPotentialInputRegisterStorage(self, prog: ghidra.program.model.listing.Program) -> jpype.JArray[ghidra.program.model.listing.VariableStorage]:
        """
        Get a list of all input storage locations consisting of a single register
        
        :param ghidra.program.model.listing.Program prog: is the current Program
        :return: a VariableStorage ojbect for each register
        :rtype: jpype.JArray[ghidra.program.model.listing.VariableStorage]
        """

    def getReturnAddress(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: list of registers/memory used to store the return address
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getReturnLocation(self, dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the preferred return location given the specified dataType.
        If the return value is passed back through a hidden input pointer,
        i.e. :obj:`AutoParameterType.RETURN_STORAGE_PTR`, this routine will not pass back
        the storage location of the pointer, but will typically pass
        back the location of the normal return register which holds a copy of the pointer.
         
        
        Note: storage will not be assigned to the :obj:`default undefined <DataType.DEFAULT>` datatype
        or zero-length datatype.
        
        :param ghidra.program.model.data.DataType dataType: first parameter dataType or null for an undefined type.
        :param ghidra.program.model.listing.Program program: is the Program
        :return: return location or :obj:`VariableStorage.UNASSIGNED_STORAGE` if
        unable to determine suitable location
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    def getStackParameterAlignment(self) -> int:
        """
        Assuming the model allows open ended storage of parameters on the stack,
        return the byte alignment required for individual stack parameters.
        
        :return: the stack alignment in bytes
        :rtype: int
        """

    def getStackParameterOffset(self) -> int:
        """
        Return the byte offset where the first input parameter on the stack is allocated.
        The value is relative to the incoming stack pointer of the called function.
        For normal stacks, this is the offset of the first byte in the first parameter.
        For reverse stacks, this is the offset immediately after the last byte of the parameter.
        
        :return: the byte offset of the first param
        :rtype: int
        """

    def getStackshift(self) -> int:
        """
        
        
        :return: the number of bytes on the stack used, by this model, to store the return value
        :rtype: int
        """

    def getStorageLocations(self, program: ghidra.program.model.listing.Program, dataTypes: jpype.JArray[ghidra.program.model.data.DataType], addAutoParams: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.listing.VariableStorage]:
        """
        Compute the variable storage for a given array of return/parameter datatypes.  The first array element
        is the return datatype, which is followed by any input parameter datatypes in order.
        If addAutoParams is true, pointer datatypes will automatically be inserted for "this" or "hidden return"
        input parameters, if needed.  In this case, the dataTypes array should not include explicit entries for
        these parameters.  If addAutoParams is false, the dataTypes array is assumed to already contain explicit
        entries for any of these parameters.
         
        
        Note: storage will not be assigned to the :obj:`default undefined <DataType.DEFAULT>` datatype
        or zero-length datatypes or any subsequent parameter following such a parameter.
        
        :param ghidra.program.model.listing.Program program: is the Program
        :param jpype.JArray[ghidra.program.model.data.DataType] dataTypes: return/parameter datatypes (first element is always the return datatype, 
        i.e., minimum array length is 1)
        :param jpype.JBoolean or bool addAutoParams: true if auto-parameter storage locations can be generated
        :return: dynamic storage locations orders by ordinal where first element corresponds to
        return storage. The returned array may also include additional auto-parameter storage 
        locations.
        :rtype: jpype.JArray[ghidra.program.model.listing.VariableStorage]
        """

    def getUnaffectedList(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: list of registers unaffected by called functions
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def hasInjection(self) -> bool:
        """
        Return true if this model has specific p-code injections associated with it
        (either an "uponentry" or "uponreturn" payload),
        which are used to decompile functions with this model.
        
        :return: true if this model uses p-code injections
        :rtype: bool
        """

    def hasThisPointer(self) -> bool:
        """
        
        
        :return: true if this model has an implied "this" parameter for referencing class data
        :rtype: bool
        """

    def isConstructor(self) -> bool:
        """
        
        
        :return: true if this model is used specifically for class constructors
        :rtype: bool
        """

    def isEquivalent(self, obj: PrototypeModel) -> bool:
        """
        Determine if this PrototypeModel is equivalent to another instance
        
        :param PrototypeModel obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isErrorPlaceholder(self) -> bool:
        """
        If a PrototypeModel fails to parse (from XML) a substitute model may be provided, in which
        case this method returns true.  In all other cases this method returns false;
        
        :return: true if this object is a substitute for a model that didn't parse
        :rtype: bool
        """

    def isMerged(self) -> bool:
        """
        If this returns true, it indicates this model is an artificial merge of other models.
        A merged model can be used as part of the analysis process when attempting to distinguish
        between different possible models for an unknown function.
        
        :return: true if this model is an artificial merge of other models
        :rtype: bool
        """

    def isProgramExtension(self) -> bool:
        """
        
        
        :return: true if this model is a Program specific extension to the CompilerSpec
        :rtype: bool
        """

    def possibleInputParamWithSlot(self, loc: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], res: ParamList.WithSlotRec) -> bool:
        """
        Determine if the given address range is possible input parameter storage for this model.
        If it is, "true" is returned, and additional information about the parameter's
        position is passed back in the provided record.
        
        :param ghidra.program.model.address.Address loc: is the starting address of the range
        :param jpype.JInt or int size: is the size of the range in bytes
        :param ParamList.WithSlotRec res: is the pass-back record
        :return: true if the range is a possible parameter
        :rtype: bool
        """

    def possibleOutputParamWithSlot(self, loc: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], res: ParamList.WithSlotRec) -> bool:
        """
        Determine if the given address range is possible return value storage for this model.
        If it is, "true" is returned, and additional information about the storage
        position is passed back in the provided record.
        
        :param ghidra.program.model.address.Address loc: is the starting address of the range
        :param jpype.JInt or int size: is the size of the range in bytes
        :param ParamList.WithSlotRec res: is the pass-back record
        :return: true if the range is possible return value storage
        :rtype: bool
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, cspec: CompilerSpec):
        """
        Restore the model from an XML stream.
        
        :param ghidra.xml.XmlPullParser parser: is the XML parser (initialized to the start of the stream)
        :param CompilerSpec cspec: is the parent compiler specification owning the model
        :raises XmlParseException: is there are problems parsing the XML
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def inputListType(self) -> InputListType:
        ...

    @property
    def internalStorage(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def potentialInputRegisterStorage(self) -> jpype.JArray[ghidra.program.model.listing.VariableStorage]:
        ...

    @property
    def merged(self) -> jpype.JBoolean:
        ...

    @property
    def errorPlaceholder(self) -> jpype.JBoolean:
        ...

    @property
    def constructor(self) -> jpype.JBoolean:
        ...

    @property
    def likelyTrash(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def extrapop(self) -> jpype.JInt:
        ...

    @property
    def unaffectedList(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def stackshift(self) -> jpype.JInt:
        ...

    @property
    def stackParameterAlignment(self) -> jpype.JInt:
        ...

    @property
    def returnAddress(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def aliasParent(self) -> PrototypeModel:
        ...

    @property
    def programExtension(self) -> jpype.JBoolean:
        ...

    @property
    def stackParameterOffset(self) -> jpype.JLong:
        ...

    @property
    def killedByCallList(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...


class ProgramProcessorContext(ProcessorContext):
    """
    Implementation for the program processor context interface
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: ghidra.program.model.listing.ProgramContext, addr: ghidra.program.model.address.Address):
        """
        Constructs a new ProgramProcessorContext that will have the processor
        state be the state of the given programContext at the given address
        
        :param ghidra.program.model.listing.ProgramContext context: the programContext which contains the register state at every address
        :param ghidra.program.model.address.Address addr: the address at which to get the register state
        """


class UndefinedValueException(ghidra.util.exception.UsrException):
    """
    
    An UndefinedValueException is thrown when a value
    for a register is looked up that is undefined.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        construct a new UndefinedValueException with no message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        constructs a new UndefinedValueException with a descriptive
        message.
        
        :param java.lang.String or str message: the description of what went wrong.
        """


class Register(java.io.Serializable, java.lang.Comparable[Register]):
    """
    Class to represent a processor register. To sort of handle bit registers, a special addressing
    convention is used. First the upper bit is set. Second, the next 3 bits are used to specify what
    bit position within a byte that this register bit exists at. Finally, the rest of the address is
    the address of the byte where the register bit lives.
    """

    class_: typing.ClassVar[java.lang.Class]
    TYPE_NONE: typing.Final = 0
    TYPE_FP: typing.Final = 1
    TYPE_SP: typing.Final = 2
    TYPE_PC: typing.Final = 4
    TYPE_CONTEXT: typing.Final = 8
    TYPE_ZERO: typing.Final = 16
    TYPE_HIDDEN: typing.Final = 32
    TYPE_DOES_NOT_FOLLOW_FLOW: typing.Final = 64
    TYPE_VECTOR: typing.Final = 128
    """
    Register can be used in SIMD operations
    """

    NO_CONTEXT: typing.Final[Register]
    """
    Register used to denote NO defined context for a language
    """


    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, numBytes: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], typeFlags: typing.Union[jpype.JInt, int]):
        """
        Constructs a new Register object.
        
        :param java.lang.String or str name: the name of this Register.
        :param java.lang.String or str description: the description of this Register
        :param ghidra.program.model.address.Address address: the address in register space of this register
        :param jpype.JInt or int numBytes: the size (in bytes) of this register
        :param jpype.JBoolean or bool bigEndian: true if the most significant bytes are associated with the lowest register
                    addresses, and false if the least significant bytes are associated with the lowest
                    register addresses.
        :param jpype.JInt or int typeFlags: the type(s) of this Register (TYPE_NONE, TYPE_FP, TYPE_SP, TYPE_PC,
                    TYPE_CONTEXT, TYPE_ZERO);)
        """

    @typing.overload
    def __init__(self, register: Register):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, numBytes: typing.Union[jpype.JInt, int], leastSignificantBit: typing.Union[jpype.JInt, int], bitLength: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], typeFlags: typing.Union[jpype.JInt, int]):
        ...

    def contains(self, reg: Register) -> bool:
        """
        Determines if reg is contained within this register. Method does not work for bit registers
        (e.g., context-bits)
        
        :param Register reg: another register
        :return: true if reg equals this register or is contained within it.
        :rtype: bool
        """

    def followsFlow(self) -> bool:
        """
        Returns true for a register whose context value should follow the disassembly flow.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the register.
        """

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Returns the register address space
        """

    def getAliases(self) -> java.lang.Iterable[java.lang.String]:
        """
        Return register aliases. NOTE: This is generally only supported for context register fields.
        
        :return: register aliases or null
        :rtype: java.lang.Iterable[java.lang.String]
        """

    def getBaseMask(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the mask that indicates which bits in the base register apply to this register.
        
        :return: the mask that indicates which bits in the base register apply to this register
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getBaseRegister(self) -> Register:
        ...

    def getBitLength(self) -> int:
        """
        Gets the total number of bits for this Register.
        
        :return: the total number of bits for this Register.
        :rtype: int
        """

    def getChildRegisters(self) -> java.util.List[Register]:
        """
        Returns list of children registers sorted by lest-significant bit-offset within this
        register.
        """

    def getDescription(self) -> str:
        """
        Get the description of the Register.
        
        :return: the description of the register
        :rtype: str
        """

    def getGroup(self) -> str:
        ...

    def getLaneSizes(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the sorted array of lane sizes for this register, measured in bytes.
        
        :return: array of lane sizes, or ``null`` if ``this`` is not a vector register or no
                lane sizes have been set.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getLeastSignificantBit(self) -> int:
        """
        Returns the bit offset from the register address for this register.
        
        :return: the bit offset from the register address for this register.
        :rtype: int
        """

    def getLeastSignificantBitInBaseRegister(self) -> int:
        ...

    def getMinimumByteSize(self) -> int:
        """
        Returns the minimum number of bytes required to store a value for this Register.
        """

    def getName(self) -> str:
        """
        Gets the name of this Register.
        
        :return: the name of this Register.
        :rtype: str
        """

    def getNumBytes(self) -> int:
        """
        Returns the number of bytes spanned by this Register.
         
         
        
        Compare to :meth:`getMinimumByteSize() <.getMinimumByteSize>`: Suppose a 5-bit register spans 2 bytes: 1 bit in
        the first byte, and the remaining 4 in the following byte. Its value can still be stored in 1
        byte, which is what :meth:`getMinimumByteSize() <.getMinimumByteSize>` returns; however, its storage still spans 2
        bytes of the base register, which is what this method returns.
        """

    def getOffset(self) -> int:
        """
        Returns the offset into the register space for this register
        """

    def getParentRegister(self) -> Register:
        ...

    def getTypeFlags(self) -> int:
        ...

    def hasChildren(self) -> bool:
        ...

    def isBaseRegister(self) -> bool:
        ...

    def isBigEndian(self) -> bool:
        ...

    def isDefaultFramePointer(self) -> bool:
        """
        Returns true if this is the default frame pointer register
        """

    def isHidden(self) -> bool:
        """
        Returns true if this is a hidden register.
        """

    def isProcessorContext(self) -> bool:
        """
        Returns true if this is a processor state register
        """

    def isProgramCounter(self) -> bool:
        """
        Returns true if this is the program counter register
        """

    def isValidLaneSize(self, laneSizeInBytes: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determines whether ``laneSizeInBytes`` is a valid lane size for this register.
        
        :param jpype.JInt or int laneSizeInBytes: lane size to check, measured in bytes
        :return: true precisely when ``this`` is a vector register and ``laneSizeInBytes`` is
                a valid lane size.
        :rtype: bool
        """

    def isVectorRegister(self) -> bool:
        """
        Returns true if this is a vector register
        
        :return: true precisely when ``this`` is a full vector register (i.e., a register that can
                be used as input or output for a SIMD operation).
        :rtype: bool
        """

    def isZero(self) -> bool:
        """
        Returns true for a register that is always zero
        """

    @property
    def bitLength(self) -> jpype.JInt:
        ...

    @property
    def aliases(self) -> java.lang.Iterable[java.lang.String]:
        ...

    @property
    def hidden(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def baseRegister(self) -> Register:
        ...

    @property
    def vectorRegister(self) -> jpype.JBoolean:
        ...

    @property
    def zero(self) -> jpype.JBoolean:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def numBytes(self) -> jpype.JInt:
        ...

    @property
    def leastSignificantBit(self) -> jpype.JInt:
        ...

    @property
    def childRegisters(self) -> java.util.List[Register]:
        ...

    @property
    def leastSignificantBitInBaseRegister(self) -> jpype.JInt:
        ...

    @property
    def group(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def validLaneSize(self) -> jpype.JBoolean:
        ...

    @property
    def programCounter(self) -> jpype.JBoolean:
        ...

    @property
    def defaultFramePointer(self) -> jpype.JBoolean:
        ...

    @property
    def parentRegister(self) -> Register:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def processorContext(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def laneSizes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def typeFlags(self) -> jpype.JInt:
        ...

    @property
    def baseMask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def minimumByteSize(self) -> jpype.JInt:
        ...


class PrototypeModelMerged(PrototypeModel):
    """
    This model serves as a placeholder for multiple model
    Currently all the models being selected between must share the same output model
    """

    @typing.type_check_only
    class PEntry(java.lang.Comparable[PrototypeModelMerged.PEntry]):

        class_: typing.ClassVar[java.lang.Class]
        slot: jpype.JInt
        size: jpype.JInt


    @typing.type_check_only
    class ScoreProtoModel(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, isinput: typing.Union[jpype.JBoolean, bool], mod: PrototypeModel, numparam: typing.Union[jpype.JInt, int]):
            ...

        def addParameter(self, addr: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int]):
            ...

        def doScore(self):
            ...

        def getScore(self) -> int:
            ...

        @property
        def score(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getModel(self, i: typing.Union[jpype.JInt, int]) -> PrototypeModel:
        ...

    def numModels(self) -> int:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, modelList: java.util.List[PrototypeModel]):
        ...

    def selectModel(self, params: jpype.JArray[ghidra.program.model.listing.Parameter]) -> PrototypeModel:
        ...

    @property
    def model(self) -> PrototypeModel:
        ...


class StorageClass(java.lang.Enum[StorageClass]):
    """
    Data-type class for the purpose of assigning storage
    """

    class_: typing.ClassVar[java.lang.Class]
    GENERAL: typing.Final[StorageClass]
    FLOAT: typing.Final[StorageClass]
    PTR: typing.Final[StorageClass]
    HIDDENRET: typing.Final[StorageClass]
    VECTOR: typing.Final[StorageClass]
    CLASS1: typing.Final[StorageClass]
    CLASS2: typing.Final[StorageClass]
    CLASS3: typing.Final[StorageClass]
    CLASS4: typing.Final[StorageClass]

    @staticmethod
    def getClass(val: typing.Union[java.lang.String, str]) -> StorageClass:
        ...

    def getValue(self) -> int:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> StorageClass:
        ...

    @staticmethod
    def values() -> jpype.JArray[StorageClass]:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class RegisterTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, oldLang: Language, newLang: Language):
        ...

    @typing.overload
    def getNewRegister(self, offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> Register:
        ...

    @typing.overload
    def getNewRegister(self, oldReg: Register) -> Register:
        ...

    def getNewRegisters(self) -> java.util.List[Register]:
        ...

    @typing.overload
    def getOldRegister(self, offset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> Register:
        ...

    @typing.overload
    def getOldRegister(self, newReg: Register) -> Register:
        ...

    @property
    def newRegister(self) -> Register:
        ...

    @property
    def oldRegister(self) -> Register:
        ...

    @property
    def newRegisters(self) -> java.util.List[Register]:
        ...


class ProgramArchitecture(java.lang.Object):
    """
    ``ProgramArchitecture`` which identifies program architecture details required to 
    utilize language/compiler-specific memory and variable storage specifications.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Get the address factory for this architecture.  In the case of a :obj:`Program` this should 
        be the extended address factory that includes the stack space and any defined overlay
        spaces (i.e., :obj:`OverlayAddressSpace`).
        
        :return: address factory
        :rtype: ghidra.program.model.address.AddressFactory
        """

    def getCompilerSpec(self) -> CompilerSpec:
        """
        Get the compiler specification
        
        :return: compiler specification
        :rtype: CompilerSpec
        """

    def getLanguage(self) -> Language:
        """
        Get the processor language
        
        :return: processor language
        :rtype: Language
        """

    def getLanguageCompilerSpecPair(self) -> LanguageCompilerSpecPair:
        """
        Get the language/compiler spec ID pair associated with this program architecture.
        
        :return: language/compiler spec ID pair
        :rtype: LanguageCompilerSpecPair
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def languageCompilerSpecPair(self) -> LanguageCompilerSpecPair:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def compilerSpec(self) -> CompilerSpec:
        ...


class Processor(java.lang.Comparable[Processor]):

    @typing.type_check_only
    class RegisterHook(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def register(self, name: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def findOrPossiblyCreateProcessor(name: typing.Union[java.lang.String, str]) -> Processor:
        """
        Use this method if you want to grab a reference to a Processor given its
        name, but if it doesn't exist go ahead and create it anyway and return
        the new instance.
        
        :param java.lang.String or str name: the name of the Processor you're looking for/going to create
        :return: the Processor
        :rtype: Processor
        """

    @staticmethod
    def toProcessor(name: typing.Union[java.lang.String, str]) -> Processor:
        """
        Use this method to look up a Processor from a String when you want a ProcessorNotFoundException
        thrown if the Processor isn't found.
         
        
        **Warning:** Use of this method depends upon languages being loaded.  See
        :obj:`DefaultLanguageService`.
        
        :param java.lang.String or str name: the name of the Processor you're looking for
        :return: the Processor
        :rtype: Processor
        :raises ProcessorNotFoundException: if the processor doesn't exist yet
        """


class ProcessorContextImpl(ProcessorContext):
    """
    An implementation of processor context which contains the state of all
    processor registers.
     
    
    Note that the ContextChangeException will never be thrown by this implementation
    of Processor
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: Language):
        ...

    def clearAll(self):
        ...


class AddressLabelInfo(java.lang.Comparable[AddressLabelInfo]):
    """
    ``AddressLabelInfo`` is a utility class for storing
    an ``Address`` together with a corresponding language-defined 
    label or alias that is within the global namespace which is
    established with a SourceType of IMPORTED within a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, sizeInBytes: typing.Union[java.lang.Integer, int], label: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], isPrimary: typing.Union[jpype.JBoolean, bool], isEntry: typing.Union[jpype.JBoolean, bool], type: ghidra.program.model.util.ProcessorSymbolType, isVolatile: typing.Union[java.lang.Boolean, bool]):
        """
        Constructor for class AddressLabelInfo
        
        :param ghidra.program.model.address.Address addr: Address object that describes the memory address
        :param java.lang.Integer or int sizeInBytes: Integer describing the Size in bytes that the label applies to.
        :param java.lang.String or str label: String label or alias for the Address
        :param java.lang.String or str description: Label description
        :param jpype.JBoolean or bool isPrimary: boolean describes if this object is the primary label for the Address 'addr'
        :param jpype.JBoolean or bool isEntry: boolean describes if this object is an entry label for the Address 'addr'
        :param ghidra.program.model.util.ProcessorSymbolType type: ProcessorSymbolType the type of symbol
        :param java.lang.Boolean or bool isVolatile: Boolean describes if the memory at this address is volatile
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: object's address.
        :rtype: ghidra.program.model.address.Address
        """

    def getByteSize(self) -> int:
        """
        
        
        :return: the object's size in bytes. Always non-zero positive value and defaults to 
        addressable unit size of associated address space.
        :rtype: int
        """

    def getDescription(self) -> str:
        """
        
        
        :return: the object's description if it has one, null otherwise
        :rtype: str
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the object's end address.
        :rtype: ghidra.program.model.address.Address
        """

    def getLabel(self) -> str:
        """
        
        
        :return: the object's label or alias.
        :rtype: str
        """

    def getProcessorSymbolType(self) -> ghidra.program.model.util.ProcessorSymbolType:
        """
        Returns the type of processor symbol (if this was defined by a pspec) or null if this
        is not a processor symbol or it was not specified in the pspec file.  It basically allows
        a pspec file to give more information about a symbol such as if code or a code pointer is
        expected to be at the symbol's address.
        
        :return: the ProcesorSymbolType if it has one.
        :rtype: ghidra.program.model.util.ProcessorSymbolType
        """

    def isEntry(self) -> bool:
        ...

    def isPrimary(self) -> bool:
        """
        
        
        :return: whether the object is the primary label at the address.
        :rtype: bool
        """

    def isVolatile(self) -> bool:
        """
        
        
        :return: whether the object is volatile.
        Boolean.False when the address is explicitly not volatile.
        Boolean.True when the address is volatile.
        NULL when the volatility is not defined at this address.
        :rtype: bool
        """

    @property
    def entry(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def byteSize(self) -> jpype.JInt:
        ...

    @property
    def processorSymbolType(self) -> ghidra.program.model.util.ProcessorSymbolType:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...


class SpaceNames(java.lang.Object):
    """
    Reserved AddressSpace names across architectures and associated attributes
    """

    class_: typing.ClassVar[java.lang.Class]
    CONSTANT_SPACE_NAME: typing.Final = "const"
    UNIQUE_SPACE_NAME: typing.Final = "unique"
    STACK_SPACE_NAME: typing.Final = "stack"
    JOIN_SPACE_NAME: typing.Final = "join"
    OTHER_SPACE_NAME: typing.Final = "OTHER"
    IOP_SPACE_NAME: typing.Final = "iop"
    FSPEC_SPACE_NAME: typing.Final = "fspec"
    CONSTANT_SPACE_INDEX: typing.Final = 0
    OTHER_SPACE_INDEX: typing.Final = 1
    UNIQUE_SPACE_SIZE: typing.Final = 4

    def __init__(self):
        ...


class UnknownDataException(ghidra.util.exception.UsrException):
    """
    
    An UnknownDataException indicates that the bytes at the parse
    address did not form a legal known data item.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an UnknownDataException with a default message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an UnknownDataException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class OperandType(java.lang.Object):
    """
    Helper class for testing operand related flags in an integer.
    """

    class_: typing.ClassVar[java.lang.Class]
    READ: typing.Final = 1
    """
    Bit set if operand refers to an address being read
    """

    WRITE: typing.Final = 2
    """
    Bit set if operand refers to an address being written to
    """

    INDIRECT: typing.Final = 4
    """
    Bit set if operand is an indirect reference.
    """

    IMMEDIATE: typing.Final = 8
    """
    Bit set if operand is an immediate value.
    """

    RELATIVE: typing.Final = 16
    """
    Bit set if operand depends on the instruction's address.
    """

    IMPLICIT: typing.Final = 32
    """
    Bit set if operand is implicit.
    """

    CODE: typing.Final = 64
    """
    Bit set it the address referred to contains code.
    """

    DATA: typing.Final = 128
    """
    Bit set if the address referred to contains data.
    """

    PORT: typing.Final = 256
    """
    Bit set if the operand is a port.
    """

    REGISTER: typing.Final = 512
    """
    Bit set if the operand is a register.
    """

    LIST: typing.Final = 1024
    """
    Bit set if the operand is a list.
    """

    FLAG: typing.Final = 2048
    """
    Bit set if the operand is a flag.
    """

    TEXT: typing.Final = 4096
    """
    Bit set if the operand is text.
    """

    ADDRESS: typing.Final = 8192
    """
    Bit set if the operand is used as an address.
    If this is not set, assume it is a scalar value.
    """

    SCALAR: typing.Final = 16384
    """
    Bit set if the operand is a scalar value
    """

    BIT: typing.Final = 32768
    """
    Bit set if the operand is a bit value
    """

    BYTE: typing.Final = 65536
    """
    Bit set if the operand is a byte value
    """

    WORD: typing.Final = 131072
    """
    Bit set if the operand is a 2 byte value
    """

    QUADWORD: typing.Final = 262144
    """
    Bit set if the operand is a 8 byte value
    """

    SIGNED: typing.Final = 524288
    """
    Bit set if the operand is a signed value
    """

    FLOAT: typing.Final = 1048576
    """
    Bit set if the operand is a float value
    """

    COP: typing.Final = 2097152
    """
    Bit set if the operand is a co-processor value
    """

    DYNAMIC: typing.Final = 4194304
    """
    Bit set if the operand is dynamically defined given some processorContext.
    If bit is set then the SCALAR or ADDRESS bit must be set.
    """


    def __init__(self):
        ...

    @staticmethod
    def doesRead(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the READ flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the READ flag is set.
        :rtype: bool
        """

    @staticmethod
    def doesWrite(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the WRITE flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the WRITE flag is set.
        :rtype: bool
        """

    @staticmethod
    def isAddress(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check ADDRESS flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the ADDRESS flag is set
        :rtype: bool
        """

    @staticmethod
    def isBit(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the BIT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the BIT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isByte(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the BYTE flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the BYTE flag is set.
        :rtype: bool
        """

    @staticmethod
    def isCoProcessor(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the COPROCESSOR flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the COPROCESSOR flag is set.
        :rtype: bool
        """

    @staticmethod
    def isCodeReference(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the CODE flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the CODE flag is set.
        :rtype: bool
        """

    @staticmethod
    def isDataReference(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the DATA flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the DATA flag is set.
        :rtype: bool
        """

    @staticmethod
    def isDynamic(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the DYNAMIC flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the DYNAMIC flag is set.
        :rtype: bool
        """

    @staticmethod
    def isFlag(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the CONDITION FLAG flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the CONDITION flag is set.
        :rtype: bool
        """

    @staticmethod
    def isFloat(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the FLOAT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the FLOAT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isImmediate(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the IMMEDIATE flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the IMMEDIATE flag is set.
        :rtype: bool
        """

    @staticmethod
    def isImplicit(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the IMPLICIT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the IMPLICIT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isIndirect(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the INDIRECT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the INDIRECT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isList(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the LIST flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the LIST flag is set.
        :rtype: bool
        """

    @staticmethod
    def isPort(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the PORT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the PORT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isQuadWord(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the QUADWORD flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the QUADWORD flag is set.
        :rtype: bool
        """

    @staticmethod
    def isRegister(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the REGISTER flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the REGISTER flag is set.
        :rtype: bool
        """

    @staticmethod
    def isRelative(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the RELATIVE flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the RELATIVE flag is set.
        :rtype: bool
        """

    @staticmethod
    def isScalar(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check SCALAR flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the SCALAR flag is set
        :rtype: bool
        """

    @staticmethod
    def isScalarAsAddress(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check if both a scalar and an address
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if it is both a scalar and an address
        :rtype: bool
        """

    @staticmethod
    def isSigned(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the SIGNED flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the SIGNED flag is set.
        :rtype: bool
        """

    @staticmethod
    def isText(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the TEXT flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the TEXT flag is set.
        :rtype: bool
        """

    @staticmethod
    def isWord(operandType: typing.Union[jpype.JInt, int]) -> bool:
        """
        check the WORD flag.
        
        :param jpype.JInt or int operandType: the bit field to examine.
        :return: true if the WORD flag is set.
        :rtype: bool
        """

    @staticmethod
    def toString(operandType: typing.Union[jpype.JInt, int]) -> str:
        """
        returns a string representation of the given operandType
        
        :param jpype.JInt or int operandType: the operandType bits
        :return: the string rep
        :rtype: str
        """


class IncompatibleMaskException(ghidra.util.exception.UsrException):
    """
    
    An IncompatibleMaskException is thrown when operations
    are attempting involving two masks of different lengths.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        construct a new IncompatibleMaskException with no message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        constructs a new IncompatiblemaskException with a descriptive
        message.
        
        :param java.lang.String or str message: the description of what went wrong.
        """


class VersionedLanguageService(LanguageService):
    """
    Service that provides a Language given a name, and 
    information about the language.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLanguage(self, languageID: LanguageID, version: typing.Union[jpype.JInt, int]) -> Language:
        """
        Returns a specific language version with the given language ID.
        This form should only be used when handling language upgrade concerns.
        
        :param LanguageID languageID: the ID of language to retrieve.
        :param jpype.JInt or int version: major version
        :raises LanguageNotFoundException: if the specified language version can not be found 
        for the given ID.
        """

    def getLanguageDescription(self, languageID: LanguageID, version: typing.Union[jpype.JInt, int]) -> LanguageDescription:
        """
        Get language information for a specific version of the given language ID.
        This form should only be used when handling language upgrade concerns.
        
        :param LanguageID languageID: the id for the language.
        :return: language information for the given language ID.
        :rtype: LanguageDescription
        :raises LanguageNotFoundException: if there is no language for the given ID.
        """


class UnknownInstructionException(ghidra.util.exception.UsrException):
    """
    
    An UnknownInstructionException indicates that the bytes at the parse
    address did not form a legal known instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an InsufficientBytesException with a default message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an InsufficientBytesException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class BasicCompilerSpecDescription(CompilerSpecDescription):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: CompilerSpecID, name: typing.Union[java.lang.String, str]):
        ...

    def getCompilerSpecID(self) -> CompilerSpecID:
        ...

    def getCompilerSpecName(self) -> str:
        ...

    def getSource(self) -> str:
        ...

    @property
    def compilerSpecName(self) -> java.lang.String:
        ...

    @property
    def compilerSpecID(self) -> CompilerSpecID:
        ...

    @property
    def source(self) -> java.lang.String:
        ...


class CompilerSpecID(java.lang.Comparable[CompilerSpecID]):
    """
    Represents an opinion's compiler (gcc, borlandcpp, etc).
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_ID: typing.Final = "default"

    def __init__(self, id: typing.Union[java.lang.String, str]):
        """
        Creates a new compiler spec ID.
        
        :param java.lang.String or str id: The compiler ID (gcc, borlandcpp, etc) as defined in the appropriate 
        :obj:`LanguageDescription`.  If null the value of "default" will be assumed.
        """

    def getIdAsString(self) -> str:
        """
        Gets the compiler spec ID as a string.
        
        :return: The compilers spec ID as a string.
        :rtype: str
        :raises IllegalArgumentException: if the compiler spec ID is null or empty.
        """

    @property
    def idAsString(self) -> java.lang.String:
        ...


class InjectPayloadCallfixup(InjectPayloadSleigh):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str]):
        ...

    def getTargets(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def targets(self) -> java.util.List[java.lang.String]:
        ...


class ParamListRegisterOut(ParamListStandardOut):
    """
    A list of resources describing possible storage locations for a function's return value,
    and a strategy for selecting a storage location based on data-types in a function signature.
     
    The assignment strategy for this class is to take the first storage location in the list
    that fits for the given function signature's return data-type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RegisterTree(java.lang.Comparable[RegisterTree]):
    """
    The RegisterTree class builds and represents relationships between registers. Any
    register that "breaks down" into smaller registers can be represent by a 
    RegisterTree.  The largest register will be at the root and the registers that
    make it up will be its children trees.  The children are RegisterTrees as well
    and can have children trees of thier own.  The root of a RegisterTree may not
    have an associated Register which means that its children are unrelated.  This
    way all the registers of a processor can be represented as a single RegisterTree.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, reg: Register):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], regs: jpype.JArray[Register]):
        """
        Constructs a RegisterTree with the given name and set of registers
        
        :param java.lang.String or str name: the name of the tree
        :param jpype.JArray[Register] regs: the array of registers to form into a tree
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], tree: RegisterTree):
        """
        Constructs a RegisterTree with one RegisterTree child
        
        :param java.lang.String or str name: the name of this tree
        :param RegisterTree tree: the child tree.
        """

    def add(self, tree: RegisterTree):
        """
        Adds a Register Tree to this tree.
        
        :param RegisterTree tree: the register tree to add
        """

    def compareTo(self, other: RegisterTree) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(java.lang.Object)`
        """

    def getComponents(self) -> jpype.JArray[RegisterTree]:
        """
        Get the RegisterTrees that are the children of this RegisterTree
        
        :return: a array of RegisterTrees
        :rtype: jpype.JArray[RegisterTree]
        """

    def getName(self) -> str:
        """
        Returns the name of this register tree.
        """

    def getParent(self) -> RegisterTree:
        """
        Returns the parent RegisterTree.
        """

    def getParentRegisterPath(self) -> str:
        """
        The parent path of this RegisterTree if it exists or null if this tree has no parent or
        no parent with a register.
        
        :return: The parent path of this RegisterTree.
        :rtype: str
        """

    def getRegister(self) -> Register:
        """
        Returns the Register associated with this tree. This may be null which
        indicates the children RegisterTrees are unrelated to each other.
        """

    def getRegisterPath(self) -> str:
        """
        The path of this register, which includes the parent path of this RegisterTree if this
        RegisterTree has a parent.
        
        :return: the path of this register.
        :rtype: str
        """

    def getRegisterTree(self, register1: Register) -> RegisterTree:
        """
        Returns the RegisterTree for the given register if one exists in this RegisterTree object.
        
        :param Register register1: The register for which to get a RegisterTree.
        :return: The RegisterTree for the given register if one exists in this RegisterTree object.
        :rtype: RegisterTree
        """

    def remove(self, reg: Register):
        """
        Removes the register from the children
        
        :param Register reg: the register to remove.
        """

    @property
    def parent(self) -> RegisterTree:
        ...

    @property
    def parentRegisterPath(self) -> java.lang.String:
        ...

    @property
    def components(self) -> jpype.JArray[RegisterTree]:
        ...

    @property
    def registerTree(self) -> RegisterTree:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def registerPath(self) -> java.lang.String:
        ...

    @property
    def register(self) -> Register:
        ...


class ParserContext(java.lang.Object):
    """
    ``ParserContext`` represents a language provider specific parser context
    which may be cached.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPrototype(self) -> InstructionPrototype:
        ...

    @property
    def prototype(self) -> InstructionPrototype:
        ...


class PrototypeModelError(PrototypeModel):
    """
    A PrototypeModel cloned from another, but marked as an error placeholder
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], copyModel: PrototypeModel):
        ...


class InjectPayloadSegment(InjectPayloadSleigh):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: typing.Union[java.lang.String, str]):
        ...


class UnknownContextException(ghidra.util.exception.UsrException):
    """
    
    An UnknownContextException indicates a processor state context must be known
    before the bytes at the parse address can form a legal known instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs an UnknownContextException with a default message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Constructs an UnknownContextException with the specified detail message.
        
        :param java.lang.String or str message: The message.
        """


class PcodeParser(ghidra.pcodeCPort.slgh_compile.PcodeCompile):
    """
    This class is intended to parse p-code snippets, typically from compiler specification files or
    extensions. This is outside the normal SLEIGH compilation process, and the parser is built on top
    of an existing SleighLanguage.
    """

    class PcodeTranslate(ghidra.pcodeCPort.sleighbase.SleighBase):
        """
        This class wraps on existing SleighLanguage with the SleighBase interface expected by
        PcodeCompile. It populates the symbol table with user-defined operations and the global
        VarnodeSymbol objects, which typically includes all the general purpose registers.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, ubase: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, ubase: typing.Union[jpype.JLong, int]):
        """
        Build parser from an existing SleighLanguage.
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: is the existing language
        :param jpype.JLong or int ubase: is the starting offset for allocating temporary registers
        """

    def addOperand(self, loc: ghidra.sleigh.grammar.Location, name: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]):
        """
        Inject a symbol representing an "operand" to the pcode snippet.
         
         
        
        This puts a placeholder in the resulting template, which gets filled in with the context
        specific storage locations when final p-code is generated
        
        :param ghidra.sleigh.grammar.Location loc: is location information for the operand
        :param java.lang.String or str name: of operand symbol
        :param jpype.JInt or int index: to use for the placeholder
        """

    def clearSymbols(self):
        ...

    def compilePcode(self, pcodeStatements: typing.Union[java.lang.String, str], srcFile: typing.Union[java.lang.String, str], srcLine: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        """
        Compile pcode semantic statements.
        
        :param java.lang.String or str pcodeStatements: is the raw source to parse
        :param java.lang.String or str srcFile: source filename from which pcodeStatements came (
        :param jpype.JInt or int srcLine: line number in srcFile corresponding to pcodeStatements
        :return: ConstructTpl. A null may be returned or an exception thrown if parsing/compiling
                fails (see application log for errors).
        :rtype: ghidra.app.plugin.processors.sleigh.template.ConstructTpl
        :raises SleighException: pcode compile error
        """

    def getNextTempOffset(self) -> int:
        ...

    def getSleigh(self) -> ghidra.pcodeCPort.sleighbase.SleighBase:
        ...

    def translateConstTpl(self, constTpl: ghidra.pcodeCPort.semantics.ConstTpl) -> ghidra.app.plugin.processors.sleigh.template.ConstTpl:
        ...

    def translateConstructTpl(self, constructTpl: ghidra.pcodeCPort.semantics.ConstructTpl) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl:
        ...

    def translateHandleTpl(self, handleTpl: ghidra.pcodeCPort.semantics.HandleTpl) -> ghidra.app.plugin.processors.sleigh.template.HandleTpl:
        ...

    def translateOpTpl(self, opTpl: ghidra.pcodeCPort.semantics.OpTpl) -> ghidra.app.plugin.processors.sleigh.template.OpTpl:
        ...

    def translateVarnodeTpl(self, varnodeTpl: ghidra.pcodeCPort.semantics.VarnodeTpl) -> ghidra.app.plugin.processors.sleigh.template.VarnodeTpl:
        ...

    @property
    def sleigh(self) -> ghidra.pcodeCPort.sleighbase.SleighBase:
        ...

    @property
    def nextTempOffset(self) -> jpype.JLong:
        ...


class InstructionBlock(java.lang.Iterable[ghidra.program.model.listing.Instruction]):
    """
    Represents a block of instructions.  Used as part of an InstructionSet to be added to the
    program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startAddr: ghidra.program.model.address.Address):
        ...

    def addBlockFlow(self, blockFlow: InstructionBlockFlow):
        """
        Add a block flow specified by a InstructionBlockFlow object.  These flows include all
        calls, branches and fall-throughs and may span across multiple InstructionSets and are
        not used by the block flow iterator within the associated InstructionSet.
        
        :param InstructionBlockFlow blockFlow: block flow
        """

    def addBranchFlow(self, destinationAddress: ghidra.program.model.address.Address):
        """
        Adds a branch type flow to this instruction block and is used by the block flow
        iterator of the associated InstructionSet.
        
        :param ghidra.program.model.address.Address destinationAddress: the destination of a branch type flow from this instruction block.
        """

    def addInstruction(self, instruction: ghidra.program.model.listing.Instruction):
        """
        Adds an instruction to this block.  If the block in not empty, the newly added instruction
        must be directly after the current block maximum address.  In other words, all instructions
        int the block must be consecutive.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction to add to this block.
        :raises IllegalArgumentException: if the new instruction does not immediately follow the
        last instruction added.
        """

    def clearConflict(self):
        """
        Clears any conflict associated with this block.
        """

    def findFirstIntersectingInstruction(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Find the first instruction within this block which intersects the specified range.
        This method should be used sparingly since it uses a brute-force search.
        
        :param ghidra.program.model.address.Address min: the minimum intersection address
        :param ghidra.program.model.address.Address max: the maximum intersection address
        :return: instruction within this block which intersects the specified range or null
        if not found
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getBlockFlows(self) -> java.util.List[InstructionBlockFlow]:
        """
        Returns a list of all block flows that were added to this instruction block as
        a list of InstructionBlockFlow objects.  NOTE: These flows may not be contained 
        within the associated InstructionSet.
        
        :return: a list of all flows that were added to this instruction block.
        :rtype: java.util.List[InstructionBlockFlow]
        """

    def getBranchFlows(self) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Returns a list of all the branch flows that were added to this instruction block
        and flow to other blocks within the associated InstructionSet.
        
        :return: a list of all the branch flows that were added to this instruction block.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    def getFallThrough(self) -> ghidra.program.model.address.Address:
        """
        Returns the fallthrough address.  Null is returned if there is no fall through.
        
        :return: the fallthrough address.
        :rtype: ghidra.program.model.address.Address
        """

    def getFlowFromAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getInstructionAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction at the specified address within this block
        
        :param ghidra.program.model.address.Address address: 
        :return: instruction at the specified address within this block or null if not found
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionConflict(self) -> InstructionError:
        """
        Returns the current conflict associated with this block.
        
        :return: the current conflict associated with this block.
        :rtype: InstructionError
        """

    def getInstructionCount(self) -> int:
        """
        
        
        :return: number of instructions contained within this block
        :rtype: int
        """

    def getInstructionsAddedCount(self) -> int:
        """
        
        
        :return: number of instructions which were added to the program
        successfully.
        :rtype: int
        """

    def getLastInstructionAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: address of last instruction contained within this block
        :rtype: ghidra.program.model.address.Address
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the maximum address of the block, or null if the block is empty;
        
        :return: the maximum address of the block.
        :rtype: ghidra.program.model.address.Address
        """

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the minimum/start address of the block;
        
        :return: the minimum/start address of the block
        :rtype: ghidra.program.model.address.Address
        """

    def hasInstructionError(self) -> bool:
        ...

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if no instructions exist within this block
        :rtype: bool
        """

    def isFlowStart(self) -> bool:
        """
        
        
        :return: true if this block should be treated as the start of a new 
        flow when added to a InstructionSet.
        :rtype: bool
        """

    def iterator(self) -> java.util.Iterator[ghidra.program.model.listing.Instruction]:
        """
        Returns an iterator over all the instructions in this block.
        """

    def setCodeUnitConflict(self, codeUnitAddr: ghidra.program.model.address.Address, newInstrAddr: ghidra.program.model.address.Address, flowFromAddr: ghidra.program.model.address.Address, isInstruction: typing.Union[jpype.JBoolean, bool], isOffcut: typing.Union[jpype.JBoolean, bool]):
        """
        Set offcut-instruction or data CODE_UNIT conflict
        
        :param ghidra.program.model.address.Address codeUnitAddr: existing instruction/data address
        :param ghidra.program.model.address.Address newInstrAddr: new disassembled instruction address
        :param ghidra.program.model.address.Address flowFromAddr: flow-from address
        :param jpype.JBoolean or bool isInstruction: true if conflict is due to offcut-instruction, otherwise data is assumed
        :param jpype.JBoolean or bool isOffcut: true if conflict due to offcut instruction
        """

    def setFallThrough(self, fallthroughAddress: ghidra.program.model.address.Address):
        """
        Sets the fall through address for this block and is used by the block flow
        iterator of the associated InstructionSet.  The fallthrough should not be 
        set if it is added as a block flow.
        
        :param ghidra.program.model.address.Address fallthroughAddress: the address of the fallthrough
        """

    def setFlowFromAddress(self, flowFrom: ghidra.program.model.address.Address):
        ...

    def setInconsistentPrototypeConflict(self, instrAddr: ghidra.program.model.address.Address, flowFromAddr: ghidra.program.model.address.Address):
        """
        Set inconsistent instruction prototype CODE_UNIT conflict
        
        :param ghidra.program.model.address.Address instrAddr: instruction addr where inconsistent prototype exists
        :param ghidra.program.model.address.Address flowFromAddr: flow-from address
        """

    def setInstructionError(self, type: InstructionError.InstructionErrorType, intendedInstructionAddress: ghidra.program.model.address.Address, conflictAddress: ghidra.program.model.address.Address, flowFromAddress: ghidra.program.model.address.Address, message: typing.Union[java.lang.String, str]):
        """
        Sets this block to have an instruction error.
        
        :param InstructionError.InstructionErrorType type: The type of error/conflict.
        :param ghidra.program.model.address.Address intendedInstructionAddress: address of intended instruction which failed to be created
        :param ghidra.program.model.address.Address conflictAddress: the address of the exiting code unit that is preventing the instruction in this
        block to be laid down (required for CODE_UNIT or DUPLCIATE conflict error).
        :param ghidra.program.model.address.Address flowFromAddress: the flow-from instruction address or null if unknown
        :param java.lang.String or str message: - A message that describes the conflict to a user.
        """

    def setInstructionMemoryError(self, instrAddr: ghidra.program.model.address.Address, flowFromAddr: ghidra.program.model.address.Address, errorMsg: typing.Union[java.lang.String, str]):
        """
        Set instruction memory error
        
        :param ghidra.program.model.address.Address instrAddr: instruction address
        :param ghidra.program.model.address.Address flowFromAddr: flow-from address
        :param java.lang.String or str errorMsg:
        """

    def setInstructionsAddedCount(self, count: typing.Union[jpype.JInt, int]):
        """
        Set the number of instructions which were added to the program
        
        :param jpype.JInt or int count:
        """

    def setParseConflict(self, conflictAddress: ghidra.program.model.address.Address, contextValue: RegisterValue, flowFromAddress: ghidra.program.model.address.Address, message: typing.Union[java.lang.String, str]):
        """
        Sets this block to have a PARSE conflict which means that the instruction parse failed
        at the specified conflictAddress using the specified contextValue.
        
        :param ghidra.program.model.address.Address conflictAddress: the address of the exiting code unit that is preventing the instruction in this
        block to be laid down.
        :param RegisterValue contextValue: the context-register value used during the failed parse attempt
        :param ghidra.program.model.address.Address flowFromAddress: the flow-from instruction address or null
        :param java.lang.String or str message: - A message that describes the conflict to a user.
        """

    def setStartOfFlow(self, isStart: typing.Union[jpype.JBoolean, bool]):
        """
        Allows the block to be tagged as start of flow to force
        InstructionSet iterator to treat as a flow start.
        This method should not be used after this block has
        been added to an InstructionSet
        
        :param jpype.JBoolean or bool isStart:
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def instructionsAddedCount(self) -> jpype.JInt:
        ...

    @instructionsAddedCount.setter
    def instructionsAddedCount(self, value: jpype.JInt):
        ...

    @property
    def fallThrough(self) -> ghidra.program.model.address.Address:
        ...

    @fallThrough.setter
    def fallThrough(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def flowFromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @flowFromAddress.setter
    def flowFromAddress(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def instructionConflict(self) -> InstructionError:
        ...

    @property
    def instructionCount(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def instructionAt(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def blockFlows(self) -> java.util.List[InstructionBlockFlow]:
        ...

    @property
    def flowStart(self) -> jpype.JBoolean:
        ...

    @property
    def lastInstructionAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def branchFlows(self) -> java.util.List[ghidra.program.model.address.Address]:
        ...


class CompilerSpecDescription(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getCompilerSpecID(self) -> CompilerSpecID:
        ...

    def getCompilerSpecName(self) -> str:
        ...

    def getSource(self) -> str:
        ...

    @property
    def compilerSpecName(self) -> java.lang.String:
        ...

    @property
    def compilerSpecID(self) -> CompilerSpecID:
        ...

    @property
    def source(self) -> java.lang.String:
        ...


class LanguageProvider(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL LanguageProvider CLASSES MUST END IN "LanguageProvider".  If not,
    the ClassSearcher will not find them.
     
    Service for providing languages.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLanguage(self, languageId: LanguageID) -> Language:
        """
        Returns the language with the given name or null if no language has that name
        
        :param LanguageID languageId: the name of the language to be retrieved
        :return: the :obj:`Language` with the given name or null if not found
        :rtype: Language
        :raises RuntimeException: if language instantiation error occurs
        """

    def getLanguageDescriptions(self) -> jpype.JArray[LanguageDescription]:
        """
        Returns a list of language descriptions provided by this provider
        """

    def hadLoadFailure(self) -> bool:
        """
        
        
        :return: true if one of more languages or language description failed to load
        properly.
        :rtype: bool
        """

    def isLanguageLoaded(self, languageId: LanguageID) -> bool:
        """
        Returns true if the given language has been successfully loaded
        
        :param LanguageID languageId: the name of the language to be retrieved
        :return: true if the given language has been successfully loaded
        :rtype: bool
        """

    @property
    def languageDescriptions(self) -> jpype.JArray[LanguageDescription]:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def languageLoaded(self) -> jpype.JBoolean:
        ...


class LanguageCompilerSpecQuery(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    processor: typing.Final[Processor]
    endian: typing.Final[Endian]
    size: typing.Final[java.lang.Integer]
    variant: typing.Final[java.lang.String]
    compilerSpecID: typing.Final[CompilerSpecID]

    def __init__(self, processor: Processor, endian: Endian, size: typing.Union[java.lang.Integer, int], variant: typing.Union[java.lang.String, str], compilerSpecID: CompilerSpecID):
        """
        Constructs a new LanguageCompilerSpecQuery
        
        :param Processor processor: the language's processor
        :param Endian endian: the processor's endianness
        :param java.lang.Integer or int size: the size of an address
        :param java.lang.String or str variant: the processor variant
        :param CompilerSpecID compilerSpecID: the compiler spec id
        """


class InsufficientBytesException(ghidra.util.exception.UsrException):
    """
    
    An InsufficientBytesException indicates that there were not enough
    consecutive bytes available to fully parse an instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an InsufficientBytesException with a default message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an InsufficientBytesException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class Mask(java.lang.Object):
    """
    The Mask class is used to perform some basic bit tests on an
    array of bits.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def applyMask(self, cde: jpype.JArray[jpype.JByte], results: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Apply the mask to a byte array.
        
        :param jpype.JArray[jpype.JByte] cde: the array that contains the values to be masked
        :param jpype.JArray[jpype.JByte] results: the array to contain the results.
        :return: the resulting byte array.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IncompatibleMaskException: thrown if byte
        arrays are not of the correct size
        """

    @typing.overload
    def applyMask(self, cde: jpype.JArray[jpype.JByte], cdeOffset: typing.Union[jpype.JInt, int], results: jpype.JArray[jpype.JByte], resultsOffset: typing.Union[jpype.JInt, int]):
        """
        Apply the mask to a byte array.
        
        :param jpype.JArray[jpype.JByte] cde: the array that contains the values to be masked
        :param jpype.JInt or int cdeOffset: the offset into the array that contains the values to be masked
        :param jpype.JArray[jpype.JByte] results: the array to contain the results.
        :param jpype.JInt or int resultsOffset: the offset into the array that contains the results
        :raises IncompatibleMaskException: thrown if byte
        arrays are not of the correct size
        """

    @typing.overload
    def applyMask(self, buffer: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[jpype.JByte]:
        """
        Apply the mask to a memory buffer.
        
        :param ghidra.program.model.mem.MemBuffer buffer: the memory buffer that contains the values to be masked
        :return: the resulting masked byte array.
        :rtype: jpype.JArray[jpype.JByte]
        :raises MemoryAccessException: thrown if mask exceeds the available data 
        within buffer
        """

    def complementMask(self, msk: jpype.JArray[jpype.JByte], results: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        applies the complement of the mask to the given byte array.
        
        :param jpype.JArray[jpype.JByte] msk: the bytes to apply the inverted mask.
        :param jpype.JArray[jpype.JByte] results: the array for storing the results.
        :return: the results array.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IncompatibleMaskException: thrown if byte
        arrays are not of the correct size
        """

    def equalMaskedValue(self, cde: jpype.JArray[jpype.JByte], target: jpype.JArray[jpype.JByte]) -> bool:
        """
        Tests if the results of apply the mask to the given array matches a
        target array.
        
        :param jpype.JArray[jpype.JByte] cde: the source bytes.
        :param jpype.JArray[jpype.JByte] target: the result bytes to be tested.
        :return: true if the target array is equal to the source array with
        the mask applied.
        :rtype: bool
        :raises IncompatibleMaskException: thrown if byte
        arrays are not of the correct size
        """

    @typing.overload
    def equals(self, obj: java.lang.Object) -> bool:
        """
        Test if the given object is equal to this object. Two masks are
        equal if they have exactly the same values in thier byte arrays.
        
        :param java.lang.Object obj: the object to be tested for equals
        :return: true if the object is equal to this mask, false otherwise.
        :rtype: bool
        """

    @typing.overload
    def equals(self, mask: jpype.JArray[jpype.JByte]) -> bool:
        """
        Check if the mask represented by the byte array is equal to this one.
        
        :param jpype.JArray[jpype.JByte] mask: mask represented as byte array
        :return: true if the masks are the same, false otherwise
        :rtype: bool
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the bytes that make up this mask.
        """

    def subMask(self, msk: jpype.JArray[jpype.JByte]) -> bool:
        """
        Tests if the given mask matches the this mask for the first n
        bytes, where n is the size of the given mask.
        
        :param jpype.JArray[jpype.JByte] msk: the bytes to be tested to see if they match the first
        bytes of this mask.
        :return: true if the bytes match up to the length of the passed in
        byte array.
        :rtype: bool
        :raises IncompatibleMaskException: thrown if byte
        arrays are not of the correct size
        """

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class RegisterManager(java.lang.Object):

    @typing.type_check_only
    class RegisterSizeKey(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getContextBaseRegister(self) -> Register:
        """
        Get context base-register
        
        :return: context base register or null if one has not been defined by the language.
        :rtype: Register
        """

    def getContextRegisters(self) -> java.util.List[Register]:
        """
        Get unsorted unmodifiable list of all processor context registers (include base context
        register and children)
        
        :return: all processor context registers
        :rtype: java.util.List[Register]
        """

    @typing.overload
    def getRegister(self, addr: ghidra.program.model.address.Address) -> Register:
        """
        Returns the largest register located at the specified address
        
        :param ghidra.program.model.address.Address addr: register address
        :return: register or null if not found
        :rtype: Register
        """

    @typing.overload
    def getRegister(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> Register:
        """
        Get register by address and size
        
        :param ghidra.program.model.address.Address addr: register address
        :param jpype.JInt or int size: register size
        :return: register or null if not found
        :rtype: Register
        """

    @typing.overload
    def getRegister(self, name: typing.Union[java.lang.String, str]) -> Register:
        """
        Get register by name. A semi-case-insensitive lookup is performed. The specified name must
        match either the case-sensitive name or be entirely lowercase or uppercase.
        
        :param java.lang.String or str name: register name
        :return: register or null if not found
        :rtype: Register
        """

    def getRegisterAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the set of addresses contained in registers
        
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getRegisterNames(self) -> java.util.List[java.lang.String]:
        """
        Get an alphabetical sorted unmodifiable list of original register names (including context
        registers). Names correspond to orignal register name and not aliases which may be defined.
        
        :return: alphabetical sorted unmodifiable list of original register names.
        :rtype: java.util.List[java.lang.String]
        """

    @typing.overload
    def getRegisters(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Register]:
        """
        Returns all registers located at the specified address
        
        :param ghidra.program.model.address.Address addr: register address
        :return: array of registers found (may be empty)
        :rtype: jpype.JArray[Register]
        """

    @typing.overload
    def getRegisters(self) -> java.util.List[Register]:
        """
        Get all registers as an unsorted unmodifiable list.
        
        :return: unmodifiable list of all registers defined
        :rtype: java.util.List[Register]
        """

    def getSortedVectorRegisters(self) -> java.util.List[Register]:
        """
        Get an unmodifiable list of all vector registers indentified by the processor specification
        in sorted order based upon address and size.
        
        :return: all vector registers as unmodifiable list
        :rtype: java.util.List[Register]
        """

    @property
    def registerAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def sortedVectorRegisters(self) -> java.util.List[Register]:
        ...

    @property
    def contextRegisters(self) -> java.util.List[Register]:
        ...

    @property
    def registers(self) -> jpype.JArray[Register]:
        ...

    @property
    def registerNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def contextBaseRegister(self) -> Register:
        ...

    @property
    def register(self) -> Register:
        ...


class DisassemblerContextAdapter(DisassemblerContext):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ParamList(java.lang.Object):
    """
    A group of ParamEntry that form a complete set for passing parameters (in one direction)
    """

    class WithSlotRec(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def assignMap(self, proto: PrototypePieces, dtManage: ghidra.program.model.data.DataTypeManager, res: java.util.ArrayList[ParameterPieces], addAutoParams: typing.Union[jpype.JBoolean, bool]):
        """
        Given a list of datatypes, calculate the storage locations used for passing those data-types
        
        :param PrototypePieces proto: is the list of datatypes
        :param ghidra.program.model.data.DataTypeManager dtManage: is the data-type manager
        :param java.util.ArrayList[ParameterPieces] res: is the vector for holding the storage locations and other parameter properties
        :param jpype.JBoolean or bool addAutoParams: if true add/process auto-parameters
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder, isInput: typing.Union[jpype.JBoolean, bool]):
        ...

    def getLanguage(self) -> Language:
        """
        
        
        :return: the associated Language
        :rtype: Language
        """

    def getPotentialRegisterStorage(self, prog: ghidra.program.model.listing.Program) -> jpype.JArray[ghidra.program.model.listing.VariableStorage]:
        """
        Get a list of all parameter storage locations consisting of a single register
        
        :param ghidra.program.model.listing.Program prog: is the controlling program
        :return: an array of VariableStorage
        :rtype: jpype.JArray[ghidra.program.model.listing.VariableStorage]
        """

    def getSpacebase(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the address space associated with any stack based parameters in this list.
        
        :return: the stack address space, if this models parameters passed on the stack, null otherwise
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getStackParameterAlignment(self) -> int:
        """
        Return the amount of alignment used for parameters passed on the stack, or -1 if there are no stack params
        
        :return: the alignment
        :rtype: int
        """

    def getStackParameterOffset(self) -> int:
        """
        Find the boundary offset that separates parameters on the stack from other local variables
        This is usually the address of the first stack parameter, but if the stack grows positive, this is
        the first address AFTER the parameters on the stack
        
        :return: the boundary offset
        :rtype: int
        """

    def isEquivalent(self, obj: ParamList) -> bool:
        """
        Determine if this ParmList is equivalent to another instance
        
        :param ParamList obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isThisBeforeRetPointer(self) -> bool:
        """
        Return true if the this pointer occurs before an indirect return pointer
         
        The automatic parameters: this parameter and the hidden return value pointer both
        tend to be allocated from the initial general purpose registers reserved for parameter passing.
        This method returns true if the this parameter is allocated first.
        
        :return: false if the hidden return value pointer is allocated first
        :rtype: bool
        """

    def possibleParamWithSlot(self, loc: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], res: ParamList.WithSlotRec) -> bool:
        """
        Determine if a particular address range is a possible parameter, and if so what slot(s) it occupies
        
        :param ghidra.program.model.address.Address loc: is the starting address of the range
        :param jpype.JInt or int size: is the size of the range in bytes
        :param ParamList.WithSlotRec res: holds the resulting slot and slotsize
        :return: true if the range is a possible parameter
        :rtype: bool
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, cspec: CompilerSpec):
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def potentialRegisterStorage(self) -> jpype.JArray[ghidra.program.model.listing.VariableStorage]:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def stackParameterOffset(self) -> jpype.JLong:
        ...

    @property
    def stackParameterAlignment(self) -> jpype.JInt:
        ...

    @property
    def spacebase(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def thisBeforeRetPointer(self) -> jpype.JBoolean:
        ...


class DynamicVariableStorage(ghidra.program.model.listing.VariableStorage):

    class_: typing.ClassVar[java.lang.Class]
    INDIRECT_VOID_STORAGE: typing.Final[DynamicVariableStorage]
    """
    ``INDIRECT_VOID_STORAGE`` used to identify return storage which is "mapped"
    with a data-type of void but was forced indirect with the corresponding use of a
    hidden return-storage-parameter.
    """


    @typing.overload
    def __init__(self, program: ProgramArchitecture, autoParamType: ghidra.program.model.listing.AutoParameterType, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Construct dynamic variable storage with an optional auto-parameter type
        
        :param ProgramArchitecture program: 
        :param ghidra.program.model.listing.AutoParameterType autoParamType: auto-parameter type or null if not applicable
        :param ghidra.program.model.address.Address address: varnode address
        :param jpype.JInt or int size: varnode size
        :raises InvalidInputException:
        """

    @typing.overload
    def __init__(self, program: ProgramArchitecture, autoParamType: ghidra.program.model.listing.AutoParameterType, *varnodes: ghidra.program.model.pcode.Varnode):
        """
        Construct dynamic variable storage with an optional auto-parameter type
        
        :param ProgramArchitecture program: 
        :param ghidra.program.model.listing.AutoParameterType autoParamType: auto-parameter type or null if not applicable
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] varnodes: one or more ordered storage varnodes
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    @typing.overload
    def __init__(self, program: ProgramArchitecture, forcedIndirect: typing.Union[jpype.JBoolean, bool], address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Construct dynamic variable storage
        
        :param ProgramArchitecture program: 
        :param jpype.JBoolean or bool forcedIndirect: if true indicates that the parameter has been forced to pass 
        as a pointer instead of its raw type
        :param ghidra.program.model.address.Address address: varnode address
        :param jpype.JInt or int size: varnode size
        :raises InvalidInputException:
        """

    @typing.overload
    def __init__(self, program: ProgramArchitecture, forcedIndirect: typing.Union[jpype.JBoolean, bool], *varnodes: ghidra.program.model.pcode.Varnode):
        """
        Construct dynamic variable storage
        
        :param ProgramArchitecture program: 
        :param jpype.JBoolean or bool forcedIndirect: if true indicates that the parameter has been forced to pass 
        as a pointer instead of its raw type
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] varnodes: one or more ordered storage varnodes
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    @staticmethod
    @typing.overload
    def getUnassignedDynamicStorage(autoParamType: ghidra.program.model.listing.AutoParameterType) -> DynamicVariableStorage:
        """
        Construct Unassigned dynamic variable storage with an optional auto-parameter type.
        NOTE: The :meth:`isUnassignedStorage() <.isUnassignedStorage>` method should be used to
        detect this type of storage.
        
        :param ghidra.program.model.listing.AutoParameterType autoParamType: auto-parameter type or null if not applicable
        :return: Unassigned dynamic variable storage
        :rtype: DynamicVariableStorage
        """

    @staticmethod
    @typing.overload
    def getUnassignedDynamicStorage(forcedIndirect: typing.Union[jpype.JBoolean, bool]) -> DynamicVariableStorage:
        """
        Construct Unassigned dynamic variable storage.
        NOTE: The :meth:`isUnassignedStorage() <.isUnassignedStorage>` method should be used to
        detect this type of storage.
        
        :param jpype.JBoolean or bool forcedIndirect: if true indicates that the parameter has been forced to pass 
        as a pointer instead of its raw type
        :return: Unassigned dynamic variable storage
        :rtype: DynamicVariableStorage
        """


class PcodeInjectLibrary(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, l: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        ...

    @typing.overload
    def __init__(self, op2: PcodeInjectLibrary):
        """
        Clone a library so that a Program can extend the library without
        modifying the base library from Language.  InjectPayloads can be considered
        immutable and don't need to be cloned.
        
        :param PcodeInjectLibrary op2: is the library to clone
        """

    def allocateInject(self, sourceName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], tp: typing.Union[jpype.JInt, int]) -> InjectPayload:
        """
        The main InjectPayload factory interface. This can be overloaded by derived libraries
        to produce custom dynamic payloads.
        
        :param java.lang.String or str sourceName: is a description of the source of the payload
        :param java.lang.String or str name: is the formal name of the payload
        :param jpype.JInt or int tp: is the type of payload:  CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
        :return: the newly minted InjectPayload
        :rtype: InjectPayload
        """

    def buildInjectContext(self) -> InjectContext:
        ...

    def encodeCompilerSpec(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode the parts of the inject library that come from the compiler spec
        to the output stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for errors writing to the underlying stream
        """

    def getCallFixupNames(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        :return: a list of names for all installed call-fixups
        :rtype: jpype.JArray[java.lang.String]
        """

    def getCallotherFixupNames(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        :return: a list of names for all installed callother-fixups
        :rtype: jpype.JArray[java.lang.String]
        """

    def getConstantPool(self, program: ghidra.program.model.listing.Program) -> ConstantPool:
        """
        Get the constant pool associated with the given Program
        
        :param ghidra.program.model.listing.Program program: is the given Program
        :return: the ConstantPool associated with the Program
        :rtype: ConstantPool
        :raises IOException: for issues constructing the object
        """

    def getPayload(self, type: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> InjectPayload:
        ...

    def getProgramPayloads(self) -> jpype.JArray[InjectPayloadSleigh]:
        """
        
        
        :return: an array of all the program specific payloads (or null)
        :rtype: jpype.JArray[InjectPayloadSleigh]
        """

    def hasProgramPayload(self, nm: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determine if the given payload name and type exists and is an extension
        of the program.
        
        :param java.lang.String or str nm: is the payload name
        :param jpype.JInt or int type: is the payload type
        :return: true if the program extension exists
        :rtype: bool
        """

    def hasUserDefinedOp(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Determine if the language has a given user-defined op.
        In which case, a CALLOTHER_FIXUP can be installed for it.
        
        :param java.lang.String or str name: is the putative name of the user-defined op
        :return: true if the user-defined op exists
        :rtype: bool
        """

    def isEquivalent(self, obj: PcodeInjectLibrary) -> bool:
        """
        Compare that this and the other library contain all equivalent payloads
        
        :param PcodeInjectLibrary obj: is the other library
        :return: true if all payloads are equivalent
        :rtype: bool
        """

    def isOverride(self, nm: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if a specific payload has been overridden by a user extension
        
        :param java.lang.String or str nm: is the name of the payload
        :param jpype.JInt or int type: is the type of payload
        :return: true if the payload is overridden
        :rtype: bool
        """

    def parseInject(self, payload: InjectPayload):
        """
        Convert the XML string representation of the given payload to a ConstructTpl
        The payload should be unattached (not already installed in the library)
        
        :param InjectPayload payload: is the given payload whose XML should be converted
        :raises SleighException: if there is any parsing issue
        """

    def restoreXmlInject(self, source: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], tp: typing.Union[jpype.JInt, int], parser: ghidra.xml.XmlPullParser) -> InjectPayload:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def callotherFixupNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def constantPool(self) -> ConstantPool:
        ...

    @property
    def programPayloads(self) -> jpype.JArray[InjectPayloadSleigh]:
        ...

    @property
    def callFixupNames(self) -> jpype.JArray[java.lang.String]:
        ...


class ParameterPieces(java.lang.Object):
    """
    Basic elements of a parameter: address, data-type, properties
    """

    class_: typing.ClassVar[java.lang.Class]
    address: ghidra.program.model.address.Address
    type: ghidra.program.model.data.DataType
    joinPieces: jpype.JArray[ghidra.program.model.pcode.Varnode]
    isThisPointer: jpype.JBoolean
    hiddenReturnPtr: jpype.JBoolean
    isIndirect: jpype.JBoolean

    def __init__(self):
        ...

    def assignAddressFromPieces(self, pieces: java.util.ArrayList[ghidra.program.model.pcode.Varnode], mostToLeast: typing.Union[jpype.JBoolean, bool], onePieceJoin: typing.Union[jpype.JBoolean, bool], language: Language):
        """
        Generate a parameter address given the list of Varnodes making up the parameter.
        
        :param java.util.ArrayList[ghidra.program.model.pcode.Varnode] pieces: is the given list of Varnodes
        :param jpype.JBoolean or bool mostToLeast: is true if the list is ordered most significant to least
        :param jpype.JBoolean or bool onePieceJoin: is true if the address should be considered a join of one piece
        :param Language language: is the Language associated with the calling convention
        """

    def getVariableStorage(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        ...

    @staticmethod
    def mergeSequence(seq: java.util.ArrayList[ghidra.program.model.pcode.Varnode], language: Language) -> java.util.ArrayList[ghidra.program.model.pcode.Varnode]:
        """
        Assuming the given list of Varnodes go from most significant to least significant,
        merge any contiguous elements in the list.  Merges in a register space are only allowed
        if the bigger Varnode exists as a formal register.
        
        :param java.util.ArrayList[ghidra.program.model.pcode.Varnode] seq: is the given list of Varnodes
        :param Language language: is the Language associated with the calling convention.
        :return: the merged list  (which may be the original list)
        :rtype: java.util.ArrayList[ghidra.program.model.pcode.Varnode]
        """

    def swapMarkup(self, op: ParameterPieces):
        """
        Swap data-type markup between this and another parameter
         
        Swap any data-type and flags, but leave the storage address intact.
        This assumes the two parameters are the same size.
        
        :param ParameterPieces op: is the other parameter to swap with this.
        """

    @property
    def variableStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...


class LanguageCompilerSpecPair(java.lang.Comparable[LanguageCompilerSpecPair]):
    """
    Represents an opinion's processor language and compiler.
    
    
    .. seealso::
    
        | :obj:`LanguageID`
    
        | :obj:`CompilerSpecID`
    """

    class_: typing.ClassVar[java.lang.Class]
    languageID: typing.Final[LanguageID]
    compilerSpecID: typing.Final[CompilerSpecID]

    @typing.overload
    def __init__(self, languageID: typing.Union[java.lang.String, str], compilerSpecID: typing.Union[java.lang.String, str]):
        """
        Creates a new language and compiler pair.
        
        :param java.lang.String or str languageID: The language ID string (x86:LE:32:default, 8051:BE:16:default, etc).
        :param java.lang.String or str compilerSpecID: The compiler spec ID string (gcc, borlandcpp, etc).
        :raises IllegalArgumentException: if the language or compiler ID strings are null or empty.
        """

    @typing.overload
    def __init__(self, languageID: LanguageID, compilerSpecID: CompilerSpecID):
        """
        Creates a new language and compiler pair.
        
        :param LanguageID languageID: The language ID.
        :param CompilerSpecID compilerSpecID: The compiler spec ID.
        :raises IllegalArgumentException: if the language or compiler ID is null.
        """

    @typing.overload
    def getCompilerSpec(self) -> CompilerSpec:
        """
        Gets the :obj:`CompilerSpec` for this object's :obj:`CompilerSpecID`.
        
        :return: The :obj:`CompilerSpec` for this object's :obj:`CompilerSpecID`.
        :rtype: CompilerSpec
        :raises LanguageNotFoundException: if no :obj:`Language` could be found for this
        object's :obj:`LanguageID`.
        :raises CompilerSpecNotFoundException: if no :obj:`CompilerSpec` could be found for this
        object's :obj:`CompilerSpecID`.
        """

    @typing.overload
    def getCompilerSpec(self, languageService: LanguageService) -> CompilerSpec:
        """
        Gets the :obj:`CompilerSpec` for this object's :obj:`CompilerSpecID`, using the given
        language service to do the lookup.
        
        :param LanguageService languageService: The language service to use for compiler lookup.
        :return: The :obj:`CompilerSpec` for this object's :obj:`CompilerSpecID`, using the given 
        language service to do the lookup.
        :rtype: CompilerSpec
        :raises LanguageNotFoundException: if no :obj:`Language` could be found for this
        object's :obj:`LanguageID` using the given language service.
        :raises CompilerSpecNotFoundException: if no :obj:`CompilerSpec` could be found for this
        object's :obj:`CompilerSpecID` using the given language service.
        """

    @typing.overload
    def getCompilerSpecDescription(self) -> CompilerSpecDescription:
        """
        Gets the :obj:`CompilerSpecDescription` for this object's :obj:`CompilerSpecID`.
        
        :return: The :obj:`CompilerSpecDescription` for this object's :obj:`CompilerSpecID`.
        :rtype: CompilerSpecDescription
        :raises LanguageNotFoundException: if no :obj:`LanguageDescription` could be found for this
        object's :obj:`LanguageID`.
        :raises CompilerSpecNotFoundException: if no :obj:`CompilerSpecDescription` could be found 
        for this object's :obj:`CompilerSpecID`.
        """

    @typing.overload
    def getCompilerSpecDescription(self, languageService: LanguageService) -> CompilerSpecDescription:
        """
        Gets the :obj:`CompilerSpecDescription` for this object's :obj:`CompilerSpecID`.
        
        :param LanguageService languageService: The language service to use for description lookup.
        :return: The :obj:`CompilerSpecDescription` for this object's :obj:`CompilerSpecID`.
        :rtype: CompilerSpecDescription
        :raises LanguageNotFoundException: if no :obj:`LanguageDescription` could be found for this
        object's :obj:`LanguageID`.
        :raises CompilerSpecNotFoundException: if no :obj:`CompilerSpecDescription` could be found 
        for this object's :obj:`CompilerSpecID` using the given language service.
        """

    def getCompilerSpecID(self) -> CompilerSpecID:
        """
        Get the compiler spec ID
        
        :return: compiler spec ID
        :rtype: CompilerSpecID
        """

    @typing.overload
    def getLanguage(self) -> Language:
        """
        Gets the :obj:`Language` for this object's :obj:`LanguageID`.
        
        :return: The :obj:`Language` for this object's :obj:`LanguageID`.
        :rtype: Language
        :raises LanguageNotFoundException: if no :obj:`Language` could be found for this
        object's :obj:`LanguageID`.
        """

    @typing.overload
    def getLanguage(self, languageService: LanguageService) -> Language:
        """
        Gets the :obj:`Language` for this object's :obj:`LanguageID`, using the given language
        service to do the lookup.
        
        :param LanguageService languageService: The language service to use for language lookup.
        :return: The :obj:`Language` for this object's :obj:`LanguageID`, using the given language
        service to do the lookup.
        :rtype: Language
        :raises LanguageNotFoundException: if no :obj:`Language` could be found for this
        object's :obj:`LanguageID` using the given language service.
        """

    @typing.overload
    def getLanguageDescription(self) -> LanguageDescription:
        """
        Gets the :obj:`LanguageDescription` for this object's :obj:`LanguageID`.
        
        :return: The :obj:`LanguageDescription` for this object's :obj:`LanguageID`.
        :rtype: LanguageDescription
        :raises LanguageNotFoundException: if no :obj:`LanguageDescription` could be found for this
        object's :obj:`LanguageID`.
        """

    @typing.overload
    def getLanguageDescription(self, languageService: LanguageService) -> LanguageDescription:
        """
        Gets the :obj:`LanguageDescription` for this object's :obj:`LanguageID`.
        
        :param LanguageService languageService: The language service to use for description lookup.
        :return: The :obj:`LanguageDescription` for this object's :obj:`LanguageID`.
        :rtype: LanguageDescription
        :raises LanguageNotFoundException: if no :obj:`LanguageDescription` could be found for this
        object's :obj:`LanguageID` using the given language service.
        """

    def getLanguageID(self) -> LanguageID:
        """
        Get the language ID
        
        :return: language ID
        :rtype: LanguageID
        """

    @property
    def languageDescription(self) -> LanguageDescription:
        ...

    @property
    def language(self) -> Language:
        ...

    @property
    def compilerSpecDescription(self) -> CompilerSpecDescription:
        ...

    @property
    def compilerSpec(self) -> CompilerSpec:
        ...


class DisassemblerContext(ProcessorContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def setFutureRegisterValue(self, address: ghidra.program.model.address.Address, value: RegisterValue):
        """
        Combines ``value`` with any previously saved future
        register value at ``address`` or any value stored in the program if there is no
        previously saved future value.  Use this method when multiple flows to the same address
        don't matter or the flowing from address is unknown.
         
        
        When ``value`` has conflicting bits with the previously
        saved value, ``value`` will take precedence.
         
         
        If the register value is the value for the 
        processor context register and a previously saved
        value does not exist, the user saved values in the 
        stored context of the program will be used as existing
        value.
        
        :param ghidra.program.model.address.Address address: the address to store the register value
        :param RegisterValue value: the register value to store at the address
        """

    @typing.overload
    def setFutureRegisterValue(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, value: RegisterValue):
        """
        Combines ``value`` with any previously saved future
        register value at ``fromAddr/toAddr`` or any value stored in the program if there is no
        previously saved future value.
         
        
        When ``value`` has conflicting bits with the previously
        saved value, ``value`` will take precedence.
         
         
        If the register value is the value for the 
        processor context register and a previously saved
        value does not exist, the user saved values in the 
        stored context of the program will be used as existing
        value.
        
        :param ghidra.program.model.address.Address fromAddr: the address this value if flowing from
        :param ghidra.program.model.address.Address toAddr: the address to store the register value
        :param RegisterValue value: the register value to store at the address
        """


class InjectContext(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    language: ghidra.app.plugin.processors.sleigh.SleighLanguage
    baseAddr: ghidra.program.model.address.Address
    nextAddr: ghidra.program.model.address.Address
    callAddr: ghidra.program.model.address.Address
    refAddr: ghidra.program.model.address.Address
    inputlist: java.util.ArrayList[ghidra.program.model.pcode.Varnode]
    output: java.util.ArrayList[ghidra.program.model.pcode.Varnode]

    def __init__(self):
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder):
        ...


class LanguageNotFoundException(java.io.IOException):
    """
    Exception class used when the named language cannot be found.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, languageID: LanguageID, majorVersion: typing.Union[jpype.JInt, int], minorVersion: typing.Union[jpype.JInt, int]):
        """
        Newer version of language required
        
        :param LanguageID languageID: 
        :param jpype.JInt or int majorVersion: 
        :param jpype.JInt or int minorVersion:
        """

    @typing.overload
    def __init__(self, languageID: LanguageID):
        """
        Language not found
        
        :param LanguageID languageID:
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, languageID: LanguageID, compilerSpecID: CompilerSpecID):
        ...

    @typing.overload
    def __init__(self, languageID: LanguageID, msg: typing.Union[java.lang.String, str]):
        """
        Language not found
        
        :param LanguageID languageID: 
        :param java.lang.String or str msg:
        """

    @typing.overload
    def __init__(self, processor: Processor):
        ...


class InstructionContext(java.lang.Object):
    """
    ``InstructionContext`` is utilized by a shared instruction prototype to
    access all relevant instruction data and context-register storage needed during 
    instruction parse and semantic pcode generation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the instruction address that this context corresponds to.
        
        :return: instruction address
        :rtype: ghidra.program.model.address.Address
        """

    def getMemBuffer(self) -> ghidra.program.model.mem.MemBuffer:
        """
        Get the read-only memory buffer containing the instruction bytes.  Its position will
        correspond to the instruction address.
        
        :return: instruction memory buffer
        :rtype: ghidra.program.model.mem.MemBuffer
        """

    @typing.overload
    def getParserContext(self) -> ParserContext:
        """
        Get the instruction parser context for the instruction which corresponds to this 
        context object.
        
        :return: the instruction parser context for the instruction which corresponds to this 
        context object.
        :rtype: ParserContext
        :raises MemoryAccessException: if memory error occurred while resolving instruction
        details.
        """

    @typing.overload
    def getParserContext(self, instructionAddress: ghidra.program.model.address.Address) -> ParserContext:
        """
        Get the instruction parser context which corresponds to the specified instruction
        address.  This may be obtained via either caching or by parsing the instruction
        at the specified address.  The returned ParserContext may be cast to the prototype's
        implementation without checking.  This method will throw an UnknownContextException
        if a compatible ParserContext is not found at the specified address.
        
        :param ghidra.program.model.address.Address instructionAddress: instruction address of requested context
        :return: the instruction parser context at the specified instruction address
        :rtype: ParserContext
        :raises UnknownContextException: if the instruction at the specified address
        was not previously parsed or attempting to instantiate context resulted in an
        exception.
        :raises MemoryAccessException: if memory error occurred while resolving instruction
        details.
        """

    def getProcessorContext(self) -> ProcessorContextView:
        """
        Get the read-only processor context containing the context-register state
        state at the corresponding instruction.  This is primarily used during the 
        parse phase to provide the initial context-register state.
        
        :return: the read-only processor context
        :rtype: ProcessorContextView
        """

    @property
    def processorContext(self) -> ProcessorContextView:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def memBuffer(self) -> ghidra.program.model.mem.MemBuffer:
        ...

    @property
    def parserContext(self) -> ParserContext:
        ...


class DataTypeProviderContext(java.lang.Object):
    """
    Interface for objects that can provide new instances of dataTypes
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataTypeComponent(self, offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Get one data type from buffer at the current position plus offset.
        
        :param jpype.JInt or int offset: the displacement from the current position.
        :return: the data type at offset from the current position.
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises IndexOutOfBoundsException: if offset is negative
        """

    def getDataTypeComponents(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.data.DataTypeComponent]:
        """
        Get an array of DataTypeComponents that begin at start or before end.
        DataTypes that begin before start are not returned
        DataTypes that begin before end, but terminate after end ARE returned
        
        :param jpype.JInt or int start: start offset
        :param jpype.JInt or int end: end offset
        :return: array of DataTypes that exist between start and end.
        :rtype: jpype.JArray[ghidra.program.model.data.DataTypeComponent]
        """

    def getUniqueName(self, baseName: typing.Union[java.lang.String, str]) -> str:
        """
        Get a unique name for a data type given a prefix name
        
        :param java.lang.String or str baseName: prefix for unique name
        :return: a unique data type name
        :rtype: str
        """

    @property
    def uniqueName(self) -> java.lang.String:
        ...

    @property
    def dataTypeComponent(self) -> ghidra.program.model.data.DataTypeComponent:
        ...


class InstructionSet(java.lang.Iterable[InstructionBlock]):
    """
    A set of instructions organized as a graph of basic blocks.
    """

    @typing.type_check_only
    class BlockIterator(java.util.Iterator[InstructionBlock]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FlowQueue(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory):
        ...

    def addBlock(self, block: InstructionBlock):
        """
        Add an Instruction block to this Instruction Set. 
        If the block is empty it will only be added to the empty-list and will not
        be added to the maps or block iterator
        
        :param InstructionBlock block: the block to add.
        """

    def containsBlockAt(self, blockAddr: ghidra.program.model.address.Address) -> bool:
        ...

    def emptyBlockIterator(self) -> java.util.Iterator[InstructionBlock]:
        """
        Returns an iterator over all empty blocks which likely contain a conflict error.
        
        :return: empty block iterator
        :rtype: java.util.Iterator[InstructionBlock]
        """

    def findFirstIntersectingBlock(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> InstructionBlock:
        """
        Find the first block within this InstructionSet which intersects the specified range.
        This method should be used sparingly since it uses a brute-force search.
        
        :param ghidra.program.model.address.Address min: the minimum intersection address
        :param ghidra.program.model.address.Address max: the maximum intersection address
        :return: block within this InstructionSet which intersects the specified range or null
        if not found
        :rtype: InstructionBlock
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address set that makes up all the instructions contained in this set.
        
        :return: the address set that makes up all the instructions contained in this set.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getConflicts(self) -> java.util.List[InstructionError]:
        """
        Returns a list of conflicts for this set.  If a block is not reachable from a non-conflicted
        block, it's conflicts(if any) will not be included.
        
        :return: the list of conflicts for this set.
        :rtype: java.util.List[InstructionError]
        """

    def getInstructionAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction at the specified address within this instruction set
        
        :param ghidra.program.model.address.Address address: 
        :return: instruction at the specified address within this instruction set or null if not found
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionBlockContaining(self, address: ghidra.program.model.address.Address) -> InstructionBlock:
        """
        Returns the non-empty InstructionBlock containing the specified address
        
        :param ghidra.program.model.address.Address address: 
        :return: the InstructionBlock containing the specified address or null if not found
        :rtype: InstructionBlock
        """

    def getInstructionCount(self) -> int:
        """
        Returns the number of instructions in this instruction set.
        
        :return: the number of instructions in this instruction set.
        :rtype: int
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the minimum address for this Instruction set;
        
        :return: the minimum address for this Instruction set;
        :rtype: ghidra.program.model.address.Address
        """

    def intersects(self, minAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if this instruction set intersects the specified range
        
        :param ghidra.program.model.address.Address minAddress: 
        :param ghidra.program.model.address.Address maxAddress: 
        :return: true if this instruction set intersects the specified range
        :rtype: bool
        """

    def iterator(self) -> java.util.Iterator[InstructionBlock]:
        """
        Returns an iterator over the blocks in this Instruction set, giving preference to fall
        through flows.  This iterator will not follow any flows from a block that has a conflict.
        If the last block returned from the iterator is marked as a conflict before the next() or
        hasNext() methods are called, then this iterator will respect the conflict.  In other words,
        this iterator follows block flows on the fly and doesn't pre-compute the blocks to return.  
        Also, if any blocks in this set don't have a flow to path from the start block, it will
        not be included in this iterator.
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def instructionAt(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def conflicts(self) -> java.util.List[InstructionError]:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def instructionBlockContaining(self) -> InstructionBlock:
        ...

    @property
    def instructionCount(self) -> jpype.JInt:
        ...


class Endian(java.lang.Enum[Endian]):

    class_: typing.ClassVar[java.lang.Class]
    BIG: typing.Final[Endian]
    LITTLE: typing.Final[Endian]

    def getDisplayName(self) -> str:
        ...

    def isBigEndian(self) -> bool:
        ...

    @staticmethod
    def toEndian(endianness: typing.Union[java.lang.String, str]) -> Endian:
        ...

    def toShortString(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Endian:
        ...

    @staticmethod
    def values() -> jpype.JArray[Endian]:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...


class UnknownRegister(Register):
    """
    ``UnknownRegister`` is used when a register is requested in the register space
    for an undefined location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, numBytes: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], typeFlags: typing.Union[jpype.JInt, int]):
        ...


class MaskImpl(Mask, java.io.Serializable):
    """
    Implements the Mask interface as a byte array.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msk: jpype.JArray[jpype.JByte]):
        """
        Construct a mask from a byte array.
        
        :param jpype.JArray[jpype.JByte] msk: the bits that make up the mask.
        """

    @typing.overload
    def applyMask(self, cde: jpype.JArray[jpype.JByte], result: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.applyMask(byte[], byte[])`
        """

    @typing.overload
    def applyMask(self, buffer: ghidra.program.model.mem.MemBuffer) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.applyMask(ghidra.program.model.mem.MemBuffer)`
        """

    def complementMask(self, msk: jpype.JArray[jpype.JByte], results: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.complementMask(byte[], byte[])`
        """

    def equalMaskedValue(self, cde: jpype.JArray[jpype.JByte], target: jpype.JArray[jpype.JByte]) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.equalMaskedValue(byte[], byte[])`
        """

    def equals(self, otherMask: jpype.JArray[jpype.JByte]) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.equals(byte[])`
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.getBytes()`
        """

    def subMask(self, msk: jpype.JArray[jpype.JByte]) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Mask.subMask(byte[])`
        """

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class ParallelInstructionLanguageHelper(java.lang.Object):
    """
    ``ParallelInstructionLanguageHelper`` provides the ability via a language 
    specified property to identify certain parallel instruction attributes. 
    Implementations must define a public default constructor.
     
    
    The following assumptions exist for parallel packets/groups of instructions:
    
     
    * All instructions in a packet/group which are not the last instruction in the
    packet/group must have a fall-through.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMnemonicPrefix(self, instr: ghidra.program.model.listing.Instruction) -> str:
        """
        Return the mnemonic prefix (i.e., || ) for the specified instriction.
        
        :param ghidra.program.model.listing.Instruction instr: 
        :return: mnemonic prefix or null if not applicable
        :rtype: str
        """

    def isEndOfParallelInstructionGroup(self, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Determine if the specified instruction is the last instruction in a parallel
        instruction group.  The group is defined as a sequential set of instructions 
        which are executed in parallel.  It is assumed that all terminal flows 
        will only be present in the semantics of the last instruction in a parallel
        group.
         
        
        This method is primarily intended to assist disassembly to keep parallel 
        instruction packets/groups intact within a single InstructionBlock to 
        facilitate the pcode crossbuild directive.  Such cases are expected to
        defer all flows to the last instruction in the packet and flows should never
        have a destination in the middle of a packet/group.  If pcode crossbuild's
        are never utilized this method may always return false.
        
        :param ghidra.program.model.listing.Instruction instruction: 
        :return: true if instruction is last in a parallel group or if no other
        instruction is executed in parallel with the specified instruction.
        :rtype: bool
        """

    def isParallelInstruction(self, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Determine if the specified instruction is executed in parallel with 
        the instruction preceding it.
        
        :param ghidra.program.model.listing.Instruction instruction: 
        :return: true if parallel else false
        :rtype: bool
        """

    @property
    def parallelInstruction(self) -> jpype.JBoolean:
        ...

    @property
    def mnemonicPrefix(self) -> java.lang.String:
        ...

    @property
    def endOfParallelInstructionGroup(self) -> jpype.JBoolean:
        ...


class InjectPayloadCallotherError(InjectPayloadCallother):
    """
    A substitute for a callother fixup that did not fully parse
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, failedPayload: InjectPayloadCallother):
        """
        Constructor for use if the p-code template did not parse
        
        :param ghidra.program.model.address.AddressFactory addrFactory: is the address factory to use constructing dummy p-code
        :param InjectPayloadCallother failedPayload: is the object with the failed template
        """

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, nm: typing.Union[java.lang.String, str]):
        ...


class NestedDelaySlotException(UnknownInstructionException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class InjectPayloadCallother(InjectPayloadSleigh):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str]):
        ...


class ParamEntry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, grp: typing.Union[jpype.JInt, int]):
        ...

    def containedBy(self, addr: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int]) -> bool:
        """
        Is this ParamEntry, as a memory range, contained by the given memory range.
        
        :param ghidra.program.model.address.Address addr: is the starting address of the given memory range
        :param jpype.JInt or int sz: is the number of bytes in the given memory range
        :return: true if this is contained
        :rtype: bool
        """

    def contains(self, otherEntry: ParamEntry) -> bool:
        """
        Does this ParamEntry contain another entry (as a subpiece)
        
        :param ParamEntry otherEntry: is the other entry
        :return: true if this contains the other entry
        :rtype: bool
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        ...

    def getAddrBySlot(self, slotnum: typing.Union[jpype.JInt, int], sz: typing.Union[jpype.JInt, int], typeAlign: typing.Union[jpype.JInt, int], res: ParameterPieces) -> int:
        """
        Assign the storage address when allocating something of size -sz- assuming -slotnum- slots
        have already been assigned.  Set the address to null if the -sz- is too small or if
        there are not enough slots left
        
        :param jpype.JInt or int slotnum: number of slots already assigned
        :param jpype.JInt or int sz: number of bytes to being assigned
        :param jpype.JInt or int typeAlign: required byte alignment for the parameter
        :param ParameterPieces res: will hold the final storage address
        :return: slotnum plus the number of slots used
        :rtype: int
        """

    def getAddressBase(self) -> int:
        ...

    def getAlign(self) -> int:
        ...

    def getAllGroups(self) -> jpype.JArray[jpype.JInt]:
        ...

    @staticmethod
    def getBasicTypeClass(tp: ghidra.program.model.data.DataType) -> StorageClass:
        ...

    def getGroup(self) -> int:
        ...

    def getMinSize(self) -> int:
        ...

    def getSize(self) -> int:
        ...

    def getSlot(self, addr: ghidra.program.model.address.Address, skip: typing.Union[jpype.JInt, int]) -> int:
        """
        Assuming the address is contained in this entry and we -skip- to a certain byte
        return the slot associated with that byte
        
        :param ghidra.program.model.address.Address addr: is the address to check (which MUST be contained)
        :param jpype.JInt or int skip: is the number of bytes to skip
        :return: the slot index
        :rtype: int
        """

    def getSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    def getType(self) -> StorageClass:
        ...

    def intersects(self, addr: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int]) -> bool:
        """
        Does this ParamEntry intersect the given range in some way
        
        :param ghidra.program.model.address.Address addr: is the starting address of the given range
        :param jpype.JInt or int sz: is the number of bytes in the given range
        :return: true if there is an intersection
        :rtype: bool
        """

    def isBigEndian(self) -> bool:
        ...

    def isEquivalent(self, obj: ParamEntry) -> bool:
        """
        Determine if this ParamEntry is equivalent to another instance
        
        :param ParamEntry obj: is the other instance
        :return: true if they are equivalent
        :rtype: bool
        """

    def isExclusion(self) -> bool:
        ...

    def isGrouped(self) -> bool:
        ...

    def isOverlap(self) -> bool:
        ...

    def isReverseStack(self) -> bool:
        ...

    def justifiedContain(self, addr: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def justifiedContainAddress(spc1: ghidra.program.model.address.AddressSpace, offset1: typing.Union[jpype.JLong, int], sz1: typing.Union[jpype.JInt, int], spc2: ghidra.program.model.address.AddressSpace, offset2: typing.Union[jpype.JLong, int], sz2: typing.Union[jpype.JInt, int], forceleft: typing.Union[jpype.JBoolean, bool], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        Return -1 if (op2,sz2) is not properly contained in (op1,sz1)
        If it is contained, return the endian aware offset of (op2,sz2)
        I.e. if the least significant byte of the op2 range falls on the least significant
        byte of the op1 range, return 0.  If it intersects the second least significant, return 1, etc.
        
        :param ghidra.program.model.address.AddressSpace spc1: the first address space
        :param jpype.JLong or int offset1: the first offset
        :param jpype.JInt or int sz1: size of first space
        :param ghidra.program.model.address.AddressSpace spc2: the second address space
        :param jpype.JLong or int offset2: is the second offset
        :param jpype.JInt or int sz2: size of second space
        :param jpype.JBoolean or bool forceleft: is true if containment is forced to be on the left even for big endian
        :param jpype.JBoolean or bool isBigEndian: true if big endian
        :return: the endian aware offset or -1
        :rtype: int
        """

    @staticmethod
    def orderWithinGroup(entry1: ParamEntry, entry2: ParamEntry):
        """
        ParamEntry within a group must be distinguishable by size or by type
        
        :param ParamEntry entry1: is the first being compared
        :param ParamEntry entry2: is the second being compared
        :raises XmlParseException: if the pair is not distinguishable
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, cspec: CompilerSpec, curList: java.util.List[ParamEntry], grouped: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def grouped(self) -> jpype.JBoolean:
        ...

    @property
    def reverseStack(self) -> jpype.JBoolean:
        ...

    @property
    def allGroups(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def exclusion(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> StorageClass:
        ...

    @property
    def align(self) -> jpype.JInt:
        ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def bigEndian(self) -> jpype.JBoolean:
        ...

    @property
    def overlap(self) -> jpype.JBoolean:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def minSize(self) -> jpype.JInt:
        ...

    @property
    def addressBase(self) -> jpype.JLong:
        ...

    @property
    def group(self) -> jpype.JInt:
        ...


class GhidraLanguagePropertyKeys(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    CUSTOM_DISASSEMBLER_CLASS: typing.Final = "customDisassemblerClass"
    """
    CUSTOM_DISASSEMBLER_CLASS is a full class name for a language-specific
    disassembler implementation.  The specified class must extend the generic 
    disassembler :obj:`Disassembler` implementation and must implement the same
    set of constructors.
    """

    ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS: typing.Final = "allowOffcutReferencesToFunctionStarts"
    """
    ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS is a boolean property used to
    indicate if function bodies can actually start offcut. This is useful,
    for instance, with the ARM processor in THUMB mode since the least
    significant bit of the address is 0x1 for a THUMB mode function, even
    though outside references to this function will be at one byte less than
    the actual function start. Default is false.
    """

    USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES: typing.Final = "useOperandReferenceAnalyzerSwitchTables"
    """
    USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES is a boolean property that
    indicates if a language should use the switch table analysis in the
    OperandReferenceAnalyzer. Default is false.
    """

    IS_TMS320_FAMILY: typing.Final = "isTMS320Family"
    """
    IS_TMS320_FAMILY is a boolean property that indicates this language is
    part of the general TMS320 family. Default is false. Used for general
    TMS320 analysis.
    """

    PARALLEL_INSTRUCTION_HELPER_CLASS: typing.Final = "parallelInstructionHelperClass"
    """
    PARALLEL_INSTRUCTION_HELPER_CLASS is a full class name for an implementation
    of the ParallelInstructionLanguageHelper.  Those languages which support parallel
    instruction execution may implement this helper class to facilitate display of
    a || indicator within a listing view.
    """

    ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE: typing.Final = "addressesDoNotAppearDirectlyInCode"
    """
    ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE is a boolean property that
    indicates if addresses don't appear directly in code. Supposedly applies
    to all RISC processors, according to ScalarOperandAnalyzer. Default is
    false.
    """

    USE_NEW_FUNCTION_STACK_ANALYSIS: typing.Final = "useNewFunctionStackAnalysis"
    """
    USE_NEW_FUNCTION_STACK_ANALYSIS is a boolean property that indicates if
    the StackVariableAnalyzer should use a NewFunctionStackAnalysisCmd
    instead of the older FunctionStackAnalysisCmd. Default is false.
    """

    EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS: typing.Final = "emulateInstructionStateModifierClass"
    """
    EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS is a string property that indicates the
    classname of a EmulateInstructionStateModifier implementation which should be
    used during emulation to assist with the adjusting the emulator state before and/or after
    each instruction is executed.  This class may also provide language defined behaviors
    for custom pcodeop's.  Default is null.
    """

    PCODE_INJECT_LIBRARY_CLASS: typing.Final = "pcodeInjectLibraryClass"
    """
    PCODE_INJECT_LIBRARY_CLASS indicates the classname of a PcodeInjectLibrary implementation
    that is used to generate p-code injection payloads which can replace either CALLs or CALLOTHERs
    during any form of p-code analysis.  The injections are primarily provided by ``<callfixup>``
    and ``<callotherfixup>`` tags in the compiler spec, but this provides a hook point for
    providing other means of injection.
    """

    ENABLE_SHARED_RETURN_ANALYSIS: typing.Final = "enableSharedReturnAnalysis"
    """
    Shared return analysis, where at the end of one function, the code will jump to another, and use
    the jumped to subroutines return.  Shared Return analysis is enabled by default for all processors.
     
    If calls are used as long-jumps this can cause problems, so it is disabled for older arm processors.
    """

    ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY: typing.Final = "enableContiguousFunctionsOnly"
    """
    Shared return analysis, option to assume contiguous functions where a function jumps to another function
    across the address space of another function.
     
    This could cause issues on programs with bad control flow, or bad disassembly
    """

    ENABLE_NO_RETURN_ANALYSIS: typing.Final = "enableNoReturnAnalysis"
    """
    Non returning function analysis, where a function such as exit() is known to the compiler
    not to return.  The compiler will generate data or code for another function immediately
    following the call.  Non-returning functions can be detected in many cases.
    """

    RESET_CONTEXT_ON_UPGRADE: typing.Final = "resetContextOnUpgrade"
    """
    Property to indicate that all stored instruction context should be cleared
    during a language upgrade operation which requires redisassembly.
    NOTE: This is an experimental concept which may be removed in the future
    """

    MINIMUM_DATA_IMAGE_BASE: typing.Final = "minimumDataImageBase"
    """
    Property to indicate the minimum recommended base address within the default
    data space for placing relocatable data sections.  This is intended to 
    avoid loading into low memory regions where registers may be defined.
    The default value for ELF will be just beyond the last memory register defined
    within the default data space.  This option is only utilized by the
    ELF Loader for Harvard Architecures when loading a relocatable ELF binary
    (i.e., object module) and corresponds to the ELF Loader option: ``Data Image Base``.
    """



class SleighLanguageDescription(BasicLanguageDescription):
    """
    Class for holding Language identifiers
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: LanguageID, description: typing.Union[java.lang.String, str], processor: Processor, endian: Endian, instructionEndian: Endian, size: typing.Union[jpype.JInt, int], variant: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], minorVersion: typing.Union[jpype.JInt, int], deprecated: typing.Union[jpype.JBoolean, bool], spaceTruncations: collections.abc.Mapping, compilerSpecDescriptions: java.util.List[CompilerSpecDescription], externalNames: collections.abc.Mapping):
        """
        Construct a new language description
        
        :param LanguageID id: the name of the language
        :param java.lang.String or str description: language description text
        :param Processor processor: processor name/family
        :param Endian endian: data endianness
        :param Endian instructionEndian: instruction endianness
        :param jpype.JInt or int size: processor size
        :param java.lang.String or str variant: processor variant name
        :param jpype.JInt or int version: the major version of the language.
        :param jpype.JInt or int minorVersion: minor version of language
        :param jpype.JBoolean or bool deprecated: true if this language should only be used for existing programs.
        :param collections.abc.Mapping spaceTruncations: address space truncations (or null)
        :param java.util.List[CompilerSpecDescription] compilerSpecDescriptions: one or more compiler spec descriptions
        :param collections.abc.Mapping externalNames: collection of external tools' names for the language
        """

    def getDefsFile(self) -> generic.jar.ResourceFile:
        """
        Get the specification file (if it exists)
        
        :return: specification file
        :rtype: generic.jar.ResourceFile
        """

    def getManualIndexFile(self) -> generic.jar.ResourceFile:
        ...

    def getSlaFile(self) -> generic.jar.ResourceFile:
        """
        
        
        :return: 
        :rtype: generic.jar.ResourceFile
        """

    def getSpecFile(self) -> generic.jar.ResourceFile:
        """
        Get the specification file (if it exists)
        
        :return: specification file
        :rtype: generic.jar.ResourceFile
        """

    def getTruncatedSpaceNames(self) -> java.util.Set[java.lang.String]:
        """
        
        
        :return: set of address space names which have been identified for truncation
        :rtype: java.util.Set[java.lang.String]
        """

    def getTruncatedSpaceSize(self, spaceName: typing.Union[java.lang.String, str]) -> int:
        """
        Get the truncated space size for the specified address space
        
        :param java.lang.String or str spaceName: address space name
        :return: truncated space size in bytes
        :rtype: int
        :raises NoSuchElementException:
        """

    def setDefsFile(self, defsFile: generic.jar.ResourceFile):
        """
        Set the (optional) specification file associated with this language
        
        :param generic.jar.ResourceFile defsFile: the specFile to associate with this description.
        """

    def setManualIndexFile(self, manualIndexFile: generic.jar.ResourceFile):
        ...

    def setSlaFile(self, slaFile: generic.jar.ResourceFile):
        """
        
        
        :param generic.jar.ResourceFile slaFile:
        """

    def setSpecFile(self, specFile: generic.jar.ResourceFile):
        """
        Set the (optional) specification file associated with this language
        
        :param generic.jar.ResourceFile specFile: the specFile to associate with this description.
        """

    @property
    def truncatedSpaceSize(self) -> jpype.JInt:
        ...

    @property
    def slaFile(self) -> generic.jar.ResourceFile:
        ...

    @slaFile.setter
    def slaFile(self, value: generic.jar.ResourceFile):
        ...

    @property
    def defsFile(self) -> generic.jar.ResourceFile:
        ...

    @defsFile.setter
    def defsFile(self, value: generic.jar.ResourceFile):
        ...

    @property
    def truncatedSpaceNames(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def specFile(self) -> generic.jar.ResourceFile:
        ...

    @specFile.setter
    def specFile(self, value: generic.jar.ResourceFile):
        ...

    @property
    def manualIndexFile(self) -> generic.jar.ResourceFile:
        ...

    @manualIndexFile.setter
    def manualIndexFile(self, value: generic.jar.ResourceFile):
        ...


class ProcessorNotFoundException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, processorName: typing.Union[java.lang.String, str]):
        ...


class InjectPayloadCallfixupError(InjectPayloadCallfixup):
    """
    A substitute for a callfixup that did not successfully parse.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, failedPayload: InjectPayloadCallfixup):
        ...

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, nm: typing.Union[java.lang.String, str]):
        ...


class InputListType(java.lang.Enum[InputListType]):
    """
    Cspec prototype model input listtype
    """

    class_: typing.ClassVar[java.lang.Class]
    STANDARD: typing.Final[InputListType]
    REGISTER: typing.Final[InputListType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> InputListType:
        ...

    @staticmethod
    def values() -> jpype.JArray[InputListType]:
        ...


class BasicLanguageDescription(LanguageDescription):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, id: LanguageID, processor: Processor, endian: Endian, instructionEndian: Endian, size: typing.Union[jpype.JInt, int], variant: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], minorVersion: typing.Union[jpype.JInt, int], deprecated: typing.Union[jpype.JBoolean, bool], compilerSpec: CompilerSpecDescription, externalNames: collections.abc.Mapping):
        ...

    @typing.overload
    def __init__(self, id: LanguageID, processor: Processor, endian: Endian, instructionEndian: Endian, size: typing.Union[jpype.JInt, int], variant: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], version: typing.Union[jpype.JInt, int], minorVersion: typing.Union[jpype.JInt, int], deprecated: typing.Union[jpype.JBoolean, bool], compilerSpecs: java.util.List[CompilerSpecDescription], externalNames: collections.abc.Mapping):
        ...

    def getCompatibleCompilerSpecDescriptions(self) -> java.util.List[CompilerSpecDescription]:
        ...

    def getCompilerSpecDescriptionByID(self, compilerSpecID: CompilerSpecID) -> CompilerSpecDescription:
        ...

    def getDescription(self) -> str:
        ...

    def getEndian(self) -> Endian:
        ...

    def getMinorVersion(self) -> int:
        ...

    def getProcessor(self) -> Processor:
        ...

    def getSize(self) -> int:
        ...

    def getVariant(self) -> str:
        ...

    def getVersion(self) -> int:
        ...

    def isDeprecated(self) -> bool:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def deprecated(self) -> jpype.JBoolean:
        ...

    @property
    def variant(self) -> java.lang.String:
        ...

    @property
    def compilerSpecDescriptionByID(self) -> CompilerSpecDescription:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def compatibleCompilerSpecDescriptions(self) -> java.util.List[CompilerSpecDescription]:
        ...

    @property
    def minorVersion(self) -> jpype.JInt:
        ...

    @property
    def version(self) -> jpype.JInt:
        ...

    @property
    def processor(self) -> Processor:
        ...

    @property
    def endian(self) -> Endian:
        ...


class ConstantPool(java.lang.Object):
    """
    Class for manipulating "deferred" constant systems like the java virtual machine constant pool
    """

    class Record(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        tag: jpype.JInt
        token: java.lang.String
        value: jpype.JLong
        byteData: jpype.JArray[jpype.JByte]
        type: ghidra.program.model.data.DataType
        isConstructor: jpype.JBoolean

        def __init__(self):
            ...

        def encode(self, encoder: ghidra.program.model.pcode.Encoder, ref: typing.Union[jpype.JLong, int], dtmanage: ghidra.program.model.pcode.PcodeDataTypeManager):
            ...

        def setUTF8Data(self, val: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    PRIMITIVE: typing.Final = 0
    STRING_LITERAL: typing.Final = 1
    CLASS_REFERENCE: typing.Final = 2
    POINTER_METHOD: typing.Final = 3
    POINTER_FIELD: typing.Final = 4
    ARRAY_LENGTH: typing.Final = 5
    INSTANCE_OF: typing.Final = 6
    CHECK_CAST: typing.Final = 7

    def __init__(self):
        ...

    def getRecord(self, ref: jpype.JArray[jpype.JLong]) -> ConstantPool.Record:
        ...

    @property
    def record(self) -> ConstantPool.Record:
        ...


class DecompilerLanguage(java.lang.Enum[DecompilerLanguage]):
    """
    Sources languages that can be output by the decompiler
    """

    class_: typing.ClassVar[java.lang.Class]
    C_LANGUAGE: typing.Final[DecompilerLanguage]
    JAVA_LANGUAGE: typing.Final[DecompilerLanguage]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DecompilerLanguage:
        ...

    @staticmethod
    def values() -> jpype.JArray[DecompilerLanguage]:
        ...


class RegisterBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addAlias(self, registerName: typing.Union[java.lang.String, str], alias: typing.Union[java.lang.String, str]) -> bool:
        """
        Add an alias to a previously defined register.
        
        :param java.lang.String or str registerName: defined register
        :param java.lang.String or str alias: alias to be added to defined register
        :return: true if alias addition was successful, else false
        :rtype: bool
        """

    def addLaneSize(self, registerName: typing.Union[java.lang.String, str], laneSizeInBytes: typing.Union[jpype.JInt, int]) -> bool:
        """
        Add a vector lane size to the specified register.
        
        :param java.lang.String or str registerName: register name
        :param jpype.JInt or int laneSizeInBytes: the size of the lane to add in bytes
        :return: true if register was found, else false
        :rtype: bool
        :raises UnsupportedOperationException: if register is unable to support the definition of 
        lanes.
        :raises IllegalArgumentException: if ``laneSizeInBytes`` is invalid
        """

    @typing.overload
    def addRegister(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, numBytes: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], typeFlags: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addRegister(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, numBytes: typing.Union[jpype.JInt, int], leastSignificantBit: typing.Union[jpype.JInt, int], bitLength: typing.Union[jpype.JInt, int], bigEndian: typing.Union[jpype.JBoolean, bool], typeFlags: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addRegister(self, register: Register):
        ...

    def getProcessContextAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the processor context address of the first
        context register added to this builder.
        
        :return: context address
        :rtype: ghidra.program.model.address.Address
        """

    def getRegister(self, name: typing.Union[java.lang.String, str]) -> Register:
        """
        Returns the register with the given name;
        
        :param java.lang.String or str name: the name of the register to retrieve
        :return: register or null if not found
        :rtype: Register
        """

    def getRegisterManager(self) -> RegisterManager:
        """
        Compute current register collection and instantiate a :obj:`RegisterManager`
        
        :return: new register manager instance
        :rtype: RegisterManager
        """

    def renameRegister(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]) -> bool:
        """
        Rename a register.  This allows generic register names declared within the language 
        specification (*.slaspec) to be renamed for a processor variant specification (*.pspec).
        
        :param java.lang.String or str oldName: original register name
        :param java.lang.String or str newName: new register name
        :return: true if rename was successful, else false
        :rtype: bool
        """

    def setFlag(self, registerName: typing.Union[java.lang.String, str], registerFlag: typing.Union[jpype.JInt, int]) -> bool:
        """
        Set a register flag for the specified register
        
        :param java.lang.String or str registerName: register name
        :param jpype.JInt or int registerFlag: Register defined flag bit(s)
        :return: true if register was found, else false
        :rtype: bool
        """

    def setGroup(self, registerName: typing.Union[java.lang.String, str], groupName: typing.Union[java.lang.String, str]) -> bool:
        """
        Set the group name for the specified register
        
        :param java.lang.String or str registerName: register name
        :param java.lang.String or str groupName: group name
        :return: true if register was found, else false
        :rtype: bool
        """

    @property
    def registerManager(self) -> RegisterManager:
        ...

    @property
    def register(self) -> Register:
        ...

    @property
    def processContextAddress(self) -> ghidra.program.model.address.Address:
        ...


class ExternalLanguageCompilerSpecQuery(java.lang.Object):
    """
    Analog to LanguageCompilerSpecQuery, for use with querying External Languages.
    That is, languages that exist in other products, like IDA-Pro's 'metapc.'
    """

    class_: typing.ClassVar[java.lang.Class]
    externalProcessorName: typing.Final[java.lang.String]
    externalTool: typing.Final[java.lang.String]
    endian: typing.Final[Endian]
    size: typing.Final[java.lang.Integer]
    compilerSpecID: typing.Final[CompilerSpecID]

    def __init__(self, externalProcessorName: typing.Union[java.lang.String, str], externalTool: typing.Union[java.lang.String, str], endian: Endian, size: typing.Union[java.lang.Integer, int], compilerSpecID: CompilerSpecID):
        ...


class InstructionError(java.lang.Object):

    class InstructionErrorType(java.lang.Enum[InstructionError.InstructionErrorType]):

        class_: typing.ClassVar[java.lang.Class]
        DUPLICATE: typing.Final[InstructionError.InstructionErrorType]
        """
        Duplicate instruction detected 
        while instructions were being added to program.
        This should not be marked but should prevent additional
        instructions from being added unnecessarily.
        """

        INSTRUCTION_CONFLICT: typing.Final[InstructionError.InstructionErrorType]
        """
        Conflict with existing instruction detected 
        while instructions were being added to program.
        Conflict address corresponds to existing code unit.
        The first instruction within the block whose range
        overlaps the conflict code-unit should terminate the
        block prior to being added.
        """

        DATA_CONFLICT: typing.Final[InstructionError.InstructionErrorType]
        """
        Conflict with existing data detected 
        while instructions were being added to program.
        Conflict address corresponds to existing code unit.
        The first instruction within the block whose range
        overlaps the conflict code-unit should terminate the
        block prior to being added.
        """

        OFFCUT_INSTRUCTION: typing.Final[InstructionError.InstructionErrorType]
        """
        Offcut conflict with existing instruction detected 
        while instructions were being added to program.
        Conflict address corresponds to existing code unit.
        The first instruction within the block whose range
        overlaps the conflict code-unit should terminate the
        block prior to being added.
        """

        PARSE: typing.Final[InstructionError.InstructionErrorType]
        """
        Instruction parsing failed at the conflict address.
        This conflict should only have a conflict address which 
        immediately follows the last instruction within the 
        block or matches the block-start if the block is empty.
        """

        MEMORY: typing.Final[InstructionError.InstructionErrorType]
        """
        Instruction parsing failed at the conflict address due
        to a memory error.
        This conflict should only have a conflict address which 
        immediately follows the last instruction within the 
        block or matches the block-start if the block is empty.
        """

        FLOW_ALIGNMENT: typing.Final[InstructionError.InstructionErrorType]
        """
        Instruction contains an unaligned flow which is indicative
        of a language problem.  The conflict address corresponds to the 
        instruction containing the flow.  While the instruction at the 
        conflict address may be added it should be the last.
        """

        isConflict: typing.Final[jpype.JBoolean]
        """
        Instruction error associated with a conflict with an existing
        code unit (instruction or data).
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> InstructionError.InstructionErrorType:
            ...

        @staticmethod
        def values() -> jpype.JArray[InstructionError.InstructionErrorType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def dumpInstructionDifference(newInst: ghidra.program.model.listing.Instruction, existingInstr: ghidra.program.model.listing.Instruction):
        ...

    def getConflictAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: address of another code unit which conflicts
        with intended instruction (required for CODE_UNIT 
        and DUPLCIATE errors, null for others)
        :rtype: ghidra.program.model.address.Address
        """

    def getConflictMessage(self) -> str:
        """
        
        
        :return: instruction error message
        :rtype: str
        """

    def getFlowFromAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: flow-from address if know else null
        :rtype: ghidra.program.model.address.Address
        """

    def getInstructionAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: address of new intended instruction which failed to be created (never null)
        :rtype: ghidra.program.model.address.Address
        """

    def getInstructionBlock(self) -> InstructionBlock:
        """
        
        
        :return: instruction block which corresponds to this error
        :rtype: InstructionBlock
        """

    def getInstructionErrorType(self) -> InstructionError.InstructionErrorType:
        """
        
        
        :return: type of instruction error
        :rtype: InstructionError.InstructionErrorType
        """

    def getParseContextValue(self) -> RegisterValue:
        """
        
        
        :return: disassembler context at intended instruction
        address (required for PARSE error, null for others)
        :rtype: RegisterValue
        """

    def isInstructionConflict(self) -> bool:
        ...

    def isOffcutError(self) -> bool:
        ...

    @property
    def parseContextValue(self) -> RegisterValue:
        ...

    @property
    def instructionErrorType(self) -> InstructionError.InstructionErrorType:
        ...

    @property
    def instructionBlock(self) -> InstructionBlock:
        ...

    @property
    def conflictAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def conflictMessage(self) -> java.lang.String:
        ...

    @property
    def flowFromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def offcutError(self) -> jpype.JBoolean:
        ...

    @property
    def instructionConflict(self) -> jpype.JBoolean:
        ...

    @property
    def instructionAddress(self) -> ghidra.program.model.address.Address:
        ...


class PrototypePieces(java.lang.Object):
    """
    Raw components of a function prototype (obtained from parsing source code)
    """

    class_: typing.ClassVar[java.lang.Class]
    model: PrototypeModel
    outtype: ghidra.program.model.data.DataType
    intypes: java.util.ArrayList[ghidra.program.model.data.DataType]
    firstVarArgSlot: jpype.JInt

    @typing.overload
    def __init__(self, model: PrototypeModel, oldList: jpype.JArray[ghidra.program.model.data.DataType], injectedThis: ghidra.program.model.data.DataType):
        """
        Populate pieces from old-style array of DataTypes
        
        :param PrototypeModel model: is the prototype model
        :param jpype.JArray[ghidra.program.model.data.DataType] oldList: is the list of output and input data-types
        :param ghidra.program.model.data.DataType injectedThis: if non-null is the data-type of the this pointer to be injected
        """

    @typing.overload
    def __init__(self, model: PrototypeModel, outType: ghidra.program.model.data.DataType):
        """
        Create prototype with output data-type and empty/unspecified input data-types
        
        :param PrototypeModel model: is the prototype model
        :param ghidra.program.model.data.DataType outType: is the output data-type
        """


class InjectPayload(java.lang.Object):
    """
    ``InjectPayload`` encapsulates a semantic (p-code) override which can be injected
    into analyses that work with p-code (Decompiler, SymbolicPropagator)
    The payload typically replaces either a subroutine call or a userop
    """

    class InjectParameter(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, nm: typing.Union[java.lang.String, str], sz: typing.Union[jpype.JInt, int]):
            ...

        def getIndex(self) -> int:
            ...

        def getName(self) -> str:
            ...

        def getSize(self) -> int:
            ...

        def isEquivalent(self, obj: InjectPayload.InjectParameter) -> bool:
            """
            Determine if this InjectParameter and another instance are equivalent
            
            :param InjectPayload.InjectParameter obj: is the other instance
            :return: true if they are equivalent
            :rtype: bool
            """

        @property
        def equivalent(self) -> jpype.JBoolean:
            ...

        @property
        def size(self) -> jpype.JInt:
            ...

        @property
        def name(self) -> java.lang.String:
            ...

        @property
        def index(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CALLFIXUP_TYPE: typing.Final = 1
    CALLOTHERFIXUP_TYPE: typing.Final = 2
    CALLMECHANISM_TYPE: typing.Final = 3
    EXECUTABLEPCODE_TYPE: typing.Final = 4

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode configuration parameters as a ``<pcode>`` element to stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for errors writing to the underlying stream
        """

    def getInput(self) -> jpype.JArray[InjectPayload.InjectParameter]:
        """
        
        
        :return: array of any input parameters for this inject
        :rtype: jpype.JArray[InjectPayload.InjectParameter]
        """

    def getName(self) -> str:
        """
        
        
        :return: formal name for this injection
        :rtype: str
        """

    def getOutput(self) -> jpype.JArray[InjectPayload.InjectParameter]:
        """
        
        
        :return: array of any output parameters for this inject
        :rtype: jpype.JArray[InjectPayload.InjectParameter]
        """

    def getParamShift(self) -> int:
        """
        
        
        :return: number of parameters from the original call which should be truncated
        :rtype: int
        """

    def getPcode(self, program: ghidra.program.model.listing.Program, con: InjectContext) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        A convenience function wrapping the inject method, to produce the final set
        of PcodeOp objects in an array
        
        :param ghidra.program.model.listing.Program program: is the Program for which injection is happening
        :param InjectContext con: is the context for injection
        :return: the array of PcodeOps
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        :raises MemoryAccessException: for problems establishing the injection context
        :raises IOException: for problems while emitting the injection p-code
        :raises UnknownInstructionException: if there is no underlying instruction being injected
        :raises NotFoundException: if an expected aspect of the injection is not present in context
        """

    def getSource(self) -> str:
        """
        
        
        :return: a String describing the source of this payload
        :rtype: str
        """

    def getType(self) -> int:
        """
        
        
        :return: the type of this injection:  CALLFIXUP_TYPE, CALLMECHANISM_TYPE, etc.
        :rtype: int
        """

    def inject(self, context: InjectContext, emit: ghidra.app.plugin.processors.sleigh.PcodeEmit):
        """
        Given a context, send the p-code payload to the emitter
        
        :param InjectContext context: is the context for injection
        :param ghidra.app.plugin.processors.sleigh.PcodeEmit emit: is the object accumulating the final p-code
        :raises MemoryAccessException: for problems establishing the injection context
        :raises IOException: for problems while emitting the injection p-code
        :raises UnknownInstructionException: if there is no underlying instruction being injected
        :raises NotFoundException: if an expected aspect of the injection is not present in context
        """

    def isEquivalent(self, obj: InjectPayload) -> bool:
        """
        Determine if this InjectPayload and another instance are equivalent
        (have the same name and generate the same p-code)
        
        :param InjectPayload obj: is the other payload
        :return: true if they are equivalent
        :rtype: bool
        """

    def isErrorPlaceholder(self) -> bool:
        """
        If parsing a payload (from XML) fails, a placeholder payload may be substituted and
        this method returns true for the substitute.  In all other cases, this returns false.
        
        :return: true if this is a placeholder for a payload with parse errors.
        :rtype: bool
        """

    def isFallThru(self) -> bool:
        """
        
        
        :return: true if the injected p-code falls thru
        :rtype: bool
        """

    def isIncidentalCopy(self) -> bool:
        """
        
        
        :return: true if this inject's COPY operations should be treated as incidental
        :rtype: bool
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, language: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        """
        Restore the payload from an XML stream.  The root expected document is
        the ``<pcode>`` tag, which may be wrapped with another tag by the derived class.
        
        :param ghidra.xml.XmlPullParser parser: is the XML stream
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: is used to resolve registers and address spaces
        :raises XmlParseException: for badly formed XML
        """

    @property
    def output(self) -> jpype.JArray[InjectPayload.InjectParameter]:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def paramShift(self) -> jpype.JInt:
        ...

    @property
    def input(self) -> jpype.JArray[InjectPayload.InjectParameter]:
        ...

    @property
    def incidentalCopy(self) -> jpype.JBoolean:
        ...

    @property
    def errorPlaceholder(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def fallThru(self) -> jpype.JBoolean:
        ...

    @property
    def source(self) -> java.lang.String:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...



__all__ = ["LanguageDescription", "InjectPayloadJumpAssist", "OldLanguageMappingService", "Language", "CompilerSpec", "InvalidPrototype", "ReadOnlyProcessorContext", "RegisterValue", "CompilerSpecNotFoundException", "LanguageVersionException", "InstructionPrototype", "BasicCompilerSpec", "ParamListStandard", "LanguageService", "ParamListStandardOut", "ContextSetting", "InjectPayloadSleigh", "ProcessorContext", "ProcessorContextView", "InstructionBlockFlow", "LanguageID", "PrototypeModel", "ProgramProcessorContext", "UndefinedValueException", "Register", "PrototypeModelMerged", "StorageClass", "RegisterTranslator", "ProgramArchitecture", "Processor", "ProcessorContextImpl", "AddressLabelInfo", "SpaceNames", "UnknownDataException", "OperandType", "IncompatibleMaskException", "VersionedLanguageService", "UnknownInstructionException", "BasicCompilerSpecDescription", "CompilerSpecID", "InjectPayloadCallfixup", "ParamListRegisterOut", "RegisterTree", "ParserContext", "PrototypeModelError", "InjectPayloadSegment", "UnknownContextException", "PcodeParser", "InstructionBlock", "CompilerSpecDescription", "LanguageProvider", "LanguageCompilerSpecQuery", "InsufficientBytesException", "Mask", "RegisterManager", "DisassemblerContextAdapter", "ParamList", "DynamicVariableStorage", "PcodeInjectLibrary", "ParameterPieces", "LanguageCompilerSpecPair", "DisassemblerContext", "InjectContext", "LanguageNotFoundException", "InstructionContext", "DataTypeProviderContext", "InstructionSet", "Endian", "UnknownRegister", "MaskImpl", "ParallelInstructionLanguageHelper", "InjectPayloadCallotherError", "NestedDelaySlotException", "InjectPayloadCallother", "ParamEntry", "GhidraLanguagePropertyKeys", "SleighLanguageDescription", "ProcessorNotFoundException", "InjectPayloadCallfixupError", "InputListType", "BasicLanguageDescription", "ConstantPool", "DecompilerLanguage", "RegisterBuilder", "ExternalLanguageCompilerSpecQuery", "InstructionError", "PrototypePieces", "InjectPayload"]
