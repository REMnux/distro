from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class ThunkReference(DynamicReference):
    """
    Implementation for a Thunk Function reference.
    These references are dynamic in nature and may not be explicitly added,
    removed or altered.  There presence is inferred by the existence
    of a thunk function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, thunkAddr: ghidra.program.model.address.Address, thunkedAddr: ghidra.program.model.address.Address):
        """
        Thunk reference constructor
        
        :param ghidra.program.model.address.Address thunkAddr: thunk function address
        :param ghidra.program.model.address.Address thunkedAddr: "thunked" function address
        """


class Equate(java.lang.Object):
    """
    An Equate associates a string with a scalar value in the program, 
    and contains a list of addresses and operand positions that refer 
    to this equate.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addReference(self, refAddr: ghidra.program.model.address.Address, opndPosition: typing.Union[jpype.JInt, int]):
        """
        Add a reference (at the given operand position) to this equate.  If a reference already
        exists for the instruction at this address, then the old reference will be removed
        before the new reference is added.
        
        :param ghidra.program.model.address.Address refAddr: the address where the equate is used.
        :param jpype.JInt or int opndPosition: the operand index where the equate is used.
        """

    @typing.overload
    def addReference(self, dynamicHash: typing.Union[jpype.JLong, int], refAddr: ghidra.program.model.address.Address):
        """
        Add a reference (at the given dynamic hash position) to this equate. If a reference already
        exists for the instruction at this address, then the old reference will be removed
        before the new reference is added.
        
        :param jpype.JLong or int dynamicHash: constant varnode dynamic hash value
        :param ghidra.program.model.address.Address refAddr: the address where the equate is used.
        """

    def getDisplayName(self) -> str:
        """
        Gets the "display name" of this equate.  Note that the display name may be different
        than the equate's actual name if the equate is based off a data type id.
        
        :return: The "display name" of this equate.
        :rtype: str
        """

    def getDisplayValue(self) -> str:
        """
        Gets a more accurate representation of the equate value. Used for rendering as close to the
        listing as possible.
        
        :return: A more accurate representation of the equate value.
        :rtype: str
        """

    def getEnumUUID(self) -> ghidra.util.UniversalID:
        """
        Gets the universal id from this equate if the equate was based off of an enum.
        
        :return: The universal id for this equate.
        :rtype: ghidra.util.UniversalID
        """

    def getName(self) -> str:
        """
        Get the actual name of this equate.  Note that this name may be different than the
        "display name," which is what the user will see.
        
        :return: The actual name of this equate.
        :rtype: str
        """

    def getReferenceCount(self) -> int:
        """
        Get the number of references to this equate.
        """

    @typing.overload
    def getReferences(self) -> jpype.JArray[EquateReference]:
        """
        Get the references for this equate.
        
        :return: a array of EquateReferences.
        :rtype: jpype.JArray[EquateReference]
        """

    @typing.overload
    def getReferences(self, refAddr: ghidra.program.model.address.Address) -> java.util.List[EquateReference]:
        """
        Get references for this equate attached to a specific address
        
        :param ghidra.program.model.address.Address refAddr: is the address
        :return: the list of EquateReferences
        :rtype: java.util.List[EquateReference]
        """

    def getValue(self) -> int:
        """
        Get the value of this equate.
        """

    def isEnumBased(self) -> bool:
        """
        Checks if equate is based off an enum's universal id.
        
        :return: 
        :rtype: bool
        """

    def isValidUUID(self) -> bool:
        """
        Checks if equate is based off an enum's universal id and checks if the enum still exists.
        The equate is still valid if the equate is not based off an enum.
        
        :return: true if the equate is based off an enum that still exists.
        :rtype: bool
        """

    @typing.overload
    def removeReference(self, refAddr: ghidra.program.model.address.Address, opndPosition: typing.Union[jpype.JInt, int]):
        """
        Remove the reference at the given operand position.
        
        :param ghidra.program.model.address.Address refAddr: the address that was using this equate
        :param jpype.JInt or int opndPosition: the operand index of the operand that was using this eqate.
        """

    @typing.overload
    def removeReference(self, dynamicHash: typing.Union[jpype.JLong, int], refAddr: ghidra.program.model.address.Address):
        """
        Remove the reference at the given address
        
        :param jpype.JLong or int dynamicHash: the hash of the reference
        :param ghidra.program.model.address.Address refAddr: the reference's address
        """

    def renameEquate(self, newName: typing.Union[java.lang.String, str]):
        """
        Changes the name associated with the equate.
        
        :param java.lang.String or str newName: the new name for this equate.
        :raises DuplicateNameException: thrown if newName is already
        used by another equate.
        :raises InvalidInputException: if newName contains blank characters,
        is zero length, or is null
        """

    def toString(self) -> str:
        """
        Get the name of this equate.
        
        
        .. seealso::
        
            | :obj:`.getName()`
        """

    @property
    def displayValue(self) -> java.lang.String:
        ...

    @property
    def validUUID(self) -> jpype.JBoolean:
        ...

    @property
    def references(self) -> jpype.JArray[EquateReference]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...

    @property
    def referenceCount(self) -> jpype.JInt:
        ...

    @property
    def enumBased(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def enumUUID(self) -> ghidra.util.UniversalID:
        ...


class StackReference(Reference):

    class_: typing.ClassVar[java.lang.Class]

    def getStackOffset(self) -> int:
        """
        Returns offset of referenced stack location
        """

    @property
    def stackOffset(self) -> jpype.JInt:
        ...


class Reference(java.lang.Comparable[Reference]):
    """
    Base class to hold information about a referring address. Derived classes add
    what the address is referring to. A basic reference consists of a "from"
    address, the reference type, the operand index for where the reference is,
    and whether the reference is user defined.
    """

    class_: typing.ClassVar[java.lang.Class]
    MNEMONIC: typing.Final = -1
    """
    Operand index which corresponds to the instruction/data mnemonic.
    """

    OTHER: typing.Final = -2
    """
    Special purpose operand index when not applicable (i.e., Thunk reference)
    """


    def getFromAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the codeunit that is making the reference.
        """

    def getOperandIndex(self) -> int:
        """
        Get the operand index of where this reference was placed.
        
        :return: op index or ReferenceManager.MNEMONIC
        :rtype: int
        """

    def getReferenceType(self) -> RefType:
        """
        Get the type of reference being made.
        """

    def getSource(self) -> SourceType:
        """
        Gets the source of this reference. :obj:`SourceType`s
        
        :return: the source of this reference
        :rtype: SourceType
        """

    def getSymbolID(self) -> int:
        """
        Get the symbol ID associated with this reference.
        Applies to memory references only.
        
        :return: symbol ID or -1 if no symbol is associated with this reference
        :rtype: int
        """

    def getToAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the "to" address for this reference.
        """

    def isEntryPointReference(self) -> bool:
        """
        Returns true if this reference is an instance of EntryReference.
        """

    def isExternalReference(self) -> bool:
        """
        Returns true if this reference is an instance of ExternalReference.
        """

    def isMemoryReference(self) -> bool:
        """
        Returns true if this reference to an address in the programs memory
        space. This includes offset and shifted references.
        """

    def isMnemonicReference(self) -> bool:
        """
        Return true if this reference is on the Mnemonic and not on an operand
        """

    def isOffsetReference(self) -> bool:
        """
        Returns true if this reference is an instance of OffsetReference.
        """

    def isOperandReference(self) -> bool:
        """
        Return true if this reference is on an operand and not on the Mnemonic.
        """

    def isPrimary(self) -> bool:
        """
        Return whether this reference is marked as primary.
        """

    def isRegisterReference(self) -> bool:
        """
        Returns true if this reference to an address in the programs register
        space.
        """

    def isShiftedReference(self) -> bool:
        """
        Returns true if this reference is an instance of ShiftedReference.
        """

    def isStackReference(self) -> bool:
        """
        Returns true if this reference is an instance of StackReference and
        refers to a stack location.
        """

    @property
    def symbolID(self) -> jpype.JLong:
        ...

    @property
    def stackReference(self) -> jpype.JBoolean:
        ...

    @property
    def shiftedReference(self) -> jpype.JBoolean:
        ...

    @property
    def referenceType(self) -> RefType:
        ...

    @property
    def offsetReference(self) -> jpype.JBoolean:
        ...

    @property
    def operandReference(self) -> jpype.JBoolean:
        ...

    @property
    def source(self) -> SourceType:
        ...

    @property
    def toAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...

    @property
    def registerReference(self) -> jpype.JBoolean:
        ...

    @property
    def mnemonicReference(self) -> jpype.JBoolean:
        ...

    @property
    def externalReference(self) -> jpype.JBoolean:
        ...

    @property
    def memoryReference(self) -> jpype.JBoolean:
        ...

    @property
    def entryPointReference(self) -> jpype.JBoolean:
        ...

    @property
    def fromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...


class LabelHistory(java.lang.Object):
    """
    Container for history information about what happened to a label.
    """

    class_: typing.ClassVar[java.lang.Class]
    ADD: typing.Final = 0
    """
    Label added.
    """

    REMOVE: typing.Final = 1
    """
    Label removed.
    """

    RENAME: typing.Final = 2
    """
    Label renamed.
    """


    def __init__(self, addr: ghidra.program.model.address.Address, userName: typing.Union[java.lang.String, str], actionID: typing.Union[jpype.JByte, int], labelStr: typing.Union[java.lang.String, str], modificationDate: java.util.Date):
        """
        Construct a new LabelHistory object.
        
        :param ghidra.program.model.address.Address addr: address of the label change
        :param java.lang.String or str userName: name of user who made the change
        :param jpype.JByte or int actionID: either ADD, REMOVE, or RENAME
        :param java.lang.String or str labelStr: label string
        :param java.util.Date modificationDate: date of the change
        """

    def getActionID(self) -> int:
        """
        Get the action ID for this label history object.
        
        :return: ADD, REMOVE, or RENAME
        :rtype: int
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get address for this label history object.
        """

    def getLabelString(self) -> str:
        """
        Get the label string for this label history object.
        """

    def getModificationDate(self) -> java.util.Date:
        """
        Get the modification date
        """

    def getUserName(self) -> str:
        """
        Get the user that made the change.
        """

    @property
    def modificationDate(self) -> java.util.Date:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def labelString(self) -> java.lang.String:
        ...

    @property
    def actionID(self) -> jpype.JByte:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...


class AddressLabelPair(java.io.Serializable):
    """
    Container for holding an address and label.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str]):
        """
        Creates a new ``AddressLabelPair``.
        
        :param ghidra.program.model.address.Address addr: the address
        :param java.lang.String or str label: the label
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address.
        """

    def getLabel(self) -> str:
        """
        Returns the label.
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def label(self) -> java.lang.String:
        ...


class RefTypeFactory(java.lang.Object):
    """
    Factory class to create RefType objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def get(type: typing.Union[jpype.JByte, int]) -> RefType:
        """
        Get static instance of the specified RefType/FlowType
        
        :param jpype.JByte or int type: ref-type value
        :return: ref-type instance
        :rtype: RefType
        :raises NoSuchElementException: if ref-type is not defined
        """

    @staticmethod
    def getDataRefTypes() -> jpype.JArray[RefType]:
        ...

    @staticmethod
    def getDefaultComputedFlowType(instr: ghidra.program.model.listing.Instruction) -> FlowType:
        """
        Determine default computed FlowType for a specified instruction.  It is assumed
        that all computed flows utilize a register in its destination specification/computation.
        
        :param ghidra.program.model.listing.Instruction instr: instruction
        :return: FlowType or null if unable to determine
        :rtype: FlowType
        """

    @staticmethod
    def getDefaultFlowType(instr: ghidra.program.model.listing.Instruction, toAddr: ghidra.program.model.address.Address, allowComputedFlowType: typing.Union[jpype.JBoolean, bool]) -> FlowType:
        """
        Determine default FlowType for a specified instruction and flow destination toAddr.
        
        :param ghidra.program.model.listing.Instruction instr: instruction
        :param ghidra.program.model.address.Address toAddr: flow destination address
        :param jpype.JBoolean or bool allowComputedFlowType: if true and an absolute flow type is not found
        a computed flow type will be returned if only one exists.
        :return: FlowType or null if unable to determine
        :rtype: FlowType
        """

    @staticmethod
    def getDefaultMemoryRefType(cu: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int], toAddr: ghidra.program.model.address.Address, ignoreExistingReferences: typing.Union[jpype.JBoolean, bool]) -> RefType:
        """
        Get the default memory flow/data RefType for the specified code unit and opIndex.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit
        :param jpype.JInt or int opIndex: the op index
        :param ghidra.program.model.address.Address toAddr: reference destination
        :param jpype.JBoolean or bool ignoreExistingReferences: if true existing references will not influence default
        reference type returned.
        :return: default RefType
        :rtype: RefType
        """

    @staticmethod
    def getDefaultRegisterRefType(cu: ghidra.program.model.listing.CodeUnit, reg: ghidra.program.model.lang.Register, opIndex: typing.Union[jpype.JInt, int]) -> RefType:
        """
        Get the default stack data RefType for the specified code-unit/opIndex and register
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit
        :param ghidra.program.model.lang.Register reg: the register
        :param jpype.JInt or int opIndex: the op index
        :return: default RefType
        :rtype: RefType
        """

    @staticmethod
    def getDefaultStackRefType(cu: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int]) -> RefType:
        """
        Get the default register data RefType for the specified code-unit/opIndex and register
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to get the default stack ref type.
        :param jpype.JInt or int opIndex: the operand index.
        :return: the default register datat refType.
        :rtype: RefType
        """

    @staticmethod
    def getExternalRefTypes() -> jpype.JArray[RefType]:
        ...

    @staticmethod
    def getMemoryRefTypes() -> jpype.JArray[RefType]:
        ...

    @staticmethod
    def getStackRefTypes() -> jpype.JArray[RefType]:
        ...


class SymbolType(java.lang.Object):
    """
    Class to represent the various types of Symbols.
    """

    class_: typing.ClassVar[java.lang.Class]
    LABEL: typing.Final[SymbolType]
    CODE: typing.Final[SymbolType]
    """
    
    
    
    .. deprecated::
    
    use :obj:`.LABEL` instead.
    """

    LIBRARY: typing.Final[SymbolType]
    NAMESPACE: typing.Final[SymbolType]
    CLASS: typing.Final[SymbolType]
    FUNCTION: typing.Final[SymbolType]
    PARAMETER: typing.Final[SymbolType]
    LOCAL_VAR: typing.Final[SymbolType]
    GLOBAL_VAR: typing.Final[SymbolType]
    GLOBAL: typing.Final[SymbolType]

    def allowsDuplicates(self) -> bool:
        """
        Returns true of this symbol type allows duplicate names.
        
        :return: true of this symbol type allows duplicate names.
        :rtype: bool
        """

    def getID(self) -> int:
        """
        Returns the id of this symbol type.
        """

    @staticmethod
    def getSymbolType(id: typing.Union[jpype.JInt, int]) -> SymbolType:
        """
        Returns the SymbolType for the given id.
        
        :param jpype.JInt or int id: the id for the SymbolType to find.
        """

    def isNamespace(self) -> bool:
        """
        Returns true if this symbol represents a namespace.
        """

    def isValidAddress(self, program: ghidra.program.model.listing.Program, symbolAddress: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the given address is valid for this symbol type.
        
        :param ghidra.program.model.listing.Program program: the program to test for a valid address.
        :param ghidra.program.model.address.Address symbolAddress: the address of the symbol to be tested.
        :return: true if the given address is valid within the given program.
        :rtype: bool
        """

    def isValidParent(self, program: ghidra.program.model.listing.Program, parent: Namespace, symbolAddr: ghidra.program.model.address.Address, isExternalSymbol: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Returns true if the given namespace is a valid parent for a symbol of this type
        if it has the given address and whether or not it is external.
        
        :param ghidra.program.model.listing.Program program: the program to contain the symbol
        :param Namespace parent: the namespace where a symbol will potentially be parented.
        :param ghidra.program.model.address.Address symbolAddr: the address of they symbol to be parented.
        :param jpype.JBoolean or bool isExternalSymbol: true if the symbol is external.
        :return: true if the given namespace is a valid parent for a symbol if it has the
        given address and whether or not it is external.
        :rtype: bool
        """

    def isValidSourceType(self, sourceType: SourceType, symbolAddress: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the given SourceType is valid for this symbol type. (For example, Some symbols
        don't support the SymbolType.DEFAULT)
        
        :param SourceType sourceType: the sourceType to test.
        :param ghidra.program.model.address.Address symbolAddress: the address of the symbol to be tested.
        :return: true if the given SourceType is valid for this symbol type.
        :rtype: bool
        """

    @property
    def namespace(self) -> jpype.JBoolean:
        ...

    @property
    def iD(self) -> jpype.JByte:
        ...


class DataRefType(RefType):
    """
    Class to define reference types for data.
    """

    class_: typing.ClassVar[java.lang.Class]


class ReferenceIteratorAdapter(ReferenceIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[Reference]):
        ...


class SourceType(java.lang.Enum[SourceType]):

    class_: typing.ClassVar[java.lang.Class]
    ANALYSIS: typing.Final[SourceType]
    """
    The object's source indicator for an auto analysis.
    """

    USER_DEFINED: typing.Final[SourceType]
    """
    The object's source indicator for a user defined.
    """

    DEFAULT: typing.Final[SourceType]
    """
    The object's source indicator for a default.
    """

    IMPORTED: typing.Final[SourceType]
    """
    The object's source indicator for an imported.
    """


    def getDisplayString(self) -> str:
        """
        Returns a user-friendly string
        """

    def isHigherPriorityThan(self, source: SourceType) -> bool:
        """
        Determines if this source type is a higher priority than the one being
        passed to this method as a parameter.
        USER_DEFINED objects are higher priority than IMPORTED objects which are higher
        priority than ANALYSIS objects which are higher priority than DEFAULT objects.
        
        :param SourceType source: the source type whose priority is to be compared with this one's.
        :return: true if this source type is a higher priority.
        false if this source type is the same priority or lower priority.
        :rtype: bool
        """

    def isLowerPriorityThan(self, source: SourceType) -> bool:
        """
        Determines if this source type is a lower priority than the one being
        passed to this method as a parameter.
        DEFAULT objects are lower priority than ANALYSIS objects which are lower
        priority than IMPORTED objects which are lower priority than USER_DEFINED objects.
        
        :param SourceType source: the source type whose priority is to be compared with this one's.
        :return: true if this source type is a lower priority.
        false if this source type is the same priority or higher priority.
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SourceType:
        ...

    @staticmethod
    def values() -> jpype.JArray[SourceType]:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...

    @property
    def lowerPriorityThan(self) -> jpype.JBoolean:
        ...

    @property
    def higherPriorityThan(self) -> jpype.JBoolean:
        ...


class RefType(java.lang.Object):
    """
    :obj:`RefType` defines reference types used to specify the nature of a directional 
    relationship between a source-location and a destination-location where a "location" 
    may correspond to a :obj:`Address`, :obj:`CodeUnit`, :obj:`CodeBlock` or other 
    code related objects.  Reference types are generally identified as either 
    :meth:`data <.isData>` (see :obj:`DataRefType`) or :meth:`flow <.isFlow>` 
    (see :obj:`FlowType`).
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID: typing.Final[FlowType]
    """
    :obj:`.INVALID` corresponds to an unknown :obj:`FlowType` which encountered an error
    when determining the flow-type of the instruction at the from address.
    """

    FLOW: typing.Final[FlowType]
    """
    :obj:`.FLOW` corresponds to a complex or generic :obj:`FlowType`.  This may be used 
    to describe the flow-type of an instruction or code-block which contains multiple outbound 
    flows of differing types.  This should not be used for a specific flow :obj:`Reference`.
    """

    FALL_THROUGH: typing.Final[FlowType]
    """
    :obj:`.FALL_THROUGH` corresponds to an instruction fall-through override where modeling
    requires a fall-through instruction to convey a branch around other :obj:`CodeUnit`s.
    While this may be freely used to describe the flow-type of a code-block or its relationship
    to another code-block, its use with a :obj:`Reference` is **reserved for internal use** 
    to reflect an :obj:`Instruction` fall-through-override or length-override condition.
    """

    UNCONDITIONAL_JUMP: typing.Final[FlowType]
    """
    :obj:`.UNCONDITIONAL_JUMP` corresponds to an unconditional jump/branch :obj:`FlowType`.  
    This may be used to describe the flow-type of an instruction or code-block, or
    :obj:`Reference` to another instruction or code-block.
    """

    CONDITIONAL_JUMP: typing.Final[FlowType]
    """
    :obj:`.CONDITIONAL_JUMP` corresponds to a conditional jump/branch :obj:`FlowType`.  
    This may be used to describe the flow-type of an instruction or code-block, or
    :obj:`Reference` to another instruction or code-block.
    """

    UNCONDITIONAL_CALL: typing.Final[FlowType]
    """
    :obj:`.UNCONDITIONAL_CALL` corresponds to an unconditional call :obj:`FlowType` with fall-through.   
    This may be used to describe the flow-type of an instruction or code-block, or
    call :obj:`Reference` to another instruction or code-block.
    """

    CONDITIONAL_CALL: typing.Final[FlowType]
    """
    :obj:`.CONDITIONAL_CALL` corresponds to a conditional call :obj:`FlowType` with fall-through.   
    This may be used to describe the flow-type of an instruction or code-block, or
    call :obj:`Reference` to another instruction or code-block.
    """

    TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.TERMINATOR` corresponds to a terminal :obj:`FlowType` (e.g., return from a 
    function).  This may be used to describe the flow-type of an instruction or code-block 
    but should generally not be used with a :obj:`Reference`.
    """

    COMPUTED_JUMP: typing.Final[FlowType]
    """
    :obj:`.COMPUTED_JUMP` corresponds to a computed jump/branch :obj:`FlowType`.  
    This may be used to describe the flow-type of an instruction or code-block, or
    :obj:`Reference` to another instruction or code-block.
    """

    CONDITIONAL_TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.TERMINATOR` corresponds to a terminal :obj:`FlowType` (e.g., conditional return 
    from a function).  This may be used to describe the flow-type of an instruction or code-block 
    but should generally not be used with a :obj:`Reference`.
    """

    COMPUTED_CALL: typing.Final[FlowType]
    """
    :obj:`.COMPUTED_CALL` corresponds to a computed call :obj:`FlowType` with fall-through.  
    This may be used to describe the flow-type of an instruction or code-block, or
    call :obj:`Reference` to another instruction or code-block.
    """

    CALL_TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.CALL_TERMINATOR` corresponds to an unconditional call :obj:`FlowType`
    followed by a terminal without fall-through (e.g., unconditional return from a function).  
    This may be used to describe the flow-type of an instruction or code-block but 
    should generally not be used with a :obj:`Reference`.  A corresponding :obj:`Reference`
    should generally specify :obj:`.__UNCONDITIONAL_CALL`.
    """

    COMPUTED_CALL_TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.COMPUTED_CALL_TERMINATOR` corresponds to an unconditional call :obj:`FlowType`
    followed by a terminal without fall-through (e.g., unconditional return from a function).  
    This may be used to describe the flow-type of an instruction or code-block but 
    should generally not be used with a :obj:`Reference`.  A corresponding :obj:`Reference`
    should generally specify :obj:`.COMPUTED_CALL`.
    """

    CONDITIONAL_CALL_TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.CONDITIONAL_CALL_TERMINATOR` corresponds to a conditional call :obj:`FlowType`
    followed by a terminal without fall-through (e.g., unconditional return from a function).  
    This may be used to describe the flow-type of an instruction or code-block but 
    should generally not be used with a :obj:`Reference`.  A corresponding :obj:`Reference`
    should generally specify :obj:`.CONDITIONAL_CALL`.
    """

    CONDITIONAL_COMPUTED_CALL: typing.Final[FlowType]
    """
    :obj:`.CONDITIONAL_COMPUTED_CALL` corresponds to a conditional computed call :obj:`FlowType` 
    with fall-through. This may be used to describe the flow-type of an instruction or 
    code-block, or call :obj:`Reference` to another instruction or code-block.
    """

    CONDITIONAL_COMPUTED_JUMP: typing.Final[FlowType]
    """
    :obj:`.CONDITIONAL_COMPUTED_JUMP` corresponds to a conditional computed jump/branch 
    :obj:`FlowType`.  This may be used to describe the flow-type of an instruction or 
    code-block, or :obj:`Reference` to another instruction or code-block.
    """

    JUMP_TERMINATOR: typing.Final[FlowType]
    """
    :obj:`.JUMP_TERMINATOR` corresponds to a conditional jump/branch :obj:`FlowType`
    followed by a terminal without fall-through (e.g., unconditional return from a function).  
    This may be used to describe the flow-type of an instruction or code-block but 
    should generally not be used with a :obj:`Reference`.  A corresponding :obj:`Reference`
    should generally specify :obj:`.CONDITIONAL_JUMP`.
    """

    INDIRECTION: typing.Final[FlowType]
    """
    :obj:`.INDIRECTION` corresponds to a flow :obj:`Reference` placed on a pointer data location
    that is utilized indirectly by a computed jump/branch or call instruction.
    """

    CALL_OVERRIDE_UNCONDITIONAL: typing.Final[FlowType]
    """
    :obj:`.__CALL_OVERRIDE_UNCONDITIONAL` is used with a memory :obj:`Reference` to
    override the destination of an instruction :obj:`PcodeOp.CALL` or :obj:`PcodeOp.CALLIND` 
    pcode operation. :obj:`PcodeOp.CALLIND` operations are changed to :obj:`PcodeOp.CALL` 
    operations. The new call target is the "to" address of the :obj:`Reference`. The override 
    only takes effect when the :obj:`Reference` is primary, and only when there is exactly 
    one :obj:`.__CALL_OVERRIDE_UNCONDITIONAL` :obj:`Reference` at the "from" address of 
    the reference.
    """

    JUMP_OVERRIDE_UNCONDITIONAL: typing.Final[FlowType]
    """
    :obj:`.JUMP_OVERRIDE_UNCONDITIONAL` is used with a memory :obj:`Reference` to
    override the destination of an instruction :obj:`PcodeOp.BRANCH` or :obj:`PcodeOp.CBRANCH` 
    pcode operation. :obj:`PcodeOp.CBRANCH` operations are changed to :obj:`PcodeOp.BRANCH` 
    operations. The new jump target is the "to" address of the :obj:`Reference`. The override 
    only takes effect when the :obj:`Reference` is primary, and only when there is exactly 
    one :obj:`.JUMP_OVERRIDE_UNCONDITIONAL` reference at the "from" address of 
    the reference.
    """

    CALLOTHER_OVERRIDE_CALL: typing.Final[FlowType]
    """
    :obj:`.CALLOTHER_OVERRIDE_CALL` is used to change a :obj:`PcodeOp.CALLOTHER` pcode operation 
    to a :obj:`PcodeOp.CALL` operation. The new call target is the "to" address of the 
    :obj:`Reference`. Any inputs to the original :obj:`PcodeOp.CALLOTHER` are discarded; 
    the new :obj:`PcodeOp.CALL` may have inputs assigned to it during decompilation. The 
    override only takes effect when the :obj:`Reference` is primary, and only when there is 
    exactly one :obj:`.CALLOTHER_OVERRIDE_CALL` reference at the "from" address of the 
    reference. Only the first :obj:`PcodeOp.CALLOTHER` operation at the "from" address of the 
    reference is changed. Applying this override to instances of a :obj:`PcodeOp.CALLOTHER`
    that have an output is not recommended and can adversely affect decompilation 
    (e.g., the decompiler may throw an exception). Note that this reference override takes 
    precedence over :obj:`.CALLOTHER_OVERRIDE_JUMP` references.
    """

    CALLOTHER_OVERRIDE_JUMP: typing.Final[FlowType]
    """
    :obj:`.CALLOTHER_OVERRIDE_CALL` is used to change a :obj:`PcodeOp.CALLOTHER` pcode 
    operation to a :obj:`PcodeOp.BRANCH` operation. The new jump target is the "to" address 
    of the :obj:`Reference`. The override only takes effect when the :obj:`Reference` is 
    primary, and only when there is exactly one :obj:`.CALLOTHER_OVERRIDE_CALL` reference at 
    the "from" address of the reference. Only the first :obj:`PcodeOp.CALLOTHER` operation 
    at the "from" address of the reference is changed. Applying this override to an instance 
    of a :obj:`PcodeOp.CALLOTHER` with output is not recommended 
    (see :obj:`.CALLOTHER_OVERRIDE_CALL`).
    """

    THUNK: typing.Final[RefType]
    """
    :obj:`.THUNK` type identifies the relationship between a thunk-function and its
    corresponding thunked-function which do not rely on a stored :obj:`Reference`.
    """

    DATA: typing.Final[RefType]
    """
    :obj:`.DATA` type identifies a generic reference from either an instruction,
    when the read/write data access is unknown, or from pointer data when it refers to
    data or it's unknown if it refers to code.  A pointer that is known to refer to code
    should generally have a :obj:`.INDIRECTION` type if used for by a computed 
    jump/branch or call.
    """

    PARAM: typing.Final[RefType]
    """
    :obj:`.PARAM` type is used to identify data (constant or pointer) that is passed 
    to a function.
    """

    DATA_IND: typing.Final[RefType]
    """
    :obj:`.DATA_IND` corresponds to a data :obj:`Reference` placed on a pointer data location
    that is utilized indirectly to access a data location.
    
    
    .. deprecated::
    
    use of this type is discouraged and may be eliminated in a future release.  
    The type :obj:`.DATA` should generally be used in place of this type.
    """

    READ: typing.Final[RefType]
    """
    :obj:`.READ` type identifies an instruction reference to a data location that is directly 
    read.
    """

    WRITE: typing.Final[RefType]
    """
    :obj:`.WRITE` type identifies an instruction reference to a data location that is directly 
    written.
    """

    READ_WRITE: typing.Final[RefType]
    """
    :obj:`.READ_WRITE` type identifies an instruction reference to a data location that is 
    both directly read and written.
    """

    READ_IND: typing.Final[RefType]
    """
    :obj:`.READ_IND` type identifies an instruction reference to a data location that is 
    indirectly read using a stored pointer or computed value.
    """

    WRITE_IND: typing.Final[RefType]
    """
    :obj:`.WRITE_IND` type identifies an instruction reference to a data location that is 
    indirectly written using a stored pointer or computed value.
    """

    READ_WRITE_IND: typing.Final[RefType]
    """
    :obj:`.READ_WRITE_IND` type identifies an instruction reference to a data location that is 
    both indirectly read and written using a stored pointer or computed value.
    """

    EXTERNAL_REF: typing.Final[RefType]
    """
    :obj:`.EXTERNAL_REF` type is used internally to identify external entry point locations
    using a from address of :obj:`Address.NO_ADDRESS`.
     
    
    NOTE: The use of this type for references to external library data or functions
    is deprecated and should not be used for that purpose.
    """


    def getDisplayString(self) -> str:
        """
        Returns an easy to read display string for this ref type.
        
        :return: the string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns name of ref-type
        
        :return: the name
        :rtype: str
        """

    def getValue(self) -> int:
        """
        Get the int value for this RefType object
        
        :return: the value
        :rtype: int
        """

    def hasFallthrough(self) -> bool:
        """
        Returns true if this flow type can fall through
        
        :return: true if can fall through
        :rtype: bool
        """

    def isCall(self) -> bool:
        """
        Returns true if the flow is call
        
        :return: true if is a call
        :rtype: bool
        """

    def isComputed(self) -> bool:
        """
        Returns true if the flow is a computed call or compute jump
        
        :return: true if is computed
        :rtype: bool
        """

    def isConditional(self) -> bool:
        """
        Returns true if the flow is a conditional call or jump
        
        :return: true if is conditional
        :rtype: bool
        """

    def isData(self) -> bool:
        """
        Returns true if the reference is to data
        
        :return: true if the reference is to data
        :rtype: bool
        """

    def isFallthrough(self) -> bool:
        """
        Return true if this flow type is one that does not cause a break in control flow
        
        :return: if this flow type is one that does not cause a break in control flow
        :rtype: bool
        """

    def isFlow(self) -> bool:
        """
        Returns true if the reference is an instruction flow reference
        
        :return: true if the reference is an instruction flow reference
        :rtype: bool
        """

    def isIndirect(self) -> bool:
        """
        Returns true if the reference is indirect
        
        :return: true if the reference is indirect
        :rtype: bool
        """

    def isJump(self) -> bool:
        """
        Returns true if the flow is jump
        
        :return: true if is a jump
        :rtype: bool
        """

    def isOverride(self) -> bool:
        """
        True if this is an override reference
        
        :return: true if this is an override reference
        :rtype: bool
        """

    def isRead(self) -> bool:
        """
        Returns true if the reference is a read
        
        :return: true if the reference is a read
        :rtype: bool
        """

    def isTerminal(self) -> bool:
        """
        Returns true if this instruction terminates
        
        :return: true if terminal
        :rtype: bool
        """

    def isUnConditional(self) -> bool:
        """
        Returns true if the flow is an unconditional call or jump
        
        :return: true if unconditional
        :rtype: bool
        """

    def isWrite(self) -> bool:
        """
        Returns true if the reference is a write
        
        :return: true if the reference is a write
        :rtype: bool
        """

    @property
    def read(self) -> jpype.JBoolean:
        ...

    @property
    def indirect(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> jpype.JBoolean:
        ...

    @property
    def conditional(self) -> jpype.JBoolean:
        ...

    @property
    def computed(self) -> jpype.JBoolean:
        ...

    @property
    def terminal(self) -> jpype.JBoolean:
        ...

    @property
    def unConditional(self) -> jpype.JBoolean:
        ...

    @property
    def call(self) -> jpype.JBoolean:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def override(self) -> jpype.JBoolean:
        ...

    @property
    def fallthrough(self) -> jpype.JBoolean:
        ...

    @property
    def write(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JByte:
        ...

    @property
    def flow(self) -> jpype.JBoolean:
        ...

    @property
    def jump(self) -> jpype.JBoolean:
        ...


class SymbolTableListener(java.lang.Object):
    """
    Listener methods that are called when changes to symbols are made.
    """

    class_: typing.ClassVar[java.lang.Class]

    def associationAdded(self, symbol: SourceType, ref: Reference):
        """
        Notification that the association between a reference and a 
        specific symbol has changed.
        
        :param SourceType symbol: affected symbol
        :param Reference ref: affected reference
        """

    def associationRemoved(self, ref: Reference):
        """
        Notification that the association between the given reference and
        any symbol was removed.
        
        :param Reference ref: the reference that had a symbol association removed.
        """

    def externalEntryPointAdded(self, addr: ghidra.program.model.address.Address):
        """
        Notification that an external entry point was added at the
        given address.
        
        :param ghidra.program.model.address.Address addr: the address that made an external entry point.
        """

    def externalEntryPointRemoved(self, addr: ghidra.program.model.address.Address):
        """
        Notification that an external entry point was removed from the given
        address.
        
        :param ghidra.program.model.address.Address addr: the address the removed as an external entry point.
        """

    def primarySymbolSet(self, symbol: SourceType):
        """
        Notification that the given symbol was set as the primary symbol.
        
        :param SourceType symbol: the symbol that is now primary.
        """

    def symbolAdded(self, symbol: SourceType):
        """
        Notification that the given symbol has been added.
        
        :param SourceType symbol: the symbol that was added.
        """

    def symbolRemoved(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], isLocal: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that a symbol was removed.
        
        :param ghidra.program.model.address.Address addr: address where the symbol was
        :param java.lang.String or str name: name of symbol
        :param jpype.JBoolean or bool isLocal: true if the symbol was in the scope
        of a function
        """

    def symbolRenamed(self, symbol: SourceType, oldName: typing.Union[java.lang.String, str]):
        """
        Notification that the given symbol was renamed.
        
        :param SourceType symbol: symbol that was renamed
        :param java.lang.String or str oldName: old name of the symbol
        """

    def symbolScopeChanged(self, symbol: SourceType):
        """
        Notification that the scope on a symbol changed.
        
        :param SourceType symbol: the symbol whose scope has changed.
        """


class SymbolUtilities(java.lang.Object):
    """
    Class with static methods to deal with symbol strings.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_SYMBOL_NAME_LENGTH: typing.Final = 2000
    UNK_LEVEL: typing.Final = 0
    DAT_LEVEL: typing.Final = 1
    LAB_LEVEL: typing.Final = 2
    SUB_LEVEL: typing.Final = 3
    EXT_LEVEL: typing.Final = 5
    FUN_LEVEL: typing.Final = 6
    ORDINAL_PREFIX: typing.Final = "Ordinal_"
    """
    The standard prefix for denoting the ordinal
    values of a symbol.
    """

    INVALIDCHARS: typing.Final[jpype.JArray[jpype.JChar]]
    """
    Invalid characters for a symbol name.
    """


    def __init__(self):
        ...

    @staticmethod
    def containsInvalidChars(str: typing.Union[java.lang.String, str]) -> bool:
        """
        Check for invalid characters
        (space or unprintable ascii below 0x20)
        in labels.
        
        :param java.lang.String or str str: the string to be checked for invalid characters.
        :return: boolean true if no invalid chars
        :rtype: bool
        """

    @staticmethod
    def createPreferredLabelOrFunctionSymbol(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, namespace: Namespace, name: typing.Union[java.lang.String, str], source: SourceType) -> Symbol:
        """
        Create label symbol giving preference to non-global symbols.  An existing function symbol
        may be returned.  If attempting to create a global symbol and the name already exists 
        at the address no symbol will be created and null will be returned.  
        If attempting to create a non-global symbol, which does not exist,
        and a global symbol does exist with same name its namespace will be changed.
        
        :param ghidra.program.model.listing.Program program: program within which the symbol should be created
        :param ghidra.program.model.address.Address address: memory address where symbol should be created
        :param Namespace namespace: symbol namespace or null for global
        :param java.lang.String or str name: symbol name
        :param SourceType source: symbol source type
        :return: new or existing label or function symbol or null if creating a global symbol
        whose name already exists at address
        :rtype: Symbol
        :raises InvalidInputException: if invalid symbol name provided
        """

    @staticmethod
    def getAddressAppendedName(name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> str:
        """
        Creates the standard symbol name for symbols that have the addresses appended to the 
        name following an "@" character in order to make it unique.
        
        :param java.lang.String or str name: the "true" name of the symbol
        :param ghidra.program.model.address.Address address: the address to be appended
        :return: the name with the address appended.
        :rtype: str
        """

    @staticmethod
    def getAddressString(addr: ghidra.program.model.address.Address) -> str:
        ...

    @staticmethod
    @typing.overload
    def getCleanSymbolName(symbol: Symbol) -> str:
        """
        Gets the base symbol name regardless of whether or not the address has been appended.
        
        :param Symbol symbol: the symbol to get the clean name for.
        :return: the base symbol name where the "@<address>" has been stripped away if it exists.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getCleanSymbolName(symbolName: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> str:
        """
        Gets the base symbol name regardless of whether or not the address has been appended 
        using either the standard "@" separator, or the less preferred "_" separator.  The
        address string extension must match that which is produced by the 
        :meth:`getAddressString(Address) <.getAddressString>` method for it to be recognized.
        
        :param java.lang.String or str symbolName: a symbol name to get the clean name for.
        :param ghidra.program.model.address.Address address: the symbol's address
        :return: the base symbol name where the "@<address>" has been stripped away if it exists.
        :rtype: str
        """

    @staticmethod
    def getDefaultExternalFunctionName(addr: ghidra.program.model.address.Address) -> str:
        """
        Generates a default external name for an external function
        
        :param ghidra.program.model.address.Address addr: the memory address referred to by the external.
        :return: the default generated name for the external.
        :rtype: str
        """

    @staticmethod
    def getDefaultExternalName(addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType) -> str:
        """
        Generates a default external name for a given external data/code location.
        
        :param ghidra.program.model.address.Address addr: the memory address referred to by the external.
        :param ghidra.program.model.data.DataType dt: data type associated with the specified external memory address
        :return: the default generated name for the external.
        :rtype: str
        """

    @staticmethod
    def getDefaultFunctionName(addr: ghidra.program.model.address.Address) -> str:
        """
        Generates a default function name for a given address.
        
        :param ghidra.program.model.address.Address addr: the entry point of the function.
        :return: the default generated name for the function.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getDefaultLocalName(program: ghidra.program.model.listing.Program, stackOffset: typing.Union[jpype.JInt, int], firstUseOffset: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getDefaultLocalName(program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, firstUseOffset: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def getDefaultParamName(ordinal: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getDynamicName(referenceLevel: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> str:
        """
        Create a name for a dynamic symbol with a 3-letter prefix based upon reference level
        and an address.  Acceptable referenceLevel's are: 
        :obj:`.UNK_LEVEL`, :obj:`.DAT_LEVEL`, :obj:`.LAB_LEVEL`, :obj:`.SUB_LEVEL`, 
        :obj:`.EXT_LEVEL`, :obj:`.FUN_LEVEL`.
        
        :param jpype.JInt or int referenceLevel: the type of reference for which to create a dynamic name.
        :param ghidra.program.model.address.Address addr: the address at which to create a dynamic name.
        :return: dynamic symbol name
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getDynamicName(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> str:
        """
        Create a name for a dynamic symbol.
        
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.program.model.address.Address addr: the address of the symbol for which to generate a name
        :return: a name for the symbol at the given address
        :rtype: str
        """

    @staticmethod
    def getDynamicOffcutName(addr: ghidra.program.model.address.Address) -> str:
        """
        Create a dynamic label name for an offcut reference.
        
        :param ghidra.program.model.address.Address addr: the address at which to create an offcut reference name.
        :return: dynamic offcut label name
        :rtype: str
        """

    @staticmethod
    def getExpectedLabelOrFunctionSymbol(program: ghidra.program.model.listing.Program, symbolName: typing.Union[java.lang.String, str], errorConsumer: java.util.function.Consumer[java.lang.String]) -> Symbol:
        """
        Returns the unique global label or function symbol with the given name. Also, logs if there
        is not exactly one symbol with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str symbolName: the name of the global label or function symbol to search.
        :param java.util.function.Consumer[java.lang.String] errorConsumer: the object to use for reporting errors via it's accept() method.
        :return: symbol if a unique label/function symbol with name is found or null
        :rtype: Symbol
        """

    @staticmethod
    def getLabelOrFunctionSymbol(program: ghidra.program.model.listing.Program, symbolName: typing.Union[java.lang.String, str], errorConsumer: java.util.function.Consumer[java.lang.String]) -> Symbol:
        """
        Returns the unique global label or function symbol with the given name. Also, logs if there
        is more than one symbol with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str symbolName: the name of the global label or function symbol to search.
        :param java.util.function.Consumer[java.lang.String] errorConsumer: the object to use for reporting errors via it's accept() method.
        :return: symbol if a unique label/function symbol with name is found or null
        :rtype: Symbol
        """

    @staticmethod
    def getOrdinalValue(symbolName: typing.Union[java.lang.String, str]) -> int:
        ...

    @staticmethod
    def getSymbolNameComparator() -> java.util.Comparator[Symbol]:
        """
        Returns a comparator for symbols.  The comparison is based upon the name.  This call
        replaces the former ``compareTo`` method on Symbol.  This comparator returned here
        is case-insensitive.
        
        :return: the comparator
        :rtype: java.util.Comparator[Symbol]
        """

    @staticmethod
    def getSymbolTypeDisplayName(symbol: Symbol) -> str:
        """
        Returns display text suitable for describing in the GUI the :obj:`SymbolType` of the
        given symbol
        
        :param Symbol symbol: The symbol from which to get the SymbolType
        :return: a display string for the SymbolType
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getUniqueSymbol(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str]) -> Symbol:
        """
        Returns the global symbol with the given name if and only if it is the only global symbol
        with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str name: the name of the global symbol to find.
        :return: the global symbol with the given name if and only if it is the only one.
        :rtype: Symbol
        """

    @staticmethod
    @typing.overload
    def getUniqueSymbol(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Symbol:
        """
        Returns the symbol in the given namespace with the given name if and only if it is the only
        symbol in that namespace with that name.
        
        :param ghidra.program.model.listing.Program program: the program to search.
        :param java.lang.String or str name: the name of the symbol to find.
        :param Namespace namespace: the parent namespace; may be null
        :return: the symbol with the given name if and only if it is the only one in that namespace
        :rtype: Symbol
        """

    @staticmethod
    def isDefaultLocalName(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], storage: ghidra.program.model.listing.VariableStorage) -> bool:
        ...

    @staticmethod
    def isDefaultLocalStackName(name: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def isDefaultParameterName(name: typing.Union[java.lang.String, str]) -> bool:
        ...

    @staticmethod
    def isDynamicSymbolPattern(name: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Tests if the given name is a possible dynamic symbol name.
        WARNING! This method should be used carefully since it will return true for
        any name which starts with a known dynamic label prefix or ends with an '_' 
        followed by a valid hex value.
        
        :param java.lang.String or str name: the name to test
        :param jpype.JBoolean or bool caseSensitive: true if case matters.
        :return: true if name is a possible dynamic symbol name, else false
        :rtype: bool
        """

    @staticmethod
    def isInvalidChar(c: typing.Union[jpype.JChar, int, str]) -> bool:
        """
        Returns true if the specified char
        is not valid for use in a symbol name
        
        :param jpype.JChar or int or str c: the character to be tested as a valid symbol character.
        :return: return true if c is an invalid char within a symbol name, else false
        :rtype: bool
        """

    @staticmethod
    def isPossibleDefaultExternalName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Checks if the given name could be a default external location name
        
        :param java.lang.String or str name: the name to check
        :return: true if the given name is a possible default external location name
        :rtype: bool
        """

    @staticmethod
    def isPossibleDefaultLocalOrParamName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given name is a possible default parameter name or local variable name
        
        :param java.lang.String or str name: the name to check to see if it is a possible default local or parameter name
        :return: true if the given name is a possible default parameter name or local variable name
        :rtype: bool
        """

    @staticmethod
    def isReservedDynamicLabelName(name: typing.Union[java.lang.String, str], addrFactory: ghidra.program.model.address.AddressFactory) -> bool:
        """
        Returns true if the given name could match a default dynamic label (EXT, LAB, SUB, FUN, DAT)
        at some address.
        WARNING! Does not handle dynamic labels which use data-type prefixes -
        see :meth:`isDynamicSymbolPattern(String, boolean) <.isDynamicSymbolPattern>` for more liberal check
        """

    @staticmethod
    def isReservedExternalDefaultName(name: typing.Union[java.lang.String, str], addrFactory: ghidra.program.model.address.AddressFactory) -> bool:
        """
        Returns true if the specified name is reserved as a default external name.
        
        :param java.lang.String or str name: 
        :param ghidra.program.model.address.AddressFactory addrFactory: 
        :return: true if the specified name is reserved as a default external name.
        :rtype: bool
        """

    @staticmethod
    def parseDynamicName(factory: ghidra.program.model.address.AddressFactory, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Parse a dynamic name and return its address or null if unable to parse.
        
        :param ghidra.program.model.address.AddressFactory factory: address factory
        :param java.lang.String or str name: the dynamic label name to parse into an address.
        :return: address corresponding to symbol name if it satisfies possible dynamic naming
        or null if unable to parse address fro name
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def replaceInvalidChars(str: typing.Union[java.lang.String, str], replaceWithUnderscore: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Removes from the given string any invalid characters or replaces
        them with underscores.
        
        For example:
        given "a:b*c", the return value would be "a_b_c"
        
        :param java.lang.String or str str: the string to have invalid chars converted to underscores or removed.
        :param jpype.JBoolean or bool replaceWithUnderscore: - true means replace the invalid
        chars with underscore. if false, then just drop the invalid chars
        :return: modified string
        :rtype: str
        """

    @staticmethod
    def startsWithDefaultDynamicPrefix(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given name starts with a possible default symbol prefix.
        
        :param java.lang.String or str name: the name string to test.
        :return: true if name starts with a know dynamic prefix
        :rtype: bool
        """

    @staticmethod
    def validateName(name: typing.Union[java.lang.String, str]):
        """
        Validate the given symbol name: cannot be null, cannot be an empty string, cannot contain blank
        characters, cannot be a reserved name.
        
        :param java.lang.String or str name: symbol name to be validated
        :raises InvalidInputException: invalid or reserved name has been specified
        """


class ExternalPath(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, *strings: typing.Union[java.lang.String, str]):
        ...

    def getLibraryName(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getPathElements(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def libraryName(self) -> java.lang.String:
        ...

    @property
    def pathElements(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class NameTransformer(java.lang.Object):
    """
    Interface to transform (shorten, simplify) names of data-types, functions, and name spaces
    for display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def simplify(self, input: typing.Union[java.lang.String, str]) -> str:
        """
        Return a transformed version of the given input.  If no change is made, the original
        String object is returned.
        
        :param java.lang.String or str input: is the name to transform
        :return: the transformed version
        :rtype: str
        """


class ReferenceManager(java.lang.Object):
    """
    Interface for managing references.
    """

    class_: typing.ClassVar[java.lang.Class]
    MNEMONIC: typing.Final = -1
    """
    Operand index which corresponds to the instruction/data mnemonic.
    """


    @typing.overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, libraryName: typing.Union[java.lang.String, str], extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, source: SourceType, opIndex: typing.Union[jpype.JInt, int], type: RefType) -> Reference:
        """
        Adds an external reference to an external symbol.  If a reference already
        exists at ``fromAddr`` and ``opIndex`` the existing reference is replaced
        with a new reference.  If the external symbol cannot be found, a new :obj:`Library` 
        and/or :obj:`ExternalLocation` symbol will be created which corresponds to the specified
        library/file named ``libraryName``
        and the location within that file identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param ghidra.program.model.address.Address fromAddr: from memory address (source of the reference)
        :param java.lang.String or str libraryName: name of external program
        :param java.lang.String or str extLabel: label within the external program, may be null if extAddr is not null
        :param ghidra.program.model.address.Address extAddr: memory address within the external program, may be null
        :param SourceType source: the source of this reference
        :param jpype.JInt or int opIndex: operand index
        :param RefType type: reference type - how the location is being referenced
        :return: new external space reference
        :rtype: Reference
        :raises InvalidInputException: if ``libraryName`` is invalid or null, or an invalid 
        ``extlabel`` is specified.  Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, extNamespace: Namespace, extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, source: SourceType, opIndex: typing.Union[jpype.JInt, int], type: RefType) -> Reference:
        """
        Adds an external reference.  If a reference already
        exists for the fromAddr and opIndex, the existing reference is replaced
        with the new reference.
        
        :param ghidra.program.model.address.Address fromAddr: from memory address (source of the reference)
        :param Namespace extNamespace: external namespace containing the named external label.
        :param java.lang.String or str extLabel: label within the external program, may be null if extAddr is not null
        :param ghidra.program.model.address.Address extAddr: address within the external program, may be null
        :param SourceType source: the source of this reference
        :param jpype.JInt or int opIndex: operand index
        :param RefType type: reference type - how the location is being referenced
        :return: new external space reference
        :rtype: Reference
        :raises InvalidInputException: if an invalid ``extlabel`` is specified.  
        Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], location: ExternalLocation, source: SourceType, type: RefType) -> Reference:
        """
        Adds an external reference.  If a reference already
        exists for the fromAddr and opIndex, the existing reference is replaced
        with the new reference.
        
        :param ghidra.program.model.address.Address fromAddr: from memory address (source of the reference)
        :param jpype.JInt or int opIndex: operand index
        :param ExternalLocation location: external location
        :param SourceType source: the source of this reference
        :param RefType type: reference type - how the location is being referenced
        :return: external reference
        :rtype: Reference
        :raises InvalidInputException:
        """

    def addMemoryReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, type: RefType, source: SourceType, opIndex: typing.Union[jpype.JInt, int]) -> Reference:
        """
        Adds a memory reference.  The first memory reference placed on
        an operand will be made primary by default.  All non-memory references 
        will be removed from the specified operand.  Certain reference :obj:`types <RefType>`
        may not be specified (e.g., :obj:`RefType.FALL_THROUGH`).
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.  
        Memory, stack, and register addresses are all permitted.
        :param RefType type: reference type - how the location is being referenced.
        :param SourceType source: the source of this reference
        :param jpype.JInt or int opIndex: the operand index 
        display of the operand making this reference
        :return: new memory reference
        :rtype: Reference
        :raises IllegalArgumentException: if unsupported :obj:`type <RefType>` is specified
        """

    def addOffsetMemReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, toAddrIsBase: typing.Union[jpype.JBoolean, bool], offset: typing.Union[jpype.JLong, int], type: RefType, source: SourceType, opIndex: typing.Union[jpype.JInt, int]) -> Reference:
        """
        Add an offset memory reference.  The first memory reference placed on
        an operand will be made primary by default.  All non-memory references 
        will be removed from the specified operand.  If toAddr corresponds to
        the EXTERNAL memory block (see :obj:`MemoryBlock.EXTERNAL_BLOCK_NAME`) the
        resulting offset reference will report to/base address as the same
        regardless of specified offset.
        
        :param ghidra.program.model.address.Address fromAddr: address for the "from"
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.
        :param jpype.JBoolean or bool toAddrIsBase: if true toAddr is treated as base address, else treated as (base+offet).
        It is generally preferred to specify as a base address to ensure proper handling of
        EXTERNAL block case.
        :param jpype.JLong or int offset: value added to a base address to get the toAddr
        :param RefType type: reference type - how the location is being referenced
        :param SourceType source: the source of this reference
        :param jpype.JInt or int opIndex: the operand index
        :return: new offset reference
        :rtype: Reference
        """

    def addReference(self, reference: Reference) -> Reference:
        """
        Add a memory, stack, register or external reference
        
        :param Reference reference: reference to be added
        :return: new reference
        :rtype: Reference
        """

    def addRegisterReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], register: ghidra.program.model.lang.Register, type: RefType, source: SourceType) -> Reference:
        """
        Add a reference to a register. If a reference already
        exists for the fromAddr and opIndex, the existing reference is replaced
        with the new reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address
        :param jpype.JInt or int opIndex: operand index
        :param ghidra.program.model.lang.Register register: register to add the reference to
        :param RefType type: reference type - how the location is being referenced.
        :param SourceType source: the source of this reference
        :return: new register reference
        :rtype: Reference
        """

    def addShiftedMemReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, shiftValue: typing.Union[jpype.JInt, int], type: RefType, source: SourceType, opIndex: typing.Union[jpype.JInt, int]) -> Reference:
        """
        Add a shifted memory reference; the "to" address is computed as the value
        at the operand at opIndex shifted by some number of bits, specified in the 
        shiftValue parameter.  The first memory reference placed on
        an operand will be made primary by default.  All non-memory references 
        will be removed from the specified operand.
        
        :param ghidra.program.model.address.Address fromAddr: source/from memory address
        :param ghidra.program.model.address.Address toAddr: destination/to memory address computed as some 
        :meth:`base offset value <ShiftedReference.getValue>` shifted left
        by the number of bits specified by shiftValue.  The least-significant bits of toAddr
        offset should be 0's based upon the specified shiftValue since this value is shifted
        right to calculate the base offset value.
        :param jpype.JInt or int shiftValue: number of bits to shift
        :param RefType type: reference type - how the location is being referenced
        :param SourceType source: the source of this reference
        :param jpype.JInt or int opIndex: the operand index
        :return: new shifted reference
        :rtype: Reference
        """

    def addStackReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], type: RefType, source: SourceType) -> Reference:
        """
        Add a reference to a stack location. If a reference already
        exists for the fromAddr and opIndex, the existing reference is replaced
        with the new reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address within a function
        :param jpype.JInt or int opIndex: operand index
        :param jpype.JInt or int stackOffset: stack offset of the reference
        :param RefType type: reference type - how the location is being referenced.
        :param SourceType source: the source of this reference
        :return: new stack reference
        :rtype: Reference
        """

    def delete(self, ref: Reference):
        """
        Deletes the given reference object
        
        :param Reference ref: the reference to be deleted.
        """

    def getExternalReferences(self) -> ReferenceIterator:
        """
        Returns an iterator over all external space references
        
        :return: reference iterator over all external space references
        :rtype: ReferenceIterator
        """

    def getFlowReferencesFrom(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Reference]:
        """
        Get all flow references from the given address.
        
        :param ghidra.program.model.address.Address addr: the address of the codeunit to get all flows from.
        :return: get all flow references from the given address.
        :rtype: jpype.JArray[Reference]
        """

    def getPrimaryReferenceFrom(self, addr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]) -> Reference:
        """
        Get the primary reference from the given address.
        
        :param ghidra.program.model.address.Address addr: from address
        :param jpype.JInt or int opIndex: operand index
        :return: the primary reference from the specified address
        and opindex if it exists, else null
        :rtype: Reference
        """

    def getReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]) -> Reference:
        """
        Get the reference that has the given from and to address, and
        operand index.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        :param ghidra.program.model.address.Address toAddr: the address being referred to.
        :param jpype.JInt or int opIndex: the operand index.
        :return: reference which satisfies the specified criteria or null
        :rtype: Reference
        """

    def getReferenceCountFrom(self, fromAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the number of references from the specified ``fromAddr``.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        :return: the number of references from the specified ``fromAddr``.
        :rtype: int
        """

    def getReferenceCountTo(self, toAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the number of references to the specified ``toAddr``.
        
        :param ghidra.program.model.address.Address toAddr: the address being referenced
        :return: the number of references to the specified ``toAddr``.
        :rtype: int
        """

    def getReferenceDestinationCount(self) -> int:
        """
        Return the number of references for "to" addresses.
        """

    @typing.overload
    def getReferenceDestinationIterator(self, startAddr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "To" address in a
        reference.
        
        :param ghidra.program.model.address.Address startAddr: start of iterator
        :param jpype.JBoolean or bool forward: true means to iterate in the forward direction
        address iterator where references to exist
        :return: address iterator where references to exist
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getReferenceDestinationIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "To" address in a
        memory reference, restricted by the given address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the set of address to restrict the iterator or null for all addresses.
        :param jpype.JBoolean or bool forward: true means to iterate in the forward direction
        :return: address iterator where references to exist constrained by addrSet
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getReferenceIterator(self, startAddr: ghidra.program.model.address.Address) -> ReferenceIterator:
        """
        Get an iterator over references starting with the specified 
        fromAddr.  A forward iterator is returned with references sorted on
        the from address.
        
        :param ghidra.program.model.address.Address startAddr: the first from address to consider.
        :return: a forward memory reference iterator.
        :rtype: ReferenceIterator
        """

    def getReferenceLevel(self, toAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the reference level for the references to the given address
        
        :param ghidra.program.model.address.Address toAddr: the address at which to find the highest reference level
        :return: reference level for specified to address.
        :rtype: int
        """

    def getReferenceSourceCount(self) -> int:
        """
        Return the number of references for "from" addresses.
        """

    @typing.overload
    def getReferenceSourceIterator(self, startAddr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over addresses that are the "From" address in a
        reference
        
        :param ghidra.program.model.address.Address startAddr: address to position iterator.
        :param jpype.JBoolean or bool forward: true means to iterate in the forward direction
        :return: address iterator where references from exist
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getReferenceSourceIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "From" address in a
        reference, restricted by the given address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the set of address to restrict the iterator or null for all addresses.
        :param jpype.JBoolean or bool forward: true means to iterate in the forward direction
        address iterator where references from exist
        :return: address iterator where references from exist constrained by addrSet
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getReferencedVariable(self, reference: Reference) -> ghidra.program.model.listing.Variable:
        """
        Returns the referenced function variable.
        
        :param Reference reference: variable reference
        :return: function variable or null if variable not found
        :rtype: ghidra.program.model.listing.Variable
        """

    @typing.overload
    def getReferencesFrom(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Reference]:
        """
        Get all references "from" the specified addr.
        
        :param ghidra.program.model.address.Address addr: address of code-unit making the references.
        :return: array of all references "from" the specified addr.
        :rtype: jpype.JArray[Reference]
        """

    @typing.overload
    def getReferencesFrom(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[Reference]:
        """
        Returns all references "from" the given fromAddr and operand (specified by opIndex).
        
        :param ghidra.program.model.address.Address fromAddr: the from which to get references
        :param jpype.JInt or int opIndex: the operand from which to get references
        :return: all references "from" the given fromAddr and operand.
        :rtype: jpype.JArray[Reference]
        """

    @typing.overload
    def getReferencesTo(self, var: ghidra.program.model.listing.Variable) -> jpype.JArray[Reference]:
        """
        Returns all references to the given variable.  Only data references to storage 
        are considered.
        
        :param ghidra.program.model.listing.Variable var: variable to retrieve references to
        :return: array of variable references, or zero length array if no
        references exist
        :rtype: jpype.JArray[Reference]
        """

    @typing.overload
    def getReferencesTo(self, addr: ghidra.program.model.address.Address) -> ReferenceIterator:
        """
        Get an iterator over all references that have the given address as
        their "To" address.
        
        :param ghidra.program.model.address.Address addr: the address that all references in the iterator refer to.
        :return: reference iterator over all references to the specified address.
        :rtype: ReferenceIterator
        """

    def hasFlowReferencesFrom(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Return whether the given address has flow references from it.
        
        :param ghidra.program.model.address.Address addr: the address to test for flow references.
        :return: true if the given address has flow references from it, else false
        :rtype: bool
        """

    @typing.overload
    def hasReferencesFrom(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if there are any memory references at the given
        address/opIndex.  Keep in mind this is a rather inefficient 
        method as it must examine all references from the specified 
        fromAddr.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit being tested
        :param jpype.JInt or int opIndex: the index of the operand being tested.
        :return: true if one or more reference from the specified address
        and opindex are defined, else false
        :rtype: bool
        """

    @typing.overload
    def hasReferencesFrom(self, fromAddr: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if there are any memory references at the given
        address.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit being tested
        :return: true if one or more reference from the specified address
        are defined, else false
        :rtype: bool
        """

    def hasReferencesTo(self, toAddr: ghidra.program.model.address.Address) -> bool:
        """
        Return true if a memory reference exists with the given "to" address.
        
        :param ghidra.program.model.address.Address toAddr: address being referred to.
        :return: true if specified toAddr has one or more references to it, else false.
        :rtype: bool
        """

    @typing.overload
    def removeAllReferencesFrom(self, beginAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        """
        Removes all references where "From address" is in the given range.
        
        :param ghidra.program.model.address.Address beginAddr: the first address in the range.
        :param ghidra.program.model.address.Address endAddr: the last address in the range.
        """

    @typing.overload
    def removeAllReferencesFrom(self, fromAddr: ghidra.program.model.address.Address):
        """
        Remove all stack, external, and memory references for the given
        from address.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit from which to remove all references.
        """

    def removeAllReferencesTo(self, toAddr: ghidra.program.model.address.Address):
        """
        Remove all stack, external, and memory references for the given
        to address.
        
        :param ghidra.program.model.address.Address toAddr: the address for which all references to should be removed.
        """

    def removeAssociation(self, ref: Reference):
        """
        Removes any symbol associations with the given reference.
        
        :param Reference ref: the reference for which any symbol association is to be removed.
        :raises IllegalArgumentException: if the given references does not exist.
        """

    def setAssociation(self, s: Symbol, ref: Reference):
        """
        Associates the given reference with the given symbol.
        Applies to memory references only where a specified label symbol must have 
        an address which matches the reference to-address.  Stack and register 
        reference associations to variable symbols are always inferred.
        
        :param Symbol s: the symbol to associate with the given reference.
        :param Reference ref: the reference to associate with the given symbol
        :raises IllegalArgumentException: If the given reference does not already
        exist or its "To" address
        is not the same as the symbol's address.
        """

    def setPrimary(self, ref: Reference, isPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Set the given reference's primary attribute
        
        :param Reference ref: the reference to make primary.
        :param jpype.JBoolean or bool isPrimary: true to make the reference primary, false to make it non-primary
        """

    def updateRefType(self, ref: Reference, refType: RefType) -> Reference:
        """
        Uodate the reference type on a memory reference.
        
        :param Reference ref: reference to be updated
        :param RefType refType: new reference type
        :return: updated reference
        :rtype: Reference
        """

    @property
    def externalReferences(self) -> ReferenceIterator:
        ...

    @property
    def referenceCountFrom(self) -> jpype.JInt:
        ...

    @property
    def flowReferencesFrom(self) -> jpype.JArray[Reference]:
        ...

    @property
    def referenceIterator(self) -> ReferenceIterator:
        ...

    @property
    def referencesFrom(self) -> jpype.JArray[Reference]:
        ...

    @property
    def referenceLevel(self) -> jpype.JByte:
        ...

    @property
    def referenceCountTo(self) -> jpype.JInt:
        ...

    @property
    def referenceSourceCount(self) -> jpype.JInt:
        ...

    @property
    def referenceDestinationCount(self) -> jpype.JInt:
        ...

    @property
    def referencesTo(self) -> jpype.JArray[Reference]:
        ...

    @property
    def referencedVariable(self) -> ghidra.program.model.listing.Variable:
        ...


class IdentityNameTransformer(NameTransformer):
    """
    A transformer that never alters its input
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ExternalManager(java.lang.Object):
    """
    External manager interface. Defines methods for dealing with external programs and locations
    within those programs.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addExtFunction(self, libraryName: typing.Union[java.lang.String, str], extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType) -> ExternalLocation:
        """
        Create an external :obj:`Function` in the external :obj:`Library` namespace 
        ``libararyName`` and identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param java.lang.String or str libraryName: the external library name
        :param java.lang.String or str extLabel: label within the external program, may be null if extAddr is not null
        :param ghidra.program.model.address.Address extAddr: memory address within the external program, may be null
        :param SourceType sourceType: the source type of this external library's symbol
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if ``libraryName`` is invalid or null, or an invalid 
        ``extlabel`` is specified.  Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExtFunction(self, extNamespace: Namespace, extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType) -> ExternalLocation:
        """
        Create an external :obj:`Function` in the indicated external parent namespace 
        and identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param Namespace extNamespace: the external namespace
        :param java.lang.String or str extLabel: the external label or null
        :param ghidra.program.model.address.Address extAddr: the external memory address or null
        :param SourceType sourceType: the source type of this external library's symbol
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if an invalid ``extlabel`` is specified.  
        Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExtFunction(self, extNamespace: Namespace, extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType, reuseExisting: typing.Union[jpype.JBoolean, bool]) -> ExternalLocation:
        """
        Get or create an external :obj:`Function` in the indicated external parent namespace 
        and identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param Namespace extNamespace: the external namespace
        :param java.lang.String or str extLabel: the external label or null
        :param ghidra.program.model.address.Address extAddr: the external memory address or null
        :param SourceType sourceType: the source type of this external library's symbol
        :param jpype.JBoolean or bool reuseExisting: if true, will return any existing matching location instead of
        creating a new one. If false, will prefer to create a new one as long as the specified
        address is not null and not used in an existing location.
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if an invalid ``extlabel`` is specified.  
        Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExtLocation(self, libraryName: typing.Union[java.lang.String, str], extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType) -> ExternalLocation:
        """
        Get or create an external location associated with a library/file named ``libraryName``
        and the location within that file identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param java.lang.String or str libraryName: the external library name
        :param java.lang.String or str extLabel: the external label or null
        :param ghidra.program.model.address.Address extAddr: the external memory address or null
        :param SourceType sourceType: the source type of this external library's symbol
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if ``libraryName`` is invalid or null, or an invalid 
        ``extlabel`` is specified.  Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExtLocation(self, extNamespace: Namespace, extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType) -> ExternalLocation:
        """
        Create an external location in the indicated external parent namespace 
        and identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param Namespace extNamespace: the external namespace
        :param java.lang.String or str extLabel: the external label or null
        :param ghidra.program.model.address.Address extAddr: the external memory address or null
        :param SourceType sourceType: the source type of this external library's symbol
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if an invalid ``extlabel`` is specified.  
        Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    @typing.overload
    def addExtLocation(self, extNamespace: Namespace, extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, sourceType: SourceType, reuseExisting: typing.Union[jpype.JBoolean, bool]) -> ExternalLocation:
        """
        Get or create an external location in the indicated external parent namespace 
        and identified by ``extLabel`` and/or its memory address
        ``extAddr``.  Either or both ``extLabel`` or ``extAddr`` must be specified.
        
        :param Namespace extNamespace: the external namespace
        :param java.lang.String or str extLabel: the external label or null
        :param ghidra.program.model.address.Address extAddr: the external memory address or null
        :param SourceType sourceType: the source type of this external library's symbol
        :param jpype.JBoolean or bool reuseExisting: if true, this will return an existing matching external
        location instead of creating a new one.
        :return: external location
        :rtype: ExternalLocation
        :raises InvalidInputException: if an invalid ``extlabel`` is specified.  
        Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises IllegalArgumentException: if an invalid ``extAddr`` was specified.
        """

    def addExternalLibraryName(self, libraryName: typing.Union[java.lang.String, str], source: SourceType) -> ghidra.program.model.listing.Library:
        """
        Adds a new external library name
        
        :param java.lang.String or str libraryName: the new external library name to add.
        :param SourceType source: the source of this external library
        :return: library external :obj:`namespace <Library>`
        :rtype: ghidra.program.model.listing.Library
        :raises InvalidInputException: if ``libraryName`` is invalid or null.  A library name 
        with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        """

    def contains(self, libraryName: typing.Union[java.lang.String, str]) -> bool:
        """
        Determines if the indicated external library name is being managed (exists).
        
        :param java.lang.String or str libraryName: the external library name
        :return: true if the name is defined (whether it has a path or not).
        :rtype: bool
        """

    def getExternalLibrary(self, libraryName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Library:
        """
        Get the Library which corresponds to the specified name
        
        :param java.lang.String or str libraryName: name of library
        :return: library or null if not found
        :rtype: ghidra.program.model.listing.Library
        """

    def getExternalLibraryNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array of all external names for which locations have been defined.
        
        :return: array of external names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getExternalLibraryPath(self, libraryName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the file pathname associated with an external name.
        Null is returned if either the external name does not exist or
        a pathname has not been set.
        
        :param java.lang.String or str libraryName: external name
        :return: project file pathname or null
        :rtype: str
        """

    @typing.overload
    @deprecated("Use  getExternalLocations(String, String) or \n getUniqueExternalLocation(String, String) since duplicate names may exist")
    def getExternalLocation(self, libraryName: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str]) -> ExternalLocation:
        """
        Get an external location.
        
        :param java.lang.String or str libraryName: the name of the library for which to get an external location
        :param java.lang.String or str label: the name of the external location.
        :return: first matching external location
        :rtype: ExternalLocation
        
        .. deprecated::
        
        Use  :meth:`getExternalLocations(String, String) <.getExternalLocations>` or 
        :meth:`getUniqueExternalLocation(String, String) <.getUniqueExternalLocation>` since duplicate names may exist
        """

    @typing.overload
    @deprecated("Use getExternalLocations(Namespace, String) or \n getUniqueExternalLocation(Namespace, String) since duplicate names may exist")
    def getExternalLocation(self, namespace: Namespace, label: typing.Union[java.lang.String, str]) -> ExternalLocation:
        """
        Get an external location.
        
        :param Namespace namespace: the namespace containing the external label.
        :param java.lang.String or str label: the name of the external location.
        :return: first matching external location
        :rtype: ExternalLocation
        
        .. deprecated::
        
        Use :meth:`getExternalLocations(Namespace, String) <.getExternalLocations>` or 
        :meth:`getUniqueExternalLocation(Namespace, String) <.getUniqueExternalLocation>` since duplicate names may exist
        """

    @typing.overload
    def getExternalLocation(self, symbol: Symbol) -> ExternalLocation:
        """
        Returns the external location associated with the given external symbol
        
        :param Symbol symbol: the external symbol.
        :return: the external location or null
        :rtype: ExternalLocation
        """

    @typing.overload
    def getExternalLocations(self, libraryName: typing.Union[java.lang.String, str]) -> ExternalLocationIterator:
        """
        Get an iterator over all external locations associated with the specified
        externalName.
        
        :param java.lang.String or str libraryName: the name of the library to get locations for
        :return: external location iterator
        :rtype: ExternalLocationIterator
        """

    @typing.overload
    def getExternalLocations(self, memoryAddress: ghidra.program.model.address.Address) -> ExternalLocationIterator:
        """
        Get an iterator over all external locations which have been associated to
        the specified memory address
        
        :param ghidra.program.model.address.Address memoryAddress: memory address
        :return: external location iterator
        :rtype: ExternalLocationIterator
        """

    @typing.overload
    def getExternalLocations(self, libraryName: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str]) -> java.util.List[ExternalLocation]:
        """
        Returns a list of External Locations matching the given label name in the given Library.
        
        :param java.lang.String or str libraryName: the name of the library
        :param java.lang.String or str label: the name of the label
        :return: a list of External Locations matching the given label name in the given Library.
        :rtype: java.util.List[ExternalLocation]
        """

    @typing.overload
    def getExternalLocations(self, namespace: Namespace, label: typing.Union[java.lang.String, str]) -> java.util.List[ExternalLocation]:
        """
        Returns a list of External Locations matching the given label name in the given Namespace.
        
        :param Namespace namespace: the Namespace to search
        :param java.lang.String or str label: the name of the labels to search for.
        :return: a list of External Locations matching the given label name in the given Namespace.
        :rtype: java.util.List[ExternalLocation]
        """

    @typing.overload
    def getUniqueExternalLocation(self, libraryName: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str]) -> ExternalLocation:
        """
        Returns the unique external location associated with the given library name and label
        
        :param java.lang.String or str libraryName: the library name
        :param java.lang.String or str label: the label of the external location
        :return: the unique external location or null
        :rtype: ExternalLocation
        """

    @typing.overload
    def getUniqueExternalLocation(self, namespace: Namespace, label: typing.Union[java.lang.String, str]) -> ExternalLocation:
        """
        Returns the unique external location associated with the given namespace and label
        
        :param Namespace namespace: the namespace
        :param java.lang.String or str label: the label of the external location
        :return: the unique external location or null
        :rtype: ExternalLocation
        """

    def removeExternalLibrary(self, libraryName: typing.Union[java.lang.String, str]) -> bool:
        """
        Removes external name if no associated ExternalLocation's exist
        
        :param java.lang.String or str libraryName: external library name
        :return: true if removed, false if unable to due to associated locations/references
        :rtype: bool
        """

    def setExternalPath(self, libraryName: typing.Union[java.lang.String, str], pathname: typing.Union[java.lang.String, str], userDefined: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the file pathname associated with an existing external name.
        
        :param java.lang.String or str libraryName: the name of the library to associate with a file.
        :param java.lang.String or str pathname: the path to the program to be associated with the library name.
        :param jpype.JBoolean or bool userDefined: true if the external path is being specified by the user
        :raises InvalidInputException: on invalid input
        """

    def updateExternalLibraryName(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], source: SourceType):
        """
        Change the name of an existing external name.
        
        :param java.lang.String or str oldName: the old name of the external library name.
        :param java.lang.String or str newName: the new name of the external library name.
        :param SourceType source: the source of this external library
        :raises DuplicateNameException: if another namespace has the same name
        :raises InvalidInputException: on invalid input
        """

    @property
    def externalLibrary(self) -> ghidra.program.model.listing.Library:
        ...

    @property
    def externalLocation(self) -> ExternalLocation:
        ...

    @property
    def externalLibraryNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def externalLocations(self) -> ExternalLocationIterator:
        ...

    @property
    def externalLibraryPath(self) -> java.lang.String:
        ...


class ExternalReference(Reference):
    """
    Interface for references to external locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getExternalLocation(self) -> ExternalLocation:
        """
        Returns the object that represents the external location.
        """

    def getLabel(self) -> str:
        """
        Returns the external label associated with this location (may be null).
        """

    def getLibraryName(self) -> str:
        """
        Returns the name of the external library containing this location.
        """

    @property
    def libraryName(self) -> java.lang.String:
        ...

    @property
    def externalLocation(self) -> ExternalLocation:
        ...

    @property
    def label(self) -> java.lang.String:
        ...


class EquateTable(java.lang.Object):
    """
    EquateTable manages all equates for program. An equate defines a relationship
    between a scalar value and a string whereby the scalar may be represented by
    the string. All equates are defined by the user and remain until explicitly
    removed by the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createEquate(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]) -> Equate:
        """
        Creates a new equate
        
        :param java.lang.String or str name: the name to associate with the given value.
        :param jpype.JLong or int value: the value to associate with the given name.
        :return: the equate
        :rtype: Equate
        :raises DuplicateNameException: thrown if name is already in use
        as an equate.
        :raises InvalidInputException: if name contains blank characters,
        is zero length, or is null
        """

    def deleteAddressRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all equates defined in the given range.
        
        :param ghidra.program.model.address.Address start: start of the range
        :param ghidra.program.model.address.Address end: end of the range
        :param ghidra.util.task.TaskMonitor monitor: task monitor to cancel the remove operation
        :raises CancelledException: if the operation was cancelled.
        """

    @typing.overload
    def getEquate(self, name: typing.Union[java.lang.String, str]) -> Equate:
        """
        Returns the equate with the given name, null if no such equate exists
        
        :param java.lang.String or str name: the of the equate to be retrieved
        :return: the equate
        :rtype: Equate
        """

    @typing.overload
    def getEquate(self, reference: ghidra.program.model.address.Address, opndPosition: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> Equate:
        """
        Returns the first equate found that is associated with the given 
        value at the given reference address and operand position;
        
        :param ghidra.program.model.address.Address reference: address where the equate is used.
        :param jpype.JInt or int opndPosition: the operand index of the operand where the equate is used.
        :param jpype.JLong or int value: the value where the equate is used.
        :return: the equate or null if there is no such equate.
        :rtype: Equate
        """

    @typing.overload
    def getEquateAddresses(self) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an address iterator over all the addresses where
        equates have been set.
        
        :return: the iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getEquateAddresses(self, start: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator:
        """
        Return an address iterator over each address with an
        equate reference starting at the start address.
        
        :param ghidra.program.model.address.Address start: start address
        :return: an AddressIterator over addresses with defined equate references
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getEquateAddresses(self, asv: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator:
        """
        Return an address iterator over each address with an
        equate reference that is in the specified address set.
        
        :param ghidra.program.model.address.AddressSetView asv: the address set
        :return: AddressIterator over addresses with defined equate references
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getEquates(self, reference: ghidra.program.model.address.Address, opndPosition: typing.Union[jpype.JInt, int]) -> java.util.List[Equate]:
        """
        Returns the equates (one for each scalar) at the given reference address 
        and operand position; For an instruction a given operand can have multiple scalars.
        
        :param ghidra.program.model.address.Address reference: address where the equate is used.
        :param jpype.JInt or int opndPosition: the operand index of the operand where the equate is used.
        :return: the list of equates or empty list if there is no such equate.
        :rtype: java.util.List[Equate]
        """

    @typing.overload
    def getEquates(self, reference: ghidra.program.model.address.Address) -> java.util.List[Equate]:
        """
        Returns the equates (one for each scalar and opIndex) at the given reference address.
        For an instruction a given operand can have multiple scalars.
        
        :param ghidra.program.model.address.Address reference: address where the equate is used.
        :return: the list of equates or empty list if there is no such equate.
        :rtype: java.util.List[Equate]
        """

    @typing.overload
    def getEquates(self, value: typing.Union[jpype.JLong, int]) -> java.util.List[Equate]:
        """
        Returns all equates defined for value.
        
        :param jpype.JLong or int value: the value to get all equates for.
        :return: the equates
        :rtype: java.util.List[Equate]
        """

    @typing.overload
    def getEquates(self) -> java.util.Iterator[Equate]:
        """
        Returns an iterator over all equates.
        
        :return: the iterator
        :rtype: java.util.Iterator[Equate]
        """

    def removeEquate(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Removes the equate from the program.
        
        :param java.lang.String or str name: the name of the equate to remove.
        :return: true if the equate existed, false otherwise.
        :rtype: bool
        """

    @property
    def equate(self) -> Equate:
        ...

    @property
    def equateAddresses(self) -> ghidra.program.model.address.AddressIterator:
        ...

    @property
    def equates(self) -> java.util.List[Equate]:
        ...


class Namespace(java.lang.Object):
    """
    The Namespace interface
    """

    class_: typing.ClassVar[java.lang.Class]
    GLOBAL_NAMESPACE_ID: typing.Final = 0
    DELIMITER: typing.Final = "::"
    """
    The delimiter that is used to separate namespace nodes in a namespace
    string.  For example, "Global::child1::symbolName"
    """

    NAMESPACE_DELIMITER: typing.Final = "::"
    """
    Replaced by :obj:`.DELIMITER`
    
    
    .. deprecated::
    
    use :obj:`.DELIMITER`
    """


    def getBody(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set for this namespace.  Note: The body of a namespace (currently
        only used by the function namespace) is restricted it Integer.MAX_VALUE.
        
        :return: the address set for this namespace
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getID(self) -> int:
        """
        Return the namespace id
        
        :return: the namespace id
        :rtype: int
        """

    @typing.overload
    def getName(self) -> str:
        """
        Get the name of the symbol for this scope
        
        :return: the name of the symbol for this scope
        :rtype: str
        """

    @typing.overload
    def getName(self, includeNamespacePath: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the fully qualified name
        
        :param jpype.JBoolean or bool includeNamespacePath: true to include the namespace in the returned name
        :return: the fully qualified name
        :rtype: str
        """

    def getParentNamespace(self) -> Namespace:
        """
        Get the parent scope.
        
        :return: null if this scope is the global scope.
        :rtype: Namespace
        """

    def getPathList(self, omitLibrary: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        """
        Get the namespace path as a list of namespace names.
        
        :param jpype.JBoolean or bool omitLibrary: if true Library name (if applicable) will be 
        omitted from returned list and treated same as global namespace.
        :return: namespace path list or empty list for global namespace
        :rtype: java.util.List[java.lang.String]
        """

    def getSymbol(self) -> Symbol:
        """
        Get the symbol for this namespace.
        
        :return: the symbol for this namespace.
        :rtype: Symbol
        """

    def isExternal(self) -> bool:
        """
        Returns true if this namespace is external (i.e., associated with a Library)
        
        :return: true if this namespace is external (i.e., associated with a Library)
        :rtype: bool
        """

    def isGlobal(self) -> bool:
        """
        Return true if this is the global namespace
        
        :return: true if this is the global namespace
        :rtype: bool
        """

    def isLibrary(self) -> bool:
        """
        Return true if this is a library
        
        :return: true if this is a library
        :rtype: bool
        """

    def setParentNamespace(self, parentNamespace: Namespace):
        """
        Set the parent namespace for this namespace. Restrictions may apply.
        
        :param Namespace parentNamespace: the namespace to use as this namespace's parent.
        :raises InvalidInputException: if the parent namespace is not applicable for
        this namespace.
        :raises DuplicateNameException: if another symbol exists in the parent namespace with
        the same name as this namespace
        :raises CircularDependencyException: if the parent namespace is a descendant of this
        namespace.
        """

    @property
    def symbol(self) -> Symbol:
        ...

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def library(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def parentNamespace(self) -> Namespace:
        ...

    @parentNamespace.setter
    def parentNamespace(self, value: Namespace):
        ...

    @property
    def global_(self) -> jpype.JBoolean:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def pathList(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView:
        ...


class DynamicReference(Reference):
    """
    ``DynamicReference`` is a dynamically determined reference which 
    may not be explicitly added, deleted or modified
    """

    class_: typing.ClassVar[java.lang.Class]


class ShiftedReference(Reference):
    """
    ``ShiftedReference`` is a memory reference whose "to" address is
    computed from a base value left shifted by a shift amount.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getShift(self) -> int:
        """
        Returns the left shift amount.
        
        :return: the shift
        :rtype: int
        """

    def getValue(self) -> int:
        """
        Returns the base value.
        
        :return: the value
        :rtype: int
        """

    @property
    def shift(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class ReferenceIterator(java.util.Iterator[Reference], java.lang.Iterable[Reference]):
    """
    Iterator that gives out MemReference objects.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Returns whether there is a next memory reference in the iterator.
        """

    def next(self) -> Reference:
        """
        Get the next memory reference.
        
        :return: null if there is no next reference
        :rtype: Reference
        """


class ExternalLocation(java.lang.Object):
    """
    ``ExternalLocation`` defines a location within an external
    program (i.e., library).  The external program is uniquely identified
    by a program name, and the location within the program is identified by
    label, address or both.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createFunction(self) -> ghidra.program.model.listing.Function:
        """
        Create an external function associated with this location or return
        the existing function if one already exists
        
        :return: external function
        :rtype: ghidra.program.model.listing.Function
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the external address if known, or null
        
        :return: the external address if known, or null
        :rtype: ghidra.program.model.address.Address
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the DataType which has been associated with this location.
        """

    def getExternalSpaceAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address in "External" (fake) space where this location is stored.
        
        :return: the address that represents this location in "External" space.
        :rtype: ghidra.program.model.address.Address
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the external function associated with this location or null if this is a data
        location.
        
        :return: external function associated with this location or null
        if this is a data location.
        :rtype: ghidra.program.model.listing.Function
        """

    def getLabel(self) -> str:
        """
        Returns the external label associated with this location.
        
        :return: the external label associated with this location.
        :rtype: str
        """

    def getLibraryName(self) -> str:
        """
        Returns the name of the external program containing this location.
        
        :return: the name of the external program containing this location.
        :rtype: str
        """

    def getOriginalImportedName(self) -> str:
        """
        Returns the original name for this location. Will be null if the name was never
        changed.
        
        :return: the original name for this location. Will be null if the name was never
        changed.
        :rtype: str
        """

    def getParentName(self) -> str:
        """
        Returns the name of the parent namespace containing this location.
        
        :return: the name of the parent namespace containing this location.
        :rtype: str
        """

    def getParentNameSpace(self) -> Namespace:
        """
        Returns the parent namespace containing this location.
        
        :return: the parent namespace containing this location.
        :rtype: Namespace
        """

    def getSource(self) -> SourceType:
        """
        Returns the source of this location.
        
        :return: the source
        :rtype: SourceType
        """

    def getSymbol(self) -> Symbol:
        """
        Returns the symbol associated with this external location or null.
        
        :return: the symbol associated with this external location or null.
        :rtype: Symbol
        """

    def isEquivalent(self, other: ExternalLocation) -> bool:
        """
        Returns true if the given external location has the same name, namespace, original import name,
        and external address.
        
        :param ExternalLocation other: the other ExternalLocation to compare
        :return: true if the other location is equivalent to this one.
        :rtype: bool
        """

    def isFunction(self) -> bool:
        """
        
        
        :return: true if location corresponds to a function
        :rtype: bool
        """

    def restoreOriginalName(self):
        """
        If this external location has a replacement name, then the primary symbol will be deleted and
        the original symbol will become the primary symbol, effectively restoring the location to
        it's original name.
        """

    def setAddress(self, address: ghidra.program.model.address.Address):
        """
        Sets the address in the external program associated with this location.
        The address may not be null if location has a default label.
        
        :param ghidra.program.model.address.Address address: the address to set.
        :raises InvalidInputException: if address is null and location currently has a default name
        """

    def setDataType(self, dt: ghidra.program.model.data.DataType):
        """
        Associate the specified data type with this location.
        
        :param ghidra.program.model.data.DataType dt: data type
        """

    def setLocation(self, label: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, source: SourceType):
        """
        Set the external label which defines this location.
        
        :param java.lang.String or str label: external label, may be null if addr is not null.  Label may also be
        namespace qualified and best effort will be used to parse namespace (see :obj:`SymbolPath`).
        If a namespace is not included within label, the current namespace will be preserved.
        Note that this method does not properly handle the presence of template information within the
        label.
        :param ghidra.program.model.address.Address addr: external address, may be null
        :param SourceType source: the source of the external label name
        :raises DuplicateNameException: if another location with this label has
        already been defined
        :raises InvalidInputException:
        """

    def setName(self, namespace: Namespace, name: typing.Union[java.lang.String, str], sourceType: SourceType):
        """
        Set a new name for this external location. The new
        name will become the primary symbol for this location. The current name
        for this location will be saved as the original symbol for this location.
        
        :param Namespace namespace: the namespace for the original symbol.  Can be different than original symbol
        :param java.lang.String or str name: the user-friendly name.
        :param SourceType sourceType: the SourceType for the new name.
        :raises InvalidInputException: if the name contains illegal characters (space for example)
        """

    @property
    def libraryName(self) -> java.lang.String:
        ...

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def symbol(self) -> Symbol:
        ...

    @property
    def parentName(self) -> java.lang.String:
        ...

    @property
    def externalSpaceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def originalImportedName(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @address.setter
    def address(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def parentNameSpace(self) -> Namespace:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType):
        ...

    @property
    def source(self) -> SourceType:
        ...

    @property
    def label(self) -> java.lang.String:
        ...


class MemReferenceImpl(Reference):
    """
    Implementation for a reference, not associated with a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: RefType, sourceType: SourceType, opIndex: typing.Union[jpype.JInt, int], isPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a MemReferenceImpl.
        
        :param ghidra.program.model.address.Address fromAddr: reference from address
        :param ghidra.program.model.address.Address toAddr: reference to address
        :param RefType refType: the type of the reference
        :param SourceType sourceType: reference source type :obj:`SourceType`
        :param jpype.JInt or int opIndex: the operand index of the from location
        :param jpype.JBoolean or bool isPrimary: true if this reference should substitue the operand
        """

    def compareTo(self, ref: Reference) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(Object)`
        """

    def getFromAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.getFromAddress()`
        """

    def getOperandIndex(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.getOperandIndex()`
        """

    def getReferenceType(self) -> RefType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.getReferenceType()`
        """

    def getSource(self) -> SourceType:
        ...

    def getSymbolID(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.getSymbolID()`
        """

    def getToAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.getToAddress()`
        """

    def isEntryPointReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isEntryPointReference()`
        """

    def isExternalReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isExternalReference()`
        """

    def isMemoryReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isMemoryReference()`
        """

    def isMnemonicReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isMnemonicReference()`
        """

    def isOffsetReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isOffsetReference()`
        """

    def isOperandReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isOperandReference()`
        """

    def isPrimary(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isPrimary()`
        """

    def isRegisterReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isRegisterReference()`
        """

    def isShiftedReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isShiftedReference()`
        """

    def isStackReference(self) -> bool:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.Reference.isStackReference()`
        """

    def setSource(self, source: SourceType):
        ...

    @property
    def symbolID(self) -> jpype.JLong:
        ...

    @property
    def stackReference(self) -> jpype.JBoolean:
        ...

    @property
    def shiftedReference(self) -> jpype.JBoolean:
        ...

    @property
    def referenceType(self) -> RefType:
        ...

    @property
    def offsetReference(self) -> jpype.JBoolean:
        ...

    @property
    def operandReference(self) -> jpype.JBoolean:
        ...

    @property
    def source(self) -> SourceType:
        ...

    @source.setter
    def source(self, value: SourceType):
        ...

    @property
    def toAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...

    @property
    def registerReference(self) -> jpype.JBoolean:
        ...

    @property
    def mnemonicReference(self) -> jpype.JBoolean:
        ...

    @property
    def externalReference(self) -> jpype.JBoolean:
        ...

    @property
    def memoryReference(self) -> jpype.JBoolean:
        ...

    @property
    def entryPointReference(self) -> jpype.JBoolean:
        ...

    @property
    def fromAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...


class ExternalLocationIterator(java.util.Iterator[ExternalLocation]):
    """
    Iterator interface for external locations.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Returns true if another external location is available with the next() method.
        """

    def next(self) -> ExternalLocation:
        """
        Returns the next external location
        """


class SymbolTable(java.lang.Object):
    """
    A SymbolTable manages the Symbols defined in a program.
     
    
    A Symbol is an association between an Address, a String name. In addition, symbols may have one
    or more References.
     
    
    A Reference is a 4-tuple of a source address, destination address, type, and either a mnemonic or
    operand index.
     
    
    Any address in a program can have more than one symbol associated to it. At any given time, one
    and only one symbol will be designated as the primary.
     
    
    A symbol can be either global or local. Local symbols belong to some namespace other than the
    global namespace.
     
    
    Label and Function symbols do not have to have unique names with a namespace. All other symbols
    must be unique within a namespace and be unique with all other symbols that must be unique. In
    other words, you can have several functions named "foo" and several labels named "foo" in the
    same namespace. But you can't have a class named "foo" and a namespace named "foo". But you can
    have a class named "foo" and many functions and labels named "foo" all in the same namespace.
     
    
    A symbol can also be designated as dynamic. Which means the name is generated on-the-fly by the
    system based on its context.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addExternalEntryPoint(self, addr: ghidra.program.model.address.Address):
        """
        Add a memory address to the external entry points.
        
        :param ghidra.program.model.address.Address addr: the memory address to add
        :raises IllegalArgumentException: if a non-memory is specified
        """

    def convertNamespaceToClass(self, namespace: Namespace) -> ghidra.program.model.listing.GhidraClass:
        """
        Convert the given namespace to a class namespace
        
        :param Namespace namespace: the namespace to convert
        :return: the new class
        :rtype: ghidra.program.model.listing.GhidraClass
        :raises ConcurrentModificationException: if the given parent namespace has been deleted
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table or the namespace not allowed (e.g., global or
                    library namespace).
        """

    def createClass(self, parent: Namespace, name: typing.Union[java.lang.String, str], source: SourceType) -> ghidra.program.model.listing.GhidraClass:
        """
        Create a class namespace in the given parent namespace
        
        :param Namespace parent: the parent namespace, or null for the global namespace
        :param java.lang.String or str name: the name of the namespace
        :param SourceType source: the source of this class namespace's symbol
        :return: the new class namespace
        :rtype: ghidra.program.model.listing.GhidraClass
        :raises DuplicateNameException: thrown if another non function or label symbol exists with the
                    given name
        :raises InvalidInputException: throw if the name has invalid characters or is null
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table or if source is :obj:`SourceType.DEFAULT`
        """

    def createExternalLibrary(self, name: typing.Union[java.lang.String, str], source: SourceType) -> ghidra.program.model.listing.Library:
        """
        Create a library namespace with the given name
        
        :param java.lang.String or str name: the name of the new library namespace
        :param SourceType source: the source of this external library's symbol
        :return: the new library namespace
        :rtype: ghidra.program.model.listing.Library
        :raises InvalidInputException: if the name is invalid
        :raises IllegalArgumentException: if you try to set the source to :obj:`SourceType.DEFAULT`
        :raises DuplicateNameException: thrown if another non function or label symbol exists with the
                    given name
        """

    @typing.overload
    def createLabel(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], source: SourceType) -> Symbol:
        """
        Create a label symbol with the given name in the global namespace and associated to the 
        given memory address. (see :meth:`Address.isMemoryAddress() <Address.isMemoryAddress>`).
         
        
        The new symbol will be of type :obj:`SymbolType.LABEL` or :obj:`SymbolType.FUNCTION` if a 
        default function symbol currently exists at the address. If a default function symbol exists 
        at the specified address the function symbol will be renamed and returned.  Label and function
        symbols do not need to be unique across multiple addresses.  However, if a global symbol at 
        the specified address already has the specified name it will be returned without changing the 
        source type.  If this is the first non-dynamic symbol defined for the address it becomes the 
        primary symbol.
        
        :param ghidra.program.model.address.Address addr: the memory address at which to create a symbol
        :param java.lang.String or str name: the name of the symbol
        :param SourceType source: the source of this symbol.  In general, a source of :obj:`SourceType.DEFAULT` 
                    should never be specified using this method.
        :return: new labe or function symbol
        :rtype: Symbol
        :raises InvalidInputException: if name contains white space, is zero length, or is null for
                    non-default source
        :raises IllegalArgumentException: if :obj:`SourceType.DEFAULT` is improperly specified, or 
                    a non-memory address.
        """

    @typing.overload
    def createLabel(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: Namespace, source: SourceType) -> Symbol:
        """
        Create a label symbol with the given name and namespace associated to the given memory 
        address.  (see :meth:`Address.isMemoryAddress() <Address.isMemoryAddress>`).
         
        
        The new symbol will be of type :obj:`SymbolType.LABEL` or :obj:`SymbolType.FUNCTION` if a 
        default function symbol currently exists at the address. If a default function symbol exists 
        at the specified address the function symbol will be renamed and returned.  Label and function
        symbols do not need to be unique across multiple addresses or namespaces.  However, if a 
        symbol at the specified address already has the specified name and namespace it will be 
        returned without changing the source type.  If this is the first non-dynamic symbol defined 
        for the address it becomes the primary symbol.
        
        :param ghidra.program.model.address.Address addr: the address at which to create a symbol
        :param java.lang.String or str name: the name of the symbol
        :param Namespace namespace: the parent namespace of the symbol, or null for the global namespace.
        :param SourceType source: the source of this symbol. In general, a source of :obj:`SourceType.DEFAULT` 
                    should never be specified using this method.
        :return: new label or function symbol
        :rtype: Symbol
        :raises InvalidInputException: if name contains white space, is zero length, or is null for
                    non-default source. Also thrown if invalid parent namespace is specified.
        :raises IllegalArgumentException: if :obj:`SourceType.DEFAULT` is improperly specified, or 
                    a non-memory address, or if the given parent namespace is from a different 
                    program than that of this symbol table.
        """

    def createNameSpace(self, parent: Namespace, name: typing.Union[java.lang.String, str], source: SourceType) -> Namespace:
        """
        Create a new namespace
        
        :param Namespace parent: the parent of the new namespace, or null for the global namespace
        :param java.lang.String or str name: the name of the new namespace
        :param SourceType source: the source of this namespace's symbol
        :return: the new namespace
        :rtype: Namespace
        :raises DuplicateNameException: if another non function or label symbol exists with the given
                    name
        :raises InvalidInputException: if the name is invalid
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table or if source is :obj:`SourceType.DEFAULT`
        """

    def getAllSymbols(self, includeDynamicSymbols: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all of the symbols, optionally including dynamic symbols
        
        :param jpype.JBoolean or bool includeDynamicSymbols: if true, the iterator will include dynamic symbols
        :return: an iterator over the symbols
        :rtype: SymbolIterator
        """

    def getChildren(self, parentSymbol: Symbol) -> SymbolIterator:
        """
        Get all symbols that have the given parent symbol
         
        
        **NOTE:** The resulting iterator will not return default thunks (i.e., thunk function
        symbol with default source type) or global dynamic label symbols.
        
        :param Symbol parentSymbol: the parent symbol
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    def getClassNamespaces(self) -> java.util.Iterator[ghidra.program.model.listing.GhidraClass]:
        """
        Get all class namespaces defined within the program, in no particular order
        
        :return: an iterator over the classes
        :rtype: java.util.Iterator[ghidra.program.model.listing.GhidraClass]
        """

    def getClassSymbol(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Symbol:
        """
        Get the class symbol with the given name in the given namespace
        
        :param java.lang.String or str name: the name of the class
        :param Namespace namespace: the parent namespace to search for the class
        :return: the class symbol with the given name in the given namespace
        :rtype: Symbol
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    def getDefinedSymbols(self) -> SymbolIterator:
        """
        Get all defined symbols in no particular order.  All global dynamic memory labels will be 
        excluded.
        
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    def getDynamicSymbolID(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Get the unique symbol ID for a dynamic symbol at the specified address
         
        
        Having a dynamic symbol ID does not imply that a dynamic symbol actually exists. Rather, this
        just gives the ID that a dynamic symbol at that address would have, should it ever exist.
         
        
        **NOTE:** This symbol ID should not be permanently stored since the encoding may change
        between software releases.
        
        :param ghidra.program.model.address.Address addr: the dynamic symbol memory address
        :return: unique symbol ID
        :rtype: int
        :raises IllegalArgumentException: if a non-memory address is specified
        """

    def getExternalEntryPointIterator(self) -> ghidra.program.model.address.AddressIterator:
        """
        Get the external entry points (addresses)
        
        :return: entry-point address iterator
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getExternalSymbol(self, name: typing.Union[java.lang.String, str]) -> Symbol:
        """
        Get the external symbol with the given name.  The first occurrence of the named symbol found
        within any external namespace will be returned.  If all matching symbols need to be
        considered the :meth:`getExternalSymbols(String) <.getExternalSymbols>` should be used.
        
        :param java.lang.String or str name: the name of the symbol
        :return: the symbol, or null if no external symbol has that name
        :rtype: Symbol
        """

    @typing.overload
    def getExternalSymbols(self, name: typing.Union[java.lang.String, str]) -> SymbolIterator:
        """
        Get all the external symbols with the given name
        
        :param java.lang.String or str name: the name of symbols
        :return: an iterator over the symbols
        :rtype: SymbolIterator
        """

    @typing.overload
    def getExternalSymbols(self) -> SymbolIterator:
        """
        Get all defined external symbols in no particular order
        
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    def getGlobalSymbol(self, name: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address) -> Symbol:
        """
        Get the global symbol with the given name and address.
         
        
        Note that this results in a single Symbol because of an additional restriction that allows
        only one symbol with a given name at the same address and namespace (in this case the global
        namespace).
         
        
        This is just a convenience method for :meth:`getSymbol(String, Address, Namespace) <.getSymbol>` where
        the namespace is the global namespace.
         
        
        **NOTE:** This method will not return a default thunk (i.e., thunk function symbol with
        default source type) since it mirrors the name and parent namespace of the function it
        thunks.
        
        :param java.lang.String or str name: the name of the symbol to retrieve
        :param ghidra.program.model.address.Address addr: the address of the symbol to retrieve
        :return: the symbol which matches the specified criteria in the global namespace or null if
                not found
        :rtype: Symbol
        
        .. seealso::
        
            | :obj:`.getSymbol(String, Address, Namespace)`
        """

    def getGlobalSymbols(self, name: typing.Union[java.lang.String, str]) -> java.util.List[Symbol]:
        """
        Get a list of all global symbols with the given name.  Matches against dynamic label symbols 
        will be included.  
         
        
        **NOTE:** This method will not return default thunks (i.e., thunk function symbol with
        default source type).
        
        :param java.lang.String or str name: the name of the symbols to retrieve
        :return: a list of all global symbols with the given name
        :rtype: java.util.List[Symbol]
        """

    @typing.overload
    def getLabelHistory(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[LabelHistory]:
        """
        Get the label history for the given address
         
        
        Each entry records a change made to the labels at the given address
        
        :param ghidra.program.model.address.Address addr: address of the label change
        :return: array of history objects
        :rtype: jpype.JArray[LabelHistory]
        """

    @typing.overload
    def getLabelHistory(self) -> java.util.Iterator[LabelHistory]:
        """
        Get the complete label history of the program
        
        :return: an iterator over history entries
        :rtype: java.util.Iterator[LabelHistory]
        """

    def getLabelOrFunctionSymbols(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> java.util.List[Symbol]:
        """
        Get all the label or function symbols that have the given name in the given parent namespace.
        If the global namespace is specified matches against dynamic label symbols will be included.  
         
        
        **NOTE:** If a function namespace is specified default parameter and local variable names 
        will be included.  If an external library or namespace is specified default external 
        label/function symbols will be included.
         
        
        **NOTE:** This method will not return a default thunk (i.e., thunk function symbol with
        default source type) since it mirrors the name and parent namespace of the function it
        thunks.
        
        :param java.lang.String or str name: the name of the symbols to search for
        :param Namespace namespace: the namespace to search. If null, then the global namespace is assumed.
        :return: a list of all the label or function symbols with the given name in the given parent
                namespace
        :rtype: java.util.List[Symbol]
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    def getLibrarySymbol(self, name: typing.Union[java.lang.String, str]) -> Symbol:
        """
        Get the library symbol with the given name
        
        :param java.lang.String or str name: the name of the library symbol to retrieve
        :return: the library symbol with the given name
        :rtype: Symbol
        """

    def getLocalVariableSymbol(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Symbol:
        """
        Get the local variable symbol with the given name in the given namespace
        
        :param java.lang.String or str name: the name of the local variable
        :param Namespace namespace: the parent namespace (function) to search for the local variable
        :return: the local variable symbol with the given name in the given namespace
        :rtype: Symbol
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    @typing.overload
    def getNamespace(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Namespace:
        """
        Get the namespace with the given name in the given parent namespace.
         
        
        The returned namespace can be a generic namespace (:obj:`SymbolType.NAMESPACE`, 
        :obj:`NamespaceSymbol`), class (:obj:`SymbolType.CLASS`, :obj:`ClassSymbol`),or 
        library (:obj:`SymbolType.LIBRARY`, :obj:`LibrarySymbol`), but not a function.
         
        
        There can be only one because these symbol types have a unique name 
        requirement within their parent namespace.
        
        :param java.lang.String or str name: the name of the namespace to be retrieved
        :param Namespace namespace: the parent namespace of the namespace to be retrieved
        :return: the namespace with the given name in the given parent namespace
        :rtype: Namespace
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    @typing.overload
    def getNamespace(self, addr: ghidra.program.model.address.Address) -> Namespace:
        """
        Get the deepest namespace containing the given address
        
        :param ghidra.program.model.address.Address addr: the address contained in the namespace
        :return: the deepest namespace which contains the address
        :rtype: Namespace
        """

    def getNamespaceSymbol(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Symbol:
        """
        Get a generic namespace symbol with the given name in the given parent namespace
        
        :param java.lang.String or str name: the name of the namespace symbol to retrieve
        :param Namespace namespace: the namespace containing the symbol to retrieve
        :return: the symbol, or null
        :rtype: Symbol
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    def getNumSymbols(self) -> int:
        """
        Get the total number of symbols in the table
        
        :return: total number of symbols
        :rtype: int
        """

    def getOrCreateNameSpace(self, parent: Namespace, name: typing.Union[java.lang.String, str], source: SourceType) -> Namespace:
        """
        Get or create the namespace with the given name in the given parent
         
        
        If the namespace does not already exists, then it will be created.
        
        :param Namespace parent: the parent namespace
        :param java.lang.String or str name: the namespace name
        :param SourceType source: the source type for the namespace if it is created
        :return: the namespace
        :rtype: Namespace
        :raises DuplicateNameException: if another non function or label symbol exists with the given
                    name
        :raises InvalidInputException: if the name is invalid
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table
        :raises ConcurrentModificationException: if the given parent namespace has been deleted
        """

    def getParameterSymbol(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> Symbol:
        """
        Get the parameter symbol with the given name in the given namespace
        
        :param java.lang.String or str name: the name of the parameter
        :param Namespace namespace: the namespace (function) to search for the class
        :return: the parameter symbol with the given name in the given namespace
        :rtype: Symbol
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    def getPrimarySymbol(self, addr: ghidra.program.model.address.Address) -> Symbol:
        """
        Get the primary label or function symbol at the given address
         
        
        This method will return null if the address specified is neither a memory address nor an
        external address.
        
        :param ghidra.program.model.address.Address addr: the address of the symbol
        :return: the symbol, or null if no symbol is at the address
        :rtype: Symbol
        """

    @typing.overload
    def getPrimarySymbolIterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all primary label and function symbols defined within program memory address.
        Iteration may span multiple memory spaces. 
         
        
        **NOTE:** The returned symbols will not include any external symbols defined within the 
        :obj:`AddressSpace.EXTERNAL_SPACE`.  In addition, all global dynamic label symbols will 
        be omitted.
        
        :param jpype.JBoolean or bool forward: true means the iterator is in the forward direction
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getPrimarySymbolIterator(self, startAddr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all primary label and function symbols starting at the specified memory address through 
        to the program's maximum memory address.  Iteration may span multiple memory spaces. 
         
        
        **NOTE:** The returned symbols will not include any external symbols defined within the 
        :obj:`AddressSpace.EXTERNAL_SPACE`.  In addition, all global dynamic label symbols will 
        be omitted.
        
        :param ghidra.program.model.address.Address startAddr: the starting memory address
        :param jpype.JBoolean or bool forward: true means the iterator is in the forward direction
        :return: symbol iterator
        :rtype: SymbolIterator
        :raises IllegalArgumentException: if a non-memory address is specified
        """

    @typing.overload
    def getPrimarySymbolIterator(self, addressSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get primary label and function symbols within the given address set.  
         
        
        **NOTE:** All external symbols will be omitted unless the full 
        :obj:`AddressSpace.EXTERNAL_SPACE` range is included within the specified address set
        or a null addressSet is specified.  All global dynamic label symbols will be omitted.
        
        :param ghidra.program.model.address.AddressSetView addressSet: the set of address containing the symbols.  A null value may be specified
        to include all memory and external primary symbols.
        :param jpype.JBoolean or bool forward: true means the iterator is in the forward direction
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbol(self, symbolID: typing.Union[jpype.JLong, int]) -> Symbol:
        """
        Get the symbol for the given symbol ID.
        
        :param jpype.JLong or int symbolID: the id of the symbol to be retrieved
        :return: null if there is no symbol with the given ID
        :rtype: Symbol
        """

    @typing.overload
    def getSymbol(self, name: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, namespace: Namespace) -> Symbol:
        """
        Get the symbol with the given name, address, and namespace.
         
        
        Note that for a symbol to be uniquely specified, all these parameters are required. Any
        method that queries for symbols using just one or two of these parameters will return only
        the first match.
         
        
        **NOTE:** This method will not return a default thunk (i.e., thunk function symbol with
        default source type) since it mirrors the name and parent namespace of the function it
        thunks.
        
        :param java.lang.String or str name: the name of the symbol to retrieve
        :param ghidra.program.model.address.Address addr: the address of the symbol to retrieve
        :param Namespace namespace: the namespace of the symbol to retrieve. May be null which indicates the
                    global namespace.
        :return: the symbol which matches the specified criteria or null if not found
        :rtype: Symbol
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table
        
        .. seealso::
        
            | :obj:`.getGlobalSymbol(String, Address)`for a convenience method if the namespace is the
            global namespace.
        """

    @typing.overload
    def getSymbol(self, ref: Reference) -> Symbol:
        """
        Get the symbol that a given reference associates
        
        :param Reference ref: the reference for the associated symbol
        :return: the associated symbol
        :rtype: Symbol
        """

    @typing.overload
    def getSymbolIterator(self, searchStr: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get an iterator over all symbols that match the given query
         
        
        **NOTE:** The iterator is in the forward direction only and will not return default thunks
        (i.e., thunk function symbol with default source type).
        
        :param java.lang.String or str searchStr: the query, which may contain * to match any sequence or ? to match a single
                    char
        :param jpype.JBoolean or bool caseSensitive: flag to specify whether the search is case sensitive
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbolIterator(self) -> SymbolIterator:
        """
        Get all label symbols
         
        
        Labels are defined on memory locations.
        
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbolIterator(self, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all the symbols defined with program memory.
         
        
        **NOTE:** The returned symbols will not include any external symbols defined within the 
        :obj:`AddressSpace.EXTERNAL_SPACE`.  In addition, all global dynamic label symbols will 
        be omitted.
        
        :param jpype.JBoolean or bool forward: the direction of the iterator, by address
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbolIterator(self, startAddr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all the symbols starting at the specified memory address.
         
        
        **NOTE:** The returned symbols will not include any external symbols defined within the 
        :obj:`AddressSpace.EXTERNAL_SPACE`.  In addition, all global dynamic label symbols will 
        be omitted.
        
        :param ghidra.program.model.address.Address startAddr: the starting address
        :param jpype.JBoolean or bool forward: true means the iterator is in the forward direction
        :return: symbol iterator
        :rtype: SymbolIterator
        :raises IllegalArgumentException: if startAddr is not a memory address
        """

    @typing.overload
    def getSymbols(self, name: typing.Union[java.lang.String, str], namespace: Namespace) -> java.util.List[Symbol]:
        """
        Get a list of all symbols with the given name in the given parent namespace.  If the global
        namespace is specified matches against dynamic label symbols will be included.  
         
        
        **NOTE:** If a function namespace is specified default parameter and local variable names 
        will be included.  If an external library or namespace is specified default external 
        label/function symbols will be included.
         
        
        **NOTE:** The resulting iterator will not return default thunks (i.e., thunk function
        symbol with default source type).
        
        :param java.lang.String or str name: the name of the symbols to retrieve
        :param Namespace namespace: the namespace to search for symbols
        :return: a list of symbols which satisfy specified criteria
        :rtype: java.util.List[Symbol]
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                than that of this symbol table
        """

    @typing.overload
    def getSymbols(self, name: typing.Union[java.lang.String, str]) -> SymbolIterator:
        """
        Get all the symbols with the given name
         
        
        **NOTE:** The resulting iterator will not return default thunks (i.e., thunk function
        symbol with default source type). It will also not work for default local variables and
        parameters.
        
        :param java.lang.String or str name: the name of symbols to search for
        :return: an iterator over symbols with the given name
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbols(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Symbol]:
        """
        Get all the symbols at the given address.  This method will include a dynamic memory symbol
        if one exists at the specified address.
         
        
        For a memory address the primary symbol will be returned at array index 0. **WARNING!**
        Use of this method with non-memory addresses is discouraged.  Example: Variable
        address could be used multiple times by many functions. 
         
        
        **NOTE:** unless all the symbols are needed at once, and a dynamic symbol can be ignored,
        consider using :meth:`getSymbolsAsIterator(Address) <.getSymbolsAsIterator>` instead.
        
        :param ghidra.program.model.address.Address addr: the address of the symbols
        :return: an array, possibly empty, of the symbols at the given address
        :rtype: jpype.JArray[Symbol]
        
        .. seealso::
        
            | :obj:`.getSymbolsAsIterator(Address)`
        """

    @typing.overload
    def getSymbols(self, namespace: Namespace) -> SymbolIterator:
        """
        Get an iterator over all the symbols in the given namespace
         
        
        **NOTE:** The resulting iterator will not return default thunks (i.e., thunk function
        symbol with default source type).
        
        :param Namespace namespace: the namespace to search for symbols
        :return: an iterator over the symbols
        :rtype: SymbolIterator
        :raises IllegalArgumentException: if the given parent namespace is from a different program
                    than that of this symbol table
        """

    @typing.overload
    def getSymbols(self, namespaceID: typing.Union[jpype.JLong, int]) -> SymbolIterator:
        """
        Get an iterator over all the symbols in the given namespace
         
        
        **NOTE:** The resulting iterator will not return default thunks (i.e., thunk function
        symbol with default source type).
        
        :param jpype.JLong or int namespaceID: the namespace ID to search for symbols.
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    @typing.overload
    def getSymbols(self, addressSet: ghidra.program.model.address.AddressSetView, type: SymbolType, forward: typing.Union[jpype.JBoolean, bool]) -> SymbolIterator:
        """
        Get all the symbols of the given type within the given address set.
         
        
        **NOTE:** All external symbols will be omiitted unless the full 
        :obj:`AddressSpace.EXTERNAL_SPACE` range is included within the specified address set
        or a null addressSet is specified.  All global dynamic label symbols will be omitted.
        
        :param ghidra.program.model.address.AddressSetView addressSet: the address set containing the symbols.  A null value may be specified
        to include all memory and external primary symbols.
        :param SymbolType type: the type of the symbols
        :param jpype.JBoolean or bool forward: the direction of the iterator, by address
        :return: symbol iterator
        :rtype: SymbolIterator
        """

    def getSymbolsAsIterator(self, addr: ghidra.program.model.address.Address) -> SymbolIterator:
        """
        Get an iterator over the symbols at the given address.  Any dynamic symbol at the address
        will be excluded.
         
        
        Use this instead of :meth:`getSymbols(Address) <.getSymbols>` when you do not need to get all symbols, but
        rather are searching for a particular symbol. This method prevents all symbols at the given
        address from being loaded up front.
        
        :param ghidra.program.model.address.Address addr: the address of the symbols
        :return: an iterator over the symbols at the given address
        :rtype: SymbolIterator
        
        .. seealso::
        
            | :obj:`.getSymbols(Address)`
        """

    def getUserSymbols(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Symbol]:
        """
        Get an array of defined symbols at the given address (i.e., those with database record).  
        Any dynamic memory symbol at the address will be excluded. 
         
        
        **WARNING!**
        Use of this method with non-memory addresses is discouraged.  Example: Variable
        address could be used multiple times by many functions. 
         
        
        **NOTE:** unless all the symbols are needed at once, consider using 
        :meth:`getSymbolsAsIterator(Address) <.getSymbolsAsIterator>` instead.
        
        :param ghidra.program.model.address.Address addr: the address of the symbols
        :return: an array, possibly empty, of the symbols
        :rtype: jpype.JArray[Symbol]
        """

    def getVariableSymbol(self, name: typing.Union[java.lang.String, str], function: ghidra.program.model.listing.Function) -> Symbol:
        """
        Get a symbol that is either a parameter or local variable.
         
        
        There can be only one because these symbol types have a unique name requirement.
        
        :param java.lang.String or str name: the name of the variable
        :param ghidra.program.model.listing.Function function: the function to search
        :return: a parameter or local variable symbol with the given name
        :rtype: Symbol
        """

    def hasLabelHistory(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if there is a history of label changes at the given address
        
        :param ghidra.program.model.address.Address addr: the address to check
        :return: true if a label history exists for specified address, otherwise false
        :rtype: bool
        """

    def hasSymbol(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if there exists any symbol at the given address
        
        :param ghidra.program.model.address.Address addr: address to check for an existing symbol
        :return: true if any symbol exists
        :rtype: bool
        """

    def isExternalEntryPoint(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if the given address is an external entry point
        
        :param ghidra.program.model.address.Address addr: address to check
        :return: true if specified address has been marked as an entry point, otherwise false
        :rtype: bool
        """

    def removeExternalEntryPoint(self, addr: ghidra.program.model.address.Address):
        """
        Remove an address from the external entry points
        
        :param ghidra.program.model.address.Address addr: the address to remove
        """

    def removeSymbolSpecial(self, sym: Symbol) -> bool:
        """
        Removes the specified symbol from the symbol table.
         
        
        If removing any **non-function** symbol, the behavior will be the same as invoking
        :meth:`Symbol.delete() <Symbol.delete>` on the symbol. Use of this method for non-function symbols is
        discouraged.
         
        
        **WARNING!** If removing a function symbol, the behavior differs from directly invoking
        :meth:`Symbol.delete() <Symbol.delete>` on the function symbol. When removing a function symbol this method
        has the following behavior:
         
        * If the function is a default symbol (e.g., FUN_12345678) this method has no effect and
        will return false.
        * If no other labels exist at the function entry, the function will be renamed to the
        default function name.
        * If another label does exist at the function entry point, that label will be removed, and
        the function will be renamed to that label's name.
        
         
        
        Any reference bound to a removed symbol will lose that symbol specific binding.
        
        :param Symbol sym: the symbol to be removed.
        :return: true if a symbol is removed, false if not or in case of failure
        :rtype: bool
        """

    def scanSymbolsByName(self, startName: typing.Union[java.lang.String, str]) -> SymbolIterator:
        """
        Scan symbols lexicographically by name
         
        
        If a symbol with the given start name does not exist, the iterator will start at the first
        symbol following it. This includes only symbols whose addresses are in memory. In particular,
        it excludes external symbols and dynamic symbols, i.e., those generated as a reference
        destination.
        
        :param java.lang.String or str startName: the starting point
        :return: an iterator over the symbols in lexicographical order
        :rtype: SymbolIterator
        """

    @property
    def symbol(self) -> Symbol:
        ...

    @property
    def externalEntryPoint(self) -> jpype.JBoolean:
        ...

    @property
    def classNamespaces(self) -> java.util.Iterator[ghidra.program.model.listing.GhidraClass]:
        ...

    @property
    def allSymbols(self) -> SymbolIterator:
        ...

    @property
    def userSymbols(self) -> jpype.JArray[Symbol]:
        ...

    @property
    def definedSymbols(self) -> SymbolIterator:
        ...

    @property
    def symbolIterator(self) -> SymbolIterator:
        ...

    @property
    def externalSymbols(self) -> SymbolIterator:
        ...

    @property
    def symbols(self) -> SymbolIterator:
        ...

    @property
    def labelHistory(self) -> jpype.JArray[LabelHistory]:
        ...

    @property
    def symbolsAsIterator(self) -> SymbolIterator:
        ...

    @property
    def externalSymbol(self) -> Symbol:
        ...

    @property
    def globalSymbols(self) -> java.util.List[Symbol]:
        ...

    @property
    def children(self) -> SymbolIterator:
        ...

    @property
    def numSymbols(self) -> jpype.JInt:
        ...

    @property
    def externalEntryPointIterator(self) -> ghidra.program.model.address.AddressIterator:
        ...

    @property
    def namespace(self) -> Namespace:
        ...

    @property
    def librarySymbol(self) -> Symbol:
        ...

    @property
    def dynamicSymbolID(self) -> jpype.JLong:
        ...

    @property
    def primarySymbolIterator(self) -> SymbolIterator:
        ...

    @property
    def primarySymbol(self) -> Symbol:
        ...


class IllegalCharCppTransformer(NameTransformer):
    """
    Replace illegal characters in the given name with '_'.  The transformer treats the name as a
    C++ symbol. Letters and digits are generally legal. '~' is allowed at the start of the symbol.
    Template parameters, surrounded by '<' and '>', allow additional special characters. 
    Certain special characters are allowed after the keyword "operator".
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceListener(java.lang.Object):
    """
    Interface to define methods that are called when references are
    added or removed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def externalReferenceAdded(self, ref: Reference):
        """
        Notification that the given external reference has been added.
        
        :param Reference ref: the external reference that was added.
        """

    def externalReferenceNameChanged(self, ref: Reference):
        """
        Notification that the external program name in the reference
        has changed.
        
        :param Reference ref: the external reference with its new external name.
        """

    def externalReferenceRemoved(self, ref: Reference):
        """
        Notification that the given external reference has been removed.
        
        :param Reference ref: the external reference that was removed.
        """

    def memReferenceAdded(self, ref: Reference):
        """
        Notification that the given memory reference has been added.
        
        :param Reference ref: the reference that was added.
        """

    def memReferencePrimaryRemoved(self, ref: Reference):
        """
        Notification that the given memory reference is no longer the primary
        reference.
        
        :param Reference ref: the reference that was primary but now is not.
        """

    def memReferencePrimarySet(self, ref: Reference):
        """
        Notification that the given memory reference has been set as
        the primary reference.
        
        :param Reference ref: the reference that is now primary.
        """

    def memReferenceRemoved(self, ref: Reference):
        """
        Notification that the given memory reference has bee removed.
        
        :param Reference ref: the reference that was removed.
        """

    def memReferenceTypeChanged(self, newRef: Reference, oldRef: Reference):
        """
        Notification that the reference type on the given memory reference
        has changed.
        
        :param Reference newRef: the reference with the new reference type.
        :param Reference oldRef: the reference with the old reference type.
        """

    def stackReferenceAdded(self, ref: Reference):
        """
        Notification that the given stack reference has been added.
        
        :param Reference ref: the stack reference that was added.
        """

    def stackReferenceRemoved(self, ref: Reference):
        """
        Notification tbat the given stack reference has been removed.
        
        :param Reference ref: The stack reference that was removed
        """


class EquateReference(java.lang.Object):
    """
    Interface to define an equate reference. Equate references consist of an 
    address and an operand index.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address associated with this reference.
        """

    def getDynamicHashValue(self) -> int:
        """
        Returns the dynamic Hash value associated with the referenced constant varnode.
        A value of zero (0) indicates not applicable.
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.pcode.DynamicHash`
        """

    def getOpIndex(self) -> int:
        """
        Returns the opcode index for the instruction located at this
        references address, or -1 if .
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def opIndex(self) -> jpype.JShort:
        ...

    @property
    def dynamicHashValue(self) -> jpype.JLong:
        ...


class SymbolIteratorAdapter(SymbolIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[Symbol]):
        ...


class SymbolIterator(java.util.Iterator[Symbol], java.lang.Iterable[Symbol]):
    """
    Iterator defined to return Symbol objects.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ITERATOR: typing.Final[SymbolIterator]

    def hasNext(self) -> bool:
        """
        Return true if there is a next symbol.
        """

    def next(self) -> Symbol:
        """
        Get the next symbol or null if no more symbols.
         
        NOTE: This deviates from the standard :obj:`Iterator` interface
        by returning null instead of throwing an exception.
        """


class FlowType(RefType):
    """
    Class to define flow types for instruction (how it
    flows from one instruction to the next)
    """

    @typing.type_check_only
    class Builder(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ExternalLocationAdapter(ExternalLocationIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: java.util.Iterator[ExternalLocation]):
        ...


class OffsetReference(Reference):
    """
    ``OffsetReference`` is a memory reference whose "to" address is
    computed from a base address plus an offset.
     
    
    NOTE: References into the reserved EXTERNAL block must report :meth:`getToAddress() <.getToAddress>`
    the same as :meth:`getBaseAddress() <.getBaseAddress>` regardless of offset value due to symbol
    spacing limitations within the EXTERNAL block.  See :obj:`MemoryBlock.EXTERNAL_BLOCK_NAME`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the base address.
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getOffset(self) -> int:
        """
        Returns the offset.
        
        :return: the offset
        :rtype: int
        """

    def getToAddress(self) -> ghidra.program.model.address.Address:
        """
        Return the base address plus the offset.  The exception to this is the
        EXTERNAL block case where this method returns the base address regardless
        of the offset value.
        
        :return: reference "to" address
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def baseAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def toAddress(self) -> ghidra.program.model.address.Address:
        ...


class Symbol(java.lang.Object):
    """
    Interface for a symbol, which associates a string value with
    an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self) -> bool:
        """
        Delete the symbol and its associated resources.  Any references symbol associations
        will be discarded.
        
        :return: true if successful
        :rtype: bool
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the address for the symbol.
        :rtype: ghidra.program.model.address.Address
        """

    def getID(self) -> int:
        """
        
        
        :return: this symbol's ID.
        :rtype: int
        """

    @typing.overload
    def getName(self) -> str:
        """
        
        
        :return: the name of this symbol.
        :rtype: str
        """

    @typing.overload
    def getName(self, includeNamespace: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the symbol name, optionally prepended with the namespace path.
        
        :param jpype.JBoolean or bool includeNamespace: if true, the namespace path is prepended to the name.
        :return: formatted name
        :rtype: str
        """

    def getObject(self) -> java.lang.Object:
        """
        
        
        :return: object associated with this symbol or null if symbol has been deleted
        :rtype: java.lang.Object
        """

    def getParentNamespace(self) -> Namespace:
        """
        Return the parent namespace for this symbol.
        
        :return: the namespace that contains this symbol.
        :rtype: Namespace
        """

    def getParentSymbol(self) -> Symbol:
        """
        Returns namespace symbol of the namespace containing this symbol
        
        :return: parent namespace symbol
        :rtype: Symbol
        """

    def getPath(self) -> jpype.JArray[java.lang.String]:
        """
        Gets the full path name for this symbol as an ordered array of strings ending
        with the symbol name.
        
        :return: the array indicating the full path name for this symbol.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program associated with this symbol
        
        :return: the program associated with this symbol.
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns a program location for this symbol; may be null.  This allows implementations to 
        return a more specific program location than what is typically used by the system.
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getReferenceCount(self) -> int:
        """
        
        
        :return: the number of References to this symbol.
        :rtype: int
        """

    @typing.overload
    def getReferences(self, monitor: ghidra.util.task.TaskMonitor) -> jpype.JArray[Reference]:
        """
        Returns all memory references to the address of this symbol.  If you do not have a
        :obj:`TaskMonitor` instance, then you can pass :obj:`TaskMonitor.DUMMY` or
        ``null``.
        
        :return: all memory references to the address of this symbol.
        :rtype: jpype.JArray[Reference]
        :param ghidra.util.task.TaskMonitor monitor: the monitor that is used to report progress and to cancel this
                potentially long-running call
        """

    @typing.overload
    def getReferences(self) -> jpype.JArray[Reference]:
        """
        Returns all memory references to the address of this symbol.
        
        :return: all memory references to the address of this symbol
        :rtype: jpype.JArray[Reference]
        
        .. seealso::
        
            | :obj:`.getReferences(TaskMonitor)`
        """

    def getSource(self) -> SourceType:
        """
        Gets the source of this symbol.
        :obj:`SourceType`
        
        :return: the source of this symbol
        :rtype: SourceType
        """

    def getSymbolType(self) -> SymbolType:
        """
        Returns this symbol's type
        
        :return: symbol type
        :rtype: SymbolType
        """

    def hasMultipleReferences(self) -> bool:
        """
        
        
        :return: true if this symbol has more than one reference to it.
        :rtype: bool
        """

    def hasReferences(self) -> bool:
        """
        
        
        :return: true if this symbol has at least one reference to it.
        :rtype: bool
        """

    def isDeleted(self) -> bool:
        """
        Determine if this symbol object has been deleted.  NOTE: the symbol could be
        deleted at anytime due to asynchronous activity.
        
        :return: true if symbol has been deleted, false if not.
        :rtype: bool
        """

    def isDescendant(self, namespace: Namespace) -> bool:
        """
        Returns true if the given namespace symbol is a descendant of this symbol.
        
        :param Namespace namespace: to test as descendant symbol of this Symbol
        :return: true if this symbol is an ancestor of the given namespace symbol
        :rtype: bool
        """

    def isDynamic(self) -> bool:
        """
        
        
        :return: true if this symbol is a dynamic symbol (not actually defined in the database).
        :rtype: bool
        """

    def isExternal(self) -> bool:
        """
        Returns true if this an external symbol.
        
        :return: true if this an external symbol.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`Address.isExternalAddress()`
        """

    def isExternalEntryPoint(self) -> bool:
        """
        
        
        :return: true if the symbol is at an address
        set as a external entry point.
        :rtype: bool
        """

    def isGlobal(self) -> bool:
        """
        
        
        :return: true if the symbol is global
        :rtype: bool
        """

    def isPinned(self) -> bool:
        """
        Returns true if the symbol is pinned to its current address. If it is pinned, then moving
        or removing the memory associated with that address will not affect this symbol.
        
        :return: true if the symbol is pinned to its current address.
        :rtype: bool
        """

    def isPrimary(self) -> bool:
        """
        
        
        :return: true if this symbol is primary
        :rtype: bool
        """

    def isValidParent(self, parent: Namespace) -> bool:
        """
        Determines if the given parent is valid for this Symbol.  Specified namespace 
        must belong to the same symbol table as this symbol.
        
        :param Namespace parent: prospective parent namespace for this symbol
        :return: true if parent is valid
        :rtype: bool
        """

    def setName(self, newName: typing.Union[java.lang.String, str], source: SourceType):
        """
        Sets the name this symbol.
        If this symbol is dynamic, then the name is set
        and the symbol is no longer dynamic.
        
        :param java.lang.String or str newName: the new name for this symbol.
        :param SourceType source: the source of this symbol
         
        Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
        :raises DuplicateNameException: if name already exists as the name of another symbol or alias.
        :raises InvalidInputException: if alias contains blank characters, is zero length, or is null
        :raises IllegalArgumentException: if you try to set the source to DEFAULT for a symbol type
        that doesn't allow it.
        """

    def setNameAndNamespace(self, newName: typing.Union[java.lang.String, str], newNamespace: Namespace, source: SourceType):
        """
        Sets the symbols name and namespace.  This is provided to allow the caller to
        avoid a name conflict by creating an autonomous action.
        
        :param java.lang.String or str newName: new symbol name
        :param Namespace newNamespace: new parent namespace
        :param SourceType source: the source of this symbol
         
        Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
        :raises DuplicateNameException: if newNamespace already contains a symbol
        with this symbol's name
        :raises InvalidInputException: is newNamespace is not a valid parent for
        this symbol
        :raises CircularDependencyException: if this symbol is an ancestor of
        newNamespace
        """

    def setNamespace(self, newNamespace: Namespace):
        """
        Sets the symbols namespace
        
        :param Namespace newNamespace: new parent namespace
        :raises DuplicateNameException: if newNamespace already contains a symbol
        with this symbol's name
        :raises InvalidInputException: is newNamespace is not a valid parent for
        this symbol
        :raises CircularDependencyException: if this symbol is an ancestor of
        newNamespace
        """

    def setPinned(self, pinned: typing.Union[jpype.JBoolean, bool]):
        """
        
        Sets whether or not this symbol is pinned to its associated address.
        
        
         
        If the symbol is pinned then moving or removing the memory associated with its address will
        not cause this symbol to be removed and will not cause its address to change.
        If the symbol is not pinned, then removing the memory at its address will also remove this
        symbol.
        
        
         
        Likewise, moving a memory block containing a symbol that is not anchored will change
        the address for that symbol to keep it associated with the same byte in the memory block.
        
        
        :param jpype.JBoolean or bool pinned: true indicates this symbol is anchored to its address.
                false indicates this symbol is not anchored to its address.
        """

    def setPrimary(self) -> bool:
        """
        Sets this symbol to be primary. All other symbols at the same address will be set to 
        !primary.  Only applies to non-function symbols.
        
        :return: returns true if the symbol was not primary and now it is, otherwise false
        :rtype: bool
        """

    def setSource(self, source: SourceType):
        """
        Sets the source of this symbol.
        :obj:`SourceType`
        
        :param SourceType source: the new source of this symbol
        """

    @property
    def pinned(self) -> jpype.JBoolean:
        ...

    @pinned.setter
    def pinned(self, value: jpype.JBoolean):
        ...

    @property
    def externalEntryPoint(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def references(self) -> jpype.JArray[Reference]:
        ...

    @property
    def parentSymbol(self) -> Symbol:
        ...

    @property
    def parentNamespace(self) -> Namespace:
        ...

    @property
    def global_(self) -> jpype.JBoolean:
        ...

    @property
    def descendant(self) -> jpype.JBoolean:
        ...

    @property
    def source(self) -> SourceType:
        ...

    @source.setter
    def source(self, value: SourceType):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def symbolType(self) -> SymbolType:
        ...

    @property
    def validParent(self) -> jpype.JBoolean:
        ...

    @property
    def path(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def external(self) -> jpype.JBoolean:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def referenceCount(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...

    @property
    def object(self) -> java.lang.Object:
        ...


class EntryPointReference(Reference):
    """
    Reference object for entry points
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ThunkReference", "Equate", "StackReference", "Reference", "LabelHistory", "AddressLabelPair", "RefTypeFactory", "SymbolType", "DataRefType", "ReferenceIteratorAdapter", "SourceType", "RefType", "SymbolTableListener", "SymbolUtilities", "ExternalPath", "NameTransformer", "ReferenceManager", "IdentityNameTransformer", "ExternalManager", "ExternalReference", "EquateTable", "Namespace", "DynamicReference", "ShiftedReference", "ReferenceIterator", "ExternalLocation", "MemReferenceImpl", "ExternalLocationIterator", "SymbolTable", "IllegalCharCppTransformer", "ReferenceListener", "EquateReference", "SymbolIteratorAdapter", "SymbolIterator", "FlowType", "ExternalLocationAdapter", "OffsetReference", "Symbol", "EntryPointReference"]
