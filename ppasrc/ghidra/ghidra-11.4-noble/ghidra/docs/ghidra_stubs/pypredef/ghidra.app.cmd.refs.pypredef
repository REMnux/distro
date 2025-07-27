from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang # type: ignore


class SetExternalNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting the external program name and path.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, externalName: typing.Union[java.lang.String, str], externalPath: typing.Union[java.lang.String, str]):
        """
        Constructs a new command for setting the external program name and path.
        
        :param java.lang.String or str externalName: the name of the link.
        :param java.lang.String or str externalPath: the path of the file to associate with this link.
        """


class AddMemRefsCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    ``AddMemRefsCmd`` adds a set of memory references from a
    specified address and opIndex to all code units identified by a 
    set of addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, toSet: ghidra.program.model.address.AddressSetView, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]):
        """
        Add memory references.
        
        :param ghidra.program.model.address.Address fromAddr: reference source
        :param ghidra.program.model.address.AddressSetView toSet: set of addresses which make up reference destinations.
        Only those addresses on code where a code unit exists will be considered.
        :param ghidra.program.model.symbol.RefType refType: reference type to be applied.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: source operand index
        """


class RemoveExternalRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for removing external references.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for removing an external reference.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the external reference.
        :param jpype.JInt or int opIndex: the operand index.
        """


class AddExternalNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to update the name for an external program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding the name of an external program.
        
        :param java.lang.String or str name: the new name to be used for the external program link.
        :param ghidra.program.model.symbol.SourceType source: the source of this external name
        """


class EditRefTypeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to change the reference type of a memory reference
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ref: ghidra.program.model.symbol.Reference, newRefType: ghidra.program.model.symbol.RefType):
        """
        Constructs a new command for changing the reference type of a reference.
        
        :param ghidra.program.model.symbol.Reference ref: the reference whose type it to be changed.
        :param ghidra.program.model.symbol.RefType newRefType: the ref type to assign to the reference.
        """


class ClearFallThroughCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to clear a fallthrough.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instAddr: ghidra.program.model.address.Address):
        """
        Constructs a new command to remove a fallthrough.
        
        :param ghidra.program.model.address.Address instAddr: the address of the instruction from which to remove the
        fallthrough.
        """


class RemoveExternalNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to remove an external program name from the reference manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, externalName: typing.Union[java.lang.String, str]):
        """
        Constructs a new command removing an external program name.
        
        :param java.lang.String or str externalName: the name of the external program name to be removed.
        """


class RemoveReferenceCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for removing memory references.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference):
        """
        Constructs a new command for removing a memory reference.
        
        :param ghidra.program.model.symbol.Reference ref: the reference to remove
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for removing a memory reference.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        :param ghidra.program.model.address.Address toAddr: the address being referred to.
        :param jpype.JInt or int opIndex: the operand index.
        """


class AssociateSymbolCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class for associating a reference with a specific label
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference, scope: ghidra.program.model.symbol.Namespace):
        """
        Constructor.
        
        :param ghidra.program.model.symbol.Reference ref: the reference to associate with a symbol
        :param ghidra.program.model.symbol.Namespace scope: scope that has the symbol to associate with the reference
        """

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference, symbolName: typing.Union[java.lang.String, str], scope: ghidra.program.model.symbol.Namespace):
        """
        Constructor
        
        :param ghidra.program.model.symbol.Reference ref: the reference to associate with a symbol
        :param java.lang.String or str symbolName: the name of the symbol with which to associate the reference.
        :param ghidra.program.model.symbol.Namespace scope: scope of the symbol with the given symbolName
        """

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference, symbolName: typing.Union[java.lang.String, str]):
        """
        Create a associate symbol command for a global symbol
        
        :param ghidra.program.model.symbol.Reference ref: the reference to associate with a symbol
        :param java.lang.String or str symbolName: the name of the symbol with which to associate the reference.
        """


class AddOffsetMemRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class to add an offset memory reference to the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, toAddrIsBase: typing.Union[jpype.JBoolean, bool], refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JLong, int]):
        """
        Command constructor for adding an offset memory reference. The first memory reference placed on
        an operand will be made primary by default.  All non-memory references 
        will be removed from the specified operand.  If toAddr corresponds to
        the EXTERNAL memory block (see :obj:`MemoryBlock.EXTERNAL_BLOCK_NAME`) the
        resulting offset reference will report to/base address as the same
        regardless of specified offset.
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.
        :param jpype.JBoolean or bool toAddrIsBase: if true toAddr is treated as base address, else treated as (base+offet).
        It is generally preferred to specify as a base address to ensure proper handling of
        EXTERNAL block case.
        :param ghidra.program.model.symbol.RefType refType: reference type - how the location is being referenced.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: the operand index in the code unit where the reference occurs
        :param jpype.JLong or int offset: value added to a base address to get the toAddr
        """


class SetFallThroughCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting the fallthrough property on an instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instAddr: ghidra.program.model.address.Address, fallthroughAddr: ghidra.program.model.address.Address):
        """
        Constructs a new command for setting the fallthrough property on an instruction.
        
        :param ghidra.program.model.address.Address instAddr: the address of the instruction whose fallthrought property is
        to be set.
        :param ghidra.program.model.address.Address fallthroughAddr: the address to use for the instructions fallthrough.
        """


class AddStackRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class for adding stack references to a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a stack reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address within a function
        :param jpype.JInt or int opIndex: operand index
        :param jpype.JInt or int stackOffset: stack offset of the reference
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a stack reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address within a function
        :param jpype.JInt or int opIndex: operand index
        :param jpype.JInt or int stackOffset: stack offset of the reference
        :param ghidra.program.model.symbol.RefType refType: reference type (e.g., STACK_READ or STACK_WRITE)
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        """


class AddRegisterRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class to add a register reference to the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], reg: ghidra.program.model.lang.Register, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a register reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address
        :param jpype.JInt or int opIndex: operand index
        :param ghidra.program.model.lang.Register reg: register to add the reference to
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], reg: ghidra.program.model.lang.Register, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a register reference.
        
        :param ghidra.program.model.address.Address fromAddr: "from" address
        :param jpype.JInt or int opIndex: operand index
        :param ghidra.program.model.lang.Register reg: register to add the reference to
        :param ghidra.program.model.symbol.RefType refType: reference type or null to use a default RefType
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        """


class RemoveAllReferencesCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to remove all references at an address or for a particular operand 
    index at an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address):
        """
        Constructs a new command for removing all references.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for removing all references.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        :param jpype.JInt or int opIndex: the operand index.
        """


class ClearExternalNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to remove an external program name from the reference manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, externalName: typing.Union[java.lang.String, str]):
        """
        Constructs a new command removing an external program name.
        
        :param java.lang.String or str externalName: the name of the external program name to be removed.
        """


class SetExternalRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class for adding external references.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], extName: typing.Union[java.lang.String, str], extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding external references.
        
        :param ghidra.program.model.address.Address fromAddr: from address (source of the reference)
        :param jpype.JInt or int opIndex: operand index
        :param java.lang.String or str extName: name of external program
        :param java.lang.String or str extLabel: label within the external program, may be null if extAddr is not null
        :param ghidra.program.model.address.Address extAddr: address within the external program, may be null
        :param ghidra.program.model.symbol.RefType refType: reference type (NOTE: data/pointer should generally utilize :obj:`RefType.DATA`
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        """

    @typing.overload
    @deprecated("the other constructor form should be used with an appropriate RefType specified.\n RefType.DATA should be used for address table pointer references.")
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], extName: typing.Union[java.lang.String, str], extLabel: typing.Union[java.lang.String, str], extAddr: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding an external reference from data using :obj:`RefType.DATA`.
        
        :param ghidra.program.model.address.Address fromAddr: from address (source of the reference)
        :param jpype.JInt or int opIndex: operand index
        :param java.lang.String or str extName: name of external program
        :param java.lang.String or str extLabel: label within the external program, may be null if extAddr is not null
        :param ghidra.program.model.address.Address extAddr: address within the external program, may be null
        :param ghidra.program.model.symbol.SourceType source: the source of this reference
        
        .. deprecated::
        
        the other constructor form should be used with an appropriate RefType specified.
        :obj:`RefType.DATA` should be used for address table pointer references.
        """


class UpdateExternalNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to update the name for an external program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for updating the name of an external program.
        
        :param java.lang.String or str oldName: the current name of the external program link.
        :param java.lang.String or str newName: the new name to be used for the external program link.
        :param ghidra.program.model.symbol.SourceType source: the source of this external name
        """


class AddShiftedMemRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class to add a shifted memory reference to the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int], shift: typing.Union[jpype.JInt, int]):
        """
        Command constructor for adding a shifted memory reference
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: computed as the value of the operand at opIndex shifted
        by the number of bits specified by shiftValue
        :param ghidra.program.model.symbol.RefType refType: reference type - how the location is being referenced.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: the operand index in the code unit where the reference occurs
        :param jpype.JInt or int shift: the number of bits to shift the value by
        """


class AddMemRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class to add a memory reference to the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int], setPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Command constructor for adding a memory reference with a default refType
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: the operand index in the code unit where the reference occurs
        :param jpype.JBoolean or bool setPrimary: true if this reference should be primary.
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int]):
        """
        Command constructor for adding a memory reference
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.
        :param ghidra.program.model.symbol.RefType refType: reference type - how the location is being referenced.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: the operand index in the code unit where the reference occurs
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: typing.Union[jpype.JInt, int], setPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Command constructor for adding a memory reference
        
        :param ghidra.program.model.address.Address fromAddr: address of the codeunit where the reference occurs
        :param ghidra.program.model.address.Address toAddr: address of the location being referenced.
        :param ghidra.program.model.symbol.RefType refType: reference type - how the location is being referenced.
        :param ghidra.program.model.symbol.SourceType source: the source of the reference
        :param jpype.JInt or int opIndex: the operand index in the code unit where the reference occurs
        :param jpype.JBoolean or bool setPrimary: set the newly added reference primary
        """


class SetPrimaryRefCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command class for setting a reference to be primary.  Any other
    reference that was primary at that address will no longer be primary.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference, isPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a command for setting whether or not a reference is the primary reference.
        If isPrimary is true, any other reference that was primary at that 
        address will no longer be primary.
        
        :param ghidra.program.model.symbol.Reference ref: the reference
        :param jpype.JBoolean or bool isPrimary: true to make the reference primary, false to make it non-primary
        """

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], toAddr: ghidra.program.model.address.Address, isPrimary: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a command for setting whether or not a reference is the primary reference.
        If isPrimary is true, any other reference that was primary at that 
        address will no longer be primary.
        
        :param ghidra.program.model.address.Address fromAddr: the address of the codeunit making the reference.
        :param jpype.JInt or int opIndex: the operand index.
        :param ghidra.program.model.address.Address toAddr: the address being referred to.
        :param jpype.JBoolean or bool isPrimary: true to make the reference primary, false to make it non-primary
        """



__all__ = ["SetExternalNameCmd", "AddMemRefsCmd", "RemoveExternalRefCmd", "AddExternalNameCmd", "EditRefTypeCmd", "ClearFallThroughCmd", "RemoveExternalNameCmd", "RemoveReferenceCmd", "AssociateSymbolCmd", "AddOffsetMemRefCmd", "SetFallThroughCmd", "AddStackRefCmd", "AddRegisterRefCmd", "RemoveAllReferencesCmd", "ClearExternalNameCmd", "SetExternalRefCmd", "UpdateExternalNameCmd", "AddShiftedMemRefCmd", "AddMemRefCmd", "SetPrimaryRefCmd"]
