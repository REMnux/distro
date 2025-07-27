from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.cache
import generic.concurrent
import ghidra.app.decompiler
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class CreateFunctionDefinitionCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for creating a function definition data type based on the
    function signature for a function at an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entry: ghidra.program.model.address.Address, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        """
        Constructs a new command for creating a function definition.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function whose signature is to 
        be used to create the function defintion data type.
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: optional service provider (may be null).  If specified and the 
        :obj:`DataTypeManagerService` is found, the newly created function definition
        will be selected within the GUI.
        """


class ApplyFunctionSignatureCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command to create apply a function signature at an address.
    
    :obj:`Function` signature changes are applied using 
    :meth:`Function.updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType) <Function.updateFunction>`
    with an update type of :obj:`FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, signature: ghidra.program.model.listing.FunctionSignature, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for applying a signature to an existing function.
         
        
        Only a function with a default name will be renamed to the function signature's name
        (see :obj:`FunctionRenameOption.RENAME_IF_DEFAULT`).
         
        
        All datatypes will be resolved using the 
        :obj:`default conflict handler <DataTypeConflictHandler.DEFAULT_HANDLER>`.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.listing.FunctionSignature signature: function signature to apply
        :param ghidra.program.model.symbol.SourceType source: the source of this function signature
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, signature: ghidra.program.model.listing.FunctionSignature, source: ghidra.program.model.symbol.SourceType, preserveCallingConvention: typing.Union[jpype.JBoolean, bool], forceSetName: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for applying a signature to an existing function.
         
        
        All datatypes will be resolved using the 
        :obj:`default conflict handler <DataTypeConflictHandler.DEFAULT_HANDLER>`.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.listing.FunctionSignature signature: function signature to apply
        :param ghidra.program.model.symbol.SourceType source: the source of this function signature
        :param jpype.JBoolean or bool preserveCallingConvention: if true the function calling convention will not be changed
        :param jpype.JBoolean or bool forceSetName: true if name of the function should be set to the name, otherwise name
                            will only be set name if currently default (e.g., FUN_1234). A value of 
                            true is equivalent to :obj:`FunctionRenameOption.RENAME`, while a value
                            of false is equivalent to :obj:`FunctionRenameOption.RENAME_IF_DEFAULT`.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, signature: ghidra.program.model.listing.FunctionSignature, source: ghidra.program.model.symbol.SourceType, preserveCallingConvention: typing.Union[jpype.JBoolean, bool], functionRenameOption: FunctionRenameOption):
        """
        Constructs a new command for applying a signature to an existing function.
         
        
        All datatypes will be resolved using the 
        :obj:`default conflict handler <DataTypeConflictHandler.DEFAULT_HANDLER>`.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.listing.FunctionSignature signature: function signature to apply
        :param ghidra.program.model.symbol.SourceType source: the source of this function signature
        :param jpype.JBoolean or bool preserveCallingConvention: if true the function calling convention will not be changed
        :param FunctionRenameOption functionRenameOption: controls renaming of the function using the name from the 
                            specified function signature.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, signature: ghidra.program.model.listing.FunctionSignature, source: ghidra.program.model.symbol.SourceType, preserveCallingConvention: typing.Union[jpype.JBoolean, bool], applyEmptyComposites: typing.Union[jpype.JBoolean, bool], conflictHandler: ghidra.program.model.data.DataTypeConflictHandler, functionRenameOption: FunctionRenameOption):
        """
        Constructs a new command for applying a signature to an existing function.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.listing.FunctionSignature signature: function signature to apply
        :param ghidra.program.model.symbol.SourceType source: the source of this function signature
        :param jpype.JBoolean or bool preserveCallingConvention: if true the function calling convention will not be changed
        :param jpype.JBoolean or bool applyEmptyComposites: If true, applied composites will be resolved without their
                                respective components if the type does not already exist in the 
                                destination datatype manager.  If false, normal type resolution 
                                will occur.
        :param ghidra.program.model.data.DataTypeConflictHandler conflictHandler: conflict handler to be used when applying datatypes to the
                                destination program.  If this value is not null or 
                                :obj:`DataTypeConflictHandler.DEFAULT_HANDLER` the datatypes will be 
                                resolved prior to updating the destinationFunction.  This handler
                                will provide some control over how applied datatype are handled when 
                                they conflict with existing datatypes. 
                                See :obj:`DataTypeConflictHandler` which provides some predefined
                                handlers.
        :param FunctionRenameOption functionRenameOption: controls renaming of the function using the name from the 
                                specified function signature.
        """


class DeleteVariableCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for deleting a variable in a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, var: ghidra.program.model.listing.Variable):
        ...


@deprecated("function signatures should be modified in their entirety using \n either UpdateFunctionCommand or ApplyFunctionSignatureCmd.")
class AddRegisterParameterCommand(AddParameterCommand):
    """
    A command to create a new function register parameter.
    
    
    .. deprecated::
    
    function signatures should be modified in their entirety using 
    either :obj:`UpdateFunctionCommand` or :obj:`ApplyFunctionSignatureCmd`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, register: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, ordinal: typing.Union[jpype.JInt, int], source: ghidra.program.model.symbol.SourceType):
        ...


class FunctionStackAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for analyzing the Stack; the command is run in the background.
    NOTE: referenced thunk-functions should be created prior to this command
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.
        
        :param ghidra.program.model.address.AddressSetView entries: and address set indicating the entry points of functions that have 
        stacks to be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.
        
        :param ghidra.program.model.address.Address entry: the entry point of the function that contains the stack to
                be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, doParameterAnalysis: typing.Union[jpype.JBoolean, bool], doLocalAnalysis: typing.Union[jpype.JBoolean, bool], forceProcessing: typing.Union[jpype.JBoolean, bool]):
        ...


class FunctionPurgeAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for analyzing the Stack; the command is run in the background.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entries: ghidra.program.model.address.AddressSetView):
        """
        Constructs a new command for analyzing the Stack.
        
        :param ghidra.program.model.address.AddressSetView entries: and address set indicating the entry points of functions that have 
        stacks to be analyzed.
        """


class DeleteFunctionCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for clearing a function at an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address):
        """
        Constructs a new command for deleting a function.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be deleted.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, ignoreMissingFunction: typing.Union[jpype.JBoolean, bool]):
        ...


class ApplyFunctionDataTypesCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Apply all function signature data types in a data type manager to
    any user defined label that has the same name as the function
    signature.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, managers: java.util.List[ghidra.program.model.data.DataTypeManager], set: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType, alwaysReplace: typing.Union[jpype.JBoolean, bool], createBookmarksEnabled: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command to apply all function signature data types
        in the given data type manager.
        
        :param java.util.List[ghidra.program.model.data.DataTypeManager] managers: list of data type managers containing the function signature data types
        :param ghidra.program.model.address.AddressSetView set: set of addresses containing labels to match against function names.
                    The addresses must not already be included in the body of any existing function.
                    If null, all symbols will be processed
        :param ghidra.program.model.symbol.SourceType source: the source of this command.
        :param jpype.JBoolean or bool alwaysReplace: true to always replace the existing function signature with the
                                function signature data type.
        :param jpype.JBoolean or bool createBookmarksEnabled: true to create a bookmark when a function signature
                                        has been applied.
        """

    @typing.overload
    def __init__(self, sourceCategory: ghidra.program.model.data.Category, set: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType, alwaysReplace: typing.Union[jpype.JBoolean, bool], createBookmarksEnabled: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command to apply all function signature data types
        in the given data type category (includes all subcategories).
        
        :param ghidra.program.model.data.Category sourceCategory: datatype category containing the function signature data types
        :param ghidra.program.model.address.AddressSetView set: set of addresses containing labels to match against function names.
                    The addresses must not already be included in the body of any existing function.
                    If null, all symbols will be processed
        :param ghidra.program.model.symbol.SourceType source: the source of this command.
        :param jpype.JBoolean or bool alwaysReplace: true to always replace the existing function signature with the
                                function signature data type.
        :param jpype.JBoolean or bool createBookmarksEnabled: true to create a bookmark when a function signature
                                        has been applied.
        """


class SetVariableNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to rename a stack variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, var: ghidra.program.model.listing.Variable, newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to rename a stack/reg variable.
        
        :param ghidra.program.model.listing.Variable var: variable to rename
        :param java.lang.String or str newName: the new name to give to the stack variable.
        :param ghidra.program.model.symbol.SourceType source: the source of this variable name
        """

    @typing.overload
    def __init__(self, fnEntry: ghidra.program.model.address.Address, varName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to rename a stack/reg variable.
        
        :param ghidra.program.model.address.Address fnEntry: 
        :param java.lang.String or str varName: 
        :param java.lang.String or str newName: 
        :param ghidra.program.model.symbol.SourceType source:
        """


class SetFunctionNameCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set the name of a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entry: ghidra.program.model.address.Address, newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for setting the name of a function.
        
        :param ghidra.program.model.address.Address entry: the address of the function to be renamed.
        :param java.lang.String or str newName: the new name for the function.
        :param ghidra.program.model.symbol.SourceType source: the source of this function name
        """


class NewFunctionStackAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for analyzing the Stack; the command is run in the background.
    NOTE: referenced thunk-functions should be created prior to this command
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.  All stack references will be
        marked-up and local stack variables created.  Stack parameters are not created 
        by default to avoid setting an incomplete function signature.
        
        :param ghidra.program.model.address.AddressSetView entries: and address set indicating the entry points of functions that have 
        stacks to be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.  All stack references will be
        marked-up and local stack variables created.  Stack parameters are not created 
        by default to avoid setting an incomplete function signature.
        
        :param ghidra.program.model.address.Address entry: the entry point of the function that contains the stack to
                be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, createStackParams: typing.Union[jpype.JBoolean, bool], createLocalStackVars: typing.Union[jpype.JBoolean, bool], forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param ghidra.program.model.address.AddressSetView entries: 
        :param jpype.JBoolean or bool createStackParams: 
        :param jpype.JBoolean or bool createLocalStackVars: 
        :param jpype.JBoolean or bool forceProcessing:
        """


class CallDepthChangeInfo(java.lang.Object):
    """
    Given a function in a program or the start of a function, record information
    about the change to a stack pointer from a subroutine call. The routine
    getCallChange() can be called with the address of a call instruction. If the
    stack could be tracked, the call instruction will return the change in the
    stack pointer that would result from a call to the function.
     
    The computation is based on a set of equations that are generated and solved.
    Each equation represents the stack change for a given basic flow block or
    call instruction within the function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, func: ghidra.program.model.listing.Function):
        """
        Construct a new CallDepthChangeInfo object.
        Using this constructor will NOT track the stack depth at the start/end of each instruction.
        
        :param ghidra.program.model.listing.Function func: function to examine
        """

    @typing.overload
    def __init__(self, func: ghidra.program.model.listing.Function, storeDepthAtEachInstuction: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new CallDepthChangeInfo object.
        Allows calls to getRegDepth() and getRegValueRepresentation()
        
        :param ghidra.program.model.listing.Function func: function to examine
        :param jpype.JBoolean or bool storeDepthAtEachInstuction: true to track stack at start/end of each instruction. allowing
        a call to
        """

    @typing.overload
    def __init__(self, func: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new CallDepthChangeInfo object.
        
        :param ghidra.program.model.listing.Function func: function to examine
        :param ghidra.util.task.TaskMonitor monitor: used to cancel the operation
        :raises CancelledException: if the operation was canceled
        """

    @typing.overload
    def __init__(self, function: ghidra.program.model.listing.Function, restrictSet: ghidra.program.model.address.AddressSetView, frameReg: ghidra.program.model.lang.Register, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new CallDepthChangeInfo object.
        Using this constructor will track the stack depth at the start/end of each instruction.
        
        :param ghidra.program.model.listing.Function function: function to examine
        :param ghidra.program.model.address.AddressSetView restrictSet: set of addresses to restrict flow flowing to.
        :param ghidra.program.model.lang.Register frameReg: register that is to have it's depth(value) change tracked
        :param ghidra.util.task.TaskMonitor monitor: monitor used to cancel the operation
        :raises CancelledException: if the operation was canceled
        """

    def getCallChange(self, addr: ghidra.program.model.address.Address) -> int:
        ...

    def getDepth(self, addr: ghidra.program.model.address.Address) -> int:
        ...

    def getInstructionStackDepthChange(self, instr: ghidra.program.model.listing.Instruction) -> int:
        """
        Inspect the instruction and return how it affects the stack depth. If the
        depth cannot be determined, then return that the stack depth change is
        unknown.
        
        :param ghidra.program.model.listing.Instruction instr: instruction to analyze
        :return: int change to stack depth if it can be determined,
                Function.UNKNOWN_STACK_DEPTH_CHANGE otherwise.
        :rtype: int
        """

    def getRegDepth(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> int:
        """
        Get the stack register depth at address.
        To have a valid value, the class must be constructed to storeDepthAtEachInstuction
        
        :param ghidra.program.model.address.Address addr: the address to get the register depth at.
        :param ghidra.program.model.lang.Register reg: the register to get the depth of.
        :return: the depth of the register at the address.
        :rtype: int
        """

    def getRegValueRepresentation(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> str:
        """
        Get the stack register value as a printable string.  This can be an equation
        of register+value.
         
        To have a valid value, the class must be constructed to storeDepthAtEachInstuction
        
        :param ghidra.program.model.address.Address addr: the address of the register value to get the representation of.
        :param ghidra.program.model.lang.Register reg: the register to get the representation of.
        :return: the string representation of the register value.
        :rtype: str
        """

    def getSPDepth(self, addr: ghidra.program.model.address.Address) -> int:
        """
        
        
        :param ghidra.program.model.address.Address addr: the address to get the stack pointer depth at.
        :return: the stack pointer depth at the address.
        :rtype: int
        """

    @staticmethod
    def getStackDepthChange(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> int:
        """
        Gets the stack depth change value that has been set at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program to be checked
        :param ghidra.program.model.address.Address address: the program address
        :return: the stack depth change value or null if value has not been set
        :rtype: int
        """

    @staticmethod
    def getStackDepthChanges(program: ghidra.program.model.listing.Program, addressSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator:
        """
        Gets an iterator indicating all the addresses that have a stack depth change value specified
        within a program's indicated address set.
        
        :param ghidra.program.model.listing.Program program: the program to be checked
        :param ghidra.program.model.address.AddressSetView addressSet: the set of addresses to check for a stack depth change value
        :return: the address iterator indicating where stack depth change values have been set
        :rtype: ghidra.program.model.address.AddressIterator
        """

    def getStackOffset(self, cu: ghidra.program.model.listing.Instruction, opIndex: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getStackPurge(self) -> int:
        ...

    @staticmethod
    def removeStackDepthChange(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> bool:
        """
        Removes the value for the stack depth change at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program where the value will be removed
        :param ghidra.program.model.address.Address address: the program address
        :return: true if a stack depth change existed at the indicated at the address and it was removed.
        :rtype: bool
        """

    @staticmethod
    def setStackDepthChange(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, stackDepthChange: typing.Union[jpype.JInt, int]):
        """
        Sets a new value for the stack depth change at the indicated address.
        
        :param ghidra.program.model.listing.Program program: the program where the value will be set
        :param ghidra.program.model.address.Address address: the program address
        :param jpype.JInt or int stackDepthChange: the new stack depth change value
        :raises DuplicateNameException: if the property name for stack depth changes conflicted 
        with another property tha has the same name.
        """

    @property
    def depth(self) -> jpype.JInt:
        ...

    @property
    def instructionStackDepthChange(self) -> jpype.JInt:
        ...

    @property
    def sPDepth(self) -> jpype.JInt:
        ...

    @property
    def stackPurge(self) -> jpype.JInt:
        ...

    @property
    def callChange(self) -> jpype.JInt:
        ...


class SetVariableDataTypeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set the datatype on a stack variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, var: ghidra.program.model.listing.Variable, dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for setting the datatype on a stack/reg variable.
        Conflicting stack variables will be removed.
        
        :param ghidra.program.model.listing.Variable var: the variable for which to set the datatype.
        :param ghidra.program.model.data.DataType dataType: the datatype to apply to the stack variable.
        :param ghidra.program.model.symbol.SourceType source: signature source
        """

    @typing.overload
    def __init__(self, fnEntry: ghidra.program.model.address.Address, varName: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for setting the datatype on a stack/reg variable.
        Conflicting stack variables will be removed.
        
        :param ghidra.program.model.address.Address fnEntry: 
        :param java.lang.String or str varName: 
        :param ghidra.program.model.data.DataType dataType: 
        :param ghidra.program.model.symbol.SourceType source: signature source
        """

    @typing.overload
    def __init__(self, fnEntry: ghidra.program.model.address.Address, varName: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, align: typing.Union[jpype.JBoolean, bool], force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for setting the datatype on a stack/reg variable
        
        :param ghidra.program.model.address.Address fnEntry: 
        :param java.lang.String or str varName: 
        :param ghidra.program.model.data.DataType dataType: 
        :param jpype.JBoolean or bool align: maintain proper alignment/justification if supported by implementation (ignored for non-stack variables).
                    If false and this is a stack variable, the current stack address/offset will not change.
                    If true, the affect is implementation dependent since alignment can
                    not be performed without access to a compiler specification.
        :param jpype.JBoolean or bool force: overwrite conflicting stack variables
        :param ghidra.program.model.symbol.SourceType source: signature source
        """


class CaptureFunctionDataTypesListener(java.lang.Object):
    """
    Listener that is notified when the CaptureFunctionDataTypesCmd completes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def captureFunctionDataTypesCompleted(self, cmd: CaptureFunctionDataTypesCmd):
        """
        Notification that the capture function data types command completed
        
        :param CaptureFunctionDataTypesCmd cmd: command that was completed; the command has the 
        status as to whether the capture was successful
        """


class AddFunctionTagCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for assigning a tag to a function. Executing this will pop up a dialog
    allowing the user to assign tags to a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tagName: typing.Union[java.lang.String, str], entryPoint: ghidra.program.model.address.Address):
        """
        Constructor
        
        :param java.lang.String or str tagName: the name of the tag to add
        :param ghidra.program.model.address.Address entryPoint: the function address
        """


@deprecated("function signatures should be modified in their entirety using \n either UpdateFunctionCommand or ApplyFunctionSignatureCmd.")
class AddStackParameterCommand(AddParameterCommand):
    """
    A command to create a new function stack parameter.
    
    
    .. deprecated::
    
    function signatures should be modified in their entirety using 
    either :obj:`UpdateFunctionCommand` or :obj:`ApplyFunctionSignatureCmd`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, stackOffset: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, ordinal: typing.Union[jpype.JInt, int], source: ghidra.program.model.symbol.SourceType):
        ...


class SetFunctionVarArgsCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    A simple command to set whether or not a function has VarArgs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, hasVarArgs: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new command that will set whether or not there are VarArgs on the given
        function.
        
        :param ghidra.program.model.listing.Function function: The function on which to set whether or not there are VarArgs.
        :param jpype.JBoolean or bool hasVarArgs: true if you want to set this function to have VarArgs.
        """


class CreateFunctionCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for Creating a function at an address.  It will copy off the
    parameters used to create the function (Selection or just an address) and
    create the function on redo and clear on undo.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], entries: ghidra.program.model.address.AddressSetView, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType, findEntryPoint: typing.Union[jpype.JBoolean, bool], recreateFunction: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for creating a function.  The default name
        for a function is the name associated with the current primary symbol which
        will be removed.
        
        :param java.lang.String or str name: function name or null for default name.
        :param ghidra.program.model.address.AddressSetView entries: the entry points at which to create functions.
        :param ghidra.program.model.address.AddressSetView body: set of addresses to associated with the function to be created.
        The addresses must not already be included in the body of any existing function.
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :param jpype.JBoolean or bool findEntryPoint: true if the entry point should be computed (entry could be in the middle of a function)
        :param jpype.JBoolean or bool recreateFunction: true if the function body should be recreated even if the function exists.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], entry: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType, findEntryPoint: typing.Union[jpype.JBoolean, bool], recreateFunction: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for creating a function.  The default name
        for a function is the name associated with the current primary symbol which
        will be removed.
        
        :param java.lang.String or str name: function name or null for default name.
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.address.AddressSetView body: set of addresses to associated with the function to be created.
        The addresses must not already be included in the body of any existing function.
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :param jpype.JBoolean or bool findEntryPoint: true if the entry point should be computed (entry could be in the middle of a function)
        :param jpype.JBoolean or bool recreateFunction: true if the function body should be recreated even if the function exists.
        """

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, findEntryPoint: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for creating functions that automatically computes
        the body of each function.
        
        :param ghidra.program.model.address.AddressSetView entries: the entry points at which to create functions.
        :param jpype.JBoolean or bool findEntryPoint: true if entry point is unknown and should be found
        """

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView):
        """
        Constructs a new command for creating functions that automatically computes
        the body of each function.
        
        :param ghidra.program.model.address.AddressSetView entries: the entry points at which to create functions.
        """

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for creating functions that automatically computes
        the body of each function.
        
        :param ghidra.program.model.address.AddressSetView entries: the entry points at which to create functions.
        :param ghidra.program.model.symbol.SourceType source: SourceType for created function
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], entry: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType):
        ...

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address):
        """
        Constructs a new command for creating a function that automatically computes
        the body of the function.
        
        :param ghidra.program.model.address.Address entry: the entry point at which to create a function.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, findEntryPoint: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    @typing.overload
    def fixupFunctionBody(program: ghidra.program.model.listing.Program, start_inst: ghidra.program.model.listing.Instruction, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Recompute function body.  An open transaction must already exist.
        
        :param ghidra.program.model.listing.Program program: the program the function is in.
        :param ghidra.program.model.listing.Instruction start_inst: instruction that is within the function to be fixed up.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if successful, false if cancelled or unable to fixup function or
        no function found containing the start address of the indicated instruction
        :rtype: bool
        :raises CancelledException: if the function fixup is cancelled.
        """

    @staticmethod
    @typing.overload
    def fixupFunctionBody(program: ghidra.program.model.listing.Program, func: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Recompute function body.  An open transaction must already exist.
        
        :param ghidra.program.model.listing.Program program: the program the function is in.
        :param ghidra.program.model.listing.Function func: the function to be fixed up.  A null function will return false.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if successful, false if unable to fixup function or
        no function found containing the start address of the indicated instruction
        :rtype: bool
        :raises CancelledException: if the function fixup is cancelled.
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns function if create command was successful
        
        :return: last new created function, null if failed
        :rtype: ghidra.program.model.listing.Function
        """

    @staticmethod
    @typing.overload
    def getFunctionBody(monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSetView:
        """
        Find the function body by following all flows other than a call from the
        entry point.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :param ghidra.program.model.listing.Program program: the program where the function is being created.
        :param ghidra.program.model.address.Address entry: entry point to start tracing flow
        :return: AddressSetView address set representing the body of the function
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    @typing.overload
    def getFunctionBody(program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSetView:
        """
        Find the function body by following all flows other than a call from the
        entry point.
        
        :param ghidra.program.model.listing.Program program: the program where the function is being created.
        :param ghidra.program.model.address.Address entry: entry point to start tracing flow
        :return: AddressSetView address set representing the body of the function
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    @typing.overload
    def getFunctionBody(program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        ...

    @staticmethod
    @typing.overload
    def getFunctionBody(program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address, includeOtherFunctions: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...


class SetFunctionPurgeCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    A simple command to set the stack purge size of a function.
    
    
    .. versionadded:: Tracker Id 548
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, newPurge: typing.Union[jpype.JInt, int]):
        """
        Creates a new command that will set the given purge size on the given
        function.
        
        :param ghidra.program.model.listing.Function function: The function on which to set the purge size.
        :param jpype.JInt or int newPurge: The new stack purge size.
        """


class UpdateFunctionCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    A command to update :obj:`Function` signature in its entirety including optional
    custom storage.
     
    If the function does not rely on custom storage the use of :obj:`ApplyFunctionSignatureCmd`
    may be more appropriate.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, updateType: ghidra.program.model.listing.Function.FunctionUpdateType, callingConvention: typing.Union[java.lang.String, str], returnVar: ghidra.program.model.listing.Variable, params: java.util.List[ghidra.program.model.listing.Variable], source: ghidra.program.model.symbol.SourceType, force: typing.Union[jpype.JBoolean, bool]):
        """
        Construct command to update a :obj:`Function` signature including optional custom storage.
        :obj:`VariableStorage.UNASSIGNED_STORAGE` should be specified when not using custom storage
        or storage is unknown.
        
        :param ghidra.program.model.listing.Function function: function to be modified
        :param ghidra.program.model.listing.Function.FunctionUpdateType updateType: indicates how function should be updated including the use of custom or
        non-custom storage.
        :param java.lang.String or str callingConvention: a valid calling convention name or null if no change is required.
        Calling conventions are limited to :const:`Function.DEFAULT_CALLING_CONVENTION_STRING`,
        :const:`Function.UNKNOWN_CALLING_CONVENTION_STRING` or those defined by the associated 
        compiler specification.
        :param ghidra.program.model.listing.Variable returnVar: function return type and storage.
        :param java.util.List[ghidra.program.model.listing.Variable] params: function parameter list (specifics depend on specified 
        :obj:`updateType <FunctionUpdateType>`).
        :param ghidra.program.model.symbol.SourceType source: the source of these parameters which will be applied to the parameter 
        symbols and overall function signature source. If parameter names are null, or a default 
        name, a :obj:`SourceType.DEFAULT` will be applied to the corresponding parameter symbol.
        :param jpype.JBoolean or bool force: if true any conflicting local parameters will be removed
        """


class ChangeFunctionTagCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Updates the name or comment field for a given function tag
    """

    class_: typing.ClassVar[java.lang.Class]
    TAG_NAME_CHANGED: typing.Final = 0
    TAG_COMMENT_CHANGED: typing.Final = 1

    def __init__(self, tagName: typing.Union[java.lang.String, str], newVal: typing.Union[java.lang.String, str], field: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param java.lang.String or str tagName: the name of the tag to change
        :param java.lang.String or str newVal: the new value to set
        :param jpype.JInt or int field: the field to set
        """


class CreateMultipleFunctionsCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for Creating multiple functions from a selection.
    This tries to create functions by working from the minimum address to the maximum address in
    the selection. Any addresses in the selection that are already in existing functions are
    discarded. Every time a function is created, all the other addresses for that function are
    also discarded.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selection: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType):
        ...


class AddStackVarCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to add a stack variable to a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, stackOffset: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to add a stack variable to a function.
        
        :param ghidra.program.model.address.Address addr: initial declaration point of variable.
        :param jpype.JInt or int stackOffset: offset into the stack for the new variable.
        :param java.lang.String or str name: name of the new variable.
        :param ghidra.program.model.data.DataType dataType: variable data-type or null for a default data type of minimal size
        :param ghidra.program.model.symbol.SourceType source: the source of this stack variable
        """


class RemoveStackDepthChangeCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address):
        ...


class AddRegisterVarCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to add a register variable to a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to add a register variable to a function.
        
        :param ghidra.program.model.address.Address addr: initial declaration point of variable.
        :param ghidra.program.model.lang.Register reg: register for the new variable.
        :param java.lang.String or str name: name of the new variable.
        :param ghidra.program.model.symbol.SourceType source: the source of this register variable
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to add a register variable to a function.
        
        :param ghidra.program.model.address.Address addr: initial declaration point of variable.
        :param ghidra.program.model.lang.Register reg: register for the new variable.
        :param java.lang.String or str name: name of the new variable.
        :param ghidra.program.model.data.DataType dataType: data type to set on the new variable
        :param ghidra.program.model.symbol.SourceType source: the source of this register variable
        """


class CreateThunkFunctionCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for creating a thunk function at an address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, referencedFunctionAddr: ghidra.program.model.address.Address, referringThunkAddresses: java.util.List[ghidra.program.model.address.Address]):
        """
        Constructs a new command for creating a thunk function.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.address.AddressSetView body: set of addresses to associated with the function to be created.
        The addresses must not already be included in the body of any existing function.
        If null, and entry corresponds to an existing function, that function will be
        converted to a thunk, otherwise an error will result.
        :param ghidra.program.model.address.Address referencedFunctionAddr: the function address to which this thunk refers.  If no function
        exists at that specified referencedFunctionAddr one will be created per the following scheme:
         
        
        * If referencedFunctionAddr is not contained within a memory block, an external function will
        be created (a check will be done to look for an previously defined external location)
        * If referencedFunctionAddr corresponds to an instruction, a new function will be
        created at that address.
        
        :param java.util.List[ghidra.program.model.address.Address] referringThunkAddresses: provides a list of referring Thunk functions which lead to
        the creation of the function at entry.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, referencedFunctionAddr: ghidra.program.model.address.Address):
        """
        Constructs a new command for creating a thunk function.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.address.AddressSetView body: set of addresses to associated with the function to be created.
        The addresses must not already be included in the body of any existing function.
        If null, and entry corresponds to an existing function, that function will be
        converted to a thunk, otherwise an error will result.
        :param ghidra.program.model.address.Address referencedFunctionAddr: the function address to which this thunk refers.  If no function
        exists at that specified referencedFunctionAddr one will be created per the following scheme:
         
        
        * If referencedFunctionAddr is not contained within a memory block, an external function will
        be created (a check will be done to look for an previously defined external location)
        * If referencedFunctionAddr corresponds to an instruction, a new function will be
        created at that address.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, referencedSymbol: ghidra.program.model.symbol.Symbol):
        """
        Constructs a new command for creating a thunk function.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param ghidra.program.model.address.AddressSetView body: set of addresses to associated with the function to be created.
        The addresses must not already be included in the body of any existing function.
        If null, and entry corresponds to an existing function, that function will be
        converted to a thunk, otherwise an error will result.
        :param ghidra.program.model.symbol.Symbol referencedSymbol: the symbol which identifies the intended function to which this thunk refers.
        If no function exists at that specified referencedSymbol location, one will be created per the following scheme:
         
        
        * If referencedFunctionAddr is not contained within a memory block, an external function will
        be created (a check will be done to look for an previously defined external location)
        * If referencedFunctionAddr corresponds to an instruction, a new function will be
        created at that address.
        * If referencedSymbol corresponds to an external CODE symbol, it will be converted to an
        external FUNCTION
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, checkForSideEffects: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for creating a thunk function that can compute the function this function is thunking to.
        
        :param ghidra.program.model.address.Address entry: entry point address for the function to be created.
        :param jpype.JBoolean or bool checkForSideEffects: true to check for side-effects that indicate it is not a pure thunk.
         
        The body may be computed.  References to the thunked to function may be created.
         
        If no function exists at the location being thunked, it will be created based on the above rules.
        """

    def getReferencedFunction(self) -> ghidra.program.model.listing.Function:
        """
        
        
        :return: the function referenced by the newly created thunk function
        is command was successful
        :rtype: ghidra.program.model.listing.Function
        """

    def getThunkFunction(self) -> ghidra.program.model.listing.Function:
        """
        
        
        :return: function if create command was successful
        :rtype: ghidra.program.model.listing.Function
        """

    @staticmethod
    @typing.overload
    def getThunkedAddr(program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        if the code starting at entry is a thunk, return the thunked addess if known.
        
        :param ghidra.program.model.listing.Program program: code resides in
        :param ghidra.program.model.address.Address entry: start of the code
        :return: the function address, Address.NO_ADDRESS if thunk but unknonw addr, null otherwise
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def getThunkedAddr(program: ghidra.program.model.listing.Program, entry: ghidra.program.model.address.Address, checkForSideEffects: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Get the address that this function would thunk if it is a valid thunk
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address entry: location to check for a thunk
        :param jpype.JBoolean or bool checkForSideEffects: true if there should be no extra registers affected
        :return: address that the thunk thunks,Address.NO_ADDRESS if thunk but unknown addr, null otherwise
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def isThunk(program: ghidra.program.model.listing.Program, func: ghidra.program.model.listing.Function) -> bool:
        """
        Check if this is a Thunking function.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.listing.Function func: function to check
        :return: true if this is a function thunking another.
        :rtype: bool
        """

    @property
    def thunkFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def referencedFunction(self) -> ghidra.program.model.listing.Function:
        ...


class SetReturnDataTypeCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting a function's return type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entry: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for setting a function's return type.
        
        :param ghidra.program.model.address.Address entry: the entry point of the function having its return type set.
        :param ghidra.program.model.data.DataType dataType: the datatype to set on the function.
        :param ghidra.program.model.symbol.SourceType source: TODO
        """


class CreateFunctionTagCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for assigning a tag to a function
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str name: the name of the new tag
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str name: the name of the new tag
        :param java.lang.String or str comment: the tag comment
        """


@deprecated("function signatures should be modified in their entirety using \n either UpdateFunctionCommand or ApplyFunctionSignatureCmd.")
class AddParameterCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Allows for the adding of a parameter to a given function.
     
    Note: If no ordinal is provided to this class at construction time, then
    the ordinal of hte given parameter will be used.
    
    
    .. deprecated::
    
    function signatures should be modified in their entirety using 
    either :obj:`UpdateFunctionCommand` or :obj:`ApplyFunctionSignatureCmd`.
    
    .. seealso::
    
        | :obj:`AddRegisterParameterCommand`
    
        | :obj:`AddStackParameterCommand`
    
        | :obj:`AddMemoryParameterCommand`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, parameter: ghidra.program.model.listing.Parameter, ordinal: typing.Union[jpype.JInt, int], source: ghidra.program.model.symbol.SourceType):
        ...


class CaptureFunctionDataTypesCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Capture all selected function signature data types from the current program and put them 
    in the data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager, set: ghidra.program.model.address.AddressSetView, listener: CaptureFunctionDataTypesListener):
        """
        Constructs a new command to create function definition data types
        in the given data type manager from the function's whose entry points are in the
        address set.
        
        :param ghidra.program.model.data.DataTypeManager dtm: data type manager containing the function signature data types
        :param ghidra.program.model.address.AddressSetView set: set of addresses containing the entry points of the functions whose signatures
        are to be turned into data types.
        :param CaptureFunctionDataTypesListener listener:
        """


class FunctionRenameOption(java.lang.Enum[FunctionRenameOption]):
    """
    Option for controlling the renaming of a :obj:`Function` when applying a 
    :obj:`FunctionSignature` or :obj:`FunctionDefinition`.
     
    See :obj:`ApplyFunctionSignatureCmd`.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_CHANGE: typing.Final[FunctionRenameOption]
    """
    :obj:`.NO_CHANGE` indicates that the current :obj:`Function` name should be changed.
    """

    RENAME_IF_DEFAULT: typing.Final[FunctionRenameOption]
    """
    :obj:`.RENAME_IF_DEFAULT` indicates that the current :obj:`Function` name should be only
    be changed if it is a default name (e.g., FUN_1234).
    """

    RENAME: typing.Final[FunctionRenameOption]
    """
    :obj:`.RENAME` indicates that the current :obj:`Function` name should always be changed.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionRenameOption:
        ...

    @staticmethod
    def values() -> jpype.JArray[FunctionRenameOption]:
        ...


class CreateExternalFunctionCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, extSymbol: ghidra.program.model.symbol.Symbol):
        """
        Create an external function
        
        :param ghidra.program.model.symbol.Symbol extSymbol: a non-function external symbol
        """

    @typing.overload
    def __init__(self, libraryName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType):
        """
        Create an external function
        
        :param java.lang.String or str libraryName: library name, if null the UNKNOWN library will be used
        :param java.lang.String or str name: function name (required)
        :param ghidra.program.model.address.Address address: the address of the function's entry point in the external library (optional)
        :param ghidra.program.model.symbol.SourceType source: the source type for this external function
        """

    @typing.overload
    def __init__(self, externalParentNamespace: ghidra.program.model.symbol.Namespace, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType):
        """
        Create an external function in the specified external namespace.
        
        :param ghidra.program.model.symbol.Namespace externalParentNamespace: the external parent namespace where the named function should be created (required)
        :param java.lang.String or str name: function name (required)
        :param ghidra.program.model.address.Address address: the address of the function's entry point in the external library (optional)
        :param ghidra.program.model.symbol.SourceType source: the source type for this external function
        """

    def getExtSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def extSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...


class SetVariableCommentCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set the comment on a function varible.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, var: ghidra.program.model.listing.Variable, newComment: typing.Union[java.lang.String, str]):
        """
        Constructs a new command for setting the comment on a function variable.
        
        :param ghidra.program.model.listing.Variable var: the variable on which to set the comment.
        :param java.lang.String or str newComment: the comment string to set on the specified variable.
        """


class FunctionResultStateStackAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for analyzing the Stack; the command is run in the background.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, entries: ghidra.program.model.address.AddressSetView, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.
        
        :param ghidra.program.model.address.AddressSetView entries: and address set indicating the entry points of functions that have 
        stacks to be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """

    @typing.overload
    def __init__(self, entry: ghidra.program.model.address.Address, forceProcessing: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new command for analyzing the Stack.
        
        :param ghidra.program.model.address.Address entry: the entry point of the function that contains the stack to
                be analyzed.
        :param jpype.JBoolean or bool forceProcessing: flag to force processing of stack references even if the stack
                has already been defined.
        """


class DeleteFunctionTagCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Command for deleting a tag from the system
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tagName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str tagName: the name of the tag to delete
        """


class RemoveFunctionTagCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for removing a tag from a function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tagName: typing.Union[java.lang.String, str], entryPoint: ghidra.program.model.address.Address):
        """
        Constructor
        
        :param java.lang.String or str tagName: the name of the tag to remove
        :param ghidra.program.model.address.Address entryPoint: the address of the function
        """


class SetStackDepthChangeCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address, newStackDepthChange: typing.Union[jpype.JInt, int]):
        ...


@deprecated("function signatures should be modified in their entirety using \n either UpdateFunctionCommand or ApplyFunctionSignatureCmd.")
class AddMemoryParameterCommand(AddParameterCommand):
    """
    A command to create a new function memory parameter.
    
    
    .. deprecated::
    
    function signatures should be modified in their entirety using 
    either :obj:`UpdateFunctionCommand` or :obj:`ApplyFunctionSignatureCmd`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, memAddr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, ordinal: typing.Union[jpype.JInt, int], source: ghidra.program.model.symbol.SourceType):
        ...


class SetFunctionRepeatableCommentCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to set the Function's Repeatable Comment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, entry: ghidra.program.model.address.Address, newRepeatableComment: typing.Union[java.lang.String, str]):
        """
        Constructs a new command for setting the Repeatable comment.
        
        :param ghidra.program.model.address.Address entry: address of the function for which to set a Repeatablecomment.
        :param java.lang.String or str newRepeatableComment: comment to set as the function Repeatable comment.
        """


class AddMemoryVarCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to add a memory variable to a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, memAddr: ghidra.program.model.address.Address, firstUseAddr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to add a memory variable to a function.
        
        :param ghidra.program.model.address.Address memAddr: memory variable address
        :param ghidra.program.model.address.Address firstUseAddr: initial declaration point of variable.
        :param java.lang.String or str name: name of the new variable.
        :param ghidra.program.model.symbol.SourceType source: the source of this memory variable
        """

    @typing.overload
    def __init__(self, memAddr: ghidra.program.model.address.Address, firstUseAddr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command to add a memory variable to a function.
        
        :param ghidra.program.model.address.Address memAddr: memory variable address
        :param ghidra.program.model.address.Address firstUseAddr: initial declaration point of variable.
        :param java.lang.String or str name: name of the new variable.
        :param ghidra.program.model.data.DataType dt: variable data type
        :param ghidra.program.model.symbol.SourceType source: the source of this memory variable
        """


class DecompilerParallelConventionAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, func: ghidra.program.model.listing.Function, decompilerInterface: ghidra.app.decompiler.DecompInterface, decompilerTimeoutSecs: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def createDecompilerInterface(program: ghidra.program.model.listing.Program) -> ghidra.app.decompiler.DecompInterface:
        ...


class DecompilerSwitchAnalysisCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, decompileResults: ghidra.app.decompiler.DecompileResults):
        ...

    def hasAllReferences(self, monitor: ghidra.util.task.TaskMonitor, table: ghidra.program.model.pcode.JumpTable, instr: ghidra.program.model.listing.Instruction, containingFunction: ghidra.program.model.listing.Function) -> bool:
        ...

    def markDataAsConstant(self, addr: ghidra.program.model.address.Address):
        ...


class DecompilerParameterIdCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    @typing.type_check_only
    class DecompilerFactory(generic.cache.CountingBasicFactory[ghidra.app.decompiler.DecompInterface]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ParallelDecompileRunnable(generic.concurrent.QRunnable[ghidra.program.model.address.Address]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], entries: ghidra.program.model.address.AddressSetView, sourceTypeClearLevel: ghidra.program.model.symbol.SourceType, commitDataTypes: typing.Union[jpype.JBoolean, bool], commitVoidReturn: typing.Union[jpype.JBoolean, bool], decompilerTimeoutSecs: typing.Union[jpype.JInt, int]):
        ...



__all__ = ["CreateFunctionDefinitionCmd", "ApplyFunctionSignatureCmd", "DeleteVariableCmd", "AddRegisterParameterCommand", "FunctionStackAnalysisCmd", "FunctionPurgeAnalysisCmd", "DeleteFunctionCmd", "ApplyFunctionDataTypesCmd", "SetVariableNameCmd", "SetFunctionNameCmd", "NewFunctionStackAnalysisCmd", "CallDepthChangeInfo", "SetVariableDataTypeCmd", "CaptureFunctionDataTypesListener", "AddFunctionTagCmd", "AddStackParameterCommand", "SetFunctionVarArgsCommand", "CreateFunctionCmd", "SetFunctionPurgeCommand", "UpdateFunctionCommand", "ChangeFunctionTagCmd", "CreateMultipleFunctionsCmd", "AddStackVarCmd", "RemoveStackDepthChangeCommand", "AddRegisterVarCmd", "CreateThunkFunctionCmd", "SetReturnDataTypeCmd", "CreateFunctionTagCmd", "AddParameterCommand", "CaptureFunctionDataTypesCmd", "FunctionRenameOption", "CreateExternalFunctionCmd", "SetVariableCommentCmd", "FunctionResultStateStackAnalysisCmd", "DeleteFunctionTagCmd", "RemoveFunctionTagCmd", "SetStackDepthChangeCommand", "AddMemoryParameterCommand", "SetFunctionRepeatableCommentCmd", "AddMemoryVarCmd", "DecompilerParallelConventionAnalysisCmd", "DecompilerSwitchAnalysisCmd", "DecompilerParameterIdCmd"]
