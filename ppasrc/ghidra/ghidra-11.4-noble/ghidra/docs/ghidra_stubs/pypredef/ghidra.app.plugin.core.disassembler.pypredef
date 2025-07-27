from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.cmd.label
import ghidra.app.context
import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.table
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class AutoTableDisassemblerPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):

    @typing.type_check_only
    class MakeTablesTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class EntryPointAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Disassemble Entry Points"

    def __init__(self):
        ...


@typing.type_check_only
class RestrictedDisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for restricted disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class MipsDisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for Mips mode disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str], disassembleMIPS16: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class DisassembleAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class PowerPCDisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for PPC mode disassembly when VLE instruction support is present
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str], disassemblePPC: typing.Union[jpype.JBoolean, bool]):
        ...

    def initializeContextMenu(self):
        ...


class DisassembledViewPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    A plugin to disassemble the address at the current ProgramLocation and to
    display the Instruction.  This work of this plugin is temporary in that it
    will not change the state of the program.
     
     
     
    TODO Change the PseudoCodeUnit's getComment(int) method or change its
        getPreview(int) method not to call getComment(int) and then change
        this class to not handle the UnsupportedOperationException.
    TODO are the category and names correct?
    TODO decide how to represent multiple selections in the display
     
    TODO Potential user options:
        -look ahead count
        -to or to not display multiple selections
        -change the format of the preview displayed
    """

    @typing.type_check_only
    class DisassembledViewComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
        """
        The component provided for the DisassembledViewPlugin.
        """

        @typing.type_check_only
        class DisassembledViewOptionsListener(ghidra.framework.options.OptionsChangeListener):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def closeComponent(self):
            """
            Notifies the provider that the user pressed the "close" button.
            The provider should take appropriate action.  Usually the
            appropriate action is to hide the component or remove the
            component.  If the provider does nothing in this method,
            then the close button will appear broken.
            """

        def componentHidden(self):
            """
            Notifies the provider that the component is being hidden.
            """

        def componentShown(self):
            """
            Notifies the provider that the component is being shown.
            """

        def getComponent(self) -> javax.swing.JComponent:
            """
            Gets the component that will house our view.
            
            :return: the component that will house our view.
            :rtype: javax.swing.JComponent
            """

        @property
        def component(self) -> javax.swing.JComponent:
            ...


    @typing.type_check_only
    class DisassembledAddressInfo(java.lang.Object):
        """
        An object that provides information about the address that it wraps.  The info knows how to
        locate an info object for the address and can generate a string preview of the address.
        """

        class_: typing.ClassVar[java.lang.Class]

        def getAddressPreview(self, format: ghidra.program.model.listing.CodeUnitFormat) -> str:
            ...

        def getCodeUnitLength(self) -> int:
            """
            Gets the length of the :obj:`CodeUnit` for the address wrapped
            by this info.
             
            
            Note: If :meth:`isValidAddress() <.isValidAddress>` returns false, then this method
            will return ``-1``.
            
            :return: the length of the code unit for the address wrapped by this
                    info.
            :rtype: int
            """

        def isValidAddress(self) -> bool:
            """
            Returns true if there is a :obj:`CodeUnit` for the address
            wrapped by this info.  If not, then we do not have a valid address.
            
            :return: true if there is a :obj:`CodeUnit` for the address
                    wrapped by this info.
            :rtype: bool
            """

        @property
        def addressPreview(self) -> java.lang.String:
            ...

        @property
        def validAddress(self) -> jpype.JBoolean:
            ...

        @property
        def codeUnitLength(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor to initialize and register as an event listener.
        
        :param ghidra.framework.plugintool.PluginTool plugintool: The PluginTool required to initialize this plugin.
        """


class X86_64DisassembleAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str], disassemble32Bit: typing.Union[jpype.JBoolean, bool]):
        ...


class AddressTableDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: AutoTableDisassemblerPlugin):
        ...

    def setSelectedRows(self, selectedRows: jpype.JArray[jpype.JInt]):
        ...


@typing.type_check_only
class StaticDisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for static disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


class CallFixupChangeAnalyzer(CallFixupAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class SetFlowOverrideDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ContextAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class SetFlowOverrideAction(ghidra.app.context.ListingContextAction):

    @typing.type_check_only
    class OverrideSelectionInspector(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


class AddressTable(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    BILLION_CASES: typing.Final = 1073741824
    TOO_MANY_ENTRIES: typing.Final = 1048576
    MINIMUM_SAFE_ADDRESS: typing.Final = 1024

    @typing.overload
    def __init__(self, topAddress: ghidra.program.model.address.Address, tableElements: jpype.JArray[ghidra.program.model.address.Address], addrByteSize: typing.Union[jpype.JInt, int], skipAmount: typing.Union[jpype.JInt, int], shiftedAddr: typing.Union[jpype.JBoolean, bool]):
        """
        Define an address table
        
        :param ghidra.program.model.address.Address topAddress: start address of the table
        :param jpype.JArray[ghidra.program.model.address.Address] tableElements: pointer values from the table
        :param jpype.JInt or int addrByteSize: pointer data size
        :param jpype.JInt or int skipAmount: number of bytes to skip between address entries
        :param jpype.JBoolean or bool shiftedAddr: if true an attempt will be made to utilize
                    shifted-pointers if the associated program data organization
                    specifies a pointer shift amount. The size of shifted-pointers
                    is also determined by the data organization and not the
                    specified addrByteSize (this is due to the fact that the
                    ShiftedAddressDataType is not a Pointer data type).
        """

    @typing.overload
    def __init__(self, topAddress: ghidra.program.model.address.Address, tableElements: jpype.JArray[ghidra.program.model.address.Address], topIndexAddress: ghidra.program.model.address.Address, indexLen: typing.Union[jpype.JInt, int], addrByteSize: typing.Union[jpype.JInt, int], skipAmount: typing.Union[jpype.JInt, int], shiftedAddr: typing.Union[jpype.JBoolean, bool]):
        """
        Create an address table with a secondary index into the table entries
        
        :param ghidra.program.model.address.Address topAddress: start address of the table
        :param jpype.JArray[ghidra.program.model.address.Address] tableElements: pointer values from the table
        :param ghidra.program.model.address.Address topIndexAddress: first address of the index into the address table
        :param jpype.JInt or int indexLen: length of the index
        :param jpype.JInt or int addrByteSize: size of address in bytes
        :param jpype.JInt or int skipAmount: distance between each entry in the address table
        :param jpype.JBoolean or bool shiftedAddr: true if the address entries are shifted
        """

    def changeEntry(self, i: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address):
        """
        Change table entry i to a new target address
        """

    def createSwitchTable(self, program: ghidra.program.model.listing.Program, start_inst: ghidra.program.model.listing.Instruction, opindex: typing.Union[jpype.JInt, int], flagNewCode: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Create a switch table. If any new code is found while disassembling the
        table destinations, don't finish making the table!
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.listing.Instruction start_inst: 
        :param jpype.JInt or int opindex: 
        :param table: :param jpype.JBoolean or bool flagNewCode: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: true if any new code was discovered!
        :rtype: bool
        """

    def createTableIndex(self, program: ghidra.program.model.listing.Program):
        """
        Create the index array for this table if it has an index
        """

    def disassemble(self, program: ghidra.program.model.listing.Program, instr: ghidra.program.model.listing.Instruction, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Disassemble all the entries in the table
        """

    def fixupFunctionBody(self, program: ghidra.program.model.listing.Program, start_inst: ghidra.program.model.listing.Instruction, monitor: ghidra.util.task.TaskMonitor):
        """
        Fixup the function body if there is a function defined here.
        
        :param ghidra.program.model.listing.Program program: program we are in
        :param ghidra.program.model.listing.Instruction start_inst: start instruction of the jump table
        :param table: :param ghidra.util.task.TaskMonitor monitor: monitor to output results.
        """

    @typing.overload
    def getByteLength(self) -> int:
        """
        
        
        :return: byte length of this table in memory
        :rtype: int
        """

    @typing.overload
    def getByteLength(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], includeIndex: typing.Union[jpype.JBoolean, bool]) -> int:
        """
        
        
        :return: byte length of this table in memory
        :rtype: int
        """

    def getElementPrefix(self, offsetLen: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the prefix for a label to be created based on the address table
        element that points to it. The prefix consists of "AddrTable" followed by
        the address that is indicated as an offset from the beginning of the
        table followed by "Element". The element number can then be appended to
        this to create the label.
        
        :param jpype.JInt or int offsetLen: the number of addresses the embedded prefix address
                    should be from the start of this address table.
        :return: the prefix string for an address table element.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getEntry(program: ghidra.program.model.listing.Program, topAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor, checkExisting: typing.Union[jpype.JBoolean, bool], minimumTableSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], skipAmount: typing.Union[jpype.JInt, int], minAddressOffset: typing.Union[jpype.JLong, int], useRelocationTable: typing.Union[jpype.JBoolean, bool]) -> AddressTable:
        """
        Get an Address Table Object (always uses shifted addresses, if specified
        by language)
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.Address topAddr: starting adddress of the table
        :param jpype.JBoolean or bool checkExisting: check for existing instructions, data, or labels
        :param jpype.JInt or int minimumTableSize: minimum table size
        :param jpype.JInt or int alignment: only return a table for addresses that fall on alignment
                    in bytes
        :param jpype.JLong or int minAddressOffset: minimum value to be considered a pointer,
                    dangerous to go below 1024 for some things
        :param jpype.JBoolean or bool useRelocationTable: use relocationTable for relocatablePrograms to
                    check for valid pointers
        :return: null if no valid table exists at the topAddr
        :rtype: AddressTable
        """

    @staticmethod
    @typing.overload
    def getEntry(program: ghidra.program.model.listing.Program, topAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor, checkExisting: typing.Union[jpype.JBoolean, bool], minimumTableSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], skipAmount: typing.Union[jpype.JInt, int], minAddressOffset: typing.Union[jpype.JLong, int], useShiftedAddressesIfNecessary: typing.Union[jpype.JBoolean, bool], checkForIndex: typing.Union[jpype.JBoolean, bool], useRelocationTable: typing.Union[jpype.JBoolean, bool]) -> AddressTable:
        """
        Get an Address Table Object (allows you to specify whether to use shifted
        addresses or not)
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.Address topAddr: starting adddress of the table
        :param jpype.JBoolean or bool checkExisting: check for existing instructions, data, or labels
        :param jpype.JInt or int minimumTableSize: minimum table size
        :param jpype.JInt or int alignment: only return a table for addresses that fall on alignment
                    in bytes
        :param jpype.JInt or int skipAmount: number of bytes to skip between address entries
        :param jpype.JLong or int minAddressOffset: minimum value to be considered a pointer,
                    dangerous to go below 1024 for some things
        :param jpype.JBoolean or bool checkForIndex: true if check for a single byte index table after
                    the address table
        :param jpype.JBoolean or bool useRelocationTable: true to only consider pointers that are in the
                    relocationTable for relocatable programs
        :return: null if no valid table exists at the topAddr
        :rtype: AddressTable
        """

    def getFunctionEntries(self, program: ghidra.program.model.listing.Program, offset: typing.Union[jpype.JInt, int]) -> java.util.ArrayList[ghidra.program.model.address.Address]:
        ...

    def getIndexLength(self) -> int:
        """
        
        
        :return: number of entries in the index table if found
        :rtype: int
        """

    def getIndexName(self, offsetLen: typing.Union[jpype.JInt, int]) -> str:
        """
        Get a generic name for the index to the table
        
        :param jpype.JInt or int offsetLen: offset from the top of the table
        :return: a general name for the table based on the start and an optional
                offset
        :rtype: str
        """

    def getNumberAddressEntries(self) -> int:
        """
        
        
        :return: number of address table entries
        :rtype: int
        """

    def getTableBody(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set that represents the addresses consumed by this table.
        
        :return: address set representing the bytes that make up the table.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getTableElements(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        
        
        :return: the actual found addresses table address entries
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def getTableName(self, offsetLen: typing.Union[jpype.JInt, int]) -> str:
        """
        Get a generic name for the table
        
        :param offset: from the top of the table, normally 0:return: a general name for the table based on the start and an optional
                offset
        :rtype: str
        """

    def getTableTypeString(self, memory: ghidra.program.model.mem.Memory) -> str:
        ...

    @staticmethod
    def getThresholdRunOfValidPointers(program: ghidra.program.model.listing.Program, oneInNumberOfCases: typing.Union[jpype.JLong, int]) -> int:
        """
        
        
        :param ghidra.program.model.listing.Program program: to check
        :param jpype.JLong or int oneInNumberOfCases: 1 in this number of cases
        :return: the number of valid runs of pointers to achieve a ( 1 in
                numberOfCases)
        :rtype: int
        """

    def getTopAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the first address of the address table
        :rtype: ghidra.program.model.address.Address
        """

    def getTopIndexAddress(self) -> ghidra.program.model.address.Address:
        """
        Index table Addresses .... Index offsets into the address table ....
        
        :return: top address of the index table following the address table
        :rtype: ghidra.program.model.address.Address
        """

    def isFunctionTable(self, program: ghidra.program.model.listing.Program, offset: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def isNegativeTable(self) -> bool:
        """
        
        
        :return: true if this is a negatively indexed table
        :rtype: bool
        """

    def labelTable(self, program: ghidra.program.model.listing.Program, start_inst: ghidra.program.model.listing.Instruction, switchLabelList: java.util.ArrayList[ghidra.app.cmd.label.AddLabelCmd], tableNameLabel: ghidra.app.cmd.label.AddLabelCmd):
        ...

    @typing.overload
    def makeTable(self, program: ghidra.program.model.listing.Program, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], autoLabel: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Make the table
        
        :param ghidra.program.model.listing.Program program: 
        :param jpype.JInt or int start: start index
        :param jpype.JInt or int end: end index (inclusive)
        :param jpype.JBoolean or bool autoLabel: true if labels should be created on the table
        :return: 
        :rtype: bool
        """

    @typing.overload
    def makeTable(self, program: ghidra.program.model.listing.Program, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], createIndex: typing.Union[jpype.JBoolean, bool], autoLabel: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Make the table
        
        :param ghidra.program.model.listing.Program program: 
        :param jpype.JInt or int start: start index
        :param jpype.JInt or int end: end index (inclusive)
        :param jpype.JBoolean or bool createIndex: don't create index if false
        :param jpype.JBoolean or bool autoLabel: true if labels should be created on the table
        :return: true if tablecreated else false
        :rtype: bool
        """

    def newRemainingAddressTable(self, startPos: typing.Union[jpype.JInt, int]) -> AddressTable:
        """
        Create a new address table from any remaining table entries starting at startPos
        
        :param jpype.JInt or int startPos: new start position in list of existing table entries
        :return: new address table if any elements left, null otherwise
        :rtype: AddressTable
        """

    def setNegativeTable(self, isNegative: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this is a negatively indexed table
        
        :param jpype.JBoolean or bool isNegative: true if is negatively indexed table
        """

    def truncate(self, tableLen: typing.Union[jpype.JInt, int]):
        """
        Truncate the table to tableLen entries
        
        :param jpype.JInt or int tableLen:
        """

    @property
    def tableBody(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def topIndexAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def tableElements(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def indexLength(self) -> jpype.JInt:
        ...

    @property
    def tableTypeString(self) -> java.lang.String:
        ...

    @property
    def numberAddressEntries(self) -> jpype.JInt:
        ...

    @property
    def indexName(self) -> java.lang.String:
        ...

    @property
    def negativeTable(self) -> jpype.JBoolean:
        ...

    @negativeTable.setter
    def negativeTable(self, value: jpype.JBoolean):
        ...

    @property
    def topAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def byteLength(self) -> jpype.JInt:
        ...

    @property
    def elementPrefix(self) -> java.lang.String:
        ...

    @property
    def tableName(self) -> java.lang.String:
        ...


@typing.type_check_only
class Hcs12DisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for HCS12 mode disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str], disassembleXgate: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class SetLengthOverrideAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str]):
        ...


class ProcessorStateDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, programContext: ghidra.program.model.listing.ProgramContext):
        ...

    def okCallback(self):
        """
        The callback method for when the "OK" button is pressed.
        """


class DisassemblerPlugin(ghidra.framework.plugintool.Plugin):
    """
    ``DisassemblerPlugin`` provides functionality for dynamic disassembly, static
    disassembly.
    
    In dynamic disassembly disassembling begins from the selected addresses or if there is no
    selection then at the address of the current cursor location and attempts to continue
    disassembling through fallthroughs and along all flows from a disassembled instruction. For
    instance, if a jump instruction is disassembled then the address being jumped to will be
    disassembled. The dynamic disassembly will also follow data pointers to addresses containing
    undefined data, which is then disassembled.
    
    In static disassembly a range or set of ranges is given and disassembly is attempted on each
    range. Any defined code in the ranges before the static disassembly are first removed.
    
     
    
    ``DisassemblerPlugin`` provides access to its functions as a service that another plugin
    may use and through the popup menu to the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new instance of the plugin giving it the tool that it will work in.
        """

    def disassembleArmCallback(self, context: ghidra.app.context.ListingActionContext, thumbMode: typing.Union[jpype.JBoolean, bool]):
        ...

    def disassembleHcs12Callback(self, context: ghidra.app.context.ListingActionContext, xgMode: typing.Union[jpype.JBoolean, bool]):
        ...

    def disassembleMipsCallback(self, context: ghidra.app.context.ListingActionContext, mips16: typing.Union[jpype.JBoolean, bool]):
        ...

    def disassemblePPCCallback(self, context: ghidra.app.context.ListingActionContext, vle: typing.Union[jpype.JBoolean, bool]):
        ...

    def disassembleX86_64Callback(self, context: ghidra.app.context.ListingActionContext, size32Mode: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def getCategory() -> str:
        """
        Get the category.
        """

    @staticmethod
    def getDescription() -> str:
        """
        Get the description of this plugin.
        """

    @staticmethod
    def getDescriptiveName() -> str:
        """
        Get the descriptive name.
        """

    def hasContextRegisters(self, currentProgram: ghidra.program.model.listing.Program) -> bool:
        ...

    def setDefaultContext(self, context: ghidra.app.context.ListingActionContext):
        ...


class CallFixupAnalyzer(ghidra.app.services.AbstractAnalyzer):

    @typing.type_check_only
    class SubMonitor(ghidra.util.task.TaskMonitorAdapter):
        """
        A monitor that let's us update the status of our overall progress monitor without
        altering the overall progress.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parentMonitor: ghidra.util.task.TaskMonitor):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], analyzerType: ghidra.app.services.AnalyzerType, supportsOneTimeAnalysis: typing.Union[jpype.JBoolean, bool]):
        ...


class AddressTableAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Check operand references to memory locations looking for Data
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class ArmDisassembleAction(ghidra.app.context.ListingContextAction):
    """
    Action for Arm mode disassembly
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DisassemblerPlugin, groupName: typing.Union[java.lang.String, str], disassembleThumb: typing.Union[jpype.JBoolean, bool]):
        ...


@typing.type_check_only
class AutoTableDisassemblerModel(ghidra.util.table.AddressBasedTableModel[AddressTable]):

    @typing.type_check_only
    class AddressTableStorage(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def contains(self, address: ghidra.program.model.address.Address) -> bool:
            ...

        def get(self, address: ghidra.program.model.address.Address) -> AddressTable:
            ...

        def put(self, address: ghidra.program.model.address.Address, table: AddressTable):
            ...


    @typing.type_check_only
    class NullStorage(AutoTableDisassemblerModel.AddressTableStorage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MapStorage(AutoTableDisassemblerModel.AddressTableStorage):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getTableLength(self, row: typing.Union[jpype.JInt, int]) -> int:
        ...

    @property
    def tableLength(self) -> jpype.JInt:
        ...



__all__ = ["AutoTableDisassemblerPlugin", "EntryPointAnalyzer", "RestrictedDisassembleAction", "MipsDisassembleAction", "DisassembleAction", "PowerPCDisassembleAction", "DisassembledViewPlugin", "X86_64DisassembleAction", "AddressTableDialog", "StaticDisassembleAction", "CallFixupChangeAnalyzer", "SetFlowOverrideDialog", "ContextAction", "SetFlowOverrideAction", "AddressTable", "Hcs12DisassembleAction", "SetLengthOverrideAction", "ProcessorStateDialog", "DisassemblerPlugin", "CallFixupAnalyzer", "AddressTableAnalyzer", "ArmDisassembleAction", "AutoTableDisassemblerModel"]
