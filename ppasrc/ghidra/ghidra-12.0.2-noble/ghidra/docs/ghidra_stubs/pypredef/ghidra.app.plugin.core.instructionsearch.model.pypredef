from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.plugin.core.instructionsearch.ui
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing.border # type: ignore
import javax.swing.table # type: ignore


class InstructionTableDataObject(java.lang.Object):
    """
    Defines the contents of a single cell in the :obj:`InstructionTable`.
     
    
    To be notified of table changes, clients can subscribe to this object using
    the register() method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, data: typing.Union[java.lang.String, str], isInstruction: typing.Union[jpype.JBoolean, bool], state: ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState):
        """
        Constructor.
        
        :param java.lang.String or str data: the text to be displayed
        :param jpype.JBoolean or bool isInstruction: true if the code unit is an instruction, false if
                    data or something else.
        :param ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState state: the initial state of the item
        """

    def getBackgroundColor(self) -> java.awt.Color:
        ...

    def getBorder(self) -> javax.swing.border.Border:
        ...

    def getData(self) -> str:
        ...

    def getForegroundColor(self) -> java.awt.Color:
        ...

    def getOperandCase(self) -> OperandMetadata:
        ...

    def getState(self) -> ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState:
        ...

    def isInstruction(self) -> bool:
        ...

    def register(self, observer: InstructionTableObserver):
        ...

    def setData(self, data: typing.Union[java.lang.String, str]):
        ...

    def setOperandCase(self, operandCase: OperandMetadata):
        ...

    def setState(self, state: ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState, update: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the state of the operand or mnemonic.
        
        :param ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState state: the new operand state
        :param jpype.JBoolean or bool update: if true, a notification is issued to subscribers
        """

    def toString(self) -> str:
        """
        Override of the toString method to just print the contents of the cell.
        """

    def toggleMaskState(self):
        """
        Toggles the state of the cell between masked/unmasked. A notification is
        issued to subscribers if there is a state change.
        """

    @property
    def border(self) -> javax.swing.border.Border:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def data(self) -> java.lang.String:
        ...

    @data.setter
    def data(self, value: java.lang.String):
        ...

    @property
    def instruction(self) -> jpype.JBoolean:
        ...

    @property
    def operandCase(self) -> OperandMetadata:
        ...

    @operandCase.setter
    def operandCase(self, value: OperandMetadata):
        ...

    @property
    def foregroundColor(self) -> java.awt.Color:
        ...

    @property
    def state(self) -> ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState:
        ...


class MaskSettings(java.lang.Object):
    """
    Contains information about how to mask the associated address range.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maskAddresses: typing.Union[jpype.JBoolean, bool], maskOperands: typing.Union[jpype.JBoolean, bool], maskScalars: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param jpype.JBoolean or bool maskAddresses: 
        :param jpype.JBoolean or bool maskOperands: 
        :param jpype.JBoolean or bool maskScalars:
        """

    def clear(self):
        ...

    def isMaskAddresses(self) -> bool:
        ...

    def isMaskOperands(self) -> bool:
        ...

    def isMaskScalars(self) -> bool:
        ...

    def setMaskAddresses(self, maskAddresses: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMaskOperands(self, maskOperands: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMaskScalars(self, maskScalars: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def maskOperands(self) -> jpype.JBoolean:
        ...

    @maskOperands.setter
    def maskOperands(self, value: jpype.JBoolean):
        ...

    @property
    def maskScalars(self) -> jpype.JBoolean:
        ...

    @maskScalars.setter
    def maskScalars(self, value: jpype.JBoolean):
        ...

    @property
    def maskAddresses(self) -> jpype.JBoolean:
        ...

    @maskAddresses.setter
    def maskAddresses(self, value: jpype.JBoolean):
        ...


class InstructionTableObserver(java.util.Observer):
    """
    Interface for classes wishing to be notified when the :obj:`InstructionTable` is 
    changed.
     
    Note: This class is here since the basic :obj:`Observer` interface is not exactly
    what we need.  It requires that any observables extend the :obj:`Observable` class, 
    which we can't do since the precludes extending other classes we DO need.  Hence the
    need for this custom implementation of the Observer pattern.  Note that we still take 
    advantage of the :obj:`Observer` interface but only use part of its definition.
    """

    class_: typing.ClassVar[java.lang.Class]

    def changed(self):
        ...


class InstructionSearchData(java.util.Observable):
    """
    This is the data model that :obj:`InstructionSearchDialog` instances use
    when building their displays.
    """

    class UpdateType(java.lang.Enum[InstructionSearchData.UpdateType]):

        class_: typing.ClassVar[java.lang.Class]
        RELOAD: typing.Final[InstructionSearchData.UpdateType]
        UPDATE: typing.Final[InstructionSearchData.UpdateType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> InstructionSearchData.UpdateType:
            ...

        @staticmethod
        def values() -> jpype.JArray[InstructionSearchData.UpdateType]:
            ...


    @typing.type_check_only
    class LoadInstructionsTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView):
        """
        Examines the given addresses from the given program to extract all instructions; results are 
        stored in the local :obj:`InstructionMetadata` list.
        
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.program.model.address.AddressSetView addresses: the addresses to load instructions for
        :raises InvalidInputException: if there's an error parsing the instructions
        """

    def applyMasks(self, table: ghidra.app.plugin.core.instructionsearch.ui.InstructionTable):
        """
        This method ensures that all mask settings in the dialog are applied to
        the :obj:`.instructions` list.
        
        
        .. seealso::
        
            | :obj:`InstructionSearchData`
        """

    def clearAndReload(self):
        """
        Clears out the instruction list in this model, and fires off a
        notification to subscribers.
        """

    def getCombinedString(self) -> str:
        """
        Returns the mask and value for all instructions, combined into one binary
        string.
        
        :return: the combined string
        :rtype: str
        """

    def getInstructions(self) -> java.util.List[InstructionMetadata]:
        """
        Returns the list of all instructions.
        
        :return: the list of instructions
        :rtype: java.util.List[InstructionMetadata]
        """

    def getMaskString(self) -> str:
        """
        Returns the mask for all instructions as a binary string.
        
        :return: the mask string
        :rtype: str
        """

    def getMaxNumOperands(self) -> int:
        """
        Returns the maximum number of operands across all instructions. ie: if
        one instruction has 2 operands, another has 3, and another has 5, this
        will return 5.
        
        :return: the max number of operands
        :rtype: int
        """

    def getValueString(self) -> str:
        """
        Returns the value for all instructions as a binary string.
        
        :return: the value string
        :rtype: str
        """

    def load(self, program: ghidra.program.model.listing.Program, addressRange: ghidra.program.model.address.AddressRange):
        """
        Parses the given :obj:`AddressRange` from the given :obj:`Program` to
        extract all instructions; results are stored in the local
        :obj:`InstructionMetadata` list.
        
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.program.model.address.AddressRange addressRange: the addresses to load instructions for
        :raises InvalidInputException: if there's an error parsing the
                    instructions
        """

    def maskAllOperands(self):
        """
        Masks all operands in the instruction set.
        """

    def maskOperandsByType(self, operandType: typing.Union[jpype.JInt, int]):
        """
        Masks all operands in the instruction set that have the given type.
        
        :param jpype.JInt or int operandType: :obj:`OperandType`
        """

    def registerForGuiUpdates(self, table: ghidra.app.plugin.core.instructionsearch.ui.InstructionTable):
        """
        If this data model is being run in a headed environment, this method
        should be called to have the model be notified when users have toggled
        masks via the gui.
        
        :param ghidra.app.plugin.core.instructionsearch.ui.InstructionTable table: the table to register for
        """

    @typing.overload
    def search(self, plugin: ghidra.app.plugin.ProgramPlugin, searchBounds: ghidra.program.model.address.AddressRange, taskMonitor: ghidra.util.task.TaskMonitor, forwardSearch: typing.Union[jpype.JBoolean, bool]) -> InstructionMetadata:
        """
        Searches through instructions in the given program for a specific byte
        pattern. If found, returns the instruction. i
        
        :param program: the program to search:param ghidra.program.model.address.AddressRange searchBounds: the addresses to search
        :param ghidra.util.task.TaskMonitor taskMonitor: the task monitor
        :param jpype.JBoolean or bool forwardSearch: if true, search through addresses forward
        :raises IllegalArgumentException: if there's a problem parsing addresses
        :return: the instruction, or null if not found
        :rtype: InstructionMetadata
        """

    @typing.overload
    def search(self, program: ghidra.program.model.listing.Program, searchBounds: ghidra.program.model.address.AddressRange, taskMonitor: ghidra.util.task.TaskMonitor) -> java.util.List[InstructionMetadata]:
        """
        Searches the given program for a specific byte pattern, returning all
        found results
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.address.AddressRange searchBounds: the addresses to search
        :param ghidra.util.task.TaskMonitor taskMonitor: the task monitor
        :raises java.lang.IllegalArgumentException: if there's a problem parsing addresses
        :return: list of found instructions
        :rtype: java.util.List[InstructionMetadata]
        """

    def setInstructions(self, instructions: java.util.List[InstructionMetadata]):
        """
        Replaces the instructions in this model with the given list, and fires
        off a notification to subscribers.
        
        :param java.util.List[InstructionMetadata] instructions: the instructions to replace
        """

    @property
    def instructions(self) -> java.util.List[InstructionMetadata]:
        ...

    @instructions.setter
    def instructions(self, value: java.util.List[InstructionMetadata]):
        ...

    @property
    def maskString(self) -> java.lang.String:
        ...

    @property
    def valueString(self) -> java.lang.String:
        ...

    @property
    def maxNumOperands(self) -> jpype.JInt:
        ...

    @property
    def combinedString(self) -> java.lang.String:
        ...


class InstructionTableModel(javax.swing.table.DefaultTableModel, InstructionTableObserver):
    """
    Defines the model that backs the :obj:`InstructionTable`.  The main reason for this so 
    clients can register for changes on this model and receive notifications whenever
    any underlying :obj:`InstructionTableDataObject` instances change.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tableContentsDO: jpype.JArray[jpype.JArray[InstructionTableDataObject]], colNames: jpype.JArray[java.lang.Object]):
        """
        Constructor.  Initializes the table model with the :obj:`InstructionTableDataObject` array, and 
        registers the creator for any changes to those objects.
        
        :param jpype.JArray[jpype.JArray[InstructionTableDataObject]] tableContentsDO: 
        :param jpype.JArray[java.lang.Object] colNames:
        """

    def changed(self):
        """
        Called whenever a :obj:`InstructionTableDataObject` has changed.
         
        Note: This is our custom version of the update() method in the :obj:`Observer` 
        interface.
        """

    def update(self, o: java.util.Observable, arg: java.lang.Object):
        """
        This is a method provided by the :obj:`Observer` interface and must be 
        implemented.  However, we will not be using it (see :obj:`InstructionTableObserver` 
        for details).
        """


class InstructionMetadata(java.lang.Object):
    """
    Data container encapsulating all pertinent mask information about a single
    instruction. In some cases, the user may have selected a set of instructions
    that contains data elements that are technically NOT instructions, but are
    captured using this data structure anyway (hence the private 'instruction'
    boolean.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, maskContainer: MaskContainer):
        """
        Constructor. We always need to have a mask container, so force users to
        pass it in.
        
        :param MaskContainer maskContainer:
        """

    def getAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getMaskContainer(self) -> MaskContainer:
        ...

    def getOperands(self) -> java.util.List[OperandMetadata]:
        ...

    def getTextRep(self) -> str:
        ...

    def isInstruction(self) -> bool:
        ...

    def isMasked(self) -> bool:
        ...

    def setAddr(self, addr: ghidra.program.model.address.Address):
        ...

    def setIsInstruction(self, instruction: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMasked(self, mask: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOperands(self, operands: java.util.List[OperandMetadata]):
        ...

    def setTextRep(self, textRep: typing.Union[java.lang.String, str]):
        ...

    @property
    def operands(self) -> java.util.List[OperandMetadata]:
        ...

    @operands.setter
    def operands(self, value: java.util.List[OperandMetadata]):
        ...

    @property
    def masked(self) -> jpype.JBoolean:
        ...

    @masked.setter
    def masked(self, value: jpype.JBoolean):
        ...

    @property
    def instruction(self) -> jpype.JBoolean:
        ...

    @property
    def addr(self) -> ghidra.program.model.address.Address:
        ...

    @addr.setter
    def addr(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def textRep(self) -> java.lang.String:
        ...

    @textRep.setter
    def textRep(self, value: java.lang.String):
        ...

    @property
    def maskContainer(self) -> MaskContainer:
        ...


class MaskContainer(java.lang.Object):
    """
    Contains the mask/value information for a single mnemonic or operand.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mask: jpype.JArray[jpype.JByte], value: jpype.JArray[jpype.JByte]):
        """
        
        
        :param jpype.JArray[jpype.JByte] mask: 
        :param jpype.JArray[jpype.JByte] value: 
        :raises InvalidInputException:
        """

    def getMask(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: the mask
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getMaskAsBinaryString(self) -> str:
        """
        
        
        :return: 
        :rtype: str
        """

    def getValue(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: the value
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getValueAsBinaryString(self) -> str:
        """
        
        
        :return: 
        :rtype: str
        """

    def setMask(self, mask: jpype.JArray[jpype.JByte]):
        """
        
        
        :param jpype.JArray[jpype.JByte] mask: the mask to set
        """

    def setValue(self, value: jpype.JArray[jpype.JByte]):
        """
        
        
        :param jpype.JArray[jpype.JByte] value: the value to set
        """

    def toBinaryString(self) -> str:
        """
        Returns the bytes and masking merged together, as a binary string.
        
        :param mask: :param value: :return: list containing the value (index 0) and mask (index 1).
        :rtype: str
        """

    @property
    def maskAsBinaryString(self) -> java.lang.String:
        ...

    @property
    def valueAsBinaryString(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...

    @value.setter
    def value(self, value: jpype.JArray[jpype.JByte]):
        ...

    @property
    def mask(self) -> jpype.JArray[jpype.JByte]:
        ...

    @mask.setter
    def mask(self, value: jpype.JArray[jpype.JByte]):
        ...


class OperandMetadata(java.lang.Object):
    """
    Holds information related to a single operand in the :obj:`InstructionTable`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMaskContainer(self) -> MaskContainer:
        ...

    def getOpType(self) -> int:
        ...

    def getTextRep(self) -> str:
        ...

    def isMasked(self) -> bool:
        ...

    def setMaskContainer(self, maskContainer: MaskContainer):
        ...

    def setMasked(self, mask: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOpType(self, opType: typing.Union[jpype.JInt, int]):
        ...

    def setTextRep(self, textRep: typing.Union[java.lang.String, str]):
        ...

    @property
    def masked(self) -> jpype.JBoolean:
        ...

    @masked.setter
    def masked(self, value: jpype.JBoolean):
        ...

    @property
    def opType(self) -> jpype.JInt:
        ...

    @opType.setter
    def opType(self, value: jpype.JInt):
        ...

    @property
    def textRep(self) -> java.lang.String:
        ...

    @textRep.setter
    def textRep(self, value: java.lang.String):
        ...

    @property
    def maskContainer(self) -> MaskContainer:
        ...

    @maskContainer.setter
    def maskContainer(self, value: MaskContainer):
        ...



__all__ = ["InstructionTableDataObject", "MaskSettings", "InstructionTableObserver", "InstructionSearchData", "InstructionTableModel", "InstructionMetadata", "MaskContainer", "OperandMetadata"]
