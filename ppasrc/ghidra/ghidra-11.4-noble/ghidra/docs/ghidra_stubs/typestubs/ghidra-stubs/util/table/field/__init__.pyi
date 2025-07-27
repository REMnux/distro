from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.plugin.core.analysis
import ghidra.app.plugin.core.disassembler
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.classfinder
import ghidra.util.table.column
import java.lang # type: ignore
import java.util # type: ignore


COLUMN_TYPE = typing.TypeVar("COLUMN_TYPE")
ROW_TYPE = typing.TypeVar("ROW_TYPE")


class ReferenceFromAddressTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, ghidra.program.model.address.Address]):
    """
    This table field displays the FromAddress for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getProgramLocation(self, rowObject: ghidra.app.plugin.core.analysis.ReferenceAddressPair, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        ...


class FunctionPurgeTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.String]):
    """
    This table field displays the Function Purge for either the program location or the address
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractReferenceBytesTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, jpype.JArray[java.lang.Byte]]):
    """
    This table field displays the bytes of the code unit at the ToAddress 
    for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LabelTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):
    """
    This table column displays the Label for either the program location or the address
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IsFunctionNonReturningTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.Boolean]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceCountToAddressTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.address.Address, java.lang.Integer]):
    """
    This table field displays the number of references to the location that was found
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.address.Address, AddressBasedLocation]):
    """
    This table field displays Address associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Location"

    def __init__(self):
        ...


class ReferenceToBytesTableColumn(AbstractReferenceBytesTableColumn):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceToAddressTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, ghidra.program.model.address.Address]):
    """
    This table field displays the ToAddress for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getProgramLocation(self, rowObject: ghidra.app.plugin.core.analysis.ReferenceAddressPair, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        ...


class MonospacedByteRenderer(ghidra.util.table.column.AbstractGColumnRenderer[jpype.JArray[java.lang.Byte]]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CodeUnitCountSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[CodeUnitCountSettingsDefinition]
    MAX_CODE_UNIT_COUNT: typing.Final = 8

    def getCount(self, settings: ghidra.docking.settings.Settings) -> int:
        ...

    def getDisplayValue(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def setCount(self, settings: ghidra.docking.settings.Settings, count: typing.Union[jpype.JInt, int]):
        ...

    @property
    def displayValue(self) -> java.lang.String:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...


class AddressBasedLocation(java.lang.Comparable[AddressBasedLocation]):
    """
    ``AddressBasedLocation`` provides the ability to render and compare
    addresses (e.g., location table column). This may be necessary when working a
    mixture of address types (e.g., memory, stack, register, variable, external)
    with the need to render in a meaningful way. Generally, only memory addresses
    are meaningful to a user when rendered as a simple address (e.g.,
    ram:00123456). While most address types are handled, VARIABLE addresses will
    only render as "<VARIABLE>". As such, this implementation should be
    extended if VARIABLE addresses will be encountered.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a null location which generally corresponds to a unknown/bad
        address
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        """
        Construction a location. The memory block name will never be included in
        string representation.
        
        :param ghidra.program.model.listing.Program program: program to which address belongs
        :param ghidra.program.model.address.Address address: address object (VARIABLE addresses should be avoided)
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, reference: ghidra.program.model.symbol.Reference, showBlockName: ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName):
        """
        Construct a location which corresponds to a reference TO address. String
        representation includes support for Offset References and allows control
        over inclusion of memory block name with memory addresses.
        
        :param ghidra.program.model.listing.Program program: program to which address belongs
        :param ghidra.program.model.symbol.Reference reference: program reference (e.g., memory, stack, register, external)
        :param ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName showBlockName: ShowBlockName option for controlling inclusion of memory block 
        name with address rendering
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def isMemoryLocation(self) -> bool:
        """
        
        
        :return: true if location corresponds to memory address
        :rtype: bool
        """

    def isOffsetAddress(self) -> bool:
        """
        Determine if location corresponds to a shifted memory reference
        destination
        
        :return: true if location corresponds to a shifted memory reference destination
        :rtype: bool
        """

    def isReferenceDestination(self) -> bool:
        """
        Determine if location corresponds to a reference destination
        
        :return: true if location corresponds to a reference destination
        :rtype: bool
        """

    def isShiftedAddress(self) -> bool:
        """
        Determine if location corresponds to a shifted memory reference destination
        
        :return: true if location corresponds to a shifted memory reference destination
        :rtype: bool
        """

    @property
    def referenceDestination(self) -> jpype.JBoolean:
        ...

    @property
    def memoryLocation(self) -> jpype.JBoolean:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def shiftedAddress(self) -> jpype.JBoolean:
        ...

    @property
    def offsetAddress(self) -> jpype.JBoolean:
        ...


class IsFunctionCustomStorageTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.Boolean]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceFromBytesTableColumn(AbstractReferenceBytesTableColumn):
    """
    This table field displays the bytes of the code unit at the FromAddress 
    for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionNoReturnSettingsDefinition(ghidra.docking.settings.BooleanSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[FunctionNoReturnSettingsDefinition]

    def __init__(self):
        ...


class ByteCountProgramLocationBasedTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.Integer]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceFromFunctionTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, java.lang.String]):
    """
    This table field displays the name of the function containing the from address for the reference.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getProgramLocation(self, rowObject: ghidra.app.plugin.core.analysis.ReferenceAddressPair, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        ...


class CodeUnitTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, CodeUnitTableCellData]):
    """
    Table column to display :obj:`CodeUnit`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionCallingConventionTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionParameterCountTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.address.Address, java.lang.Integer]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionThunkSettingsDefinition(ghidra.docking.settings.BooleanSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[FunctionThunkSettingsDefinition]

    def __init__(self):
        ...


class PreviewTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, ghidra.util.table.PreviewTableCellData]):
    """
    This table column displays a preview of the :obj:`ProgramLocation` with a row in the table.
    The actual content displayed will vary, depending upon the location.  Further, the preview is
    meant to mimic what the user will see displayed in the Listing display window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ByteCountSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[ByteCountSettingsDefinition]
    DEFAULT: typing.Final = 0
    MAX_BYTE_COUNT: typing.Final = 8


class ReferenceToPreviewTableColumn(AbstractReferencePreviewTableColumn):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceTypeTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.symbol.Reference, ghidra.program.model.symbol.RefType]):
    """
    This table field displays the reference type for the reference 
    associated with a row in the table.
    """

    @typing.type_check_only
    class ReferenceTypeTableCellRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[ghidra.program.model.symbol.RefType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceFromPreviewTableColumn(AbstractReferencePreviewTableColumn):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CodeUnitTableCellData(java.lang.Comparable[CodeUnitTableCellData]):
    """
    A class that knows how to render :obj:`CodeUnit`s in 1 or more lines
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.program.util.ProgramLocation, codeUnitFormat: ghidra.program.model.listing.CodeUnitFormat, codeUnitOffset: typing.Union[jpype.JInt, int], codeUnitCount: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param ghidra.program.util.ProgramLocation location: the location of the code unit to display
        :param ghidra.program.model.listing.CodeUnitFormat codeUnitFormat: the format needed to render the code unit
        :param jpype.JInt or int codeUnitOffset: relative code-unit offset from the specified address 
                    (this is not a byte-offset, it is expressed in terms of number of code-units).
        :param jpype.JInt or int codeUnitCount: number of code-units to be displayed
        """

    def getDisplayString(self) -> str:
        """
        Get the visual representation for the code unit at or containing the address 
        associated with this cell's row
        
        :return: the display string
        :rtype: str
        """

    def getDisplayStrings(self) -> java.util.List[java.lang.String]:
        ...

    def getHTMLDisplayString(self) -> str:
        """
        Get the visual representation as HTML for the code unit at or containing the 
        address associated with this cell's row
        
        :return: the display string
        :rtype: str
        """

    def isOffcut(self) -> bool:
        ...

    @property
    def hTMLDisplayString(self) -> java.lang.String:
        ...

    @property
    def displayStrings(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def offcut(self) -> jpype.JBoolean:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...


class AbstractProgramBasedDynamicTableColumn(docking.widgets.table.AbstractDynamicTableColumn[ROW_TYPE, COLUMN_TYPE, ghidra.program.model.listing.Program], typing.Generic[ROW_TYPE, COLUMN_TYPE]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, uniqueID: typing.Union[java.lang.String, str]):
        ...


class MemoryTypeProgramLocationBasedTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, ghidra.program.model.mem.MemoryBlock]):

    @typing.type_check_only
    class MemoryTypeRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[ghidra.program.model.mem.MemoryBlock]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MemoryTypeComparator(java.util.Comparator[ghidra.program.model.mem.MemoryBlock]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramLocationTableColumnExtensionPoint(docking.widgets.table.DynamicTableColumnExtensionPoint[ROW_TYPE, COLUMN_TYPE, ghidra.program.model.listing.Program], ProgramLocationTableColumn[ROW_TYPE, COLUMN_TYPE], typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    """
    A convenience class that allows subclasses to signal that they implement 
    :obj:`ProgramLocationTableColumn` and that they are :obj:`ExtensionPoint`s.
     
    
    If you do not wish to be an extension point, but do wish to provide ProgramLocation objects,
    then you can just implement :obj:`ProgramLocationTableColumn` or extend 
    :obj:`AbstractProgramLocationTableColumn`.
    
    
    .. seealso::
    
        | :obj:`ProgramLocationTableColumn`
    
        | :obj:`AbstractProgramLocationTableColumn`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramBasedDynamicTableColumnExtensionPoint(AbstractProgramBasedDynamicTableColumn[ROW_TYPE, COLUMN_TYPE], ghidra.util.classfinder.ExtensionPoint, typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    """
    NOTE:  ALL ProgramBasedDynamicTableColumnExtensionPoint CLASSES MUST END IN "TableColumn".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, uniqueID: typing.Union[java.lang.String, str]):
        ...


class ProgramLocationTableColumn(ProgramBasedDynamicTableColumn[ROW_TYPE, COLUMN_TYPE], typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    """
    An table column that knows how to generate ProgramLocation objects for a give row type.
    
    
    .. seealso::
    
        | :obj:`AbstractProgramBasedDynamicTableColumn`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getProgramLocation(self, rowObject: ROW_TYPE, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        """
        Determines an appropriate program location associated with this field for the indicated row object.
        The most probable use is for navigating from the field.
        
        :param ROW_TYPE rowObject: the object associated with the table row.
        :param ghidra.docking.settings.Settings settings: field settings
        :param ghidra.program.model.listing.Program program: the program associated with the table.
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the plugin tool associated with the table.
        :return: the address associated with the field.
        :rtype: ghidra.program.util.ProgramLocation
        """


class FunctionTagTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.String]):
    """
    Table column for displaying all function tags associated with a given function. Tags
    will be displayed as a set of comma-delimited strings, in sorted order.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressRangeEndpointSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):
    """
    A class for selecting whether to use the min address or the max address of an 
    :obj:`AddressRange` for address range table columns
    """

    class_: typing.ClassVar[java.lang.Class]
    BEGIN: typing.Final = "Begin"
    END: typing.Final = "End"
    BEGIN_CHOICE_INDEX: typing.Final = 0
    END_CHOICE_INDEX: typing.Final = 1
    DEF: typing.Final[AddressRangeEndpointSettingsDefinition]


class MemorySectionProgramLocationBasedTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionInlineSettingsDefinition(ghidra.docking.settings.BooleanSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[FunctionInlineSettingsDefinition]

    def __init__(self):
        ...


class OffcutReferenceCountToAddressTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.address.Address, java.lang.Integer]):
    """
    This table field displays the number of references to the location that was found
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IncomingReferenceEndpoint(ReferenceEndpoint):
    """
    Marker row object that signals to the table API that the references contained therein all
    share the ``to`` address, with each row showing the ``from`` address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, r: ghidra.program.model.symbol.Reference, isOffcut: typing.Union[jpype.JBoolean, bool]):
        ...


class OutgoingReferenceEndpoint(ReferenceEndpoint):
    """
    Marker row object that signals to the table API that the references contained therein all
    share the ``from`` address, with each row showing the ``to`` address.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, r: ghidra.program.model.symbol.Reference, isOffcut: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, r: ghidra.program.model.symbol.Reference, toAddress: ghidra.program.model.address.Address, isOffcut: typing.Union[jpype.JBoolean, bool]):
        """
        A special constructor that allows clients to override the 'toAddress' of the reference.
        
        :param ghidra.program.model.symbol.Reference r: the reference
        :param ghidra.program.model.address.Address toAddress: the desired 'toAddress'
        :param jpype.JBoolean or bool isOffcut: false if the given reference points to the min address of a code unit
        """


class AbstractReferencePreviewTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, ghidra.util.table.PreviewTableCellData]):
    """
    This table field displays the preview of the code unit at the ToAddress 
    for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EOLCommentTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):
    """
    This table column displays the Label for either the program location or the address
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceEndpoint(java.lang.Object):
    """
    An object that is one end of a :obj:`Reference`.  This is used by table models that want to
    show all references from one location to many other locations or models that wish to 
    show all references to one location from many other locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getReference(self) -> ghidra.program.model.symbol.Reference:
        ...

    def getReferenceType(self) -> ghidra.program.model.symbol.RefType:
        ...

    def getSource(self) -> ghidra.program.model.symbol.SourceType:
        ...

    def isOffcut(self) -> bool:
        ...

    @property
    def reference(self) -> ghidra.program.model.symbol.Reference:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def offcut(self) -> jpype.JBoolean:
        ...

    @property
    def referenceType(self) -> ghidra.program.model.symbol.RefType:
        ...

    @property
    def source(self) -> ghidra.program.model.symbol.SourceType:
        ...


class CodeUnitOffsetSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[CodeUnitOffsetSettingsDefinition]
    DEFAULT_OFFSET: typing.Final = 0
    MIN_OFFSET: typing.Final = -8
    MAX_OFFSET: typing.Final = 8
    DEFAULT_CHOICE: typing.Final = 8

    def getDisplayValue(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getOffset(self, settings: ghidra.docking.settings.Settings) -> int:
        ...

    def setOffset(self, settings: ghidra.docking.settings.Settings, offset: typing.Union[jpype.JInt, int]):
        ...

    @property
    def displayValue(self) -> java.lang.String:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...


class IsFunctionVarargsTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.Boolean]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressTableLengthTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.disassembler.AddressTable, java.lang.Integer]):
    """
    This table field displays size of the address table associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getProgramLocation(self, rowObject: ghidra.app.plugin.core.disassembler.AddressTable, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        ...


class ProgramBasedDynamicTableColumn(docking.widgets.table.DynamicTableColumn[ROW_TYPE, COLUMN_TYPE, ghidra.program.model.listing.Program], typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AbstractProgramLocationTableColumn(AbstractProgramBasedDynamicTableColumn[ROW_TYPE, COLUMN_TYPE], ProgramLocationTableColumn[ROW_TYPE, COLUMN_TYPE], typing.Generic[ROW_TYPE, COLUMN_TYPE]):
    """
    A convenience class that allows subclasses to signal that they implement 
    :obj:`ProgramLocationTableColumn`, but they do not want to be :obj:`ExtensionPoint`s.  For
    those wishing to be ExtensionPoints, see :obj:`ProgramLocationTableColumnExtensionPoint`.
    
    
    .. seealso::
    
        | :obj:`ProgramLocationTableColumnExtensionPoint`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class IsFunctionInlineTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.Boolean]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionNameTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.address.Address, java.lang.String]):
    """
    This table field displays the Function Name containing either the program location or the address
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceFromLabelTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.analysis.ReferenceAddressPair, java.lang.String]):
    """
    This table field displays the primary symbol at the FromAddress
    for the reference or possible reference address pair
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getProgramLocation(self, rowObject: ghidra.app.plugin.core.analysis.ReferenceAddressPair, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation:
        ...


class FunctionSignatureTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.listing.Function, ghidra.program.model.listing.Function]):
    """
    This table field displays the Function Signature for either the program location or the address
    associated with a row in the table.
    """

    @typing.type_check_only
    class SignatureRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[ghidra.program.model.listing.Function]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SourceTypeTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BytesTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.program.model.address.Address, jpype.JArray[java.lang.Byte]]):
    """
    This table field displays the bytes for the code unit beginning at the address
    associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default Constructor
        """


class SymbolTypeTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NamespaceTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.util.ProgramLocation, java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemoryOffsetSettingsDefinition(ghidra.docking.settings.EnumSettingsDefinition):

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[MemoryOffsetSettingsDefinition]
    DEFAULT_OFFSET: typing.Final = 0
    MIN_OFFSET: typing.Final = -8
    MAX_OFFSET: typing.Final = 8
    DEFAULT_CHOICE: typing.Final = 8

    def getDisplayValue(self, settings: ghidra.docking.settings.Settings) -> str:
        ...

    def getOffset(self, settings: ghidra.docking.settings.Settings) -> int:
        ...

    def setOffset(self, settings: ghidra.docking.settings.Settings, offset: typing.Union[jpype.JInt, int]):
        ...

    @property
    def displayValue(self) -> java.lang.String:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...


class FunctionBodySizeTableColumn(ProgramBasedDynamicTableColumnExtensionPoint[ghidra.program.model.listing.Function, java.lang.Integer]):

    @typing.type_check_only
    class FunctionBodySizeRenderer(docking.widgets.table.GTableCellRenderer, ghidra.util.table.column.AbstractWrapperTypeColumnRenderer[java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressTableDataTableColumn(ProgramLocationTableColumnExtensionPoint[ghidra.app.plugin.core.disassembler.AddressTable, java.lang.String]):
    """
    This table column displays Data for the address table associated with a row in the table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ReferenceFromAddressTableColumn", "FunctionPurgeTableColumn", "AbstractReferenceBytesTableColumn", "LabelTableColumn", "IsFunctionNonReturningTableColumn", "ReferenceCountToAddressTableColumn", "AddressTableColumn", "ReferenceToBytesTableColumn", "ReferenceToAddressTableColumn", "MonospacedByteRenderer", "CodeUnitCountSettingsDefinition", "AddressBasedLocation", "IsFunctionCustomStorageTableColumn", "ReferenceFromBytesTableColumn", "FunctionNoReturnSettingsDefinition", "ByteCountProgramLocationBasedTableColumn", "ReferenceFromFunctionTableColumn", "CodeUnitTableColumn", "FunctionCallingConventionTableColumn", "FunctionParameterCountTableColumn", "FunctionThunkSettingsDefinition", "PreviewTableColumn", "ByteCountSettingsDefinition", "ReferenceToPreviewTableColumn", "ReferenceTypeTableColumn", "ReferenceFromPreviewTableColumn", "CodeUnitTableCellData", "AbstractProgramBasedDynamicTableColumn", "MemoryTypeProgramLocationBasedTableColumn", "ProgramLocationTableColumnExtensionPoint", "ProgramBasedDynamicTableColumnExtensionPoint", "ProgramLocationTableColumn", "FunctionTagTableColumn", "AddressRangeEndpointSettingsDefinition", "MemorySectionProgramLocationBasedTableColumn", "FunctionInlineSettingsDefinition", "OffcutReferenceCountToAddressTableColumn", "IncomingReferenceEndpoint", "OutgoingReferenceEndpoint", "AbstractReferencePreviewTableColumn", "EOLCommentTableColumn", "ReferenceEndpoint", "CodeUnitOffsetSettingsDefinition", "IsFunctionVarargsTableColumn", "AddressTableLengthTableColumn", "ProgramBasedDynamicTableColumn", "AbstractProgramLocationTableColumn", "IsFunctionInlineTableColumn", "FunctionNameTableColumn", "ReferenceFromLabelTableColumn", "FunctionSignatureTableColumn", "SourceTypeTableColumn", "BytesTableColumn", "SymbolTypeTableColumn", "NamespaceTableColumn", "MemoryOffsetSettingsDefinition", "FunctionBodySizeTableColumn", "AddressTableDataTableColumn"]
