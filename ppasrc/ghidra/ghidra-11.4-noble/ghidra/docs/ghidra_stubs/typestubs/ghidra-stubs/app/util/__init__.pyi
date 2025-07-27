from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.dnd
import docking.widgets.fieldpanel.support
import docking.widgets.table
import generic.concurrent
import generic.stl
import generic.theme
import ghidra.app.nav
import ghidra.app.util.bin
import ghidra.app.util.html
import ghidra.app.util.importer
import ghidra.app.util.query
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.options
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.table
import ghidra.util.table.field
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore
import javax.swing.event # type: ignore


I = typing.TypeVar("I")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class SearchConstants(java.lang.Object):
    """
    Miscellaneous constants
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_SEARCH_LIMIT: typing.Final = 500
    """
    The default search limit.
    """

    SEARCH_OPTION_NAME: typing.Final = "Search"
    """
    Name of the Options object for Search.
    """

    SEARCH_LIMIT_NAME: typing.Final = "Search Limit"
    """
    Option for the max number of hits found in a search; the search
    stops when it reaches this limit.
    """

    SEARCH_HIGHLIGHT_NAME: typing.Final = "Highlight Search Results"
    """
    Option name for whether to highlight search results.
    """

    SEARCH_HIGHLIGHT_COLOR_OPTION_NAME: typing.Final = " Highlight Color"
    """
    Color for highlighting for searches.
    """

    SEARCH_HIGHLIGHT_COLOR: typing.Final[generic.theme.GColor]
    SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME: typing.Final = "Highlight Color for Current Match"
    """
    Default highlight color used when something to highlight is at the current address.
    """

    SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR: typing.Final[generic.theme.GColor]


class ClipboardType(java.lang.Object):
    """
    Defines a "type" for items in the Clipboard
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, flavor: java.awt.datatransfer.DataFlavor, typeName: typing.Union[java.lang.String, str]):
        """
        Constructs a new ClipboardType
        
        :param java.awt.datatransfer.DataFlavor flavor: the DataFlavor of the data in the clipboard
        :param java.lang.String or str typeName: the name for this ClipboardType
        """

    def getFlavor(self) -> java.awt.datatransfer.DataFlavor:
        """
        Returns the DataFlavor for this type
        
        :return: the flavor
        :rtype: java.awt.datatransfer.DataFlavor
        """

    def getTypeName(self) -> str:
        """
        Returns the name of this type
        
        :return: the name
        :rtype: str
        """

    @property
    def flavor(self) -> java.awt.datatransfer.DataFlavor:
        ...

    @property
    def typeName(self) -> java.lang.String:
        ...


class DomainObjectService(java.lang.Object):
    """
    Simple interface for getting a DomainObject. This is used to delay the opening of
    a domainObject until it is needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDomainObject(self) -> ghidra.framework.model.DomainObject:
        """
        Get the domain object to be exported
        
        :return: domain object or null if export limited to domain file
        :rtype: ghidra.framework.model.DomainObject
        """

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...


class SelectionTransferData(java.lang.Object):
    """
    Data that is the transferable in SelectionTransferable; it contains an address set and the
    path of the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, set: ghidra.program.model.address.AddressSetView, programPath: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.address.AddressSetView set: address set to transfer
        :param java.lang.String or str programPath: path to the program that contains the set
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Return the address set.
        """

    def getProgramPath(self) -> str:
        """
        Return the program path.
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def programPath(self) -> java.lang.String:
        ...


class HexLong(java.lang.Number):

    class_: typing.ClassVar[java.lang.Class]
    longValue: typing.Final[java.lang.Long]

    def __init__(self, longValue: typing.Union[jpype.JLong, int]):
        ...


class ProgramDropProvider(java.lang.Object):
    """
    Generic interface to handle drag and drop.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, contextObj: java.lang.Object, data: java.lang.Object, flavor: java.awt.datatransfer.DataFlavor):
        """
        Adds the dropped data to this drop service.
        
        :param java.lang.Object contextObj: The object where the drop occurred
        :param java.lang.Object data: The actual data dropped
        :param java.awt.datatransfer.DataFlavor flavor: The selected data flavor
        """

    def getDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Get the data flavors that this drop service accepts.
        
        :return: an array of all DataFlavors that this drop service supports
        :rtype: jpype.JArray[java.awt.datatransfer.DataFlavor]
        """

    def getPriority(self) -> int:
        """
        Returns the priority of this provider.  Higher priority services will be chosen
        if there are multiple services that accept the same type in the same context.
        """

    def isDropOk(self, contextObj: java.lang.Object, evt: java.awt.dnd.DropTargetDragEvent) -> bool:
        """
        Returns true if this service can accept a drop with the specified context.
        
        :param java.lang.Object contextObj: The object where the drop will occur
        :param java.awt.dnd.DropTargetDragEvent evt: The event associated with the drop that includes the dropped DataFlavors
        """

    @property
    def dataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class Option(java.lang.Object):
    """
    Container class to hold a name, value, and class of the value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], value: java.lang.Object):
        """
        Construct a new Option.
        
        :param java.lang.String or str name: name of the option
        :param java.lang.Object value: value of the option. Value can't be null with this constructor.
        :raises IllegalArgumentException: if value is null
        """

    @typing.overload
    def __init__(self, group: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], value: java.lang.Object):
        """
        Construct a new Option.
        
        :param java.lang.String or str group: Name for group of options
        :param java.lang.String or str name: name of the option
        :param java.lang.Object value: value of the option
        :raises IllegalArgumentException: if value is null
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[typing.Any]):
        """
        Construct a new Option.
        
        :param java.lang.String or str name: name of the option
        :param java.lang.Class[typing.Any] valueClass: class of the option's value
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], value: java.lang.Object, valueClass: java.lang.Class[typing.Any], arg: typing.Union[java.lang.String, str]):
        """
        Construct a new Option
        
        :param java.lang.String or str name: name of the option
        :param java.lang.Object value: value of the option
        :param java.lang.Class[typing.Any] valueClass: class of the option's value
        :param java.lang.String or str arg: the option's command line argument
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[typing.Any], value: java.lang.Object, arg: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str]):
        """
        Construct a new Option
        
        :param java.lang.String or str name: name of the option
        :param java.lang.Class[typing.Any] valueClass: class of the option's value
        :param java.lang.Object value: value of the option
        :param java.lang.String or str arg: the option's command line argument
        :param java.lang.String or str group: Name for group of options
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], valueClass: java.lang.Class[typing.Any], value: java.lang.Object, arg: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], stateKey: typing.Union[java.lang.String, str], hidden: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new Option
        
        :param java.lang.String or str name: name of the option
        :param java.lang.Class[typing.Any] valueClass: class of the option's value
        :param java.lang.Object value: value of the option
        :param java.lang.String or str arg: the option's command line argument
        :param java.lang.String or str group: Name for group of options
        :param java.lang.String or str stateKey: state key name
        :param jpype.JBoolean or bool hidden: true if this option should be hidden from the user; otherwise, false
        """

    def copy(self) -> Option:
        """
        Creates a copy of this Option object.
        
        :return: a copy of this Option object.
        :rtype: Option
        """

    def getArg(self) -> str:
        """
        :return: the command line argument for this option (could be null)
        :rtype: str
        """

    def getCustomEditorComponent(self) -> java.awt.Component:
        """
        Override if you want to provide a custom widget for selecting your
        options. 
         
        
        Important! If you override this you MUST also override the :meth:`copy() <.copy>`
        method so it returns a new instance of your custom editor.
        
        :return: the custom editor
        :rtype: java.awt.Component
        """

    def getGroup(self) -> str:
        """
        :return: the group name for this option; may be null if group was not specified
        :rtype: str
        """

    def getName(self) -> str:
        """
        :return: the name of this option
        :rtype: str
        """

    def getState(self) -> ghidra.framework.options.SaveState:
        """
        :return: the current project state associated with this option (could be null)
        :rtype: ghidra.framework.options.SaveState
        """

    def getStateKey(self) -> str:
        """
        :return: the state key name (could be null)
        :rtype: str
        """

    def getValue(self) -> java.lang.Object:
        """
        :return: the value of this option
        :rtype: java.lang.Object
        """

    def getValueClass(self) -> java.lang.Class[typing.Any]:
        """
        :return: the class of the value for this option
        :rtype: java.lang.Class[typing.Any]
        """

    def isHidden(self) -> bool:
        """
        :return: whether or not this option is hidden
        :rtype: bool
        """

    def parseAndSetValueByType(self, str: typing.Union[java.lang.String, str], addressFactory: ghidra.program.model.address.AddressFactory) -> bool:
        """
        Set the value for this option by parsing the given string and converting it to the option's
        type.  Fails if this option doesn't have a type associated with it, or if an unsupported
        type is needed to be parsed.
        
        :param java.lang.String or str str: The value to set, in string form.
        :param ghidra.program.model.address.AddressFactory addressFactory: An address factory to use for when the option trying to be set is an Address.
        If null, an exception will be thrown for Address type options.
        :return: True if the value was successfully parsed and set; otherwise, false.
        :rtype: bool
        """

    def setOptionListener(self, listener: OptionListener):
        ...

    def setValue(self, object: java.lang.Object):
        """
        Set the value for this option.
        
        :param java.lang.Object object: value of this option
        """

    @property
    def hidden(self) -> jpype.JBoolean:
        ...

    @property
    def arg(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def customEditorComponent(self) -> java.awt.Component:
        ...

    @property
    def valueClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def state(self) -> ghidra.framework.options.SaveState:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @value.setter
    def value(self, value: java.lang.Object):
        ...

    @property
    def stateKey(self) -> java.lang.String:
        ...

    @property
    def group(self) -> java.lang.String:
        ...


class ListingHighlightProvider(java.lang.Object):
    """
    Provider of Highlight objects appropriate :obj:`ListingField`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_HIGHLIGHTS: typing.Final[jpype.JArray[docking.widgets.fieldpanel.support.Highlight]]

    def createHighlights(self, text: typing.Union[java.lang.String, str], field: ghidra.app.util.viewer.field.ListingField, cursorTextOffset: typing.Union[jpype.JInt, int]) -> jpype.JArray[docking.widgets.fieldpanel.support.Highlight]:
        """
        Get the highlights appropriate for the given text
        
        :param java.lang.String or str text: the entire text contained in the field, regardless of layout.
        :param ghidra.app.util.viewer.field.ListingField field: the field being rendered.  From this field you can get the field factory and 
                the proxy object, which is usually a :obj:`CodeUnit`.
        :param jpype.JInt or int cursorTextOffset: the cursor position within the given text or -1 if no cursor in this 
                field.
        :return: an array of highlight objects that indicate the location within the text string to
                be highlighted.
        :rtype: jpype.JArray[docking.widgets.fieldpanel.support.Highlight]
        """


class EditFieldNameDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        """
        Construct a new dialog.
        
        :param java.lang.String or str title: title for the dialog, null value is acceptable if no title
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool
        """

    def editField(self, dataTypeComponent: ghidra.program.model.data.DataTypeComponent, p: ghidra.program.model.listing.Program):
        ...


class EolComments(java.lang.Object):
    """
    Utility class with methods to get comment information that can be displayed in the end of line
    comment field. Each instance of this class is associated with a code unit.  This class uses the
    provided options to decide how to load and filter existing comments.
    
     
    Comment types that can be shown include the End of Line comment for the code unit, the
    Repeatable comment for the code unit, any repeatable comments for the code units that this code
    unit has references to, and possibly a comment indicating the data at a code unit that is
    referenced by this code unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cu: ghidra.program.model.listing.CodeUnit, operandsShowReferences: typing.Union[jpype.JBoolean, bool], maxDisplayComments: typing.Union[jpype.JInt, int], extraCommentsOption: ghidra.app.util.viewer.field.EolExtraCommentsOption):
        ...

    def getAutomaticComment(self) -> java.util.List[java.lang.String]:
        """
        Gets the automatic comments
        
        :return: the comments
        :rtype: java.util.List[java.lang.String]
        """

    def getComments(self) -> java.util.List[java.lang.String]:
        """
        Return all comments loaded by this class
        
        :return: the comments
        :rtype: java.util.List[java.lang.String]
        """

    def getEOLComments(self) -> java.util.List[java.lang.String]:
        """
        Gets the End of Line comments
        
        :return: the comments
        :rtype: java.util.List[java.lang.String]
        """

    def getLocation(self, eolRow: typing.Union[jpype.JInt, int], eolColumn: typing.Union[jpype.JInt, int]) -> ghidra.program.util.ProgramLocation:
        ...

    def getOffcutEolComments(self) -> java.util.List[java.lang.String]:
        ...

    def getReferencedRepeatableComments(self) -> java.util.List[RefRepeatComment]:
        """
        Gets the repeatable comments at the "to reference"s
        
        :return: the comments
        :rtype: java.util.List[RefRepeatComment]
        """

    def getRepeatableComments(self) -> java.util.List[java.lang.String]:
        """
        Gets the repeatable comments
        
        :return: the comments
        :rtype: java.util.List[java.lang.String]
        """

    def getRowCol(self, cloc: ghidra.program.util.CommentFieldLocation) -> docking.widgets.fieldpanel.support.RowColLocation:
        ...

    def isShowingAutoComments(self) -> bool:
        ...

    def isShowingOffcutComments(self) -> bool:
        ...

    def isShowingRefRepeatables(self) -> bool:
        ...

    def isShowingRepeatables(self) -> bool:
        ...

    @property
    def showingRefRepeatables(self) -> jpype.JBoolean:
        ...

    @property
    def eOLComments(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def referencedRepeatableComments(self) -> java.util.List[RefRepeatComment]:
        ...

    @property
    def comments(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def showingAutoComments(self) -> jpype.JBoolean:
        ...

    @property
    def showingRepeatables(self) -> jpype.JBoolean:
        ...

    @property
    def repeatableComments(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def offcutEolComments(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def automaticComment(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def showingOffcutComments(self) -> jpype.JBoolean:
        ...

    @property
    def rowCol(self) -> docking.widgets.fieldpanel.support.RowColLocation:
        ...


class CodeUnitInfoTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is an ArrayList of CodeUnitInfo objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    localDataTypeFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    """
    DataFlavor that it is an ArrayList of CodeUnitInfo objects.
    """


    def __init__(self, list: java.util.List[CodeUnitInfo]):
        """
        Construct a new CodeUnitTransferable.
        
        :param java.util.List[CodeUnitInfo] list: list of CodeUnitInfo objects
        """

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specified data flavor is supported.
        """

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        ...

    def toString(self) -> str:
        """
        Get the string representation for this transferable.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


class AddressInput(javax.swing.JPanel, docking.widgets.table.FocusableEditor):
    """
    Input field for entering address or address expression.  Handles multiple address
    spaces and supports both hex and decimal number modes for evaluating numbers.
    """

    @typing.type_check_only
    class AddressSpaceField(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ALL_MEMORY_SPACES: typing.Final[java.util.function.Predicate[ghidra.program.model.address.AddressSpace]]
    LOADED_MEMORY_SPACES: typing.Final[java.util.function.Predicate[ghidra.program.model.address.AddressSpace]]

    @typing.overload
    def __init__(self):
        """
        Constructs an AddressInput field with no specified program or address.
        """

    @typing.overload
    def __init__(self, addressChangedConsumer: java.util.function.Consumer[ghidra.program.model.address.Address]):
        """
        Constructs an AddressInput field with a consumer to be called when the address field's
        value changes.
        
        :param java.util.function.Consumer[ghidra.program.model.address.Address] addressChangedConsumer: the consumer to be called when the value in the address field 
        changes
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Constructs an AddressInput field and initialized with a program.
        
        :param ghidra.program.model.listing.Program program: the program used to evaluate the entered address expression.
        """

    @typing.overload
    def __init__(self, factory: ghidra.program.model.address.AddressFactory):
        """
        Constructs an AddressInput field and initialized with an address factory.
        
        :param ghidra.program.model.address.AddressFactory factory: the address factory used to evaluate the entered address expression.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addressChangedConsumer: java.util.function.Consumer[ghidra.program.model.address.Address]):
        """
        Constructs an AddressInput field with a consumer to be notified when the address field
        changes and initialized with a program.
        
        :param ghidra.program.model.listing.Program program: the program used to evaluate the entered address expression.
        :param java.util.function.Consumer[ghidra.program.model.address.Address] addressChangedConsumer: the consumer to be called when the value in the address field
        changes
        """

    @typing.overload
    def __init__(self, factory: ghidra.program.model.address.AddressFactory, addressChangedConsumer: java.util.function.Consumer[ghidra.program.model.address.Address]):
        """
        Constructs an AddressInput field with a consumer to be notified when the address field
        changes and initialized with an address factory.
        
        :param ghidra.program.model.address.AddressFactory factory: the address factory used to evaluate the entered address expression.
        :param java.util.function.Consumer[ghidra.program.model.address.Address] addressChangedConsumer: the consumer to be called when the value in the address field
        changes
        """

    def addActionListener(self, listener: java.awt.event.ActionListener):
        """
        Add an action listener that will be notified anytime the user presses the
        return key while in the text field.
        
        :param java.awt.event.ActionListener listener: the action listener to be notified.
        """

    def clear(self):
        """
        Clear the offset part of the address field.
        """

    def containsAddressSpaces(self) -> bool:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the current address the field evaluates to or null if the text does not evaluate to 
        a valid, unique address.
        
        :return: the current address the field evalutes to or null if the text does not evalute to 
        a valid unique address.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Returns the address space selected in the combobox the default address space if the
        comboBox is not being shown.
        
        :return: the selected address space, or the default address space if no combo added, or
        null if no program is set.
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getAddressWithExceptions(self) -> ghidra.program.model.address.Address:
        """
        Returns the address in the field or null if the address can't
        be parsed.
        
        :return: The address for the current value in the text field
        :rtype: ghidra.program.model.address.Address
        :raises ExpressionException: if expression can not be evaluated to a valid address.
        :raises NullPointerException: if AddressFactory has not been set.
        """

    def getText(self) -> str:
        """
        Returns the text in this field.
        
        :return: the text in this field
        :rtype: str
        """

    def hasInput(self) -> bool:
        """
        Returns true if the Address input field contains text.
        The getAddress() method will return null if text is not
        a valid address.
        
        :return: true if the address field is not blank
        :rtype: bool
        """

    def isEditable(self) -> bool:
        """
        Returns true if the address input field is editable.
        
        :return: true if the address input field is editable.
        :rtype: bool
        """

    def removeActionListener(self, listener: java.awt.event.ActionListener):
        """
        Removes the action listener from the list to be notified.
        
        :param java.awt.event.ActionListener listener: the listener to be removed
        """

    def select(self):
        """
        Select the text field that is the offset.
        """

    def setAccessibleName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the accessible name for this address input field.
        
        :param java.lang.String or str name: the accessible name for this address field
        """

    def setAddress(self, address: ghidra.program.model.address.Address):
        """
        Set the field to display the given address
        
        :param ghidra.program.model.address.Address address: the new address to display
        """

    def setAddressErrorConsumer(self, addressErrorConsumer: java.util.function.Consumer[java.lang.String]):
        """
        Sets a consumer to be notified when the address input field changes, but can't be parsed
        into a valid address.
        
        :param java.util.function.Consumer[java.lang.String] addressErrorConsumer: the consumer to be notified for bad address input
        """

    def setAddressFactory(self, factory: ghidra.program.model.address.AddressFactory):
        """
        Legacy method for setting the address factory to be used to parse address. Should only be
        used when a program is not readily available.
        
        :param ghidra.program.model.address.AddressFactory factory: the address factory to be used to parse addresses.
        """

    def setAddressSpace(self, addressSpace: ghidra.program.model.address.AddressSpace):
        """
        Sets the selected AddressSpace to the given space.
        
        :param ghidra.program.model.address.AddressSpace addressSpace: the address space to set selected
        """

    def setAddressSpaceEditable(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Set the address space (if it is shown) such that it is not editable.
        If the combo box is shown for multiple address spaces, then
        the combo box is replaced with a fixed uneditable text field that shows
        the currently selected address space.
        
        :param jpype.JBoolean or bool state: false means that the combo box should not be editable
        """

    def setAddressSpaceFilter(self, spaceFilter: java.util.function.Predicate[ghidra.program.model.address.AddressSpace]):
        """
        Sets a filter predicate to determine which address spaces should be selectable by the user.
        If after filtering only one space is remaining, the address space portion of the address
        input field will not be shown.
        
        :param java.util.function.Predicate[ghidra.program.model.address.AddressSpace] spaceFilter: the predicate for filtering selectable address spaces.
        """

    def setAssumeHex(self, hexMode: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the hex/decimal mode for this field. When in hex mode, all numbers are assumed to be
        hexadecimal values. When in decimal mode, all numbers are assumed to be decimal numbers 
        unless prefixed with "0x".
        
        :param jpype.JBoolean or bool hexMode: true to assume numbers are hexadecimal.
        """

    def setComponentBorders(self, border: javax.swing.border.Border):
        """
        Used to set the internal borders for use in specialized use cases such as a table field
        editor.
        
        :param javax.swing.border.Border border: the border to use for the internal components that make up this input field
        """

    def setEditable(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Set the text field to be editable or not.
        
        :param jpype.JBoolean or bool b: true if the address input field can be edited
        """

    @typing.overload
    def setProgram(self, program: ghidra.program.model.listing.Program):
        """
        Set the program to be used to parse addresses and expressions and also
        to determine the list of valid address spaces. Only loaded memory spaces
        will be allowed (see :meth:`AddressSpace.isLoadedMemorySpace() <AddressSpace.isLoadedMemorySpace>`).
        
        :param ghidra.program.model.listing.Program program: the program to use to resolve address expressions
        """

    @typing.overload
    def setProgram(self, program: ghidra.program.model.listing.Program, addessSpaceFilter: java.util.function.Predicate[ghidra.program.model.address.AddressSpace]):
        """
        Sets the program and the address space filter at the same time. This avoid some weird 
        intermediate results if the are set separately.
        
        :param ghidra.program.model.listing.Program program: the program to use to parse addresses and expressions.
        :param java.util.function.Predicate[ghidra.program.model.address.AddressSpace] addessSpaceFilter: the predicate to determine which address spaces are user selectable
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text in the expression input textfield.
        
        :param java.lang.String or str text: the text to initialize the input textfield
        """

    def simulateAddressChanged(self, addr: ghidra.program.model.address.Address):
        """
        Set the address space and offset.
        NOTE: Unlike :meth:`setAddress(Address) <.setAddress>` this method is intended for test use only 
        and mimics user input with address changed notification
        
        :param ghidra.program.model.address.Address addr: the address value
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @address.setter
    def address(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @editable.setter
    def editable(self, value: jpype.JBoolean):
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @addressSpace.setter
    def addressSpace(self, value: ghidra.program.model.address.AddressSpace):
        ...

    @property
    def addressWithExceptions(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...


class MemoryBlockUtils(java.lang.Object):
    """
    Convenience methods for creating memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def adjustFragment(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]):
        """
        Adjusts the name of the fragment at the given address to the given name.
        
        :param ghidra.program.model.listing.Program program: the program whose fragment is to be renamed.
        :param ghidra.program.model.address.Address address: the address of the fragment to be renamed.
        :param java.lang.String or str name: the new name for the fragment.
        """

    @staticmethod
    def createBitMappedBlock(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, base: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], overlay: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.mem.MemoryBlock:
        """
        Creates a new bit mapped memory block. (A bit mapped block is a block where each byte value
        is either 1 or 0 and the value is taken from a bit in a byte at some other address in memory)
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param ghidra.program.model.address.Address base: the address of the region in memory to map to.
        :param jpype.JInt or int length: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param jpype.JBoolean or bool overlay: create overlay block if true otherwise a normal mapped block will be created
        :param ghidra.app.util.importer.MessageLog log: a :obj:`StringBuffer` for appending error messages
        :return: the new created block
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    @staticmethod
    def createByteMappedBlock(program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, base: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], overlay: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.mem.MemoryBlock:
        """
        Creates a new byte mapped memory block with a 1:1 byte mapping scheme. 
        (A byte mapped block is a block where each byte value
        is taken from a byte at some other address in memory)
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param ghidra.program.model.address.Address base: the address of the region in memory to map to.
        :param jpype.JInt or int length: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param jpype.JBoolean or bool overlay: create overlay block if true otherwise a normal mapped block will be created
        :param ghidra.app.util.importer.MessageLog log: a :obj:`MessageLog` for appending error messages
        :return: the new created block
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    @staticmethod
    @typing.overload
    def createFileBytes(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes:
        """
        Creates a new :obj:`FileBytes` object using all the bytes from a :obj:`ByteProvider`
        
        :param ghidra.program.model.listing.Program program: the program in which to create a new FileBytes object
        :param ghidra.app.util.bin.ByteProvider provider: the ByteProvider from which to get the bytes.
        :return: the newly created FileBytes object.
        :rtype: ghidra.program.database.mem.FileBytes
        :param ghidra.util.task.TaskMonitor monitor: the monitor for canceling this potentially long running operation.
        :raises IOException: if an IOException occurred.
        :raises CancelledException: if the user cancelled the operation
        """

    @staticmethod
    @typing.overload
    def createFileBytes(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes:
        """
        Creates a new :obj:`FileBytes` object using a portion of the bytes from a :obj:`ByteProvider`
        
        :param ghidra.program.model.listing.Program program: the program in which to create a new FileBytes object
        :param ghidra.app.util.bin.ByteProvider provider: the ByteProvider from which to get the bytes.
        :param jpype.JLong or int offset: the offset into the ByteProvider from which to start loading bytes.
        :param jpype.JLong or int length: the number of bytes to load
        :param ghidra.util.task.TaskMonitor monitor: the monitor for canceling this potentially long running operation.
        :return: the newly created FileBytes object.
        :rtype: ghidra.program.database.mem.FileBytes
        :raises IOException: if an IOException occurred.
        :raises CancelledException: if the user cancelled the operation
        """

    @staticmethod
    @typing.overload
    def createInitializedBlock(program: ghidra.program.model.listing.Program, isOverlay: typing.Union[jpype.JBoolean, bool], name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.mem.MemoryBlock:
        """
        Create a new initialized memory block.  Initialized to all zeros.
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay space for that block
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param jpype.JLong or int length: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param ghidra.app.util.importer.MessageLog log: a :obj:`MessageLog` for appending error messages
        :return: the newly created block or null if the operation failed.
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    @staticmethod
    @typing.overload
    def createInitializedBlock(program: ghidra.program.model.listing.Program, isOverlay: typing.Union[jpype.JBoolean, bool], name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, fileBytes: ghidra.program.database.mem.FileBytes, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.mem.MemoryBlock:
        """
        Creates a new initialized block in memory using the bytes from a :obj:`FileBytes` object.
        If there is a conflict when creating this block (some other block occupies at least some
        of the addresses that would be occupied by the new block), then an attempt will be made
        to create the new block in an overlay.
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay space for that block
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param ghidra.program.database.mem.FileBytes fileBytes: the :obj:`FileBytes` object that supplies the bytes for this block.
        :param jpype.JLong or int offset: the offset into the :obj:`FileBytes` object where the bytes for this block reside.
        :param jpype.JLong or int length: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param ghidra.app.util.importer.MessageLog log: a :obj:`MessageLog` for appending error messages
        :return: the newly created block or null if the operation failed
        :rtype: ghidra.program.model.mem.MemoryBlock
        :raises AddressOverflowException: if the address
        """

    @staticmethod
    @typing.overload
    def createInitializedBlock(program: ghidra.program.model.listing.Program, isOverlay: typing.Union[jpype.JBoolean, bool], name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, dataInput: java.io.InputStream, dataLength: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.mem.MemoryBlock:
        """
        Creates a new initialized block in memory using the bytes from the given input stream.
        If there is a conflict when creating this block (some other block occupies at least some
        of the addresses that would be occupied by the new block), then an attempt will be made
        to create the new block in an overlay.
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay space for that block
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param java.io.InputStream dataInput: the :obj:`InputStream` object that supplies the bytes for this block.
        :param jpype.JLong or int dataLength: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param ghidra.app.util.importer.MessageLog log: a :obj:`MessageLog` for appending error messages
        :param ghidra.util.task.TaskMonitor monitor: the monitor for canceling this potentially long running operation.
        :return: the newly created block or null if the operation failed
        :rtype: ghidra.program.model.mem.MemoryBlock
        :raises AddressOverflowException: if the address
        """

    @staticmethod
    def createUninitializedBlock(program: ghidra.program.model.listing.Program, isOverlay: typing.Union[jpype.JBoolean, bool], name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], r: typing.Union[jpype.JBoolean, bool], w: typing.Union[jpype.JBoolean, bool], x: typing.Union[jpype.JBoolean, bool], log: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.mem.MemoryBlock:
        """
        Creates a new uninitialized memory block.
        
        :param ghidra.program.model.listing.Program program: the program in which to create the block.
        :param jpype.JBoolean or bool isOverlay: if true, the block will be created in a new overlay space for that block
        :param java.lang.String or str name: the name of the new block.
        :param ghidra.program.model.address.Address start: the starting address of the new block.
        :param jpype.JLong or int length: the length of the new block
        :param java.lang.String or str comment: the comment text to associate with the new block.
        :param java.lang.String or str source: the source of the block (This field is not well defined - currently another comment)
        :param jpype.JBoolean or bool r: the read permission for the new block.
        :param jpype.JBoolean or bool w: the write permission for the new block.
        :param jpype.JBoolean or bool x: the execute permission for the new block.
        :param ghidra.app.util.importer.MessageLog log: a :obj:`MessageLog` for appending error messages
        :return: the newly created block or null if the operation failed.
        :rtype: ghidra.program.model.mem.MemoryBlock
        """


class ColorAndStyle(java.lang.Object):
    """
    A container class to hold a color and a style value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getColor(self) -> java.awt.Color:
        ...

    def getStyle(self) -> int:
        ...

    def isBold(self) -> bool:
        ...

    def isItalic(self) -> bool:
        ...

    def toHtml(self, text: typing.Union[java.lang.String, str]) -> str:
        """
        Wraps the given text with HTML markup for each attribute and color defined by this 
        class.  The returned result will **not** be prepended with ``<HTML>``.
        
        :param java.lang.String or str text: the text to wrap
        :return: the wrapped text
        :rtype: str
        """

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def style(self) -> jpype.JInt:
        ...

    @property
    def bold(self) -> jpype.JBoolean:
        ...

    @property
    def italic(self) -> jpype.JBoolean:
        ...


class XReferenceUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getAllXrefs(location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.program.model.symbol.Reference]:
        """
        Returns all xrefs to the given location.  If in data, then xrefs to the specific data
        component will be returned.  Otherwise, the code unit containing the address of the
        given location will be used as the source of the xrefs.
        
        :param ghidra.program.util.ProgramLocation location: the location for which to get xrefs
        :return: the xrefs
        :rtype: java.util.Set[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    def getOffcutXReferences(cu: ghidra.program.model.listing.CodeUnit, max: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing all offcut xref references to the specified code unit
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the offcut xrefs
        :param jpype.JInt or int max: max number of offcut xrefs to get, or -1 to get all offcut references
        :return: array of all offcut xrefs to the code unit
        :rtype: java.util.List[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    @typing.overload
    def getVariableRefs(var: ghidra.program.model.listing.Variable, xrefs: java.util.List[ghidra.program.model.symbol.Reference], offcuts: java.util.List[ghidra.program.model.symbol.Reference]):
        """
        Populates the provided lists with the direct and offcut xrefs to the specified variable
        
        :param ghidra.program.model.listing.Variable var: variable to get references
        :param java.util.List[ghidra.program.model.symbol.Reference] xrefs: list to put direct references in
        :param java.util.List[ghidra.program.model.symbol.Reference] offcuts: list to put offcut references in
        """

    @staticmethod
    @typing.overload
    def getVariableRefs(var: ghidra.program.model.listing.Variable, xrefs: java.util.List[ghidra.program.model.symbol.Reference], offcuts: java.util.List[ghidra.program.model.symbol.Reference], max: typing.Union[jpype.JInt, int]):
        """
        Populates the provided lists with the direct and offcut xrefs to the specified variable
        
        :param ghidra.program.model.listing.Variable var: variable to get references
        :param java.util.List[ghidra.program.model.symbol.Reference] xrefs: list to put direct references in
        :param java.util.List[ghidra.program.model.symbol.Reference] offcuts: list to put offcut references in
        :param jpype.JInt or int max: max number of xrefs to get, or -1 to get all references
        """

    @staticmethod
    def getXReferences(cu: ghidra.program.model.listing.CodeUnit, max: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing the first **``max``**
        direct xref references to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the xrefs
        :param jpype.JInt or int max: max number of xrefs to get, or -1 to get all references
        :return: array first **``max``** xrefs to the code unit
        :rtype: java.util.List[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    def showXrefs(navigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider, service: ghidra.app.util.query.TableService, location: ghidra.program.util.ProgramLocation, xrefs: collections.abc.Sequence):
        """
        Shows all xrefs to the given location in a new table.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable used for navigation from the table
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the service provider needed to wire navigation
        :param ghidra.app.util.query.TableService service: the service needed to show the table
        :param ghidra.program.util.ProgramLocation location: the location for which to find references
        :param collections.abc.Sequence xrefs: the xrefs to show
        """


class RefRepeatComment(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCommentLineCount(self) -> int:
        ...

    def getCommentLines(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def commentLineCount(self) -> jpype.JInt:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def commentLines(self) -> jpype.JArray[java.lang.String]:
        ...


class ByteCopier(java.lang.Object):
    """
    Base class that can copy bytes into a Transferable object, and paste bytes into a program.
    """

    @typing.type_check_only
    class PasteByteStringCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ByteIterator(java.util.Iterator[java.lang.Byte]):
        """
        An iterator of bytes from memory. This class exists because the :obj:`MemoryByteIterator`
        throws an exception from its next() method, which will not work for us.
        """

        class_: typing.ClassVar[java.lang.Class]


    class ProgrammingByteStringTransferable(java.awt.datatransfer.Transferable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, byteString: typing.Union[java.lang.String, str], flavor: java.awt.datatransfer.DataFlavor):
            ...


    class ByteStringTransferable(java.awt.datatransfer.Transferable):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, byteString: typing.Union[java.lang.String, str]):
            ...

        @typing.overload
        def __init__(self, byteString: typing.Union[java.lang.String, str], stringRepresentation: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BYTE_STRING_FLAVOR: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    BYTE_STRING_NO_SPACES_FLAVOR: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    PYTHON_BYTE_STRING_FLAVOR: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    PYTHON_LIST_FLAVOR: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    CPP_BYTE_ARRAY_FLAVOR: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    BYTE_STRING_TYPE: typing.Final[ClipboardType]
    BYTE_STRING_NO_SPACE_TYPE: typing.Final[ClipboardType]
    PYTHON_BYTE_STRING_TYPE: typing.Final[ClipboardType]
    PYTHON_LIST_TYPE: typing.Final[ClipboardType]
    CPP_BYTE_ARRAY_TYPE: typing.Final[ClipboardType]

    @staticmethod
    def createStringTransferable(text: typing.Union[java.lang.String, str]) -> java.awt.datatransfer.Transferable:
        """
        Create a Transferable from the given text.
        
        :param java.lang.String or str text: text used to create a Transferable
        :return: a Transferable
        :rtype: java.awt.datatransfer.Transferable
        """


class ToolTipUtils(java.lang.Object):
    """
    A utility class that creates tool tip text for given data types.
    
    
    .. versionadded:: Tracker Id 616
    """

    class_: typing.ClassVar[java.lang.Class]
    LINE_LENGTH: typing.Final = 80

    @staticmethod
    def getFullToolTipText(dataType: ghidra.program.model.data.DataType) -> str:
        """
        Examines the give ``dataType`` and creates a tool tip for it,
        depending upon its actual class type.
         
         
        Note: the text returned here will not be truncated.  This can result in tool tip windows
        that are too large to fit in the screen.  For truncated tool tip text, use
        :meth:`getToolTipText(DataType) <.getToolTipText>`.
        
        :param ghidra.program.model.data.DataType dataType: The data type from which a tool tip will be
                created.
        :return: tool tip text for the given data type.
        :rtype: str
        """

    @staticmethod
    def getHTMLRepresentation(dataType: ghidra.program.model.data.DataType) -> ghidra.app.util.html.HTMLDataTypeRepresentation:
        """
        Return dataType details as HTML.
        
        :param ghidra.program.model.data.DataType dataType: the dataType to be represented
        :return: dataType details formatted as HTML
        :rtype: ghidra.app.util.html.HTMLDataTypeRepresentation
        """

    @staticmethod
    @typing.overload
    def getToolTipText(dataType: ghidra.program.model.data.DataType) -> str:
        """
        Examines the give ``dataType`` and creates a tool tip for it,
        depending upon its actual class type.
         
         
        Note: the text returned here will be truncated as needed for the type of data.  To
        get the full tool tip text, use :meth:`getFullToolTipText(DataType) <.getFullToolTipText>`.
        
        :param ghidra.program.model.data.DataType dataType: The data type from which a tool tip will be
                created.
        :return: tool tip text for the given data type.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getToolTipText(extLoc: ghidra.program.model.symbol.ExternalLocation, includeSymbolDetails: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Return an HTML formatted rendering of an external location/function.
        
        :param ghidra.program.model.symbol.ExternalLocation extLoc: the location
        :param jpype.JBoolean or bool includeSymbolDetails: true to include details of the symbol
        :return: tool tip text for the given external location/function
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getToolTipText(function: ghidra.program.model.listing.Function, includeSymbolDetails: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Return an HTML formatted rendering of a function
        
        :param ghidra.program.model.listing.Function function: the function
        :param jpype.JBoolean or bool includeSymbolDetails: true to include details of the symbol
        :return: tool tip text for the given function
        :rtype: str
        """


class SymbolInspector(ghidra.framework.options.OptionsChangeListener):
    """
    Class for coloring symbols.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, repaintComp: java.awt.Component):
        """
        Constructs a new symbol inspector
        It uses the tool to get the CATEGORY_BROWSER_DISPLAY options
        
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: a service provider for getting services
        :param java.awt.Component repaintComp: the component to repaint when the options change
        """

    @typing.overload
    def __init__(self, options: ghidra.framework.options.ToolOptions, repaintComp: java.awt.Component):
        """
        Constructs a new symbol inspector
        
        :param ghidra.framework.options.ToolOptions options: the options from which to get colors
        :param java.awt.Component repaintComp: the component to repaint when the options change
        """

    def dispose(self):
        """
        Call this when you are done with this inspector and will not use it again.
        Cleans up listeners, etc.
        """

    def getColor(self, s: ghidra.program.model.symbol.Symbol) -> java.awt.Color:
        """
        Get the color used to render the given symbol.
        
        :param ghidra.program.model.symbol.Symbol s: symbol to inspect
        :return: Color for the symbol
        :rtype: java.awt.Color
        """

    @typing.overload
    def getColorAndStyle(self, s: ghidra.program.model.symbol.Symbol) -> ColorAndStyle:
        """
        Gets the color and style used to render the given symbol.  Calling this method is
        faster than calling :meth:`getColor(Symbol) <.getColor>` and :meth:`getStyle(Symbol) <.getStyle>`
        separately.
        
        :param ghidra.program.model.symbol.Symbol s: the symbol
        :return: the color and style
        :rtype: ColorAndStyle
        """

    @typing.overload
    def getColorAndStyle(self, p: ghidra.program.model.listing.Program, r: ghidra.program.model.symbol.Reference) -> ColorAndStyle:
        """
        Gets the color and style used to render the given reference.  Calling this method is
        faster than calling :meth:`getColor(Symbol) <.getColor>` and :meth:`getStyle(Symbol) <.getStyle>`
        separately.
        
        :param ghidra.program.model.listing.Program p: the program
        :param ghidra.program.model.symbol.Reference r: the reference
        :return: the color and style
        :rtype: ColorAndStyle
        """

    def getOffcutSymbolColor(self) -> java.awt.Color:
        ...

    def getOffcutSymbolStyle(self) -> int:
        ...

    @deprecated("returns null")
    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        :return: null
        :rtype: ghidra.program.model.listing.Program
        
        
        
        .. deprecated::
        
        returns null
        """

    @typing.overload
    def getScreenElement(self, s: ghidra.program.model.symbol.Symbol) -> ghidra.app.util.viewer.options.ScreenElement:
        """
        Get the ScreenElement corresponding to the type of the symbol
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to inspect
        :return: the screen element
        :rtype: ghidra.app.util.viewer.options.ScreenElement
        """

    @typing.overload
    def getScreenElement(self, p: ghidra.program.model.listing.Program, r: ghidra.program.model.symbol.Reference) -> ghidra.app.util.viewer.options.ScreenElement:
        """
        Get the ScreenElement corresponding to the type of the reference.
        
        :param ghidra.program.model.listing.Program p: the program
        :param ghidra.program.model.symbol.Reference r: the reference to inspect
        :return: the screen element
        :rtype: ghidra.app.util.viewer.options.ScreenElement
        """

    def getStyle(self, s: ghidra.program.model.symbol.Symbol) -> int:
        """
        Get the style used to render the given symbol
        
        :param ghidra.program.model.symbol.Symbol s: symbol to inspect
        :return: the style for the symbol
        :rtype: int
        """

    def isBadReferenceSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Returns true if symbol is at a non-existent address
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if symbol is bad
        :rtype: bool
        """

    def isDataSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Returns true if the symbol is on a data item.
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if s is a data symbol
        :rtype: bool
        """

    def isDeadCodeSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Returns true if the symbol is on "dead" code
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is on dead code
        :rtype: bool
        """

    def isEntryPointSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the given symbol is at an external entry point
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is at an external entry point address.
        :rtype: bool
        """

    def isExternalSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        ...

    def isFunctionSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is at a function
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check.
        :return: boolean true if there is a function at the symbol's address.
        :rtype: bool
        """

    def isGlobalSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is global or local
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is global, false if the symbol is
        local.
        :rtype: bool
        """

    def isInstructionSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is at or inside an instruction
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is on an instruction
        :rtype: bool
        """

    def isLocalSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is local
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is local, false if it is global
        :rtype: bool
        """

    def isNonPrimarySymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is not a primary symbol
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check.
        :return: boolean true if the symbol is non-primary
        :rtype: bool
        """

    def isOffcutSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is offcut
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is offcut
        :rtype: bool
        """

    def isPrimarySymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        returns true if the symbol is primary
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is primary
        :rtype: bool
        """

    def isSubroutineSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is at the beginning of a subroutine.
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: boolean true if the symbol is at the beginning of a subroutine.
        :rtype: bool
        """

    def isVariableSymbol(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Checks if the symbol is a function variable
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: true if s is a function variable symbol
        :rtype: bool
        """

    @deprecated("this method does nothing")
    def setProgram(self, p: ghidra.program.model.listing.Program):
        """
        Does nothing
        
        :param ghidra.program.model.listing.Program p: the program
        
        .. deprecated::
        
        this method does nothing
        """

    @property
    def entryPointSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def dataSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def globalSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @program.setter
    def program(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def nonPrimarySymbol(self) -> jpype.JBoolean:
        ...

    @property
    def screenElement(self) -> ghidra.app.util.viewer.options.ScreenElement:
        ...

    @property
    def instructionSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def deadCodeSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def offcutSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def externalSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def subroutineSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def variableSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def offcutSymbolColor(self) -> java.awt.Color:
        ...

    @property
    def offcutSymbolStyle(self) -> jpype.JInt:
        ...

    @property
    def localSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def colorAndStyle(self) -> ColorAndStyle:
        ...

    @property
    def badReferenceSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def style(self) -> jpype.JInt:
        ...

    @property
    def functionSymbol(self) -> jpype.JBoolean:
        ...

    @property
    def primarySymbol(self) -> jpype.JBoolean:
        ...


class CodeUnitInfo(java.lang.Object):
    """
    Container object to keep a relative index, label, and comments. Used
    in a list for copying/pasting labels and comments from one program to
    another.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, index: typing.Union[jpype.JInt, int]):
        """
        Constructor a new CodeUnitInfo.
        
        :param jpype.JInt or int index: relative index added to a base address
        for where this information will be placed
        """

    def getEOLComment(self) -> jpype.JArray[java.lang.String]:
        """
        Get the EOL comment.
        """

    def getFunctionComments(self) -> jpype.JArray[java.lang.String]:
        """
        Get the function comments.
        """

    def getFunctionName(self) -> str:
        """
        Get the function name.
        """

    def getFunctionScopeSymbolNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of the function scope symbols.
        """

    def getFunctionScopeSymbolSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        """
        Get the sources of the function scope symbols.
        """

    def getIndex(self) -> int:
        """
        Get the relative index for this CodeUnitInfo to add to a base address.
        """

    def getOtherSymbolNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of the other symbols not in a function scope.
        """

    def getOtherSymbolSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        """
        Get the sources of the other symbols not in a function scope.
        """

    def getPlateComment(self) -> jpype.JArray[java.lang.String]:
        """
        Get the plate comment.
        """

    def getPostComment(self) -> jpype.JArray[java.lang.String]:
        """
        Get the post comment.
        """

    def getPreComment(self) -> jpype.JArray[java.lang.String]:
        """
        Get the pre comment.
        """

    def getPrimarySymbolName(self) -> str:
        """
        Get the label; may be null.
        """

    def getPrimarySymbolSource(self) -> ghidra.program.model.symbol.SourceType:
        """
        Get the label source
        """

    def getRepeatableComment(self) -> jpype.JArray[java.lang.String]:
        """
        Get the repeatable comment.
        """

    def getStackOffsets(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the stack offsets.
        """

    def getStackVarFirstUseOffsets(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the stack variable "First Use Offsets"
        """

    def getStackVariableComments(self) -> jpype.JArray[java.lang.String]:
        """
        Get the stack variable comments.
        """

    def getStackVariableNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the stack variable names.
        """

    def getStackVariableSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        """
        Get the stack variable sources.
        """

    def getVarAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get the storage addresses corresponding to each non-stack variable.
        """

    def getVarFirstUseOffsets(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the non-stack variable "First Use Offsets"
        """

    def getVariableComments(self) -> jpype.JArray[java.lang.String]:
        """
        Get the non-stack variable comments.
        """

    def getVariableNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the non-stack variable names.
        """

    def getVariableSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        """
        Get the non-stack variable sources.
        """

    def hasDynamicSymbol(self) -> bool:
        """
        Return whether this CodeUnitInfo has a dynamic symbol.
        """

    def hasSymbols(self) -> bool:
        """
        Return whether this CodeUnitInfo has symbols to copy.
        """

    def isPrimarySymbolInFunctionScope(self) -> bool:
        """
        Is primary symbol in a function scope
        """

    def setComment(self, commentType: ghidra.program.model.listing.CommentType, comment: jpype.JArray[java.lang.String]):
        """
        Set the comment to be transferred.
        
        :param ghidra.program.model.listing.CommentType commentType: comment type
        :param jpype.JArray[java.lang.String] comment: comment
        """

    def setFunction(self, function: ghidra.program.model.listing.Function):
        """
        Set the function info.
        
        :param ghidra.program.model.listing.Function function: function used to get function info to transfer
        """

    def setSymbols(self, symbols: jpype.JArray[ghidra.program.model.symbol.Symbol]):
        """
        Set the symbols to be transferred.
        """

    @property
    def functionScopeSymbolSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        ...

    @property
    def repeatableComment(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def primarySymbolSource(self) -> ghidra.program.model.symbol.SourceType:
        ...

    @property
    def stackVariableComments(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def variableSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        ...

    @property
    def stackVariableSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        ...

    @property
    def varFirstUseOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def stackVarFirstUseOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def postComment(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def plateComment(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def stackOffsets(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def primarySymbolName(self) -> java.lang.String:
        ...

    @property
    def primarySymbolInFunctionScope(self) -> jpype.JBoolean:
        ...

    @property
    def functionName(self) -> java.lang.String:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def varAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def variableNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def preComment(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def otherSymbolSources(self) -> jpype.JArray[ghidra.program.model.symbol.SourceType]:
        ...

    @property
    def functionComments(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def eOLComment(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def functionScopeSymbolNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def stackVariableNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def variableComments(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def otherSymbolNames(self) -> jpype.JArray[java.lang.String]:
        ...


class GhidraFileOpenDataFlavorHandlerService(java.lang.Object):
    """
    A class used to initialize the handling of files that are dropped onto the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class ImporterDocumentListener(javax.swing.event.DocumentListener):
    ...
    class_: typing.ClassVar[java.lang.Class]


class Permissions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[Permissions]
    READ_ONLY: typing.Final[Permissions]
    READ_EXECUTE: typing.Final[Permissions]
    read: typing.Final[jpype.JBoolean]
    write: typing.Final[jpype.JBoolean]
    execute: typing.Final[jpype.JBoolean]

    def __init__(self, read: typing.Union[jpype.JBoolean, bool], write: typing.Union[jpype.JBoolean, bool], execute: typing.Union[jpype.JBoolean, bool]):
        ...


class FunctionXrefsTableModel(ghidra.util.table.ReferencesFromTableModel):

    @typing.type_check_only
    class ThunkIncomingReferenceEndpoint(ghidra.util.table.field.IncomingReferenceEndpoint):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, r: ghidra.program.model.symbol.Reference, isOffcut: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class IsThunkTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.util.table.field.ReferenceEndpoint, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, directRefs: collections.abc.Sequence, sp: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program):
        ...


class ProcessorInfo(java.lang.Object):
    """
    Miscellanious address space defines for language providers.
    Provides recommended default address space names and IDs.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_SPACE: typing.Final = "MEM"
    """
    The default address space in a program.
    """

    CODE_SPACE: typing.Final = "CODE"
    """
    The code space in a program.
    """

    INTMEM_SPACE: typing.Final = "INTMEM"
    """
    The internal memory space in a program.
    """

    BIT_SPACE: typing.Final = "BITS"
    """
    The bit space in a program.
    """

    EXTMEM_SPACE: typing.Final = "EXTMEM"
    """
    The external memory space in a program.
    """

    SFR_SPACE: typing.Final = "SFR"
    """
    The Special function registers space in a program
    """

    CODE_SPACE_ID: typing.Final = 0
    """
    ID for the CODE_SPACE.
    """

    INTMEM_SPACE_ID: typing.Final = 3
    """
    ID for the INTMEM_SPACE.
    """

    SFR_SPACE_ID: typing.Final = 4
    """
    ID for the SFR_SPACE.
    """

    EXTMEM_SPACE_ID: typing.Final = 8
    """
    ID for the EXTMEM_SPACE.
    """



class OptionsEditorPanel(javax.swing.JPanel):
    """
    Editor Panel for displaying and editing options associated with importing or exporting. It takes
    in a list of Options and generates editors for each of them on th fly.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, options: java.util.List[Option], addressFactoryService: AddressFactoryService):
        """
        Construct a new OptionsEditorPanel
        
        :param java.util.List[Option] options: the list of options to be edited.
        :param AddressFactoryService addressFactoryService: a service for providing an appropriate AddressFactory if needed
        for editing an options.  If null, address based options will not be available.
        """


class HelpTopics(java.lang.Object):
    """
    Topics for Help. The strings correspond to a folder under the "topics"
    resource.
    """

    class_: typing.ClassVar[java.lang.Class]
    ABOUT: typing.Final = "About"
    """
    Help Topic for "About."
    """

    AUTO_ANALYSIS: typing.Final = "AutoAnalysisPlugin"
    """
    Help Topic for auto analysis.
    """

    BLOCK_MODEL: typing.Final = "BlockModel"
    """
    Help Topic for block models.
    """

    BOOKMARKS: typing.Final = "BookmarkPlugin"
    """
    Help Topic for bookmarks.
    """

    BYTE_VIEWER: typing.Final = "ByteViewerPlugin"
    """
    Help Topic for the byte viewer.
    """

    CODE_BROWSER: typing.Final = "CodeBrowserPlugin"
    """
    Help Topic for the code browser.
    """

    CONSOLE: typing.Final = "ConsolePlugin"
    """
    Help Topic for the Console Plugin.
    """

    COMMENTS: typing.Final = "CommentsPlugin"
    """
    Help Topic for comments.
    """

    DATA: typing.Final = "DataPlugin"
    """
    Help Topic for data.
    """

    DATA_MANAGER: typing.Final = "DataTypeManagerPlugin"
    """
    Help Topic for the data manager.
    """

    DATA_TYPE_EDITORS: typing.Final = "DataTypeEditors"
    """
    Help Topic for the data type editors.
    """

    DECOMPILER: typing.Final = "DecompilePlugin"
    """
    Help Topic for the decompiler
    """

    DIFF: typing.Final = "Diff"
    """
    Help Topic for doing diffs between programs.
    """

    EQUATES: typing.Final = "EquatePlugin"
    """
    Help Topic for equates.
    """

    EXPORTER: typing.Final = "ExporterPlugin"
    """
    Help Topic for the exporters.
    """

    FIND_REFERENCES: typing.Final = "LocationReferencesPlugin"
    """
    Help Topic for references searching
    """

    FRONT_END: typing.Final = "FrontEndPlugin"
    """
    Name of options for the help topic for the front end (Ghidra
    Project Window).
    """

    GLOSSARY: typing.Final = "Glossary"
    """
    Help Topic for the glossary.
    """

    HIGHLIGHT: typing.Final = "SetHighlightPlugin"
    """
    Help Topic for highlighting.
    """

    IMPORTER: typing.Final = "ImporterPlugin"
    """
    Help Topic for the importers.
    """

    INTRO: typing.Final = "Intro"
    """
    Help for Intro topics.
    """

    LABEL: typing.Final = "LabelMgrPlugin"
    """
    Help Topic for the add/edit label.
    """

    NAVIGATION: typing.Final = "Navigation"
    """
    Help Topic for navigation.
    """

    MEMORY_MAP: typing.Final = "MemoryMapPlugin"
    """
    Help Topic for the memory map.
    """

    PE2XML: typing.Final = "PE2XMLPlugin"
    """
    Help Topic for the P2 to XML exporter.
    """

    PROGRAM: typing.Final = "ProgramManagerPlugin"
    """
    Help Topic for programs (open, close, save, etc.).
    """

    PROGRAM_TREE: typing.Final = "ProgramTreePlugin"
    """
    Help Topic for the program tree.
    """

    REFERENCES: typing.Final = "ReferencesPlugin"
    """
    Help Topic for references.
    """

    RELOCATION_TABLE: typing.Final = "RelocationTablePlugin"
    """
    Help Topic for the relocation table.
    """

    REPOSITORY: typing.Final = "Repository"
    """
    Help Topic for the project repository.
    """

    RUNTIME_INFO: typing.Final = "RuntimeInfoPlugin"
    """
    Help Topic for the Runtime Info Plugin.
    """

    SEARCH: typing.Final = "Search"
    """
    Help Topic for search functions.
    """

    SELECTION: typing.Final = "Selection"
    """
    Help Topic for selection.
    """

    SYMBOL_TABLE: typing.Final = "SymbolTablePlugin"
    """
    Help Topic for the symbol table.
    """

    SYMBOL_TREE: typing.Final = "SymbolTreePlugin"
    """
    Help Topic for the symbol tree.
    """

    TOOL: typing.Final = "Tool"
    """
    Help Topic for tools.
    """



class DataTypeNamingUtil(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def generateMangledSignature(functionDefinition: ghidra.program.model.data.FunctionDefinitionDataType) -> str:
        """
        Generate a simple mangled function signature.  Generated string will start with
        ``_func``.
        
        :param ghidra.program.model.data.FunctionDefinitionDataType functionDefinition: function definition is used for generating the name
        :return: generated name
        :rtype: str
        """

    @staticmethod
    def setMangledAnonymousFunctionName(functionDefinition: ghidra.program.model.data.FunctionDefinitionDataType) -> str:
        """
        Generate a simple mangled function definition name and apply it to the specified
        functionDefinition.  Generated name will start with ``_func``.
        
        :param ghidra.program.model.data.FunctionDefinitionDataType functionDefinition: function definition whose name should be set
        :return: name applied to functionDefinition
        :rtype: str
        """


@deprecated("deprecated for 10.1; removal for 10.3 or later")
class XReferenceUtil(java.lang.Object):
    """
    A utility class to handle the generation of direct and offcut cross-reference (xref) lists
    on code units and stack variables.
    
    
    .. deprecated::
    
    deprecated for 10.1; removal for 10.3 or later
    """

    class_: typing.ClassVar[java.lang.Class]
    ALL_REFS: typing.Final = -1

    def __init__(self):
        ...

    @staticmethod
    def getAllXrefs(location: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.program.model.symbol.Reference]:
        """
        Returns all xrefs to the given location.  If in data, then xrefs to the specific data
        component will be returned.  Otherwise, the code unit containing the address of the
        given location will be used as the source of the xrefs.
        
        :param ghidra.program.util.ProgramLocation location: the location for which to get xrefs
        :return: the xrefs
        :rtype: java.util.Set[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    def getOffcutXRefCount(cu: ghidra.program.model.listing.CodeUnit) -> int:
        """
        Returns the count of all offcut xref addresses to the specified code unit
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the offcut xrefs
        :return: count of all offcut xrefs to the code unit
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getOffcutXRefList(cu: ghidra.program.model.listing.CodeUnit) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns an array containing all
        offcut xref addresses to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the offcut xrefs
        :return: array of all offcut xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @staticmethod
    @typing.overload
    def getOffcutXRefList(cu: ghidra.program.model.listing.CodeUnit, maxXRefs: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns an array containing all
        offcut xref addresses to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the offcut xrefs
        :param jpype.JInt or int maxXRefs: max number of offcut xrefs to get,
                        or -1 to get all offcut references
        :return: array of all offcut xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @staticmethod
    def getOffcutXReferences(cu: ghidra.program.model.listing.CodeUnit, maxXRefs: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing all offcut xref references to the specified code unit
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the offcut xrefs
        :param jpype.JInt or int maxXRefs: max number of offcut xrefs to get, or -1 to get all offcut references
        :return: array of all offcut xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    @typing.overload
    def getVariableRefs(var: ghidra.program.model.listing.Variable, xrefs: java.util.List[ghidra.program.model.symbol.Reference], offcuts: java.util.List[ghidra.program.model.symbol.Reference]):
        """
        Populates the provided lists with the direct and offcut xrefs to the specified variable
        
        :param ghidra.program.model.listing.Variable var: variable to get references
        :param java.util.List[ghidra.program.model.symbol.Reference] xrefs: list to put direct references in
        :param java.util.List[ghidra.program.model.symbol.Reference] offcuts: list to put offcut references in
        """

    @staticmethod
    @typing.overload
    def getVariableRefs(var: ghidra.program.model.listing.Variable) -> java.util.Set[ghidra.program.model.symbol.Reference]:
        """
        Returns the direct and offcut xrefs to the specified variable
        
        :param ghidra.program.model.listing.Variable var: variable to get references
        :return: the set of references
        :rtype: java.util.Set[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    @typing.overload
    def getXRefList(cu: ghidra.program.model.listing.CodeUnit) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns an array containing all
        direct xref addresses to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the xrefs
        :return: array of all xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @staticmethod
    @typing.overload
    def getXRefList(cu: ghidra.program.model.listing.CodeUnit, maxNumber: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns an array containing the first **``maxNumber``**
        direct xref addresses to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the xrefs
        :param jpype.JInt or int maxNumber: max number of xrefs to get,
                        or -1 to get all references
        :return: array first **``maxNumber``** xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @staticmethod
    def getXReferences(cu: ghidra.program.model.listing.CodeUnit, maxNumber: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing the first **``maxNumber``**
        direct xref references to the specified code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to generate the xrefs
        :param jpype.JInt or int maxNumber: max number of xrefs to get,
                        or -1 to get all references
        :return: array first **``maxNumber``** xrefs to the code unit
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    @staticmethod
    def showAllXrefs(navigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider, service: ghidra.app.util.query.TableService, location: ghidra.program.util.ProgramLocation, xrefs: java.util.Set[ghidra.program.model.symbol.Reference]):
        """
        Shows all xrefs to the given location in a new table.  These xrefs are retrieved
        from the given supplier.  Thus, it is up to the client to determine which xrefs to show.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable used for navigation from the table
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: the service provider needed to wire navigation
        :param ghidra.app.util.query.TableService service: the service needed to show the table
        :param ghidra.program.util.ProgramLocation location: the location for which to find references
        :param java.util.Set[ghidra.program.model.symbol.Reference] xrefs: the xrefs to show
        """


class OptionsDialog(docking.DialogComponentProvider, OptionListener):
    """
    Dialog for editing the import options for a selected importer format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, originalOptions: java.util.List[Option], validator: OptionValidator, addressFactoryService: AddressFactoryService):
        """
        Constructs a new OptionsDialog for editing the options associated with a specific import format
        such as PE, ELF, XML, etc.
        
        :param java.util.List[Option] originalOptions: the list of options generated from the specific import format selected.
        :param OptionValidator validator: a callback for validating the options as they are set.
        :param AddressFactoryService addressFactoryService: a service for retrieving the AddressFactory if needed. This is
        passed instead of an actual AddressFactory, because to get an AddressFactory, it might
        require that a language be loaded or a program be opened and not all options require an
        AddressFactory.  If null, address based options will not be available.
        """

    def getOptions(self) -> java.util.List[Option]:
        """
        Returns the list of Options with the values as they were set in this dialog.
        
        :return: the list of Options with the values as they were set in this dialog.
        :rtype: java.util.List[Option]
        """

    def wasCancelled(self) -> bool:
        ...

    @property
    def options(self) -> java.util.List[Option]:
        ...


class AddressSetEditorPanel(javax.swing.JPanel):

    @typing.type_check_only
    class AddressSetListModel(javax.swing.AbstractListModel[ghidra.program.model.address.AddressRange]):

        class_: typing.ClassVar[java.lang.Class]

        def setData(self, list: java.util.List[ghidra.program.model.address.AddressRange]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addressFactory: ghidra.program.model.address.AddressFactory, addressSet: ghidra.program.model.address.AddressSetView):
        ...

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        ...

    def getAddressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        ...

    @property
    def addressSetView(self) -> ghidra.program.model.address.AddressSetView:
        ...


class OptionListener(java.lang.Object):
    """
    Notification that an Option changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def optionChanged(self, option: Option):
        """
        Notification that the given option changed.
        
        :param Option option: option that changed
        """


class SelectionTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is an AddressSetView.
    """

    class_: typing.ClassVar[java.lang.Class]
    localProgramSelectionFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]
    """
    DataFlavor for program selection.
    """


    def __init__(self, selectionData: SelectionTransferData):
        """
        Construct a new SelectionTransferable.
        
        :param SelectionTransferData selectionData: the data indicating the selection for the selection transferable
        """

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specified data flavor is supported.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


@deprecated("the enum should be used in place of integers")
class CommentTypes(java.lang.Object):
    """
    Class with a convenience method to get an array of the CodeUnit
    comment types. The method is useful to loop through the comment types
    once you have a code unit.
    
    
    .. deprecated::
    
    the :obj:`enum should be used in place of integers <CommentType>`
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getTypes() -> jpype.JArray[jpype.JInt]:
        """
        :return: an array containing the comment types on a code unit
        :rtype: jpype.JArray[jpype.JInt]
        """


class AddEditDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog used to a label or to edit an existing label.
    """

    class NamespaceWrapper(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, namespace: ghidra.program.model.symbol.Namespace):
            ...

        def getNamespace(self) -> ghidra.program.model.symbol.Namespace:
            ...

        @property
        def namespace(self) -> ghidra.program.model.symbol.Namespace:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def addLabel(self, address: ghidra.program.model.address.Address, prog: ghidra.program.model.listing.Program):
        """
        Invokes the dialog to add a new label in the given program at the given address
        
        :param ghidra.program.model.address.Address address: the address at which to add a new label
        :param ghidra.program.model.listing.Program prog: the program in which to add a new label
        """

    @typing.overload
    def addLabel(self, address: ghidra.program.model.address.Address, targetProgram: ghidra.program.model.listing.Program, provider: docking.ComponentProvider):
        """
        Invokes the dialog to add a new label in the given program at the given address
        
        :param ghidra.program.model.address.Address address: the address at which to add a new label
        :param ghidra.program.model.listing.Program targetProgram: the program in which to add a new label
        :param docking.ComponentProvider provider: the ComponentProvider to parent and center the dialog over.
        """

    @typing.overload
    def addLabel(self, address: ghidra.program.model.address.Address, targetProgram: ghidra.program.model.listing.Program, centeredOverComponent: java.awt.Component):
        """
        Invokes the dialog to add a new label in the given program at the given address
        
        :param ghidra.program.model.address.Address address: the address at which to add a new label
        :param ghidra.program.model.listing.Program targetProgram: the program in which to add a new label
        :param java.awt.Component centeredOverComponent: the component over which to center the dialog
        """

    @typing.overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program):
        """
        Invokes the dialog to edit an existing label in the given program
        
        :param ghidra.program.model.symbol.Symbol targetSymbol: the symbol(label) to edit
        :param ghidra.program.model.listing.Program targetProgram: the program containing the symbol
        """

    @typing.overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program, centeredOverComponent: java.awt.Component):
        """
        Invokes the dialog to edit an existing label in the given program
        
        :param ghidra.program.model.symbol.Symbol targetSymbol: the symbol(label) to edit
        :param ghidra.program.model.listing.Program targetProgram: the program containing the symbol
        :param java.awt.Component centeredOverComponent: the component over which to center the dialog
        """

    @typing.overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program, provider: docking.ComponentProvider):
        """
        Invokes the dialog to edit an existing label in the given program
        
        :param ghidra.program.model.symbol.Symbol targetSymbol: the symbol(label) to edit
        :param ghidra.program.model.listing.Program targetProgram: the program containing the symbol
        :param docking.ComponentProvider provider: the ComponentProvider to parent and center the dialog over.
        """

    def setReusable(self, isReusable: typing.Union[jpype.JBoolean, bool]):
        """
        Signals that the client wishes to reuse the dialog instead of creating a new instance each
        time the dialog is shown.  
         
        
        When not reusable, closing this dialog will call :meth:`dispose() <.dispose>`.
        
        :param jpype.JBoolean or bool isReusable: true when being reused
        """


class OptionException(java.lang.Exception):
    """
    Exception thrown if there was a problem accessing an Option, or if
    an informational message is to be conveyed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Construct a new OptionException.
        
        :param java.lang.String or str msg: reason for the exception
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], isInfo: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new OptionException that may be an informational message
        if isValid is true.
        
        :param java.lang.String or str msg: message to display
        :param jpype.JBoolean or bool isInfo: true if the msg is in informational message
        """

    def isInfoMessage(self) -> bool:
        """
        Return whether the message associated with this exception is
        informational.
        """

    @property
    def infoMessage(self) -> jpype.JBoolean:
        ...


class OptionUtils(java.lang.Object):
    """
    Utility class for providing convenience methods for working with :obj:`Option`'s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def containsOption(optionName: typing.Union[java.lang.String, str], options: java.util.List[Option]) -> bool:
        """
        Checks to see whether or not the given list of options contains the given option name.
        
        :param java.lang.String or str optionName: The name of the option to check.
        :param java.util.List[Option] options: A list of the all the options.
        :return: True if the given list contains the given option; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def getBooleanOptionValue(optionName: typing.Union[java.lang.String, str], options: java.util.List[Option], defaultValue: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Gets the boolean value of the option with the given name from the given list of options.
        
        :param java.lang.String or str optionName: The name of the boolean option to get.
        :param java.util.List[Option] options: The list of options to get the option from.
        :param jpype.JBoolean or bool defaultValue: A default option value to use if the option name was not found.
        :return: The boolean value of the option with the given name, or the default value if it was 
        not found as a boolean option.
        :rtype: bool
        """

    @staticmethod
    def getOption(optionName: typing.Union[java.lang.String, str], options: java.util.List[Option], defaultValue: T) -> T:
        """
        Gets the value of the option with the given name from the given list of options.
        
        :param java.lang.String or str optionName: The name of the option to get.
        :param java.util.List[Option] options: The list of options to get the option from.
        :param T defaultValue: A default option value to use if the option name was not found.
        :return: The value of the option with the given name, or the default value if it was not 
        found.
        :rtype: T
        """


class AddressFactoryService(java.lang.Object):
    """
    Simple interface for getting an address factory. This is used to delay the opening of
    a program until it is needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...


class OptionValidator(java.lang.Object):
    """
    Callback interface for validating a list of options with values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def validateOptions(self, options: java.util.List[Option]) -> str:
        """
        Validates the options if valid, returns null. Otherwise an error message is returned.
        
        :param java.util.List[Option] options: the options to be validated.
        :return: null, if the options have valid values.  Otherwise return an error message.
        :rtype: str
        """


class NamespaceUtils(java.lang.Object):
    """
    A class to hold utility methods for working with namespaces.
     
    
     
    .. _examples:
    
    
    Example string format:
     
    * global:obj:`:: <Namespace.DELIMITER>`child1:obj:`:: <Namespace.DELIMITER>`child2
    * child1
    
     
    .. _assumptions:
    
    
    **Assumptions for creating namespaces from a path string: **
     
    * All elements of a namespace path should be namespace symbols and not other
    symbol types.
    * Absolute paths can optionally start with the global namespace.
    * You can provide a relative path that will start at the given
    parent namespace (or global if there is no parent provided).
    * You can provide a path that has as its first entry the name of the
    given parent.  In this case, the first entry will not be created,
    but rather the provided parent will be used.
    * If you provide a path and a parent, but the first element of the
    path is the global namespace, then the global namespace will be
    used as the parent namespace and not the one that was provided.
    * You cannot embed the global namespace in a path, but it can be at
    the root.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def convertNamespaceToClass(namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.listing.GhidraClass:
        """
        Convert a namespace to a class by copying all namespace children into a newly created class
        and then removing the old namespace
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace to be converted
        :return: new class namespace
        :rtype: ghidra.program.model.listing.GhidraClass
        :raises InvalidInputException: if namespace was contained within a function and can not be
                    converted to a class
        """

    @staticmethod
    @typing.overload
    def createNamespaceHierarchy(namespacePath: typing.Union[java.lang.String, str], rootNamespace: ghidra.program.model.symbol.Namespace, program: ghidra.program.model.listing.Program, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        """
        Takes a namespace path string and creates a namespace hierarchy to
        match that string.  This method ignores function namespaces so the path
        should not contain any function names.  If you want traverse down through
        functions, then use the version that also takes an address that is used to distinguish
        between multiple functions with the same name.
         
        
        The root namespace can be a function.
        
        :param java.lang.String or str namespacePath: The namespace name or path string to be parsed.
                This value should not include a trailing symbol name, only namespace names.
        :param ghidra.program.model.symbol.Namespace rootNamespace: The parent namespace under which the desired
                namespace or path resides.  If this value is null, then the
                global namespace will be used. This namespace can be a function name;
        :param ghidra.program.model.listing.Program program: The current program in which the desired namespace
                resides.
        :param ghidra.program.model.symbol.SourceType source: the source type of the namespace
        :return: The namespace that matches the given path.  This can be either an existing
                namespace or a newly created one.
        :rtype: ghidra.program.model.symbol.Namespace
        :raises InvalidInputException: If a given namespace name is in an
                invalid format and this method attempts to create that
                namespace, or if the namespace string contains the global
                namespace name in a position other than the root.
        
        .. seealso::
        
            | `assumptions <assumptions_>`_
        """

    @staticmethod
    @typing.overload
    def createNamespaceHierarchy(namespacePath: typing.Union[java.lang.String, str], rootNamespace: ghidra.program.model.symbol.Namespace, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        """
        Takes a namespace path string and creates a namespace hierarchy to
        match that string.  This method allows function namespaces in the path
        and uses the given address to resolve functions with duplicate names.  When
        resolving down the namespace path, a function that matches a name will only
        be used if the given address is contained in the body of that function.
         
         
        The root namespace can be a function.
         
         
        If an address is passed, then the path can contain a function name provided the
        address is in the body of the function; otherwise the names must all be namespaces other
        than functions.
        
        :param java.lang.String or str namespacePath: The namespace name or path string to be parsed
                This value should not include a trailing symbol name, only namespace names
        :param ghidra.program.model.symbol.Namespace rootNamespace: The parent namespace under which the desired
                namespace or path resides.  If this value is null, then the
                global namespace will be used.
        :param ghidra.program.model.listing.Program program: The current program in which the desired namespace
                resides
        :param ghidra.program.model.address.Address address: the address used to resolve possible functions with duplicate names; may
                be null
        :param ghidra.program.model.symbol.SourceType source: the source of the namespace
        :return: The namespace that matches the given path.  This can be either an existing
                namespace or a newly created one.
        :rtype: ghidra.program.model.symbol.Namespace
        :raises InvalidInputException: If a given namespace name is in an
                invalid format and this method attempts to create that
                namespace, or if the namespace string contains the global
                namespace name in a position other than the root.
        :raises java.lang.IllegalArgumentException: if specified rootNamespace is not valid for 
                specified program.
        
        .. seealso::
        
            | `assumptions <assumptions_>`_
        """

    @staticmethod
    def getFirstNonFunctionNamespace(parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the first namespace with the given name and that is NOT a function that
        is within the parent namespace. (ie. the first namespace that is not tied to a program
        address)
        
        :param ghidra.program.model.symbol.Namespace parent: the parent namespace to search
        :param java.lang.String or str namespaceName: the name of the namespace to find
        :param ghidra.program.model.listing.Program program: the program to search.
        :return: the first namespace that matches, or null if no match.
        :rtype: ghidra.program.model.symbol.Namespace
        :raises java.lang.IllegalArgumentException: if specified parent Namespace is not valid for 
                specified program.
        """

    @staticmethod
    def getFunctionNamespaceAt(program: ghidra.program.model.listing.Program, symbolPath: SymbolPath, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the existing Function at the given address if its :obj:`SymbolPath` matches the
        given path
        
        :param ghidra.program.model.listing.Program program: the program
        :param SymbolPath symbolPath: the path of namespace
        :param ghidra.program.model.address.Address address: the address
        :return: the namespace represented by the given path, or null if no such namespace exists
        :rtype: ghidra.program.model.symbol.Namespace
        """

    @staticmethod
    def getFunctionNamespaceContaining(program: ghidra.program.model.listing.Program, symbolPath: SymbolPath, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the existing Function containing the given address if its
        :obj:`SymbolPath` matches the given path
        
        :param ghidra.program.model.listing.Program program: the program
        :param SymbolPath symbolPath: the path of namespace
        :param ghidra.program.model.address.Address address: the address
        :return: the namespace represented by the given path, or null if no such namespace exists
        :rtype: ghidra.program.model.symbol.Namespace
        """

    @staticmethod
    def getLibrary(namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.listing.Library:
        """
        Get the library associated with the specified namespace
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace
        :return: associated library or null if not associated with a library
        :rtype: ghidra.program.model.listing.Library
        """

    @staticmethod
    def getMatchingNamespaces(childName: typing.Union[java.lang.String, str], parents: java.util.List[ghidra.program.model.symbol.Namespace], program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.symbol.Namespace]:
        """
        Returns a list all namespaces that have the given name in any of the given namespaces
        
        :param java.lang.String or str childName: the name of the namespaces to retrieve
        :param java.util.List[ghidra.program.model.symbol.Namespace] parents: a list of all namespaces to search for child namespaces with the given name
        :param ghidra.program.model.listing.Program program: the program to search
        :return: a list all namespaces that have the given name in any of the given namespaces.
        Empty list if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Namespace]
        :raises java.lang.IllegalArgumentException: if one or more invalid parent namespaces were specified
        """

    @staticmethod
    def getNamespaceByPath(program: ghidra.program.model.listing.Program, parent: ghidra.program.model.symbol.Namespace, pathString: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.symbol.Namespace]:
        """
        Returns a list of namespaces that match the given path.  The path can be
        relative to the given root namespace or absolute if the path begins with
        the global namespace name.
        
         
        Note: this path must only contain Namespace names and no other symbol types.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.symbol.Namespace parent: the namespace to use as the root for relative paths. If null, the
                global namespace will be used
        :param java.lang.String or str pathString: the path to the desired namespace
        :return: a list of namespaces that match the given path.  An empty list is returned 
                if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Namespace]
        :raises java.lang.IllegalArgumentException: if specified parent Namespace is not valid for 
                specified program.
        """

    @staticmethod
    def getNamespaceParts(namespace: ghidra.program.model.symbol.Namespace) -> java.util.List[ghidra.program.model.symbol.Namespace]:
        """
        Returns a list of namespaces, where each element is a component of the original specified
        namespace, excluding the global root namespace.
         
        
        Namespace "ns1::ns2::ns3" returns [ "ns1", "ns1::ns2", "ns1::ns2::ns3" ]
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace to process
        :return: list of namespaces
        :rtype: java.util.List[ghidra.program.model.symbol.Namespace]
        """

    @staticmethod
    def getNamespacePathWithoutLibrary(namespace: ghidra.program.model.symbol.Namespace) -> str:
        """
        Get the normal namespace path excluding any library name.  Global namespace will be
        returned as empty string, while other namespace paths will be returned with trailing ::
        suffix.
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace
        :return: namespace path excluding any library name
        :rtype: str
        """

    @staticmethod
    def getNamespaceQualifiedName(namespace: ghidra.program.model.symbol.Namespace, symbolName: typing.Union[java.lang.String, str], excludeLibraryName: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get namespace qualified symbol name
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace object
        :param java.lang.String or str symbolName: name of symbol
        :param jpype.JBoolean or bool excludeLibraryName: if true any library name will be excluded from path returned,
        otherwise it will be included
        :return: namespace qualified symbol name
        :rtype: str
        """

    @staticmethod
    def getNamespacesByName(program: ghidra.program.model.listing.Program, parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.symbol.Namespace]:
        """
        Returns a list of all namespaces with the given name in the parent namespace
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.symbol.Namespace parent: the parent namespace from which to find all namespaces with the given name;
                if null, the global namespace will be used
        :param java.lang.String or str namespaceName: the name of the namespaces to retrieve
        :return: a list of all namespaces that match the given name in the given parent namespace.
        An empty list is returned if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Namespace]
        :raises java.lang.IllegalArgumentException: if specified parent Namespace is not valid for 
                specified program.
        """

    @staticmethod
    def getNonFunctionNamespace(program: ghidra.program.model.listing.Program, symbolPath: SymbolPath) -> ghidra.program.model.symbol.Namespace:
        """
        Finds the namespace for the given symbol path **that is not a function**
        
        :param ghidra.program.model.listing.Program program: the program from which to get the namespace
        :param SymbolPath symbolPath: the path of namespace names including the name of the desired namespace
        :return: the namespace represented by the given path, or null if no such namespace exists or
                the namespace is a function
        :rtype: ghidra.program.model.symbol.Namespace
        """

    @staticmethod
    @typing.overload
    def getSymbols(symbolPath: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns a list of all symbols that match the given path within the global namespace. 
        The path consists of a series of namespaces names separated by "::" followed by a label 
        or function name.
        
        :param java.lang.String or str symbolPath: the names of namespaces and symbol separated by "::".
        :param ghidra.program.model.listing.Program program: the program to search
        :return: the list of symbols that match the given symbolPath.  An empty list is returned
        if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """

    @staticmethod
    @typing.overload
    def getSymbols(symbolPath: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, searchWithinAllLibraries: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns a list of all symbols that match the given path. The path consists of a series
        of namespaces names separated by "::" followed by a label or function name.
        
        :param java.lang.String or str symbolPath: the names of namespaces and symbol separated by "::".
        :param ghidra.program.model.listing.Program program: the program to search
        :param jpype.JBoolean or bool searchWithinAllLibraries: if true all libraries will be searched provided first element 
        of symbolPath is not a library name, else search symbolPath within global namespace only.
        :return: the list of symbols that match the given symbolPath.  An empty list is returned
        if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """

    @staticmethod
    @typing.overload
    def getSymbols(symbolPath: SymbolPath, program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns a list of Symbol that match the given symbolPath within the global namespace.
        
        :param SymbolPath symbolPath: the symbol path that specifies a series of namespace and symbol names.
        :param ghidra.program.model.listing.Program program: the program to search for symbols with the given path.
        :return: a list of Symbol that match the given symbolPath.  An empty list is returned
        if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """

    @staticmethod
    @typing.overload
    def getSymbols(symbolPath: SymbolPath, program: ghidra.program.model.listing.Program, searchWithinAllLibraries: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns a list of Symbol that match the given symbolPath.
        
        :param SymbolPath symbolPath: the symbol path that specifies a series of namespace and symbol names.
        :param ghidra.program.model.listing.Program program: the program to search for symbols with the given path.
        :param jpype.JBoolean or bool searchWithinAllLibraries: if true all libraries will be searched provided first element 
        of symbolPath is not a library name, else search symbolPath within global namespace only.
        :return: a list of Symbol that match the given symbolPath.  An empty list is returned
        if none found.
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """


class PseudoFlowProcessor(java.lang.Object):
    """
    Defines methods for flow as if the code were actually being disassembled.
    """

    class_: typing.ClassVar[java.lang.Class]

    def followFlows(self, instr: PseudoInstruction) -> bool:
        """
        Return true if the flows should be followed from this instruction
        
        :param PseudoInstruction instr: instruction to test
        :return: false if flows should not be followed
        :rtype: bool
        """

    def process(self, instr: PseudoInstruction) -> bool:
        """
        Process this instruction; return false if instr terminates.
        
        :param PseudoInstruction instr: instruction to check
        :return: false when the processing should stop
        :rtype: bool
        """


class PseudoDisassembler(java.lang.Object):
    """
    PseudoDisassembler.java
     
    Useful for disassembling and getting an Instruction or creating Data
    at a location in memory when you don't want the program to be changed.
     
    The Instructions or Data that area created are PseudoInstruction's and
    PseudoData's.  They act like regular instructions in most respects, but
    they don't exist in the program.  No references, symbols, are created or
    will be saved when the program is saved.
     
    You do not need to have an open transaction on the program to use the
    PseudoDisassembler.
     
    The PseudoDisassembler can also be used to check if something is a valid
    subroutine.  The algorithm it uses could definitely use some tuning, but
    it generally works well.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Create a pseudo disassembler for the given program.
        """

    def applyDataType(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType) -> PseudoData:
        """
        Apply a dataType to the program at the given address.  The program is
        not affected.  A PseudoData item that acts like a Data item retrieved from
        a program is returned.  This is useful if you have a datatype and you
        want to use it to get values from the program at a given address.
        
        :param ghidra.program.model.address.Address addr: location to get a PseudoData item for
        :param ghidra.program.model.data.DataType dt: the data type to be applied
        :return: :obj:`PseudoData` that acts like Data
        :rtype: PseudoData
        """

    @typing.overload
    def checkValidSubroutine(self, entryPoint: ghidra.program.model.address.Address, allowExistingInstructions: typing.Union[jpype.JBoolean, bool], mustTerminate: typing.Union[jpype.JBoolean, bool], requireContiguous: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if there is a valid subroutine at the target address
        
        :param ghidra.program.model.address.Address entryPoint: address to check
        :param jpype.JBoolean or bool allowExistingInstructions: true to allow running into existing instructions
        :param jpype.JBoolean or bool mustTerminate: true if the subroutine must hit a terminator (return) instruction
        :param jpype.JBoolean or bool requireContiguous: true if the caller will require some number of contiguous instructions
                call getLastCheckValidInstructionCount() to get the initial number of contiguous instructions
                if this is true
        :return: true if entryPoint is the probable subroutine start
        :rtype: bool
        """

    @typing.overload
    def checkValidSubroutine(self, entryPoint: ghidra.program.model.address.Address, procContext: PseudoDisassemblerContext, allowExistingInstructions: typing.Union[jpype.JBoolean, bool], mustTerminate: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if there is a valid subroutine at the target address
        
        :param ghidra.program.model.address.Address entryPoint: address to check
        :param PseudoDisassemblerContext procContext: processor context to use when pseudo disassembling instructions
        :param jpype.JBoolean or bool allowExistingInstructions: true to allow running into existing instructions
        :param jpype.JBoolean or bool mustTerminate: true if the subroutine must hit a terminator (return) instruction
        :return: true if entryPoint is the probable subroutine start
        :rtype: bool
        """

    @typing.overload
    def checkValidSubroutine(self, entryPoint: ghidra.program.model.address.Address, procContext: PseudoDisassemblerContext, allowExistingInstructions: typing.Union[jpype.JBoolean, bool], mustTerminate: typing.Union[jpype.JBoolean, bool], requireContiguous: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if there is a valid subroutine at the target address
        
        :param ghidra.program.model.address.Address entryPoint: address to check
        :param PseudoDisassemblerContext procContext: processor context to use when pseudo disassembling instructions
        :param jpype.JBoolean or bool allowExistingInstructions: true to allow running into existing instructions
        :param jpype.JBoolean or bool mustTerminate: true if the subroutine must hit a terminator (return) instruction
        :param jpype.JBoolean or bool requireContiguous: true if the caller will require some number of contiguous instructions
                call getLastCheckValidInstructionCount() to get the initial number of contiguous instructions
                if this is true
        :return: true if entryPoint is the probable subroutine start
        :rtype: bool
        """

    @typing.overload
    def disassemble(self, addr: ghidra.program.model.address.Address) -> PseudoInstruction:
        """
        Disassemble a single instruction.  The program is not affected.
        
        :param ghidra.program.model.address.Address addr: location to disassemble
        :return: a PseudoInstruction
        :rtype: PseudoInstruction
        :raises InsufficientBytesException: 
        :raises UnknownInstructionException: 
        :raises UnknownContextException:
        """

    @typing.overload
    def disassemble(self, addr: ghidra.program.model.address.Address, disassemblerContext: PseudoDisassemblerContext, isInDelaySlot: typing.Union[jpype.JBoolean, bool]) -> PseudoInstruction:
        """
        Disassemble a single instruction.  The program is not affected.
        
        :param ghidra.program.model.address.Address addr: 
        :param PseudoDisassemblerContext disassemblerContext: 
        :param jpype.JBoolean or bool isInDelaySlot: 
        :return: 
        :rtype: PseudoInstruction
        :raises InsufficientBytesException: 
        :raises UnknownInstructionException: 
        :raises UnknownContextException:
        """

    @typing.overload
    def disassemble(self, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> PseudoInstruction:
        """
        Disassemble a location in memory with the given set of bytes.
        Useful when the address has no actual bytes defined, or you want to use
        your own bytes instead of what is in the program at the address.
        
        :param ghidra.program.model.address.Address addr: address to disassemble
        :param jpype.JArray[jpype.JByte] bytes: bytes to use instead of those currently defined in program
        :return: PseudoInstruction.
        :rtype: PseudoInstruction
        :raises InsufficientBytesException: 
        :raises UnknownInstructionException: 
        :raises UnknownContextException:
        """

    @typing.overload
    def disassemble(self, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], disassemblerContext: PseudoDisassemblerContext) -> PseudoInstruction:
        """
        Disassemble a location in memory with the given set of bytes.
        Useful when the address has no actual bytes defined, or you want to use
        your own bytes instead of what is in the program at the address.
        
        :param ghidra.program.model.address.Address addr: address to disassemble
        :param jpype.JArray[jpype.JByte] bytes: bytes to use instead of those currently defined in program
        :param PseudoDisassemblerContext disassemblerContext: the disassembler context to use.
        :return: PseudoInstruction.
        :rtype: PseudoInstruction
        :raises InsufficientBytesException: 
        :raises UnknownInstructionException: 
        :raises UnknownContextException:
        """

    @typing.overload
    def followSubFlows(self, entryPoint: ghidra.program.model.address.Address, maxInstr: typing.Union[jpype.JInt, int], processor: PseudoFlowProcessor) -> ghidra.program.model.address.AddressSet:
        """
        Process a subroutine using the processor function.
        The process function can control what flows are followed and when to stop.
        
        :param ghidra.program.model.address.Address entryPoint: start address
        :param jpype.JInt or int maxInstr: maximum number of instructions to evaluate
        :param PseudoFlowProcessor processor: processor to use
        :return: the address set of instructions that were followed
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def followSubFlows(self, entryPoint: ghidra.program.model.address.Address, procContext: PseudoDisassemblerContext, maxInstr: typing.Union[jpype.JInt, int], processor: PseudoFlowProcessor) -> ghidra.program.model.address.AddressSet:
        """
        Process a subroutine using the processor function.
        The process function can control what flows are followed and when to stop.
        
        :param ghidra.program.model.address.Address entryPoint: start address
        :param PseudoDisassemblerContext procContext: initial processor context for disassembly
        :param jpype.JInt or int maxInstr: maximum number of instructions to evaluate
        :param PseudoFlowProcessor processor: processor to use
        :return: the address set of instructions that were followed
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getIndirectAddr(self, toAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Interpret the bytes at a location in memory as an address
        and return the address.  This routine assumes that the bytes
        needed to create the address are the same size as the bytes
        needed to represent the toAddr.  So this is somewhat generic.
        
        :param ghidra.program.model.address.Address toAddr: location of the bytes in memory
        :return: the address value
        :rtype: ghidra.program.model.address.Address
        """

    def getLastCheckValidInstructionCount(self) -> int:
        """
        Get the last number of disassembled instructions
        or the number of initial contiguous instruction if requireContiguous is true
        """

    @staticmethod
    def getNormalizedDisassemblyAddress(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get an address that can be used for disassembly.  Useful for some processors where
        pointers to code have 1 added to them for different modes such as Thumb mode for ARM.
        
        :param ghidra.program.model.listing.Program program: to get address from
        :param ghidra.program.model.address.Address addr: to be normallized/aligned for disassembly
        :return: the normalized/aligned address for disassembly
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getTargetContextRegisterValueForDisassembly(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        
        
        :return: RegisterValue setting for the context register to disassemble correctly at the given address
                or null, if no setting is needed.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @staticmethod
    def hasLowBitCodeModeInAddrValues(program: ghidra.program.model.listing.Program) -> bool:
        """
        
        
        :return: true if program has uses the low bit of an address to change Instruction Set mode
        :rtype: bool
        """

    @typing.overload
    def isValidCode(self, entryPoint: ghidra.program.model.address.Address) -> bool:
        """
        Check that this entry point leads to valid code:
         
        *  May have multiple entries into the body of the code.
        * The intent is that it be valid code, not nice code.
        * Hit no bad instructions.
        * It should return.
        
        
        :param ghidra.program.model.address.Address entryPoint: 
        :return: true if the entry point leads to valid code
        :rtype: bool
        """

    @typing.overload
    def isValidCode(self, entryPoint: ghidra.program.model.address.Address, context: PseudoDisassemblerContext) -> bool:
        """
        Check that this entry point leads to valid code:
         
        *  May have multiple entries into the body of the code.
        * The intent is that it be valid code, not nice code.
        * Hit no bad instructions.
        * It should return.
        
        
        :param ghidra.program.model.address.Address entryPoint: location to test for valid code
        :param PseudoDisassemblerContext context: disassembly context for program
        :return: true if the entry point leads to valid code
        :rtype: bool
        """

    @typing.overload
    def isValidSubroutine(self, entryPoint: ghidra.program.model.address.Address) -> bool:
        """
        Check that this entry point leads to a well behaved subroutine:
         
        * It should return.
        * Hit no bad instructions.
        * Have only one entry point.
        * Not overlap any existing data or instructions.
        
        
        :param ghidra.program.model.address.Address entryPoint: entry point to check
        :return: true if entry point leads to a well behaved subroutine
        :rtype: bool
        """

    @typing.overload
    def isValidSubroutine(self, entryPoint: ghidra.program.model.address.Address, allowExistingCode: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check that this entry point leads to a well behaved subroutine, allow it
        to fall into existing code.
         
        * It should return.
        * Hit no bad instructions.
        * Have only one entry point.
        * Not overlap any existing data or cause offcut references.
        
        
        :param ghidra.program.model.address.Address entryPoint: entry point to check
        :param jpype.JBoolean or bool allowExistingCode: true allows this subroutine to flow into existing instructions.
        :return: true if entry point leads to a well behaved subroutine
        :rtype: bool
        """

    @typing.overload
    def isValidSubroutine(self, entryPoint: ghidra.program.model.address.Address, allowExistingCode: typing.Union[jpype.JBoolean, bool], mustTerminate: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check that this entry point leads to a well behaved subroutine, allow it
        to fall into existing code.
         
        * Hit no bad instructions.
        * Have only one entry point.
        * Not overlap any existing data or cause offcut references.
        
        
        :param ghidra.program.model.address.Address entryPoint: entry point to check
        :param jpype.JBoolean or bool allowExistingCode: true allows this subroutine to flow into existing instructions.
        :param jpype.JBoolean or bool mustTerminate: true if the subroutine must terminate
        :return: true if entry point leads to a well behaved subroutine
        :rtype: bool
        """

    def setMaxInstructions(self, maxNumInstructions: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of instructions to check
        
        :param jpype.JInt or int maxNumInstructions: - maximum number of instructions to check before returning
        """

    def setRespectExecuteFlag(self, respect: typing.Union[jpype.JBoolean, bool]):
        """
        Set flag to respect Execute bit on memory if present on any memory
        
        :param jpype.JBoolean or bool respect: - true, respect execute bit on memory blocks
        """

    @staticmethod
    @typing.overload
    def setTargetContextForDisassembly(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        If this processor uses the low bit of an address to change to a new Instruction Set mode
        Check the low bit and change the instruction state at the address.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.address.Address addr: the raw address
        :return: the correct address to disassemble at if it needs to be aligned
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def setTargetContextForDisassembly(procContext: ghidra.program.model.lang.DisassemblerContext, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        In order to check a location to see if it disassembles from an address reference, the
        address is checked for low-bit code switch behavior.  If it does switch, the context
        is changed.
        
        :param ghidra.program.model.lang.DisassemblerContext procContext: context to change
        :param ghidra.program.model.address.Address addr: destination address that will be disassembled (possible pseudo disassembled)
        :return: the correct disassembly location if the address needed to be adjusted.
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def lastCheckValidInstructionCount(self) -> jpype.JInt:
        ...

    @property
    def validCode(self) -> jpype.JBoolean:
        ...

    @property
    def validSubroutine(self) -> jpype.JBoolean:
        ...

    @property
    def indirectAddr(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class PseudoCodeUnit(ghidra.program.model.listing.CodeUnit):

    class_: typing.ClassVar[java.lang.Class]

    def addMnemonicReference(self, refAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Add a reference to the mnemonic for this code unit.
        
        :param ghidra.program.model.address.Address refAddr: address of reference to add
        :param ghidra.program.model.symbol.RefType refType: type of reference being added
        """

    def addOperandReference(self, opIndex: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address, type: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Add a user defined reference to the operand at the given index.
        
        
        .. seealso::
        
            | :obj:`CodeUnit.addOperandReference(int, Address, RefType, SourceType)`
        """

    def compareTo(self, a: ghidra.program.model.address.Address) -> int:
        """
        Compares the given address to the address range of this node.
        
        :param ghidra.program.model.address.Address a: the address
        :return: a negative integer if addr is greater than the maximum range
                address zero if addr is in the range a positive integer if addr
                is less than minimum range address
        :rtype: int
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def contains(self, testAddr: ghidra.program.model.address.Address) -> bool:
        """
        Determines if this code unit contains the indicated address.
        
        :param ghidra.program.model.address.Address testAddr: the address to test
        :return: true if address is contained in the range.
        :rtype: bool
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the Address which corresponds to the offset 0.
        
        :return: the current address of offset 0.
        :rtype: ghidra.program.model.address.Address
        """

    def getByte(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get one byte from memory at the current position plus offset.
        
        :param jpype.JInt or int offset: the displacement from the current position.
        :return: the data at offset from the current position.
        :rtype: int
        :raises AddressOutOfBoundsException: if offset exceeds address space
        :raises IndexOutOfBoundsException: if offset is negative
        :raises MemoryAccessException: if memory cannot be read
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Gets the bytes for this code unit.
        """

    def getCommentAsArray(self, commentType: ghidra.program.model.listing.CommentType) -> jpype.JArray[java.lang.String]:
        """
        Get the comment as an array where each element is a single line for the
        given type.
        
        :param ghidra.program.model.listing.CommentType commentType: must be either EOL_COMMENT_TYPE, PRE_COMMENT_TYPE,
                    POST_COMMENT_TYPE, or PLATE_COMMENT_TYPE
        :raises IllegalArgumentException: if type is not one of the three types of comments supported
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getIntProperty(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get the int property for name.
        
        :param java.lang.String or str name: the name of the property.
        :raises NoValueException: if there is not name property for this code unit
        :raises TypeMismatchException: if the property manager for name does not support int types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    @deprecated("")
    def getLabel(self) -> str:
        """
        Get the label for this code unit.
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        
        .. deprecated::
        """

    def getLength(self) -> int:
        """
        Get the length of the code unit.
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the ending address for this code unit.
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getMemory(self) -> ghidra.program.model.mem.Memory:
        """
        Get the Memory object actually used by the MemBuffer.
         
        return the Memory used by this MemBuffer.
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the starting address for this code unit.
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getMnemonicReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get references for the mnemonic for this instruction.
        """

    def getNextCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        """
        :return: the code unit after this code unit.
        :rtype: ghidra.program.model.listing.CodeUnit
        
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getObjectProperty(self, name: typing.Union[java.lang.String, str]) -> ghidra.util.Saveable:
        """
        Get the object property for name; returns null if there is no name
        property for this code unit.
        
        :param java.lang.String or str name: the name of the property.
        :raises TypeMismatchException: if the property manager for name does not support object
                    types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getOperandReferences(self, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get the references for the operand index. If the operand type is a
        register, then the user defined references are returned; otherwise an
        array with the address for the operand value is returned.
        """

    def getPreviousCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        """
        :return: the code unit before this code unit.
        :rtype: ghidra.program.model.listing.CodeUnit
        
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getPrimarySymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get the primary Symbol for this code unit.
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getReferencesFrom(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get ALL reference FROM this code unit.
        """

    def getStackReference(self, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.StackReference:
        ...

    def getStringProperty(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Get the string property for name; returns null if there is no name
        property for this code unit.
        
        :param java.lang.String or str name: the name of the property.
        :raises TypeMismatchException: if the property manager for name does not support string
                    types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getSymbols(self) -> jpype.JArray[ghidra.program.model.symbol.Symbol]:
        """
        Get the symbols for this code unit.
        
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def getVoidProperty(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns whether this code unit is marked as having the name property.
        
        :param java.lang.String or str name: the name of the property.
        :raises TypeMismatchException: if the property manager for name does not support void types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def invalidate(self):
        """
        Invalidate memory buffer
        """

    def isValid(self) -> bool:
        ...

    def removeMnemonicReference(self, refAddr: ghidra.program.model.address.Address):
        """
        Remove a reference to the mnemonic for this instruction.
        """

    def removeOperandReference(self, opIndex: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address):
        """
        Remove a user defined reference to the operand at opIndex.
        """

    def removeProperty(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the property value with the given name for this code unit.
        
        :param java.lang.String or str name: the name of the property.
        """

    def removeStackReference(self, opIndex: typing.Union[jpype.JInt, int]):
        ...

    def setComment(self, commentType: ghidra.program.model.listing.CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given type.
        
        :param ghidra.program.model.listing.CommentType commentType: must be either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, or
                    PLATE_COMMENT
        :param java.lang.String or str comment: the comment
        :raises IllegalArgumentException: if type is not one of the three types of comments supported
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def setCommentAsArray(self, commentType: ghidra.program.model.listing.CommentType, comment: jpype.JArray[java.lang.String]):
        """
        Set the comment for the given type.
        
        :param ghidra.program.model.listing.CommentType commentType: must be either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, or
                    PLATE_COMMENT
        :param jpype.JArray[java.lang.String] comment: the lines that make up the comment
        :raises IllegalArgumentException: if type is not one of the three types of comments supported
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    def setExternalReference(self, ref: ghidra.program.model.symbol.Reference):
        ...

    def setMemoryReference(self, opIndex: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType):
        ...

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: ghidra.util.Saveable):
        """
        Set the property name with the given value for this code unit.
        
        :param java.lang.String or str name: the name of the property to save.
        :param ghidra.util.Saveable value: the value of the property to save.
        :raises TypeMismatchException: if the property manager for name does not support object
                    types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Set the property name with the given value for this code unit.
        
        :param java.lang.String or str name: the name of the property to save.
        :param java.lang.String or str value: the value of the property to save.
        :raises TypeMismatchException: if the property manager for name does not support string
                    types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        """
        Set the property name with the given value for this code unit.
        
        :param java.lang.String or str name: the name of the property to save.
        :param jpype.JInt or int value: the value of the property to save.
        :raises TypeMismatchException: if the property manager for name does not support int types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    @typing.overload
    def setProperty(self, name: typing.Union[java.lang.String, str]):
        """
        Mark the property name as having a value for this code unit.
        
        :param java.lang.String or str name: the name of the property to save.
        :raises TypeMismatchException: if the property manager for name does not support void types
        :raises ConcurrentModificationException: if this object is no longer valid.
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def intProperty(self) -> jpype.JInt:
        ...

    @property
    def stackReference(self) -> ghidra.program.model.symbol.StackReference:
        ...

    @property
    def memory(self) -> ghidra.program.model.mem.Memory:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def voidProperty(self) -> jpype.JBoolean:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def operandReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @property
    def symbols(self) -> jpype.JArray[ghidra.program.model.symbol.Symbol]:
        ...

    @property
    def stringProperty(self) -> java.lang.String:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def commentAsArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def referencesFrom(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def previousCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def objectProperty(self) -> ghidra.util.Saveable:
        ...

    @property
    def nextCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def mnemonicReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def primarySymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...


class PseudoData(PseudoCodeUnit, ghidra.program.model.listing.Data):
    """
    "Fake" data generated by the PseudoDisassembler.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, memBuffer: ghidra.program.model.mem.MemBuffer):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, memBuffer: ghidra.program.model.mem.MemBuffer):
        ...

    def getByteCodeString(self) -> str:
        ...

    @property
    def byteCodeString(self) -> java.lang.String:
        ...


class PseudoDisassemblerContext(ghidra.program.model.lang.DisassemblerContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, context: ghidra.program.model.listing.ProgramContext):
        ...

    def copyToFutureFlowState(self, target: ghidra.program.model.address.Address):
        ...

    def flowEnd(self, address: ghidra.program.model.address.Address):
        ...

    def flowStart(self, address: ghidra.program.model.address.Address):
        ...

    def flowToAddress(self, target: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def setValue(self, register: ghidra.program.model.lang.Register, addr: ghidra.program.model.address.Address, value: java.math.BigInteger):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class RepeatInstructionByteTracker(java.lang.Object):
    """
    ``RepeatInstructionByteTracker`` provides pseudo-disassemblers the ability to track
    repeated bytes during disassembly of a block of instructions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, repeatPatternLimit: typing.Union[jpype.JInt, int], repeatPatternLimitIgnoredRegion: ghidra.program.model.address.AddressSetView):
        """
        Constructor.
        
        :param jpype.JInt or int repeatPatternLimit: maximum number of instructions containing the same repeated 
        byte values.  A value less than or equal to 0 will disable counting.
        :param ghidra.program.model.address.AddressSetView repeatPatternLimitIgnoredRegion: optional set of addresses where check is not 
        performed or null for check to be performed everywhere.
        """

    def exceedsRepeatBytePattern(self, inst: PseudoInstruction) -> bool:
        """
        Check the next instruction within a block of instructions.
        
        :param PseudoInstruction inst: next instruction
        :return: true if repeat limit has been exceeded, else false.  
        If the repeat limit has been set <= 0 false will be returned.
        :rtype: bool
        """

    def reset(self):
        """
        Reset internal counter.  This should be performed before disassembling
        a new block of instructions.
        """

    def setRepeatPatternLimit(self, maxInstructions: typing.Union[jpype.JInt, int]):
        """
        Set the maximum number of instructions in a single run which contain the same byte values.
        
        :param jpype.JInt or int maxInstructions: limit on the number of consecutive instructions with the same 
        byte values.  A non-positive value (<= 0) will disable the 
        :meth:`exceedsRepeatBytePattern(PseudoInstruction) <.exceedsRepeatBytePattern>` checking.
        """

    def setRepeatPatternLimitIgnored(self, set: ghidra.program.model.address.AddressSetView):
        """
        Set the region over which the repeat pattern limit will be ignored.
        
        :param ghidra.program.model.address.AddressSetView set: region over which the repeat pattern limit will be ignored
        """


class SymbolPathParser(java.lang.Object):
    """
    A parser for breaking down namespaces in the presence of complicating factors such
    as templates.
     
    
    For example, if a SymbolPath is constructed with "foo<int, blah::hah>::bar::baz",
    then "baz" is the name of a symbol in the "bar" namespace, which is in the
    "foo<int, blah::hah>" namespace.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def parse(name: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Parses a String pathname into its constituent namespace and name components.
        The list does not contain the global namespace, which is implied, but then
        has each more deeply nested namespace contained in order in the list, followed
        by the trailing name.
        
        :param java.lang.String or str name: The input String to be parsed.
        :return: List<String> containing the sequence of namespaces and trailing name.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    @typing.overload
    def parse(name: typing.Union[java.lang.String, str], ignoreLeaderParens: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        """
        Parses a String pathname into its constituent namespace and name components.
        The list does not contain the global namespace, which is implied, but then
        has each more deeply nested namespace contained in order in the list, followed
        by the trailing name.
        
        :param java.lang.String or str name: The input String to be parsed.
        :param jpype.JBoolean or bool ignoreLeaderParens: true signals to ignore any string that starts with a '(' char.  
                This is useful to work around some problem characters.
        :return: List<String> containing the sequence of namespaces and trailing name.
        :rtype: java.util.List[java.lang.String]
        """


@typing.type_check_only
class PseudoDataComponent(PseudoData):
    """
    ``DataComponent`` provides Data and CodeUnit access to Struct and Array components.
    
    NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
    the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
    The CodeUnit key should only be used for managing an object cache.
    """

    class_: typing.ClassVar[java.lang.Class]


class PseudoInstruction(PseudoCodeUnit, ghidra.program.model.listing.Instruction, ghidra.program.model.lang.InstructionContext):
    """
    Pseudo (i.e., fake) instruction that is generated by the Disassembler.  This form of 
    has some limitation over an instruction which is obtained from a program listing.
    The instruction will completely cache all bytes corresponding to the prototype length
    at the specified address.  Additional bytes will be cached for delay-slotted instructions
    to facilitate pcode generation and obtaining general pcode related attributes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuffer: ghidra.program.model.mem.MemBuffer, procContext: ghidra.program.model.lang.ProcessorContext):
        """
        Construct a new PseudoInstruction within a program.
        
        :param ghidra.program.model.listing.Program program: is the given Program
        :param ghidra.program.model.address.Address addr: address of the instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: prototype of the instruction
        :param ghidra.program.model.mem.MemBuffer memBuffer: buffer containing the bytes for the instruction
        :param ghidra.program.model.lang.ProcessorContext procContext: processor state information during disassembly
        :raises AddressOverflowException: if code unit length causes wrap within space
        """

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, addr: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuffer: ghidra.program.model.mem.MemBuffer, procContext: ghidra.program.model.lang.ProcessorContext):
        """
        Construct a new PseudoInstruction within a program.
        
        :param ghidra.program.model.address.AddressFactory addrFactory: program/language address factory
        :param ghidra.program.model.address.Address addr: address of the instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: prototype of the instruction
        :param ghidra.program.model.mem.MemBuffer memBuffer: buffer containing the bytes for the instruction
        :param ghidra.program.model.lang.ProcessorContext procContext: processor state information during disassembly
        :raises AddressOverflowException: if code unit length causes wrap within space
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuffer: ghidra.program.model.mem.MemBuffer, procContext: ghidra.program.model.lang.ProcessorContext):
        """
        Construct a new PseudoInstruction without a program (flow override not supported).
        
        :param ghidra.program.model.address.Address addr: address of the instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: prototype of the instruction
        :param ghidra.program.model.mem.MemBuffer memBuffer: buffer containing the bytes for the instruction
        :param ghidra.program.model.lang.ProcessorContext procContext: processor state information during disassembly
        :raises AddressOverflowException: if code unit length causes wrap within space
        """

    def getRepeatedByte(self) -> int:
        """
        Return the byte value repeated for all bytes within this instruction or null
        if byte values vary.
        
        :return: repeated byte value or null if bytes vary
        :rtype: int
        """

    def setInstructionBlock(self, bl: ghidra.program.model.lang.InstructionBlock):
        ...

    @property
    def repeatedByte(self) -> jpype.JByte:
        ...


class SymbolPath(java.lang.Comparable[SymbolPath]):
    """
    A convenience object for parsing a namespace path to a symbol.
     
    
    For example, if a SymbolPath is constructed with "foo::bar::baz", then "baz" is the
    name of a symbol in the "bar" namespace, which is in the "foo" namespace.
     
    * :meth:`getName() <.getName>` will return "baz".
    * :meth:`getParentPath() <.getParentPath>` will return "foo:bar".
    * :meth:`getPath() <.getPath>` will return "foo::bar::baz".
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, symbolPathString: typing.Union[java.lang.String, str]):
        """
        Construct a SymbolPath from a string containing NAMESPACE_DELIMITER ("::") sequences to
        separate the namespace names.  This is the only constructor that employs special
        string-based namespace parsing.
        
        :param java.lang.String or str symbolPathString: the string to parse as a sequence of namespace names separated by
        "::".
        """

    @typing.overload
    def __init__(self, symbolPath: jpype.JArray[java.lang.String]):
        """
        Construct a SymbolPath from an array of strings where each string is the name of a namespace
        in the symbol path.
        
        :param jpype.JArray[java.lang.String] symbolPath: the array of names of namespaces.
        """

    @typing.overload
    def __init__(self, symbolList: java.util.List[java.lang.String]):
        """
        Construct a SymbolPath from a list of strings where each string is the name of a namespace
        in the symbol path.
        
        :param java.util.List[java.lang.String] symbolList: the array of names of namespaces.
        :raises IllegalArgumentException: if the given list is null or empty.
        """

    @typing.overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol):
        """
        Constructs a new SymbolPath for the given symbol.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to get a SymbolPath for.
        """

    @typing.overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, excludeLibrary: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new SymbolPath for the given symbol with the option to exclude a beginning
        library name.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to get a SymbolPath for.
        :param jpype.JBoolean or bool excludeLibrary: if true, any library name at the front of the path will be removed.
        """

    @typing.overload
    def __init__(self, parent: SymbolPath, name: typing.Union[java.lang.String, str]):
        """
        Creates a Symbol from a parent SymbolPath and a symbol name.
        
        :param SymbolPath parent: the parent SymbolPath. Can be null if the name is in the global space.
        :param java.lang.String or str name: the name of the symbol. This can't be null;
        """

    def append(self, path: SymbolPath) -> SymbolPath:
        """
        Creates a new SymbolPath composed of the list of names in this path followed by the
        list of names in the given path.
        
        :param SymbolPath path: the path of names to append to this path.
        :return: a new SymbolPath that appends the given path to this path.
        :rtype: SymbolPath
        """

    def asArray(self) -> jpype.JArray[java.lang.String]:
        """
        Returns an array of names of the symbols in the symbol path, starting with the name just
        below the global namespace.
        
        :return: an array of names of the symbols in the symbol path.
        :rtype: jpype.JArray[java.lang.String]
        """

    def asList(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of names of the symbols in the symbol path, starting with the name just
        below the global namespace.
        
        :return: a list of names of the symbols in the symbol path.
        :rtype: java.util.List[java.lang.String]
        """

    def containsPathEntry(self, text: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if this path contains any path entry matching the given text
        
        :param java.lang.String or str text: the text for which to search
        :return: true if any path entry matches the given text
        :rtype: bool
        """

    def getName(self) -> str:
        """
        Returns the name of the symbol;
        
        :return: the symbol name as string without any path information.
        :rtype: str
        """

    def getParent(self) -> SymbolPath:
        """
        Returns the SymbolPath for the parent namespace or null if the parent is the global space.
        
        :return: the SymbolPath for the parent namespace or null if the parent is the global space.
        :rtype: SymbolPath
        """

    def getParentPath(self) -> str:
        """
        Returns null if the parent is null or global; otherwise returns the path as a string of the
        parent namespace path.
        
        :return: the path of the parent namespace as string. Returns null if the parent is null or global.
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Returns the full symbol path as a string.
        
        :return: the SymbolPath for the complete name as string, including namespace.
        :rtype: str
        """

    def matchesPathOf(self, s: ghidra.program.model.symbol.Symbol) -> bool:
        """
        A convenience method to check if the given symbol's symbol path matches this path
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to check
        :return: true if the symbol paths match
        :rtype: bool
        """

    def replaceInvalidChars(self) -> SymbolPath:
        """
        Returns a new SymbolPath in which invalid characters are replaced
        with underscores.
        
        :return: the new SymbolPath with replaced characters.
        :rtype: SymbolPath
        """

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def parent(self) -> SymbolPath:
        ...

    @property
    def parentPath(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class FileOpenDataFlavorHandler(java.lang.Object):
    """
    Interface for classes that will handle drop actions for files dropped onto the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def handle(self, tool: ghidra.framework.plugintool.PluginTool, obj: java.lang.Object, e: java.awt.dnd.DropTargetDropEvent, f: java.awt.datatransfer.DataFlavor):
        ...


class GenericHelpTopics(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    ABOUT: typing.Final = "About"
    """
    Help Topic for "About."
    """

    FRONT_END: typing.Final = "FrontEndPlugin"
    """
    Name of options for the help topic for the front end
    (Project Window).
    """

    GLOSSARY: typing.Final = "Glossary"
    """
    Help Topic for the glossary.
    """

    INTRO: typing.Final = "Intro"
    """
    Help for Intro topics.
    """

    REPOSITORY: typing.Final = "Repository"
    """
    Help Topic for the project repository.
    """

    VERSION_CONTROL: typing.Final = "VersionControl"
    """
    Help Topic for the version control.
    """

    TOOL: typing.Final = "Tool"
    """
    Help Topic for tools.
    """


    def __init__(self):
        ...


class FileOpenDropHandler(docking.DropTargetHandler, docking.dnd.Droppable, java.awt.event.ContainerListener):
    """
    Handles drag/drop events on a given component such that a file
    dropped on the component from the front end tool will cause
    that file to be opened.  Properly handles drop events with
    child components and listens for components being added/removed
    in order to properly support drag/drop with all components.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, component: java.awt.Component):
        """
        Construct a new FileOpenDropHandler.
        
        :param ghidra.framework.plugintool.PluginTool tool: plugin tool
        :param java.awt.Component component: component that is the drop target
        """

    @staticmethod
    def addDataFlavorHandler(dataFlavor: java.awt.datatransfer.DataFlavor, handler: FileOpenDataFlavorHandler):
        ...

    def dispose(self):
        """
        Dispose this drop handler.
        """

    @staticmethod
    def removeDataFlavorHandler(dataFlavor: java.awt.datatransfer.DataFlavor) -> FileOpenDataFlavorHandler:
        ...


class DecompilerConcurrentQ(java.lang.Object, typing.Generic[I, R]):
    """
    A class to perform some of the boilerplate setup of the :obj:`ConcurrentQ` that is shared
    amongst clients that perform decompilation in parallel.
    
     
    This class can be used in a blocking or non-blocking fashion.
    
     
    * For blocking usage, call
    one of the``add`` methods to put items in the queue and then call
    :meth:`waitForResults() <.waitForResults>`.
    * For non-blocking usage, simply call
    :meth:`process(Iterator, Consumer) <.process>`, passing the consumer of the results.
    """

    @typing.type_check_only
    class InternalResultListener(generic.concurrent.QItemListener[I, R]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, callback: generic.concurrent.QCallback[I, R], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def __init__(self, callback: generic.concurrent.QCallback[I, R], threadPoolName: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def __init__(self, callback: generic.concurrent.QCallback[I, R], pool: generic.concurrent.GThreadPool, collectResults: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        ...

    def add(self, i: I):
        ...

    @typing.overload
    def addAll(self, collection: collections.abc.Sequence):
        ...

    @typing.overload
    def addAll(self, iterator: java.util.Iterator[I]):
        ...

    @typing.overload
    def dispose(self):
        ...

    @typing.overload
    def dispose(self, timeoutSeconds: typing.Union[jpype.JLong, int]):
        """
        Calls dispose on the queue being processed.  Further, the call will block for up to
        ``timeoutSeconds`` while waiting for the queue to finish processing.
        
        :param jpype.JLong or int timeoutSeconds: the number of seconds to wait for the disposed queue to finish
                processing
        """

    def process(self, functions: java.util.Iterator[I], consumer: java.util.function.Consumer[R]):
        """
        Adds all items to the queue for processing.  The results will be passed to the given consumer
        as they are produced.
        
        :param java.util.Iterator[I] functions: the functions to process
        :param java.util.function.Consumer[R] consumer: the results consumer
        """

    def waitForResults(self) -> java.util.Collection[generic.concurrent.QResult[I, R]]:
        """
        Waits for all results to be delivered.  The client is responsible for processing the
        results and handling any exceptions that may have occurred.
        
        :return: all results
        :rtype: java.util.Collection[generic.concurrent.QResult[I, R]]
        :raises java.lang.InterruptedException: if interrupted while waiting
        """

    def waitUntilDone(self):
        """
        Waits for all work to finish. Any exception encountered will trigger all processing to
        stop.  If you wish for the work to continue despite exceptions, then use
        :meth:`waitForResults() <.waitForResults>`.
        
        :raises java.lang.InterruptedException: if interrupted while waiting
        :raises java.lang.Exception: any exception that is encountered while processing items.
        """


class DataTypeDependencyOrderer(java.lang.Object):
    """
    Creates an acyclic dependency list of data types.
    """

    class Entry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dtManager: ghidra.program.model.data.DataTypeManager):
        """
        This constructor starts with an empty DataType list, which can be added to.
        
        :param ghidra.program.model.data.DataTypeManager dtManager: the manager used to extract IDs
        """

    @typing.overload
    def __init__(self, dtManager: ghidra.program.model.data.DataTypeManager, dtlist: java.util.ArrayList[ghidra.program.model.data.DataType]):
        """
        This constructor takes an initial DataType list.
        
        :param ghidra.program.model.data.DataTypeManager dtManager: the manager used to extract IDs
        :param java.util.ArrayList[ghidra.program.model.data.DataType] dtlist: Initial list of DataTypes to order
        """

    def addType(self, dataType: ghidra.program.model.data.DataType):
        """
        This method adds a single DataTypes to the input DataType list and
        marks the data as dirty (all must need recalculated).
        
        :param ghidra.program.model.data.DataType dataType: A single DataType to add to the input DataType list.
        """

    def addTypeList(self, dtlist: java.util.ArrayList[ghidra.program.model.data.DataType]):
        """
        This method adds a list of DataTypes to the input DataType list and
        marks the data as dirty (all must need recalculated).
        
        :param java.util.ArrayList[ghidra.program.model.data.DataType] dtlist: List of DataTypes to add to the input DataType list.
        """

    def clear(self):
        """
        This method clears the input DataType list and
        marks the data as dirty (all must need recalculated).
        """

    def getAcyclicDependencyLists(self) -> generic.stl.Pair[java.util.ArrayList[ghidra.program.model.data.DataType], java.util.ArrayList[ghidra.program.model.data.DataType]]:
        """
        This method returns two lists:
        1) is the set of structs/unions. Intended for outputting zero-sized definitions.
        2) is the acyclic dependency list (broken at composites and pointers to composites)
        This works (and the dependency graph is able to be broken of cycles) because
        composites can be given zero size to start with and then later updated with full size.
        
        :return: pair of arrayLists--one of composites and one complete list of dependents
        :rtype: generic.stl.Pair[java.util.ArrayList[ghidra.program.model.data.DataType], java.util.ArrayList[ghidra.program.model.data.DataType]]
        """

    def getCompositeList(self) -> java.util.ArrayList[ghidra.program.model.data.DataType]:
        """
        This method returns the ArrayList of structs/unions
        
        :return: An arrayList of Composite
        :rtype: java.util.ArrayList[ghidra.program.model.data.DataType]
        """

    def getDependencyList(self) -> java.util.ArrayList[ghidra.program.model.data.DataType]:
        """
        This returns the acyclic dependency list (broken at composites and pointers to composites)
        
        :return: An ArrayList of dependents.
        :rtype: java.util.ArrayList[ghidra.program.model.data.DataType]
        """

    def removeType(self, dataType: ghidra.program.model.data.DataType):
        """
        This method removes a DataType from the list and
        marks the data as dirty (all must need recalculated).
        
        :param ghidra.program.model.data.DataType dataType: The DataType to remove from the input list
        """

    @property
    def acyclicDependencyLists(self) -> generic.stl.Pair[java.util.ArrayList[ghidra.program.model.data.DataType], java.util.ArrayList[ghidra.program.model.data.DataType]]:
        ...

    @property
    def dependencyList(self) -> java.util.ArrayList[ghidra.program.model.data.DataType]:
        ...

    @property
    def compositeList(self) -> java.util.ArrayList[ghidra.program.model.data.DataType]:
        ...



__all__ = ["SearchConstants", "ClipboardType", "DomainObjectService", "SelectionTransferData", "HexLong", "ProgramDropProvider", "Option", "ListingHighlightProvider", "EditFieldNameDialog", "EolComments", "CodeUnitInfoTransferable", "AddressInput", "MemoryBlockUtils", "ColorAndStyle", "XReferenceUtils", "RefRepeatComment", "ByteCopier", "ToolTipUtils", "SymbolInspector", "CodeUnitInfo", "GhidraFileOpenDataFlavorHandlerService", "ImporterDocumentListener", "Permissions", "FunctionXrefsTableModel", "ProcessorInfo", "OptionsEditorPanel", "HelpTopics", "DataTypeNamingUtil", "XReferenceUtil", "OptionsDialog", "AddressSetEditorPanel", "OptionListener", "SelectionTransferable", "CommentTypes", "AddEditDialog", "OptionException", "OptionUtils", "AddressFactoryService", "OptionValidator", "NamespaceUtils", "PseudoFlowProcessor", "PseudoDisassembler", "PseudoCodeUnit", "PseudoData", "PseudoDisassemblerContext", "RepeatInstructionByteTracker", "SymbolPathParser", "PseudoDataComponent", "PseudoInstruction", "SymbolPath", "FileOpenDataFlavorHandler", "GenericHelpTopics", "FileOpenDropHandler", "DecompilerConcurrentQ", "DataTypeDependencyOrderer"]
