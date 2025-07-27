from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.actions
import ghidra.app.context
import ghidra.app.nav
import ghidra.app.plugin.core.navigation
import ghidra.app.services
import ghidra.app.util
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util
import ghidra.util.datastruct
import ghidra.util.table
import ghidra.util.table.actions
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


class LocationReferenceToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[LocationReference, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LocationDescriptor(java.lang.Object):
    """
    A class that 'describes' a :obj:`ProgramLocation`.  The descriptor is also based upon the
    program to which the location belongs and requires the :obj:`PluginTool` to which the
    program belongs.
     
    
    A location descriptor 'knows' how to identify the 'thing' at the given location and how to get
    addresses that reference that 'thing'.  For example, if the program location is based on a
    :obj:`DataType`, then the descriptor knows how to find all places that datatype is applied.
    Alternatively, if the program location is a label in an operand field, then the descriptor
    will provide addresses of places that reference the item to which the label is attached and
    **not** the given location.
     
    
    Location descriptors also 'know' how to highlight the relevant reference points that
    refer to the 'thing' that the descriptor is describing.  For example, if the program location
    is based on a datatype, then all applied datatypes will be highlighted.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...

    def getLabel(self) -> str:
        ...

    def getTypeName(self) -> str:
        """
        Returns a descriptive category name for this location descriptor.  This is used for
        display in a popup menu.
        
        :return: a descriptive category name for this location descriptor
        :rtype: str
        """

    @property
    def typeName(self) -> java.lang.String:
        ...

    @property
    def label(self) -> java.lang.String:
        ...


@typing.type_check_only
class OperandLocationDescriptor(LocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LocationReferenceToFunctionContainingTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[LocationReference, ghidra.program.model.listing.Function]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LocationReferenceContext(java.lang.Object):
    """
    A class to hold context representation for :obj:`LocationReference`s.
    
    
    .. seealso::
    
        | :obj:`LocationReferenceContextBuilder`
    """

    @typing.type_check_only
    class Part(java.lang.Object):
        """
        A class that represents one or more characters within the full text of this context class
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BasicPart(LocationReferenceContext.Part):
        """
        A basic string part that has no decoration
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatchPart(LocationReferenceContext.Part):
        """
        A string part of the overall text of this context that matches client-defined text
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_CONTEXT: typing.Final[LocationReferenceContext]

    @staticmethod
    @typing.overload
    def get(text: typing.Union[java.lang.String, str]) -> LocationReferenceContext:
        """
        A factory method to create a context instance with the given text.  The context created this
        way will have no special HTML formatting applied by :meth:`getBoldMatchingText() <.getBoldMatchingText>`, as no
        matching parts will be defined.
        
        :param java.lang.String or str text: the text
        :return: the context
        :rtype: LocationReferenceContext
        """

    @staticmethod
    @typing.overload
    def get(context: LocationReferenceContext) -> LocationReferenceContext:
        """
        A factory method to provided as a convenience to handle null context objects.
        
        :param LocationReferenceContext context: the context to verify is not null
        :return: the given context or the :obj:`.EMPTY_CONTEXT` if the given context is null
        :rtype: LocationReferenceContext
        """

    def getBoldMatchingText(self) -> str:
        """
        Returns HTML text for this context.  Any matching items embedded in the returned string will
        be bold.
        
        :return: the text
        :rtype: str
        """

    def getDebugText(self) -> str:
        """
        Returns text that is helpful for debugging, such as printing to a console.
        
        :return: the text
        :rtype: str
        """

    def getMatches(self) -> java.util.List[java.lang.String]:
        """
        Returns any sub-strings of this context's overall text that match client-defined input
        
        See the :obj:`LocationReferenceContextBuilder` for how to define matching text pieces
        
        :return: the matching strings
        :rtype: java.util.List[java.lang.String]
        """

    def getPlainText(self) -> str:
        """
        The full plain text of this context.
        
        :return: the text
        :rtype: str
        """

    @property
    def boldMatchingText(self) -> java.lang.String:
        ...

    @property
    def plainText(self) -> java.lang.String:
        ...

    @property
    def matches(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def debugText(self) -> java.lang.String:
        ...


@typing.type_check_only
class LocationReferencesTableModel(ghidra.util.table.AddressBasedTableModel[LocationReference]):
    """
    A table model that shows the same contents as the :obj:`AddressPreviewTableModel`, but will
    also add a references table column when the underlying data contains references.  This model
    uses data provided by a :obj:`LocationDescriptor`, which is contained by the given
    :obj:`LocationReferencesProvider`.
     
    
    This model also adds the functionality for clients to know when the model has finished loading
    and it also allows users to reload the data.
    """

    @typing.type_check_only
    class ContextTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[LocationReference, LocationReference]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ContextCellRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[LocationReference]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class GenericDataTypeProgramLocation(ghidra.program.util.ProgramLocation):
    """
    A class to signal that the ProgramLocation is used for data types and is not really 
    connected to the listing.
    
    
    .. seealso::
    
        | :obj:`GenericDataTypeLocationDescriptor`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class GenericCompositeDataTypeLocationDescriptor(GenericDataTypeLocationDescriptor):
    """
    A data type location descriptor that allows you to represent a location for a member field of a
    data type, such as a composite or an enum
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: GenericCompositeDataTypeProgramLocation, program: ghidra.program.model.listing.Program):
        ...


class FindReferencesToAction(ghidra.app.context.ListingContextAction):
    """
    :obj:`LocationReferencesPlugin`'s action for finding references to a thing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: LocationReferencesPlugin, subGroupPosition: typing.Union[jpype.JInt, int]):
        ...


@typing.type_check_only
class UnionLocationDescriptor(DataTypeLocationDescriptor):
    """
    A location descriptor to find references to a Union data type.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionReturnTypeLocationDescriptor(DataTypeLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LabelLocationDescriptor(LocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VariableTypeLocationDescriptor(DataTypeLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LocationReferenceToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[LocationReference, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AddressLocationDescriptor(LocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FunctionParameterTypeLocationDescriptor(DataTypeLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LocationReferencesPanel(javax.swing.JPanel):
    """
    A panel that contains a table for displaying results of performing a search for references 
    to a given location.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionDefinitionLocationDescriptor(GenericDataTypeLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class StructureMemberLocationDescriptor(LocationDescriptor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memberLocation: ghidra.program.util.ProgramLocation, fieldName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        ...


class LocationReferencesService(java.lang.Object):
    """
    A service that provides a GUI listing of all ***from*** locations that refer 
    to a given ***to*** location.
    """

    class_: typing.ClassVar[java.lang.Class]
    MENU_GROUP: typing.Final = "References"

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for help content that describes this service.
        
        :return: the help location for help content that describes this service.
        :rtype: ghidra.util.HelpLocation
        """

    def showReferencesToLocation(self, location: ghidra.program.util.ProgramLocation, navigatable: ghidra.app.nav.Navigatable):
        """
        Shows a ComponentProvider containing a table of references that refer to the given
        location.
        
        :param ghidra.program.util.ProgramLocation location: The location for which to show references.
        :param ghidra.app.nav.Navigatable navigatable: The navigatable in which the references should be shown
        :raises NullPointerException: if ``location`` is null.
        """

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...


class LocationReferencesPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.plugin.core.navigation.FindAppliedDataTypesService, LocationReferencesService):
    """
    Plugin to show a list of references to the item represented by the location of the cursor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class GenericDataTypeLocationDescriptor(DataTypeLocationDescriptor):
    """
    A LocationDescriptor that is used when the user wants to create a descriptor that describes at
    data type, but not a real location that contains a data type.  Most LocationDescriptors 
    describe an exact point in the listing display.  This descriptor is designed to describe a 
    data type, but does not point to any real position in the display.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocationReferencesProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.framework.model.DomainObjectListener, ghidra.app.nav.NavigatableRemovalListener):
    """
    ComponentProvider for the :obj:`LocationReferencesPlugin`.
    """

    @typing.type_check_only
    class DeleteAction(ghidra.util.table.actions.DeleteTableRowAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Location References Provider"


class GenericCompositeDataTypeProgramLocation(GenericDataTypeProgramLocation):
    """
    A class to signal that the ProgramLocation is used for data types and is not really
    connected to the listing.  This is a subclass is designed for data types that have fields, such
    as :obj:`Composite` types and :obj:`Enum` types.
    
    
    .. seealso::
    
        | :obj:`GenericCompositeDataTypeLocationDescriptor`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFieldMatcher(self) -> ghidra.app.services.FieldMatcher:
        ...

    @property
    def fieldMatcher(self) -> ghidra.app.services.FieldMatcher:
        ...


class LocationReferenceContextBuilder(java.lang.Object):
    """
    A builder for :obj:`LocationReferenceContext` objects.  Use :meth:`append(String) <.append>` for normal
    text pieces.  Use :meth:`appendMatch(String) <.appendMatch>` for text that is meant to be rendered specially
    by the context class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def append(self, text: typing.Union[java.lang.String, str]) -> LocationReferenceContextBuilder:
        """
        Appends the given text to this builder.
        
        :param java.lang.String or str text: the text
        :return: this builder
        :rtype: LocationReferenceContextBuilder
        """

    def appendMatch(self, text: typing.Union[java.lang.String, str]) -> LocationReferenceContextBuilder:
        """
        Appends the given text to this builder.   This text represents a client-defined 'match' that
        will be rendered with markup when :meth:`LocationReferenceContext.getBoldMatchingText() <LocationReferenceContext.getBoldMatchingText>` is
        called.
        
        :param java.lang.String or str text: the text
        :return: this builder
        :rtype: LocationReferenceContextBuilder
        """

    def build(self) -> LocationReferenceContext:
        """
        Builds a :obj:`LocationReferenceContext` using the text supplied via the ``append``
        methods.
        
        :return: the context
        :rtype: LocationReferenceContext
        """

    def isEmpty(self) -> bool:
        """
        Returns true if no text has been added to this builder.
        
        :return: true if no text has been added to this builder
        :rtype: bool
        """

    def newline(self) -> LocationReferenceContextBuilder:
        """
        Adds a newline character to the previously added text.
        
        :return: this builder
        :rtype: LocationReferenceContextBuilder
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class VariableXRefLocationDescriptor(XRefLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VariableNameLocationDescriptor(FunctionParameterNameLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MnemonicLocationDescriptor(DataTypeLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LocationReferencesHighlighter(java.lang.Object):
    """
    Handles highlighting for :obj:`LocationReferencesProvider`.
    """

    @typing.type_check_only
    class LocationReferencesHighlightProvider(ghidra.app.util.ListingHighlightProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MarkerRemover(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class XRefLocationDescriptor(LocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FindReferencesToAddressAction(ghidra.app.actions.AbstractFindReferencesToAddressAction):
    """
    Only shows addresses to the code unit at the address for the current context.  This differs
    from the normal 'find references' action in that it will find references by inspecting 
    context for more information, potentially searching for more than just direct references to 
    the code unit at the current address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: LocationReferencesPlugin, subGroupPosition: typing.Union[jpype.JInt, int]):
        ...


@typing.type_check_only
class DataTypeLocationDescriptor(LocationDescriptor):
    """
    A location descriptor that should be extended by location descriptor implementations that are
    based upon data types.
    """

    class_: typing.ClassVar[java.lang.Class]


class LocationReference(java.lang.Comparable[LocationReference]):
    """
    A simple container object to provide clients with a reference and an address when both are
    available.  If no reference exists, then only the :meth:`getLocationOfUse() <.getLocationOfUse>` address is
    available.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getContext(self) -> LocationReferenceContext:
        """
        Returns the context associated with this location.  The context may be a simple plain string
        or may be String that highlights part of a function signature the location matches or
        a line from the Decompiler that matches.
        
        :return: the context
        :rtype: LocationReferenceContext
        """

    def getLocationOfUse(self) -> ghidra.program.model.address.Address:
        """
        Returns the address where the item described by this object is used.  For example, for
        data types, the address is where a data type is applied; for references, this value is the
        ``from`` address.
        
        :return: the address where the item described by this object is used.
        :rtype: ghidra.program.model.address.Address
        """

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the program location associated with this reference; may be null.
        
        :return: the program location associated with this reference; may be null.
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getRefTypeString(self) -> str:
        """
        Returns the type of reference
        
        :return: type of reference or empty string if unknown
        :rtype: str
        """

    def isOffcutReference(self) -> bool:
        """
        Returns true if the corresponding reference is to an offcut address
        
        :return: true if offcut
        :rtype: bool
        """

    @property
    def context(self) -> LocationReferenceContext:
        ...

    @property
    def locationOfUse(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def offcutReference(self) -> jpype.JBoolean:
        ...

    @property
    def refTypeString(self) -> java.lang.String:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


@typing.type_check_only
class FunctionParameterNameLocationDescriptor(FunctionSignatureFieldLocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ReferenceUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def findDataTypeFieldReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], fieldMatcher: ghidra.app.services.FieldMatcher, program: ghidra.program.model.listing.Program, discoverTypes: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Returns all references (locations) that use the given datatype.
         
        
        **Note: ** This method call may take a long time, as it must search all of the data
        within the program and may also perform long running tasks, like decompiling every function
        in the program.
         
        
        The supplied field matcher will be used to restrict matches to the given field.  The matcher
        may be 'empty', supplying only the data type for which to search.  In this case, all uses
        of the type will be matched, regardless of field.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results storage.
        :param ghidra.app.services.FieldMatcher fieldMatcher: the field matcher.
        :param ghidra.program.model.listing.Program program: The program from within which to find references.
        :param jpype.JBoolean or bool discoverTypes: if true, the :obj:`DataTypeReferenceFinder` service will be used to
        search for data types that are not applied in memory.  Using the service will be slower, but
        will recover type usage that could not be found by examining the Listing.
        :param ghidra.util.task.TaskMonitor monitor: A task monitor to be updated as data is searched; if this is null, then a
                dummy monitor will be used.
        :raises CancelledException: if the monitor is cancelled.
        """

    @staticmethod
    def findDataTypeMatchesInDefinedData(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], program: ghidra.program.model.listing.Program, dataMatcher: java.util.function.Predicate[ghidra.program.model.listing.Data], fieldMatcher: ghidra.app.services.FieldMatcher, monitor: ghidra.util.task.TaskMonitor):
        """
        Searches defined data for types that match, according to the given predicate.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results accumulator
        :param ghidra.program.model.listing.Program program: the program
        :param java.util.function.Predicate[ghidra.program.model.listing.Data] dataMatcher: the predicate that determines a successful match
        :param ghidra.app.services.FieldMatcher fieldMatcher: the field matcher; will be ignored if it contains null values
        :param ghidra.util.task.TaskMonitor monitor: the task monitor used to track progress and cancel the work
        :raises CancelledException: if the operation was cancelled
        """

    @staticmethod
    @typing.overload
    @deprecated("use findDataTypeFieldReferences(Accumulator, FieldMatcher, Program,\n boolean, TaskMonitor).")
    def findDataTypeReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        """
        Returns all references (locations) that use the given datatype.
         
        
        **Note: ** This method call may take a long time, as it must search all of the data
        within the program and may also perform long running tasks, like decompiling every function
        in the program.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results storage.
        :param ghidra.program.model.data.DataType dataType: The datatype for which to find references.
        :param java.lang.String or str fieldName: optional field name for which to search; the ``dataType`` must be a
        :obj:`Composite` to search for a field.
        :param ghidra.program.model.listing.Program program: The program from within which to find references.
        :param ghidra.util.task.TaskMonitor monitor: A task monitor to be updated as data is searched; if this is null, then a
        dummy monitor will be used.
        :raises CancelledException: if the monitor is cancelled.
        
        .. deprecated::
        
        use :meth:`findDataTypeFieldReferences(Accumulator, FieldMatcher, Program,
        boolean, TaskMonitor) <.findDataTypeFieldReferences>`.
        """

    @staticmethod
    @typing.overload
    @deprecated("use findDataTypeFieldReferences(Accumulator, FieldMatcher, Program,\n boolean, TaskMonitor).")
    def findDataTypeReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, discoverTypes: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Returns all references (locations) that use the given datatype.
         
        
        **Note: ** This method call may take a long time, as it must search all of the data
        within the program and may also perform long running tasks, like decompiling every function
        in the program.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results storage.
        :param ghidra.program.model.data.DataType dataType: The datatype for which to find references.
        :param java.lang.String or str fieldName: optional field name for which to search; the ``dataType`` must be a
        :obj:`Composite` to search for a field.
        :param ghidra.program.model.listing.Program program: The program from within which to find references.
        :param jpype.JBoolean or bool discoverTypes: if true, the :obj:`DataTypeReferenceFinder` service will be used to
        search for data types that are not applied in memory.  Using the service will be slower, but
        will recover type usage that could not be found by examining the Listing.
        :param ghidra.util.task.TaskMonitor monitor: A task monitor to be updated as data is searched; if this is null, then a
        dummy monitor will be used.
        :raises CancelledException: if the monitor is cancelled.
        
        .. deprecated::
        
        use :meth:`findDataTypeFieldReferences(Accumulator, FieldMatcher, Program,
        boolean, TaskMonitor) <.findDataTypeFieldReferences>`.
        """

    @staticmethod
    @typing.overload
    def findDataTypeReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program, discoverTypes: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Returns all references (locations) that use the given datatype.
         
        
        **Note: ** This method call may take a long time, as it must search all of the data
        within the program and may also perform long running tasks, like decompiling every function
        in the program.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results storage.
        :param ghidra.program.model.data.DataType dataType: The datatype for which to find references.
        :param ghidra.program.model.listing.Program program: The program from within which to find references.
        :param jpype.JBoolean or bool discoverTypes: if true, the :obj:`DataTypeReferenceFinder` service will be used to
        search for data types that are not applied in memory.  Using the service will be slower, but
        will recover type usage that could not be found by examining the Listing.
        :param ghidra.util.task.TaskMonitor monitor: A task monitor to be updated as data is searched; if this is null, then a
                dummy monitor will be used.
        :raises CancelledException: if the monitor is cancelled.
        """

    @staticmethod
    @typing.overload
    def getBaseDataType(dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        A recursive function to get the base highest level data type for the given data type.  For
        example, if the give data type is an :obj:`Array`, then this
        method will be called again on its data type.
         
        
        It is not always appropriate to find the base data type. This method contains the
        logic for determining when it is appropriate the seek out the
        base data type, as in the case of an Array object.
        
        :param ghidra.program.model.data.DataType dataType: The data type for which to find the highest level data type.
        :return: The highest level data type for the given data type.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    @typing.overload
    def getBaseDataType(dataType: ghidra.program.model.data.DataType, includeTypedefs: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.DataType:
        """
        A recursive function to get the base highest level data type for the given data type.  For
        example, if the give data type is an :obj:`Array`, then this
        method will be called again on its data type.
         
        
        It is not always appropriate to find the base data type. This method contains the
        logic for determining when it is appropriate the seek out the
        base data type, as in the case of an Array object.
        
        :param ghidra.program.model.data.DataType dataType: The data type for which to find the highest level data type
        :param jpype.JBoolean or bool includeTypedefs: if true, then Typedef data types will be replaced with their base
                data type
        :return: The highest level data type for the given data type
        :rtype: ghidra.program.model.data.DataType
        
        .. seealso::
        
            | :obj:`.getBaseDataType(DataType)`
        """

    @staticmethod
    def getLocationDescriptor(location: ghidra.program.util.ProgramLocation) -> LocationDescriptor:
        """
        Creates a LocationDescriptor for the given location
        
        :param ghidra.program.util.ProgramLocation location: The program location for which to get a descriptor
        :return: a LocationDescriptor for the given location
        :rtype: LocationDescriptor
        """

    @staticmethod
    def getReferenceAddresses(location: ghidra.program.util.ProgramLocation, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[ghidra.program.model.address.Address]:
        """
        Returns a set references to the given address.
        
        :param ghidra.program.util.ProgramLocation location: the location for which to find references
        :param ghidra.util.task.TaskMonitor monitor: the task monitor used to track progress and cancel the work
        :return: A set of addresses or an empty set if there are no references.
        :rtype: java.util.Set[ghidra.program.model.address.Address]
        :raises CancelledException: if the operation was cancelled
        """

    @staticmethod
    def getReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], location: ghidra.program.util.ProgramLocation, monitor: ghidra.util.task.TaskMonitor):
        """
        Returns addresses that reference the item at the given location.
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: The Accumulator into which LocationReferences will be placed.
        :param ghidra.program.util.ProgramLocation location: The location for which to find references
        :param ghidra.util.task.TaskMonitor monitor: the task monitor used to track progress and cancel the work
        :raises CancelledException: if the operation was cancelled
        """

    @staticmethod
    def getVariableReferences(accumulator: ghidra.util.datastruct.Accumulator[LocationReference], program: ghidra.program.model.listing.Program, variable: ghidra.program.model.listing.Variable):
        """
        Returns all references to the given variable
        
        :param ghidra.util.datastruct.Accumulator[LocationReference] accumulator: the results accumulator
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.listing.Variable variable: the variable
        """

    @staticmethod
    def getVariables(function: ghidra.program.model.listing.Function, localsOnly: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.model.listing.Variable]:
        """
        Gets all variables for the given function including all parameters and local variables.
        
        :param ghidra.program.model.listing.Function function: The function from which to get the variables
        :param jpype.JBoolean or bool localsOnly: true signals to return only local variables (not parameters); false
                will return parameters and local variables
        :return: A list of Variable objects.
        :rtype: java.util.List[ghidra.program.model.listing.Variable]
        :raises NullPointerException: if the function is null.
        """

    @staticmethod
    def isOffcut(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the given address does not point to the minimum address of the containing
        :obj:`CodeUnit`.
        
        :param ghidra.program.model.listing.Program program: the program containing the address
        :param ghidra.program.model.address.Address address: the address to check
        :return: true if the address is offcut
        :rtype: bool
        """


@typing.type_check_only
class FunctionSignatureFieldLocationDescriptor(LocationDescriptor):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["LocationReferenceToAddressTableRowMapper", "LocationDescriptor", "OperandLocationDescriptor", "LocationReferenceToFunctionContainingTableRowMapper", "LocationReferenceContext", "LocationReferencesTableModel", "GenericDataTypeProgramLocation", "GenericCompositeDataTypeLocationDescriptor", "FindReferencesToAction", "UnionLocationDescriptor", "FunctionReturnTypeLocationDescriptor", "LabelLocationDescriptor", "VariableTypeLocationDescriptor", "LocationReferenceToProgramLocationTableRowMapper", "AddressLocationDescriptor", "FunctionParameterTypeLocationDescriptor", "LocationReferencesPanel", "FunctionDefinitionLocationDescriptor", "StructureMemberLocationDescriptor", "LocationReferencesService", "LocationReferencesPlugin", "GenericDataTypeLocationDescriptor", "LocationReferencesProvider", "GenericCompositeDataTypeProgramLocation", "LocationReferenceContextBuilder", "VariableXRefLocationDescriptor", "VariableNameLocationDescriptor", "MnemonicLocationDescriptor", "LocationReferencesHighlighter", "XRefLocationDescriptor", "FindReferencesToAddressAction", "DataTypeLocationDescriptor", "LocationReference", "FunctionParameterNameLocationDescriptor", "ReferenceUtils", "FunctionSignatureFieldLocationDescriptor"]
