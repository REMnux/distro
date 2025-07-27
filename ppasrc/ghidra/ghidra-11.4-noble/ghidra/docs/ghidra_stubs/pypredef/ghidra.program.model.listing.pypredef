from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.app.util.template
import ghidra.docking.settings
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.reloc
import ghidra.program.model.scalar
import ghidra.program.model.sourcemap
import ghidra.program.model.symbol
import ghidra.program.model.util
import ghidra.program.util
import ghidra.util.exception
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class CodeUnitFormat(java.lang.Object):

    @typing.type_check_only
    class InstructionScalarInfo(java.lang.Object):
        """
        A simple class to find the scalars and addresses in the operand
        representation list and to keep track of whether to process a scalar with
        a zero value.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EXTENDED_REFERENCE_DELIMITER: typing.ClassVar[java.lang.String]
    EXTENDED_INDIRECT_REFERENCE_DELIMITER: typing.ClassVar[java.lang.String]
    DEFAULT: typing.ClassVar[CodeUnitFormat]
    """
    Default code unit format
    """


    @typing.overload
    def __init__(self, showBlockName: CodeUnitFormatOptions.ShowBlockName, showNamespace: CodeUnitFormatOptions.ShowNamespace):
        """
        Format constructor.
        
        :param CodeUnitFormatOptions.ShowBlockName showBlockName: whether or not to display block name;
                    {SHOW_BLOCKNAME_ALWAYS, SHOW_BLOCKNAME_NEVER,
                    SHOW_SEGMENT_NON_LOCAL}
        :param CodeUnitFormatOptions.ShowNamespace showNamespace: if true display labels with their name-space path.
        """

    @typing.overload
    def __init__(self, options: CodeUnitFormatOptions):
        """
        Format constructor with more options. Extended reference mark-up is
        enabled.
        
        :param CodeUnitFormatOptions options: format options
        """

    def getDataValueRepresentation(self, data: Data) -> OperandRepresentationList:
        """
        Returns a formatted data value for the specified data unit. The return
        list will contain a single object which may be an instance of String,
        LabelString, Address, Scalar or Equate
        
        :param Data data: data unit
        :return: representation list containing a single object.
        :rtype: OperandRepresentationList
        """

    def getDataValueRepresentationString(self, data: Data) -> str:
        """
        Returns a formatted data value for the specified data unit.
        
        :param Data data: data unit
        :return: data value string
        :rtype: str
        """

    def getMnemonicRepresentation(self, cu: CodeUnit) -> str:
        """
        Returns a formatted code unit mnemonic
        
        :param CodeUnit cu: code unit
        :return: mnemonic representation
        :rtype: str
        """

    def getOffcutLabelString(self, offcutAddress: ghidra.program.model.address.Address, cu: CodeUnit, markupAddress: ghidra.program.model.address.Address) -> str:
        ...

    def getOperandRepresentationList(self, cu: CodeUnit, opIndex: typing.Union[jpype.JInt, int]) -> OperandRepresentationList:
        """
        Returns a formatted list of operand objects for the specified code unit
        operand. In the case of Data opIndex=1, this will be a list containing a
        single String object (see getDataValueRepresentation(Data)). In the case
        of an Instruction, the list will contain a list of Objects, including any
        combination of Character, String, VariableOffset, Register, Address,
        Scalar, List, LabelString etc.. All objects returned must support the
        toString() method.
        
        :param CodeUnit cu: code unit
        :param jpype.JInt or int opIndex: operand index
        :return: list of representation objects or null for an unsupported
                language.
        :rtype: OperandRepresentationList
        """

    def getOperandRepresentationString(self, cu: CodeUnit, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns a formatted string representation of the specified code unit
        operand.
        
        :param CodeUnit cu: code unit
        :param jpype.JInt or int opIndex: 
        :return: formatted code unit representation
        :rtype: str
        """

    def getReferenceRepresentationString(self, fromCodeUnit: CodeUnit, ref: ghidra.program.model.symbol.Reference) -> str:
        """
        Returns a marked-up representation of the reference destination.
        
        :param CodeUnit fromCodeUnit: 
        :param ghidra.program.model.symbol.Reference ref: 
        :return: destination as a string or null if a suitable string could not be
                produced.
        :rtype: str
        """

    @typing.overload
    def getRepresentationString(self, cu: CodeUnit) -> str:
        """
        Returns a formatted string representation of the specified code unit,
        including mnemonic and operand(s) only.
        
        :param CodeUnit cu: code unit
        :return: formatted code unit representation
        :rtype: str
        """

    @typing.overload
    def getRepresentationString(self, cu: CodeUnit, includeEOLcomment: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a formatted string representation of the specified code unit
        mnemonic and operand(s).
        
        :param CodeUnit cu: code unit
        :param jpype.JBoolean or bool includeEOLcomment: if true EOL comment will be appended to code
                    unit representation
        :return: formatted code unit representation
        :rtype: str
        """

    def getShowBlockName(self) -> CodeUnitFormatOptions.ShowBlockName:
        """
        Returns ShowBlockName setting
        """

    @property
    def showBlockName(self) -> CodeUnitFormatOptions.ShowBlockName:
        ...

    @property
    def representationString(self) -> java.lang.String:
        ...

    @property
    def dataValueRepresentationString(self) -> java.lang.String:
        ...

    @property
    def dataValueRepresentation(self) -> OperandRepresentationList:
        ...

    @property
    def mnemonicRepresentation(self) -> java.lang.String:
        ...


class CodeUnitFormatOptions(java.lang.Object):

    class ShowBlockName(java.lang.Enum[CodeUnitFormatOptions.ShowBlockName]):
        """
        ``ShowBlockName`` defines the valid options for
        controlling the display of block names on labels.
        """

        class_: typing.ClassVar[java.lang.Class]
        NEVER: typing.Final[CodeUnitFormatOptions.ShowBlockName]
        """
        Indicator to never the show block name in an address, label, or operand
        representation.
        """

        ALWAYS: typing.Final[CodeUnitFormatOptions.ShowBlockName]
        """
        Indicator to show the block name in all address, label, or operand
        representations.
        """

        NON_LOCAL: typing.Final[CodeUnitFormatOptions.ShowBlockName]
        """
        Indicator to show the block name in address, label, or operand
        representations which are not contained within the current block.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CodeUnitFormatOptions.ShowBlockName:
            ...

        @staticmethod
        def values() -> jpype.JArray[CodeUnitFormatOptions.ShowBlockName]:
            ...


    class ShowNamespace(java.lang.Enum[CodeUnitFormatOptions.ShowNamespace]):
        """
        ``ShowNamespace`` defines the valid options for
        controlling the display of name-spaces on labels.
        """

        class_: typing.ClassVar[java.lang.Class]
        NEVER: typing.Final[CodeUnitFormatOptions.ShowNamespace]
        """
        Indicator to never the show namespace for a label reference.
        """

        ALWAYS: typing.Final[CodeUnitFormatOptions.ShowNamespace]
        """
        Indicator to always show namespace for a label reference..
        """

        NON_LOCAL: typing.Final[CodeUnitFormatOptions.ShowNamespace]
        """
        Indicator to show namespace for a label reference if the label is in a 
        different namespace from the referenced location.
        """

        LOCAL: typing.Final[CodeUnitFormatOptions.ShowNamespace]
        """
        Indicator to show namespace for a label reference if the label is in the
        same namespace as the reference location (i.e., local to function).
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> CodeUnitFormatOptions.ShowNamespace:
            ...

        @staticmethod
        def values() -> jpype.JArray[CodeUnitFormatOptions.ShowNamespace]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, showBlockName: CodeUnitFormatOptions.ShowBlockName, showNamespace: CodeUnitFormatOptions.ShowNamespace):
        """
        Format options constructor using primarily default format options.
        
        :param CodeUnitFormatOptions.ShowBlockName showBlockName: controls display of block name in address representations.
        :param CodeUnitFormatOptions.ShowNamespace showNamespace: controls display of namespace path with label references.
        """

    @typing.overload
    def __init__(self, showBlockName: CodeUnitFormatOptions.ShowBlockName, showNamespace: CodeUnitFormatOptions.ShowNamespace, localPrefixOverride: typing.Union[java.lang.String, str], doRegVariableMarkup: typing.Union[jpype.JBoolean, bool], doStackVariableMarkup: typing.Union[jpype.JBoolean, bool], includeInferredVariableMarkup: typing.Union[jpype.JBoolean, bool], alwaysShowPrimaryReference: typing.Union[jpype.JBoolean, bool], includeScalarReferenceAdjustment: typing.Union[jpype.JBoolean, bool], showLibraryInNamespace: typing.Union[jpype.JBoolean, bool], followReferencedPointers: typing.Union[jpype.JBoolean, bool], templateSimplifier: ghidra.app.util.template.TemplateSimplifier):
        """
        Format options constructor.  Extended reference mark-up is enabled.
        
        :param CodeUnitFormatOptions.ShowBlockName showBlockName: controls display of block name in address representations.
        :param CodeUnitFormatOptions.ShowNamespace showNamespace: controls display of namespace path with label references.
        :param java.lang.String or str localPrefixOverride: optional override for local name-space when showNamespace
        is ShowNamespace.LOCAL or ShowNamespace.ALWAYS.  Specifying a null value
        will cause the actual name-space to be used.
        :param jpype.JBoolean or bool doRegVariableMarkup: perform register variable/reference mark-up if true
        :param jpype.JBoolean or bool doStackVariableMarkup: perform stack variable/reference mark-up if true
        :param jpype.JBoolean or bool includeInferredVariableMarkup: if true and doRegVariableMarkup is also true, an attempt
        will be made to mark-up inferred register variable usage.
        :param jpype.JBoolean or bool alwaysShowPrimaryReference: if true forces the primary reference to be rendered with
        the operand using the => separator if necessary
        :param jpype.JBoolean or bool includeScalarReferenceAdjustment: if true scalar adjustment of certain reference offsets
        will be included to maintain replaced scalar value
        :param jpype.JBoolean or bool showLibraryInNamespace: if true any referenced external symbols will include 
        library name
        :param jpype.JBoolean or bool followReferencedPointers: if true referenced pointers (read or indirect) will
        follow the pointer and display the indirect symbol with -> instead of pointer label.
        """

    def getShowBlockNameOption(self) -> CodeUnitFormatOptions.ShowBlockName:
        """
        Get current ShowBlockName option
        
        :return: ShowBlockName option
        :rtype: CodeUnitFormatOptions.ShowBlockName
        """

    def simplifyTemplate(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    @property
    def showBlockNameOption(self) -> CodeUnitFormatOptions.ShowBlockName:
        ...


class AddressChangeSet(ghidra.framework.model.ChangeSet):
    """
    Interface for an Address Change set.  Objects that implements this interface track
    various change information on a set of addresses where the program has changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Adds the address set to the set addresses where changes occurred.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the set of addresses to add as changes.
        """

    def addRange(self, addr1: ghidra.program.model.address.Address, addr2: ghidra.program.model.address.Address):
        """
        Adds the range of addresses to the set addresses where changes occurred.
        
        :param ghidra.program.model.address.Address addr1: the first address in the range
        :param ghidra.program.model.address.Address addr2: the last address in the range. (inclusive)
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address set of all addresses where the listing has changed.
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...


class AutoParameterType(java.lang.Enum[AutoParameterType]):
    """
    ``AutoParameterType`` defines the various
    types of auto-parameters.
    """

    class_: typing.ClassVar[java.lang.Class]
    THIS: typing.Final[AutoParameterType]
    """
    ``THIS`` corresponds to the object pointer parameter associated
    with a __thiscall calling convention and passed as a hidden parameter
    """

    RETURN_STORAGE_PTR: typing.Final[AutoParameterType]
    """
    ``RETURN_STORAGE_PTR`` corresponds to a caller allocated return
    storage pointer passed as a hidden parameter
    """


    def getDisplayName(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AutoParameterType:
        ...

    @staticmethod
    def values() -> jpype.JArray[AutoParameterType]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...


class Library(ghidra.program.model.symbol.Namespace):
    """
    Interface for a Library namespace.
    """

    class_: typing.ClassVar[java.lang.Class]
    UNKNOWN: typing.Final = "<EXTERNAL>"

    def getAssociatedProgramPath(self) -> str:
        """
        
        
        :return: the associated program within the project which corresponds to this library
        :rtype: str
        """

    @property
    def associatedProgramPath(self) -> java.lang.String:
        ...


class FunctionTagChangeSet(ghidra.framework.model.ChangeSet):
    """
    Defines a Function Tag Change set.  This is meant to track changes that
    are made to :obj:`FunctionTag` objects in a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getTagChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns a list of all tag ids that have been changed (edited/deleted).
        
        :return: the list of tag ids (from :obj:`FunctionTagAdapter <ghidra.program.database.function.FunctionTagAdapter>`)
        :rtype: jpype.JArray[jpype.JLong]
        """

    def getTagCreations(self) -> jpype.JArray[jpype.JLong]:
        """
        Returns a list of all tag ids that have been created.
        
        :return: the list of tag ids (from :obj:`FunctionTagAdapter <ghidra.program.database.function.FunctionTagAdapter>`)
        :rtype: jpype.JArray[jpype.JLong]
        """

    def tagChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        Indicates that a tag has been changed (edited/deleted).
        
        :param jpype.JLong or int id: the id of the tag (from :obj:`FunctionTagAdapter <ghidra.program.database.function.FunctionTagAdapter>`)
        """

    def tagCreated(self, id: typing.Union[jpype.JLong, int]):
        """
        Indicates that a tag has been created.
        
        :param jpype.JLong or int id: the id of the tag (from :obj:`FunctionTagAdapter <ghidra.program.database.function.FunctionTagAdapter>`)
        """

    @property
    def tagCreations(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def tagChanges(self) -> jpype.JArray[jpype.JLong]:
        ...


class BookmarkType(java.lang.Object):
    """
    Interface for bookmark types.
    """

    class_: typing.ClassVar[java.lang.Class]
    NOTE: typing.Final = "Note"
    INFO: typing.Final = "Info"
    ERROR: typing.Final = "Error"
    WARNING: typing.Final = "Warning"
    ANALYSIS: typing.Final = "Analysis"

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns Icon associated with this type or null if one has not been 
        set by a plugin.
        
        :return: the icon.
        :rtype: javax.swing.Icon
        """

    def getMarkerColor(self) -> java.awt.Color:
        """
        Returns marker color associated with this type or null if one has not been 
        set by a plugin.
        
        :return: the color.
        :rtype: java.awt.Color
        """

    def getMarkerPriority(self) -> int:
        """
        Returns marker priority associated with this type or -1 if one has not been 
        set by a plugin.
        
        :return: the priority.
        :rtype: int
        """

    def getTypeId(self) -> int:
        """
        Returns the id associated with this bookmark type.
        
        :return: the id associated with this bookmark type.
        :rtype: int
        """

    def getTypeString(self) -> str:
        """
        Returns the type as a string.
        
        :return: the type as a string.
        :rtype: str
        """

    def hasBookmarks(self) -> bool:
        """
        Returns true if there is at least one bookmark defined for this type.
        
        :return: true if there is at least one bookmark defined for this type.
        :rtype: bool
        """

    @property
    def markerPriority(self) -> jpype.JInt:
        ...

    @property
    def markerColor(self) -> java.awt.Color:
        ...

    @property
    def typeString(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def typeId(self) -> jpype.JInt:
        ...


class InstructionIterator(java.util.Iterator[Instruction], java.lang.Iterable[Instruction]):
    """
    Interface to define an iterator over some set of instructions.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasNext(self) -> bool:
        """
        Returns true if the iteration has more elements.
        """

    def next(self) -> Instruction:
        """
        Return the next instruction in the iteration.
        """


class AutoParameterImpl(ParameterImpl):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: ghidra.program.model.data.DataType, ordinal: typing.Union[jpype.JInt, int], storage: VariableStorage, function: Function):
        ...


class VariableSizeException(ghidra.util.exception.InvalidInputException):
    """
    ``VariableSizeException`` is thrown when a variable
    data-type exceeds storage constraints.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor.
        The canForce value is assumed to be false.
        
        :param java.lang.String or str msg: message text
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], canForce: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor.
        
        :param java.lang.String or str msg: message text
        :param jpype.JBoolean or bool canForce: if true conveys to the user that the operation may
        be successful if forced.
        """

    def canForce(self) -> bool:
        """
        Returns true if the operation could be successful if forced.
        """


class Data(CodeUnit, ghidra.docking.settings.Settings):
    """
    Interface for interacting with data at an address in a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addValueReference(self, refAddr: ghidra.program.model.address.Address, type: ghidra.program.model.symbol.RefType):
        """
        Add a memory reference to the value.
        
        :param ghidra.program.model.address.Address refAddr: address referenced.
        :param ghidra.program.model.symbol.RefType type: the type of reference to be added.
        """

    def getBaseDataType(self) -> ghidra.program.model.data.DataType:
        """
        If the dataType is a typeDef, then the typeDef's base type is returned, otherwise, the
        datatType is returned.
        
        :return: the data type
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getComponent(self, index: typing.Union[jpype.JInt, int]) -> Data:
        """
        Returns the immediate n'th component or null if none exists.
        
        :param jpype.JInt or int index: the index of the component to get.
        :return: the component
        :rtype: Data
        """

    @typing.overload
    def getComponent(self, componentPath: jpype.JArray[jpype.JInt]) -> Data:
        """
        Get a data item given  the index path. Each integer in the array represents an index into
        the data item at that level.
        
        :param jpype.JArray[jpype.JInt] componentPath: the array of indexes to use to find the requested data item.
        :return: the component
        :rtype: Data
        """

    @deprecated("method name has been changed to better reflect behavior.  The method\n getComponentContaining(int) should be used instead.")
    def getComponentAt(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Return the first immediate child component that contains the byte at the given offset.  It
        is important to note that with certain datatypes there may be more than one component
        containing the specified offset (see :meth:`getComponentsContaining(int) <.getComponentsContaining>`).
        
        :param jpype.JInt or int offset: the amount to add to this data items address to get the address of the
        requested data item.
        :return: first data component containing offset or null
        :rtype: Data
        
        .. deprecated::
        
        method name has been changed to better reflect behavior.  The method
        :meth:`getComponentContaining(int) <.getComponentContaining>` should be used instead.
        """

    def getComponentContaining(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Return the first immediate child component that contains the byte at the given offset.  It
        is important to note that with certain datatypes there may be more than one component
        containing the specified offset (see :meth:`getComponentsContaining(int) <.getComponentsContaining>`).
        
        :param jpype.JInt or int offset: the amount to add to this data items address to get the
        :return: first data component containing offset or null address of the requested data item.
        :rtype: Data
        """

    def getComponentIndex(self) -> int:
        """
        Get the index of this component in its parent
        
        :return: -1 if this data item is not a component of another data item.
        :rtype: int
        """

    def getComponentLevel(self) -> int:
        """
        Get this data's component level in its hierarchy of components.
        
        :return: the level of this data item with 0 being the level of top data items.
        :rtype: int
        """

    def getComponentPath(self) -> jpype.JArray[jpype.JInt]:
        """
        Get the component path if this is a component. The component path is an array of integers
        that represent each index in the tree of data items. Top level data items have an empty
        array for their component path.
        
        :return: the path
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getComponentPathName(self) -> str:
        """
        Returns the component path name (dot notation) for this field
        
        :return: the component path name
        :rtype: str
        """

    def getComponentsContaining(self, offset: typing.Union[jpype.JInt, int]) -> java.util.List[Data]:
        """
        Returns a list of all the immediate child components that contain the byte at the
        given offset.
         
        
        For a union, this will return all the components (if the offset is 0).  The presence of bit-fields
        or zero-length components may cause multiple components to be returned.
        
        :param jpype.JInt or int offset: the amount to add to this data items address to get the
        address of the requested data item.
        :return: a list of all the immediate child components that contain the byte at the
        given offset or null if offset is out of bounds.
        :rtype: java.util.List[Data]
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the Data type for the data.
        
        :return: the data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getDefaultLabelPrefix(self, options: ghidra.program.model.data.DataTypeDisplayOptions) -> str:
        """
        Returns the appropriate string to use as the default label prefix or null if it has no
        preferred default label prefix;
        
        :param ghidra.program.model.data.DataTypeDisplayOptions options: the options
        :return: the prefix
        :rtype: str
        """

    def getDefaultValueRepresentation(self) -> str:
        """
        Returns a string that represents the data value without markup.
        
        :return: the string
        :rtype: str
        """

    def getFieldName(self) -> str:
        """
        Get the field name of this data item if it is "inside" another data item, otherwise return
        null.
        
        :return: the name of this data as known from some parent data item or
                null if this data item is not a component of another data item.
        :rtype: str
        """

    def getNumComponents(self) -> int:
        """
        Return the number of components that make up this data item.
        if this is an Array, return the number of elements in the array.
        
        :return: the number of components
        :rtype: int
        """

    def getParent(self) -> Data:
        """
        Get the immediate parent data item of this data item or null if this data item is not
        contained in another data item.
        
        :return: the data
        :rtype: Data
        """

    def getParentOffset(self) -> int:
        """
        Get the offset of this Data item from the start of its immediate parent.
        
        :return: the offset
        :rtype: int
        """

    def getPathName(self) -> str:
        """
        Returns the full path name (dot notation) for this field.  This includes the symbol name at
        this address.
        
        :return: the path name
        :rtype: str
        """

    def getPrimitiveAt(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Returns the primitive component containing this offset (i.e., one that does not
        have sub-components).  This is useful for data items which are made up of multiple
        layers of other data items. This method immediately goes to the lowest level data item.
        If the minimum offset of a component is specified, the only first component containing
        the offset will be considered (e.g., 0-element array).
        
        :param jpype.JInt or int offset: the offset
        :return: primitive component containing this offset
        :rtype: Data
        """

    def getRoot(self) -> Data:
        """
        Get the highest level Data item in a hierarchy of structures containing this component.
        
        :return: the data
        :rtype: Data
        """

    def getRootOffset(self) -> int:
        """
        Get the offset of this Data item from the start of the root data item of some hierarchy of
        structures.
        
        :return: the offset
        :rtype: int
        """

    def getValue(self) -> java.lang.Object:
        """
        Returns the value of the data item.  The value may be an address, a scalar,
        register or null if no value.
        
        :return: the value
        :rtype: java.lang.Object
        """

    def getValueClass(self) -> java.lang.Class[typing.Any]:
        """
        Get the class used to express the value of this data.
        
         
        NOTE: This determination is made based upon data type and settings only and does not
        examine memory bytes which are used to construct the data value object.
        
        :return: value class or null if a consistent class is not utilized.
        :rtype: java.lang.Class[typing.Any]
        """

    def getValueReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get the references for the value.
        
        :return: the references
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    def hasStringValue(self) -> bool:
        """
        Returns true if this data corresponds to string data.  This is determined
        by the corresponding data type producing a String value.
        
        :return: true if this data returns a String value and can be treated as string data.
        :rtype: bool
        """

    def isArray(self) -> bool:
        """
        Returns true if this data item is an Array of DataTypes
        
        :return: true if an array
        :rtype: bool
        """

    def isConstant(self) -> bool:
        """
        Determine if this data has explicitly been marked as constant.
        NOTE: This is based upon explicit :obj:`Data` and :obj:`DataType` mutability settings
        and does not reflect independent memory block or processor specification settings.
        
        :return: true if data is constant, else false.
        :rtype: bool
        """

    def isDefined(self) -> bool:
        """
        Returns true if the data type is defined.  Any address that has not been defined to be code
        or data is treated as undefined data.
        
        :return: true if is defined
        :rtype: bool
        """

    def isDynamic(self) -> bool:
        """
        Returns true if this data item is a dynamic DataType.
        
        :return: true if is dynamic
        :rtype: bool
        """

    def isPointer(self) -> bool:
        """
        Returns true if this is a pointer, which implies getValue() will return an Object that is an
        Address.
        
        :return: true if a pointer
        :rtype: bool
        """

    def isStructure(self) -> bool:
        """
        Returns true if this data item is a Structure.
        
        :return: true if a structure
        :rtype: bool
        """

    def isUnion(self) -> bool:
        """
        Returns true if this data item is a Union.
        
        :return: true if a union
        :rtype: bool
        """

    def isVolatile(self) -> bool:
        """
        Determine if this data has explicitly been marked as volatile.
        NOTE: This is based upon explicit :obj:`Data` and :obj:`DataType` mutability settings
        and does not reflect independent memory block or processor specification settings.
        
        :return: true if data is volatile, else false.
        :rtype: bool
        """

    def isWritable(self) -> bool:
        """
        Determine if this data has explicitly been marked as writable.
        NOTE: This is based upon explicit :obj:`Data` and :obj:`DataType` mutability settings
        and does not reflect independent memory block or processor specification settings.
        
        :return: true if data is writable, else false.
        :rtype: bool
        """

    def removeValueReference(self, refAddr: ghidra.program.model.address.Address):
        """
        Remove a reference to the value.
        
        :param ghidra.program.model.address.Address refAddr: address of reference to be removed.
        """

    @property
    def pathName(self) -> java.lang.String:
        ...

    @property
    def parent(self) -> Data:
        ...

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def writable(self) -> jpype.JBoolean:
        ...

    @property
    def baseDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def componentPathName(self) -> java.lang.String:
        ...

    @property
    def array(self) -> jpype.JBoolean:
        ...

    @property
    def root(self) -> Data:
        ...

    @property
    def parentOffset(self) -> jpype.JInt:
        ...

    @property
    def dynamic(self) -> jpype.JBoolean:
        ...

    @property
    def defaultValueRepresentation(self) -> java.lang.String:
        ...

    @property
    def componentLevel(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> java.lang.Object:
        ...

    @property
    def defined(self) -> jpype.JBoolean:
        ...

    @property
    def componentIndex(self) -> jpype.JInt:
        ...

    @property
    def pointer(self) -> jpype.JBoolean:
        ...

    @property
    def valueReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def rootOffset(self) -> jpype.JInt:
        ...

    @property
    def defaultLabelPrefix(self) -> java.lang.String:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def primitiveAt(self) -> Data:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @property
    def componentsContaining(self) -> java.util.List[Data]:
        ...

    @property
    def union(self) -> jpype.JBoolean:
        ...

    @property
    def componentAt(self) -> Data:
        ...

    @property
    def structure(self) -> jpype.JBoolean:
        ...

    @property
    def componentContaining(self) -> Data:
        ...

    @property
    def component(self) -> Data:
        ...

    @property
    def componentPath(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def valueClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def numComponents(self) -> jpype.JInt:
        ...


@deprecated("FunctionDefinitionDataType should be used for defining a function signature")
class FunctionSignatureImpl(ghidra.program.model.data.FunctionDefinitionDataType):
    """
    Implementation of a Function Signature.  All the information about
    a function that is portable from one program to another.
    
    
    .. deprecated::
    
    FunctionDefinitionDataType should be used for defining a function signature
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates new FunctionSignatureImpl with the given name, default return type
        and no parameters.
        
        :param java.lang.String or str name: the name of the function
        """

    @typing.overload
    def __init__(self, signature: FunctionSignature):
        """
        Creates new FunctionSignatureImpl based upon an existing function signature.
        
        :param FunctionSignature signature: the signature of the function
        """

    @typing.overload
    def __init__(self, function: Function):
        """
        Create a Function Definition based on a Function.
        The effective signature will be used where forced indirect and auto-params
        are reflected in the signature.
        
        :param Function function: the function to use to create a Function Signature.
        """

    @typing.overload
    def __init__(self, function: Function, formalSignature: typing.Union[jpype.JBoolean, bool]):
        """
        Create a Function Definition based on a Function
        
        :param Function function: the function to use to create a Function Signature.
        :param jpype.JBoolean or bool formalSignature: if true only original raw types will be retained and 
        auto-params discarded (e.g., this, __return_storage_ptr__, etc.).  If false,
        the effective signature will be used where forced indirect and auto-params
        are reflected in the signature.  This option has no affect if the specified 
        function has custom storage enabled.
        """


class VariableFilter(java.lang.Object):

    class ParameterFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, allowAutoParams: typing.Union[jpype.JBoolean, bool]):
            ...


    class LocalVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class StackVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class CompoundStackVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RegisterVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class MemoryVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class UniqueVariableFilter(VariableFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    PARAMETER_FILTER: typing.Final[VariableFilter]
    """
    ``PARAMETER_FILTER`` matches all parameters (includes auto-params).  A variable is
    treated as a parameter by this filter if it implements the Parameter interface.
    """

    NONAUTO_PARAMETER_FILTER: typing.Final[VariableFilter]
    """
    ``NONAUTO_PARAMETER_FILTER`` matches all parameters which are not an auto-param.  A variable is
    treated as a parameter by this filter if it implements the Parameter interface.
    """

    LOCAL_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``LOCAL_VARIABLE_FILTER`` matches all simple stack variables.  A variable is
    treated as local by this filter if it does not implement the Parameter interface.
    """

    STACK_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``STACK_VARIABLE_FILTER`` matches all simple stack variables
    """

    COMPOUND_STACK_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``COMPOUND_STACK_VARIABLE_FILTER`` matches all simple or compound variables
    which utilize a stack storage element
    """

    REGISTER_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``REGISTER_VARIABLE_FILTER`` matches all simple register variables
    """

    MEMORY_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``MEMORY_VARIABLE_FILTER`` matches all simple memory variables
    """

    UNIQUE_VARIABLE_FILTER: typing.Final[VariableFilter]
    """
    ``UNIQUE_VARIABLE_FILTER`` matches all simple unique variables identified by a hash value
    """


    def matches(self, variable: Variable) -> bool:
        """
        Determine if the specified variable matches this filter criteria
        
        :param Variable variable: 
        :return: true if variable satisfies the criteria of this filter
        :rtype: bool
        """


class FunctionOverlapException(ghidra.util.exception.UsrException):
    """
    ``FunctionOverlapException`` is thrown in cases where
    a function creation or change would result in overlapping functions.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class StackFrame(java.lang.Object):
    """
    Definition of a stack frame.
    All offsets into a stack are from a zero base.  Usually
    negative offsets are parameters and positive offsets are
    locals.  That does not have to be the case, it depends on whether
    the stack grows positively or negatively.  On an a 80x86 architecture,
    the stack grows negatively.  When a value is pushed onto the stack,
    the stack pointer is decremented by some size.
    
     
    Each frame consists of a local sections, parameter section, and save
    information (return address, saved registers, etc...).  A frame is said to
    grow negative if the parameters are referenced with negative offsets from 0,
    or positive if the parameters are referenced with negative offsets from 0.
     
    
    
    Negative Growth
                        -5      local2 (2 bytes)
                        -3      local1 (4 bytes)
    frame base        0      stuff (4 bytes)
    return offset     4      return addr (4 bytes)
    param offset      8      param2 (4 bytes)
                        12      param1
    
           
    Positive Growth
                    -15     param offset 1
                    -11     param offset 2
    param offset     -8     
    return offset    -7     return address
                        -3     stuff 
    frame base        0     local 1
                        4     local 2
                        8
    """

    class_: typing.ClassVar[java.lang.Class]
    GROWS_NEGATIVE: typing.Final = -1
    """
    Indicator for a Stack that grows negatively.
    """

    GROWS_POSITIVE: typing.Final = 1
    """
    Indicator for a Stack that grows positively.
    """

    UNKNOWN_PARAM_OFFSET: typing.Final = 131072
    """
    Indicator for a unknown stack parameter offset
    """


    def clearVariable(self, offset: typing.Union[jpype.JInt, int]):
        """
        Clear the stack variable defined at offset
        
        :param jpype.JInt or int offset: Offset onto the stack to be cleared.
        """

    def createVariable(self, name: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType) -> Variable:
        """
        Create a stack variable.  It could be a parameter or a local depending
        on the direction of the stack.
         
        **WARNING!** Use of this method to add parameters may force the function
        to use custom variable storage.  In addition, parameters may be appended even if the
        current calling convention does not support them.
        
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if data type size is too large based upon storage constraints.
        """

    def getFrameSize(self) -> int:
        """
        Get the size of this stack frame in bytes.
        
        :return: stack frame size
        :rtype: int
        """

    def getFunction(self) -> Function:
        """
        Get the function that this stack belongs to.
        This could return null if the stack frame isn't part of a function.
        
        :return: the function
        :rtype: Function
        """

    def getLocalSize(self) -> int:
        """
        Get the local portion of the stack frame in bytes.
        
        :return: local frame size
        :rtype: int
        """

    def getLocals(self) -> jpype.JArray[Variable]:
        """
        Get all defined local variables.
        
        :return: an array of all local variables
        :rtype: jpype.JArray[Variable]
        """

    def getParameterOffset(self) -> int:
        """
        Get the offset to the start of the parameters.
        
        :return: offset
        :rtype: int
        """

    def getParameterSize(self) -> int:
        """
        Get the parameter portion of the stack frame in bytes.
        
        :return: parameter frame size
        :rtype: int
        """

    def getParameters(self) -> jpype.JArray[Variable]:
        """
        Get all defined parameters as stack variables.
        
        :return: an array of parameters.
        :rtype: jpype.JArray[Variable]
        """

    def getReturnAddressOffset(self) -> int:
        """
        Get the return address stack offset.
        
        :return: return address offset.
        :rtype: int
        """

    def getStackVariables(self) -> jpype.JArray[Variable]:
        """
        Get all defined stack variables.
        Variables are returned from least offset (-) to greatest offset (+)
        
        :return: an array of parameters.
        :rtype: jpype.JArray[Variable]
        """

    def getVariableContaining(self, offset: typing.Union[jpype.JInt, int]) -> Variable:
        """
        Get the stack variable containing offset.  This may fall in
        the middle of a defined variable.
        
        :param jpype.JInt or int offset: offset of on stack to get variable.
        """

    def growsNegative(self) -> bool:
        """
        A stack that grows negative has local references negative and
        parameter references positive.  A positive growing stack has
        positive locals and negative parameters.
        
        :return: true if the stack grows in a negative direction.
        :rtype: bool
        """

    def isParameterOffset(self, offset: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if specified offset could correspond to a parameter
        
        :param jpype.JInt or int offset:
        """

    def setLocalSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Set the size of the local stack in bytes.
        
        :param jpype.JInt or int size: size of local stack
        """

    def setReturnAddressOffset(self, offset: typing.Union[jpype.JInt, int]):
        """
        Set the return address stack offset.
        
        :param jpype.JInt or int offset: offset of return address.
        """

    @property
    def returnAddressOffset(self) -> jpype.JInt:
        ...

    @returnAddressOffset.setter
    def returnAddressOffset(self, value: jpype.JInt):
        ...

    @property
    def frameSize(self) -> jpype.JInt:
        ...

    @property
    def stackVariables(self) -> jpype.JArray[Variable]:
        ...

    @property
    def localSize(self) -> jpype.JInt:
        ...

    @localSize.setter
    def localSize(self, value: jpype.JInt):
        ...

    @property
    def function(self) -> Function:
        ...

    @property
    def parameterSize(self) -> jpype.JInt:
        ...

    @property
    def parameterOffset(self) -> jpype.JInt:
        ...

    @property
    def variableContaining(self) -> Variable:
        ...

    @property
    def parameters(self) -> jpype.JArray[Variable]:
        ...

    @property
    def locals(self) -> jpype.JArray[Variable]:
        ...


class ProgramFragment(Group, ghidra.program.model.address.AddressSetView):
    """
    A ``ProgramFragment`` is a set of ``CodeUnit``s that have been
    bundled together with some additional information such as a name, comment,
    alias, etc. Every code unit in the program is in one and only one fragment
    so the fragments form a partition of the program. Fragments in turn are the
    building blocks of ``ProgramModule``s. Program fragments and modules 
    allow the user to overlay a hierarchical structure upon the program which can then 
    be used to control viewing and navigating the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, codeUnit: CodeUnit) -> bool:
        """
        Returns whether this fragment contains the given code unit.
        
        :param CodeUnit codeUnit: the code unit being tested.
        :return: true if the code unit is in the fragment, false otherwise.
        :rtype: bool
        """

    def getCodeUnits(self) -> CodeUnitIterator:
        """
        Returns a forward iterator over the code units making up this fragment.
        """

    def move(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address):
        """
        Moves all of the code units in a given range into this fragment.
        Note that ``min`` must the starting address of a code unit
        and ``max`` must be the ending address of a code unit.
        Furthermore every address in the given range must exist in program
        memory.
        
        :param ghidra.program.model.address.Address min: min address of range specifying the code units to move
        :param ghidra.program.model.address.Address max: max address of range specifying the code units to move
        :raises NotFoundException: thrown if any address between ``min``
        and ``max`` (inclusive) does not belong to program memory.
        """

    @property
    def codeUnits(self) -> CodeUnitIterator:
        ...


class DataTypeArchiveChangeSet(DomainObjectChangeSet, DataTypeChangeSet):
    """
    Interface for a data type archive change set.  Objects that implements this interface track
    various change information on a data type archive.
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultProgramContext(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDefaultValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the default value of a register at a given address.
        
        :param ghidra.program.model.lang.Register register: the register for which to get a default value.
        :param ghidra.program.model.address.Address address: the address at which to get a default value.
        :return: the default value of the register at the given address or null if no default value
        has been assigned.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def setDefaultValue(self, registerValue: ghidra.program.model.lang.RegisterValue, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Associates a default value with the given register over the given range.
        
        :param ghidra.program.model.lang.RegisterValue registerValue: the register for which to associate a default value.
        :param ghidra.program.model.address.Address start: the start address.
        :param ghidra.program.model.address.Address end: the end address (inclusive)
        """


class VariableUtilities(java.lang.Object):

    @typing.type_check_only
    class StackAttributes(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, stackAlign: typing.Union[jpype.JInt, int], bias: typing.Union[jpype.JInt, int], rightJustify: typing.Union[jpype.JBoolean, bool]):
            ...


    class VariableConflictHandler(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def resolveConflicts(self, conflicts: java.util.List[Variable]) -> bool:
            """
            Provides means of resolving variable conflicts (e.g., removing of conflicts)
            
            :param java.util.List[Variable] conflicts: variable conflicts
            :return: true if conflicts resolved else false
            :rtype: bool
            """


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: typing.Union[jpype.JBoolean, bool], defaultSize: typing.Union[jpype.JInt, int], dtMgr: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
        not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         
        * Function definition datatype
        * An unsized/zero-element array
        
        
        :param ghidra.program.model.data.DataType dataType: datatype to be checked
        :param jpype.JBoolean or bool voidOK: true if checking return datatype and void is allow, else false.
        :param jpype.JInt or int defaultSize: Undefined datatype size to be used if specified datatype is null.  A value less than 1
        will result in the DEFAULT data type being returned (i.e., "undefined").
        :param ghidra.program.model.data.DataTypeManager dtMgr: target datatype manager (null permitted which will adopt default data organization)
        :return: cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidInputException: if an unacceptable datatype was specified
        """

    @staticmethod
    @typing.overload
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: typing.Union[jpype.JBoolean, bool], defaultSize: typing.Union[jpype.JInt, int], program: Program) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
        not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         
        * Function definition datatype
        * An unsized/zero-element array
        
        
        :param ghidra.program.model.data.DataType dataType: datatype to be checked
        :param jpype.JBoolean or bool voidOK: true if checking return datatype and void is allow, else false.
        :param jpype.JInt or int defaultSize: Undefined datatype size to be used if specified datatype is null.  A value less than 1
        will result in the DEFAULT data type being returned (i.e., "undefined").
        :param Program program: target program
        :return: cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidInputException: if an unacceptable datatype was specified
        """

    @staticmethod
    @typing.overload
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: typing.Union[jpype.JBoolean, bool], dtMgr: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
        not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         
        * Function definition datatype
        * An unsized/zero-element array
        
        
        :param ghidra.program.model.data.DataType dataType: datatype to be checked.  If null is specified the DEFAULT datatype will be
        returned.
        :param jpype.JBoolean or bool voidOK: true if checking return datatype and void is allow, else false.
        :param ghidra.program.model.data.DataTypeManager dtMgr: target datatype manager (null permitted which will adopt default data organization)
        :return: cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidInputException: if an unacceptable datatype was specified
        """

    @staticmethod
    @typing.overload
    def checkStorage(storage: VariableStorage, dataType: ghidra.program.model.data.DataType, allowSizeMismatch: typing.Union[jpype.JBoolean, bool]):
        """
        Perform variable storage checks using the specified datatype.
        
        :param VariableStorage storage: variable storage whose size must match the specified data type size
        :param ghidra.program.model.data.DataType dataType: a datatype checked using :meth:`checkDataType(DataType, boolean, int, Program) <.checkDataType>`
        :param jpype.JBoolean or bool allowSizeMismatch: if true size mismatch will be ignore
        :raises InvalidInputException: if specified storage is not suitable for datatype
        """

    @staticmethod
    @typing.overload
    def checkStorage(function: Function, storage: VariableStorage, dataType: ghidra.program.model.data.DataType, allowSizeMismatch: typing.Union[jpype.JBoolean, bool]) -> VariableStorage:
        """
        Perform variable storage checks using the specified datatype.
        
        :param Function function: if specified and variable storage size does not match the data-type size
        an attempt will be made to resize the specified storage.
        :param VariableStorage storage: variable storage
        :param ghidra.program.model.data.DataType dataType: a datatype checked using :meth:`checkDataType(DataType, boolean, int, Program) <.checkDataType>`
        :param jpype.JBoolean or bool allowSizeMismatch: if true size mismatch will be ignore
        :return: original storage or resized storage with the correct size.
        :rtype: VariableStorage
        :raises InvalidInputException: if specified storage is not suitable for datatype
        """

    @staticmethod
    @typing.overload
    def checkVariableConflict(function: Function, var: Variable, newStorage: VariableStorage, deleteConflictingVariables: typing.Union[jpype.JBoolean, bool]):
        """
        Check for variable storage conflict and optionally remove conflicting variables.
        
        :param Function function: function which corresponds to specified variable
        :param Variable var: existing function variable or null for new variable
        :param VariableStorage newStorage: new/updated variable storage
        :param jpype.JBoolean or bool deleteConflictingVariables: if true function's conflicting variables may be deleted
        :raises VariableSizeException: if deleteConflictingVariables is false and another variable conflicts
        """

    @staticmethod
    @typing.overload
    def checkVariableConflict(existingVariables: java.util.List[Variable], var: Variable, newStorage: VariableStorage, conflictHandler: VariableUtilities.VariableConflictHandler):
        """
        Check for variable storage conflict and optionally remove conflicting variables.
        
        :param java.util.List[Variable] existingVariables: variables to check (may contain null entries)
        :param Variable var: function variable
        :param VariableStorage newStorage: variable storage
        :param VariableUtilities.VariableConflictHandler conflictHandler: variable conflict handler
        :raises VariableSizeException: if another variable conflicts
        """

    @staticmethod
    def compare(v1: Variable, v2: Variable) -> int:
        """
        Compare two variables without using the instance specific compareTo method.
        
        :param Variable v1: a function variable
        :param Variable v2: another function variable
        :return: a negative value if v1 < v2, 0 if equal, and
        positive if v1 > v2
        :rtype: int
        """

    @staticmethod
    def equivalentVariableArrays(vars1: jpype.JArray[Variable], vars2: jpype.JArray[Variable]) -> bool:
        ...

    @staticmethod
    def equivalentVariables(var1: Variable, var2: Variable) -> bool:
        ...

    @staticmethod
    @typing.overload
    def findExistingClassStruct(classNamespace: GhidraClass, dataTypeManager: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified class namespace
        within the specified data type manager.
         
        The preferred structure will utilize a namespace-based category path, however,
        the match criteria can be fuzzy and relies primarily on the class name.
        A properly named class structure must reside within a category whose trailing 
        path either matches the class namespace or the class-parent's namespace.  
        Preference is given to it residing within the class-parent's namespace.
        
        :param GhidraClass classNamespace: class namespace
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: data type manager which should be searched.
        :return: existing structure whose name matches the specified class namespace
        or null if not found.
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    @typing.overload
    def findExistingClassStruct(func: Function) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified function's class namespace
        within the function's program.
         
        The preferred structure will utilize a namespace-based category path, however,
        the match criteria can be fuzzy and relies primarily on the class name.
        A properly named class structure must reside within a category whose trailing 
        path either matches the class namespace or the class-parent's namespace.  
        Preference is given to it residing within the class-parent's namespace.
        
        :param Function func: the function.
        :return: existing structure whose name matches the specified function's class namespace
        or null if not found.
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    @typing.overload
    def findOrCreateClassStruct(classNamespace: GhidraClass, dataTypeManager: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified class namespace
        within the specified data type manager.
         
        The preferred structure will utilize a namespace-based category path, however,
        the match criteria can be fuzzy and relies primarily on the class name.
        A properly named class structure must reside within a category whose trailing 
        path either matches the class namespace or the class-parent's namespace.  
        Preference is given to it residing within the class-parent's namespace.
         
        If a match is not found an empty placeholder structure will be instantiated
        and returned.  A newly instantiated structure will not be added to the data type manager
        and may refer to a non-existing category path which corresponds to the class-parent's 
        namespace.
         
        If an unrelated data-type already exists matching the class name and category,
        null is returned.
        
        :param GhidraClass classNamespace: class namespace
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: data type manager which should be searched and whose
        data organization should be used.
        :return: new or existing structure whose name matches the specified class namespace
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    @typing.overload
    def findOrCreateClassStruct(function: Function) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified function's class namespace
        within the function's program.
         
        The preferred structure will utilize a namespace-based category path, however,
        the match criteria can be fuzzy and relies primarily on the class name.
        A properly named class structure must reside within a category whose trailing 
        path either matches the class namespace or the class-parent's namespace.  
        Preference is given to it residing within the class-parent's namespace.
         
        If a match is not found an empty placeholder structure will be instantiated
        and returned.  A newly instantiated structure will not be added to the data type manager
        and may refer to a non-existing category path which corresponds to the class-parent's 
        namespace.
         
        If the function is not part of a class, or if an unrelated data-type already exists with
        the class's name and category, null is returned.
        
        :param Function function: function's whose class namespace is the basis for the structure
        :return: new or existing structure whose name matches the function's class namespace or
        null if function not contained within a class namespace.
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    def getAutoDataType(function: Function, returnDataType: ghidra.program.model.data.DataType, storage: VariableStorage) -> ghidra.program.model.data.DataType:
        """
        Determine the appropriate data type for an automatic parameter
        
        :param Function function: function whose auto param datatype is to be determined
        :param ghidra.program.model.data.DataType returnDataType: function's formal return datatype
        :param VariableStorage storage: variable storage for an auto-parameter (isAutoStorage should be true)
        :return: auto-parameter data type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getBaseStackParamOffset(function: Function) -> int:
        """
        Determine the minimum stack offset for parameters
        
        :param Function function: function whose stack use is to be examined
        :return: stack parameter offset or null if it could not be determined
        :rtype: int
        """

    @staticmethod
    def getPrecedence(var: Variable) -> int:
        """
        Get a precedence value for the specified variable.
        This value can be used to assist with LocalVariable.compareTo(Variable var)
        
        :param Variable var: function variable
        :return: numeric precedence
        :rtype: int
        """

    @staticmethod
    @deprecated("should rely on auto-param instead - try not to use this method which may be eliminated")
    def getThisParameter(function: Function, convention: ghidra.program.model.lang.PrototypeModel) -> ParameterImpl:
        """
        Generate a suitable 'this' parameter for the specified function
        
        :param Function function: function for which a ``this`` parameter is to be generated
        :param ghidra.program.model.lang.PrototypeModel convention: function calling convention
        :return: this parameter or null of calling convention is not a 'thiscall'
        or some other error prevents it
        :rtype: ParameterImpl
        
        .. deprecated::
        
        should rely on auto-param instead - try not to use this method which may be eliminated
        """

    @staticmethod
    def resizeStorage(curStorage: VariableStorage, dataType: ghidra.program.model.data.DataType, alignStack: typing.Union[jpype.JBoolean, bool], function: Function) -> VariableStorage:
        """
        Perform resize variable storage to desired newSize.  This method has limited ability to grow
        storage if current storage does not have a stack component or if other space constraints
        are exceeded.
        
        :param VariableStorage curStorage: current variable storage
        :param ghidra.program.model.data.DataType dataType: variable datatype
        :param jpype.JBoolean or bool alignStack: if false no attempt is made to align stack usage for big-endian
        :param Function function: function which corresponds to resized variable storage
        :return: resize storage
        :rtype: VariableStorage
        :raises InvalidInputException: if unable to resize storage to specified size.
        """

    @staticmethod
    @typing.overload
    def storageMatches(vars: java.util.List[Variable], otherVars: java.util.List[Variable]) -> bool:
        """
        Compare storage varnodes for two lists of variables.  No check is done to ensure that
        storage is considered good/valid (i.e., BAD_STORAGE, UNASSIGNED_STORAGE and VOID_STORAGE
        all have an empty varnode list and would be considered a match)
        
        :param java.util.List[Variable] vars: function variables
        :param java.util.List[Variable] otherVars: other function variables
        :return: true if the exact sequence of variable storage varnodes matches across two lists of variables.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def storageMatches(vars: java.util.List[Variable], *otherVars: Variable) -> bool:
        """
        Compare storage varnodes for two lists of variables.  No check is done to ensure that
        storage is considered good/valid (i.e., BAD_STORAGE, UNASSIGNED_STORAGE and VOID_STORAGE
        all have an empty varnode list and would be considered a match)
        
        :param java.util.List[Variable] vars: function variables
        :param jpype.JArray[Variable] otherVars: other function variables
        :return: true if the exact sequence of variable storage varnodes matches across two lists of variables.
        :rtype: bool
        """


class Parameter(Variable):
    """
    Interface for function parameters
    """

    class_: typing.ClassVar[java.lang.Class]
    RETURN_NAME: typing.Final = "<RETURN>"
    RETURN_ORIDINAL: typing.Final = -1
    UNASSIGNED_ORDINAL: typing.Final = -2

    def getAutoParameterType(self) -> AutoParameterType:
        """
        If this is an auto-parameter this method will indicate its type.
        
        :return: auto-parameter type of null if not applicable.
        :rtype: AutoParameterType
        """

    def getFormalDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the original formal signature data type before a possible forced indirect was
        possibly imposed by the functions calling convention.  The :meth:`getDataType() <.getDataType>` method 
        will always return the effective data type which corresponds to the allocated 
        variable storage.
        
        :return: Formal data type.  This type will only differ from the :meth:`getDataType() <.getDataType>`
        value if this parameter isForcedIndirect.
        :rtype: ghidra.program.model.data.DataType
        """

    def getOrdinal(self) -> int:
        """
        Returns the ordinal (index) of this parameter within the function signature.
        """

    def isAutoParameter(self) -> bool:
        """
        
        
        :return: true if this parameter is automatically generated based upon the associated
        function calling convention and function signature.  An example of such a parameter 
        include the "__return_storage_ptr__" parameter.
        :rtype: bool
        """

    def isForcedIndirect(self) -> bool:
        """
        If this parameter which was forced by the associated calling 
        convention to be passed as a pointer instead of its original formal type.
        
        :return: true if this parameter was forced to be passed as a pointer instead of its 
        original formal type
        :rtype: bool
        """

    @property
    def forcedIndirect(self) -> jpype.JBoolean:
        ...

    @property
    def autoParameterType(self) -> AutoParameterType:
        ...

    @property
    def autoParameter(self) -> jpype.JBoolean:
        ...

    @property
    def formalDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...


class IncompatibleLanguageException(java.lang.Exception):
    """
    Exception thrown when attempting to replace one language in a program with another that
    is not "address space" compatable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new IncompatibleLanguageExcepton
        """


class FunctionSignature(java.lang.Object):
    """
    Interface describing all the things about a function that are portable
    from one program to another.
    """

    class_: typing.ClassVar[java.lang.Class]
    NORETURN_DISPLAY_STRING: typing.Final = "noreturn"
    VAR_ARGS_DISPLAY_STRING: typing.Final = "..."
    VOID_PARAM_DISPLAY_STRING: typing.Final = "void"

    def getArguments(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        """
        Get function signature parameter arguments
        
        :return: an array of parameters for the function
        :rtype: jpype.JArray[ghidra.program.model.data.ParameterDefinition]
        """

    def getCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the calling convention prototype model for this function if associated with a 
        compiler specificfation.  This method will always return null if signature is not 
        associated with a specific program architecture.
        
        :return: the prototype model of the function's current calling convention or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    def getCallingConventionName(self) -> str:
        """
        Returns the calling convention name associated with this function definition.
        Reserved names may also be returned: :obj:`Function.UNKNOWN_CALLING_CONVENTION_STRING`,
        :obj:`Function.DEFAULT_CALLING_CONVENTION_STRING`.
        The "unknown" convention must be returned instead of null.
        
        :return: calling convention name
        :rtype: str
        """

    def getComment(self) -> str:
        """
        Get descriptive comment for signature
        
        :return: the comment string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Return the name of this function
        """

    @typing.overload
    def getPrototypeString(self) -> str:
        """
        Get string representation of the function signature without the
        calling convention specified.
        
        :return: function signature string
        :rtype: str
        """

    @typing.overload
    def getPrototypeString(self, includeCallingConvention: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get string representation of the function signature
        
        :param jpype.JBoolean or bool includeCallingConvention: if true prototype will include call convention
        declaration if known as well as ``noreturn`` indicator if applicable.
        :return: function signature string
        :rtype: str
        """

    def getReturnType(self) -> ghidra.program.model.data.DataType:
        """
        Get function signature return type
        
        :return: the return data type
        :rtype: ghidra.program.model.data.DataType
        """

    def hasNoReturn(self) -> bool:
        """
        
        
        :return: true if this function signature corresponds to a non-returning function.
        :rtype: bool
        """

    def hasUnknownCallingConventionName(self) -> bool:
        """
        Determine if this signature has an unknown or unrecognized calling convention name.
        
        :return: true if calling convention is unknown or unrecognized name, else false.
        :rtype: bool
        """

    def hasVarArgs(self) -> bool:
        """
        
        
        :return: true if this function signature has a variable argument list (VarArgs).
        :rtype: bool
        """

    def isEquivalentSignature(self, signature: FunctionSignature) -> bool:
        """
        Returns true if the given signature is equivalent to this signature.  The
        precise meaning of "equivalent" is dependent upon return/parameter dataTypes.
        
        :param FunctionSignature signature: the function signature being tested for equivalence.
        :return: true if the if the given signature is equivalent to this signature.
        :rtype: bool
        """

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def equivalentSignature(self) -> jpype.JBoolean:
        ...

    @property
    def callingConventionName(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def arguments(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def prototypeString(self) -> java.lang.String:
        ...


class BookmarkComparator(java.util.Comparator[Bookmark]):
    """
    Provides an ordering for bookmarks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def compare(self, bm1: Bookmark, bm2: Bookmark) -> int:
        """
        Comparator for bookmarks.
        
        :param Bookmark bm1: first bookmark
        :param Bookmark bm2: second bookmark
        :return: a negative integer, zero, or a positive integer as the
                    first argument is less than, equal to, or greater than the
                second.
        :rtype: int
        """


class DataStub(Data):
    """
    DataStub can be extended for use by tests. It throws an UnsupportedOperationException
    for all methods in the Data interface. Any method that is needed for your test can then
    be overridden so it can provide its own test implementation and return value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RegisterChangeSet(ghidra.framework.model.ChangeSet):
    """
    Interface for a Register Change set.  Objects that implements this interface track
    various change information on a set of addresses where the program register values have changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addRegisterRange(self, addr1: ghidra.program.model.address.Address, addr2: ghidra.program.model.address.Address):
        """
        Adds the ranges of addresses that have register changes.
        
        :param ghidra.program.model.address.Address addr1: the first address in the range.
        :param ghidra.program.model.address.Address addr2: the last address in the range.
        """

    def getRegisterAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of Addresses containing register changes.
        """

    @property
    def registerAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...


class InstructionStub(Instruction):
    """
    InstructionStub can be extended for use by tests. It throws an UnsupportedOperationException
    for all methods in the Instruction interface. Any method that is needed for your test can then 
    be overridden so it can provide its own test implementation and return value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BookmarkTypeComparator(java.util.Comparator[BookmarkType]):
    """
    Provides an ordering for bookmark types.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def compare(self, bt1: BookmarkType, bt2: BookmarkType) -> int:
        """
        Comparator for bookmark types.
        
        :param BookmarkType bt1: first bookmark type
        :param BookmarkType bt2: second bookmark type
        :return: a negative integer, zero, or a positive integer as the
                    first argument is less than, equal to, or greater than the
                second.
        :rtype: int
        """


class InstructionPcodeOverride(ghidra.program.model.pcode.PcodeOverride):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instr: Instruction):
        """
        This constructor caches the primary and overriding "from" references of ``instr``.  
        This cache is never updated; the assumption is that this object is short-lived 
        (duration of :obj:`PcodeEmit`)
        
        :param Instruction instr: the instruction
        """


class ProgramContext(java.lang.Object):
    """
    Interface to define a processor register context over the address space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseContextRegister(self) -> ghidra.program.model.lang.Register:
        """
        Returns the base context register.
        
        :return: the base context register.
        :rtype: ghidra.program.model.lang.Register
        """

    def getContextRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Gets the registers for this context that are used for processor context states.
        
        :return: all processor context registers
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    def getDefaultDisassemblyContext(self) -> ghidra.program.model.lang.RegisterValue:
        """
        
        
        :return: Get the current default disassembly context to be used when initiating disassmbly
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getDefaultRegisterValueAddressRanges(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator over all addresses that have an associated default value for the given 
        register.  Each range returned will have the same default value associated with the register for all 
        addresses in that range.
        
        :param ghidra.program.model.lang.Register register: the register for which to get set default value ranges.
        :return: An AddressRangeIterator over all address that have default values for the given register.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getDefaultRegisterValueAddressRanges(self, register: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator over all addresses that have an associated default value within the
        given range for the given register.  Each range returned will have the same default value
        associated with the register for all addresses in that range.
        
        :param ghidra.program.model.lang.Register register: the register for which to get default value ranges.
        :param ghidra.program.model.address.Address start: start of address range to search
        :param ghidra.program.model.address.Address end: end of address range to search
        :return: An AddressRangeIterator over all address within the given range that have default values
        for the given register.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getDefaultValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the default value of a register at a given address.
        
        :param ghidra.program.model.lang.Register register: the register for which to get a default value.
        :param ghidra.program.model.address.Address address: the address at which to get a default value.
        :return: the default value of the register at the given address or null if no default value
        has been assigned.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getDisassemblyContext(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the disassembly context for a specified address.  This context is formed
        from the default disassembly context and the context register value stored
        at the specified address.  Those bits specified by the stored context value
        take precedence.
        
        :param ghidra.program.model.address.Address address: program address
        :return: disassembly context register value
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getFlowValue(self, value: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        """
        Modify register value to eliminate non-flowing bits
        
        :param ghidra.program.model.lang.RegisterValue value: register value to be modified
        :return: value suitable for flowing
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getNonDefaultValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the (non-default)value assigned to a register at a given address.
        
        :param ghidra.program.model.lang.Register register: the register for which to get its value.
        :param ghidra.program.model.address.Address address: the address at which to get a value.
        :return: a RegisterValue object containing the value of the register at the given address or 
        possibly null if no value has been assigned.
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getNonFlowValue(self, value: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        """
        Modify register value to only include non-flowing bits
        
        :param ghidra.program.model.lang.RegisterValue value: register value to be modified
        :return: new value or null
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getRegister(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.Register:
        """
        Get a Register object given the name of a register
        
        :param java.lang.String or str name: the name of the register.
        :return: The register with the given name or null if no register has that name.
        :rtype: ghidra.program.model.lang.Register
        """

    def getRegisterNames(self) -> java.util.List[java.lang.String]:
        """
        Get an alphabetical sorted unmodifiable list of original register names 
        (including context registers).  Names correspond to orignal register
        name and not aliases which may be defined.
        
        :return: alphabetical sorted unmodifiable list of original register names.
        :rtype: java.util.List[java.lang.String]
        """

    def getRegisterValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns a register value and mask for the given register.
        
        :param ghidra.program.model.lang.Register register: the register
        :param ghidra.program.model.address.Address address: the address of the value
        :return: a register value and mask for the given register
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getRegisterValueAddressRanges(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator over all addresses that have an associated value for the given 
        register.  Each range returned will have the same value associated with the register for all 
        addresses in that range.
        
        :param ghidra.program.model.lang.Register register: the register for which to get set value ranges.
        :return: An AddressRangeIterator over all address that have values for the given register.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getRegisterValueAddressRanges(self, register: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator over all addresses that have an associated value within the
        given range for the given register.  Each range returned will have the same value
        associated with the register for all addresses in that range.
        
        :param ghidra.program.model.lang.Register register: the register for which to get set value ranges.
        :param ghidra.program.model.address.Address start: start of address range to search
        :param ghidra.program.model.address.Address end: end of address range to search
        :return: An AddressRangeIterator over all address within the given range that have values
        for the given register.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getRegisterValueRangeContaining(self, register: ghidra.program.model.lang.Register, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Returns the bounding address-range containing addr and the same RegisterValue throughout.
        The range returned may be limited by other value changes associated with register's base-register.
        
        :param ghidra.program.model.lang.Register register: program register
        :param ghidra.program.model.address.Address addr: program address
        :return: single register-value address-range containing addr
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Get all the register descriptions defined for this program context.
        
        :return: unmodifiable list of defined register descriptions
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    def getRegistersWithValues(self) -> jpype.JArray[ghidra.program.model.lang.Register]:
        """
        Returns an array of all registers that at least one value associated with an address.
        
        :return: a array of all registers that at least one value associated with an address.
        :rtype: jpype.JArray[ghidra.program.model.lang.Register]
        """

    def getValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address, signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Returns the value assigned to a register at a given address.  This method will return any
        default value assigned to the register at the given address if no explicit value has been set
        at that address.
        
        :param ghidra.program.model.lang.Register register: the register for which to get its value.
        :param ghidra.program.model.address.Address address: the address at which to get a value.
        :param jpype.JBoolean or bool signed: if true, interprets the fix-bit size register value as a signed value.
        :return: a BigInteger object containing the value of the registe at the given address or null
        if no value has been assigned.
        :rtype: java.math.BigInteger
        """

    def hasNonFlowingContext(self) -> bool:
        """
        
        
        :return: true if one or more non-flowing context registers fields
        have been defined within the base processor context register.
        :rtype: bool
        """

    def hasValueOverRange(self, reg: ghidra.program.model.lang.Register, value: java.math.BigInteger, addrSet: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Returns true if the given register has the value over the addressSet
        
        :param ghidra.program.model.lang.Register reg: the register whose value is to be tested.
        :param java.math.BigInteger value: the value to test for.
        :param ghidra.program.model.address.AddressSetView addrSet: the set of addresses to test
        :return: true if every address in the addrSet has the value.
        :rtype: bool
        """

    def remove(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, register: ghidra.program.model.lang.Register):
        """
        Remove (unset) the register values for a given address range.
        
        :param ghidra.program.model.address.Address start: starting address.
        :param ghidra.program.model.address.Address end: ending adddress.
        :param ghidra.program.model.lang.Register register: handle to the register to be set.
        :raises ContextChangeException: thrown if context change not permitted over specified 
        range (e.g., instructions exist)
        """

    def setDefaultDisassemblyContext(self, value: ghidra.program.model.lang.RegisterValue):
        """
        Set the initial disassembly context to be used when initiating disassmbly
        
        :param ghidra.program.model.lang.RegisterValue value: context register value
        """

    def setRegisterValue(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, value: ghidra.program.model.lang.RegisterValue):
        """
        Sets the register context over the given range to the given value.
        
        :param ghidra.program.model.address.Address start: the start address to set values
        :param ghidra.program.model.address.Address end: the end address to set values
        :param ghidra.program.model.lang.RegisterValue value: the actual values to store at address
        :raises ContextChangeException: if failed to modifiy context across specified range 
        (e.g., instruction exists).
        """

    def setValue(self, register: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, value: java.math.BigInteger):
        """
        Associates a value with a register over a given address range. Any previous values will be
        overwritten.
        
        :param ghidra.program.model.lang.Register register: the register for which to assign a value.
        :param ghidra.program.model.address.Address start: the start address.
        :param ghidra.program.model.address.Address end: the end address (inclusive).
        :param java.math.BigInteger value: the value to assign.  A value of null will effective clear any existing values.
        :raises ContextChangeException: if failed to modifiy context across specified range 
        (e.g., instruction exists).
        """

    @property
    def flowValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def registerValueAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def contextRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def nonFlowValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def registers(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def registerNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def defaultRegisterValueAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def disassemblyContext(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def registersWithValues(self) -> jpype.JArray[ghidra.program.model.lang.Register]:
        ...

    @property
    def defaultDisassemblyContext(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @defaultDisassemblyContext.setter
    def defaultDisassemblyContext(self, value: ghidra.program.model.lang.RegisterValue):
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def baseContextRegister(self) -> ghidra.program.model.lang.Register:
        ...


class LocalVariableImpl(VariableImpl, LocalVariable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program):
        """
        Construct a stack variable at the specified stack offset with a first-use offset of 0.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: signed stack offset
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        :raises AddressOutOfBoundsException: if invalid stack offset specified
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a stack variable at the specified stack offset with a first-use offset of 0.
        
        :param java.lang.String or str name: variable name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: 
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        :raises AddressOutOfBoundsException: if invalid stack offset specified
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, register: ghidra.program.model.lang.Register, program: Program):
        """
        Construct a register variable with the specified register storage.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.lang.Register register: the register used for the storage.
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, register: ghidra.program.model.lang.Register, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a variable with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param java.lang.String or str name: variable name
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.lang.Register register: the register used for the storage.
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storageAddr: ghidra.program.model.address.Address, program: Program):
        """
        Construct a variable with a single storage element at the specified address.  If address 
        is contained within a register it may get realigned to the register based upon the resolved 
        datatype length.  Variable storage will be aligned to the least-significant portion of the 
        register.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.address.Address storageAddr: storage address or null if no storage has been identified
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storageAddr: ghidra.program.model.address.Address, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a variable with a single storage element at the specified address.  If address 
        is contained within a register it may get realigned to the register based upon the resolved 
        datatype length.  Variable storage will be aligned to the least-significant portion of the 
        register.
        
        :param java.lang.String or str name: variable name
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.address.Address storageAddr: storage address or null if no storage has been identified
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, program: Program):
        """
        Construct a variable with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage (may not be null)
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, force: typing.Union[jpype.JBoolean, bool], program: Program):
        """
        Construct a variable with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage (may not be null)
        :param jpype.JBoolean or bool force: if true storage will be forced even if incorrect size
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], firstUseOffset: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, force: typing.Union[jpype.JBoolean, bool], program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a variable with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param java.lang.String or str name: variable name
        :param jpype.JInt or int firstUseOffset: first use function-relative offset (i.e., start of scope).
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage (may not be null)
        :param jpype.JBoolean or bool force: if true storage will be forced even if incorrect size
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """


class ParameterImpl(VariableImpl, Parameter):
    """
    Generic implementation of Parameter.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, param: Parameter, program: Program):
        """
        Construct a parameter from another.
        
        :param Parameter param: parameter to be copied
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, program: Program):
        """
        Construct a parameter which has no specific storage specified.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a parameter which has no specific storage specified.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program):
        """
        Construct a stack parameter at the specified stack offset.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype. (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: parameter stack offset
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        :raises AddressOutOfBoundsException: if invalid stack offset specified
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a stack parameter at the specified stack offset.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype. (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: parameter stack offset
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        :raises AddressOutOfBoundsException: if invalid stack offset specified
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, register: ghidra.program.model.lang.Register, program: Program):
        """
        Construct a register parameter using the specified register.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.lang.Register register: parameter register storage
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, register: ghidra.program.model.lang.Register, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a register parameter using the specified register.
        Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.lang.Register register: parameter register storage
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, storageAddr: ghidra.program.model.address.Address, program: Program):
        """
        Construct a parameter with a single storage element at the specified address.  If address 
        is contained within a register it may get realigned to the register based upon the resolved 
        datatype length.  Variable storage will be aligned to the least-significant portion of the 
        register.  Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.address.Address storageAddr: storage address or null if no storage has been identified
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, storageAddr: ghidra.program.model.address.Address, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a parameter with a single storage element at the specified address.  If address 
        is contained within a register it may get realigned to the register based upon the resolved 
        datatype length.  Variable storage will be aligned to the least-significant portion of the 
        register.  Ordinal assignment is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.address.Address storageAddr: storage address or null if no storage has been identified
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, program: Program):
        """
        Construct a parameter with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.  Ordinal assignment
        is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage or null for unassigned storage
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a parameter with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.  Ordinal assignment
        is not established (UNASSIGNED_ORDINAL).
        
        :param java.lang.String or str name: variable name or null for default name
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage or null for unassigned storage
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], ordinal: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, storage: VariableStorage, force: typing.Union[jpype.JBoolean, bool], program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a parameter with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param java.lang.String or str name: variable name or null for default name
        :param jpype.JInt or int ordinal: parameter ordinal (-1 for return ordinal)
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage or null for unassigned storage
        :param jpype.JBoolean or bool force: if true storage will be forced even if incorrect size
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: name source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """


class FunctionTagManager(java.lang.Object):
    """
    Interface for managing function tags. Tags are simple objects consisting of a name and an 
    optional comment, which can be applied to functions.
     
    See ghidra.program.database.function.FunctionTagAdapter 
    See ghidra.program.database.function.FunctionTagMappingAdapter
    """

    class_: typing.ClassVar[java.lang.Class]

    def createFunctionTag(self, name: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> FunctionTag:
        """
        Creates a new function tag with the given attributes if one does
        not already exist. Otherwise, returns the existing tag.
        
        :param java.lang.String or str name: the tag name
        :param java.lang.String or str comment: the comment associated with the tag (optional)
        :return: the new function tag
        :rtype: FunctionTag
        """

    def getAllFunctionTags(self) -> java.util.List[FunctionTag]:
        """
        Returns all function tags in the database
        
        :return: list of function tags
        :rtype: java.util.List[FunctionTag]
        """

    @typing.overload
    def getFunctionTag(self, name: typing.Union[java.lang.String, str]) -> FunctionTag:
        """
        Returns the function tag with the given name
        
        :param java.lang.String or str name: the tag name
        :return: the function tag, or null if not found
        :rtype: FunctionTag
        """

    @typing.overload
    def getFunctionTag(self, id: typing.Union[jpype.JLong, int]) -> FunctionTag:
        """
        Returns the function tag with the given database id
        
        :param jpype.JLong or int id: the tags database id
        :return: the function tag, or null if not found
        :rtype: FunctionTag
        """

    def getUseCount(self, tag: FunctionTag) -> int:
        """
        Returns the number of times the given tag has been applied to a function
        
        :param FunctionTag tag: the tag
        :return: the count
        :rtype: int
        """

    def isTagAssigned(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given tag is assigned to a function
        
        :param java.lang.String or str name: the tag name
        :return: true if assigned to a function
        :rtype: bool
        """

    @property
    def tagAssigned(self) -> jpype.JBoolean:
        ...

    @property
    def functionTag(self) -> FunctionTag:
        ...

    @property
    def useCount(self) -> jpype.JInt:
        ...

    @property
    def allFunctionTags(self) -> java.util.List[FunctionTag]:
        ...


class Instruction(CodeUnit, ghidra.program.model.lang.ProcessorContext):
    """
    Interface to define an instruction for a processor.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID_DEPTH_CHANGE: typing.Final = 16777216
    MAX_LENGTH_OVERRIDE: typing.Final = 7

    def clearFallThroughOverride(self):
        """
        Restores this instruction's fallthrough address back to the default fallthrough
        for this instruction.
        """

    def getDefaultFallThrough(self) -> ghidra.program.model.address.Address:
        """
        Get the default fallthrough for this instruction.
        This accounts for any instructions contained with delay slots.
        
        :return: fall-through address or null if instruction has no default fallthrough
        :rtype: ghidra.program.model.address.Address
        """

    def getDefaultFallThroughOffset(self) -> int:
        """
        Get default fall-through offset in bytes from start of instruction to the
        fallthrough instruction.  This accounts for any
        instructions contained with delay slots.
        
        :return: default fall-through offset or zero (0) if instruction has no fallthrough
        :rtype: int
        """

    def getDefaultFlows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get an array of Address objects for all default flows established
        by the underlying instruction prototype.  References are ignored.
        
        :return: flow addresses or null if there are no flows
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def getDefaultOperandRepresentation(self, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the operand representation for the given operand index without markup.
        
        :param jpype.JInt or int opIndex: operand index
        :return: operand represented as a string.
        :rtype: str
        """

    def getDefaultOperandRepresentationList(self, opIndex: typing.Union[jpype.JInt, int]) -> java.util.List[java.lang.Object]:
        """
        Get the operand representation for the given operand index.
        A list of Register, Address, Scalar, Character and String objects is returned - without markup!
        
        :param jpype.JInt or int opIndex: operand index
        :return: ArrayList of pieces of the operand representation.  Unsupported languages may return null.
        :rtype: java.util.List[java.lang.Object]
        """

    def getDelaySlotDepth(self) -> int:
        """
        Get the number of delay slot instructions for this
        argument. This should be 0 for instructions which don't have a
        delay slot.  This is used to support the delay slots found on
        some RISC processors such as SPARC and the PA-RISC. This
        returns an integer instead of a boolean in case some other
        processor executes more than one instruction from a delay slot.
        
        :return: delay slot depth (number of instructions)
        :rtype: int
        """

    def getFallFrom(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the Address for the instruction that fell through to
        this instruction.
        This is useful for handling instructions that are found
        in a delay slot.
         
        Note: if an instruction is in a delayslot, then it may have
            a branch into the delayslot, which is handled as follows
            
         
        JMPIF Y, X
        lab:
            _ADD         getFallFrom() = JMPIF
        MOV              getFallFrom() = _ADD
         
        JMP Y, X
        lab:
            _ADD         getFallFrom() = null
        MOV              getFallFrom() = _ADD
        
        JMPIF Y, X
            _ADD         getFallFrom() = JMPIF
        MOV              getFallFrom() = JMPIF
           
        JMP Y, X
            _ADD         getFallFrom() = JMP
        MOV              getFallFrom() = null
        
        :rtype: ghidra.program.model.address.Address
        """

    def getFallThrough(self) -> ghidra.program.model.address.Address:
        """
        Get the fallthrough for this instruction, factoring in
        any fallthrough override and delay slotted instructions.
        
        :return: fall-through address or null if instruction has no fallthrough
        :rtype: ghidra.program.model.address.Address
        """

    def getFlowOverride(self) -> FlowOverride:
        """
        
        
        :return: the flow override which may have been set on this instruction.
        :rtype: FlowOverride
        """

    def getFlowType(self) -> ghidra.program.model.symbol.FlowType:
        """
        
        
        :return: the flow type of this instruction (how this
        instruction flows to the next instruction).
        :rtype: ghidra.program.model.symbol.FlowType
        """

    def getFlows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Get an array of Address objects for all flows other than
        a fall-through.  This will include any flow references which
        have been added to the instruction.
        
        :return: flow addresses or null if there are no flows
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def getInputObjects(self) -> jpype.JArray[java.lang.Object]:
        """
        Get the Input objects used by this instruction.
        These could be Scalars, Registers, Addresses
        
        :return: an array of objects that are used by this instruction
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getInstructionContext(self) -> ghidra.program.model.lang.InstructionContext:
        """
        
        
        :return: the instruction context for this instruction
        :rtype: ghidra.program.model.lang.InstructionContext
        """

    def getNext(self) -> Instruction:
        """
        
        
        :return: the instruction following this one in address order or null if none found.
        :rtype: Instruction
        """

    def getOpObjects(self, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.Object]:
        """
        Get objects used by this operand (Address, Scalar, Register ...)
        
        :param jpype.JInt or int opIndex: index of the operand.
        :return: objects used by this operand (Address, Scalar, Register ...)
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getOperandRefType(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.RefType:
        """
        Get the operand reference type for the given operand index.
        
        :param jpype.JInt or int index: operand index
        :return: the operand reference type for the given operand index.
        :rtype: ghidra.program.model.symbol.RefType
        """

    def getOperandType(self, opIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the type of a specific operand.
        
        :param jpype.JInt or int opIndex: the index of the operand. (zero based)
        :return: the type of the operand.
        :rtype: int
        
        .. seealso::
        
            | :obj:`OperandType`
        """

    def getParsedBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the actual bytes parsed when forming this instruction.  While this method
        will generally return the same value as :meth:`getBytes() <.getBytes>`, it will return more bytes when
        :meth:`setLengthOverride(int) <.setLengthOverride>` has been used.  In this override situation, the bytes 
        returned will generally duplicate some of the parsed bytes associated with the next
        instruction that this instruction overlaps.
        This method is equivalent to the following code for a given instruction:
         
        
         
        :obj:`InstructionPrototype` proto = instruction.:meth:`getPrototype() <.getPrototype>`;
        :obj:`Memory` mem = instruction.:meth:`getMemory() <.getMemory>`;
        byte[] bytes = mem.getBytes(instruction.:meth:`getAddress() <.getAddress>`, proto.getLength());
        int length = proto.:meth:`getLength() <InstructionPrototype.getLength>`;
         
        
        :return: the actual number of bytes parsed when forming this instruction
        :rtype: jpype.JArray[jpype.JByte]
        :raises MemoryAccessException: if the full number of bytes could not be read
        """

    def getParsedLength(self) -> int:
        """
        Get the actual number of bytes parsed when forming this instruction.  While this method
        will generally return the same value as :meth:`getLength() <.getLength>`, its value will differ when
        :meth:`setLengthOverride(int) <.setLengthOverride>` has been used. In addition, it is important to note that
        :meth:`getMaxAddress() <.getMaxAddress>` will always reflect a non-overlapping address which reflects 
        :meth:`getLength() <.getLength>`.
        This method is equivalent to the following code for a given instruction:
         
        
         
        :obj:`InstructionPrototype` proto = instruction.:meth:`getPrototype() <.getPrototype>`;
        int length = proto.:meth:`getLength() <InstructionPrototype.getLength>`;
         
        
        :return: the actual number of bytes parsed when forming this instruction
        :rtype: int
        """

    @typing.overload
    def getPcode(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Get an array of PCode operations (micro code) that this instruction
        performs.  Flow overrides are not factored into pcode.
        
        :return: an array of Pcode operations,
                a zero length array if the language does not support PCode
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    @typing.overload
    def getPcode(self, includeOverrides: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Get an array of PCode operations (micro code) that this instruction
        performs.  NOTE: If includeOverrides is true, unique temporary varnodes
        may be produced which vary in size to those produced for other instructions.
        
        :param jpype.JBoolean or bool includeOverrides: if true any flow overrides will be factored
        into generated pcode.
        :return: an array of Pcode operations,
                a zero length array if the language does not support PCode
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    @typing.overload
    def getPcode(self, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        """
        Get an array of PCode operations (micro code) that a particular operand
        performs to compute its value.
        
        :param jpype.JInt or int opIndex: index of the operand to retrieve PCode
        :return: an array of PCode operations,
                a zero length array if the language does not support PCode
        :rtype: jpype.JArray[ghidra.program.model.pcode.PcodeOp]
        """

    def getPrevious(self) -> Instruction:
        """
        
        
        :return: the instruction before this one in address order or null if none found.
        :rtype: Instruction
        """

    def getPrototype(self) -> ghidra.program.model.lang.InstructionPrototype:
        """
        
        
        :return: the prototype for this instruction.
        :rtype: ghidra.program.model.lang.InstructionPrototype
        """

    def getRegister(self, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Register:
        """
        If operand is a pure Register, return the register.
        
        :param jpype.JInt or int opIndex: index of the operand.
        :return: A register if the operand represents a register.
        :rtype: ghidra.program.model.lang.Register
        """

    def getResultObjects(self) -> jpype.JArray[java.lang.Object]:
        """
        Get the Result objects produced/affected by this instruction
        These would probably only be Register or Address
        
        :return: an array of objects that are affected by this instruction
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getSeparator(self, opIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the separator strings between an operand.
         
        The separator string for 0 are the characters before the first operand.
        The separator string for numOperands+1 are the characters after the last operand.
        
        :param jpype.JInt or int opIndex: valid values are 0 thru numOperands+1
        :return: separator string, or null if there is no string
        :rtype: str
        """

    def hasFallthrough(self) -> bool:
        """
        
        
        :return: true if this instruction has a fall-through flow.
        :rtype: bool
        """

    def isFallThroughOverridden(self) -> bool:
        """
        
        
        :return: true if this instructions fallthrough has been overriden.
        :rtype: bool
        """

    def isFallthrough(self) -> bool:
        """
        
        
        :return: true if this instruction has no execution flow other than fall-through.
        :rtype: bool
        """

    def isInDelaySlot(self) -> bool:
        """
        
        
        :return: true if this instruction was disassembled in a delay slot
        :rtype: bool
        """

    def isLengthOverridden(self) -> bool:
        """
        Determine if an instruction length override has been set.
        
        :return: true if length override has been set else false.
        :rtype: bool
        """

    def setFallThrough(self, addr: ghidra.program.model.address.Address):
        """
        Overrides the instruction's default fallthrough address to the given address.
        The given address may be null to indicate that the instruction has no fallthrough.
        
        :param ghidra.program.model.address.Address addr: the address to be used as this instructions fallthrough address.  May be null.
        """

    def setFlowOverride(self, flowOverride: FlowOverride):
        """
        Set the flow override for this instruction.
        
        :param FlowOverride flowOverride: flow override setting or :obj:`FlowOverride.NONE` to clear.
        """

    def setLengthOverride(self, length: typing.Union[jpype.JInt, int]):
        """
        Set instruction length override.  Specified length must be in the range 0..7 where 0 clears 
        the setting and adopts the default length.  The specified length must be less than the actual 
        number of bytes consumed by the prototype and be a multiple of the language specified 
        instruction alignment. 
         
        
        NOTE: Use of the feature with a delay slot instruction is discouraged.
        
        :param jpype.JInt or int length: effective instruction code unit length.
        :raises CodeUnitInsertionException: if expanding instruction length conflicts with another 
        instruction or length is not a multiple of the language specified instruction alignment.
        """

    @property
    def next(self) -> Instruction:
        ...

    @property
    def fallThrough(self) -> ghidra.program.model.address.Address:
        ...

    @fallThrough.setter
    def fallThrough(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def pcode(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...

    @property
    def flowOverride(self) -> FlowOverride:
        ...

    @flowOverride.setter
    def flowOverride(self, value: FlowOverride):
        ...

    @property
    def operandType(self) -> jpype.JInt:
        ...

    @property
    def parsedBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def defaultOperandRepresentationList(self) -> java.util.List[java.lang.Object]:
        ...

    @property
    def opObjects(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def defaultOperandRepresentation(self) -> java.lang.String:
        ...

    @property
    def flows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def fallFrom(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def defaultFallThrough(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def resultObjects(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def parsedLength(self) -> jpype.JInt:
        ...

    @property
    def operandRefType(self) -> ghidra.program.model.symbol.RefType:
        ...

    @property
    def defaultFlows(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def previous(self) -> Instruction:
        ...

    @property
    def delaySlotDepth(self) -> jpype.JInt:
        ...

    @property
    def defaultFallThroughOffset(self) -> jpype.JInt:
        ...

    @property
    def inDelaySlot(self) -> jpype.JBoolean:
        ...

    @property
    def lengthOverridden(self) -> jpype.JBoolean:
        ...

    @property
    def separator(self) -> java.lang.String:
        ...

    @property
    def prototype(self) -> ghidra.program.model.lang.InstructionPrototype:
        ...

    @property
    def inputObjects(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def fallThroughOverridden(self) -> jpype.JBoolean:
        ...

    @property
    def fallthrough(self) -> jpype.JBoolean:
        ...

    @property
    def instructionContext(self) -> ghidra.program.model.lang.InstructionContext:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType:
        ...


class GhidraClass(ghidra.program.model.symbol.Namespace):
    """
    Interface for representing class objects in the program.
    """

    class_: typing.ClassVar[java.lang.Class]


class Bookmark(java.lang.Comparable[Bookmark]):
    """
    Interface for bookmarks.  Bookmarks are locations that are marked within the program so
    that they can be easily found.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns address at which this bookmark is applied.
        """

    def getCategory(self) -> str:
        """
        Returns bookmark category
        """

    def getComment(self) -> str:
        """
        Returns bookmark comment
        """

    def getId(self) -> int:
        """
        Returns the id of the bookmark.
        """

    def getType(self) -> BookmarkType:
        """
        Returns bookmark type object.
        """

    def getTypeString(self) -> str:
        """
        Returns bookmark type as a string
        """

    def set(self, category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        """
        Set the category and comment associated with a bookmark.
        
        :param java.lang.String or str category: category
        :param java.lang.String or str comment: single line comment
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def typeString(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def id(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> BookmarkType:
        ...

    @property
    def category(self) -> java.lang.String:
        ...


class DuplicateGroupException(ghidra.util.exception.UsrException):
    """
    ``DuplicateGroupException`` is thrown when a fragment or child
    is added to a module and that fragment or module is already a child.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new exception with the default message.
        """

    @typing.overload
    def __init__(self, usrMessage: typing.Union[java.lang.String, str]):
        """
        Creates a new exception with the given user message.
        """


class VariableOffset(java.lang.Object):
    """
    ``VariableOffset`` can be used as an operand or sub-operand representation
    object.  The toString() method should be used to obtain the displayable representation
    string.  This object is intended to correspond to a explicit or implicit register/stack 
    variable reference.  If an offset other than 0 is specified, the original Scalar should
    be specified.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, variable: Variable, offset: typing.Union[jpype.JLong, int], indirect: typing.Union[jpype.JBoolean, bool], dataAccess: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for an implied variable reference.
        
        :param Variable variable: function variable
        :param jpype.JLong or int offset: offset into variable
        :param jpype.JBoolean or bool indirect: if true and variable data-type is a pointer, the offset 
        is relative to underlying data-type of the pointer-type.  This should generally be
        true for register use which would contain a structure pointer not a structure instance,
        whereas it would be false for stack-references.
        :param jpype.JBoolean or bool dataAccess: true if content of variable is being read and/or written
        """

    @typing.overload
    def __init__(self, ref: ghidra.program.model.symbol.Reference, var: Variable):
        """
        Constructor for an explicit variable reference.
        
        :param ghidra.program.model.symbol.Reference ref: the reference
        :param Variable var: the variable being referenced
        """

    def getDataTypeDisplayText(self) -> str:
        """
        Returns the data type access portion of this variable offset as a string
        
        :return: the text
        :rtype: str
        """

    def getObjects(self) -> java.util.List[java.lang.Object]:
        """
        Get list of markup objects
        
        :return: list of markup objects
        :rtype: java.util.List[java.lang.Object]
        """

    def getOffset(self) -> int:
        ...

    def getReplacedElement(self) -> java.lang.Object:
        """
        Returns the Scalar or Register sub-operand replaced by this VariableOffset object.
        
        :return: object or null
        :rtype: java.lang.Object
        """

    def getVariable(self) -> Variable:
        ...

    def isDataAccess(self) -> bool:
        ...

    def isIndirect(self) -> bool:
        ...

    @typing.overload
    def setReplacedElement(self, s: ghidra.program.model.scalar.Scalar, includeScalarAdjustment: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the original replaced sub-operand Scalar.
        
        :param ghidra.program.model.scalar.Scalar s: scalar
        :param jpype.JBoolean or bool includeScalarAdjustment: if true scalar adjustment will be included 
        with object list or string representation
        """

    @typing.overload
    def setReplacedElement(self, reg: ghidra.program.model.lang.Register):
        """
        Sets the original replaced sub-operand Register.
        """

    @property
    def dataAccess(self) -> jpype.JBoolean:
        ...

    @property
    def indirect(self) -> jpype.JBoolean:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def replacedElement(self) -> java.lang.Object:
        ...

    @property
    def objects(self) -> java.util.List[java.lang.Object]:
        ...

    @property
    def variable(self) -> Variable:
        ...

    @property
    def dataTypeDisplayText(self) -> java.lang.String:
        ...


class FunctionTag(java.lang.Comparable[FunctionTag]):
    """
    Represents a function tag object that can be associated with 
    functions. This maps to the  ``FunctionTagAdapter`` table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def delete(self):
        """
        Deletes this tag from the program
        """

    def getComment(self) -> str:
        """
        Returns the tag comment
        
        :return: the tag comment
        :rtype: str
        """

    def getId(self) -> int:
        """
        Returns the id of the item
        
        :return: the id of the item
        :rtype: int
        """

    def getName(self) -> str:
        """
        Returns the tag name
        
        :return: the tag name
        :rtype: str
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Sets the comment for this tag
        
        :param java.lang.String or str comment: the tag comment
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of the tag
        
        :param java.lang.String or str name: the tag name
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def id(self) -> jpype.JLong:
        ...


class DomainObjectChangeSet(java.lang.Object):
    """
    Interface for a domain object change set.  Objects that implements this interface track
    various change information on a domain object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasChanges(self) -> bool:
        ...


class CommentHistory(java.lang.Object):
    """
    Container class for information about changes to a comment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, commentType: CommentType, userName: typing.Union[java.lang.String, str], comments: typing.Union[java.lang.String, str], modificationDate: java.util.Date):
        """
        Constructs a new CommentHistory object
        
        :param ghidra.program.model.address.Address addr: the address of the comment
        :param CommentType commentType: the type of comment
        :param java.lang.String or str userName: the name of the user that changed the comment
        :param java.lang.String or str comments: the list of comments.
        :param java.util.Date modificationDate: the date the comment was changed.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get address for this label history object
        
        :return: address for this label history object.
        :rtype: ghidra.program.model.address.Address
        """

    def getCommentType(self) -> CommentType:
        """
        Get the comment type
        
        :return: the comment type
        :rtype: CommentType
        """

    def getComments(self) -> str:
        """
        Get the comments for this history object
        
        :return: the comments for this history object
        :rtype: str
        """

    def getModificationDate(self) -> java.util.Date:
        """
        Get the modification date
        
        :return: the modification date
        :rtype: java.util.Date
        """

    def getUserName(self) -> str:
        """
        Get the user that made the change
        
        :return: the user that made the change
        :rtype: str
        """

    @property
    def modificationDate(self) -> java.util.Date:
        ...

    @property
    def comments(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def commentType(self) -> CommentType:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...


class ProgramTreeChangeSet(ghidra.framework.model.ChangeSet):
    """
    Interface for a Program Tree Change set.  Objects that implements this interface track
    various change information on a program tree manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getProgramTreeAdditions(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of program tree IDs that have been added.
        """

    def getProgramTreeChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of program tree IDs that have changed.
        """

    def programTreeAdded(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the program tree id to the list of trees that have been added.
        """

    def programTreeChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the program tree id to the list of trees that have changed.
        """

    @property
    def programTreeAdditions(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def programTreeChanges(self) -> jpype.JArray[jpype.JLong]:
        ...


class CodeUnitComments(java.lang.Object):
    """
    Container for all the comments at an address
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comments: jpype.JArray[java.lang.String]):
        ...

    def getComment(self, type: CommentType) -> str:
        """
        Get the comment for the given comment type
        
        :param CommentType type: the :obj:`CommentType` to retrieve
        :return: the comment of the given type or null if no comment of that type exists
        :rtype: str
        """

    @property
    def comment(self) -> java.lang.String:
        ...


class Group(java.lang.Object):
    """
    The interface for groupings of code units that may have attributes such
    as names and comments.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, codeUnit: CodeUnit) -> bool:
        """
        Returns whether this fragment contains the given code unit.
        
        :param CodeUnit codeUnit: the code unit being tested.
        :return: true if the code unit is in the fragment, false otherwise.
        :rtype: bool
        """

    def getComment(self) -> str:
        """
        Obtains the comment that has been associated with this fragment or module.
        
        :return: may be null.
        :rtype: str
        """

    def getGroupPath(self) -> ghidra.program.util.GroupPath:
        """
        Returns one of many possible GroupPaths for this group. Since Fragments can belong in
        more than one module, there can be multiple legitimate group paths for a group. This method
        arbitrarily returns one valid group path.
        
        :return: one of several possible group paths for this group
        :rtype: ghidra.program.util.GroupPath
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getName(self) -> str:
        """
        Obtains the name that has been associated with this fragment. A fragment will
        always have a name and it will be unique within the set of all fragment and
        module names.
        """

    def getNumParents(self) -> int:
        """
        Obtains the number of parent's of this fragment. If a fragment is in a module
        then the module is a *parent* of the fragment and the fragment is a
        *child* of the module. A fragment must have at least one parent and it
        may have multiple parents.
        
        :return: the number of parents of this fragment.
        :rtype: int
        """

    def getParentNames(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the names of the modules which are parents to this
        fragment.
        """

    def getParents(self) -> jpype.JArray[ProgramModule]:
        """
        Returns a list of the modules which are parents for this group.
        """

    def getTreeName(self) -> str:
        """
        Returns the name of the tree that this group belongs to.
        """

    def isDeleted(self) -> bool:
        """
        Returns true if this group has been deleted from the program
        
        :return: true if this group has been deleted from the program
        :rtype: bool
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Sets the comment to associate with this fragment.
        
        :param java.lang.String or str comment: the comment.
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of this fragment.
        
        :param java.lang.String or str name: the string to use for the fragment's name.
        :raises DuplicateNameException: thrown if the name being set is already in use by another fragment or a
                        module.
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def parentNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def treeName(self) -> java.lang.String:
        ...

    @property
    def numParents(self) -> jpype.JInt:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def groupPath(self) -> ghidra.program.util.GroupPath:
        ...

    @property
    def parents(self) -> jpype.JArray[ProgramModule]:
        ...


class RepeatableComment(java.lang.Object):
    """
    Interface to define a comment that can be shared by more 
    than one code unit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComment(self) -> str:
        """
        Get the text of the repeatable comment.
        
        :return: comment
        :rtype: str
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the text of this repeatable comment.
        
        :param java.lang.String or str comment: new text for the repeatable comment
        """

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...


class OperandRepresentationList(java.util.ArrayList[java.lang.Object]):
    """
    ``OperandRepresentation`` provides a list for operand sub-elements.
    The number of elements are expected to remain constant for a given code unit
    operand regardless of its format.
     
    
    The list may contain various Objects including any combination of Character,
    String, VariableOffset, Register, Address, Scalar, LabelString, and 
    nesting of other OperandRepresentationList objects.
     
     
    All objects returned must support the toString() method for producing
    an appropriate listing representation.
    """

    class_: typing.ClassVar[java.lang.Class]

    def hasError(self) -> bool:
        """
        Returns true if the representation encountered an error.
        Error will be reflected within the representation as a String.
        """

    def isPrimaryReferenceHidden(self) -> bool:
        """
        Returns true if the primary reference is not reflected in the representation.
        """

    def toString(self) -> str:
        """
        Returns a formatted string representation of the specified code unit operand.
        
        :return: formatted code unit representation
        :rtype: str
        """

    @property
    def primaryReferenceHidden(self) -> jpype.JBoolean:
        ...


class SymbolChangeSet(ghidra.framework.model.ChangeSet):
    """
    Interface for a Symbol Change set.  Objects that implements this interface track
    various change information on a symbol manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getSymbolAdditions(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of symbols IDs that have been added.
        """

    def getSymbolChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of symbol IDs that have changed.
        """

    def symbolAdded(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the symbols id to the list of symbols that have been added.
        """

    def symbolChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the symbol id to the list of symbols that have changed.
        """

    @property
    def symbolChanges(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def symbolAdditions(self) -> jpype.JArray[jpype.JLong]:
        ...


class LabelString(java.lang.Object):

    class LabelType(java.lang.Enum[LabelString.LabelType]):

        class_: typing.ClassVar[java.lang.Class]
        CODE_LABEL: typing.Final[LabelString.LabelType]
        VARIABLE: typing.Final[LabelString.LabelType]
        EXTERNAL: typing.Final[LabelString.LabelType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LabelString.LabelType:
            ...

        @staticmethod
        def values() -> jpype.JArray[LabelString.LabelType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CODE_LABEL: typing.Final[LabelString.LabelType]
    VARIABLE: typing.Final[LabelString.LabelType]
    EXTERNAL: typing.Final[LabelString.LabelType]

    def __init__(self, label: typing.Union[java.lang.String, str], type: LabelString.LabelType):
        ...

    def getLabelType(self) -> LabelString.LabelType:
        ...

    @property
    def labelType(self) -> LabelString.LabelType:
        ...


class Program(ghidra.program.model.data.DataTypeManagerDomainObject, ghidra.program.model.lang.ProgramArchitecture):
    """
    This interface represents the main entry point into an object which
    stores all information relating to a single program.  This program
    model divides a program into four major parts: the memory, the symbol table,
    the equate table, and the listing.  Each of these parts has an extensive
    interface and can be retrieved via this program interface.  Although the
    components are divided into separate objects, they are not independent.  Any
    changes to one component may and probably will affect the other components.
    Also, the state of one component will restrict the actions of another
    component.
    For example, the createCodeUnit() method of listing will fail if memory is
    undefined at the address where the codeUnit is to be created.
    """

    class_: typing.ClassVar[java.lang.Class]
    ANALYSIS_PROPERTIES: typing.Final = "Analyzers"
    DISASSEMBLER_PROPERTIES: typing.Final = "Disassembler"
    PROGRAM_INFO: typing.Final = "Program Information"
    """
    Options for storing program info
    """

    ANALYZED_OPTION_NAME: typing.Final = "Analyzed"
    """
    Name of boolean analyzed property
    """

    ASK_TO_ANALYZE_OPTION_NAME: typing.Final = "Should Ask To Analyze"
    """
    Property to control if user should be asked to analyze when unanalyzed program opened
    """

    DATE_CREATED: typing.Final = "Date Created"
    """
    Date created property
    """

    CREATED_WITH_GHIDRA_VERSION: typing.Final = "Created With Ghidra Version"
    """
    Ghidra version property
    """

    PREFERRED_ROOT_NAMESPACE_CATEGORY_PROPERTY: typing.Final = "Preferred Root Namespace Category"
    """
    Ghidra preferred root namespace category property
    """

    ANALYSIS_START_DATE: typing.Final = "2007-Jan-01"
    """
    Creation date for analysis
    """

    ANALYSIS_START_DATE_FORMAT: typing.Final = "yyyy-MMM-dd"
    """
    Format string of analysis date
    """

    JANUARY_1_1970: typing.Final[java.util.Date]
    """
    A date from January 1, 1970
    """

    MAX_OPERANDS: typing.Final = 16
    """
    The maximum number of operands for any assembly language
    """


    def createAddressSetPropertyMap(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.AddressSetPropertyMap:
        """
        Create a new AddressSetPropertyMap with the specified name.
        
        :param java.lang.String or str name: name of the property map.
        :return: the newly created property map.
        :rtype: ghidra.program.model.util.AddressSetPropertyMap
        :raises DuplicateNameException: if a property map already exists with the given name.
        """

    def createIntRangeMap(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.database.IntRangeMap:
        """
        Create a new IntRangeMap with the specified name.
        
        :param java.lang.String or str name: name of the property map.
        :return: the newly created property map.
        :rtype: ghidra.program.database.IntRangeMap
        :raises DuplicateNameException: if a property map already exists with the given name.
        """

    def createOverlaySpace(self, overlaySpaceName: typing.Union[java.lang.String, str], baseSpace: ghidra.program.model.address.AddressSpace) -> ghidra.program.database.ProgramOverlayAddressSpace:
        """
        Create a new overlay space based upon the given base AddressSpace
        
        :param java.lang.String or str overlaySpaceName: the name of the new overlay space.
        :param ghidra.program.model.address.AddressSpace baseSpace: the base AddressSpace to overlay (i.e., overlayed-space)
        :return: the new overlay space
        :rtype: ghidra.program.database.ProgramOverlayAddressSpace
        :raises DuplicateNameException: if an address space already exists with specified overlaySpaceName.
        :raises LockException: if the program is shared and not checked out exclusively.
        :raises java.lang.IllegalStateException: if image base override is active
        :raises InvalidNameException: if overlaySpaceName contains invalid characters
        """

    def deleteAddressSetPropertyMap(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the property map from the program.
        
        :param java.lang.String or str name: name of the property map to remove
        """

    def deleteIntRangeMap(self, name: typing.Union[java.lang.String, str]):
        """
        Remove the property map from the program.
        
        :param java.lang.String or str name: name of the property map to remove
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Returns the AddressFactory for this program.
        
        :return: the program address factory
        :rtype: ghidra.program.model.address.AddressFactory
        """

    @deprecated("Method intended for internal ProgramDB use and is not intended for general use.\n This method may be removed from this interface in a future release.")
    def getAddressMap(self) -> ghidra.program.database.map.AddressMap:
        """
        Get the internal program address map
        
        :return: internal address map
        :rtype: ghidra.program.database.map.AddressMap
        
        .. deprecated::
        
        Method intended for internal ProgramDB use and is not intended for general use.
        This method may be removed from this interface in a future release.
        """

    def getAddressSetPropertyMap(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.AddressSetPropertyMap:
        """
        Get the property map with the given name.
        
        :param java.lang.String or str name: name of the property map
        :return: null if no property map exist with the given name
        :rtype: ghidra.program.model.util.AddressSetPropertyMap
        """

    def getBookmarkManager(self) -> BookmarkManager:
        """
        Get the bookmark manager.
        
        :return: the bookmark manager
        :rtype: BookmarkManager
        """

    def getChanges(self) -> ProgramChangeSet:
        """
        Get the program changes since the last save as a set of addresses.
        
        :return: set of changed addresses within program.
        :rtype: ProgramChangeSet
        """

    def getCompiler(self) -> str:
        """
        Gets the name of the compiler believed to have been used to create this program.
        If the compiler hasn't been determined then "unknown" is returned.
        
        :return: name of the compiler or "unknown".
        :rtype: str
        """

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        """
        Returns the CompilerSpec currently used by this program.
        
        :return: the compilerSpec currently used by this program.
        :rtype: ghidra.program.model.lang.CompilerSpec
        """

    def getCreationDate(self) -> java.util.Date:
        """
        Returns the creation date of this program.
        If the program was created before this property
        existed, then Jan 1, 1970 is returned.
        
        :return: the creation date of this program
        :rtype: java.util.Date
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.ProgramBasedDataTypeManager:
        """
        Returns the program's datatype manager.
        """

    def getDefaultPointerSize(self) -> int:
        """
        Gets the default pointer size in bytes as it may be stored within the program listing.
        
        :return: default pointer size.
        :rtype: int
        
        .. seealso::
        
            | :obj:`DataOrganization.getPointerSize()`
        """

    def getEquateTable(self) -> ghidra.program.model.symbol.EquateTable:
        """
        Get the equate table object.
        
        :return: the equate table.
        :rtype: ghidra.program.model.symbol.EquateTable
        """

    def getExecutableFormat(self) -> str:
        """
        Returns a value corresponding to the original file format.
        
        :return: original file format used to load program or null if unknown
        :rtype: str
        """

    def getExecutableMD5(self) -> str:
        """
        Returns a value corresponding to the original binary file MD5 hash.
        
        :return: original loaded file MD5 or null
        :rtype: str
        """

    def getExecutablePath(self) -> str:
        """
        Gets the path to the program's executable file. For example, ``/home/user/foo.exe``.
        This will allow plugins to execute the program.
         
        
        NOTE: The format of the path is not guaranteed to follow any standard naming conventions.
        If used for anything other than display purpose, callers of this method should take extra
        steps to ensure the path is in a form suitable for their needs.
        
        :return: String  path to program's exe file
        :rtype: str
        """

    def getExecutableSHA256(self) -> str:
        """
        Returns a value corresponding to the original binary file SHA256 hash.
        
        :return: original loaded file SHA256 or null
        :rtype: str
        """

    def getExternalManager(self) -> ghidra.program.model.symbol.ExternalManager:
        """
        Returns the external manager.
        
        :return: the external manager
        :rtype: ghidra.program.model.symbol.ExternalManager
        """

    def getFunctionManager(self) -> FunctionManager:
        """
        Returns the programs function manager.
        
        :return: the function manager
        :rtype: FunctionManager
        """

    def getGlobalNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the global namespace for this program
        
        :return: the global namespace
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getImageBase(self) -> ghidra.program.model.address.Address:
        """
        Returns the current program image base address
        
        :return: program image base address within default space
        :rtype: ghidra.program.model.address.Address
        """

    def getIntRangeMap(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.database.IntRangeMap:
        """
        Get the property map with the given name.
        
        :param java.lang.String or str name: name of the property map
        :return: null if no property map exist with the given name
        :rtype: ghidra.program.database.IntRangeMap
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Returns the language used by this program.
        
        :return: the language used by this program.
        :rtype: ghidra.program.model.lang.Language
        """

    def getLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        """
        Return the name of the language used by this program.
        
        :return: the name of the language
        :rtype: ghidra.program.model.lang.LanguageID
        """

    def getListing(self) -> Listing:
        """
        Get the listing object.
        
        :return: the Listing interface to the listing object.
        :rtype: Listing
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the programs maximum address.
        NOTE: An :obj:`AddressRange` should generally not be formed using this address
        and :meth:`getMinAddress() <.getMinAddress>` since it may span multiple :obj:`AddressSpace`s.
        
        :return: the program's maximum address or null if no memory blocks
        have been defined in the program.
        :rtype: ghidra.program.model.address.Address
        """

    def getMemory(self) -> ghidra.program.model.mem.Memory:
        """
        Get the memory object.
        
        :return: the memory object.
        :rtype: ghidra.program.model.mem.Memory
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the program's minimum address.
        NOTE: An :obj:`AddressRange` should generally not be formed using this address
        and :meth:`getMaxAddress() <.getMaxAddress>` since it may span multiple :obj:`AddressSpace`s.
        
        :return: the program's minimum address or null if no memory blocks
        have been defined in the program.
        :rtype: ghidra.program.model.address.Address
        """

    def getPreferredRootNamespaceCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Gets the preferred root data type category path which corresponds
        to the global namespace of a namespace-based storage area.  Preference
        will be given to this category when searching for data types
        within a specific namespace.
         
        This setting corresponds to the Program Information option 
        *"Preferred Root Namespace Category*.  See :obj:`DataTypeUtilities` 
        and its various find methods for its usage details.
        
        :return: data type category path for root namespace or null if not set or is invalid.
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getProgramContext(self) -> ProgramContext:
        """
        Returns the program context.
        
        :return: the program context object
        :rtype: ProgramContext
        """

    def getProgramUserData(self) -> ProgramUserData:
        """
        Returns the user-specific data manager for
        this program.
        
        :return: the program-specific user data manager
        :rtype: ProgramUserData
        """

    def getReferenceManager(self) -> ghidra.program.model.symbol.ReferenceManager:
        """
        Get the reference manager.
        
        :return: the reference manager
        :rtype: ghidra.program.model.symbol.ReferenceManager
        """

    @typing.overload
    def getRegister(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.Register:
        """
        Returns the register with the given name;
        
        :param java.lang.String or str name: the name of the register to retrieve
        :return: register or null
        :rtype: ghidra.program.model.lang.Register
        """

    @typing.overload
    def getRegister(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.Register:
        """
        Returns the largest register located at the specified address
        
        :param ghidra.program.model.address.Address addr: register minimum address
        :return: largest register at addr or null
        :rtype: ghidra.program.model.lang.Register
        """

    @typing.overload
    def getRegister(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Register:
        """
        Returns a specific register based upon its address and size
        
        :param ghidra.program.model.address.Address addr: register address
        :param jpype.JInt or int size: the size of the register (in bytes);
        :return: register or null
        :rtype: ghidra.program.model.lang.Register
        """

    @typing.overload
    def getRegister(self, varnode: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.lang.Register:
        """
        Returns the register which corresponds to the specified varnode
        
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        :return: register or null
        :rtype: ghidra.program.model.lang.Register
        """

    def getRegisters(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.lang.Register]:
        """
        Returns all registers located at the specified address
        
        :param ghidra.program.model.address.Address addr: register minimum address
        :return: all registers at addr
        :rtype: jpype.JArray[ghidra.program.model.lang.Register]
        """

    def getRelocationTable(self) -> ghidra.program.model.reloc.RelocationTable:
        """
        Gets the relocation table.
        
        :return: relocation table object
        :rtype: ghidra.program.model.reloc.RelocationTable
        """

    def getSourceFileManager(self) -> ghidra.program.model.sourcemap.SourceFileManager:
        """
        Returns the program's :obj:`SourceFileManager`.
        
        :return: the source file manager
        :rtype: ghidra.program.model.sourcemap.SourceFileManager
        """

    def getSymbolTable(self) -> ghidra.program.model.symbol.SymbolTable:
        """
        Get the symbol table object.
        
        :return: the symbol table object.
        :rtype: ghidra.program.model.symbol.SymbolTable
        """

    def getUniqueProgramID(self) -> int:
        """
        Returns an ID that is unique for this program.  This provides an easy way to store
        references to a program across client persistence.
        
        :return: unique program ID
        :rtype: int
        """

    def getUsrPropertyManager(self) -> ghidra.program.model.util.PropertyMapManager:
        """
        Get the user propertyMangager stored with this program. The user property
        manager is used to store arbitrary address indexed information associated
        with the program.
        
        :return: the user property manager.
        :rtype: ghidra.program.model.util.PropertyMapManager
        """

    @typing.overload
    def parseAddress(self, addrStr: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Return an array of Addresses that could represent the given
        string.
        
        :param java.lang.String or str addrStr: the string to parse.
        :return: zero length array if addrStr is properly formatted but
        no matching addresses were found or if the address is improperly formatted.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @typing.overload
    def parseAddress(self, addrStr: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Return an array of Addresses that could represent the given
        string.
        
        :param java.lang.String or str addrStr: the string to parse.
        :param jpype.JBoolean or bool caseSensitive: whether or not to process any addressSpace names as case sensitive.
        :return: zero length array if addrStr is properly formatted but
        no matching addresses were found or if the address is improperly formatted.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    def removeOverlaySpace(self, overlaySpaceName: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove the specified overlay address space from this program.
        
        :param java.lang.String or str overlaySpaceName: overlay address space name
        :return: true if successfully removed, else false if blocks still make use of overlay space.
        :rtype: bool
        :raises LockException: if program does not has exclusive access
        :raises NotFoundException: if specified overlay space not found in program
        """

    def renameOverlaySpace(self, overlaySpaceName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Rename an existing overlay address space.  
        NOTE: This experimental method has known limitations with existing :obj:`Address` and 
        :obj:`AddressSpace` objects following an undo/redo which may continue to refer to the old 
        overlay name which may lead to unxpected errors.
        
        :param java.lang.String or str overlaySpaceName: overlay address space name
        :param java.lang.String or str newName: new name for overlay
        :raises NotFoundException: if the specified overlay space was not found
        :raises InvalidNameException: if new name is invalid
        :raises DuplicateNameException: if new name already used by another address space
        :raises LockException: if program does not has exclusive access
        """

    def restoreImageBase(self):
        """
        Restores the last committed image base.
        """

    def setCompiler(self, compiler: typing.Union[java.lang.String, str]):
        """
        Sets the name of the compiler which created this program.
        
        :param java.lang.String or str compiler: the name
        """

    def setExecutableFormat(self, format: typing.Union[java.lang.String, str]):
        """
        Sets the value corresponding to the original file format.
        
        :param java.lang.String or str format: the binary file format string to set.
        """

    def setExecutableMD5(self, md5: typing.Union[java.lang.String, str]):
        """
        Sets the value corresponding to the original binary file MD5 hash.
        
        :param java.lang.String or str md5: MD5 binary file hash
        """

    def setExecutablePath(self, path: typing.Union[java.lang.String, str]):
        """
        Sets the path to the program's executable file. For example, ``/home/user/foo.exe``.
        
        :param java.lang.String or str path: the path to the program's exe
        """

    def setExecutableSHA256(self, sha256: typing.Union[java.lang.String, str]):
        """
        Sets the value corresponding to the original binary file SHA256 hash.
        
        :param java.lang.String or str sha256: SHA256 binary file hash
        """

    def setImageBase(self, base: ghidra.program.model.address.Address, commit: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the program's image base address.
        
        :param ghidra.program.model.address.Address base: the new image base address;
        :param jpype.JBoolean or bool commit: if false, then the image base change is temporary and does not really change
        the program and will be lost once the program is closed.  If true, the change is permanent
        and marks the program as "changed" (needs saving).
        :raises AddressOverflowException: if the new image would cause a memory block to end past the
        the address space.
        :raises LockException: if the program is shared and the user does not have an exclusive checkout.
        This will never be thrown if commit is false.
        :raises java.lang.IllegalStateException: if the program state is not suitable for setting the image base.
        """

    def setLanguage(self, language: ghidra.program.model.lang.Language, compilerSpecID: ghidra.program.model.lang.CompilerSpecID, forceRedisassembly: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Sets the language for the program. If the new language is "compatible" with the old language,
        the addressMap is adjusted then the program is "re-disassembled".
        
        :param ghidra.program.model.lang.Language language: the new language to use.
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecID: the new compiler specification ID
        :param jpype.JBoolean or bool forceRedisassembly: if true a redisassembly will be forced.  This should always be false.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises java.lang.IllegalStateException: thrown if any error occurs, including a cancelled monitor, which leaves this 
        program object in an unusable state.  The current transaction should be aborted and the program instance
        discarded.
        :raises IncompatibleLanguageException: thrown if the new language is too different from the
        existing language.
        :raises LockException: if the program is shared and not checked out exclusively.
        """

    def setPreferredRootNamespaceCategoryPath(self, categoryPath: typing.Union[java.lang.String, str]):
        """
        Sets the preferred data type category path which corresponds
        to the root of a namespace hierarchy storage area.  Preference
        will be given to this category when searching for data types
        within a specific namespace.
         
        This setting corresponds to the Program Information option 
        *"Preferred Root Namespace Category*.  See :obj:`DataTypeUtilities` 
        and its various find methods for its usage details.
        
        :param java.lang.String or str categoryPath: data type category path for root namespace or null 
        to clear option.  The specified path must be absolute and start with "/"
        and must not end with one (e.g., */ClassDataTypes*).  An invalid
        path setting will be ignored.
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def memory(self) -> ghidra.program.model.mem.Memory:
        ...

    @property
    def languageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def changes(self) -> ProgramChangeSet:
        ...

    @property
    def usrPropertyManager(self) -> ghidra.program.model.util.PropertyMapManager:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def executableMD5(self) -> java.lang.String:
        ...

    @executableMD5.setter
    def executableMD5(self, value: java.lang.String):
        ...

    @property
    def sourceFileManager(self) -> ghidra.program.model.sourcemap.SourceFileManager:
        ...

    @property
    def functionManager(self) -> FunctionManager:
        ...

    @property
    def equateTable(self) -> ghidra.program.model.symbol.EquateTable:
        ...

    @property
    def bookmarkManager(self) -> BookmarkManager:
        ...

    @property
    def imageBase(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programContext(self) -> ProgramContext:
        ...

    @property
    def registers(self) -> jpype.JArray[ghidra.program.model.lang.Register]:
        ...

    @property
    def globalNamespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def listing(self) -> Listing:
        ...

    @property
    def compiler(self) -> java.lang.String:
        ...

    @compiler.setter
    def compiler(self, value: java.lang.String):
        ...

    @property
    def uniqueProgramID(self) -> jpype.JLong:
        ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def preferredRootNamespaceCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def executableFormat(self) -> java.lang.String:
        ...

    @executableFormat.setter
    def executableFormat(self, value: java.lang.String):
        ...

    @property
    def addressSetPropertyMap(self) -> ghidra.program.model.util.AddressSetPropertyMap:
        ...

    @property
    def symbolTable(self) -> ghidra.program.model.symbol.SymbolTable:
        ...

    @property
    def intRangeMap(self) -> ghidra.program.database.IntRangeMap:
        ...

    @property
    def executableSHA256(self) -> java.lang.String:
        ...

    @executableSHA256.setter
    def executableSHA256(self, value: java.lang.String):
        ...

    @property
    def addressMap(self) -> ghidra.program.database.map.AddressMap:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def referenceManager(self) -> ghidra.program.model.symbol.ReferenceManager:
        ...

    @property
    def creationDate(self) -> java.util.Date:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    @property
    def programUserData(self) -> ProgramUserData:
        ...

    @property
    def externalManager(self) -> ghidra.program.model.symbol.ExternalManager:
        ...

    @property
    def executablePath(self) -> java.lang.String:
        ...

    @executablePath.setter
    def executablePath(self, value: java.lang.String):
        ...

    @property
    def relocationTable(self) -> ghidra.program.model.reloc.RelocationTable:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.ProgramBasedDataTypeManager:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def defaultPointerSize(self) -> jpype.JInt:
        ...


@typing.type_check_only
class VariableImpl(Variable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Construct a stack variable at the specified stack offset.
        
        :param java.lang.String or str name: variable name or null for default naming
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: signed stack offset
        :param Program program: target program
        :param ghidra.program.model.symbol.SourceType sourceType: source type
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        :raises AddressOutOfBoundsException: if invalid stack offset specified
        """


class CodeUnitIterator(java.util.Iterator[CodeUnit], java.lang.Iterable[CodeUnit]):
    """
    Interface to define an iterator over some set of code units.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ITERATOR: typing.Final[CodeUnitIterator]

    def hasNext(self) -> bool:
        """
        Return true if there is a next CodeUnit.
        """

    def next(self) -> CodeUnit:
        """
        Get the next CodeUnit or null if no more CodeUnits.
         
        NOTE: This deviates from the standard :obj:`Iterator` interface
        by returning null instead of throwing an exception.
        """


class CommentType(java.lang.Enum[CommentType]):
    """
    Types of comments that be placed at an address or on a :obj:`CodeUnit`
    """

    class_: typing.ClassVar[java.lang.Class]
    EOL: typing.Final[CommentType]
    PRE: typing.Final[CommentType]
    POST: typing.Final[CommentType]
    PLATE: typing.Final[CommentType]
    REPEATABLE: typing.Final[CommentType]

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> CommentType:
        ...

    @staticmethod
    @typing.overload
    def valueOf(commentType: typing.Union[jpype.JInt, int]) -> CommentType:
        """
        Get the comment type which corresponds to the specified ordinal value.
         
        
        NOTE: This method is intended for conversion of old legacy commentType integer
        values to the enum type.
        
        :param jpype.JInt or int commentType: comment type value
        :return: comment type enum which corresponds to specified ordinal
        :rtype: CommentType
        :raises java.lang.IllegalArgumentException: if invalid comment type ordinal specified
        """

    @staticmethod
    def values() -> jpype.JArray[CommentType]:
        ...


class DataBuffer(java.lang.Object):
    """
    DataBuffer provides an array like interface into a set of Data
    at a specific index.  Data can be retrieved by using a positive
    offset from the current position.  The purpose of this class is to
    provide an opaque storage mechanism for Data that is made up of other
    Data items.
    
    This interface does not provide methods to reposition the data item
    buffer.  This is so that it is clear that methods accepeting this
    base class are not to mess which the base Address for this object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the Address which corresponds to the offset 0.
        
        :return: the current address of offset 0.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getData(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Get one Data item from the buffer at the current position plus offset.
        
        :param jpype.JInt or int offset: the displacement from the current position.
        :return: the Data item at offset from the current position.
        :rtype: Data
        :raises ghidra.program.model.address.AddressOutOfBoundsException: if offset exceeds
        address space
        :raises IndexOutOfBoundsException: if offset is negative
        """

    @typing.overload
    def getData(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> jpype.JArray[Data]:
        """
        Get an array of data items that begin at or after start up to end.
        Data items that exist before start are not returned
        Data items that exist before end, but terminate after end ARE returned
        
        :param jpype.JInt or int start: start offset
        :param jpype.JInt or int end: end offset
        :return: array of CodeDatas that exist between start and end.
        :rtype: jpype.JArray[Data]
        """

    def getDataAfter(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Get the next data item starting after offset.
        
        :param jpype.JInt or int offset: offset to look after
        :return: Data item starting after this offset
        :rtype: Data
        """

    def getDataBefore(self, offset: typing.Union[jpype.JInt, int]) -> Data:
        """
        Get the previous data item starting before offset.
        
        :param jpype.JInt or int offset: offset to look before
        :return: Data item starting before this offset
        :rtype: Data
        """

    def getNextOffset(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the offset to the next data item found after offset.
        
        :param jpype.JInt or int offset: offset to look after
        :return: offset of the first data item existing after this one.
        :rtype: int
        """

    def getPreviousOffset(self, offset: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the offset to the previous data item existing before this offset.
        
        :param jpype.JInt or int offset: offset to look before
        :return: offset of the first data item existing before this one.
        :rtype: int
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def data(self) -> Data:
        ...

    @property
    def previousOffset(self) -> jpype.JInt:
        ...

    @property
    def dataAfter(self) -> Data:
        ...

    @property
    def dataBefore(self) -> Data:
        ...

    @property
    def nextOffset(self) -> jpype.JInt:
        ...


class LocalVariable(Variable):

    class_: typing.ClassVar[java.lang.Class]

    def setFirstUseOffset(self, firstUseOffset: typing.Union[jpype.JInt, int]) -> bool:
        """
        Set the first use offset.
        
        :param jpype.JInt or int firstUseOffset: 
        :return: true if successful, else false
        :rtype: bool
        """


class ProgramChangeSet(DomainObjectChangeSet, AddressChangeSet, RegisterChangeSet, DataTypeChangeSet, ProgramTreeChangeSet, SymbolChangeSet, FunctionTagChangeSet):
    """
    Interface for a Program Change set.  Objects that implements this interface track
    various change information on a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddressSetCollectionSinceCheckout(self) -> ghidra.program.model.address.AddressSetCollection:
        """
        Gets an AddressSetCollection which contains the addressSets that track all the addresses
        where changes have occurred since the file was checked out. If the file is not versioned,
        this AddressSetCollection will be empty.
        
        :return: AddressSetCollection containing all addresses that changed since the program was checked out.
        :rtype: ghidra.program.model.address.AddressSetCollection
        """

    def getAddressSetCollectionSinceLastSave(self) -> ghidra.program.model.address.AddressSetCollection:
        """
        Gets an AddressSetCollection which contains the addressSets that track all the addresses
        where changes have occurred since the last save.
        
        :return: AddressSetCollection containing all addresses that changed since the last save.
        :rtype: ghidra.program.model.address.AddressSetCollection
        """

    @property
    def addressSetCollectionSinceCheckout(self) -> ghidra.program.model.address.AddressSetCollection:
        ...

    @property
    def addressSetCollectionSinceLastSave(self) -> ghidra.program.model.address.AddressSetCollection:
        ...


class ThunkFunction(Function):
    """
    ``ThunkFunction`` corresponds to a fragment of code which simply passes control
    to a destination function.  All Function behaviors are mapped through to the current
    destination function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDestinationFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        Returns the current destination function entry point address.
        A function should exist at the specified address although there is no guarantee.
        If the address is within the EXTERNAL space, this a place-holder for a an external
        library function.
        
        :return: destination function entry point address
        :rtype: ghidra.program.model.address.Address
        """

    def setDestinationFunction(self, function: Function):
        """
        Set the destination function which corresponds to this thunk.
        
        :param Function function: destination function
        """

    @property
    def destinationFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        ...


class CodeUnit(ghidra.program.model.mem.MemBuffer, ghidra.program.model.util.PropertySet):
    """
    Interface common to both instructions and data.
    """

    class_: typing.ClassVar[java.lang.Class]
    MNEMONIC: typing.Final = -1
    """
    Indicator for a mnemonic (versus an operand).
    """

    EOL_COMMENT: typing.Final = 0
    """
    comment type for end of line
    
    
    .. deprecated::
    
    use :obj:`CommentType.EOL`
    """

    PRE_COMMENT: typing.Final = 1
    """
    comment type that goes before a code unit
    
    
    .. deprecated::
    
    use :obj:`CommentType.PRE`
    """

    POST_COMMENT: typing.Final = 2
    """
    comment type that follows after a code unit
    
    
    .. deprecated::
    
    use :obj:`CommentType.POST`
    """

    PLATE_COMMENT: typing.Final = 3
    """
    Property name for plate comment type
    
    
    .. deprecated::
    
    use :obj:`CommentType.POST`
    """

    REPEATABLE_COMMENT: typing.Final = 4
    """
    Property name for repeatable comment type
    
    
    .. deprecated::
    
    use :obj:`CommentType.REPEATABLE`
    """

    COMMENT_PROPERTY: typing.Final = "COMMENT__GHIDRA_"
    """
    Any comment property.
    """

    SPACE_PROPERTY: typing.Final = "Space"
    """
    Property name for vertical space formatting
    """

    INSTRUCTION_PROPERTY: typing.Final = "INSTRUCTION__GHIDRA_"
    """
    Property name for code units that are instructions
    """

    DEFINED_DATA_PROPERTY: typing.Final = "DEFINED_DATA__GHIDRA_"
    """
    Property name for code units that are defined data
    """


    def addMnemonicReference(self, refAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Add a reference to the mnemonic for this code unit.
        
        :param ghidra.program.model.address.Address refAddr: address to add as a reference.
        :param ghidra.program.model.symbol.RefType refType: the type of reference to add.
        :param ghidra.program.model.symbol.SourceType sourceType: the source of this reference
        """

    def addOperandReference(self, index: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address, type: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType):
        """
        Add a memory reference to the operand at the given index.
        
        :param jpype.JInt or int index: operand index
        :param ghidra.program.model.address.Address refAddr: reference address
        :param ghidra.program.model.symbol.RefType type: the reference type to be added.
        :param ghidra.program.model.symbol.SourceType sourceType: the source of this reference
        """

    def compareTo(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Compares the given address to the address range of this node.
        
        :param ghidra.program.model.address.Address addr: address to compare.
        :return: a negative integer if this addr is greater than the maximum range address
                zero if addr is in the range
                a positive integer if addr is less than minimum range address
        :rtype: int
        """

    def contains(self, testAddr: ghidra.program.model.address.Address) -> bool:
        """
        :return: true if address is contained in the range of this codeUnit
        :rtype: bool
        
        
        :param ghidra.program.model.address.Address testAddr: the address to test.
        """

    def getAddress(self, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Get the Address for the given operand index if one exists.  Data
        objects have one operand (the value).
        
        :param jpype.JInt or int opIndex: index of the operand.
        :return: An addres if the operand represents a fully qualified
        address (given the context), or if the operand is a Scalar treated
        as an address. Null is returned if no address or scalar exists on that 
        operand.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressString(self, showBlockName: typing.Union[jpype.JBoolean, bool], pad: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Get the string representation of the starting address for
        this code unit.
        
        :param jpype.JBoolean or bool showBlockName: true if the string should include the memory block name
        :param jpype.JBoolean or bool pad: if true, the address will be padded with leading zeros.  Even if pad is
        false, the string will be padded to make the address string contain at least 4 digits.
        :return: string representation of address
        :rtype: str
        """

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the bytes that make up this code unit.
        NOTE: If an :meth:`instruction length-override <Instruction.isLengthOverridden>` is
        set this method will not return all bytes associated with the 
        :obj:`instruction prototype <InstructionPrototype>`.
        
        :return: an array of bytes that are in memory at the codeunits address.  The
        array length is the same as the codeUnits length
        :rtype: jpype.JArray[jpype.JByte]
        :raises MemoryAccessException: if the full number of bytes could not be read.
        """

    def getBytesInCodeUnit(self, buffer: jpype.JArray[jpype.JByte], bufferOffset: typing.Union[jpype.JInt, int]):
        """
        Copies max(buffer.length, code unit length) bytes into buffer starting at location offset in buffer.
        
        :param jpype.JArray[jpype.JByte] buffer: byte array to copy into
        :param jpype.JInt or int bufferOffset: offset in byte array the copy will start
        :raises MemoryAccessException: if the full number of bytes could not be read.
        """

    @typing.overload
    @deprecated("use getComment(CommentType) instead")
    def getComment(self, commentType: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the comment for the given type
        
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, 
        POST_COMMENT, or REPEATABLE_COMMENT
        :return: the comment string of the appropriate type or null if no comment of
        that type exists for this codeunit
        :rtype: str
        :raises IllegalArgumentException: if type is not one of the
        three types of comments supported
        
        .. deprecated::
        
        use :meth:`getComment(CommentType) <.getComment>` instead
        """

    @typing.overload
    def getComment(self, type: CommentType) -> str:
        """
        Get the comment for the given type
        
        :param CommentType type: :obj:`comment type <CommentType>`
        :return: the comment string of the appropriate type or null if no comment of
        that type exists for this code unit
        :rtype: str
        """

    @typing.overload
    @deprecated("use getCommentAsArray(CommentType) instead")
    def getCommentAsArray(self, commentType: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.String]:
        """
        Get the comment for the given type and parse it into an array of strings
        such that each line is its own string.
        
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, 
        POST_COMMENT, or REPEATABLE_COMMENT
        :return: an array of strings where each item in the array is a line of text
        in the comment.  If there is no comment of the requested type, an empty array
        is returned.
        :rtype: jpype.JArray[java.lang.String]
        :raises IllegalArgumentException: if type is not one of the
        three types of comments supported
        
        .. deprecated::
        
        use :meth:`getCommentAsArray(CommentType) <.getCommentAsArray>` instead
        """

    @typing.overload
    def getCommentAsArray(self, type: CommentType) -> jpype.JArray[java.lang.String]:
        """
        Get the comment for the given type and parse it into an array of strings
        such that each line is its own string.
        
        :param CommentType type: :obj:`comment type <CommentType>`
        :return: an array of strings where each item in the array is a line of text
        in the comment.  If there is no comment of the requested type, an empty array
        is returned.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getExternalReference(self, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.ExternalReference:
        """
        Gets the external reference (if any) at the opIndex
        
        :param jpype.JInt or int opIndex: the operand index to look for external references
        :return: the external reference at the operand or null if none exists.
        :rtype: ghidra.program.model.symbol.ExternalReference
        """

    def getLabel(self) -> str:
        """
        :return: the label for this code unit.
        :rtype: str
        """

    def getLength(self) -> int:
        """
        Get length of this code unit.  
        NOTE: If an :meth:`instruction length-override <Instruction.isLengthOverridden>` is
        set this method will return the reduced length.
        
        :return: code unit length
        :rtype: int
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the ending address for this code unit.
        :rtype: ghidra.program.model.address.Address
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the starting address for this code unit.
        :rtype: ghidra.program.model.address.Address
        """

    def getMnemonicReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get references for the mnemonic for this code unit.
        
        :return: an array of memory references. A zero length array will be 
        returned if there are no references for the mnemonic.
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    def getMnemonicString(self) -> str:
        """
        :return: the mnemonic for this code unit, e.g., MOV, JMP
        :rtype: str
        """

    def getNumOperands(self) -> int:
        """
        :return: the number of operands for this code unit.
        :rtype: int
        """

    def getOperandReferences(self, index: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        :return: the references for the operand index.
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        
        
        :param jpype.JInt or int index: operand index (0 is the first operand)
        """

    def getPrimaryReference(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.symbol.Reference:
        """
        :return: the primary reference for the operand index.
        :rtype: ghidra.program.model.symbol.Reference
        
        
        :param jpype.JInt or int index: operand index (0 is the first operand)
        """

    def getPrimarySymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        :return: the Primary Symbol for this code unit.
        :rtype: ghidra.program.model.symbol.Symbol
        
        
        :raises ConcurrentModificationException: if this object is no
        longer valid.
        """

    def getProgram(self) -> Program:
        """
        :return: the program that generated this CodeUnit.
        :rtype: Program
        """

    def getReferenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator:
        """
        :return: an iterator over all references TO this code unit.
        :rtype: ghidra.program.model.symbol.ReferenceIterator
        """

    def getReferencesFrom(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Get ALL memory references FROM this code unit.
        
        :return: an array of memory references from this codeUnit or an empty array
        if there are no references.
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    def getScalar(self, opIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.scalar.Scalar:
        """
        Returns the scalar at the given operand index.  Data objects have
        one operand (the value).
        
        :param jpype.JInt or int opIndex: index of the operand.
        :return: the scalar at the given operand index or null if no
        scalar exists at that index.
        :rtype: ghidra.program.model.scalar.Scalar
        """

    def getSymbols(self) -> jpype.JArray[ghidra.program.model.symbol.Symbol]:
        """
        :return: the Symbols for this code unit.
        :rtype: jpype.JArray[ghidra.program.model.symbol.Symbol]
        
        
        :raises ConcurrentModificationException: if this object is no
        longer valid.
        """

    def removeExternalReference(self, opIndex: typing.Union[jpype.JInt, int]):
        """
        Remove external reference (if any) at the given opIndex
        
        :param jpype.JInt or int opIndex: the index of the operand from which to remove any external reference.
        """

    def removeMnemonicReference(self, refAddr: ghidra.program.model.address.Address):
        """
        Remove a reference to the mnemonic for this code unit.
        
        :param ghidra.program.model.address.Address refAddr: the address to remove as a reference.
        """

    def removeOperandReference(self, index: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address):
        """
        Remove a reference to the operand.
        
        :param jpype.JInt or int index: operand index
        :param ghidra.program.model.address.Address refAddr: address referencing the operand
        """

    @typing.overload
    @deprecated("use setComment(CommentType, String) instead")
    def setComment(self, commentType: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given comment type.  Passing ``null`` clears the comment
        
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, 
        POST_COMMENT, or REPEATABLE_COMMENT
        :param java.lang.String or str comment: comment for code unit; null clears the comment
        :raises IllegalArgumentException: if type is not one of the
        three types of comments supported
        
        .. deprecated::
        
        use :meth:`setComment(CommentType, String) <.setComment>` instead
        """

    @typing.overload
    def setComment(self, type: CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given comment type.  Passing ``null`` clears the comment
        
        :param CommentType type: :obj:`comment type <CommentType>`
        :param java.lang.String or str comment: comment for code unit; null clears the comment
        """

    @typing.overload
    @deprecated("use setCommentAsArray(CommentType, String[]) instead")
    def setCommentAsArray(self, commentType: typing.Union[jpype.JInt, int], comment: jpype.JArray[java.lang.String]):
        """
        Set the comment (with each line in its own string) for the given comment type
        
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, 
        POST_COMMENT, or REPEATABLE_COMMENT
        :param jpype.JArray[java.lang.String] comment: an array of strings where each string is a single line of the comment.
        :raises IllegalArgumentException: if type is not one of the
        three types of comments supported
        
        .. deprecated::
        
        use :meth:`setCommentAsArray(CommentType, String[]) <.setCommentAsArray>` instead
        """

    @typing.overload
    def setCommentAsArray(self, type: CommentType, comment: jpype.JArray[java.lang.String]):
        """
        Set the comment (with each line in its own string) for the given comment type
        
        :param CommentType type: :obj:`comment type <CommentType>`
        :param jpype.JArray[java.lang.String] comment: an array of strings where each string is a single line of the comment.
        :raises IllegalArgumentException: if type is not one of the
        three types of comments supported
        """

    def setPrimaryMemoryReference(self, ref: ghidra.program.model.symbol.Reference):
        """
        Sets a memory reference to be the primary reference at its
        address/opIndex location. The primary reference is the one that
        is used in the getOperandRepresentation() method.
        
        :param ghidra.program.model.symbol.Reference ref: the reference to be set as primary.
        """

    def setRegisterReference(self, opIndex: typing.Union[jpype.JInt, int], reg: ghidra.program.model.lang.Register, sourceType: ghidra.program.model.symbol.SourceType, refType: ghidra.program.model.symbol.RefType):
        """
        Sets a register reference at the ``offset`` on the
        specified operand index, which effectively substitutes the previous
        operation interpretation
         
        
        *NOTE: If another reference was previously set on the
        operand, then it will be replaced with this register
        reference*
        
        :param jpype.JInt or int opIndex: the index of the operand to set this register reference
        :param ghidra.program.model.lang.Register reg: a register
        :param ghidra.program.model.symbol.SourceType sourceType: the source of this reference
        :param ghidra.program.model.symbol.RefType refType: type of reference, RefType.READ,WRITE,PTR...
        """

    def setStackReference(self, opIndex: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JInt, int], sourceType: ghidra.program.model.symbol.SourceType, refType: ghidra.program.model.symbol.RefType):
        """
        Sets a stack reference at the ``offset`` on the
        specified operand index, which effectively substitutes the previous
        operation interpretation
         
        
        *NOTE: If another reference was previously set on the
        operand, then it will be replaced with this stack
        reference*
        
        :param jpype.JInt or int opIndex: the index of the operand to set this stack reference
        :param jpype.JInt or int offset: the (+/-) offset from stack base address
        :param ghidra.program.model.symbol.SourceType sourceType: the source of this reference
        :param ghidra.program.model.symbol.RefType refType: type of reference, RefType.READ,WRITE,PTR...
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def mnemonicString(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
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
    def program(self) -> Program:
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @property
    def numOperands(self) -> jpype.JInt:
        ...

    @property
    def symbols(self) -> jpype.JArray[ghidra.program.model.symbol.Symbol]:
        ...

    @property
    def externalReference(self) -> ghidra.program.model.symbol.ExternalReference:
        ...

    @property
    def scalar(self) -> ghidra.program.model.scalar.Scalar:
        ...

    @property
    def referenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator:
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
    def comment(self) -> java.lang.String:
        ...

    @property
    def primaryReference(self) -> ghidra.program.model.symbol.Reference:
        ...

    @property
    def mnemonicReferences(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def primarySymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...


class VariableStorage(java.lang.Comparable[VariableStorage]):
    """
    Encapsulates the ordered list of storage varnodes which correspond to a 
    function parameter or local variable.  For big-endian the first element corresponds 
    to the most-significant varnode, while for little-endian the first element 
    corresponds to the least-significant varnode.
    """

    class_: typing.ClassVar[java.lang.Class]
    BAD_STORAGE: typing.Final[VariableStorage]
    """
    ``BAD_STORAGE`` used to identify variable storage which is no longer
    valid.  This can be caused by various events such as significant language/processor
    changes or software bugs which prevent variable storage to be properly decoded.
    """

    UNASSIGNED_STORAGE: typing.Final[VariableStorage]
    """
    ``UNASSIGNED_STORAGE`` used to identify parameter storage which is "unmapped"
    or could not be determined.
    """

    VOID_STORAGE: typing.Final[VariableStorage]
    """
    ``VOID_STORAGE`` used to identify parameter/return storage which is "mapped"
    with a data-type of void.
    """


    @typing.overload
    def __init__(self, programArch: ghidra.program.model.lang.ProgramArchitecture, *varnodes: ghidra.program.model.pcode.Varnode):
        """
        Construct variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] varnodes: one or more ordered storage varnodes
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    @typing.overload
    def __init__(self, programArch: ghidra.program.model.lang.ProgramArchitecture, *registers: ghidra.program.model.lang.Register):
        """
        Construct register variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param jpype.JArray[ghidra.program.model.lang.Register] registers: one or more ordered registers
        :raises InvalidInputException: if specified registers violate storage restrictions
        """

    @typing.overload
    def __init__(self, programArch: ghidra.program.model.lang.ProgramArchitecture, stackOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]):
        """
        Construct stack variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param jpype.JInt or int stackOffset: stack offset
        :param jpype.JInt or int size: stack element size
        :raises InvalidInputException: if specified registers violate storage restrictions
        """

    @typing.overload
    def __init__(self, programArch: ghidra.program.model.lang.ProgramArchitecture, varnodes: java.util.List[ghidra.program.model.pcode.Varnode]):
        """
        Construct variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param java.util.List[ghidra.program.model.pcode.Varnode] varnodes: one or more ordered storage varnodes
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    @typing.overload
    def __init__(self, programArch: ghidra.program.model.lang.ProgramArchitecture, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Construct variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param ghidra.program.model.address.Address address: varnode address
        :param jpype.JInt or int size: varnode size
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    def clone(self, newProgramArch: ghidra.program.model.lang.ProgramArchitecture) -> VariableStorage:
        """
        Attempt to clone variable storage for use in a different program.
        Dynamic storage characteristics will not be preserved.
        
        :param ghidra.program.model.lang.ProgramArchitecture newProgramArch: target program architecture details
        :return: cloned storage
        :rtype: VariableStorage
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    def compareTo(self, otherStorage: VariableStorage) -> int:
        """
        Compare this variable storage with another.  A value of 0 indicates 
        that the two objects are equal
        
        
        .. seealso::
        
            | :obj:`java.lang.Comparable.compareTo(java.lang.Object)`
        """

    def contains(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the specified address is contained within this storage
        
        :param ghidra.program.model.address.Address address: address
        :return: true if this storage varnode(s) contain specified address
        :rtype: bool
        """

    @staticmethod
    def deserialize(programArch: ghidra.program.model.lang.ProgramArchitecture, serialization: typing.Union[java.lang.String, str]) -> VariableStorage:
        """
        Construct variable storage
        
        :param ghidra.program.model.lang.ProgramArchitecture programArch: program architecture details
        :param java.lang.String or str serialization: storage serialization string
        :return: deserialized variable storage.  :obj:`.BAD_STORAGE` may be returned on failure.
        :rtype: VariableStorage
        :raises InvalidInputException: if specified varnodes violate storage restrictions
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        This storage is considered equal if it consists of the same storage varnodes.
        """

    def getAutoParameterType(self) -> AutoParameterType:
        """
        If this storage corresponds to a auto-parameter, return the type associated
        with the auto-parameter.
        
        :return: auto-parameter type or null if not applicable
        :rtype: AutoParameterType
        """

    def getFirstVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        
        
        :return: first varnode within the ordered list of varnodes
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def getLastVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        
        
        :return: last varnode within the ordered list of varnodes
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def getLongHash(self) -> int:
        ...

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the minimum address corresponding to the first varnode of this storage
        or null if this is a special empty storage: :meth:`isBadStorage() <.isBadStorage>`, :meth:`isUnassignedStorage() <.isUnassignedStorage>`,
        :meth:`isVoidStorage() <.isVoidStorage>`
        :rtype: ghidra.program.model.address.Address
        """

    def getProgramArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture:
        """
        
        
        :return: program for which this storage is associated
        :rtype: ghidra.program.model.lang.ProgramArchitecture
        """

    def getRegister(self) -> ghidra.program.model.lang.Register:
        """
        
        
        :return: first storage register associated with this register or compound storage, else
        null is returned.
        :rtype: ghidra.program.model.lang.Register
        
        .. seealso::
        
            | :obj:`Variable.isRegisterVariable()`
        """

    def getRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        
        
        :return: storage register(s) associated with this register or compound storage, else
        null is returned.
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        
        .. seealso::
        
            | :obj:`Variable.isRegisterVariable()`
        
            | :obj:`.isCompoundStorage()`
        """

    @typing.overload
    def getSerializationString(self) -> str:
        """
        Return a serialization form of this variable storage.
        
        :return: storage serialization string useful for subsequent reconstruction
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getSerializationString(*varnodes: ghidra.program.model.pcode.Varnode) -> str:
        """
        Generate VariableStorage serialization string
        
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] varnodes: one or more storage varnodes
        :return: storage serialization string useful for subsequent reconstruction
        of a VariableStorage object
        :rtype: str
        """

    def getStackOffset(self) -> int:
        """
        
        
        :return: the stack offset associated with simple stack storage or compound 
        storage where the last varnode is stack, see :meth:`hasStackStorage() <.hasStackStorage>`.
        :rtype: int
        :raises UnsupportedOperationException: if storage does not have a stack varnode
        """

    def getVarnodeCount(self) -> int:
        """
        
        
        :return: the number of varnodes associated with this variable storage
        :rtype: int
        """

    @typing.overload
    def getVarnodes(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :return: ordered varnodes associated with this variable storage
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    @staticmethod
    @typing.overload
    def getVarnodes(addrFactory: ghidra.program.model.address.AddressFactory, serialization: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.pcode.Varnode]:
        """
        Parse a storage serialization string to produce an array or varnodes
        
        :param ghidra.program.model.address.AddressFactory addrFactory: address factory
        :param java.lang.String or str serialization: serialized variable storage string (see :meth:`getSerializationString() <.getSerializationString>`).
        :return: array of varnodes or null if invalid
        :rtype: java.util.List[ghidra.program.model.pcode.Varnode]
        :raises InvalidInputException: if specified registers violate storage restrictions
        """

    def hasStackStorage(self) -> bool:
        """
        
        
        :return: true if the last varnode for simple or compound storage is a stack varnode
        :rtype: bool
        """

    @typing.overload
    def intersects(self, variableStorage: VariableStorage) -> bool:
        """
        Determine if this variable storage intersects the specified variable storage
        
        :param VariableStorage variableStorage: other variable storage
        :return: true if any intersection exists between this storage and the specified
        variable storage
        :rtype: bool
        """

    @typing.overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Determine if this storage intersects the specified address set
        
        :param ghidra.program.model.address.AddressSetView set: address set
        :return: true if this storage intersects the specified address set
        :rtype: bool
        """

    @typing.overload
    def intersects(self, reg: ghidra.program.model.lang.Register) -> bool:
        """
        Determine if this storage intersects the specified register
        
        :param ghidra.program.model.lang.Register reg: the register
        :return: true if this storage intersects the specified register
        :rtype: bool
        """

    def isAutoStorage(self) -> bool:
        """
        Associated with auto-parameters.  Parameters whose existence is dictated
        by a calling-convention may automatically inject additional hidden
        parameters.  If this storage is associated with a auto-parameter, this
        method will return true.
        
        :return: true if this storage is associated with an auto-parameter, else false
        :rtype: bool
        """

    def isBadStorage(self) -> bool:
        """
        
        
        :return: true if this storage is bad (could not be resolved)
        :rtype: bool
        """

    def isCompoundStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of two or more storage varnodes
        :rtype: bool
        """

    def isConstantStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of a single constant-space varnode which is used when storing
        local function constants.
        :rtype: bool
        """

    def isForcedIndirect(self) -> bool:
        """
        If this storage corresponds to parameter which was forced by the associated calling 
        convention to be passed as a pointer instead of its raw type.
        
        :return: true if this parameter was forced to be passed as a pointer instead of its raw type
        :rtype: bool
        """

    def isHashStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of a single hash-space varnode which is used when storing
        local unique function variables.
        :rtype: bool
        """

    def isMemoryStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of a single memory varnode which does not correspond
        to a register.
        :rtype: bool
        """

    def isRegisterStorage(self) -> bool:
        """
        
        
        :return: true if this is a simple variable consisting of a single register varnode
        which will be returned by either the :meth:`Variable.getFirstStorageVarnode() <Variable.getFirstStorageVarnode>` or 
        :meth:`Variable.getLastStorageVarnode() <Variable.getLastStorageVarnode>` methods.  The register can be obtained using the 
        :meth:`getRegister() <.getRegister>` method.  Keep in mind that registers
        may exist in a memory space or the register space.
        :rtype: bool
        """

    def isStackStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of a single stack varnode
        :rtype: bool
        """

    def isUnassignedStorage(self) -> bool:
        """
        
        
        :return: true if storage has not been assigned (no varnodes)
        :rtype: bool
        """

    def isUniqueStorage(self) -> bool:
        """
        
        
        :return: true if storage consists of a single unique-space varnode which is used during
        function analysis.  This type of storage is not suitable for database-stored function
        variables.  This type of storage must be properly converted to Hash storage when 
        storing unique function variables.
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        
        
        :return: true if storage is assigned and is not BAD
        :rtype: bool
        """

    def isVoidStorage(self) -> bool:
        """
        
        
        :return: true if storage corresponds to the VOID_STORAGE instance
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.VOID_STORAGE`
        """

    def size(self) -> int:
        """
        
        
        :return: the total size of corresponding storage varnodes
        :rtype: int
        """

    @staticmethod
    def translateSerialization(translator: ghidra.program.util.LanguageTranslator, serialization: typing.Union[java.lang.String, str]) -> str:
        """
        Perform language translations on VariableStorage serialization string
        
        :param ghidra.program.util.LanguageTranslator translator: language translator
        :param java.lang.String or str serialization: VariableStorage serialization string
        :return: translated serialization string
        :rtype: str
        :raises InvalidInputException: if serialization has invalid format
        """

    @property
    def registerStorage(self) -> jpype.JBoolean:
        ...

    @property
    def stackOffset(self) -> jpype.JInt:
        ...

    @property
    def unassignedStorage(self) -> jpype.JBoolean:
        ...

    @property
    def autoStorage(self) -> jpype.JBoolean:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def stackStorage(self) -> jpype.JBoolean:
        ...

    @property
    def programArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def hashStorage(self) -> jpype.JBoolean:
        ...

    @property
    def memoryStorage(self) -> jpype.JBoolean:
        ...

    @property
    def forcedIndirect(self) -> jpype.JBoolean:
        ...

    @property
    def varnodeCount(self) -> jpype.JInt:
        ...

    @property
    def autoParameterType(self) -> AutoParameterType:
        ...

    @property
    def voidStorage(self) -> jpype.JBoolean:
        ...

    @property
    def compoundStorage(self) -> jpype.JBoolean:
        ...

    @property
    def serializationString(self) -> java.lang.String:
        ...

    @property
    def registers(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def constantStorage(self) -> jpype.JBoolean:
        ...

    @property
    def varnodes(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def lastVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def firstVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def uniqueStorage(self) -> jpype.JBoolean:
        ...

    @property
    def badStorage(self) -> jpype.JBoolean:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def longHash(self) -> jpype.JLong:
        ...


class StackVariableComparator(java.util.Comparator[java.lang.Object]):
    """
    Compares stack variable offsets; has a static factory method to get
    a StackVariableComparator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def compare(self, obj1: java.lang.Object, obj2: java.lang.Object) -> int:
        """
        Compares a stack variable offsets. One or both objects must be
        a StackVariable.
        
        :param java.lang.Object obj1: a StackVariable or Integer
        :param java.lang.Object obj2: a StackVariable or Integer
        :return: a negative integer, zero, or a positive integer
        if the first argument is less than, equal to, or greater than the second.
        :rtype: int
        """

    @staticmethod
    def get() -> StackVariableComparator:
        """
        Returns a shared instance of a StackVariableComparator.
        """


class Function(ghidra.program.model.symbol.Namespace):
    """
    Interface to define methods available on a function. Functions have a single entry point.
    """

    class FunctionUpdateType(java.lang.Enum[Function.FunctionUpdateType]):

        class_: typing.ClassVar[java.lang.Class]
        CUSTOM_STORAGE: typing.Final[Function.FunctionUpdateType]
        """
        All parameters and return have been specified with their storage.
        """

        DYNAMIC_STORAGE_FORMAL_PARAMS: typing.Final[Function.FunctionUpdateType]
        """
        The formal signature parameters and return have been specified without storage.
        Storage will be computed.  Any use of the reserved names 'this' and 
        '__return_storage_ptr__' will be stripped before considering the injection
        of these parameters.
        """

        DYNAMIC_STORAGE_ALL_PARAMS: typing.Final[Function.FunctionUpdateType]
        """
        All parameters and return have been specified without storage.
        Storage will be computed.  Any use of the reserved names 'this' and 
        '__return_storage_ptr__' will be stripped before considering the injection
        of these parameters.  In addition, if the calling convention is '__thiscall'
        if the 'this' parameter was not identified by name, the first parameter will
        be assumed the 'this' parameter if its name is a default name and it has
        the size of a pointer.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Function.FunctionUpdateType:
            ...

        @staticmethod
        def values() -> jpype.JArray[Function.FunctionUpdateType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_PARAM_PREFIX: typing.Final = "param_"
    THIS_PARAM_NAME: typing.Final = "this"
    RETURN_PTR_PARAM_NAME: typing.Final = "__return_storage_ptr__"
    DEFAULT_PARAM_PREFIX_LEN: typing.Final[jpype.JInt]
    DEFAULT_LOCAL_PREFIX: typing.Final = "local_"
    DEFAULT_LOCAL_RESERVED_PREFIX: typing.Final = "local_res"
    DEFAULT_LOCAL_TEMP_PREFIX: typing.Final = "temp_"
    DEFAULT_LOCAL_PREFIX_LEN: typing.Final[jpype.JInt]
    UNKNOWN_CALLING_CONVENTION_STRING: typing.Final = "unknown"
    DEFAULT_CALLING_CONVENTION_STRING: typing.Final = "default"
    INLINE: typing.Final = "inline"
    NORETURN: typing.Final = "noreturn"
    THUNK: typing.Final = "thunk"
    UNKNOWN_STACK_DEPTH_CHANGE: typing.Final = 2147483647
    """
    Default Stack depth for a function.
    """

    INVALID_STACK_DEPTH_CHANGE: typing.Final = 2147483646

    def addLocalVariable(self, var: Variable, source: ghidra.program.model.symbol.SourceType) -> Variable:
        """
        Adds a local variable to the function.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param Variable var: the variable to add.
        :param ghidra.program.model.symbol.SourceType source: the source of this local variable
        :return: the Variable added to the program.
        :rtype: Variable
        :raises DuplicateNameException: if another local variable or parameter already
        has that name.
        :raises InvalidInputException: if there is an error or conflict when resolving the variable
        """

    @deprecated("The use of this method is discouraged due to the potential injection of auto-parameters\n which are easily overlooked when considering parameter ordinal.  The function signature should generally be \n adjusted with a single call to updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)")
    def addParameter(self, var: Variable, source: ghidra.program.model.symbol.SourceType) -> Parameter:
        """
        Adds the given variable to the end of the parameters list.  The variable storage specified
        for the new parameter will be ignored if custom storage mode is not enabled.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param Variable var: the variable to add as a new parameter.
        :param ghidra.program.model.symbol.SourceType source: the source of this parameter which will be applied to the parameter symbol and 
        overall function signature source.  If parameter has a null or default name a SourceType of DEFAULT
        will be applied to the parameter symbol.
        :return: the Parameter object created.
        :rtype: Parameter
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if data type size is too large based upon storage constraints.
        
        .. deprecated::
        
        The use of this method is discouraged due to the potential injection of auto-parameters
        which are easily overlooked when considering parameter ordinal.  The function signature should generally be 
        adjusted with a single call to :meth:`updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType) <.updateFunction>`
        """

    def addTag(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Adds the tag with the given name to this function; if one does
        not exist, one is created.
        
        :param java.lang.String or str name: the tag name to add
        :return: true if the tag was successfully added
        :rtype: bool
        """

    def getAllVariables(self) -> jpype.JArray[Variable]:
        """
        Returns an array of all local and parameter variables
        
        :return: the variables
        :rtype: jpype.JArray[Variable]
        """

    def getAutoParameterCount(self) -> int:
        """
        Gets the number of auto-parameters for this function also included in the total
        count provided by :meth:`getParameterCount() <.getParameterCount>`.  This number will always be 0 when
        custom parameter storage is used.
        
        :return: the number of auto-parameters
        :rtype: int
        """

    def getCallFixup(self) -> str:
        """
        Returns the current call-fixup name set on this instruction or null if one has not been set
        
        :return: the call fixup name or null
        :rtype: str
        """

    def getCalledFunctions(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[Function]:
        """
        Returns a set of functions that this function calls.
        
        :param ghidra.util.task.TaskMonitor monitor: The monitor that is used to report progress and allow for canceling of 
                        the search.  May be null.
        :return: a set of functions that this function calls.
        :rtype: java.util.Set[Function]
        """

    def getCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the calling convention prototype model for this function.
        
        :return: the prototype model of the function's current calling convention or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    def getCallingConventionName(self) -> str:
        """
        Gets the calling convention's name for this function.
        
        :return: the name of the calling convention 
        or Function.DEFAULT_CALLING_CONVENTION_STRING 
        (i.e. "default", if the calling convention has been set to the default for this function)
        or Function.UNKNOWN_CALLING_CONVENTION_STRING 
        (i.e. "unknown", if no calling convention is specified for this function).
        :rtype: str
        """

    def getCallingFunctions(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[Function]:
        """
        Returns a set of functions that call this function.
        
        :param ghidra.util.task.TaskMonitor monitor: The monitor that is used to report progress and allow for canceling of 
                        the search.  May be null.
        :return: a set of functions that call this function.
        :rtype: java.util.Set[Function]
        """

    def getComment(self) -> str:
        """
        Get the comment for this function.
        
        :return: the comment for this function
        :rtype: str
        """

    def getCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the function (same as plate) comment as an array of strings where
        each item in the array is a line of text in the comment.
        
        :return: the comments
        :rtype: jpype.JArray[java.lang.String]
        """

    def getEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        Get the entry point for this function.
        Functions may only have ONE entry point.
        
        :return: the entry point
        :rtype: ghidra.program.model.address.Address
        """

    def getExternalLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        """
        
        
        :return: if this is an external function return the associated external location object.
        :rtype: ghidra.program.model.symbol.ExternalLocation
        """

    @typing.overload
    @deprecated("since many use cases will likely want a complete list of thunk functions\n a recursive search is generally needed (see getFunctionThunkAddresses(boolean)).\n This method form may be removed in a future release.")
    def getFunctionThunkAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        If this function is "Thunked", an array of Thunk Function entry points is returned.
        A non-recursive search is performed (i.e., first-hop only).
        
        :return: associated thunk function entry points or null if this is not a "Thunked" function.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        
        .. deprecated::
        
        since many use cases will likely want a complete list of thunk functions
        a recursive search is generally needed (see :meth:`getFunctionThunkAddresses(boolean) <.getFunctionThunkAddresses>`).
        This method form may be removed in a future release.
        """

    @typing.overload
    def getFunctionThunkAddresses(self, recursive: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        If this function is "Thunked", an array of Thunk Function entry points is returned.
        
        :param jpype.JBoolean or bool recursive: if true a recursive search is performed returning all effective thunks
        of this function, else if false only the first-hop (i.e., direct thunks) are returned.
        :return: associated thunk function entry points or null if this is not a "Thunked" function.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """

    @typing.overload
    def getLocalVariables(self) -> jpype.JArray[Variable]:
        """
        Get all local function variables
        
        :return: all local function variables
        :rtype: jpype.JArray[Variable]
        """

    @typing.overload
    def getLocalVariables(self, filter: VariableFilter) -> jpype.JArray[Variable]:
        """
        Get all local function variables which satisfy the specified filter
        
        :param VariableFilter filter: variable filter or null for all local variables to be returned
        :return: all function variables which satisfy the specified filter
        :rtype: jpype.JArray[Variable]
        """

    def getName(self) -> str:
        """
        Get the name of this function.
        
        :return: the functions name
        :rtype: str
        """

    def getParameter(self, ordinal: typing.Union[jpype.JInt, int]) -> Parameter:
        """
        Returns the specified parameter including an auto-param at the specified ordinal.
        
        :param jpype.JInt or int ordinal: the index of the parameter to return.
        :return: parameter or null if ordinal is out of range
        :rtype: Parameter
        """

    def getParameterCount(self) -> int:
        """
        Gets the total number of parameters for this function.  This number also includes any
        auto-parameters which may have been injected when dynamic parameter storage is used.
        
        :return: the total number of parameters
        :rtype: int
        """

    @typing.overload
    def getParameters(self) -> jpype.JArray[Parameter]:
        """
        Get all function parameters
        
        :return: all function parameters
        :rtype: jpype.JArray[Parameter]
        """

    @typing.overload
    def getParameters(self, filter: VariableFilter) -> jpype.JArray[Parameter]:
        """
        Get all function parameters which satisfy the specified filter
        
        :param VariableFilter filter: variable filter or null for all parameters to be returned
        :return: all function parameters which satisfy the specified filter
        :rtype: jpype.JArray[Parameter]
        """

    def getProgram(self) -> Program:
        """
        Get the program containing this function.
        
        :return: the program
        :rtype: Program
        """

    def getPrototypeString(self, formalSignature: typing.Union[jpype.JBoolean, bool], includeCallingConvention: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Return a string representation of the function signature
        
        :param jpype.JBoolean or bool formalSignature: if true only original raw return/parameter types will be retained and 
        auto-params discarded (e.g., this, __return_storage_ptr__, etc.) within the returned 
        signature.  If false, the effective signature will be returned where forced indirect 
        and auto-params are reflected in the signature.  This option has no affect if the specified 
        function has custom storage enabled.
        :param jpype.JBoolean or bool includeCallingConvention: if true prototype will include call convention
        declaration if known.
        :return: the prototype
        :rtype: str
        """

    def getRepeatableComment(self) -> str:
        """
        Returns the repeatable comment for this function.
        A repeatable comment is a comment that will appear
        at locations that 'call' this function.
        
        :return: the repeatable comment for this function
        :rtype: str
        """

    def getRepeatableCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the repeatable comment as an array of strings.
        
        :return: the repeatable comment as an array of strings
        :rtype: jpype.JArray[java.lang.String]
        """

    def getReturn(self) -> Parameter:
        """
        Get the Function's return type/storage represented by a Parameter 
        object.  The parameter's ordinal value will be equal to
        Parameter.RETURN_ORIDINAL.
        
        :return: return data-type/storage
        :rtype: Parameter
        """

    def getReturnType(self) -> ghidra.program.model.data.DataType:
        """
        Get the Function's return type.
        A null return value indicates the functions return type has never been set.
        
        :return: the DataType that this function returns.
        :rtype: ghidra.program.model.data.DataType
        """

    @typing.overload
    def getSignature(self) -> FunctionSignature:
        """
        Get the function's effective signature.
        This is equivalent to invoking ``getSignature(false)`` where auto-params and 
        forced-indirect types will be reflected in the signature if present.
         
        
        WARNING! It is important to note that the calling convention may not be properly retained 
        by the returned signature object if a non-generic calling convention is used by this function as 
        defined by the program's compiler specification.
        
        :return: the function's signature
        :rtype: FunctionSignature
        """

    @typing.overload
    def getSignature(self, formalSignature: typing.Union[jpype.JBoolean, bool]) -> FunctionSignature:
        """
        Get the function's signature.
         
        
        WARNING! It is important to note that the calling convention may not be properly 
        retained by the returned signature object if a non-generic calling convention is used by 
        this function as defined by the program's compiler specification.
        
        :param jpype.JBoolean or bool formalSignature: if true only original raw types will be retained and 
        auto-params discarded (e.g., this, __return_storage_ptr__, etc.) within the returned 
        signature.  If false, the effective signature will be returned where forced indirect 
        and auto-params are reflected in the signature.  This option has no affect if the specified 
        function has custom storage enabled.
        :return: the function's signature
        :rtype: FunctionSignature
        """

    def getSignatureSource(self) -> ghidra.program.model.symbol.SourceType:
        """
        Returns the source type for the overall signature excluding function name and parameter names 
        whose source is carried by the corresponding symbol.
        
        :return: the overall SourceType of the function signature;
        :rtype: ghidra.program.model.symbol.SourceType
        """

    def getStackFrame(self) -> StackFrame:
        """
        Get the stack frame for this function.
        NOTE: Use of the stack frame must be avoided during upgrade activity since
        the compiler spec may not be known (i.e., due to language upgrade process).
        
        :return: this functions stack frame
        :rtype: StackFrame
        """

    def getStackPurgeSize(self) -> int:
        """
        Get the change in the stack pointer resulting from calling
        this function.
        
        :return: int the change in bytes to the stack pointer
        :rtype: int
        """

    def getTags(self) -> java.util.Set[FunctionTag]:
        """
        Return all :obj:`FunctionTag` objects associated with this function.
        
        :return: set of tag names
        :rtype: java.util.Set[FunctionTag]
        """

    def getThunkedFunction(self, recursive: typing.Union[jpype.JBoolean, bool]) -> Function:
        """
        If this function is a Thunk, this method returns the referenced function.
        
        :param jpype.JBoolean or bool recursive: if true and the thunked-function is a thunk itself, the returned 
        thunked-function will be the final thunked-function which will never be a thunk.
        :return: function referenced by this Thunk Function or null if this is not a Thunk
        function
        :rtype: Function
        """

    def getVariables(self, filter: VariableFilter) -> jpype.JArray[Variable]:
        """
        Get all function variables which satisfy the specified filter
        
        :param VariableFilter filter: variable filter or null for all variables to be returned
        :return: all function variables which satisfy the specified filter
        :rtype: jpype.JArray[Variable]
        """

    def hasCustomVariableStorage(self) -> bool:
        """
        
        
        :return: true if function parameters utilize custom variable storage.
        :rtype: bool
        """

    def hasNoReturn(self) -> bool:
        """
        
        
        :return: true if this function does not return.
        :rtype: bool
        """

    def hasUnknownCallingConventionName(self) -> bool:
        """
        Determine if this signature has an unknown or unrecognized calling convention name.
        
        :return: true if calling convention is unknown or unrecognized name, else false.
        :rtype: bool
        """

    def hasVarArgs(self) -> bool:
        """
        Returns true if this function has a variable argument list (VarArgs)
        
        :return: true if this function has a variable argument list (VarArgs)
        :rtype: bool
        """

    @deprecated("The use of this method is discouraged due to the potential injection of auto-parameters\n which are easily overlooked when considering parameter ordinal.  The function signature should generally be \n adjusted with a single call to updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)")
    def insertParameter(self, ordinal: typing.Union[jpype.JInt, int], var: Variable, source: ghidra.program.model.symbol.SourceType) -> Parameter:
        """
        Inserts the given variable into the parameters list.  The variable storage specified
        for the new parameter will be ignored if custom storage mode is not enabled.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param jpype.JInt or int ordinal: the position with the parameters to insert to.  This ordinal must factor in the
        presence of auto-parameters which may be injected dynamically based upon calling convention and
        return data type.  Parameters may not be inserted befor an auto-parameter.
        :param Variable var: the variable to add as a new parameter.
        :param ghidra.program.model.symbol.SourceType source: the source of this parameter which will be applied to the parameter symbol and 
        overall function signature source.  If parameter has a null or default name a SourceType of DEFAULT
        will be applied to the parameter symbol.
        :return: the Parameter object created.
        :rtype: Parameter
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if data type size is too large based upon storage constraints.
        
        .. deprecated::
        
        The use of this method is discouraged due to the potential injection of auto-parameters
        which are easily overlooked when considering parameter ordinal.  The function signature should generally be 
        adjusted with a single call to :meth:`updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType) <.updateFunction>`
        """

    def isDeleted(self) -> bool:
        """
        Determine if this function object has been deleted.  NOTE: the function could be
        deleted at anytime due to asynchronous activity.
        
        :return: true if function has been deleted, false if not.
        :rtype: bool
        """

    def isInline(self) -> bool:
        """
        
        
        :return: true if this is an inline function.
        :rtype: bool
        """

    def isStackPurgeSizeValid(self) -> bool:
        """
        check if stack purge size is valid.
        
        :return: true if the stack depth is valid
        :rtype: bool
        """

    def isThunk(self) -> bool:
        """
        
        
        :return: true if this function is a Thunk and has a referenced Thunked Function.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.getThunkedFunction(boolean)`
        """

    @deprecated("The use of this method is discouraged.  The function signature should generally be \n adjusted with a single call to updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)")
    def moveParameter(self, fromOrdinal: typing.Union[jpype.JInt, int], toOrdinal: typing.Union[jpype.JInt, int]) -> Parameter:
        """
        Move the parameter which occupies the fromOrdinal position to the toOrdinal position.
        Parameters will be renumbered to reflect the new ordering.  Auto-parameters may not be 
        moved but must be accounted for in the specified ordinals.
        
        :param jpype.JInt or int fromOrdinal: from ordinal position using the current numbering
        :param jpype.JInt or int toOrdinal: the final position of the specified parameter
        :return: parameter which was moved
        :rtype: Parameter
        :raises InvalidInputException: if either ordinal is invalid
        
        .. deprecated::
        
        The use of this method is discouraged.  The function signature should generally be 
        adjusted with a single call to :meth:`updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType) <.updateFunction>`
        """

    def promoteLocalUserLabelsToGlobal(self):
        """
        Changes all local user-defined labels for this function to global symbols. If a
        global code symbol already exists with the same name at the symbols address the
        symbol will be removed.
        """

    @deprecated("The use of this method is discouraged.  The function signature should generally be \n adjusted with a single call to updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)")
    def removeParameter(self, ordinal: typing.Union[jpype.JInt, int]):
        """
        Remove the specified parameter.  Auto-parameters may not be removed but must be accounted 
        for in the specified ordinal.
        
        :param jpype.JInt or int ordinal: the index of the parameter to be removed.
        
        .. deprecated::
        
        The use of this method is discouraged.  The function signature should generally be 
        adjusted with a single call to :meth:`updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType) <.updateFunction>`
        """

    def removeTag(self, name: typing.Union[java.lang.String, str]):
        """
        Removes the given tag from this function.
        
        :param java.lang.String or str name: the tag name to be removed.
        """

    def removeVariable(self, var: Variable):
        """
        Removes the given variable from the function.
        
        :param Variable var: the variable to remove.
        """

    @typing.overload
    def replaceParameters(self, params: java.util.List[Variable], updateType: Function.FunctionUpdateType, force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Replace all current parameters with the given list of parameters.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param java.util.List[Variable] params: the new set of parameters for the function.
        :param Function.FunctionUpdateType updateType: function update type
        :param jpype.JBoolean or bool force: if true any conflicting local parameters will be removed
        :param ghidra.program.model.symbol.SourceType source: the source of these parameters which will be applied to the parameter symbols and 
        overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
        will be applied to the corresponding parameter symbol.
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if a parameter data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if a parameter data type size is too large based upon storage constraints
        or conflicts with another variable.
        """

    @typing.overload
    def replaceParameters(self, updateType: Function.FunctionUpdateType, force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType, *params: Variable):
        """
        Replace all current parameters with the given list of parameters.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param Function.FunctionUpdateType updateType: function update type
        :param jpype.JBoolean or bool force: if true any conflicting local parameters will be removed
        :param ghidra.program.model.symbol.SourceType source: the source of these parameters which will be applied to the parameter symbols and 
        overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
        will be applied to the corresponding parameter symbol.
        :param jpype.JArray[Variable] params: the new parameters for the function.
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if a parameter data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if a parameter data type size is too large based upon storage constraints
        or conflicts with another variable.
        """

    def setBody(self, newBody: ghidra.program.model.address.AddressSetView):
        """
        Set the new body for this function. The entry point must be contained
        in the new body.
        
        :param ghidra.program.model.address.AddressSetView newBody: address set to use as the body of this function
        :raises OverlappingFunctionException: if the address set overlaps that
        of another function
        """

    def setCallFixup(self, name: typing.Union[java.lang.String, str]):
        """
        Set the named call-fixup for this function.
        
        :param java.lang.String or str name: name of call-fixup specified by compiler spec.  A null
        value will clear the current setting.
        """

    def setCallingConvention(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the calling convention for this function to the named calling convention.  Only
        :meth:`known calling convention names <DataTypeManager.getKnownCallingConventionNames>`
        may be specified which will always include those defined by the associated 
        :obj:`CompilerSpec`.
        
        :param java.lang.String or str name: the name of the calling convention.  Only 
        :meth:`known calling convention names <DataTypeManager.getKnownCallingConventionNames>`
        may be specified which will always include those defined by the associated 
        :obj:`CompilerSpec`.  In addition the reserved names 
        :obj:`"unknown" <Function.UNKNOWN_CALLING_CONVENTION_STRING>` and 
        :obj:`"default" <Function.DEFAULT_CALLING_CONVENTION_STRING>` may also be
        used here.
        :raises InvalidInputException: if the specified name is not a recognized calling 
        convention name.
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for this function.
        
        :param java.lang.String or str comment: the string to set as the comment.
        """

    def setCustomVariableStorage(self, hasCustomVariableStorage: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether or not this function uses custom variable storage
        
        :param jpype.JBoolean or bool hasCustomVariableStorage: true if this function uses custom storage
        """

    def setInline(self, isInline: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not this function is inline.
        
        :param jpype.JBoolean or bool isInline: true if this is an inline function.
        """

    def setName(self, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Set the name of this function.
        
        :param java.lang.String or str name: the new name of the function
        :param ghidra.program.model.symbol.SourceType source: the source of this function name
        :raises DuplicateNameException: if the name is used by some other symbol
        :raises InvalidInputException: if the name is not a valid function name.
        """

    def setNoReturn(self, hasNoReturn: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether or not this function has a return.
        
        :param jpype.JBoolean or bool hasNoReturn: true if this function does not return.
        """

    def setRepeatableComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the repeatable comment for this function.
        
        :param java.lang.String or str comment: the string to set as the repeatable comment.
        """

    def setReturn(self, type: ghidra.program.model.data.DataType, storage: VariableStorage, source: ghidra.program.model.symbol.SourceType):
        """
        Set the return data-type and storage.
         
         
        NOTE: The storage and source are ignored if the function does not have custom storage 
        enabled.
        
        :param ghidra.program.model.data.DataType type: the data type
        :param VariableStorage storage: the storage
        :param ghidra.program.model.symbol.SourceType source: source to be combined with the overall signature source.
        :raises InvalidInputException: if data type is not a fixed length or storage is improperly 
                sized
        """

    def setReturnType(self, type: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Set the function's return type.
        
        :param ghidra.program.model.data.DataType type: the dataType that will define this functions return type.
        :param ghidra.program.model.symbol.SourceType source: signature source
        :raises InvalidInputException: if data type is not a fixed length.
        """

    def setSignatureSource(self, signatureSource: ghidra.program.model.symbol.SourceType):
        """
        Set the source type for the overall signature excluding function name and parameter names 
        whose source is carried by the corresponding symbol.
        
        :param ghidra.program.model.symbol.SourceType signatureSource: function signature source type
        """

    def setStackPurgeSize(self, purgeSize: typing.Union[jpype.JInt, int]):
        """
        Set the change in the stack pointer resulting from calling
        this function.
        
        :param jpype.JInt or int purgeSize: the change in bytes to the stack pointer
        """

    def setThunkedFunction(self, thunkedFunction: Function):
        """
        Set the currently Thunked Function or null to convert to a normal function
        
        :param Function thunkedFunction: the thunked function or null to convert this thunked function to a 
        normal function.
        :raises java.lang.IllegalArgumentException: if an attempt is made to thunk a function or another
        thunk which would result in a loop back to this function or if this function is an external
        function, or specified function is from a different program instance.
        """

    def setVarArgs(self, hasVarArgs: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether parameters can be passed as a VarArg (variable argument list)
        
        :param jpype.JBoolean or bool hasVarArgs: true if this function has a variable argument list 
                (e.g.,  printf(fmt, ...)).
        """

    @typing.overload
    def updateFunction(self, callingConvention: typing.Union[java.lang.String, str], returnValue: Variable, updateType: Function.FunctionUpdateType, force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType, *newParams: Variable):
        """
        Replace all current parameters with the given list of parameters and optionally change the 
        calling convention and function return.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param java.lang.String or str callingConvention: updated calling convention name or null if no change is required.
        Only :meth:`known calling convention names <DataTypeManager.getKnownCallingConventionNames>`
        may be specified which will always include those defined by the associated :obj:`CompilerSpec`.
        :param Variable returnValue: return variable or null if no change required
        :param Function.FunctionUpdateType updateType: function update type
        :param jpype.JBoolean or bool force: if true any conflicting local parameters will be removed
        :param ghidra.program.model.symbol.SourceType source: the source of these parameters which will be applied to the parameter symbols and 
        overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
        will be applied to the corresponding parameter symbol.
        :param jpype.JArray[Variable] newParams: a variable number of parameters for the function.
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if a parameter data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if a parameter data type size is too large based upon storage constraints
        or conflicts with another variable.
        """

    @typing.overload
    def updateFunction(self, callingConvention: typing.Union[java.lang.String, str], returnVar: Variable, newParams: java.util.List[Variable], updateType: Function.FunctionUpdateType, force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Replace all current parameters with the given list of parameters and optionally change the 
        calling convention and function return.
        The :meth:`VariableUtilities.checkVariableConflict(Function, Variable, VariableStorage, boolean) <VariableUtilities.checkVariableConflict>` 
        method may be used to check and remove conflicting variables which already exist in the function.
        
        :param java.lang.String or str callingConvention: updated calling convention name or null if no change is required.
        Only :meth:`known calling convention names <DataTypeManager.getKnownCallingConventionNames>`
        may be specified which will always include those defined by the associated :obj:`CompilerSpec`.
        :param Variable returnVar: return variable or null if no change required
        :param Function.FunctionUpdateType updateType: function update type
        :param jpype.JBoolean or bool force: if true any conflicting local parameters will be removed
        :param ghidra.program.model.symbol.SourceType source: the source of these parameters which will be applied to the parameter symbols and 
        overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
        will be applied to the corresponding parameter symbol.
        :param java.util.List[Variable] newParams: the list of new parameters for the function (required).
        :raises DuplicateNameException: if another variable(parameter or local) already
        exists in the function with that name.
        :raises InvalidInputException: if a parameter data type is not a fixed length or variable name is invalid.
        :raises VariableSizeException: if a parameter data type size is too large based upon storage constraints
        or conflicts with another variable.
        """

    @property
    def stackFrame(self) -> StackFrame:
        ...

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def signature(self) -> FunctionSignature:
        ...

    @property
    def repeatableComment(self) -> java.lang.String:
        ...

    @repeatableComment.setter
    def repeatableComment(self, value: java.lang.String):
        ...

    @property
    def stackPurgeSizeValid(self) -> jpype.JBoolean:
        ...

    @property
    def calledFunctions(self) -> java.util.Set[Function]:
        ...

    @property
    def program(self) -> Program:
        ...

    @property
    def callingFunctions(self) -> java.util.Set[Function]:
        ...

    @property
    def commentAsArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def return_(self) -> Parameter:
        ...

    @property
    def callingConventionName(self) -> java.lang.String:
        ...

    @property
    def parameter(self) -> Parameter:
        ...

    @property
    def allVariables(self) -> jpype.JArray[Variable]:
        ...

    @property
    def autoParameterCount(self) -> jpype.JInt:
        ...

    @property
    def functionThunkAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def stackPurgeSize(self) -> jpype.JInt:
        ...

    @stackPurgeSize.setter
    def stackPurgeSize(self, value: jpype.JInt):
        ...

    @property
    def variables(self) -> jpype.JArray[Variable]:
        ...

    @property
    def parameterCount(self) -> jpype.JInt:
        ...

    @property
    def thunkedFunction(self) -> Function:
        ...

    @thunkedFunction.setter
    def thunkedFunction(self, value: Function):
        ...

    @property
    def signatureSource(self) -> ghidra.program.model.symbol.SourceType:
        ...

    @signatureSource.setter
    def signatureSource(self, value: ghidra.program.model.symbol.SourceType):
        ...

    @property
    def thunk(self) -> jpype.JBoolean:
        ...

    @property
    def repeatableCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def tags(self) -> java.util.Set[FunctionTag]:
        ...

    @property
    def localVariables(self) -> jpype.JArray[Variable]:
        ...

    @property
    def deleted(self) -> jpype.JBoolean:
        ...

    @property
    def callFixup(self) -> java.lang.String:
        ...

    @callFixup.setter
    def callFixup(self, value: java.lang.String):
        ...

    @property
    def inline(self) -> jpype.JBoolean:
        ...

    @inline.setter
    def inline(self, value: jpype.JBoolean):
        ...

    @property
    def externalLocation(self) -> ghidra.program.model.symbol.ExternalLocation:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def entryPoint(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def parameters(self) -> jpype.JArray[Parameter]:
        ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType:
        ...


class ContextChangeException(ghidra.util.exception.UsrException):
    """
    ``ContextChangeException`` indicates that an illegal change to
    program context has been attempted.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        
        Constructs an ContextChangeException with no detail message.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        
        Constructs an ContextChangeException with the specified
        detail message.
        
        :param java.lang.String or str message: The message.
        """


class StubListing(Listing):
    """
    ListingStub can be extended for use by tests. It throws an UnsupportedOperationException
    for all methods in the Listing interface. Any method that is needed for your test can then
    be overridden so it can provide its own test implementation and return value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Variable(java.lang.Comparable[Variable]):
    """
    Defines an object that stores a value of some specific data type. The
    variable has a name, type, size, and a comment.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComment(self) -> str:
        """
        Get the Comment for this variable
        
        :return: the comment
        :rtype: str
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the Data Type of this variable
        
        :return: the data type of the variable
        :rtype: ghidra.program.model.data.DataType
        """

    def getFirstStorageVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        Get the first storage varnode for this variable
        
        :return: the first storage varnode associated with this variable
        :rtype: ghidra.program.model.pcode.Varnode
        
        .. seealso::
        
            | :obj:`.getVariableStorage()`
        """

    def getFirstUseOffset(self) -> int:
        """
        
        
        :return: the first use offset relative to the function entry point.
        :rtype: int
        """

    def getFunction(self) -> Function:
        """
        Returns the function that contains this Variable.  May be null if the variable is not in
        a function.
        
        :return: containing function or null
        :rtype: Function
        """

    def getLastStorageVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        Get the last storage varnode for this variable
        
        :return: the last storage varnode associated with this variable
        :rtype: ghidra.program.model.pcode.Varnode
        
        .. seealso::
        
            | :obj:`.getVariableStorage()`
        """

    def getLength(self) -> int:
        """
        Get the length of this variable
        
        :return: the length of the variable
        :rtype: int
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the minimum address corresponding to the first varnode of this storage
        or null if this is a special empty storage: :obj:`VariableStorage.BAD_STORAGE`,
        :obj:`VariableStorage.UNASSIGNED_STORAGE`, :obj:`VariableStorage.VOID_STORAGE`
        :rtype: ghidra.program.model.address.Address
        """

    def getName(self) -> str:
        """
        Get the Name of this variable or null if not assigned or not-applicable
        
        :return: the name of the variable
        :rtype: str
        """

    def getProgram(self) -> Program:
        """
        Returns the program that contains this variable or is the intended target
        
        :return: the program.
        :rtype: Program
        """

    def getRegister(self) -> ghidra.program.model.lang.Register:
        """
        
        
        :return: first storage register associated with this variable, else null is returned.
        A variable with compound storage may have more than one register or other storage
        in addition to the register returned by this method.
        :rtype: ghidra.program.model.lang.Register
        
        .. seealso::
        
            | :obj:`.isRegisterVariable()`
        """

    def getRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        
        
        :return: all storage register(s) associated with this variable, else null is returned if 
        no registers are used.  A variable with compound storage may have more than one register 
        or other storage in addition to the register(s) returned by this method.
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        
        .. seealso::
        
            | :obj:`.isRegisterVariable()`
        
            | :obj:`.isCompoundVariable()`
        """

    def getSource(self) -> ghidra.program.model.symbol.SourceType:
        """
        Get the source of this variable
        
        :return: the source of this variable
        :rtype: ghidra.program.model.symbol.SourceType
        """

    def getStackOffset(self) -> int:
        """
        
        
        :return: the stack offset associated with simple stack variable (i.e., :meth:`isStackVariable() <.isStackVariable>` 
        returns true).
        :rtype: int
        :raises UnsupportedOperationException: if storage is not a simple stack variable
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        :return: the symbol associated with this variable or null if no symbol 
        associated.  Certain dynamic variables such as auto-parameters do not
        have a symbol and will return null.
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def getVariableStorage(self) -> VariableStorage:
        """
        Get the variable storage associated with this variable.
        
        :return: the variable storage for this variable
        :rtype: VariableStorage
        """

    def hasAssignedStorage(self) -> bool:
        """
        
        
        :return: true if this variable has been assigned storage.  This is equivalent to 
        :meth:`getVariableStorage() <.getVariableStorage>` != null
        :rtype: bool
        """

    def hasStackStorage(self) -> bool:
        """
        
        
        :return: true if this variable uses simple or compound storage which contains a stack element.  
        If true, the last storage varnode will always be the stack element.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.getLastStorageVarnode()`
        """

    def isCompoundVariable(self) -> bool:
        """
        
        
        :return: true if this variable uses compound storage consisting of two or more storage elements
        which will be returned by the :meth:`getVariableStorage() <.getVariableStorage>` method.  Compound variables will
        always use a register(s) optionally followed by other storage (i.e., stack).
        :rtype: bool
        """

    def isEquivalent(self, variable: Variable) -> bool:
        """
        Determine is another variable is equivalent to this variable.
        
        :param Variable variable: other variable
        :return: true if the specified variable is equivalent to this variable
        :rtype: bool
        """

    def isMemoryVariable(self) -> bool:
        """
        
        
        :return: true if this is a simple variable consisting of a single storage memory element
        which will be returned by either the :meth:`getFirstStorageVarnode() <.getFirstStorageVarnode>` or 
        :meth:`getVariableStorage() <.getVariableStorage>` methods.
        :rtype: bool
        """

    def isRegisterVariable(self) -> bool:
        """
        
        
        :return: true if this is a simple variable consisting of a single register varnode
        which will be returned by either the :meth:`getFirstStorageVarnode() <.getFirstStorageVarnode>` or 
        :meth:`getLastStorageVarnode() <.getLastStorageVarnode>` methods.  The register can be obtained using the 
        :meth:`getRegister() <.getRegister>` method.
        :rtype: bool
        """

    def isStackVariable(self) -> bool:
        """
        
        
        :return: true if this is a simple variable consisting of a single stack varnode
        which will be returned by either the :meth:`getFirstStorageVarnode() <.getFirstStorageVarnode>` or 
        :meth:`getLastStorageVarnode() <.getLastStorageVarnode>` methods. The stack offset can be obtained using:
         
                getFirstStorageVarnode().getOffset()
          
        :rtype: bool
        """

    def isUniqueVariable(self) -> bool:
        """
        
        
        :return: true if this is a simple variable consisting of a single storage unique/hash element
        which will be returned by either the :meth:`getFirstStorageVarnode() <.getFirstStorageVarnode>` or 
        :meth:`getVariableStorage() <.getVariableStorage>` methods.  The unique hash can be obtained from the 
        storage address offset corresponding to the single storage element.
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        Verify that the variable is valid 
        (i.e., storage is valid and size matches variable data type size)
        
        :return: true if variable is valid
        :rtype: bool
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for this variable
        
        :param java.lang.String or str comment: the comment
        """

    @typing.overload
    def setDataType(self, type: ghidra.program.model.data.DataType, storage: VariableStorage, force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Set the Data Type of this variable and the associated storage whose size matches the 
        data type length.
         
        NOTE: The storage and source are ignored if the function does not have custom storage enabled.
        
        :param ghidra.program.model.data.DataType type: the data type
        :param VariableStorage storage: properly sized storage for the new data type
        :param jpype.JBoolean or bool force: overwrite conflicting variables
        :param ghidra.program.model.symbol.SourceType source: variable storage source (used only for function parameters and return)
        :raises InvalidInputException: if data type is not a fixed length or violates storage constraints.
        :raises VariableSizeException: if force is false and data type size causes a conflict 
        with other variables
        """

    @typing.overload
    def setDataType(self, type: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Set the Data Type of this variable using the default alignment behavior (implementation specific). 
        The given dataType must have a fixed length.  If contained within a stack-frame, data-type size
        will be constrained by existing variables (e.g., equivalent to force=false)
        Note: stack offset will be maintained for stack variables.
        
        :param ghidra.program.model.data.DataType type: the data type
        :param ghidra.program.model.symbol.SourceType source: signature source
        :raises InvalidInputException: if data type is not a fixed length or violates storage constraints.
        :raises VariableSizeException: if data type size causes a conflict with other variables
        
        .. seealso::
        
            | :obj:`.setDataType(DataType, boolean, boolean, SourceType)`
        """

    @typing.overload
    def setDataType(self, type: ghidra.program.model.data.DataType, alignStack: typing.Union[jpype.JBoolean, bool], force: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Set the Data Type of this variable. The given dataType must have a fixed length.
        
        :param ghidra.program.model.data.DataType type: the data type
        :param jpype.JBoolean or bool alignStack: maintain proper stack alignment/justification if supported by implementation.
                    If false and this is a stack variable, the current stack address/offset will not change.
                    If true, the affect is implementation dependent since alignment can
                    not be performed without access to a compiler specification.
        :param jpype.JBoolean or bool force: overwrite conflicting variables
        :param ghidra.program.model.symbol.SourceType source: signature source
        :raises InvalidInputException: if data type is not a fixed length or violates storage constraints.
        :raises VariableSizeException: if force is false and data type size causes a conflict 
        with other variables
        """

    def setName(self, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Set the name of this variable.
        
        :param java.lang.String or str name: the name
        :param ghidra.program.model.symbol.SourceType source: the source of this variable name
        :raises DuplicateNameException: if the name collides with the name of another variable.
        :raises InvalidInputException: if name contains blank characters, is zero length, or is null
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def uniqueVariable(self) -> jpype.JBoolean:
        ...

    @property
    def memoryVariable(self) -> jpype.JBoolean:
        ...

    @property
    def compoundVariable(self) -> jpype.JBoolean:
        ...

    @property
    def stackVariable(self) -> jpype.JBoolean:
        ...

    @property
    def stackOffset(self) -> jpype.JInt:
        ...

    @property
    def firstUseOffset(self) -> jpype.JInt:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def lastStorageVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def source(self) -> ghidra.program.model.symbol.SourceType:
        ...

    @property
    def program(self) -> Program:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def function(self) -> Function:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def registers(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def variableStorage(self) -> VariableStorage:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def registerVariable(self) -> jpype.JBoolean:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def firstStorageVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...


class FlowOverride(java.lang.Enum[FlowOverride]):

    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[FlowOverride]
    """
    No flow override has been established
    """

    BRANCH: typing.Final[FlowOverride]
    """
    Override the primary CALL or RETURN with a suitable JUMP operation.
    Pcode mapping:     CALL -> BRANCH     CALLIND -> BRANCHIND     RETURN -> BRANCHIND
    """

    CALL: typing.Final[FlowOverride]
    """
    Override the primary BRANCH or RETURN with a suitable CALL operation.
        Pcode mapping:        BRANCH -> CALL     BRANCHIND -> CALLIND     CBRANCH <addr>,<cond> -> (complex mapping)         tmp = BOOL_NEGATE <cond>         CBRANCH <label>,tmp         CALL <addr>       <label>     RETURN -> CALLIND
    """

    CALL_RETURN: typing.Final[FlowOverride]
    """
    Override the primary BRANCH, CALL, or RETURN with a suitable CALL/RETURN operation 
        Pcode mapping:        BRANCH -> CALL/RETURN     BRANCHIND -> CALLIND/RETURN     CBRANCH <addr>,<cond> -> (complex mapping)         tmp = BOOL_NEGATE <cond>         CBRANCH <label>,tmp         CALL <addr>         RETURN 0       <label>     CALL -> CALL/RETURN     CALLIND -> CALLIND/RETURN     RETURN -> CALLIND/RETURN
    """

    RETURN: typing.Final[FlowOverride]
    """
    Override the primary BRANCH or CALL with a suitable RETURN operation.
    Pcode mapping:     BRANCH <addr>  -> (complex mapping)         tmp = COPY &<addr>         RETURN tmp     BRANCHIND -> RETURN     CBRANCH <addr>,<cond>  -> (complex mapping)         tmp = BOOL_NEGATE <cond>         CBRANCH <label>,tmp         tmp2 = COPY &<addr>         RETURN tmp2       <label>     CALL <addr>    -> (complex mapping)         tmp = COPY &<addr>         RETURN tmp     CALLIND -> RETURN
    """


    @staticmethod
    def getFlowOverride(ordinal: typing.Union[jpype.JInt, int]) -> FlowOverride:
        """
        Return FlowOrdinal with the specified ordinal value.
        NONE will be returned for an unknown value.
        
        :param jpype.JInt or int ordinal: 
        :return: FlowOrdinal
        :rtype: FlowOverride
        """

    @staticmethod
    def getModifiedFlowType(originalFlowType: ghidra.program.model.symbol.FlowType, flowOverride: FlowOverride) -> ghidra.program.model.symbol.FlowType:
        """
        Get modified FlowType resulting from the application of the specified flowOverride
        
        :param ghidra.program.model.symbol.FlowType originalFlowType: 
        :param FlowOverride flowOverride: 
        :return: modified flow type
        :rtype: ghidra.program.model.symbol.FlowType
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> FlowOverride:
        ...

    @staticmethod
    def values() -> jpype.JArray[FlowOverride]:
        ...


class FunctionManager(ghidra.program.database.ManagerDB):
    """
    The manager for functions
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def createFunction(self, name: typing.Union[java.lang.String, str], entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> Function:
        """
        Create a function with the given body at entry point within the global namespace.
        
        :param java.lang.String or str name: the name of the new function or null for default name
        :param ghidra.program.model.address.Address entryPoint: entry point of function
        :param ghidra.program.model.address.AddressSetView body: addresses contained in the function body
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :return: new function or null if one or more functions overlap the specified body address set.
        :rtype: Function
        :raises InvalidInputException: if the name has invalid characters
        :raises OverlappingFunctionException: if the address set of the body overlaps an existing
                    function
        """

    @typing.overload
    def createFunction(self, name: typing.Union[java.lang.String, str], nameSpace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> Function:
        """
        Create a function with the given body at entry point.
        
        :param java.lang.String or str name: the name of the new function or null for default name
        :param ghidra.program.model.symbol.Namespace nameSpace: the nameSpace in which to create the function
        :param ghidra.program.model.address.Address entryPoint: entry point of function
        :param ghidra.program.model.address.AddressSetView body: addresses contained in the function body
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :return: new function or null if one or more functions overlap the specified body address set.
        :rtype: Function
        :raises InvalidInputException: if the name has invalid characters
        :raises OverlappingFunctionException: if the address set of the body overlaps an existing
                    function
        """

    def createThunkFunction(self, name: typing.Union[java.lang.String, str], nameSpace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, thunkedFunction: Function, source: ghidra.program.model.symbol.SourceType) -> Function:
        """
        Create a thunk function with the given body at entry point.
        
        :param java.lang.String or str name: the name of the new function or null for default name
        :param ghidra.program.model.symbol.Namespace nameSpace: the nameSpace in which to create the function
        :param ghidra.program.model.address.Address entryPoint: entry point of function
        :param ghidra.program.model.address.AddressSetView body: addresses contained in the function body
        :param Function thunkedFunction: referenced function (required is creating a thunk function)
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :return: new function or null if one or more functions overlap the specified body address set.
        :rtype: Function
        :raises OverlappingFunctionException: if the address set of the body overlaps an existing
                    function
        """

    def getCallingConvention(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the prototype model of the calling convention with the specified name in this program
        
        :param java.lang.String or str name: the calling convention name
        :return: the named function calling convention prototype model or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    def getCallingConventionNames(self) -> java.util.Collection[java.lang.String]:
        """
        Get the ordered list of defined calling convention names.  The reserved names 
        "unknown" and "default" are not included.  The returned collection may not include all names 
        referenced by various functions and function-definitions.  This set is limited to those
        defined by the associated compiler specification.  
        See :obj:`DataTypeManager.getDefinedCallingConventionNames`.
         
        
        For a set of all known names (including those that are not defined by compiler spec)
        see :meth:`DataTypeManager.getKnownCallingConventionNames() <DataTypeManager.getKnownCallingConventionNames>`.
        
        :return: the calling convention names.
        :rtype: java.util.Collection[java.lang.String]
        """

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the default calling convention's prototype model in this program.
        
        :return: the default calling convention prototype model or null.
        :rtype: ghidra.program.model.lang.PrototypeModel
        """

    def getExternalFunctions(self) -> FunctionIterator:
        """
        Get an iterator over all external functions. Functions returned have no particular order.
        
        :return: an iterator over external functions
        :rtype: FunctionIterator
        """

    def getFunction(self, key: typing.Union[jpype.JLong, int]) -> Function:
        """
        Get a Function object by its key
        
        :param jpype.JLong or int key: function symbol key
        :return: function object or null if not found
        :rtype: Function
        """

    def getFunctionAt(self, entryPoint: ghidra.program.model.address.Address) -> Function:
        """
        Get the function at entryPoint
        
        :param ghidra.program.model.address.Address entryPoint: the entry point
        :return: null if there is no function at entryPoint
        :rtype: Function
        """

    def getFunctionContaining(self, addr: ghidra.program.model.address.Address) -> Function:
        """
        Get a function containing an address.
        
        :param ghidra.program.model.address.Address addr: address within the function
        :return: function containing this address, null otherwise
        :rtype: Function
        """

    def getFunctionCount(self) -> int:
        """
        Returns the total number of functions in the program including external functions
        
        :return: the count
        :rtype: int
        """

    def getFunctionTagManager(self) -> FunctionTagManager:
        """
        Returns the function tag manager
        
        :return: the function tag manager
        :rtype: FunctionTagManager
        """

    @typing.overload
    def getFunctions(self, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Returns an iterator over all non-external functions in address (entry point) order
        
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: the iterator
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctions(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over non-external functions starting at an address and ordered by entry
        address
        
        :param ghidra.program.model.address.Address start: starting address
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: an iterator over functions.
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctions(self, asv: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over functions with entry points in the specified address set. Function are
        ordered based upon entry address.
        
        :param ghidra.program.model.address.AddressSetView asv: address set to iterate over
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: an iterator over functions.
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctionsNoStubs(self, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Returns an iterator over all REAL functions in address (entry point) order (real functions
        have instructions, and aren't stubs)
        
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: the iterator
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctionsNoStubs(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over REAL functions starting at an address and ordered by entry address (real
        functions have instructions, and aren't stubs).
        
        :param ghidra.program.model.address.Address start: starting address
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: an iterator over functions.
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctionsNoStubs(self, asv: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over REAL functions with entry points in the specified address set (real
        functions have instructions, and aren't stubs). Functions are ordered based upon entry
        address.
        
        :param ghidra.program.model.address.AddressSetView asv: address set to iterate over
        :param jpype.JBoolean or bool forward: true means to iterate in ascending address order
        :return: an iterator over functions.
        :rtype: FunctionIterator
        """

    def getFunctionsOverlapping(self, set: ghidra.program.model.address.AddressSetView) -> java.util.Iterator[Function]:
        """
        Return an iterator over functions that overlap the given address set.
        
        :param ghidra.program.model.address.AddressSetView set: address set of interest
        :return: iterator over Functions
        :rtype: java.util.Iterator[Function]
        """

    def getProgram(self) -> Program:
        """
        Returns this manager's program
        
        :return: the program
        :rtype: Program
        """

    def getReferencedFunction(self, address: ghidra.program.model.address.Address) -> Function:
        """
        Get the function which resides at the specified address or is referenced from the specified 
        address
        
        :param ghidra.program.model.address.Address address: function address or address of pointer to a function.
        :return: referenced function or null
        :rtype: Function
        """

    def getReferencedVariable(self, instrAddr: ghidra.program.model.address.Address, storageAddr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], isRead: typing.Union[jpype.JBoolean, bool]) -> Variable:
        """
        Attempts to determine which if any of the local functions variables are referenced by the
        specified reference. In utilizing the firstUseOffset scoping model, negative offsets
        (relative to the functions entry) are shifted beyond the maximum positive offset within the
        function. While this does not account for the actual instruction flow, it is hopefully
        accurate enough for most situations.
        
        :param ghidra.program.model.address.Address instrAddr: the instruction address
        :param ghidra.program.model.address.Address storageAddr: the storage address
        :param jpype.JInt or int size: varnode size in bytes (1 is assumed if value <= 0)
        :param jpype.JBoolean or bool isRead: true if the reference is a read reference
        :return: referenced variable or null if one not found
        :rtype: Variable
        """

    def invalidateCache(self, all: typing.Union[jpype.JBoolean, bool]):
        """
        Clears all data caches
        
        :param jpype.JBoolean or bool all: if false, some managers may not need to update their cache if they can
        tell that its not necessary.  If this flag is true, then all managers should clear
        their cache no matter what.
        """

    def isInFunction(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if this address contains a function.
        
        :param ghidra.program.model.address.Address addr: address to check
        :return: true if this address is contained in a function.
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all objects within an address range to a new location
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved
        :param jpype.JLong or int length: the number of addresses to move
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to use in any upgrade operations
        :raises CancelledException: if the user cancelled the operation via the task monitor
        """

    def removeFunction(self, entryPoint: ghidra.program.model.address.Address) -> bool:
        """
        Remove a function defined at entryPoint
        
        :param ghidra.program.model.address.Address entryPoint: the entry point
        :return: true if the function was removed
        :rtype: bool
        """

    @property
    def functionsNoStubs(self) -> FunctionIterator:
        ...

    @property
    def externalFunctions(self) -> FunctionIterator:
        ...

    @property
    def functions(self) -> FunctionIterator:
        ...

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def defaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        ...

    @property
    def functionContaining(self) -> Function:
        ...

    @property
    def functionAt(self) -> Function:
        ...

    @property
    def program(self) -> Program:
        ...

    @property
    def functionCount(self) -> jpype.JInt:
        ...

    @property
    def inFunction(self) -> jpype.JBoolean:
        ...

    @property
    def functionsOverlapping(self) -> java.util.Iterator[Function]:
        ...

    @property
    def referencedFunction(self) -> Function:
        ...

    @property
    def callingConventionNames(self) -> java.util.Collection[java.lang.String]:
        ...

    @property
    def function(self) -> Function:
        ...

    @property
    def functionTagManager(self) -> FunctionTagManager:
        ...


class FunctionIterator(java.util.Iterator[Function], java.lang.Iterable[Function]):
    """
    Interface for iterating over functions.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class_: typing.ClassVar[java.lang.Class]


class DataTypeChangeSet(ghidra.framework.model.ChangeSet):
    """
    Interface for a Data Type Change set.  Objects that implements this interface track
    various change information on a data type manager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def categoryAdded(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the data type category id to the list of categories that have been added.
        """

    def categoryChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        adds the data type category id to the list of categories that have changed.
        """

    def dataTypeAdded(self, id: typing.Union[jpype.JLong, int]):
        """
        Adds the data type ID to the list of added data types.
        
        :param jpype.JLong or int id:
        """

    def dataTypeChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        Adds the dataType ID to the list of changed data types.
        """

    def getCategoryAdditions(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of category IDs that have been added.
        """

    def getCategoryChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        returns the list of category IDs that have changed.
        """

    def getDataTypeAdditions(self) -> jpype.JArray[jpype.JLong]:
        """
        returns a list of data type IDs that have been added.
        """

    def getDataTypeChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        returns a list of data type IDs that have changed.
        """

    def getSourceArchiveAdditions(self) -> jpype.JArray[jpype.JLong]:
        """
        returns a list of data type source archive IDs that have been added.
        """

    def getSourceArchiveChanges(self) -> jpype.JArray[jpype.JLong]:
        """
        returns a list of data type source archive IDs that have changed.
        """

    def sourceArchiveAdded(self, id: typing.Union[jpype.JLong, int]):
        """
        Adds the data type source archive ID to the list of added data type archive IDs.
        
        :param jpype.JLong or int id: the data type source archive ID
        """

    def sourceArchiveChanged(self, id: typing.Union[jpype.JLong, int]):
        """
        Adds the data type source archive ID to the list of changed data type archive IDs.
        """

    @property
    def sourceArchiveChanges(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def categoryChanges(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def dataTypeChanges(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def dataTypeAdditions(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def categoryAdditions(self) -> jpype.JArray[jpype.JLong]:
        ...

    @property
    def sourceArchiveAdditions(self) -> jpype.JArray[jpype.JLong]:
        ...


class ReturnParameterImpl(ParameterImpl):
    """
    ``ReturnParameterImpl`` represent the function return value.
    This is special type of parameter whose ordinal is -1 and allows for the use
    of the 'void' datatype.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, param: Parameter, program: Program):
        """
        Construct a return parameter from another.
        
        :param Parameter param: parameter to be copied
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, program: Program):
        """
        Construct a return parameter which has no specific storage specified.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, stackOffset: typing.Union[jpype.JInt, int], program: Program):
        """
        Construct a return parameter at the specified stack offset.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param jpype.JInt or int stackOffset: stack offset
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, register: ghidra.program.model.lang.Register, program: Program):
        """
        Construct a return parameter using the specified register.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.lang.Register register: storage register
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, storageAddr: ghidra.program.model.address.Address, program: Program):
        """
        Construct a return parameter with a single varnode at the specified address.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param ghidra.program.model.address.Address storageAddr: storage address or null if no storage has been identified
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        address is specified, or unable to resolve storage element for specified datatype
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, storage: VariableStorage, program: Program):
        """
        Construct a return parameter with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage or null for unassigned storage
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, storage: VariableStorage, force: typing.Union[jpype.JBoolean, bool], program: Program):
        """
        Construct a return parameter with one or more associated storage elements.  Storage elements
        may get slightly modified to adjust for the resolved datatype size.
        
        :param ghidra.program.model.data.DataType dataType: a fixed-length datatype.  (NOTE: Should be cloned to program datatype manager
        prior to determining storage elements since their length may change)
        :param VariableStorage storage: variable storage or null for unassigned storage
        :param jpype.JBoolean or bool force: if true storage will be forced even if incorrect size
        :param Program program: target program
        :raises InvalidInputException: if dataType restrictions are violated, an invalid storage 
        element is specified, or error while resolving storage element for specified datatype
        """


class DataIterator(java.util.Iterator[Data], java.lang.Iterable[Data]):
    """
    Interface to define an iterator over some set of Data.
    
    
    .. seealso::
    
        | :obj:`CollectionUtils.asIterable`
    """

    class IteratorWrapper(DataIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[DataIterator]

    @staticmethod
    def of(*dataInstances: Data) -> DataIterator:
        """
        Create a DataIterator that returns a sequence of the specified items.
        
        :param jpype.JArray[Data] dataInstances: variable length list of items that will be iterated
        :return: new Iterator
        :rtype: DataIterator
        """


class ProgramUserData(ghidra.framework.model.UserData):

    class_: typing.ClassVar[java.lang.Class]

    def endTransaction(self, transactionID: typing.Union[jpype.JInt, int]):
        """
        End a previously started transaction
        
        :param jpype.JInt or int transactionID: the id of the transaction to close
        """

    def getBooleanProperty(self, owner: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.util.VoidPropertyMap:
        """
        Get a address-based Boolean property map
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :param java.lang.String or str propertyName: the name of property map
        :param jpype.JBoolean or bool create: creates the property map if it does not exist
        :return: property map
        :rtype: ghidra.program.model.util.VoidPropertyMap
        :raises PropertyTypeMismatchException: if a conflicting map definition was found
        """

    def getIntProperty(self, owner: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.util.IntPropertyMap:
        """
        Get a address-based Integer property map
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :param java.lang.String or str propertyName: the name of property map
        :param jpype.JBoolean or bool create: creates the property map if it does not exist
        :return: property map
        :rtype: ghidra.program.model.util.IntPropertyMap
        :raises PropertyTypeMismatchException: if a conflicting map definition was found
        """

    def getLongProperty(self, owner: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.util.LongPropertyMap:
        """
        Get a address-based Long property map
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :param java.lang.String or str propertyName: the name of property map
        :param jpype.JBoolean or bool create: creates the property map if it does not exist
        :return: property map
        :rtype: ghidra.program.model.util.LongPropertyMap
        :raises PropertyTypeMismatchException: if a conflicting map definition was found
        """

    def getObjectProperty(self, owner: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], saveableObjectClass: java.lang.Class[T], create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.util.ObjectPropertyMap[T]:
        """
        Get a address-based Saveable-object property map
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :param java.lang.String or str propertyName: the name of property map
        :param java.lang.Class[T] saveableObjectClass: the class type for the object property map
        :param jpype.JBoolean or bool create: creates the property map if it does not exist
        :param T: :obj:`Saveable` property value type:return: property map
        :rtype: ghidra.program.model.util.ObjectPropertyMap[T]
        :raises PropertyTypeMismatchException: if a conflicting map definition was found
        """

    def getOptions(self, optionsName: typing.Union[java.lang.String, str]) -> ghidra.framework.options.Options:
        """
        Get the Options for the given optionsName
        
        :param java.lang.String or str optionsName: the name of the options to retrieve
        :return: The options for the given name
        :rtype: ghidra.framework.options.Options
        """

    def getOptionsNames(self) -> java.util.List[java.lang.String]:
        """
        Returns all names of all the Options objects store in the user data
        
        :return: all names of all the Options objects store in the user data
        :rtype: java.util.List[java.lang.String]
        """

    def getProperties(self, owner: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.util.PropertyMap[typing.Any]]:
        """
        Get all property maps associated with a specific owner.
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :return: list of property maps
        :rtype: java.util.List[ghidra.program.model.util.PropertyMap[typing.Any]]
        """

    def getPropertyOwners(self) -> java.util.List[java.lang.String]:
        """
        Returns list of all property owners for which property maps have been defined.
        
        :return: list of all property owners for which property maps have been defined.
        :rtype: java.util.List[java.lang.String]
        """

    @typing.overload
    def getStringProperty(self, owner: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], create: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.util.StringPropertyMap:
        """
        Get a address-based String property map
        
        :param java.lang.String or str owner: name of property owner (e.g., plugin name)
        :param java.lang.String or str propertyName: the name of property map
        :param jpype.JBoolean or bool create: creates the property map if it does not exist
        :return: the property map for the given name
        :rtype: ghidra.program.model.util.StringPropertyMap
        :raises PropertyTypeMismatchException: if a conflicting map definition was found
        """

    @typing.overload
    def getStringProperty(self, propertyName: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Gets the value for the given property name
        
        :param java.lang.String or str propertyName: the name of the string property to retrieve
        :param java.lang.String or str defaultValue: the value to return if there is no saved value for the given name
        :return: the value for the given property name
        :rtype: str
        """

    def getStringPropertyNames(self) -> java.util.Set[java.lang.String]:
        """
        Returns a set of all String properties that have been set on this ProgramUserData object
        
        :return: a set of all String properties that have been set on this ProgramUserData object
        :rtype: java.util.Set[java.lang.String]
        """

    def openTransaction(self) -> db.Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         
        try (Transaction tx = pud.openTransaction(description)) {
            // ... Do something
        }
         
        
        :return: transaction object
        :rtype: db.Transaction
        :raises IllegalStateException: if this :obj:`ProgramUserData` has already been closed.
        """

    def removeStringProperty(self, propertyName: typing.Union[java.lang.String, str]) -> str:
        """
        Removes the String property with the given name;
        
        :param java.lang.String or str propertyName: the name of the property to remove;
        :return: returns the value of the property that was removed or null if the property doesn't
        exist
        :rtype: str
        """

    def setStringProperty(self, propertyName: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]):
        """
        Sets the given String property
        
        :param java.lang.String or str propertyName: the name of the property
        :param java.lang.String or str value: the value of the property
        """

    def startTransaction(self) -> int:
        """
        Start a transaction prior to changing any properties
        
        :return: transaction ID needed for endTransaction
        :rtype: int
        """

    @property
    def stringPropertyNames(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def propertyOwners(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def options(self) -> ghidra.framework.options.Options:
        ...

    @property
    def optionsNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def properties(self) -> java.util.List[ghidra.program.model.util.PropertyMap[typing.Any]]:
        ...


class CircularDependencyException(ghidra.util.exception.UsrException):
    """
    ``CircularDependencyException`` is thrown in cases where
    an action would cause the program's module structure to have a
    "cycle", that is to have two module which are both ancestors and
    descendants of each other.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class Listing(java.lang.Object):
    """
    This interface provides all the methods needed to create,delete, retrieve,
    modify code level constructs (CodeUnits, Macros, Fragments, and Modules).
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_TREE_NAME: typing.Final = "Program Tree"
    """
    The name of the default tree in the display.
    
    
    .. seealso::
    
        | :obj:`.removeTree(String)`
    """


    def addInstructions(self, instructionSet: ghidra.program.model.lang.InstructionSet, overwrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSetView:
        """
        Creates a complete set of instructions. A preliminary pass will be made
        checking for code unit conflicts which will be marked within the
        instructionSet causing dependent blocks to get pruned.
        
        :param ghidra.program.model.lang.InstructionSet instructionSet: the set of instructions to be added. All code unit
                    conflicts will be marked within the instructionSet and
                    associated blocks.
        :param jpype.JBoolean or bool overwrite: if true, overwrites existing code units.
        :raises CodeUnitInsertionException: if the instruction set is incompatible
                    with the program memory
        :return: the set of addresses over which instructions were actually added
                to the program. This may differ from the InstructionSet address
                set if conflict errors occurred. Such conflict errors will be
                recorded within the InstructionSet and its InstructionBlocks.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def clearAll(self, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all CodeUnits, comments, properties, and references from the
        listing.
        
        :param jpype.JBoolean or bool clearContext: if true, also clear any instruction context that has
                    been laid down from previous disassembly.
        :param ghidra.util.task.TaskMonitor monitor: used for tracking progress and cancelling the clear
                    operation.
        """

    @typing.overload
    def clearCodeUnits(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, clearContext: typing.Union[jpype.JBoolean, bool]):
        """
        Clears any code units in the given range returning everything to "db"s,
        and removing any references in the affected area. Note that the module
        and fragment structure is unaffected. If part of a code unit is contained
        in the given address range then the whole code unit will be cleared.
        
        :param ghidra.program.model.address.Address startAddr: the start address of the area to be cleared.
        :param ghidra.program.model.address.Address endAddr: the end address of the area to be cleared.
        :param jpype.JBoolean or bool clearContext: clear context register values if true
        """

    @typing.overload
    def clearCodeUnits(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, clearContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Clears any code units in the given range returning everything to "db"s,
        and removing any references in the affected area. Note that the module
        and fragment structure is unaffected. If part of a code unit is contained
        in the given address range then the whole code unit will be cleared.
        
        :param ghidra.program.model.address.Address startAddr: the start address of the area to be cleared.
        :param ghidra.program.model.address.Address endAddr: the end address of the area to be cleared.
        :param jpype.JBoolean or bool clearContext: clear context register values if true
        :param ghidra.util.task.TaskMonitor monitor: monitor that can be used to cancel the clear operation
        :raises CancelledException: if the operation was cancelled.
        """

    def clearComments(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        """
        Clears the comments in the given range.
        
        :param ghidra.program.model.address.Address startAddr: the start address of the range to be cleared
        :param ghidra.program.model.address.Address endAddr: the end address of the range to be cleared
        """

    def clearProperties(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        Clears the properties in the given range.
        
        :param ghidra.program.model.address.Address startAddr: the start address of the range to be cleared
        :param ghidra.program.model.address.Address endAddr: the end address of the range to be cleared
        :param ghidra.util.task.TaskMonitor monitor: task monitor for cancelling operation.
        :raises CancelledException: if the operation was cancelled.
        """

    @typing.overload
    def createData(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> Data:
        """
        Creates a new defined Data object of a given length at the given address.
        This ignores the bytes that are present
        
        :param ghidra.program.model.address.Address addr: the address at which to create a new Data object.
        :param ghidra.program.model.data.DataType dataType: the Data Type that describes the type of Data object to
                    create.
        :param jpype.JInt or int length: the length of the datatype.
        :return: newly created data unit
        :rtype: Data
        :raises CodeUnitInsertionException: thrown if the new Instruction would
                        overlap and existing Instruction or defined data.
        """

    @typing.overload
    def createData(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType) -> Data:
        """
        Creates a new defined Data object at the given address. This ignores the
        bytes that are present
        
        :param ghidra.program.model.address.Address addr: the address at which to create a new Data object.
        :param ghidra.program.model.data.DataType dataType: the Data Type that describes the type of Data object to
                    create.
        :return: newly created data unit
        :rtype: Data
        :raises CodeUnitInsertionException: thrown if the new Instruction would
                        overlap and existing Instruction or defined data.
        """

    @typing.overload
    def createFunction(self, name: typing.Union[java.lang.String, str], entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> Function:
        """
        Create a function with an entry point and a body of addresses.
        
        :param java.lang.String or str name: the name of the function to create
        :param ghidra.program.model.address.Address entryPoint: the entry point for the function
        :param ghidra.program.model.address.AddressSetView body: the address set that makes up the functions body
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :return: the created function
        :rtype: Function
        :raises InvalidInputException: if the name contains invalid characters
        :raises OverlappingFunctionException: if the given body overlaps with an
                    existing function.
        """

    @typing.overload
    def createFunction(self, name: typing.Union[java.lang.String, str], nameSpace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> Function:
        """
        Create a function in the specified namespace with an entry point and a
        body of addresses.
        
        :param java.lang.String or str name: the name of the function to create
        :param ghidra.program.model.symbol.Namespace nameSpace: the namespace in which to create the function
        :param ghidra.program.model.address.Address entryPoint: the entry point for the function
        :param ghidra.program.model.address.AddressSetView body: the address set that makes up the functions body
        :param ghidra.program.model.symbol.SourceType source: the source of this function
        :return: the created function
        :rtype: Function
        :raises InvalidInputException: if the name contains invalid characters
        :raises OverlappingFunctionException: if the given body overlaps with an
                    existing function.
        """

    def createInstruction(self, addr: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuf: ghidra.program.model.mem.MemBuffer, context: ghidra.program.model.lang.ProcessorContextView, length: typing.Union[jpype.JInt, int]) -> Instruction:
        """
        Creates a new Instruction object at the given address. The specified
        context is only used to create the associated prototype. It is critical
        that the context be written immediately after creation of the instruction
        and must be done with a single set operation on the program context. Once
        a set context is done on the instruction address, any subsequent context
        changes will result in a ``ContextChangeException``
        
        :param ghidra.program.model.address.Address addr: the address at which to create an instruction
        :param ghidra.program.model.lang.InstructionPrototype prototype: the InstructionPrototype that describes the type of instruction to create.
        :param ghidra.program.model.mem.MemBuffer memBuf: buffer that provides the bytes that make up the instruction.
        :param ghidra.program.model.lang.ProcessorContextView context: the processor context at this location.
        :param jpype.JInt or int length: instruction byte-length (must be in the range 0..prototype.getLength()).
        If smaller than the prototype length it must have a value no greater than 7, otherwise
        an error will be thrown.  A value of 0 or greater-than-or-equal the prototype length
        will be ignored and not impose and override length.  The length value must be a multiple 
        of the :meth:`instruction alignment <Language.getInstructionAlignment>` .
        :return: the newly created instruction.
        :rtype: Instruction
        :raises CodeUnitInsertionException: thrown if the new Instruction would overlap and 
        existing :obj:`CodeUnit` or the specified ``length`` is unsupported.
        :raises IllegalArgumentException: if a negative ``length`` is specified.
        """

    def createRootModule(self, treeName: typing.Union[java.lang.String, str]) -> ProgramModule:
        """
        Create a new tree that will be identified by the given name. By default,
        the new root module is populated with fragments based on memory blocks.
        Note that the root module's name is not the same as its tree name. The
        root module name defaults to the name of the program.
        
        :param java.lang.String or str treeName: name of the tree to search
        :return: root module
        :rtype: ProgramModule
        :raises DuplicateNameException: if a tree with the given name already
                    exists
        """

    def getAllComments(self, address: ghidra.program.model.address.Address) -> CodeUnitComments:
        """
        Get all the comments at the given address.
        
        :param ghidra.program.model.address.Address address: the address get comments
        :return: a CodeUnitComments object that has all the comments at the address.
        :rtype: CodeUnitComments
        """

    def getCodeUnitAfter(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        get the next code unit that starts at an address that is greater than the
        given address. The search will include instructions, defined data, and
        undefined data.
        
        :param ghidra.program.model.address.Address addr: the address from which to search forward.
        :return: the next CodeUnit found while searching forward from addr or null
                if none found.
        :rtype: CodeUnit
        """

    def getCodeUnitAt(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        get the code unit that starts at the given address.
        
        :param ghidra.program.model.address.Address addr: the address to look for a codeUnit.
        :return: the codeUnit that begins at the given address
        :rtype: CodeUnit
        """

    def getCodeUnitBefore(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        get the next code unit that starts at an address that is less than the
        given address. The search will include instructions, defined data, and
        undefined data.
        
        :param ghidra.program.model.address.Address addr: the address from which to search backwards.
        :return: The first codeUnit found while searching backwards from addr or
                null if none found.
        :rtype: CodeUnit
        """

    def getCodeUnitContaining(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        get the code unit that contains the given address.
        
        :param ghidra.program.model.address.Address addr: the address to look for a codeUnit.
        :return: the codeUnit that contains the given address
        :rtype: CodeUnit
        """

    @typing.overload
    def getCodeUnitIterator(self, property: typing.Union[java.lang.String, str], forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        Get an iterator that contains all code units in the program which have
        the specified property type defined. Standard property types are defined
        in the CodeUnit class. The property types are: EOL_COMMENT, PRE_COMMENT,
        POST_COMMENT, USER_REFERENCE, MNEMONIC_REFERENCE, VALUE_REFERENCE.
        Property types can also be user defined.
        
        :param java.lang.String or str property: the name of the property type.
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator that returns all code units from the indicated
                start address that have the specified property type defined.
        :rtype: CodeUnitIterator
        """

    @typing.overload
    def getCodeUnitIterator(self, property: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified
        property type defined. Only code units at an address greater than or
        equal to the specified start address will be returned by the iterator. If
        the start address is null then check the entire program. Standard
        property types are defined in the CodeUnit class. The property types are:
        EOL_COMMENT, PRE_COMMENT, POST_COMMENT, USER_REFERENCE,
        MNEMONIC_REFERENCE, VALUE_REFERENCE. Property types can also be user
        defined.
        
        :param java.lang.String or str property: the name of the property type. (EOL_COMMENT, PRE_COMMENT,
                    POST_COMMENT, USER_REFERENCE, MNEMONIC_REFERENCE,
                    VALUE_REFERENCE)
        :param ghidra.program.model.address.Address addr: the start address
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator that returns all code units from the indicated
                start address that have the specified property type defined.
        :rtype: CodeUnitIterator
        """

    @typing.overload
    def getCodeUnitIterator(self, property: typing.Union[java.lang.String, str], addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified
        property type defined. Only code units starting within the address set
        will be returned by the iterator. If the address set is null then check
        the entire program. Standard property types are defined in the CodeUnit
        class.
        
        :param java.lang.String or str property: the name of the property type.
        :param ghidra.program.model.address.AddressSetView addrSet: the address set
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator that returns all code units from the indicated
                address set that have the specified property type defined.
        :rtype: CodeUnitIterator
        """

    @typing.overload
    def getCodeUnits(self, forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        get a CodeUnit iterator that will iterate over the entire address space.
        
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator in forward direction
        :rtype: CodeUnitIterator
        """

    @typing.overload
    def getCodeUnits(self, addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        Returns an iterator of the code units in this listing (in proper
        sequence), starting at the specified address. The specified address
        indicates the first code unit that would be returned by an initial call
        to the ``next`` method. An initial call to the ``previous``
        method would return the code unit with an address less than the specified
        address.
        
        :param ghidra.program.model.address.Address addr: the start address of the iterator.
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator positioned just before addr.
        :rtype: CodeUnitIterator
        """

    @typing.overload
    def getCodeUnits(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> CodeUnitIterator:
        """
        Get an iterator over the address range(s). Only code units whose start
        addresses are contained in the given address set will be returned by the
        iterator.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the AddressRangeSet to iterate over (required).
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a CodeUnitIterator that is restricted to the give
                AddressRangeSet.
        :rtype: CodeUnitIterator
        """

    @typing.overload
    @deprecated("use getComment(CommentType, Address)")
    def getComment(self, commentType: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address) -> str:
        """
        Get the comment for the given type at the specified address.
        
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, POST_COMMENT,
                    PLATE_COMMENT, or REPEATABLE_COMMENT
        :param ghidra.program.model.address.Address address: the address of the comment.
        :return: the comment string of the appropriate type or null if no comment
                of that type exists for this code unit
        :rtype: str
        :raises IllegalArgumentException: if type is not one of the types of
                    comments supported
        
        .. deprecated::
        
        use :meth:`getComment(CommentType, Address) <.getComment>`
        """

    @typing.overload
    def getComment(self, type: CommentType, address: ghidra.program.model.address.Address) -> str:
        """
        Get the comment for the given type at the specified address.
        
        :param CommentType type: the comment type to retrieve
        :param ghidra.program.model.address.Address address: the address of the comment.
        :return: the comment string of the appropriate type or null if no comment
                of that type exists for this code unit
        :rtype: str
        """

    def getCommentAddressCount(self) -> int:
        """
        Returns the number of addresses where at least one comment type has been applied.
        
        :return: the number of addresses where at least one comment type has been applied
        :rtype: int
        """

    @typing.overload
    @deprecated("use getCommentAddressIterator(CommentType, AddressSetView, boolean)")
    def getCommentAddressIterator(self, commentType: typing.Union[jpype.JInt, int], addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Get a forward iterator over addresses that have the specified comment
        type.
        
        :param jpype.JInt or int commentType: type defined in CodeUnit
        :param ghidra.program.model.address.AddressSetView addrSet: address set to iterate code unit comments over
        :param jpype.JBoolean or bool forward: true to iterator from lowest address to highest, false
                    highest to lowest
        :return: an AddressIterator that returns all addresses from the indicated
                address set that have the specified comment type defined
        :rtype: ghidra.program.model.address.AddressIterator
        
        .. deprecated::
        
        use :meth:`getCommentAddressIterator(CommentType, AddressSetView, boolean) <.getCommentAddressIterator>`
        """

    @typing.overload
    def getCommentAddressIterator(self, type: CommentType, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Get a forward iterator over addresses that have the specified comment
        type.
        
        :param CommentType type: the type of comment to iterate over
        :param ghidra.program.model.address.AddressSetView addrSet: address set to iterate code unit comments over
        :param jpype.JBoolean or bool forward: true to iterator from lowest address to highest, false
                    highest to lowest
        :return: an AddressIterator that returns all addresses from the indicated
                address set that have the specified comment type defined
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    def getCommentAddressIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressIterator:
        """
        Get a forward iterator over addresses that have any type of comment.
        
        :param ghidra.program.model.address.AddressSetView addrSet: address set
        :param jpype.JBoolean or bool forward: true to iterator from lowest address to highest, false
                    highest to lowest
        :return: an AddressIterator that returns all addresses from the indicated
                address set that have any type of comment.
        :rtype: ghidra.program.model.address.AddressIterator
        """

    @typing.overload
    @deprecated("use getCommentCodeUnitIterator(CommentType, AddressSetView)")
    def getCommentCodeUnitIterator(self, commentType: typing.Union[jpype.JInt, int], addrSet: ghidra.program.model.address.AddressSetView) -> CodeUnitIterator:
        """
        Get a forward code unit iterator over code units that have the specified
        comment type.
        
        :param jpype.JInt or int commentType: type defined in CodeUnit
        :param ghidra.program.model.address.AddressSetView addrSet: address set
        :return: a CodeUnitIterator that returns all code units from the indicated
                address set that have the specified comment type defined
        :rtype: CodeUnitIterator
        
        .. deprecated::
        
        use :meth:`getCommentCodeUnitIterator(CommentType, AddressSetView) <.getCommentCodeUnitIterator>`
        """

    @typing.overload
    def getCommentCodeUnitIterator(self, type: CommentType, addrSet: ghidra.program.model.address.AddressSetView) -> CodeUnitIterator:
        """
        Get a forward code unit iterator over code units that have the specified
        comment type.
        
        :param CommentType type: the comment type
        :param ghidra.program.model.address.AddressSetView addrSet: address set to iterate code unit comments over
        :return: a CodeUnitIterator that returns all code units from the indicated
                address set that have the specified comment type defined
        :rtype: CodeUnitIterator
        """

    @typing.overload
    @deprecated("use getCommentHistory(Address, CommentType)")
    def getCommentHistory(self, addr: ghidra.program.model.address.Address, commentType: typing.Union[jpype.JInt, int]) -> jpype.JArray[CommentHistory]:
        """
        Get the comment history for comments at the given address.
        
        :param ghidra.program.model.address.Address addr: address for comments
        :param jpype.JInt or int commentType: comment type defined in CodeUnit
        :return: array of comment history records
        :rtype: jpype.JArray[CommentHistory]
        
        .. deprecated::
        
        use :meth:`getCommentHistory(Address, CommentType) <.getCommentHistory>`
        """

    @typing.overload
    def getCommentHistory(self, addr: ghidra.program.model.address.Address, type: CommentType) -> jpype.JArray[CommentHistory]:
        """
        Get the comment history for comments at the given address.
        
        :param ghidra.program.model.address.Address addr: address for comments
        :param CommentType type: :obj:`comment type <CommentType>`
        :return: array of comment history records
        :rtype: jpype.JArray[CommentHistory]
        """

    @typing.overload
    def getCompositeData(self, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Get an iterator over all the composite data objects (Arrays, Structures,
        and Union) in the program.
        
        :param jpype.JBoolean or bool forward: true means get iterator that starts at the minimum address
                    and iterates forward. Otherwise it starts at the maximum
                    address and iterates backwards.
        :return: an iterator over all the composite data objects.
        :rtype: DataIterator
        """

    @typing.overload
    def getCompositeData(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Get an iterator over all the composite data objects (Arrays, Structures,
        and Union) in the program at or after the given Address.
        
        :param ghidra.program.model.address.Address start: start of the iterator
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: an iterator over all the composite data objects starting with the
                given address.
        :rtype: DataIterator
        """

    @typing.overload
    def getCompositeData(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Get an iterator over all the composite data objects (Arrays, Structures,
        and Union) within the specified address set in the program.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address set
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: an iterator over all the composite data objects in the given
                address set.
        :rtype: DataIterator
        """

    @typing.overload
    def getData(self, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        get a Data iterator that will iterate over the entire address space;
        returning both defined and undefined Data objects.
        
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined and undefined Data
                object in the program.
        :rtype: DataIterator
        """

    @typing.overload
    def getData(self, addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Returns an iterator of the data in this listing (in proper sequence),
        starting at the specified address. The specified address indicates the
        first Data that would be returned by an initial call to the ``next``
        method. An initial call to the ``previous`` method would return the
        Data with an address less than the specified address.
        
        :param ghidra.program.model.address.Address addr: the initial position of the iterator
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all Data objects in the given
                address range set.
        :rtype: DataIterator
        """

    @typing.overload
    def getData(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Get an iterator over the address range(s). Only data whose start
        addresses are contained in the given address set will be returned by the
        iterator.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address range set to iterate over.
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined and undefined Data
                objects in the given address range set.
        :rtype: DataIterator
        """

    def getDataAfter(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the closest Data object that starts at an address that is greater
        than the given address.
        
        :param ghidra.program.model.address.Address addr: the address at which to begin the forward search.
        :return: the next Data object whose starting address is greater than addr.
        :rtype: Data
        """

    def getDataAt(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the Data (Defined or Undefined) that starts at the given address.
        
        :param ghidra.program.model.address.Address addr: the address to check for a Data object.
        :return: the Data object that starts at addr; or null if no Data
                objects(defined or undefined) start at addr.
        :rtype: Data
        """

    def getDataBefore(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the closest Data object that starts at an address that is less than
        the given address.
        
        :param ghidra.program.model.address.Address addr: The address at which to begin the backward search.
        :return: the closest Data object whose starting address is less than addr.
        :rtype: Data
        """

    def getDataContaining(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        Gets the data object that is at or contains the given address or null if
        the address in not in memory or is in an instruction.
        
        :param ghidra.program.model.address.Address addr: the address for which to find its containing data element.
        :return: the Data object containing the given address or null if there is
                no data that contains the address.
        :rtype: Data
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the data type manager for the program.
        
        :return: the datatype manager for the program.
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    def getDefaultRootModule(self) -> ProgramModule:
        """
        Returns the root module for the default program tree. This would be the
        program tree that has existed the longest.
        
        :return: the root module for the oldest existing program tree.
        :rtype: ProgramModule
        """

    def getDefinedCodeUnitAfter(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        Returns the next instruction or defined data after the given address;
        
        :param ghidra.program.model.address.Address addr: the address at which to begin the search
        :return: the next instruction or defined data at an address higher than
                the given address.
        :rtype: CodeUnit
        """

    def getDefinedCodeUnitBefore(self, addr: ghidra.program.model.address.Address) -> CodeUnit:
        """
        Returns the closest instruction or defined data that starts before the
        given address.
        
        :param ghidra.program.model.address.Address addr: the address at which to begin the search
        :return: the closest instruction or defined data at an address below the
                given address.
        :rtype: CodeUnit
        """

    @typing.overload
    def getDefinedData(self, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        get a Data iterator that will iterate over the entire address space;
        returning only defined Data objects.
        
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined Data objects in the
                program.
        :rtype: DataIterator
        """

    @typing.overload
    def getDefinedData(self, addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Returns an iterator of the defined data in this listing (in proper
        sequence), starting at the specified address. The specified address
        indicates the first defined Data that would be returned by an initial
        call to the ``next`` method. An initial call to the
        ``previous`` method would return the defined Data with an address
        less than the specified address.
        
        :param ghidra.program.model.address.Address addr: the initial position of the iterator
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined Data objects in the
                given address range set.
        :rtype: DataIterator
        """

    @typing.overload
    def getDefinedData(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> DataIterator:
        """
        Get an iterator over the address range(s). Only defined data whose start
        addresses are contained in the given address set will be returned by the
        iterator.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address range set to iterate over.
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined Data objects in the
                given address range set.
        :rtype: DataIterator
        """

    def getDefinedDataAfter(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the defined Data object that starts at an address that is greater
        than the given address.
        
        :param ghidra.program.model.address.Address addr: the address at which to begin the forward search.
        :return: the next defined Data object whose starting address is greater
                than addr.
        :rtype: Data
        """

    def getDefinedDataAt(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the Data (defined) object that starts at the given address. If no
        Data object is defined at that address, then return null.
        
        :param ghidra.program.model.address.Address addr: The address to check for defined Data.
        :return: a Data object that starts at addr, or null if no Data object has
                been defined to start at addr.
        :rtype: Data
        """

    def getDefinedDataBefore(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the closest defined Data object that starts at an address that is
        less than the given address.
        
        :param ghidra.program.model.address.Address addr: The address at which to begin the backward search.
        :return: the closest defined Data object whose starting address is less
                than addr.
        :rtype: Data
        """

    def getDefinedDataContaining(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the Data object that starts at the given address. If no Data objects
        have been defined that contain that address, then return null.
        
        :param ghidra.program.model.address.Address addr: the address to check for containment in a defined Data
                    object.
        :return: the defined Data object containing addr.
        :rtype: Data
        """

    def getExternalFunctions(self) -> FunctionIterator:
        """
        Get an iterator over all external functions
        
        :return: an iterator over all currently defined external functions.
        :rtype: FunctionIterator
        """

    def getFirstUndefinedData(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> Data:
        """
        Get the undefined Data object that falls within the set. This operation
        can be slow for large programs so a TaskMonitor is required.
        
        :param ghidra.program.model.address.AddressSetView set: the addressSet at which to find the first undefined address.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor allowing this operation to be cancelled
        :return: the next undefined Data object whose starting address falls
                within the addresSet.
        :rtype: Data
        """

    @typing.overload
    def getFragment(self, treeName: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address) -> ProgramFragment:
        """
        Returns the fragment containing the given address.
        
        :param java.lang.String or str treeName: name of the tree to search
        :param ghidra.program.model.address.Address addr: the address that is contained within a fragment.
        :return: will return null if the address is not in the program.
        :rtype: ProgramFragment
        """

    @typing.overload
    def getFragment(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ProgramFragment:
        """
        Returns the fragment with the given name.
        
        :param java.lang.String or str treeName: name of the tree to search
        :param java.lang.String or str name: the name of the fragment to find.
        :return: will return null if there is no fragment with the given name.
        :rtype: ProgramFragment
        """

    def getFunctionAt(self, entryPoint: ghidra.program.model.address.Address) -> Function:
        """
        Get a function with a given entry point.
        
        :param ghidra.program.model.address.Address entryPoint: entry point of the function
        :return: function at the entry point
        :rtype: Function
        """

    def getFunctionContaining(self, addr: ghidra.program.model.address.Address) -> Function:
        """
        Get a function containing an address.
        
        :param ghidra.program.model.address.Address addr: the address to search.
        :return: function containing this address, null otherwise
        :rtype: Function
        """

    @typing.overload
    def getFunctions(self, namespace: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> java.util.List[Function]:
        """
        Returns a list of all functions with the given name in the given
        namespace.
        
        :param java.lang.String or str namespace: the namespace to search for functions of the given name.
                    Can be null, in which case it will search the global
                    namespace.
        :param java.lang.String or str name: the name of the functions to retrieve.
        :return: a list of all global functions with the given name.
        :rtype: java.util.List[Function]
        """

    @typing.overload
    def getFunctions(self, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over all functions
        
        :param jpype.JBoolean or bool forward: if true functions are return in address order, otherwise
                    backwards address order
        :return: an iterator over all currently defined functions.
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctions(self, start: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over all functions starting at address
        
        :param ghidra.program.model.address.Address start: the address to start iterating at.
        :param jpype.JBoolean or bool forward: if true functions are return in address order, otherwise
                    backwards address order
        :return: an iterator over functions
        :rtype: FunctionIterator
        """

    @typing.overload
    def getFunctions(self, asv: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> FunctionIterator:
        """
        Get an iterator over all functions with entry points in the address set.
        
        :param ghidra.program.model.address.AddressSetView asv: the set of addresses to iterator function entry points over.
        :param jpype.JBoolean or bool forward: if true functions are return in address order, otherwise
                    backwards address order
        :return: an iterator over functions
        :rtype: FunctionIterator
        """

    def getGlobalFunctions(self, name: typing.Union[java.lang.String, str]) -> java.util.List[Function]:
        """
        Returns a list of all global functions with the given name.
        
        :param java.lang.String or str name: the name of the functions to retrieve.
        :return: a list of all global functions with the given name.
        :rtype: java.util.List[Function]
        """

    def getInstructionAfter(self, addr: ghidra.program.model.address.Address) -> Instruction:
        """
        get the closest Instruction that starts at an address that is greater
        than the given address.
        
        :param ghidra.program.model.address.Address addr: The address at which to begin the forward search.
        :return: the next Instruction whose starting address is greater than addr.
        :rtype: Instruction
        """

    def getInstructionAt(self, addr: ghidra.program.model.address.Address) -> Instruction:
        """
        get the Instruction that starts at the given address. If no Instruction
        has been defined to start at that address, return null.
        
        :param ghidra.program.model.address.Address addr: the address to check for the start of an instruction
        :return: the Instruction object that starts at addr; or null if no
                Instructions starts at addr.
        :rtype: Instruction
        """

    def getInstructionBefore(self, addr: ghidra.program.model.address.Address) -> Instruction:
        """
        get the closest Instruction that starts at an address that is less than
        the given address.
        
        :param ghidra.program.model.address.Address addr: The address at which to begin the backward search.
        :return: the closest Instruction whose starting address is less than addr.
        :rtype: Instruction
        """

    def getInstructionContaining(self, addr: ghidra.program.model.address.Address) -> Instruction:
        """
        get the Instruction that contains the given address. If an Instruction is
        defined that contains that address, it will be returned. Otherwise, null
        will be returned.
        
        :param ghidra.program.model.address.Address addr: the address to check for containment in an Instruction.
        :return: the Instruction object that contains addr; or null if no
                Instructions contain addr.
        :rtype: Instruction
        """

    @typing.overload
    def getInstructions(self, forward: typing.Union[jpype.JBoolean, bool]) -> InstructionIterator:
        """
        get an Instruction iterator that will iterate over the entire address
        space.
        
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: an InstructionIterator that iterates over all instructions in the
                program.
        :rtype: InstructionIterator
        """

    @typing.overload
    def getInstructions(self, addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> InstructionIterator:
        """
        Returns an iterator of the instructions in this listing (in proper
        sequence), starting at the specified address. The specified address
        indicates the first instruction that would be returned by an initial call
        to the ``next`` method. An initial call to the ``previous``
        method would return the instruction with an address less than the
        specified address.
        
        :param ghidra.program.model.address.Address addr: the initial position of the iterator
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: an InstructionIterator that iterates over all Instruction objects
                in the given address range set.
        :rtype: InstructionIterator
        """

    @typing.overload
    def getInstructions(self, addrSet: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]) -> InstructionIterator:
        """
        Get an Instruction iterator over the address range(s). Only instructions
        whose start addresses are contained in the given address set will be
        returned by the iterator.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address range set to iterate over.
        :param jpype.JBoolean or bool forward: true means get iterator in forward direction
        :return: a DataIterator that iterates over all defined and undefined Data
                objects in the given address range set.
        :rtype: InstructionIterator
        """

    def getModule(self, treeName: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> ProgramModule:
        """
        Returns the module with the given name.
        
        :param java.lang.String or str treeName: name of the tree to search
        :param java.lang.String or str name: the name of the module to find.
        :return: will return null if there is no module with the given name.
        :rtype: ProgramModule
        """

    def getNumCodeUnits(self) -> int:
        """
        gets the total number of CodeUnits (Instructions, defined Data, and
        undefined Data)
        
        :return: the total number of CodeUnits in the listing.
        :rtype: int
        """

    def getNumDefinedData(self) -> int:
        """
        gets the total number of defined Data objects in the listing.
        
        :return: the total number of defined Data objects in the listing.
        :rtype: int
        """

    def getNumInstructions(self) -> int:
        """
        gets the total number of Instructions in the listing.
        
        :return: number of Instructions
        :rtype: int
        """

    def getPropertyMap(self, propertyName: typing.Union[java.lang.String, str]) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        """
        Returns the PropertyMap associated with the given name
        
        :param java.lang.String or str propertyName: the property name
        :return: PropertyMap the propertyMap object.
        :rtype: ghidra.program.model.util.PropertyMap[typing.Any]
        """

    @typing.overload
    def getRootModule(self, treeName: typing.Union[java.lang.String, str]) -> ProgramModule:
        """
        Gets the root module for a tree in this listing.
        
        :param java.lang.String or str treeName: name of tree
        :return: the root module for the listing; returns null if there is no tree
                rooted at a module with the given name.
        :rtype: ProgramModule
        """

    @typing.overload
    def getRootModule(self, treeID: typing.Union[jpype.JLong, int]) -> ProgramModule:
        """
        Returns the root module of the program tree with the given name;
        
        :param jpype.JLong or int treeID: id of the program tree
        :return: the root module of the specified tree.
        :rtype: ProgramModule
        """

    def getTreeNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of all the trees defined in this listing.
        
        :return: the names of all program trees defined in the program.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getUndefinedDataAfter(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> Data:
        """
        Get the undefined Data object that starts at an address that is greater
        than the given address. This operation can be slow for large programs so
        a TaskMonitor is required.
        
        :param ghidra.program.model.address.Address addr: the address at which to begin the forward search.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor allowing this operation to be cancelled
        :return: the next undefined Data object whose starting address is greater
                than addr.
        :rtype: Data
        """

    def getUndefinedDataAt(self, addr: ghidra.program.model.address.Address) -> Data:
        """
        get the Data (undefined) object that starts at the given address.
        
        :param ghidra.program.model.address.Address addr: The address to check for undefined data.
        :return: a default DataObject if bytes exist at addr and nothing has been
                defined to exist there. Otherwise returns null.
        :rtype: Data
        """

    def getUndefinedDataBefore(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> Data:
        """
        get the closest undefined Data object that starts at an address that is
        less than the given address. This operation can be slow for large
        programs so a TaskMonitor is required.
        
        :param ghidra.program.model.address.Address addr: The address at which to begin the backward search.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor allowing this operation to be cancelled
        :return: the closest undefined Data object whose starting address is less
                than addr.
        :rtype: Data
        """

    def getUndefinedRanges(self, set: ghidra.program.model.address.AddressSetView, initializedMemoryOnly: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set which corresponds to all undefined code units within
        the specified set of address.
        
        :param ghidra.program.model.address.AddressSetView set: set of addresses to search
        :param jpype.JBoolean or bool initializedMemoryOnly: if true set will be constrained to
                    initialized memory areas, if false set will be constrained to
                    all defined memory blocks.
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: address set corresponding to undefined code units
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException: if monitor cancelled
        """

    def getUserDefinedProperties(self) -> java.util.Iterator[java.lang.String]:
        """
        Returns an iterator over all user defined property names.
        
        :return: an iterator over all user defined property names.
        :rtype: java.util.Iterator[java.lang.String]
        """

    def isInFunction(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if an address is contained in a function
        
        :param ghidra.program.model.address.Address addr: address to test
        :return: true if this address is in one or more functions
        :rtype: bool
        """

    def isUndefined(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Checks if the given ranges consists entirely of undefined data.
        
        :param ghidra.program.model.address.Address start: The start address of the range to check.
        :param ghidra.program.model.address.Address end: The end address of the range to check.
        :return: boolean true if the given range is in memory and has no
                instructions or defined data.
        :rtype: bool
        """

    def removeFunction(self, entryPoint: ghidra.program.model.address.Address):
        """
        Remove a function a given entry point.
        
        :param ghidra.program.model.address.Address entryPoint: entry point of function to be removed.
        """

    def removeTree(self, treeName: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove the tree rooted at the given name.
        
        :param java.lang.String or str treeName: the name of the tree to remove.
        :return: true if the tree was removed; return false if this is the last
                tree for the program; cannot delete the last tree.
        :rtype: bool
        """

    def removeUserDefinedProperty(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Removes the entire property from the program
        
        :param java.lang.String or str propertyName: the name of the property to remove.
        """

    def renameTree(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Rename the tree. This method does not change the root module's name only
        the identifier for the tree.
        
        :param java.lang.String or str oldName: old name of the tree
        :param java.lang.String or str newName: new name of the tree.
        :raises DuplicateNameException: if newName already exists for a root
                    module
        """

    @typing.overload
    @deprecated("use setComment(Address, CommentType, String)")
    def setComment(self, address: ghidra.program.model.address.Address, commentType: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given comment type at the specified address.
        
        :param ghidra.program.model.address.Address address: the address of the comment.
        :param jpype.JInt or int commentType: either EOL_COMMENT, PRE_COMMENT, POST_COMMENT,
                    PLATE_COMMENT, or REPEATABLE_COMMENT
        :param java.lang.String or str comment: comment to set at the address
        :raises IllegalArgumentException: if type is not one of the types of
                    comments supported
        
        .. deprecated::
        
        use :meth:`setComment(Address, CommentType, String) <.setComment>`
        """

    @typing.overload
    def setComment(self, address: ghidra.program.model.address.Address, type: CommentType, comment: typing.Union[java.lang.String, str]):
        """
        Set the comment for the given comment type at the specified address.
        
        :param ghidra.program.model.address.Address address: the address of the comment.
        :param CommentType type: the type of comment to set
        :param java.lang.String or str comment: comment to set at the address
        :raises IllegalArgumentException: if type is not one of the types of
                    comments supported
        """

    @property
    def definedDataContaining(self) -> Data:
        ...

    @property
    def instructions(self) -> InstructionIterator:
        ...

    @property
    def codeUnits(self) -> CodeUnitIterator:
        ...

    @property
    def allComments(self) -> CodeUnitComments:
        ...

    @property
    def functions(self) -> FunctionIterator:
        ...

    @property
    def definedData(self) -> DataIterator:
        ...

    @property
    def data(self) -> DataIterator:
        ...

    @property
    def instructionBefore(self) -> Instruction:
        ...

    @property
    def compositeData(self) -> DataIterator:
        ...

    @property
    def numCodeUnits(self) -> jpype.JLong:
        ...

    @property
    def functionContaining(self) -> Function:
        ...

    @property
    def definedDataAfter(self) -> Data:
        ...

    @property
    def dataBefore(self) -> Data:
        ...

    @property
    def dataAt(self) -> Data:
        ...

    @property
    def codeUnitAt(self) -> CodeUnit:
        ...

    @property
    def instructionAt(self) -> Instruction:
        ...

    @property
    def numInstructions(self) -> jpype.JLong:
        ...

    @property
    def definedCodeUnitAfter(self) -> CodeUnit:
        ...

    @property
    def instructionAfter(self) -> Instruction:
        ...

    @property
    def definedDataAt(self) -> Data:
        ...

    @property
    def userDefinedProperties(self) -> java.util.Iterator[java.lang.String]:
        ...

    @property
    def externalFunctions(self) -> FunctionIterator:
        ...

    @property
    def globalFunctions(self) -> java.util.List[Function]:
        ...

    @property
    def defaultRootModule(self) -> ProgramModule:
        ...

    @property
    def rootModule(self) -> ProgramModule:
        ...

    @property
    def functionAt(self) -> Function:
        ...

    @property
    def definedDataBefore(self) -> Data:
        ...

    @property
    def instructionContaining(self) -> Instruction:
        ...

    @property
    def codeUnitAfter(self) -> CodeUnit:
        ...

    @property
    def propertyMap(self) -> ghidra.program.model.util.PropertyMap[typing.Any]:
        ...

    @property
    def inFunction(self) -> jpype.JBoolean:
        ...

    @property
    def dataContaining(self) -> Data:
        ...

    @property
    def commentAddressCount(self) -> jpype.JLong:
        ...

    @property
    def undefinedDataAt(self) -> Data:
        ...

    @property
    def dataAfter(self) -> Data:
        ...

    @property
    def codeUnitContaining(self) -> CodeUnit:
        ...

    @property
    def treeNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def definedCodeUnitBefore(self) -> CodeUnit:
        ...

    @property
    def codeUnitBefore(self) -> CodeUnit:
        ...

    @property
    def numDefinedData(self) -> jpype.JLong:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...


class ProgramModule(Group):
    """
    A ``ProgramModule`` is a group of ``ProgramFragment``s 
    and/or other ``ProgramModule``s together with some related 
    information such as a name, comment, and alias. Users create modules to 
    overlay the program with a hierarchical structure. A *child* of a module 
    is a fragment or module which it directly contains. A *parent* of a module 
    is a module which has this module as a child. A module may be contained in more 
    than one module. A ``Program`` always has at least one module, the root module. 
    The root module cannot be removed and is the ancestor for all other modules and
    fragments in the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, module: ProgramModule):
        """
        Adds the given module as a child of this module.
        
        :param ProgramModule module: the module to be added.
        :raises CircularDependencyException: thrown if the module being
        added is an ancestor of this module. The module structure of
        a program does not allow "cycles" of this sort to be created.
        :raises DuplicateGroupException: thrown if the module being
        added is already a child of this module.
        """

    @typing.overload
    def add(self, fragment: ProgramFragment):
        """
        Adds the given fragment as a child of this module.
        
        :raises DuplicateGroupException: thrown if the fragment being
        added is already a child of this module.
        """

    @typing.overload
    def contains(self, fragment: ProgramFragment) -> bool:
        """
        Returns whether this module directly contains the
        given fragment as a child.
        
        :param ProgramFragment fragment: the fragment to check.
        """

    @typing.overload
    def contains(self, module: ProgramModule) -> bool:
        """
        Returns whether this module directly contains the
        given module as a child.
        
        :param ProgramModule module: the module to check.
        :return: true if module is the same as this module, or if module
        is a child of this module.
        :rtype: bool
        """

    def createFragment(self, fragmentName: typing.Union[java.lang.String, str]) -> ProgramFragment:
        """
        Creates a new fragment and makes it a child of this module.
        
        :param java.lang.String or str fragmentName: the name to use for the new fragment.
        :return: the newly created fragment.
        :rtype: ProgramFragment
        :raises DuplicateNameException: thrown if the given
        name is already used by an existing module or fragment.
        """

    def createModule(self, moduleName: typing.Union[java.lang.String, str]) -> ProgramModule:
        """
        Creates a new module and makes it a child of this
        module.
        
        :param java.lang.String or str moduleName: the name to use for the new module.
        :return: the newly created module.
        :rtype: ProgramModule
        :raises DuplicateNameException: thrown if the given
        name is already used by an existing module or fragment.
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the set of addresses for this module which will be the combined 
        set of addresses from the set of all fragments which are descendants of this
        module.
        
        :return: the complete address set for this module.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getChildren(self) -> jpype.JArray[Group]:
        """
        Returns an array containing this module's children.
        """

    def getFirstAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the first address of this module which will be the minimum
        address of the first descendant fragment which is non-empty. In other
        words this returns the first address for this module as defined by
        the user ordering of the module's children.
        
        :return: the first address, this will be null if all of the module's
        descendant fragments are empty.
        :rtype: ghidra.program.model.address.Address
        """

    def getIndex(self, name: typing.Union[java.lang.String, str]) -> int:
        """
        Get the index of the child with the given name.
        
        :param java.lang.String or str name: name of child
        :return: int index or -1 if this Module does not have a child
        with the given name
        :rtype: int
        """

    def getLastAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the last address of this module which will be the maximum address
        of the last descendant fragment which is non-empty. In other words this
        returns the last address for this module as defined by the user
        ordering of the module's children.
        
        :return: the last address, this will be null if all of the module's
        descendant fragments are empty.
        :rtype: ghidra.program.model.address.Address
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the maximum address of this module which will be the maximum
        address from the set of all fragments which are descendants of this
        module.
        
        :return: the maximum address, this will be null if all of the module's
        descendant fragments are empty.
        :rtype: ghidra.program.model.address.Address
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the minimum address of this module which will be the minimum
        address from the set of all fragments which are descendants of this
        module.
        
        :return: the minimum address, this will be null if all of the module's
        descendant fragments are empty.
        :rtype: ghidra.program.model.address.Address
        """

    def getModificationNumber(self) -> int:
        """
        Get the current modification number of the module tree; the number 
        is updated when ever a change is made to any module or fragment
        that is part of this module's root tree.
        """

    def getNumChildren(self) -> int:
        """
        Returns the number of children of this module.
        """

    def getTreeID(self) -> int:
        """
        Get the ID for the tree that this module belongs to.
        
        :return: ID for the tree
        :rtype: int
        """

    def getVersionTag(self) -> java.lang.Object:
        """
        Returns an object that can be used to detect when the module tree has been affected
        by an undo or redo. After an undo/redo, if this module was affected, then a new
        verionTag object is created.
        """

    @typing.overload
    def isDescendant(self, module: ProgramModule) -> bool:
        """
        Returns whether the given module is a descendant of this
        module.
        
        :param ProgramModule module: the module to check.
        :return: true if the module is a descendant, false otherwise.
        :rtype: bool
        """

    @typing.overload
    def isDescendant(self, fragment: ProgramFragment) -> bool:
        """
        Returns whether the given fragment is a descendant of this
        module.
        
        :param ProgramFragment fragment: the fragment to check.
        :return: true if the fragment is a descendant, false otherwise.
        :rtype: bool
        """

    def moveChild(self, name: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]):
        """
        Changes the ordering of this module's children by moving
        the child with the given name to position given by index.
        
        :param java.lang.String or str name: the name of the child to move.
        :param jpype.JInt or int index: the index to move it to.
        :raises NotFoundException: thrown if a child with the given
        name cannot be found in this module.
        """

    def removeChild(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Removes a child module or fragment from this Module.
        
        :return: true if successful, false if no child in this module has the given name.
        :rtype: bool
        :raises NotEmptyException: thrown if the module appears in no other
        modules and it is not empty.
        """

    def reparent(self, name: typing.Union[java.lang.String, str], oldParent: ProgramModule):
        """
        Reparents child with the given name to this Module; removes the
        child from oldParent.
        
        :param java.lang.String or str name: name of child to reparent
        :param ProgramModule oldParent: old parent
        :raises NotFoundException: if name is not the name of a child
        in oldParent
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def treeID(self) -> jpype.JLong:
        ...

    @property
    def children(self) -> jpype.JArray[Group]:
        ...

    @property
    def numChildren(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @property
    def versionTag(self) -> java.lang.Object:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def descendant(self) -> jpype.JBoolean:
        ...

    @property
    def lastAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def firstAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def modificationNumber(self) -> jpype.JLong:
        ...


class DataTypeArchive(ghidra.program.model.data.DataTypeManagerDomainObject):
    """
    This interface represents the main entry point into an object which
    stores all information relating to a single data type archive.
    """

    class_: typing.ClassVar[java.lang.Class]
    DATA_TYPE_ARCHIVE_INFO: typing.Final = "Data Type Archive Information"
    """
    Name of data type archive information property list
    """

    DATA_TYPE_ARCHIVE_SETTINGS: typing.Final = "Data Type Archive Settings"
    """
    Name of data type archive settings property list
    """

    DATE_CREATED: typing.Final = "Date Created"
    """
    Name of date created property
    """

    CREATED_WITH_GHIDRA_VERSION: typing.Final = "Created With Ghidra Version"
    """
    Name of ghidra version property
    """

    JANUARY_1_1970: typing.Final[java.util.Date]
    """
    A date from January 1, 1970
    """


    def getChanges(self) -> DataTypeArchiveChangeSet:
        """
        Get the data type archive changes since the last save as a set of addresses.
        
        :return: set of changed addresses within program.
        :rtype: DataTypeArchiveChangeSet
        """

    def getCreationDate(self) -> java.util.Date:
        """
        :return: the creation date of this data type archive or Jan 1, 1970 if unknown.
        :rtype: java.util.Date
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.StandAloneDataTypeManager:
        """
        :return: the associated standalone data type manager.
        :rtype: ghidra.program.model.data.StandAloneDataTypeManager
        """

    def getDefaultPointerSize(self) -> int:
        """
        :return: the default pointer size as it may be stored within the data type archive.
        :rtype: int
        """

    def invalidate(self):
        """
        Invalidates any caching in a data type archive.
        NOTE: Over-using this method can adversely affect system performance.
        """

    @property
    def changes(self) -> DataTypeArchiveChangeSet:
        ...

    @property
    def creationDate(self) -> java.util.Date:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.StandAloneDataTypeManager:
        ...

    @property
    def defaultPointerSize(self) -> jpype.JInt:
        ...


class BookmarkManager(java.lang.Object):
    """
    Interface for managing bookmarks.
    """

    class_: typing.ClassVar[java.lang.Class]
    OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1: typing.Final = "ghidra.app.plugin.bookmark.BookmarkInfo"
    """
    1st version of bookmark property object class (schema change and class moved)
    """

    OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2: typing.Final = "ghidra.program.util.Bookmark"
    """
    2nd version of bookmark property object class (class moved, property map no longer used)
    """


    def defineType(self, type: typing.Union[java.lang.String, str], icon: javax.swing.Icon, color: java.awt.Color, priority: typing.Union[jpype.JInt, int]) -> BookmarkType:
        """
        Define a bookmark type with its marker icon and color.  The icon and color
        values are not permanently stored.  Therefor, this method must be re-invoked
        by a plugin each time a program is opened if a custom icon and color 
        are desired.
        
        :param java.lang.String or str type: bookmark type
        :param javax.swing.Icon icon: marker icon which may get scaled
        :param java.awt.Color color: marker color
        :param jpype.JInt or int priority: the bookmark priority
        :return: bookmark type object
        :rtype: BookmarkType
        :raises IllegalArgumentException: if any of the arguments are null or if the type is empty
        """

    @typing.overload
    def getBookmark(self, addr: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str]) -> Bookmark:
        """
        Get a specific bookmark
        
        :param ghidra.program.model.address.Address addr: the address of the bookmark to retrieve
        :param java.lang.String or str type: the name of the bookmark type.
        :param java.lang.String or str category: the category of the bookmark.
        :return: the bookmark with the given attributes, or null if no bookmarks match.
        :rtype: Bookmark
        """

    @typing.overload
    def getBookmark(self, id: typing.Union[jpype.JLong, int]) -> Bookmark:
        """
        Returns the bookmark that has the given id or null if no such bookmark exists.
        
        :param jpype.JLong or int id: the id of the bookmark to be retrieved.
        :return: the bookmark
        :rtype: Bookmark
        """

    def getBookmarkAddresses(self, type: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSetView:
        """
        Get addresses for bookmarks of a specified type.
        
        :param java.lang.String or str type: bookmark type
        :return: address set containing bookmarks of the specified type.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @typing.overload
    def getBookmarkCount(self, type: typing.Union[java.lang.String, str]) -> int:
        """
        Return the number of bookmarks of the given type
        
        :param java.lang.String or str type: the type of bookmarks to count
        :return: the number of bookmarks of the given type
        :rtype: int
        """

    @typing.overload
    def getBookmarkCount(self) -> int:
        """
        Returns the total number of bookmarks in the program
        
        :return: the total number of bookmarks in the program
        :rtype: int
        """

    def getBookmarkType(self, type: typing.Union[java.lang.String, str]) -> BookmarkType:
        """
        Get a bookmark type
        
        :param java.lang.String or str type: bookmark type name
        :return: bookmark type or null if type is unknown
        :rtype: BookmarkType
        """

    def getBookmarkTypes(self) -> jpype.JArray[BookmarkType]:
        """
        Returns list of known bookmark types
        
        :return: list of known bookmark types
        :rtype: jpype.JArray[BookmarkType]
        """

    @typing.overload
    def getBookmarks(self, address: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str]) -> jpype.JArray[Bookmark]:
        """
        Get bookmarks of the indicated type on a specific address
        
        :param ghidra.program.model.address.Address address: the address at which to search for bookmarks.
        :param java.lang.String or str type: bookmark type to search for
        :return: array of bookmarks
        :rtype: jpype.JArray[Bookmark]
        """

    @typing.overload
    def getBookmarks(self, addr: ghidra.program.model.address.Address) -> jpype.JArray[Bookmark]:
        """
        Get all bookmarks on a specific address
        
        :param ghidra.program.model.address.Address addr: the address at which to retrieve all bookmarks.
        :return: array of bookmarks
        :rtype: jpype.JArray[Bookmark]
        """

    @typing.overload
    def getBookmarksIterator(self, type: typing.Union[java.lang.String, str]) -> java.util.Iterator[Bookmark]:
        """
        Get iterator over all bookmarks of the specified type.
        
        :param java.lang.String or str type: the bookmark type to search for
        :return: an iterator over all bookmarks of the specified type.
        :rtype: java.util.Iterator[Bookmark]
        """

    @typing.overload
    def getBookmarksIterator(self) -> java.util.Iterator[Bookmark]:
        """
        Returns an iterator over all bookmarks
        
        :return: an iterator over all bookmarks
        :rtype: java.util.Iterator[Bookmark]
        """

    @typing.overload
    def getBookmarksIterator(self, startAddress: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]) -> java.util.Iterator[Bookmark]:
        """
        Returns an iterator over all bookmark types, starting at the given address, with traversal
        in the given direction.
        
        :param ghidra.program.model.address.Address startAddress: the address at which to start
        :param jpype.JBoolean or bool forward: true to iterate in the forward direction; false for backwards
        :return: an iterator over all bookmark types, starting at the given address, with traversal
                    in the given direction.
        :rtype: java.util.Iterator[Bookmark]
        """

    def getCategories(self, type: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Get list of categories used for a specified type
        
        :param java.lang.String or str type: bookmark type
        :return: array of category strings
        :rtype: jpype.JArray[java.lang.String]
        """

    def getProgram(self) -> Program:
        """
        Returns the program associated with this BookmarkManager.
        
        :return: the program associated with this BookmarkManager.
        :rtype: Program
        """

    def hasBookmarks(self, type: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if program contains one or more bookmarks of the given type
        
        :param java.lang.String or str type: the type of bookmark to check for.
        :return: true if program contains one or more bookmarks of the given type
        :rtype: bool
        """

    def removeBookmark(self, bookmark: Bookmark):
        """
        Remove bookmark
        
        :param Bookmark bookmark: the bookmark to remove.
        """

    @typing.overload
    def removeBookmarks(self, type: typing.Union[java.lang.String, str]):
        """
        Removes all bookmarks of the given type.
        
        :param java.lang.String or str type: bookmark type
        """

    @typing.overload
    def removeBookmarks(self, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all bookmarks with the given type and category.
        
        :param java.lang.String or str type: the type of the bookmarks to be removed.
        :param java.lang.String or str category: bookmark category of the types to be removed.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to report the progress.
        :raises CancelledException: if the user (via the monitor) cancelled the operation.
        """

    @typing.overload
    def removeBookmarks(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all bookmarks over the given address set.
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses from which to remove all bookmarks.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to report the progress.
        :raises CancelledException: if the user (via the monitor) cancelled the operation.
        """

    @typing.overload
    def removeBookmarks(self, set: ghidra.program.model.address.AddressSetView, type: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all bookmarks of the given type over the given address set
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses from which to remove all bookmarks of the given type.
        :param java.lang.String or str type: the type of bookmarks to remove.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to report the progress.
        :raises CancelledException: if the user (via the monitor) cancelled the operation.
        """

    @typing.overload
    def removeBookmarks(self, set: ghidra.program.model.address.AddressSetView, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        Removes all bookmarks of the given type and category over the given address set
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses from which to remove all bookmarks of the given type and category.
        :param java.lang.String or str type: the type of bookmarks to remove.
        :param java.lang.String or str category: the category of bookmarks to remove.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to report the progress.
        :raises CancelledException: if the user (via the monitor) cancelled the operation.
        """

    def setBookmark(self, addr: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]) -> Bookmark:
        """
        Set a bookmark.
        
        :param ghidra.program.model.address.Address addr: the address at which to set a bookmark
        :param java.lang.String or str type: the name of the bookmark type.
        :param java.lang.String or str category: the category for the bookmark.
        :param java.lang.String or str comment: the comment to associate with the bookmark.
        :return: the new bookmark
        :rtype: Bookmark
        """

    @property
    def bookmarks(self) -> jpype.JArray[Bookmark]:
        ...

    @property
    def bookmark(self) -> Bookmark:
        ...

    @property
    def bookmarkTypes(self) -> jpype.JArray[BookmarkType]:
        ...

    @property
    def bookmarkCount(self) -> jpype.JInt:
        ...

    @property
    def program(self) -> Program:
        ...

    @property
    def categories(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def bookmarkType(self) -> BookmarkType:
        ...

    @property
    def bookmarkAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def bookmarksIterator(self) -> java.util.Iterator[Bookmark]:
        ...



__all__ = ["CodeUnitFormat", "CodeUnitFormatOptions", "AddressChangeSet", "AutoParameterType", "Library", "FunctionTagChangeSet", "BookmarkType", "InstructionIterator", "AutoParameterImpl", "VariableSizeException", "Data", "FunctionSignatureImpl", "VariableFilter", "FunctionOverlapException", "StackFrame", "ProgramFragment", "DataTypeArchiveChangeSet", "DefaultProgramContext", "VariableUtilities", "Parameter", "IncompatibleLanguageException", "FunctionSignature", "BookmarkComparator", "DataStub", "RegisterChangeSet", "InstructionStub", "BookmarkTypeComparator", "InstructionPcodeOverride", "ProgramContext", "LocalVariableImpl", "ParameterImpl", "FunctionTagManager", "Instruction", "GhidraClass", "Bookmark", "DuplicateGroupException", "VariableOffset", "FunctionTag", "DomainObjectChangeSet", "CommentHistory", "ProgramTreeChangeSet", "CodeUnitComments", "Group", "RepeatableComment", "OperandRepresentationList", "SymbolChangeSet", "LabelString", "Program", "VariableImpl", "CodeUnitIterator", "CommentType", "DataBuffer", "LocalVariable", "ProgramChangeSet", "ThunkFunction", "CodeUnit", "VariableStorage", "StackVariableComparator", "Function", "ContextChangeException", "StubListing", "Variable", "FlowOverride", "FunctionManager", "FunctionIterator", "DataTypeChangeSet", "ReturnParameterImpl", "DataIterator", "ProgramUserData", "CircularDependencyException", "Listing", "ProgramModule", "DataTypeArchive", "BookmarkManager"]
