from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import generic.theme
import ghidra.app.nav
import ghidra.app.util
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.proxy
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.classfinder
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


class ErrorFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`ErrorListingField` clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DummyFieldFactory(FieldFactory):
    """
    Generates Dummy Fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mgr: ghidra.app.util.viewer.format.FormatManager):
        ...


class XRefHeaderFieldFactory(XRefFieldFactory):
    """
    Field for display XRef headers.
    """

    class_: typing.ClassVar[java.lang.Class]
    XREF_FIELD_NAME: typing.Final = "XRef Header"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HighlightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class ExecutableTaskStringHandler(AnnotatedStringHandler):

    @typing.type_check_only
    class ProcessThread(java.lang.Thread):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IOThread(java.lang.Thread):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ImageFactoryFieldMouseHandler(FieldMouseHandlerExtension):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GhidraLocalURLAnnotatedStringHandler(URLAnnotatedStringHandler):
    """
    This implementation expands :obj:`URLAnnotatedStringHandler` providing an example form
    of a local project Ghidra URL.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VariableXRefHeaderFieldFactory(VariableXRefFieldFactory):
    """
    Field for showing Xref Headers for variables
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HighlightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class BytesFieldFactory(FieldFactory):
    """
    Generates Bytes Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Bytes"
    GROUP_TITLE: typing.Final = "Bytes Field"
    MAX_DISPLAY_LINES_MSG: typing.Final = "Bytes Field.Maximum Lines To Display"
    DELIMITER_MSG: typing.Final = "Bytes Field.Delimiter"
    BYTE_GROUP_SIZE_MSG: typing.Final = "Bytes Field.Byte Group Size"
    DISPLAY_UCASE_MSG: typing.Final = "Bytes Field.Display in Upper Case"
    REVERSE_INSTRUCTION_BYTE_ORDERING: typing.Final = "Bytes Field.Reverse Instruction Byte Ordering"
    DISPLAY_STRUCTURE_ALIGNMENT_BYTES_MSG: typing.Final = "Bytes Field.Display Structure Alignment Bytes"

    def __init__(self):
        """
        Default Constructor
        """


class FunctionOffsetFieldFactory(AbstractOffsetFieldFactory):
    """
    Generates Function Offset fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new default :obj:`FunctionOffsetFieldFactory`
        """


class InstructionMaskValueFieldFactory(FieldFactory):

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Instr Mask/Value"

    def __init__(self):
        """
        Default constructor.
        """

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class AddressFieldFactory(FieldFactory):
    """
    Generates Address Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Address"
    DISPLAY_BLOCK_NAME: typing.Final = "Address Field.Display Block Name"
    ADDRESS_DISPLAY_OPTIONS_NAME: typing.Final = "Address Field.Address Display Options"

    def __init__(self):
        """
        Default Constructor
        """


class CommentFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`CommentFieldLocation` clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SeparatorFieldFactory(FieldFactory):
    """
    Generates Separator Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Separator"

    def __init__(self):
        """
        Constructor
        """


class AbstractOffsetFieldFactory(FieldFactory):
    """
    Generates Offset fields
    """

    class_: typing.ClassVar[java.lang.Class]
    COLOR: typing.Final[generic.theme.GColor]

    def __init__(self, offsetDescription: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`AbstractOffsetFieldFactory`
        
        :param java.lang.String or str offsetDescription: A description of the offset
        """

    def getOffsetFieldType(self) -> ghidra.program.util.OffsetFieldType:
        """
        Gets the :obj:`offset type <OffsetFieldType>`
        
        :return: the :obj:`offset type <OffsetFieldType>`
        :rtype: ghidra.program.util.OffsetFieldType
        """

    def getOffsetValue(self, codeUnit: ghidra.program.model.listing.CodeUnit) -> str:
        """
        Gets the offset value
        
        :param ghidra.program.model.listing.CodeUnit codeUnit: The :obj:`CodeUnit`
        :return: The offset value
        :rtype: str
        """

    @property
    def offsetFieldType(self) -> ghidra.program.util.OffsetFieldType:
        ...

    @property
    def offsetValue(self) -> java.lang.String:
        ...


class IndentField(ListingField):
    """
    Field responsible for drawing +/- symbols when over an aggregate datatype that
    can be opened or closed.  Also adds extra spacing for each level of the sub-datatypes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, indentLevel: typing.Union[jpype.JInt, int], metrics: java.awt.FontMetrics, x: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], isLast: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param FieldFactory factory: the factory that generated this field.
        :param ghidra.app.util.viewer.proxy.ProxyObj proxy: the object associated with this field instance.
        :param jpype.JInt or int indentLevel: the level of the datatype object.
        :param java.awt.FontMetrics metrics: the FontMetrics to used to render the field.
        :param jpype.JInt or int x: the x position of the field.
        :param jpype.JInt or int width: the width of the field.
        :param jpype.JBoolean or bool isLast: true if the object is the last subcomponent at its level.
        """

    def getFieldFactory(self) -> FieldFactory:
        """
        Returns the FieldFactory that generated this field.
        """

    def getHeight(self) -> int:
        """
        Returns the height of this field when populated with the given data.
        """

    def getHeightAbove(self) -> int:
        """
        Returns the heightAbove the imaginary alignment line used to align fields
        on the same row.
        """

    def getHeightBelow(self) -> int:
        """
        Returns the heightBelow the imaginary alignment line used to align fields on
        the same row.
        """

    def getProxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj:
        """
        Returns the object associated with this field instance.
        """

    def getStartX(self) -> int:
        """
        Returns the horizontal position of this field.
        """

    def getStartY(self) -> int:
        """
        Returns the vertical position of this field.
        """

    def getWidth(self) -> int:
        """
        Returns the current width of this field.
        """

    def setStartY(self, startY: typing.Union[jpype.JInt, int]):
        """
        Sets the starting vertical position of this field.
        
        :param jpype.JInt or int startY: the starting vertical position.
        """

    def setYPos(self, yPos: typing.Union[jpype.JInt, int], heightAbove: typing.Union[jpype.JInt, int], heightBelow: typing.Union[jpype.JInt, int]):
        """
        Sets the overall y position for this field.
        
        :param jpype.JInt or int yPos: the y coordinated of the layout row that it is in.
        :param jpype.JInt or int heightAbove: the heightAbove the alignment line for the entire layout row.
        :param jpype.JInt or int heightBelow: the heighBelow the alignment line for the entire layout col.
        """

    @property
    def proxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj:
        ...

    @property
    def heightBelow(self) -> jpype.JInt:
        ...

    @property
    def fieldFactory(self) -> FieldFactory:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def startY(self) -> jpype.JInt:
        ...

    @startY.setter
    def startY(self, value: jpype.JInt):
        ...

    @property
    def startX(self) -> jpype.JInt:
        ...

    @property
    def heightAbove(self) -> jpype.JInt:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class FieldNameFieldFactory(FieldFactory):
    """
    Generates Data Field (structure field names and array indexes) name Fields.
    """

    class IndexFormat(java.lang.Enum[FieldNameFieldFactory.IndexFormat]):

        class_: typing.ClassVar[java.lang.Class]
        decimal: typing.Final[FieldNameFieldFactory.IndexFormat]
        hex: typing.Final[FieldNameFieldFactory.IndexFormat]
        octal: typing.Final[FieldNameFieldFactory.IndexFormat]
        binary: typing.Final[FieldNameFieldFactory.IndexFormat]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FieldNameFieldFactory.IndexFormat:
            ...

        @staticmethod
        def values() -> jpype.JArray[FieldNameFieldFactory.IndexFormat]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Field Name"
    ARRAY_INDEX_FORMAT_NAME: typing.Final = "Array Options.Array Index Format"

    def __init__(self):
        ...


class FunctionSignatureFieldFactory(FieldFactory):
    """
    Generates FunctionSignature Fields.
    """

    @typing.type_check_only
    class FunctionSignatureFieldElement(docking.widgets.fieldpanel.field.AbstractTextFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionReturnTypeFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionInlineFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionThunkFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionNoReturnFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionCallingConventionFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionNameFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionStartParametersFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionEndParametersFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionParameterFieldElement(FunctionSignatureFieldFactory.FunctionSignatureFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionParameterNameFieldElement(FunctionSignatureFieldFactory.FunctionParameterFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Function Signature"
    GROUP_TITLE: typing.Final = "Function Signature Field"
    DISPLAY_NAMESPACE: typing.Final = "Function Signature Field.Display Namespace"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.ToolOptions, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.ToolOptions displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class BrowserCodeUnitFormat(ghidra.program.model.listing.CodeUnitFormat):
    """
    ``BrowserCodeUnitFormat`` provides a code unit format based upon
    a common set of viewer Options for specific Tool.  The associated options correspond to
    the Browser Operand Fields category.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider):
        """
        Construct code unit format for specified serviceProvider with autoUpdate enabled.
        
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: service provider (e.g., Tool)
        """

    @typing.overload
    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, autoUpdate: typing.Union[jpype.JBoolean, bool]):
        """
        Construct code unit format for specified serviceProvider.
        
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: service provider (e.g., Tool)
        :param jpype.JBoolean or bool autoUpdate: if true format will auto update if associated options are changed.
        """

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Add a change listener to the underlying format options.  When a format change
        occurs the listener may wish to trigger a refresh of any formatted code units.
        
        :param javax.swing.event.ChangeListener listener: change listener
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Remove an existing change listener from the underlying format options.
        
        :param javax.swing.event.ChangeListener listener: change listener
        """


class RegisterTransitionFieldFactory(FieldFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor.
        """

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class SubDataFieldFactory(OperandFieldFactory):
    """
    Generates data value Fields for data subcomponents.
      
    
    This field is not meant to be loaded by the :obj:`ClassSearcher`, hence the X in the name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], path: jpype.JArray[jpype.JInt]):
        """
        Constructor
        
        :param java.lang.String or str name: the name of the field
        :param jpype.JArray[jpype.JInt] path: the component path for the data
        """


class ResourceFieldLocation(ghidra.program.util.OperandFieldLocation):
    """
    A :obj:`ProgramLocation` of an item that is a Resource 
    embedded in a binary (ie. a embedded graphic image)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], displayValue: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int], characterOffset: typing.Union[jpype.JInt, int], data: ghidra.program.model.listing.Data):
        """
        Creates an ResourceFieldLocation
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the address of the location
        :param jpype.JArray[jpype.JInt] componentPath: the data component path
        :param java.lang.String or str displayValue: the text being displayed in the text.
        :param jpype.JInt or int opIndex: the index of the operand at this location.
        :param jpype.JInt or int characterOffset: the character position from the beginning of the operand.
        :param ghidra.program.model.listing.Data data: Data instance at the specified address / component path
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring from XML.
        """

    def getResourceData(self) -> ghidra.program.model.listing.Data:
        """
        Returns the resource's Data instance.
        
        :return: the resource's Data instance
        :rtype: ghidra.program.model.listing.Data
        """

    def isDataImageResource(self) -> bool:
        """
        Returns true if this resource is a :obj:`DataImage`.
        
        :return: true if this resource is a :obj:`DataImage`
        :rtype: bool
        """

    @property
    def dataImageResource(self) -> jpype.JBoolean:
        ...

    @property
    def resourceData(self) -> ghidra.program.model.listing.Data:
        ...


class AssignedVariableFieldFactory(FieldFactory):
    """
    Generates Variable Assignment Fields (point of first-use).
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Var Assign"

    def __init__(self):
        """
        Default constructor.
        """

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class VariableNameFieldFactory(AbstractVariableFieldFactory):
    """
    Generates VariableName Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Variable Name"

    def __init__(self):
        """
        Constructor
        """


class RegisterFieldFactory(FieldFactory):
    """
    Field to show register values at the function entry point.
    """

    @typing.type_check_only
    class RegComparator(java.util.Comparator[ghidra.program.model.lang.Register]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Register"
    REGISTER_GROUP_NAME: typing.Final = "Register Field"
    DISPLAY_HIDDEN_REGISTERS_OPTION_NAME: typing.Final = "Register Field.Display Hidden Registers"
    DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME: typing.Final = "Register Field.Display Default Register Values"

    def __init__(self):
        ...


class AnnotatedStringHandler(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL AnnotatedStringHandler CLASSES MUST END IN "StringHandler".  If not,
    the ClassSearcher will not find them.
     
    An interface that describes a string that has been annotated, which allows for adding
    rendering and functionality to strings.
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY_MOUSE_HANDLER: typing.Final[AnnotatedMouseHandler]

    def createAnnotatedString(self, prototypeString: docking.widgets.fieldpanel.field.AttributedString, text: jpype.JArray[java.lang.String], program: ghidra.program.model.listing.Program) -> docking.widgets.fieldpanel.field.AttributedString:
        """
        Creates an :obj:`FieldElement` based upon the give array of Strings.  The first String
        in the list is expected to be the annotation tag used to create the annotation.  At the
        very least the array is expected to be comprised of two elements, the annotation and some
        data.  Extra data may be provided as needed by implementing classes.
        
        :param docking.widgets.fieldpanel.field.AttributedString prototypeString: The prototype :obj:`FieldElement` that dictates the
                attributes for the newly created string.  Implementations may change attributes
                as needed.
        :param jpype.JArray[java.lang.String] text: An array of Strings used to create the :obj:`FieldElement` being
                returned.
        :param ghidra.program.model.listing.Program program: The program with which the returned string is associated.
        :return: An :obj:`AnnotatedTextFieldElement` that will be used to render the given text.
        :rtype: docking.widgets.fieldpanel.field.AttributedString
        :raises AnnotationException: if the given text data does not fit the expected format for
                the given handler implementation.
        """

    @staticmethod
    def escapeAnnotationPart(s: typing.Union[java.lang.String, str]) -> str:
        """
        Escape a string that is intended to be used as a annotated string portion.
         
        
        Quotes are escaped, '}' and ' ' are placed inside quotes.
        
        :param java.lang.String or str s: string to escape
        :return: escaped string
        :rtype: str
        """

    def getDisplayString(self) -> str:
        """
        Returns the String that represents the GUI presence of this option
        
        :return: the String to display in GUI components.
        :rtype: str
        """

    @typing.overload
    def getPrototypeString(self) -> str:
        """
        Returns an example string of how the annotation is used
        
        :return: the example of how this is used.
        :rtype: str
        """

    @typing.overload
    def getPrototypeString(self, displayText: typing.Union[java.lang.String, str]) -> str:
        """
        Returns an example string of how the annotation is used
        
        :param java.lang.String or str displayText: The text that may be wrapped, cannot be null
        :return: the example of how this is used.
        :rtype: str
        """

    def getSupportedAnnotations(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the annotation string names that this AnnotatedStringHandler supports (e.g., "symbol",
        "address", etc...).
        
        :return: the annotation string names that this AnnotatedStringHandler supports.
        :rtype: jpype.JArray[java.lang.String]
        """

    def handleMouseClick(self, annotationParts: jpype.JArray[java.lang.String], sourceNavigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        A method that is notified when an annotation is clicked.  Returns true if this annotation
        handles the click; return false if this annotation does not do anything with the click.
        
        :param jpype.JArray[java.lang.String] annotationParts: The constituent parts of the annotation
        :param ghidra.app.nav.Navigatable sourceNavigatable: The location in the program that was clicked.
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: A service provider for needed services.
        :return: true if this annotation handles the click; return false if this annotation does 
                not do anything with the click.
        :rtype: bool
        """

    @property
    def supportedAnnotations(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def displayString(self) -> java.lang.String:
        ...

    @property
    def prototypeString(self) -> java.lang.String:
        ...


class MemoryBlockOffsetFieldFactory(AbstractOffsetFieldFactory):
    """
    Generates :obj:`MemoryBlock` Offset fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new default :obj:`MemoryBlockOffsetFieldFactory`
        """


class SpacerFieldFactory(FieldFactory):
    """
    Generates Spacer Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Spacer"

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], model: ghidra.app.util.viewer.format.FieldFormatModel, hsProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.Options):
        """
        Constructor
        
        :param java.lang.String or str text: The text to display in the field.
        :param ghidra.app.util.viewer.format.FieldFormatModel model: The Field model that will use this Address factory.
        :param ghidra.app.util.ListingHighlightProvider hsProvider: the HightLightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.Options fieldOptions: the Options for field specific properties.
        """

    def getStringToHighlight(self, bf: ListingTextField, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], loc: ghidra.program.util.ProgramLocation) -> str:
        """
        Returns the string to highlight
        
        :param ListingTextField bf: the ListingTextField
        :param jpype.JInt or int row: the row in the field
        :param jpype.JInt or int col: the column in the field
        :param ghidra.program.util.ProgramLocation loc: the programLocation.
        """

    def getText(self) -> str:
        """
        Returns the spacer field's text
        """

    @typing.overload
    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text for the spacer field
        
        :param java.lang.String or str text: the text to display in the listing
        """

    @typing.overload
    def setText(self):
        """
        Sets the literal text to display in this field.
        """

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...


class MnemonicFieldFactory(FieldFactory):
    """
    Generates Mnemonic Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Mnemonic"

    def __init__(self):
        """
        Default constructor.
        """

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class OpenCloseFieldFactory(FieldFactory):
    """
    Generates Open/Close Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "+"

    def __init__(self):
        ...

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class LabelCodeUnitFormat(BrowserCodeUnitFormat):
    """
    A version of :obj:`BrowserCodeUnitFormat` that changes how labels are rendered in offcut 
    situations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fieldOptions: ghidra.framework.options.ToolOptions):
        ...


class PlateFieldFactory(FieldFactory):
    """
    Class for showing plate comments
    """

    @typing.type_check_only
    class PlateListingTextField(ListingTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PlateFieldTextField(docking.widgets.fieldpanel.field.VerticalLayoutTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldElementResult(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Plate Comment"
    DEFAULT_COLOR: typing.Final[java.awt.Color]
    ENABLE_WORD_WRAP_MSG: typing.Final = "Plate Comments Field.Enable Word Wrapping"
    FUNCTION_PLATE_COMMENT: typing.Final = "FUNCTION"

    def __init__(self):
        ...


class ListingField(docking.widgets.fieldpanel.field.Field):
    """
    Interface that extends the Field interface to add addition information that
    the browser needs from the fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getClickedObject(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation) -> java.lang.Object:
        """
        Returns the object that was clicked on a Field for the given FieldLocation.  This may be the
        field itself or a lower-level entity, such as a FieldElement.
        
        :param docking.widgets.fieldpanel.support.FieldLocation fieldLocation: The location that was clicked.
        :return: the object that was clicked
        :rtype: java.lang.Object
        """

    def getFieldFactory(self) -> FieldFactory:
        """
        Returns the FieldFactory that generated this Field
        
        :return: the FieldFactory that generated this Field
        :rtype: FieldFactory
        """

    def getProxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj[typing.Any]:
        """
        Returns the object that the fieldFactory used to generate the information in this field.
        
        :return: the object that the fieldFactory used to generate the information in this field.
        :rtype: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any]
        """

    @property
    def proxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj[typing.Any]:
        ...

    @property
    def clickedObject(self) -> java.lang.Object:
        ...

    @property
    def fieldFactory(self) -> FieldFactory:
        ...


class CommentPart(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OperandFieldHelper(FieldFactory):
    """
    Helper class to store the options of the
    OperandFieldFactory and SubDataFieldFactory
    """

    class UNDERLINE_CHOICE(java.lang.Enum[OperandFieldHelper.UNDERLINE_CHOICE]):

        class_: typing.ClassVar[java.lang.Class]
        Hidden: typing.Final[OperandFieldHelper.UNDERLINE_CHOICE]
        All: typing.Final[OperandFieldHelper.UNDERLINE_CHOICE]
        None_: typing.Final[OperandFieldHelper.UNDERLINE_CHOICE]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> OperandFieldHelper.UNDERLINE_CHOICE:
            ...

        @staticmethod
        def values() -> jpype.JArray[OperandFieldHelper.UNDERLINE_CHOICE]:
            ...


    @typing.type_check_only
    class ColorStyleAttributes(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OperandFieldElement(docking.widgets.fieldpanel.field.AbstractTextFieldElement):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ListingFieldHighlightFactoryAdapter(docking.widgets.fieldpanel.support.FieldHighlightFactory):
    """
    Wrapper class to translate calls to :obj:`FieldHighlightFactory` into a call needed by the 
    :obj:`ListingHighlightProvider`.   This class holds field factory information in the text 
    field to be provided to the highlightProvider to get highlights just before the field is painted.
     
    
    This class is needed to allow the basic :obj:`Field` API to be used with more richness at the
    :obj:`ListingPanel` level.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.util.ListingHighlightProvider):
        """
        Constructor
        
        :param ghidra.app.util.ListingHighlightProvider provider: the HighlightProvider that will actually compute the highlights.
        """


class OptionsBasedDataTypeDisplayOptions(ghidra.program.model.data.DataTypeDisplayOptions):

    class_: typing.ClassVar[java.lang.Class]
    DISPLAY_ABBREVIATED_DEFAULT_LABELS: typing.Final = "Operands Field.Display Abbreviated Default Label Names"
    """
    Option for controlling the default display options.
    """

    MAXIMUM_DEFAULT_LABEL_LENGTH: typing.Final = "Operands Field.Maximum Length of String in Default Labels"

    def __init__(self, options: ghidra.framework.options.Options):
        ...


class XRefFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`XRefFieldMouseHandler` clicks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ThunkedFunctionFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`OperandFieldLocation` mouse clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnnotationCommentPart(CommentPart):

    class_: typing.ClassVar[java.lang.Class]

    def getAnnotation(self) -> Annotation:
        ...

    @property
    def annotation(self) -> Annotation:
        ...


class PcodeFieldMouseHandler(FieldMouseHandlerExtension):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VariableCommentFieldMouseHandler(CommentFieldMouseHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OpenCloseFieldMouseHandler(FieldMouseHandlerExtension):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def fieldElementClicked(self, clickedObject: java.lang.Object, sourceNavigatable: ghidra.app.nav.Navigatable, location: ghidra.program.util.ProgramLocation, mouseEvent: java.awt.event.MouseEvent, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        ...


class SpaceFieldFactory(FieldFactory):
    """
    Generates empty line Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Space"

    def __init__(self):
        """
        Constructor
        """


class AnnotationException(java.lang.RuntimeException):
    """
    Exception thrown by the annotations classes.
    
    
    .. seealso::
    
        | :obj:`AnnotatedStringHandler`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class EolEnablement(java.lang.Enum[EolEnablement]):

    class_: typing.ClassVar[java.lang.Class]
    ALWAYS: typing.Final[EolEnablement]
    DEFAULT: typing.Final[EolEnablement]
    NEVER: typing.Final[EolEnablement]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EolEnablement:
        ...

    @staticmethod
    def values() -> jpype.JArray[EolEnablement]:
        ...


class AddressFieldOptionsPropertyEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EolExtraCommentsPropertyEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ParallelInstructionFieldFactory(FieldFactory):
    """
    Generates Parallel execution marks '||' for those language which have a
    ParallelFieldLanguageHelper class and have specified the corresponding
    language property in the pspec.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Parallel ||"

    def __init__(self):
        """
        Default constructor.
        """

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields before this one.
        """


class ArrayValuesFieldFactory(FieldFactory):

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Array Values"

    def __init__(self):
        ...


class EolExtraCommentsOption(ghidra.framework.options.CustomOption):
    """
    An option class that is used by the :obj:`EolExtraCommentsPropertyEditor` to load and save 
    option settings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def alwaysShowAutoComments(self) -> bool:
        ...

    def getAutoData(self) -> EolEnablement:
        ...

    def getAutoFunction(self) -> EolEnablement:
        ...

    def getRefRepeatable(self) -> EolEnablement:
        ...

    def getRepeatable(self) -> EolEnablement:
        ...

    def isShowingAutoComments(self, hasOtherComments: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def isShowingRefRepeatables(self, hasOtherComments: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def isShowingRepeatables(self, hasOtherComments: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def setAutoData(self, priority: EolEnablement):
        ...

    def setAutoFunction(self, priority: EolEnablement):
        ...

    def setRefRepeatable(self, priority: EolEnablement):
        ...

    def setRepeatable(self, priority: EolEnablement):
        ...

    def setUseAbbreviatedComments(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def useAbbreviatedComments(self) -> bool:
        ...

    @property
    def showingRefRepeatables(self) -> jpype.JBoolean:
        ...

    @property
    def autoData(self) -> EolEnablement:
        ...

    @autoData.setter
    def autoData(self, value: EolEnablement):
        ...

    @property
    def showingAutoComments(self) -> jpype.JBoolean:
        ...

    @property
    def showingRepeatables(self) -> jpype.JBoolean:
        ...

    @property
    def autoFunction(self) -> EolEnablement:
        ...

    @autoFunction.setter
    def autoFunction(self, value: EolEnablement):
        ...

    @property
    def repeatable(self) -> EolEnablement:
        ...

    @repeatable.setter
    def repeatable(self, value: EolEnablement):
        ...

    @property
    def refRepeatable(self) -> EolEnablement:
        ...

    @refRepeatable.setter
    def refRepeatable(self, value: EolEnablement):
        ...


class InvalidAnnotatedStringHandler(AnnotatedStringHandler):
    """
    An annotated string handler that is used to display an error message string when there is a
    problem creating an annotated string.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, errorText: typing.Union[java.lang.String, str]):
        ...


class FieldFactory(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL FIELDFACTORY CLASSES MUST END IN "FieldFactory".  If not,
    the ClassSearcher will not find them.
    
    Base class for Field Factories.
    """

    class_: typing.ClassVar[java.lang.Class]
    FONT_OPTION_NAME: typing.Final = "BASE FONT"
    BASE_LISTING_FONT_ID: typing.Final = "font.listing.base"

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a FieldFactory with given name.  Used only as potential field.
        
        :param java.lang.String or str name: the name of the field.
        """

    def acceptsType(self, category: typing.Union[jpype.JInt, int], proxyObjectClass: java.lang.Class[typing.Any]) -> bool:
        """
        Used to specify which format models this field can belong to.
        
        :param jpype.JInt or int category: the category for this field
        :param java.lang.Class[typing.Any] proxyObjectClass: the type of proxy object used by this field
        :return: true if this class accepts the given category.
        :rtype: bool
        """

    def displayOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notifications that the display options changed.
        
        :param ghidra.framework.options.Options options: the Display Options object that changed.
        :param java.lang.String or str optionName: the name of the property that changed.
        :param java.lang.Object oldValue: the old value of the property.
        :param java.lang.Object newValue: the new value of the property.
        """

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notifications that the field options changed.
        
        :param ghidra.framework.options.Options options: the Field Options object that changed.
        :param java.lang.String or str optionName: the name of the property that changed.
        :param java.lang.Object oldValue: the old value of the property.
        :param java.lang.Object newValue: the new value of the property.
        """

    def getField(self, obj: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Generates a Field based on the given information.
        
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] obj: The object that the generated field will report some information about.
        :param jpype.JInt or int varWidth: the additional distance along the x axis to place the generated field.
        :return: the newly generated FactoryField that shows some property or information about
        the given object.
        :rtype: ListingField
        """

    def getFieldLocation(self, bf: ListingField, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], loc: ghidra.program.util.ProgramLocation) -> docking.widgets.fieldpanel.support.FieldLocation:
        """
        Return a FieldLocation that corresponds to the given index, fieldNum, and ProgramLocation
        IF and ONLY IF the given programLocation is the type generated by this class's
        :meth:`getFieldLocation(ListingField, BigInteger, int, ProgramLocation) <.getFieldLocation>`.  Each
        FieldFactory should generate and process a unique ProgramLocation class.
        
        :param ListingField bf: the ListingField at the current cursor.
        :param java.math.BigInteger index: the line index (corresponds to an address)
        :param jpype.JInt or int fieldNum: the index of field within the layout to try and get a FieldLocation.
        :param ghidra.program.util.ProgramLocation loc: the ProgramLocation to be converted into a FieldLocation.
        :return: the location.
        :rtype: docking.widgets.fieldpanel.support.FieldLocation
        """

    def getFieldModel(self) -> ghidra.app.util.viewer.format.FieldFormatModel:
        """
        Returns the FieldModel that this factory belongs to.
        
        :return: the model.
        :rtype: ghidra.app.util.viewer.format.FieldFormatModel
        """

    def getFieldName(self) -> str:
        """
        Returns the Field name.
        
        :return: the name.
        :rtype: str
        """

    def getFieldText(self) -> str:
        """
        Returns a description of the fields generated by this factory.
        
        :return: the text.
        :rtype: str
        """

    def getMetrics(self) -> java.awt.FontMetrics:
        """
        Returns the font metrics used by this field factory
        
        :return: the metrics.
        :rtype: java.awt.FontMetrics
        """

    def getProgramLocation(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], bf: ListingField) -> ghidra.program.util.ProgramLocation:
        """
        Returns the Program location for the given object, row, col, and groupPath
        
        :param jpype.JInt or int row: the row within this field
        :param jpype.JInt or int col: the col on the given row within this field.
        :param ListingField bf: the ListingField containing the cursor.
        :return: the location.
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getStartX(self) -> int:
        """
        Returns the starting x position for the fields generated by this factory.
        
        :return: the start x.
        :rtype: int
        """

    def getWidth(self) -> int:
        """
        Returns the width of the fields generated by this factory.
        
        :return: the width.
        :rtype: int
        """

    def isEnabled(self) -> bool:
        """
        Returns true if this FieldFactory is currently enabled to generate Fields.
        
        :return: true if enabled.
        :rtype: bool
        """

    def newInstance(self, formatModel: ghidra.app.util.viewer.format.FieldFormatModel, highlightProvider: ghidra.app.util.ListingHighlightProvider, options: ghidra.framework.options.ToolOptions, fieldOptions: ghidra.framework.options.ToolOptions) -> FieldFactory:
        """
        Returns a new instance of this FieldFactory that can be used to generate fields
        instead of being used as a prototype.
        
        :param ghidra.app.util.viewer.format.FieldFormatModel formatModel: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider highlightProvider: the HightLightProvider.
        :param ghidra.framework.options.ToolOptions options: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        :return: the factory
        :rtype: FieldFactory
        """

    def servicesChanged(self):
        """
        Notification the services changed. Subclasses should override this method
        if they care about service changes.
        """

    def setEnabled(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Turns on or off the generating of Fields by this FieldFactory.
        
        :param jpype.JBoolean or bool state: if true, this factory will generate fields.
        """

    def setStartX(self, x: typing.Union[jpype.JInt, int]):
        """
        Sets the starting x position for the fields generated by this factory.
        
        :param jpype.JInt or int x: the x position.
        """

    def setWidth(self, w: typing.Union[jpype.JInt, int]):
        """
        Sets the width of the fields generated by this factory.
        
        :param jpype.JInt or int w: the width.
        """

    def supportsLocation(self, listingField: ListingField, location: ghidra.program.util.ProgramLocation) -> bool:
        """
        Returns true if this given field represents the given location
        
        :param ListingField listingField: the field
        :param ghidra.program.util.ProgramLocation location: the location
        :return: true if this given field represents the given location
        :rtype: bool
        """

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @width.setter
    def width(self, value: jpype.JInt):
        ...

    @property
    def startX(self) -> jpype.JInt:
        ...

    @startX.setter
    def startX(self, value: jpype.JInt):
        ...

    @property
    def metrics(self) -> java.awt.FontMetrics:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def fieldText(self) -> java.lang.String:
        ...

    @property
    def fieldModel(self) -> ghidra.app.util.viewer.format.FieldFormatModel:
        ...


class FunctionPurgeFieldFactory(FieldFactory):

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Function Purge"
    COLOR: typing.Final[generic.theme.GColor]

    def __init__(self):
        ...


class ArrayElementFieldLocation(ghidra.program.util.OperandFieldLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], displayValue: typing.Union[java.lang.String, str], elementIndex: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Creates an ArrayElementFieldLocation
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the address of the location
        :param jpype.JArray[jpype.JInt] componentPath: the data component path
        :param java.lang.String or str displayValue: the text being displayed in the text.
        :param jpype.JInt or int elementIndex: the element of the array on the line.
        :param jpype.JInt or int charOffset: the character position within the text.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring from XML.
        """

    def getElementIndexOnLine(self, firstDataOnLine: ghidra.program.model.listing.Data) -> int:
        ...

    @property
    def elementIndexOnLine(self) -> jpype.JInt:
        ...


class OpenCloseField(ListingField):
    """
    FactoryField class for displaying the open/close field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], indentLevel: typing.Union[jpype.JInt, int], metrics: java.awt.FontMetrics, x: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], isLast: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param FieldFactory factory: the FieldFactory that created this field.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object associated with this field.
        :param jpype.JInt or int indentLevel: the indentation level of the data object.
        :param java.awt.FontMetrics metrics: the FontMetrics used to render this field.
        :param jpype.JInt or int x: the starting x position of this field.
        :param jpype.JInt or int width: the width of this field.
        :param jpype.JBoolean or bool isLast: true if the data object is the last subcomponent at its level.
        """

    def getStartY(self) -> int:
        """
        Returns the vertical position of this field.
        
        :return: the position
        :rtype: int
        """

    def setStartY(self, startY: typing.Union[jpype.JInt, int]):
        """
        Sets the starting vertical position of this field.
        
        :param jpype.JInt or int startY: the starting vertical position.
        """

    def setYPos(self, yPos: typing.Union[jpype.JInt, int], heightAbove: typing.Union[jpype.JInt, int], heightBelow: typing.Union[jpype.JInt, int]):
        """
        Sets the yPos relative to the overall layout.
        
        :param jpype.JInt or int yPos: the starting Y position of the layout row.
        :param jpype.JInt or int heightAbove: the heightAbove the alignment line in the layout row.
        :param jpype.JInt or int heightBelow: the heightBelow the alignment line in the layout row.
        """

    def toggleOpenCloseState(self):
        """
        Toggles the open state of this field.
        """

    @property
    def startY(self) -> jpype.JInt:
        ...

    @startY.setter
    def startY(self, value: jpype.JInt):
        ...


class EolCommentFieldFactory(FieldFactory):
    """
    Generates End of line comment Fields.
    """

    @typing.type_check_only
    class CommentStyle(java.lang.Enum[EolCommentFieldFactory.CommentStyle]):

        class_: typing.ClassVar[java.lang.Class]
        EOL: typing.Final[EolCommentFieldFactory.CommentStyle]
        REPEATABLE: typing.Final[EolCommentFieldFactory.CommentStyle]
        REF_REPEATABLE: typing.Final[EolCommentFieldFactory.CommentStyle]
        AUTO: typing.Final[EolCommentFieldFactory.CommentStyle]
        OFFCUT: typing.Final[EolCommentFieldFactory.CommentStyle]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> EolCommentFieldFactory.CommentStyle:
            ...

        @staticmethod
        def values() -> jpype.JArray[EolCommentFieldFactory.CommentStyle]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "EOL Comment"
    ENABLE_WORD_WRAP_KEY: typing.Final = "EOL Comments Field.Enable Word Wrapping"
    MAX_DISPLAY_LINES_KEY: typing.Final = "EOL Comments Field.Maximum Lines"
    ENABLE_SHOW_SEMICOLON_KEY: typing.Final = "EOL Comments Field.Prepend Semicolon"
    ENABLE_PREPEND_REF_ADDRESS_KEY: typing.Final = "EOL Comments Field.Prepend Address to References"
    EXTRA_COMMENT_KEY: typing.Final = "EOL Comments Field.Auto Comments"
    DEFAULT_COLOR: typing.Final[java.awt.Color]

    def __init__(self):
        """
        Default Constructor
        """

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Notification that an option changed.
        
        :param ghidra.framework.options.Options options: options object containing the property that changed
        :param java.lang.String or str optionName: name of option that changed
        :param java.lang.Object oldValue: old value of the option
        :param java.lang.Object newValue: new value of the option
        """

    @staticmethod
    def getSingleString(comments: jpype.JArray[java.lang.String], separatorChar: typing.Union[jpype.JChar, int, str]) -> str:
        """
        Convert the array of comments to a single string and use the given
        separatorChar as the delimiter.
        
        :param jpype.JArray[java.lang.String] comments: array of comments to convert
        :param jpype.JChar or int or str separatorChar: character to insert after each element in the comment array
        :return: the converted string
        :rtype: str
        """


class FunctionCallFixupFieldFactory(FieldFactory):
    """
    Generates Function Call-Fixup Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Function Call-Fixup"

    @typing.overload
    def __init__(self):
        """
        Default Constructor
        """

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.Options):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.Options fieldOptions: the Options for field specific properties.
        """


class GhidraServerURLAnnotatedStringHandler(URLAnnotatedStringHandler):
    """
    This implementation expands :obj:`URLAnnotatedStringHandler` providing an example form
    of a Ghidra Server URL.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ListingFieldDescriptionProvider(docking.widgets.fieldpanel.FieldDescriptionProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SourceMapFieldFactory(FieldFactory):
    """
    :obj:`FieldFactory` for showing source and line information in the Listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Default constructor
        """


class LabelFieldFactory(FieldFactory):
    """
    Generates label Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Label"
    OFFCUT_STYLE: typing.Final = "XRef Offcut Style"
    GROUP_TITLE: typing.Final = "Labels Field"
    DISPLAY_FUNCTION_LABEL: typing.Final = "Labels Field.Display Function Label"

    def __init__(self):
        ...


class AddressFieldOptionsWrappedOption(ghidra.framework.options.CustomOption):
    """
    An option class that allows the user to edit a related group of options pertaining to
    address field display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMinimumHexDigits(self) -> int:
        ...

    def padWithZeros(self) -> bool:
        ...

    def rightJustify(self) -> bool:
        ...

    def setMinimumHexDigits(self, numDigits: typing.Union[jpype.JInt, int]):
        ...

    def setPadWithZeros(self, padWithZeros: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRightJustify(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowBlockName(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def showBlockName(self) -> bool:
        ...

    @property
    def minimumHexDigits(self) -> jpype.JInt:
        ...

    @minimumHexDigits.setter
    def minimumHexDigits(self, value: jpype.JInt):
        ...


class FieldMouseHandlerExtension(FieldMouseHandler, ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL FieldMouseHandlerExtension CLASSES MUST END IN "FieldMouseHandler".  If not,
    the ClassSearcher will not find them.
     
    An interface to signal that it can handle mouse clicks for registered objects.  To register 
    the handler you need to return the class that the handler supports in the class array 
    returned from :meth:`getSupportedProgramLocations() <.getSupportedProgramLocations>`.
     
    
    New handlers are automatically picked-up by Ghidra upon startup via the 
    :obj:`ClassSearcher` mechanism.
    
    
    .. seealso::
    
        | :obj:`FieldNavigator`
    """

    class_: typing.ClassVar[java.lang.Class]


class AnnotatedMouseHandler(java.lang.Object):
    """
    An interface for handling mouse clicks on :obj:`ghidra.util.bean.field.AnnotatedTextFieldElement`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def handleMouseClick(self, location: ghidra.program.util.ProgramLocation, mouseEvent: java.awt.event.MouseEvent, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        Handles a mouse click for the given program location on an :obj:`ghidra.util.bean.field.AnnotatedTextFieldElement`.
        
        :param ghidra.program.util.ProgramLocation location: The program location for the click
        :param java.awt.event.MouseEvent mouseEvent: The mouse event that triggered the mouse click
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: A service provider used to access system services while processing
                the mouse click
        :return: true if the handler wants to be the only handler processing the click.
        :rtype: bool
        """


class XRefFieldFactory(FieldFactory):
    """
    Cross-reference Field Factory
    """

    class SORT_CHOICE(java.lang.Enum[XRefFieldFactory.SORT_CHOICE]):

        class_: typing.ClassVar[java.lang.Class]
        Address: typing.Final[XRefFieldFactory.SORT_CHOICE]
        Type: typing.Final[XRefFieldFactory.SORT_CHOICE]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> XRefFieldFactory.SORT_CHOICE:
            ...

        @staticmethod
        def values() -> jpype.JArray[XRefFieldFactory.SORT_CHOICE]:
            ...


    @typing.type_check_only
    class XrefAttributedString(docking.widgets.fieldpanel.field.CompositeAttributedString):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, xref: ghidra.program.model.symbol.Reference, content: docking.widgets.fieldpanel.field.AttributedString):
            ...

        @typing.overload
        def __init__(self, xref: ghidra.program.model.symbol.Reference, content: docking.widgets.fieldpanel.field.AttributedString, delimiter: docking.widgets.fieldpanel.field.AttributedString):
            ...


    @typing.type_check_only
    class XrefFieldElement(docking.widgets.fieldpanel.field.TextFieldElement):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, xrefString: XRefFieldFactory.XrefAttributedString, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class XrefListingField(ListingTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "XRef"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class ImagebaseOffsetFieldFactory(AbstractOffsetFieldFactory):
    """
    Generates Imagebase Offset fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new default :obj:`ImagebaseOffsetFieldFactory`
        """


class FileOffsetFieldFactory(AbstractOffsetFieldFactory):
    """
    Generates Function Offset fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new default :obj:`FileOffsetFieldFactory`
        """


class FunctionRepeatableCommentFieldFactory(FieldFactory):
    """
    Field for showing Function repeatable comments
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Function Repeatable Comment"
    COLOR: typing.Final[generic.theme.GColor]

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.Options):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.Options fieldOptions: the Options for field specific properties.
        """


class FieldMouseHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def fieldElementClicked(self, clickedObject: java.lang.Object, sourceNavigatable: ghidra.app.nav.Navigatable, programLocation: ghidra.program.util.ProgramLocation, mouseEvent: java.awt.event.MouseEvent, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool:
        """
        Called when a field :obj:`Field` has been clicked.  The object being passed in may be
        of any type, as returned by the clicked field.  The type is guaranteed to be one of the
        types returned in the call to :meth:`getSupportedProgramLocations() <.getSupportedProgramLocations>`.
        
        :param java.lang.Object clickedObject: The object that was clicked
        :param ghidra.app.nav.Navigatable sourceNavigatable: The source navigatable that was clicked upon.
        :param ghidra.program.util.ProgramLocation programLocation: The location at the time the click was made. Due to swing delay, this
        location may not be the same as you would get if you asked the navigatable for the current
        location.SC
        :param java.awt.event.MouseEvent mouseEvent: The mouse event that triggered the click
        :param ghidra.framework.plugintool.ServiceProvider serviceProvider: A service provider used to access system resources.
        :return: true if this handler wishes to have exclusive handling rights to processing the
                ``clickedObject``
        :rtype: bool
        
        .. seealso::
        
            | :obj:`ListingField.getClickedObject(docking.widgets.fieldpanel.support.FieldLocation)`
        """

    def getSupportedProgramLocations(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        """
        Returns an array of types that this handler wishes to handle.
        
        :return: an array of types that this handler wishes to handle.
        :rtype: jpype.JArray[java.lang.Class[typing.Any]]
        """

    @property
    def supportedProgramLocations(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...


class ProgramAnnotatedStringHandler(AnnotatedStringHandler):
    """
    An annotated string handler that allows handles annotations that begin with
    :obj:`.SUPPORTED_ANNOTATIONS`.  This class expects one string following the annotation
    text that is the program name.  The display text will be that of the program name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NamespaceWrappedOption(ghidra.framework.options.CustomOption):
    """
    An option class that allows the user to edit a related group of options pertaining to
    namespace display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLocalPrefixText(self) -> str:
        ...

    def isShowLibraryInNamespace(self) -> bool:
        ...

    def isShowLocalNamespace(self) -> bool:
        ...

    def isShowNonLocalNamespace(self) -> bool:
        ...

    def isUseLocalPrefixOverride(self) -> bool:
        ...

    def setLocalPrefixText(self, localPrefixText: typing.Union[java.lang.String, str]):
        ...

    def setShowLibraryInNamespace(self, showLibraryInNamespace: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowLocalNamespace(self, showLocalNamespace: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShowNonLocalNamespace(self, showNonLocalNamespace: typing.Union[jpype.JBoolean, bool]):
        ...

    def setUseLocalPrefixOverride(self, useLocalPrefixOverride: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showNonLocalNamespace(self) -> jpype.JBoolean:
        ...

    @showNonLocalNamespace.setter
    def showNonLocalNamespace(self, value: jpype.JBoolean):
        ...

    @property
    def showLocalNamespace(self) -> jpype.JBoolean:
        ...

    @showLocalNamespace.setter
    def showLocalNamespace(self, value: jpype.JBoolean):
        ...

    @property
    def showLibraryInNamespace(self) -> jpype.JBoolean:
        ...

    @showLibraryInNamespace.setter
    def showLibraryInNamespace(self, value: jpype.JBoolean):
        ...

    @property
    def localPrefixText(self) -> java.lang.String:
        ...

    @localPrefixText.setter
    def localPrefixText(self, value: java.lang.String):
        ...

    @property
    def useLocalPrefixOverride(self) -> jpype.JBoolean:
        ...

    @useLocalPrefixOverride.setter
    def useLocalPrefixOverride(self, value: jpype.JBoolean):
        ...


class ListingColors(java.lang.Object):

    class XrefColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        DEFAULT: typing.Final[generic.theme.GColor]
        OFFCUT: typing.Final[generic.theme.GColor]
        READ: typing.Final[generic.theme.GColor]
        WRITE: typing.Final[generic.theme.GColor]
        OTHER: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class PcodeColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        LABEL: typing.Final[generic.theme.GColor]
        ADDRESS_SPACE: typing.Final[generic.theme.GColor]
        VARNODE: typing.Final[generic.theme.GColor]
        USEROP: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class MnemonicColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NORMAL: typing.Final[generic.theme.GColor]
        OVERRIDE: typing.Final[generic.theme.GColor]
        UNIMPLEMENTED: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class CommentColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        AUTO: typing.Final[generic.theme.GColor]
        EOL: typing.Final[generic.theme.GColor]
        PLATE: typing.Final[generic.theme.GColor]
        POST: typing.Final[generic.theme.GColor]
        PRE: typing.Final[generic.theme.GColor]
        REPEATABLE: typing.Final[generic.theme.GColor]
        REF_REPEATABLE: typing.Final[generic.theme.GColor]
        OFFCUT: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class LabelColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        LOCAL: typing.Final[generic.theme.GColor]
        NON_PRIMARY: typing.Final[generic.theme.GColor]
        PRIMARY: typing.Final[generic.theme.GColor]
        UNREFERENCED: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class FunctionColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        CALL_FIXUP: typing.Final[generic.theme.GColor]
        NAME: typing.Final[generic.theme.GColor]
        PARAM: typing.Final[generic.theme.GColor]
        PARAM_AUTO: typing.Final[generic.theme.GColor]
        PARAM_CUSTOM: typing.Final[generic.theme.GColor]
        PARAM_DYNAMIC: typing.Final[generic.theme.GColor]
        RETURN_TYPE: typing.Final[generic.theme.GColor]
        SOURCE: typing.Final[generic.theme.GColor]
        TAG: typing.Final[generic.theme.GColor]
        VARIABLE: typing.Final[generic.theme.GColor]
        VARIABLE_ASSIGNED: typing.Final[generic.theme.GColor]
        THUNK: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class FlowArrowColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        ACTIVE: typing.Final[generic.theme.GColor]
        INACTIVE: typing.Final[generic.theme.GColor]
        SELECTED: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class MaskColors(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        BITS: typing.Final[generic.theme.GColor]
        LABEL: typing.Final[generic.theme.GColor]
        VALUE: typing.Final[generic.theme.GColor]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BACKGROUND: typing.Final[generic.theme.GColor]
    ADDRESS: typing.Final[generic.theme.GColor]
    BYTES: typing.Final[generic.theme.GColor]
    EXT_ENTRY_POINT: typing.Final[generic.theme.GColor]
    FIELD_NAME: typing.Final[generic.theme.GColor]
    SEPARATOR: typing.Final[generic.theme.GColor]
    UNDERLINE: typing.Final[generic.theme.GColor]
    ARRAY_VALUES: typing.Final[generic.theme.GColor]
    BYTES_ALIGNMENT: typing.Final[generic.theme.GColor]
    BLOCK_START: typing.Final[generic.theme.GColor]
    CONSTANT: typing.Final[generic.theme.GColor]
    REF_BAD: typing.Final[generic.theme.GColor]
    EXT_REF_UNRESOLVED: typing.Final[generic.theme.GColor]
    EXT_REF_RESOLVED: typing.Final[generic.theme.GColor]
    REGISTER: typing.Final[generic.theme.GColor]
    PARALLEL_INSTRUCTION: typing.Final[generic.theme.GColor]

    def __init__(self):
        ...


class ArrayElementPropertyEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ThunkedFunctionFieldFactory(FieldFactory):
    """
    Generates Thunked Function Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Thunked-Function"

    @typing.overload
    def __init__(self):
        """
        Default Constructor
        """

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.ToolOptions, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.ToolOptions displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class FunctionRepeatableCommentFieldMouseHandler(CommentFieldMouseHandler):
    """
    A handler to process :obj:`FunctionRepeatableCommentFieldLocation`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StringCommentPart(CommentPart):
    ...
    class_: typing.ClassVar[java.lang.Class]


class OperandFieldFactory(OperandFieldHelper):
    """
    Generates Operand Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Operands"

    def __init__(self):
        ...

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int]) -> ListingField:
        """
        Returns the FactoryField for the given object at index index.
        
        :param jpype.JInt or int varWidth: the amount of variable width spacing for any fields
        before this one.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object whose properties should be displayed.
        """


class ArrayElementWrappedOption(ghidra.framework.options.CustomOption):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getArrayElementsPerLine(self) -> int:
        ...

    def setArrayElementsPerLine(self, arrayElementsPerLine: typing.Union[jpype.JInt, int]):
        ...

    def setShowMultipleArrayElementPerLine(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def showMultipleArrayElementPerLine(self) -> bool:
        ...

    @property
    def arrayElementsPerLine(self) -> jpype.JInt:
        ...

    @arrayElementsPerLine.setter
    def arrayElementsPerLine(self, value: jpype.JInt):
        ...


class MemoryBlockStartFieldFactory(FieldFactory):
    """
    Generates a text label on each :obj:`CodeUnit` that marks the start of a memory block. The
    label will appear as part of the PLATE group in the field map.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor
        """

    def getFieldLocation(self, listingField: ListingField, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], programLoc: ghidra.program.util.ProgramLocation) -> docking.widgets.fieldpanel.support.FieldLocation:
        """
        Overridden to ensure that we only place block comments on the first :obj:`CodeUnit` of 
        the block.
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.viewer.field.FieldFactory.getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)`
        """

    def getProgramLocation(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], bf: ListingField) -> ghidra.program.util.ProgramLocation:
        """
        Overridden to ensure that we return a :obj:`MemoryBlockStartFieldLocation` instance.
        
        
        .. seealso::
        
            | :obj:`ghidra.app.util.viewer.field.FieldFactory.getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)`
        """


class AnnotatedStringFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`ghidra.util.bean.field.AnnotatedTextFieldElement` clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VariableXRefFieldMouseHandler(XRefFieldMouseHandler):
    """
    A handler to process :obj:`VariableXRefFieldLocation` clicks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VariableCommentFieldFactory(AbstractVariableFieldFactory):
    """
    Generates StackVariableComment Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Variable Comment"

    def __init__(self):
        """
        Constructor
        """


class PostCommentFieldFactory(FieldFactory):
    """
    Generates post comment Fields.
    """

    @typing.type_check_only
    class OverrideCommentData(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Post-Comment"
    ENABLE_WORD_WRAP_MSG: typing.Final = "Post-comments Field.Enable Word Wrapping"
    ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG: typing.Final = "Post-comments Field.Always Show the Automatic Comment"

    def __init__(self):
        """
        Constructor
        """


class AddressAnnotatedStringHandler(AnnotatedStringHandler):
    """
    An annotated string handler that allows handles annotations that begin with
    :obj:`.SUPPORTED_ANNOTATIONS`.  This class expects one string following the annotation
    text that is an address string and will display that string as its display text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def createAddressAnnotationString(destinationAddress: ghidra.program.model.address.Address, displayText: typing.Union[java.lang.String, str]) -> str:
        """
        Constructs a well-formed Address Annotation comment string.
        
        :param ghidra.program.model.address.Address destinationAddress: destination of the annotation
        :param java.lang.String or str displayText: text that will be used as the body of the annotation.  Problematic
        characters will be escaped
        :return: string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def createAddressAnnotationString(addressOffset: typing.Union[jpype.JLong, int], displayText: typing.Union[java.lang.String, str]) -> str:
        """
        Constructs a well-formed Address Annotation comment string.
        
        :param jpype.JLong or int addressOffset: destination of the annotation
        :param java.lang.String or str displayText: text that will be used as the body of the annotation.  Problematic
        characters will be escaped
        :return: string
        :rtype: str
        """


class VariableTypeFieldFactory(AbstractVariableFieldFactory):
    """
    Generates VariableType Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Variable Type"

    def __init__(self):
        """
        Constructor
        """


class VariableLocFieldFactory(AbstractVariableFieldFactory):
    """
    Generates VariableOffset Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Variable Location"

    def __init__(self):
        """
        Constructor
        """

    def getOffsetString(self, offset: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the string representing the offset.
        
        :param jpype.JInt or int offset: the offset to get a string for
        :return: the offset string
        :rtype: str
        """

    @property
    def offsetString(self) -> java.lang.String:
        ...


class Annotation(java.lang.Object):

    @typing.type_check_only
    class TextPart(java.lang.Object):
        """
        A simple class to hold text and extract tokens
        """

        class_: typing.ClassVar[java.lang.Class]

        def grabTokens(self, tokens: java.util.List[java.lang.String]):
            ...


    @typing.type_check_only
    class QuotedTextPart(Annotation.TextPart):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ESCAPABLE_CHARS: typing.Final = "{}\"\\"

    def __init__(self, annotationText: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program):
        """
        Constructor
        **Note**: This constructor assumes that the string starts with "{@" and ends with '}'
        
        :param java.lang.String or str annotationText: The complete annotation text.
        text this Annotation can create
        :param ghidra.program.model.listing.Program program: the program
        """

    def getAnnotationParts(self) -> jpype.JArray[java.lang.String]:
        ...

    def getAnnotationText(self) -> str:
        ...

    @property
    def annotationParts(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def annotationText(self) -> java.lang.String:
        ...


class ListingTextField(ListingField, docking.widgets.fieldpanel.field.TextField):
    """
    ListingField implementation for text fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def createMultilineTextField(factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], textElements: java.util.List[docking.widgets.fieldpanel.field.FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        """
        Displays the given List of text elements, each on its own line.
        
        :param FieldFactory factory: the field factory that generated this field
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object used to populate this field
        :param java.util.List[docking.widgets.fieldpanel.field.FieldElement] textElements: the list of text elements 
        Each of these holds text, attributes and location information.
        :param jpype.JInt or int startX: the starting X position of the field
        :param jpype.JInt or int width: the width of the field
        :param jpype.JInt or int maxLines: the maxLines to display.
        :param ghidra.app.util.ListingHighlightProvider provider: the highlight provider
        :return: the text field.
        :rtype: ListingTextField
        """

    @staticmethod
    @typing.overload
    def createMultilineTextField(factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], textElements: java.util.List[docking.widgets.fieldpanel.field.FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        """
        Displays the given List of text elements, each on its own line with no max line restriction
        
        :param FieldFactory factory: the field factory that generated this field
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object used to populate this field
        :param java.util.List[docking.widgets.fieldpanel.field.FieldElement] textElements: the list of text elements 
        Each of these holds text, attributes and location information.
        :param jpype.JInt or int startX: the starting X position of the field
        :param jpype.JInt or int width: the width of the field
        :param ghidra.app.util.ListingHighlightProvider provider: the highlight provider
        :return: the text field.
        :rtype: ListingTextField
        """

    @staticmethod
    def createPackedTextField(factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], textElements: jpype.JArray[docking.widgets.fieldpanel.field.FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        """
        Displays the list of text strings, packing as many as it can on a line before wrapping to
        the next line.
        
        :param FieldFactory factory: the field factory that generated this field
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object used to populate this field
        :param jpype.JArray[docking.widgets.fieldpanel.field.FieldElement] textElements: the array of elements for the field.
        Each of these holds text, attributes and location information.
        :param jpype.JInt or int startX: the starting X position of the field
        :param jpype.JInt or int width: the width of the field
        :param jpype.JInt or int maxLines: the maxLines to display.
        :param ghidra.app.util.ListingHighlightProvider provider: the highlight provider.
        :return: the text field.
        :rtype: ListingTextField
        """

    @staticmethod
    def createSingleLineTextField(factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        """
        Creates a new ListingTextField that displays the text on a single line, clipping as needed.
        
        :param FieldFactory factory: the field factory that generated this field
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object used to populate this field
        :param docking.widgets.fieldpanel.field.FieldElement fieldElement: the individual element within the field.
        This holds text, attributes and location information.
        :param jpype.JInt or int startX: the starting X position of the field
        :param jpype.JInt or int width: the width of the field
        :param ghidra.app.util.ListingHighlightProvider provider: the highlight provider.
        :return: the text field.
        :rtype: ListingTextField
        """

    @staticmethod
    def createSingleLineTextFieldWithReverseClipping(factory: AddressFieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        ...

    @staticmethod
    def createWordWrappedTextField(factory: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], provider: ghidra.app.util.ListingHighlightProvider) -> ListingTextField:
        """
        Displays the given text, word-wrapping as needed to avoid clipping (up to the max number of
        lines.)
        
        :param FieldFactory factory: the field factory that generated this field
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object used to populate this field
        :param docking.widgets.fieldpanel.field.FieldElement fieldElement: the individual element within the field.
        This holds text, attributes and location information.
        :param jpype.JInt or int startX: the starting X position of the field
        :param jpype.JInt or int width: the width of the field
        :param jpype.JInt or int maxLines: the maxLines to display.
        :param ghidra.app.util.ListingHighlightProvider provider: the highlight provider.
        :return: the text field.
        :rtype: ListingTextField
        """


class BrowserCodeUnitFormatOptions(ghidra.program.model.listing.CodeUnitFormatOptions, ghidra.framework.options.OptionsChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Add format change listener.
        Listeners will only be notified if autoUpdate was true when instantiated.
        
        :param javax.swing.event.ChangeListener listener: the listener
        """

    def followReferencedPointers(self) -> bool:
        """
        Get current state of the Follow Referenced Pointers option.
        
        :return: true if operand pointer read of indirect references will be followed and
        non-dynamic pointer referenced symbol will be rendered in place of pointer label.
        :rtype: bool
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Remove format change listener
        
        :param javax.swing.event.ChangeListener listener: the listener
        """


class PreCommentFieldFactory(FieldFactory):
    """
    Generates pre-comment fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Pre-Comment"
    ENABLE_WORD_WRAP_MSG: typing.Final = "Pre-comments Field.Enable Word Wrapping"
    ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG: typing.Final = "Pre-comments Field.Always Show the Automatic Comment"

    def __init__(self):
        """
        Constructor
        """


class ErrorListingField(ListingTextField):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ff: FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], varWidth: typing.Union[jpype.JInt, int], t: java.lang.Throwable):
        ...

    def getThrowable(self) -> java.lang.Throwable:
        ...

    @property
    def throwable(self) -> java.lang.Throwable:
        ...


class AbstractVariableFieldFactory(FieldFactory):

    @typing.type_check_only
    class ParameterFieldOptions(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Constructs a AbstractVariableFieldFactory with given name.  Used only as potential field.
        
        :param java.lang.String or str name: the name of the field.
        """


class ImageFactoryField(docking.widgets.fieldpanel.field.SimpleImageField, ListingField):
    """
    Class for displaying images in fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, factory: FieldFactory, icon: javax.swing.Icon, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], metrics: java.awt.FontMetrics, x: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param FieldFactory factory: the FieldFactory that generated this field.
        :param javax.swing.Icon icon: the ImageIcon to display.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object that this field represents.
        :param java.awt.FontMetrics metrics: the FontMetrics used to render.
        :param jpype.JInt or int x: the starting x position for this field.
        :param jpype.JInt or int width: the width of this field.
        """

    @typing.overload
    def __init__(self, factory: FieldFactory, icon: javax.swing.Icon, proxy: ghidra.app.util.viewer.proxy.ProxyObj[typing.Any], metrics: java.awt.FontMetrics, x: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], center: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param FieldFactory factory: the FieldFactory that generated this field.
        :param javax.swing.Icon icon: the ImageIcon to display.
        :param ghidra.app.util.viewer.proxy.ProxyObj[typing.Any] proxy: the object that this field represents.
        :param java.awt.FontMetrics metrics: the FontMetrics used to render.
        :param jpype.JInt or int x: the starting x position for this field.
        :param jpype.JInt or int width: the width of this field.
        :param jpype.JBoolean or bool center: centers the image if true.
        """


class SymbolAnnotatedStringHandler(AnnotatedStringHandler):
    """
    An annotated string handler that handles annotations that begin with
    :obj:`.SUPPORTED_ANNOTATIONS`.  This class expects one string following the annotation
    text that is the address or a symbol name.  The display text will be that of the symbol that
    is referred to by the address or symbol name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CommentUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def fixupAnnotations(rawCommentText: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> str:
        """
        Makes adjustments as necessary to any annotations in the given text.
        
        :param java.lang.String or str rawCommentText: the text to be updated
        :param ghidra.program.model.listing.Program program: the program associated with the comment
        :return: the updated string
        :rtype: str
        """

    @staticmethod
    def getAnnotatedStringHandlers() -> java.util.List[AnnotatedStringHandler]:
        """
        Returns all known annotation handlers
        
        :return: the handlers
        :rtype: java.util.List[AnnotatedStringHandler]
        """

    @staticmethod
    def getAnnotationHandler(annotationParts: jpype.JArray[java.lang.String]) -> AnnotatedStringHandler:
        """
        Returns the annotation handler for the given annotation parts.   If no handler can be found,
        then the :obj:`InvalidAnnotatedStringHandler` will be returned with n error message.
        
        :param jpype.JArray[java.lang.String] annotationParts: the annotation parts
        :return: the handler
        :rtype: AnnotatedStringHandler
        """

    @staticmethod
    def getDisplayString(rawCommentText: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> str:
        """
        Returns the display string for the given raw annotation text.  Annotations are 
        encoded strings that fit this pattern: ``{@name text}``.  This method
        will parse the given text, converting any annotations into their display version.
        
        :param java.lang.String or str rawCommentText: text that may include annotations
        :param ghidra.program.model.listing.Program program: the program
        :return: the display string
        :rtype: str
        """

    @staticmethod
    def getOffcutComments(cu: ghidra.program.model.listing.CodeUnit, type: ghidra.program.model.listing.CommentType) -> java.util.List[java.lang.String]:
        """
        Returns a list of offcut comments for the given code unit. All the offcut comments from 
        possibly multiple addresses will be combined into a single list of comment lines.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to get offcut comments for
        :param ghidra.program.model.listing.CommentType type: the type of comment to retrieve (EOL, PRE, PLATE, POST)
        :return: a list of all offcut comments for the given code unit.
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getSymbols(rawText: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns all symbols that match the given text or an empty list.
        
        :param java.lang.String or str rawText: the raw symbol text
        :param ghidra.program.model.listing.Program program: the program
        :return: the symbols
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """

    @staticmethod
    def parseTextForAnnotations(text: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, prototypeString: docking.widgets.fieldpanel.field.AttributedString, row: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.field.FieldElement:
        """
        Parses the given text looking for annotations.
        
        :param java.lang.String or str text: The text to parse.
        :param ghidra.program.model.listing.Program program: the program from which to get information
        :param docking.widgets.fieldpanel.field.AttributedString prototypeString: The reference string used to determine the attributes of any 
                newly created AttributedString.
        :param jpype.JInt or int row: the row of the newly created FieldElement
        :return: A field element containing :obj:`AttributedString`s
        :rtype: docking.widgets.fieldpanel.field.FieldElement
        """

    @staticmethod
    def sanitize(text: typing.Union[java.lang.String, str]) -> str:
        """
        Sanitizes the given text, removing or replacing illegal characters.
         
        
        Each illegal character is handled as follows:
         
        * null character (\0) -> remove
        
        
        :param java.lang.String or str text: The text to sanitize
        :return: The sanitized text, or null if the given text was null
        :rtype: str
        """


class FunctionTagFieldFactory(FieldFactory):
    """
    Generates a text label that lists the function tags for each :obj:`Function`. The
    label will appear as part of the FUNCTION group in the field map.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Function Tags"

    def __init__(self):
        """
        Default Constructor
        """

    def getFieldLocation(self, listingField: ListingField, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], programLoc: ghidra.program.util.ProgramLocation) -> docking.widgets.fieldpanel.support.FieldLocation:
        """
        Overridden to ensure that we only place function tag text on the header of a 
        function.
        """

    def getProgramLocation(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], bf: ListingField) -> ghidra.program.util.ProgramLocation:
        """
        Overridden to ensure that we return` a :obj:`FunctionTagFieldLocation` instance.
        """


class MnemonicFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`MnemonicFieldLocation` clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class VariableXRefFieldFactory(XRefFieldFactory):
    """
    Variable Cross-reference Field Factory
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Variable XRef"

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HighlightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.ToolOptions fieldOptions: the Options for field specific properties.
        """


class FieldStringInfo(java.lang.Object):
    """
    A simple data container class that contains a part string that is part of a parent string with the 
    index of the part string into the parent string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parentString: typing.Union[java.lang.String, str], fieldString: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JInt, int]):
        """
        
        
        :param java.lang.String or str parentString: The parent string
        :param java.lang.String or str fieldString: The part string that exists within the parent
        :param jpype.JInt or int offset: the offset of the part string into the parent
        """

    def getFieldString(self) -> str:
        """
        The string that exists within the parent string.
        
        :return: The string that exists within the parent string.
        :rtype: str
        """

    def getOffset(self) -> int:
        """
        The offset of the part string into the parent string
        
        :return: The offset of the part string into the parent string
        :rtype: int
        """

    def getParentString(self) -> str:
        """
        The string that contains the field string
        
        :return: The string that contains the field string
        :rtype: str
        """

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def parentString(self) -> java.lang.String:
        ...

    @property
    def fieldString(self) -> java.lang.String:
        ...


class URLAnnotatedStringHandler(AnnotatedStringHandler):
    """
    An annotated string handler that allows handles annotations that begin with
    :obj:`.SUPPORTED_ANNOTATIONS`.  This class expects one or two strings following the annotation.
    The first string will be treated as a Java :obj:`URL` and the optional second string will
    be treated as display text.  If there is not display text, then the URL will be
    displayed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionSignatureSourceFieldFactory(FieldFactory):
    """
    Generates Function Signature Source Fields.
    """

    class_: typing.ClassVar[java.lang.Class]
    FIELD_NAME: typing.Final = "Signature Source"

    @typing.overload
    def __init__(self):
        """
        Default Constructor
        """

    @typing.overload
    def __init__(self, model: ghidra.app.util.viewer.format.FieldFormatModel, hlProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.Options, fieldOptions: ghidra.framework.options.Options):
        """
        Constructor
        
        :param ghidra.app.util.viewer.format.FieldFormatModel model: the model that the field belongs to.
        :param ghidra.app.util.ListingHighlightProvider hlProvider: the HightLightProvider.
        :param ghidra.framework.options.Options displayOptions: the Options for display properties.
        :param ghidra.framework.options.Options fieldOptions: the Options for field specific properties.
        """


class OperandFieldMouseHandler(FieldMouseHandlerExtension):
    """
    A handler to process :obj:`OperandFieldLocation` mouse clicks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NamespacePropertyEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["ErrorFieldMouseHandler", "DummyFieldFactory", "XRefHeaderFieldFactory", "ExecutableTaskStringHandler", "ImageFactoryFieldMouseHandler", "GhidraLocalURLAnnotatedStringHandler", "VariableXRefHeaderFieldFactory", "BytesFieldFactory", "FunctionOffsetFieldFactory", "InstructionMaskValueFieldFactory", "AddressFieldFactory", "CommentFieldMouseHandler", "SeparatorFieldFactory", "AbstractOffsetFieldFactory", "IndentField", "FieldNameFieldFactory", "FunctionSignatureFieldFactory", "BrowserCodeUnitFormat", "RegisterTransitionFieldFactory", "SubDataFieldFactory", "ResourceFieldLocation", "AssignedVariableFieldFactory", "VariableNameFieldFactory", "RegisterFieldFactory", "AnnotatedStringHandler", "MemoryBlockOffsetFieldFactory", "SpacerFieldFactory", "MnemonicFieldFactory", "OpenCloseFieldFactory", "LabelCodeUnitFormat", "PlateFieldFactory", "ListingField", "CommentPart", "OperandFieldHelper", "ListingFieldHighlightFactoryAdapter", "OptionsBasedDataTypeDisplayOptions", "XRefFieldMouseHandler", "ThunkedFunctionFieldMouseHandler", "AnnotationCommentPart", "PcodeFieldMouseHandler", "VariableCommentFieldMouseHandler", "OpenCloseFieldMouseHandler", "SpaceFieldFactory", "AnnotationException", "EolEnablement", "AddressFieldOptionsPropertyEditor", "EolExtraCommentsPropertyEditor", "ParallelInstructionFieldFactory", "ArrayValuesFieldFactory", "EolExtraCommentsOption", "InvalidAnnotatedStringHandler", "FieldFactory", "FunctionPurgeFieldFactory", "ArrayElementFieldLocation", "OpenCloseField", "EolCommentFieldFactory", "FunctionCallFixupFieldFactory", "GhidraServerURLAnnotatedStringHandler", "ListingFieldDescriptionProvider", "SourceMapFieldFactory", "LabelFieldFactory", "AddressFieldOptionsWrappedOption", "FieldMouseHandlerExtension", "AnnotatedMouseHandler", "XRefFieldFactory", "ImagebaseOffsetFieldFactory", "FileOffsetFieldFactory", "FunctionRepeatableCommentFieldFactory", "FieldMouseHandler", "ProgramAnnotatedStringHandler", "NamespaceWrappedOption", "ListingColors", "ArrayElementPropertyEditor", "ThunkedFunctionFieldFactory", "FunctionRepeatableCommentFieldMouseHandler", "StringCommentPart", "OperandFieldFactory", "ArrayElementWrappedOption", "MemoryBlockStartFieldFactory", "AnnotatedStringFieldMouseHandler", "VariableXRefFieldMouseHandler", "VariableCommentFieldFactory", "PostCommentFieldFactory", "AddressAnnotatedStringHandler", "VariableTypeFieldFactory", "VariableLocFieldFactory", "Annotation", "ListingTextField", "BrowserCodeUnitFormatOptions", "PreCommentFieldFactory", "ErrorListingField", "AbstractVariableFieldFactory", "ImageFactoryField", "SymbolAnnotatedStringHandler", "CommentUtils", "FunctionTagFieldFactory", "MnemonicFieldMouseHandler", "VariableXRefFieldFactory", "FieldStringInfo", "URLAnnotatedStringHandler", "FunctionSignatureSourceFieldFactory", "OperandFieldMouseHandler", "NamespacePropertyEditor"]
