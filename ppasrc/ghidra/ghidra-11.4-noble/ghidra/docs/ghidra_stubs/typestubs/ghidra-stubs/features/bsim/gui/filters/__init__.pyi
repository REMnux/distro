from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.table
import ghidra.features.bsim.query.client
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.elastic
import ghidra.features.bsim.query.facade
import ghidra.features.bsim.query.protocol
import ghidra.xml
import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.time.format # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import utility.function


T = typing.TypeVar("T")


class DateBSimFilterType(BSimFilterType):
    """
    An abstract BsimFilterType for filtering on dates.
    """

    class_: typing.ClassVar[java.lang.Class]
    FORMATTERS: typing.Final[java.util.List[java.time.format.DateTimeFormatter]]

    @typing.overload
    def __init__(self, label: typing.Union[java.lang.String, str], xmlval: typing.Union[java.lang.String, str], hint: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str label: is the display name of this date filter
        :param java.lang.String or str xmlval: is the XML serialization name
        :param java.lang.String or str hint: is the pop-up hint
        """

    @typing.overload
    def __init__(self):
        ...


class ExecutableCategoryBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on specific category values.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "execatmatches"

    def __init__(self, sub: typing.Union[java.lang.String, str]):
        ...

    def gatherSQLEffect(self, effect: ghidra.features.bsim.query.client.SQLEffects, atom: ghidra.features.bsim.query.protocol.FilterAtom, resolution: ghidra.features.bsim.query.client.IDSQLResolution):
        """
        Custom category filters are processed after results are received, as a necessary consequence
        of the database structure.  So we allow the query to return all possible results, and cull
        them after the fact.
        
        
        .. seealso::
        
            | :obj:`SimilarFunctionQueryService`
        """


class PathStartsBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering on functions by the starting path of their containing program.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "pathstarts"

    def __init__(self):
        ...


class DateEarlierBSimFilterType(DateBSimFilterType):
    """
    A BsimFilterType for filtering on functions in programs created before the filter date.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "dateearlier"

    def __init__(self, sub: typing.Union[java.lang.String, str]):
        ...


class Md5BSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering on functions by the md5 of their containing program.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "md5equals"
    md5Regex: typing.Final = "[a-fA-F0-9]{32}"

    def __init__(self):
        ...


class NotExecutableNameBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering on functions whose containing program don't match a specific name.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "namenotequal"

    def __init__(self):
        ...


class BlankBSimFilterType(BSimFilterType):
    """
    A BSimFilterType that represents a non-specified filter. Used for the gui so that when adding
    a filter it doesn't have to default to some specific filter.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "blank"

    def __init__(self):
        ...


class StringBSimValueEditor(BSimValueEditor):
    """
    A BSimValueEditor for filters with arbitrary string values. Supports comma separated values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterType: BSimFilterType, initialValues: java.util.List[java.lang.String], listener: utility.function.Callback):
        ...

    def hasValidValues(self) -> bool:
        ...


class ExecutableNameBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering on functions by the name of their containing program.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "nameequals"

    def __init__(self):
        ...


class FunctionTagBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on specific function tag values.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "functiontag"
    RESERVED_BITS: typing.ClassVar[jpype.JInt]
    MAX_TAG_COUNT: typing.ClassVar[jpype.JInt]
    KNOWN_LIBRARY_MASK: typing.ClassVar[jpype.JInt]
    HAS_UNIMPLEMENTED_MASK: typing.ClassVar[jpype.JInt]
    HAS_BADDATA_MASK: typing.ClassVar[jpype.JInt]

    @typing.overload
    def __init__(self, tagName: typing.Union[java.lang.String, str], flag: typing.Union[jpype.JInt, int]):
        """
        Creates a new function tag filter.
        
        :param java.lang.String or str tagName: the tag name
        :param jpype.JInt or int flag: the bit position of this flag
        """

    @typing.overload
    def __init__(self, tagName: typing.Union[java.lang.String, str], queryService: ghidra.features.bsim.query.facade.SimilarFunctionQueryService):
        """
        Constructor for clients who do not know what the bit flag position of this
        function tag is. If that's the case, this will figure it out from the
        given queryService object.
        
        :param java.lang.String or str tagName: the name of the tag
        :param ghidra.features.bsim.query.facade.SimilarFunctionQueryService queryService: query service used to retrieve tag big position
        :raises InvalidInputException: thrown if tag does not exist
        """

    def getFlag(self) -> int:
        ...

    @property
    def flag(self) -> jpype.JInt:
        ...


class CompilerBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on a Ghidra compiler specification.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "compequals"

    def __init__(self):
        ...


class NotMd5BSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering on functions whose containing program don't match a specific md5.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "md5notequal"

    def __init__(self):
        ...


class BSimValueEditor(java.lang.Object):
    """
    Interface for BSim filter value editors. Some BSim editors can support multiple values, so the 
    getValues, setValues methods all work on lists of strings.
    """

    class_: typing.ClassVar[java.lang.Class]
    FILTER_DELIMETER: typing.Final = ","
    VALID_COLOR: typing.Final[java.awt.Color]
    INVALID_COLOR: typing.Final[java.awt.Color]

    def getComponent(self) -> javax.swing.JComponent:
        """
        returns the GUI component used to allow the user to see and change editor values.
        
        :return: the GUI component used to allow the user to see and change editor values
        :rtype: javax.swing.JComponent
        """

    def getValues(self) -> java.util.List[java.lang.String]:
        """
        Returns the current set of editor values.
        
        :return: the current set of editor values
        :rtype: java.util.List[java.lang.String]
        """

    def hasValidValues(self) -> bool:
        """
        Returns true if the editor has valid values as determined by the editor's corresponding 
        :obj:`BSimFilterType.isValidValue`.
        
        :return: true if the editor has valid values as determined by the editor's corresponding 
        filter type.
        :rtype: bool
        """

    def setValues(self, values: java.util.List[java.lang.String]):
        """
        Sets the editor to the given string values. They are displayed in the GUI as comma separated
        values.
        
        :param java.util.List[java.lang.String] values: the values to be used as the current editor values
        """

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def values(self) -> java.util.List[java.lang.String]:
        ...

    @values.setter
    def values(self, value: java.util.List[java.lang.String]):
        ...


class ArchitectureBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on a Ghidra computer architecture
    specification.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "archequals"

    def __init__(self):
        ...

    @staticmethod
    def getArchitectures() -> java.util.List[java.lang.String]:
        ...


class BooleanBSimValueEditor(BSimValueEditor):
    """
    A BSimValueEditor for boolean filter values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterType: BSimFilterType, initialValues: java.util.List[java.lang.String], listener: utility.function.Callback):
        ...


class NotExecutableCategoryBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on not matching specific category values.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "execatnomatch"

    def __init__(self, sub: typing.Union[java.lang.String, str]):
        ...

    def gatherSQLEffect(self, effect: ghidra.features.bsim.query.client.SQLEffects, atom: ghidra.features.bsim.query.protocol.FilterAtom, resolution: ghidra.features.bsim.query.client.IDSQLResolution):
        """
        Custom category filters are processed after results are received, as a necessary consequence
        of the database structure.  So we allow the query to return all possible results, and cull
        them after the fact.
        
        
        .. seealso::
        
            | :obj:`SimilarFunctionQueryService`
        """


class MultiChoiceBSimValueEditor(BSimValueEditor):
    """
    Base class for BSimValueEditors that work on a list of possible choices
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterType: BSimFilterType, choices: java.util.List[java.lang.String], initialValues: java.util.List[java.lang.String], dataTitle: typing.Union[java.lang.String, str], listener: utility.function.Callback):
        ...

    def hasValidValues(self) -> bool:
        ...


class MultiChoiceSelectionDialog(docking.DialogComponentProvider, typing.Generic[T]):
    """
    Dialog for selection one or more choices from a list of possible values.
    """

    @typing.type_check_only
    class ChoiceRowObject(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getData(self) -> T:
            ...

        def isSelected(self) -> bool:
            ...

        def setSelected(self, b: typing.Union[jpype.JBoolean, bool]):
            ...

        @property
        def data(self) -> T:
            ...

        @property
        def selected(self) -> jpype.JBoolean:
            ...

        @selected.setter
        def selected(self, value: jpype.JBoolean):
            ...


    @typing.type_check_only
    class ChoiceTableModel(docking.widgets.table.GDynamicColumnTableModel[MultiChoiceSelectionDialog.ChoiceRowObject, java.lang.Object]):

        @typing.type_check_only
        class SelectedColumn(docking.widgets.table.AbstractDynamicTableColumn[MultiChoiceSelectionDialog.ChoiceRowObject, java.lang.Boolean, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class DataColumn(docking.widgets.table.AbstractDynamicTableColumn[MultiChoiceSelectionDialog.ChoiceRowObject, java.lang.String, java.lang.Object]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def getSelectedData(self) -> java.util.List[T]:
            ...

        @property
        def selectedData(self) -> java.util.List[T]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataTitle: typing.Union[java.lang.String, str], choices: java.util.List[T], selected: java.util.Set[T]):
        ...

    @typing.overload
    def __init__(self, dataTitle: typing.Union[java.lang.String, str], choices: java.util.List[T], selected: java.util.Set[T], dataConverter: docking.widgets.DataToStringConverter[T]):
        ...

    def getSelectedChoices(self) -> java.util.List[T]:
        ...

    @property
    def selectedChoices(self) -> java.util.List[T]:
        ...


class HasNamedChildBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on calls to specific external functions.
    The called function must be external, i.e. in terms of the database, the function must be
    associated with a library executable (having no code body)
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "namedchild"

    def __init__(self):
        ...


class DateLaterBSimFilterType(DateBSimFilterType):
    """
    A BsimFilterType for filtering on functions in programs created after the filter date.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "datelater"

    def __init__(self, sub: typing.Union[java.lang.String, str]):
        ...


class BSimFilterType(java.lang.Comparable[BSimFilterType]):
    """
    The base class for BSim filter types. Each filter type represents a different filter criteria 
    that can be applied to a BSim Search query. They have a human readable description and a way
    to convert string values for the filter into SQL queries.
    """

    class_: typing.ClassVar[java.lang.Class]
    BLANK: typing.ClassVar[BSimFilterType]

    def __init__(self, label: typing.Union[java.lang.String, str], xmlval: typing.Union[java.lang.String, str], hint: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str label: is the name used for display
        :param java.lang.String or str xmlval: is the name used for XML serialization
        :param java.lang.String or str hint: is the pop-up menu hint
        """

    def buildElasticCombinedClause(self, subClauses: java.util.List[java.lang.String]) -> str:
        """
        Given (multiple) clauses for a single filter type, combine into a single elasticsearch script conditional
        
        :param java.util.List[java.lang.String] subClauses: is the list of script clauses
        :return: the combined clause
        :rtype: str
        """

    def buildSQLCombinedClause(self, subClauses: java.util.List[java.lang.String]) -> str:
        """
        Given (multiple) clauses for a single filter type, combine into a single SQL where clause
        
        :param java.util.List[java.lang.String] subClauses: is the list of SQL clauses
        :return: the combined clause
        :rtype: str
        """

    def evaluate(self, rec: ghidra.features.bsim.query.description.ExecutableRecord, value: typing.Union[java.lang.String, str]) -> bool:
        """
        Evaluate this filter for a specific ExecutableRecord and a specific filter -value-
        
        :param ghidra.features.bsim.query.description.ExecutableRecord rec: is the ExecutableRecord to filter against
        :param java.lang.String or str value: is the String value for an instantiated filter
        :return: true if this element would allow the ExecutableRecord to pass the filter
        :rtype: bool
        """

    def gatherElasticEffect(self, effect: ghidra.features.bsim.query.elastic.ElasticEffects, atom: ghidra.features.bsim.query.protocol.FilterAtom, resolution: ghidra.features.bsim.query.elastic.IDElasticResolution):
        """
        Gather pieces necessary to emit this filter as part of an elasticsearch query document
        
        :param ghidra.features.bsim.query.elastic.ElasticEffects effect: is the ElasticEffects container holding the pieces
        :param ghidra.features.bsim.query.protocol.FilterAtom atom: holds the values for a particular instantiation of this filter element
        :param ghidra.features.bsim.query.elastic.IDElasticResolution resolution: contains relevant ids for the filter, which must have been precalculated
        :raises ElasticException: for errors building the JSON subdocument
        """

    def gatherSQLEffect(self, effect: ghidra.features.bsim.query.client.SQLEffects, atom: ghidra.features.bsim.query.protocol.FilterAtom, resolution: ghidra.features.bsim.query.client.IDSQLResolution):
        """
        Gather all pieces to successfully convert this filter element into an SQL clause
        
        :param ghidra.features.bsim.query.client.SQLEffects effect: is SQLEffects container for this filter elements pieces and others
        :param ghidra.features.bsim.query.protocol.FilterAtom atom: holds the values for a particular instantiation of this filter element
        :param ghidra.features.bsim.query.client.IDSQLResolution resolution: is the IDResolution containing relevant row ids for the filter, which must have been precalculated
        :raises SQLException: for errors building the SQL clause
        """

    @staticmethod
    def generateBsimFilters(info: ghidra.features.bsim.query.description.DatabaseInformation, includeChildFilter: typing.Union[jpype.JBoolean, bool]) -> java.util.List[BSimFilterType]:
        """
        Generate a possibly restricted/extended set of FilterTemplates
        
        :param ghidra.features.bsim.query.description.DatabaseInformation info: is database information which informs about which filters to create
        :param jpype.JBoolean or bool includeChildFilter: toggles whether or not ChildFilters should be included in this particular set
        :return: the list of filter templates
        :rtype: java.util.List[BSimFilterType]
        """

    def generateIDElasticResolution(self, atom: ghidra.features.bsim.query.protocol.FilterAtom) -> ghidra.features.bsim.query.elastic.IDElasticResolution:
        """
        Construct a record describing the document id's that might be needed before this filter
        element can be converted to an Elasticsearch filter script clause
        
        :param ghidra.features.bsim.query.protocol.FilterAtom atom: is the specific FilterAtom to generate the record for
        :return: the record or null if no ids need to be recovered
        :rtype: ghidra.features.bsim.query.elastic.IDElasticResolution
        """

    def generateIDSQLResolution(self, atom: ghidra.features.bsim.query.protocol.FilterAtom) -> ghidra.features.bsim.query.client.IDSQLResolution:
        """
        Construct a record describing the column id's that might need to be recovered before this filter
        element can be converted to an SQL clause
        
        :param ghidra.features.bsim.query.protocol.FilterAtom atom: is the specific FilterAtom to generate the record for
        :return: the IDSQLResolution record or null if no ids need to be recovered
        :rtype: ghidra.features.bsim.query.client.IDSQLResolution
        """

    @staticmethod
    def getBaseFilters() -> java.util.List[BSimFilterType]:
        ...

    @staticmethod
    def getBlank() -> BSimFilterType:
        """
        
        
        :return: the Blank FilterTemplate
        :rtype: BSimFilterType
        """

    def getEditor(self, initialValues: java.util.List[java.lang.String], listener: utility.function.Callback) -> BSimValueEditor:
        ...

    def getHint(self) -> str:
        """
        
        
        :return: the hint text
        :rtype: str
        """

    def getLabel(self) -> str:
        ...

    def getXmlValue(self) -> str:
        """
        
        
        :return: the tag name for serialization
        :rtype: str
        """

    def isBlank(self) -> bool:
        """
        
        
        :return: true if this is a "blank" filter (i.e. an unused element within a gui)
        :rtype: bool
        """

    def isChildFilter(self) -> bool:
        """
        
        
        :return: true if this is a filter element based on callgraph information of functions
        :rtype: bool
        """

    def isLocal(self) -> bool:
        """
        
        
        :return: true if any id's relevant to this filter must be resolved relative to the local ColumnDatabase
        :rtype: bool
        """

    def isMultipleEntryAllowed(self) -> bool:
        """
        
        
        :return: true if multiple filters of this type are allowed.
        :rtype: bool
        """

    def isValidValue(self, value: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests if the given string is a valid value for this filter type.
        
        :param java.lang.String or str value: the value to test
        :return: true if the given string is valid for this filter
        :rtype: bool
        """

    @staticmethod
    def nameToType(el: ghidra.xml.XmlElement) -> BSimFilterType:
        """
        Convenience function for deserializing FilterTemplates
        
        :param ghidra.xml.XmlElement el: is the tag to deserialize
        :return: the deserialized FilterTemplate
        :rtype: BSimFilterType
        """

    def normalizeValue(self, value: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a normalized version of the given value for this filter.
        
        :param java.lang.String or str value: the value to be normalized
        :return: a normalized version of the given value for this filter
        :rtype: str
        """

    def orMultipleEntries(self) -> bool:
        """
        
        
        :return: true if multiple filters of this type should be OR'd. AND them otherwise.
        :rtype: bool
        """

    def saveXml(self, fwrite: java.io.Writer):
        """
        Save XML attributes corresponding to this template
        
        :param java.io.Writer fwrite: is the output stream
        :raises IOException: for problems writing to the stream
        """

    @property
    def childFilter(self) -> jpype.JBoolean:
        ...

    @property
    def blank(self) -> jpype.JBoolean:
        ...

    @property
    def xmlValue(self) -> java.lang.String:
        ...

    @property
    def validValue(self) -> jpype.JBoolean:
        ...

    @property
    def hint(self) -> java.lang.String:
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @property
    def multipleEntryAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def local(self) -> jpype.JBoolean:
        ...


class NotArchitectureBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on not matching a Ghidra computer architecture
    specification.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "archnotequal"

    def __init__(self):
        ...

    @staticmethod
    def getArchitectures() -> java.util.List[java.lang.String]:
        ...


class NotCompilerBSimFilterType(BSimFilterType):
    """
    A BsimFilterType for filtering functions based on not matching a Ghidra compiler specification.
    """

    class_: typing.ClassVar[java.lang.Class]
    XML_VALUE: typing.Final = "compnotequal"

    def __init__(self):
        ...



__all__ = ["DateBSimFilterType", "ExecutableCategoryBSimFilterType", "PathStartsBSimFilterType", "DateEarlierBSimFilterType", "Md5BSimFilterType", "NotExecutableNameBSimFilterType", "BlankBSimFilterType", "StringBSimValueEditor", "ExecutableNameBSimFilterType", "FunctionTagBSimFilterType", "CompilerBSimFilterType", "NotMd5BSimFilterType", "BSimValueEditor", "ArchitectureBSimFilterType", "BooleanBSimValueEditor", "NotExecutableCategoryBSimFilterType", "MultiChoiceBSimValueEditor", "MultiChoiceSelectionDialog", "HasNamedChildBSimFilterType", "DateLaterBSimFilterType", "BSimFilterType", "NotArchitectureBSimFilterType", "NotCompilerBSimFilterType"]
