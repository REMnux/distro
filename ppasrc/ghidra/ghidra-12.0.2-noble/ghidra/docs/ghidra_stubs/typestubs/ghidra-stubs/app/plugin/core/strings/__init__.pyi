from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.combobox
import docking.widgets.table
import docking.widgets.table.constraint
import docking.widgets.table.threaded
import generic.jar
import ghidra.app.context
import ghidra.app.plugin
import ghidra.app.services
import ghidra.docking.settings
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class CharacterScriptUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    IGNORED_SCRIPTS: typing.Final[java.util.List[java.lang.Character.UnicodeScript]]
    """
    Scripts that are not helpful to use when filtering strings
    """

    ANY_SCRIPT_ALIAS: typing.Final[java.lang.Character.UnicodeScript]
    """
    The :obj:`UnicodeScript` value that represents the "ANY" choice.  This is a bit of a hack
    and re-uses the enum value for this purpose.
    """


    def __init__(self):
        ...

    @staticmethod
    def getDisplayableScriptExamples(f: java.awt.Font, maxExampleLen: typing.Union[jpype.JInt, int]) -> java.util.Map[java.lang.Character.UnicodeScript, java.lang.String]:
        """
        Builds a map of example character sequences for every current UnicodeScript, where the
        specified font can display the characters of that script.
        
        :param java.awt.Font f: :obj:`Font`
        :param jpype.JInt or int maxExampleLen: length of the character sequence to generate
        :return: map of unicodescript-to-string
        :rtype: java.util.Map[java.lang.Character.UnicodeScript, java.lang.String]
        """


@typing.type_check_only
class EncodedStringsOptions(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def alignStartOfString(self) -> bool:
        ...

    def allowedScripts(self) -> java.util.Set[java.lang.Character.UnicodeScript]:
        ...

    def breakOnRef(self) -> bool:
        ...

    def charSize(self) -> int:
        ...

    def charsetName(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def excludeNonStdCtrlChars(self) -> bool:
        ...

    def excludeStringsWithErrors(self) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def minStringLength(self) -> int:
        ...

    def requireValidString(self) -> bool:
        ...

    def requiredScripts(self) -> java.util.Set[java.lang.Character.UnicodeScript]:
        ...

    def settings(self) -> ghidra.docking.settings.Settings:
        ...

    def stringDT(self) -> ghidra.program.model.data.AbstractStringDataType:
        ...

    def stringValidator(self) -> ghidra.app.services.StringValidatorService:
        ...

    def toString(self) -> str:
        ...


class HasTranslationValueColumnConstraint(StringDataInstanceColumnConstraint):
    """
    Tests if a string data instance has a translated value available
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Trigram(java.lang.Record, java.lang.Comparable[Trigram]):
    """
    Three (3) adjacent characters, with \0 being reserved for start and end of string magic values.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codePoints: jpype.JArray[jpype.JInt]):
        ...

    def codePoints(self) -> jpype.JArray[jpype.JInt]:
        ...

    @staticmethod
    def fromStringRep(s1: typing.Union[java.lang.String, str], s2: typing.Union[java.lang.String, str], s3: typing.Union[java.lang.String, str]) -> Trigram:
        ...

    @staticmethod
    def iterate(s: typing.Union[java.lang.String, str]) -> StringTrigramIterator:
        ...

    @staticmethod
    def of(cp1: typing.Union[jpype.JInt, int], cp2: typing.Union[jpype.JInt, int], cp3: typing.Union[jpype.JInt, int]) -> Trigram:
        ...

    def toCharSeq(self) -> str:
        ...


class IsAsciiColumnConstraint(StringDataInstanceColumnConstraint):
    """
    Tests if a string value contains only ASCII characters.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class EncodedStringsThreadedTablePanel(ghidra.util.table.GhidraThreadedTablePanel[T], typing.Generic[T]):
    """
    A Ghidra table panel that can show a custom overlay instead of an empty table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.table.threaded.ThreadedTableModel[T, typing.Any], minUpdateDelay: typing.Union[jpype.JInt, int], emptyTableOverlayComponent: java.awt.Component):
        ...

    def showEmptyTableOverlay(self, b: typing.Union[jpype.JBoolean, bool]):
        ...


class StringInfo(java.lang.Record):
    """
    Information about a string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, stringValue: typing.Union[java.lang.String, str], scripts: java.util.Set[java.lang.Character.UnicodeScript], stringFeatures: java.util.Set[StringInfoFeature]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromString(s: typing.Union[java.lang.String, str]) -> StringInfo:
        """
        Creates a :obj:`StringInfo` instance
        
        :param java.lang.String or str s: string
        :return: new :obj:`StringInfo` instance
        :rtype: StringInfo
        """

    def hasCodecError(self) -> bool:
        ...

    def hasNonStdCtrlChars(self) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def scripts(self) -> java.util.Set[java.lang.Character.UnicodeScript]:
        ...

    def stringFeatures(self) -> java.util.Set[StringInfoFeature]:
        ...

    def stringValue(self) -> str:
        ...

    def toString(self) -> str:
        ...


@typing.type_check_only
class ViewStringsTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.util.ProgramLocation]):
    """
    Table model for the "Defined Strings" table.
     
    
    This implementation keeps a local index of Address to row object (which are ProgramLocations)
    so that DomainObjectChangedEvent events can be efficiently handled.
    """

    class COLUMNS(java.lang.Enum[ViewStringsTableModel.COLUMNS]):
        """
        Columns defined by this table (useful for enum.ordinal())
        """

        class_: typing.ClassVar[java.lang.Class]
        ADDRESS_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        STRING_VALUE_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        STRING_REP_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        DATA_TYPE_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        IS_ASCII_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        CHARSET_COL: typing.Final[ViewStringsTableModel.COLUMNS]
        HAS_ENCODING_ERROR: typing.Final[ViewStringsTableModel.COLUMNS]
        UNICODE_SCRIPT: typing.Final[ViewStringsTableModel.COLUMNS]
        TRANSLATED_VALUE: typing.Final[ViewStringsTableModel.COLUMNS]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ViewStringsTableModel.COLUMNS:
            ...

        @staticmethod
        def values() -> jpype.JArray[ViewStringsTableModel.COLUMNS]:
            ...


    @typing.type_check_only
    class DataLocationColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, ghidra.util.table.field.AddressBasedLocation]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataValueColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, ghidra.program.model.data.StringDataInstance]):

        @typing.type_check_only
        class DataValueCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[ghidra.program.model.data.StringDataInstance]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringRepColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IsAsciiColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HasEncodingErrorColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CharsetColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TranslatedValueColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UnicodeScriptColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[ghidra.program.util.ProgramLocation, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addDataInstance(self, localProgram: ghidra.program.model.listing.Program, data: ghidra.program.model.listing.Data):
        ...

    def findEquivProgramLocation(self, pl: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        ...

    def reload(self, newProgram: ghidra.program.model.listing.Program):
        ...

    def removeDataInstanceAt(self, addr: ghidra.program.model.address.Address):
        ...


class HasEncodingErrorColumnConstraint(StringDataInstanceColumnConstraint):
    """
    Tests if a string value contains any Unicode :obj:`StringUtilities.UNICODE_REPLACEMENT` chars,
    which indicate that there was a decoding error
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class EncodedStringsFilterStats(java.lang.Object):
    """
    Holds counts of reasons for filter rejection
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, other: EncodedStringsFilterStats):
        ...


class TrigramStringValidator(ghidra.app.services.StringValidatorService):
    """
    A :obj:`StringValidatorService` that uses precomputed trigram frequencies from
    a ".sng" model file to score strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trigramLogs: collections.abc.Mapping, totalNumTrigrams: typing.Union[jpype.JLong, int], modelValueTransformer: java.util.function.Function[java.lang.String, java.lang.String], thresholds: jpype.JArray[jpype.JDouble], sourceFile: generic.jar.ResourceFile):
        ...

    def dumpModel(self) -> java.util.Iterator[java.lang.String]:
        ...

    def getSourceFile(self) -> generic.jar.ResourceFile:
        ...

    def getTotalNumTrigrams(self) -> int:
        ...

    @staticmethod
    def read(f: generic.jar.ResourceFile) -> TrigramStringValidator:
        ...

    @property
    def totalNumTrigrams(self) -> jpype.JLong:
        ...

    @property
    def sourceFile(self) -> generic.jar.ResourceFile:
        ...


class ViewStringsColumnConstraintProvider(docking.widgets.table.constraint.ColumnConstraintProvider):
    """
    Provides column constraints for :obj:`StringDataInstance`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ViewStringsProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Provider for the defined strings table.
    """

    @typing.type_check_only
    class StringRepCellEditor(docking.widgets.table.GTableTextCellEditor):
        """
        Table cell editor that swaps the editing value to be the raw string value instead of the
        formatted representation.
         
        
        This causes the cell to be displayed as the formatted representation and then when the user
        double clicks to start editing mode, it swaps to non-formatted version.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ICON: typing.Final[javax.swing.Icon]

    def getModel(self) -> ViewStringsTableModel:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    def showProgramLocation(self, loc: ghidra.program.util.ProgramLocation):
        ...

    @property
    def model(self) -> ViewStringsTableModel:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class DoesNotHaveTranslationValueColumnConstraint(HasTranslationValueColumnConstraint):
    """
    Tests if a string data instance has a translated value available
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ViewStringsPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    Plugin that provides the "Defined Strings" table, where all the currently defined
    string data in the program is listed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class EncodedStringsTableModel(ghidra.util.table.AddressBasedTableModel[EncodedStringsRow]):

    @typing.type_check_only
    class DataLocationColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, ghidra.util.table.field.AddressBasedLocation]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringRepColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, EncodedStringsRow]):

        @typing.type_check_only
        class StringRepCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[EncodedStringsRow]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UnicodeScriptColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefCountColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OffcutRefCountColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ValidStringColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LengthColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ByteLengthColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[EncodedStringsRow, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModelState(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getStats(self) -> EncodedStringsFilterStats:
        ...

    def removeRows(self, rows: java.util.List[EncodedStringsRow]):
        ...

    def setOptions(self, options: EncodedStringsOptions):
        ...

    @property
    def stats(self) -> EncodedStringsFilterStats:
        ...


class StringTrigramIterator(java.util.Iterator[Trigram]):
    """
    Splits a string into trigrams
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, s: typing.Union[java.lang.String, str]):
        ...


class UndefinedStringIterator(java.util.Iterator[ghidra.program.model.data.StringDataInstance], java.lang.Iterable[ghidra.program.model.data.StringDataInstance]):
    """
    Iterator that searches for locations that could be strings and returns 
    :obj:`StringDataInstance`s representing those locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, addrs: ghidra.program.model.address.AddressSetView, charSize: typing.Union[jpype.JInt, int], charAlignment: typing.Union[jpype.JInt, int], breakOnRef: typing.Union[jpype.JBoolean, bool], singleStringMode: typing.Union[jpype.JBoolean, bool], stringDataType: ghidra.program.model.data.AbstractStringDataType, stringSettings: ghidra.docking.settings.Settings, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new UndefinedStringIterator instance.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param ghidra.program.model.address.AddressSetView addrs: set of :obj:`Address`es to search.
        :param jpype.JInt or int charSize: size of the characters (and the null-terminator) that make up the string
        :param jpype.JInt or int charAlignment: alignment requirements for the start of the string
        :param jpype.JBoolean or bool breakOnRef: boolean flag, if true strings will be terminated early at locations that
        have an in-bound memory reference
        :param jpype.JBoolean or bool singleStringMode: boolean flag, if true only one string will be returned, and it must
        be located at the start of the specified address set (after alignment tweaks)
        :param ghidra.program.model.data.AbstractStringDataType stringDataType: a string data type that corresponds to the type of string being
        searched for
        :param ghidra.docking.settings.Settings stringSettings: :obj:`Settings` for the string data type
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        """


class ViewStringsContext(docking.DefaultActionContext, ghidra.app.context.DataLocationListContext):

    class_: typing.ClassVar[java.lang.Class]

    def getSelectedData(self) -> ghidra.program.model.listing.Data:
        ...

    def getSelectedRowCount(self) -> int:
        ...

    @property
    def selectedData(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def selectedRowCount(self) -> jpype.JInt:
        ...


class StringDataInstanceColumnConstraint(docking.widgets.table.constraint.ColumnConstraint[ghidra.program.model.data.StringDataInstance]):
    """
    Root class for :obj:`StringDataInstance` constraints
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StringInfoFeature(java.lang.Enum[StringInfoFeature]):

    class_: typing.ClassVar[java.lang.Class]
    CODEC_ERROR: typing.Final[StringInfoFeature]
    NON_STD_CTRL_CHARS: typing.Final[StringInfoFeature]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> StringInfoFeature:
        ...

    @staticmethod
    def values() -> jpype.JArray[StringInfoFeature]:
        ...


class EncodedStringsDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class CharScriptComboBox(docking.widgets.combobox.GhidraComboBox[java.lang.Character.UnicodeScript]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: EncodedStringsPlugin, program: ghidra.program.model.listing.Program, selectedAddresses: ghidra.program.model.address.AddressSetView):
        ...

    def getCreateButton(self) -> javax.swing.JButton:
        """
        For test/screen shot use
        
        :return: button
        :rtype: javax.swing.JButton
        """

    def getStringModel(self) -> EncodedStringsTableModel:
        """
        For test/screen shot use
        
        :return: table model
        :rtype: EncodedStringsTableModel
        """

    def programClosed(self, p: ghidra.program.model.listing.Program):
        ...

    def setAllowAnyScriptOption(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setAllowCommonScriptOption(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setAllowLatinScriptOption(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setExcludeCodecErrors(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setExcludeNonStdCtrlChars(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setRequireValidStringOption(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setRequiredScript(self, requiredScript: java.lang.Character.UnicodeScript):
        """
        For test/screen shot use
        
        :param java.lang.Character.UnicodeScript requiredScript: unicode script
        """

    def setSelectedCharset(self, charsetName: typing.Union[java.lang.String, str]):
        """
        For test/screen shot use
        
        :param java.lang.String or str charsetName: set the charset
        """

    def setShowAdvancedOptions(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    def setShowScriptOptions(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        For test/screen shot use
        
        :param jpype.JBoolean or bool b: boolean
        """

    @property
    def stringModel(self) -> EncodedStringsTableModel:
        ...

    @property
    def createButton(self) -> javax.swing.JButton:
        ...


class EncodedStringsPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getSearchForEncodedStringsAction(self) -> docking.action.DockingAction:
        ...

    @property
    def searchForEncodedStringsAction(self) -> docking.action.DockingAction:
        ...


class IsNotAsciiColumnConstraint(IsAsciiColumnConstraint):
    """
    Tests if a string value contains any non-ascii characters
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class EncodedStringsRow(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def offcutCount(self) -> int:
        ...

    def refCount(self) -> int:
        ...

    def sdi(self) -> ghidra.program.model.data.StringDataInstance:
        ...

    def stringInfo(self) -> StringInfo:
        ...

    def toString(self) -> str:
        ...

    def validString(self) -> bool:
        ...



__all__ = ["CharacterScriptUtils", "EncodedStringsOptions", "HasTranslationValueColumnConstraint", "Trigram", "IsAsciiColumnConstraint", "EncodedStringsThreadedTablePanel", "StringInfo", "ViewStringsTableModel", "HasEncodingErrorColumnConstraint", "EncodedStringsFilterStats", "TrigramStringValidator", "ViewStringsColumnConstraintProvider", "ViewStringsProvider", "DoesNotHaveTranslationValueColumnConstraint", "ViewStringsPlugin", "EncodedStringsTableModel", "StringTrigramIterator", "UndefinedStringIterator", "ViewStringsContext", "StringDataInstanceColumnConstraint", "StringInfoFeature", "EncodedStringsDialog", "EncodedStringsPlugin", "IsNotAsciiColumnConstraint", "EncodedStringsRow"]
