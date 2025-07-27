from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.filter
import docking.widgets.table
import ghidra.app.context
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore
import utility.function


class SetEquateDialog(docking.DialogComponentProvider):

    class SelectionType(java.lang.Enum[SetEquateDialog.SelectionType]):

        class_: typing.ClassVar[java.lang.Class]
        CURRENT_ADDRESS: typing.Final[SetEquateDialog.SelectionType]
        SELECTION: typing.Final[SetEquateDialog.SelectionType]
        ENTIRE_PROGRAM: typing.Final[SetEquateDialog.SelectionType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SetEquateDialog.SelectionType:
            ...

        @staticmethod
        def values() -> jpype.JArray[SetEquateDialog.SelectionType]:
            ...


    class EquateRowObject(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getEntryName(self) -> str:
            ...

        def getEnumDataType(self) -> ghidra.program.model.data.Enum:
            ...

        def getEquate(self) -> ghidra.program.model.symbol.Equate:
            ...

        def getPath(self) -> str:
            ...

        def getRefCount(self) -> int:
            ...

        @property
        def path(self) -> java.lang.String:
            ...

        @property
        def equate(self) -> ghidra.program.model.symbol.Equate:
            ...

        @property
        def refCount(self) -> jpype.JInt:
            ...

        @property
        def entryName(self) -> java.lang.String:
            ...

        @property
        def enumDataType(self) -> ghidra.program.model.data.Enum:
            ...


    @typing.type_check_only
    class EquateFilterListener(docking.widgets.filter.FilterListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EquateEnterListener(utility.function.Callback):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    CANCELED: typing.Final = 0
    OK: typing.Final = 1

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, value: ghidra.program.model.scalar.Scalar):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: the EquatePlugin that launched this dialog(used to validate input)
        :param ghidra.program.model.listing.Program program: the program the equate is located in.
        :param ghidra.program.model.scalar.Scalar value: the equate value to set.
        """

    def disableHasSelection(self):
        """
        For using the dialog outside of the EquatePlugin, the "Apply to Current" radio button
        can be selected and the other buttons disabled.
        """

    def getEnumDataType(self) -> ghidra.program.model.data.Enum:
        """
        Get's the user selected entry in the dialog and returns the enum data type for that entry
        
        :return: the enum data type for the selected entry, or null if there is no enum.
        :rtype: ghidra.program.model.data.Enum
        """

    def getEquateName(self) -> str:
        ...

    def getOverwriteExisting(self) -> bool:
        """
        Returns true if the user has chosen to overwrite any existing equate rules.
        
        :return: true if the user has chosen to overwrite any existing equate rules.
        :rtype: bool
        """

    def getSelectionType(self) -> SetEquateDialog.SelectionType:
        """
        Returns the type of selection the user has chosen.
        
        :return: the selection type
        :rtype: SetEquateDialog.SelectionType
        """

    def setHasSelection(self, context: ghidra.app.context.ListingActionContext):
        """
        Set the state of the some buttons on the dialog.  ie: if the user has selected
        a range of addresses we should automatically set the "selection" radio button
        to the selected state.
        
        :param ghidra.app.context.ListingActionContext context: The current context.
        """

    def showRenameDialog(self) -> int:
        """
        Invoke the dialog.
        
        :return: the exit condition of the dialog.  The return value can be one of:
        CANCELED - the user canceled the action.
        OK - the user pressed the "Ok" button or pressed the return key in the textfield.
        :rtype: int
        """

    def showSetDialog(self) -> int:
        """
        Invoke the dialog.
        
        :return: the exit condition of the dialog.  The return value can be one of:
        CANCELED - the user canceled the action.
        OK - the user pressed the "Ok" button or pressed the return key in the textfield.
        :rtype: int
        """

    @property
    def selectionType(self) -> SetEquateDialog.SelectionType:
        ...

    @property
    def overwriteExisting(self) -> jpype.JBoolean:
        ...

    @property
    def enumDataType(self) -> ghidra.program.model.data.Enum:
        ...

    @property
    def equateName(self) -> java.lang.String:
        ...


class SelectLanguagePanelListener(java.lang.Object):
    """
    A listener for the SelectLanguagePanel
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectIDValidation(self, langID: ghidra.program.model.lang.LanguageID, compilerSpecID: ghidra.program.model.lang.CompilerSpecID):
        """
        This method is invoked every time a languauge is selected.
        NOTE: the language could be null.
        
        :param ghidra.program.model.lang.LanguageID langID: the selected language id.
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecID: the selected compiler spec id.
        """


class FixedBitSizeValueField(javax.swing.JPanel):

    @typing.type_check_only
    class MyDocFilter(javax.swing.text.DocumentFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bitSize: typing.Union[jpype.JInt, int], includeFormatButton: typing.Union[jpype.JBoolean, bool], leftJustify: typing.Union[jpype.JBoolean, bool]):
        ...

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        ...

    def getTextComponent(self) -> java.awt.Component:
        ...

    def getValue(self) -> java.math.BigInteger:
        ...

    def processText(self) -> bool:
        ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        ...

    def setBitSize(self, bitSize: typing.Union[jpype.JInt, int]):
        ...

    def setFormat(self, radix: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMinMax(self, min: java.math.BigInteger, max: java.math.BigInteger):
        ...

    @typing.overload
    def setValue(self, value: java.math.BigInteger) -> bool:
        ...

    @typing.overload
    def setValue(self, value: java.math.BigInteger, pad: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def valueChanged(self):
        ...

    @property
    def textComponent(self) -> java.awt.Component:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...


class SelectLanguagePanel(javax.swing.JPanel):
    """
    A generic reusable panel for selecting a language.
    Also, supports a filter to limit languages that are displayed.
    """

    @typing.type_check_only
    class LanguageModel(docking.widgets.table.AbstractSortedTableModel[ghidra.program.model.lang.LanguageDescription]):

        @typing.type_check_only
        class LanguageDescriptionComparator(java.util.Comparator[ghidra.program.model.lang.LanguageDescription]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, sortColumn: typing.Union[jpype.JInt, int]):
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, service: ghidra.program.model.lang.LanguageService):
        """
        Constructs a new panel.
        
        :param ghidra.program.model.lang.LanguageService service: the language service to use to retrieve the languages
        """

    def dispose(self):
        ...

    def getSelectedLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Returns the selected language, or null if no language is selected.
        
        :return: the selected language, or null if no language is selected.
        :rtype: ghidra.program.model.lang.Language
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def selectHighestPriorityLanguage(self):
        """
        Select the highest priority language being displayed.
        If more than one language has the highest priority, then the first
        one will be used.
        """

    def setFilter(self, filter: typing.Union[java.lang.String, str]) -> int:
        """
        Sets the filter string.
        
        :param java.lang.String or str filter: the string to filter on
        :return: the number of languages that matched the filter
        :rtype: int
        """

    def setLanguageService(self, service: ghidra.program.model.lang.LanguageService):
        ...

    @typing.overload
    def setSelectedLanguage(self, languageID: ghidra.program.model.lang.LanguageID):
        """
        Selects the language with the specified language ID.
        
        :param ghidra.program.model.lang.LanguageID languageID: the ID of language to select
        """

    @typing.overload
    def setSelectedLanguage(self, lang: ghidra.program.model.lang.Language):
        ...

    def setShowVersion(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Allows language versions to appear appended to name
        
        :param jpype.JBoolean or bool enable:
        """

    def update(self):
        """
        Update the panel. Requests a new list of languages from the
        language service and updates the table.
        """

    @property
    def selectedLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @selectedLanguage.setter
    def selectedLanguage(self, value: ghidra.program.model.lang.Language):
        ...


class SetEquateTableModel(docking.widgets.table.GDynamicColumnTableModel[SetEquateDialog.EquateRowObject, ghidra.program.model.listing.Program]):

    @typing.type_check_only
    class NameColumn(docking.widgets.table.AbstractDynamicTableColumn[SetEquateDialog.EquateRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathColumn(docking.widgets.table.AbstractDynamicTableColumn[SetEquateDialog.EquateRowObject, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefsColumn(docking.widgets.table.AbstractDynamicTableColumn[SetEquateDialog.EquateRowObject, java.lang.Integer, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CaseInsensitiveComparator(java.util.Comparator[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, data: java.util.List[SetEquateDialog.EquateRowObject], program: ghidra.program.model.listing.Program):
        ...



__all__ = ["SetEquateDialog", "SelectLanguagePanelListener", "FixedBitSizeValueField", "SelectLanguagePanel", "SetEquateTableModel"]
