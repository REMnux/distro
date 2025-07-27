from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets
import docking.widgets.label
import docking.widgets.list
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util.regex # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import org.jdom # type: ignore
import utility.function


class AbstractPatternTextFilter(TextFilter):

    class_: typing.ClassVar[java.lang.Class]

    def matches(self, text: typing.Union[java.lang.String, str], pattern: java.util.regex.Pattern) -> bool:
        """
        Subclasses implement this method for their usage of the given pattern (find vs. matches)
        
        :param java.lang.String or str text: the text to check against the pattern
        :param java.util.regex.Pattern pattern: the pattern used to match the text
        :return: true if there is a match
        :rtype: bool
        """


class StartsWithTextFilter(MatchesPatternTextFilter):
    """
    A filter that will pass text when it starts with the filter text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterText: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class AbstractRegexBasedTermSplitter(TermSplitter):
    """
    Allows the user to split a string using a regex as the delimiter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delimiter: typing.Union[java.lang.String, str]):
        ...


class TextFilterStrategy(java.lang.Enum[TextFilterStrategy]):

    class_: typing.ClassVar[java.lang.Class]
    CONTAINS: typing.Final[TextFilterStrategy]
    STARTS_WITH: typing.Final[TextFilterStrategy]
    MATCHES_EXACTLY: typing.Final[TextFilterStrategy]
    REGULAR_EXPRESSION: typing.Final[TextFilterStrategy]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> TextFilterStrategy:
        ...

    @staticmethod
    def values() -> jpype.JArray[TextFilterStrategy]:
        ...


class MatchesExactlyTextFilterFactory(TextFilterFactory):
    """
    A filter factory that creates :obj:`TextFilter`s that will pass text when it matches
    the filter exactly.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class StartsWithTextFilterFactory(TextFilterFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobing: typing.Union[jpype.JBoolean, bool]):
        ...


class MatchesPatternTextFilter(AbstractPatternTextFilter):
    """
    A text filter that uses a pattern and performs a 'matches' using that pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterText: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class ClearFilterLabel(docking.widgets.label.GIconLabel):
    """
    A label that displays an icon that, when clicked, will clear the contents of the 
    associated filter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, textField: javax.swing.JTextField):
        ...

    def hideFilterButton(self):
        ...

    def setTransparency(self, transparency: typing.Union[jpype.JFloat, float]):
        ...

    def showFilterButton(self):
        ...


class CharacterTermSplitter(AbstractRegexBasedTermSplitter):
    """
    Provides the ability to split a string using a single character as the 
    delimiter, interpreted as a regex.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delimiter: typing.Union[jpype.JChar, int, str]):
        ...


class RegularExpressionTextFilterFactory(TextFilterFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FilterOptions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    VALID_MULTITERM_DELIMITERS: typing.Final[java.lang.String]
    VALID_MULTITERM_DELIMITERS_ARRAY: typing.Final[jpype.JArray[java.lang.String]]
    DEFAULT_DELIMITER: typing.Final[java.lang.Character]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, textFilterStrategy: TextFilterStrategy, allowGlobbing: typing.Union[jpype.JBoolean, bool], caseSensitive: typing.Union[jpype.JBoolean, bool], inverted: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, textFilterStrategy: TextFilterStrategy, allowGlobbing: typing.Union[jpype.JBoolean, bool], caseSensitive: typing.Union[jpype.JBoolean, bool], inverted: typing.Union[jpype.JBoolean, bool], multiTerm: typing.Union[jpype.JBoolean, bool], delimiterCharacter: typing.Union[jpype.JChar, int, str]):
        ...

    @typing.overload
    def __init__(self, textFilterStrategy: TextFilterStrategy, allowGlobbing: typing.Union[jpype.JBoolean, bool], caseSensitive: typing.Union[jpype.JBoolean, bool], inverted: typing.Union[jpype.JBoolean, bool], usePath: typing.Union[jpype.JBoolean, bool], multiTerm: typing.Union[jpype.JBoolean, bool], delimiterCharacter: typing.Union[jpype.JChar, int, str], mode: MultitermEvaluationMode):
        ...

    def getDelimitingCharacter(self) -> str:
        ...

    def getFilterDescription(self) -> str:
        ...

    def getFilterStateIcon(self) -> javax.swing.Icon:
        ...

    @staticmethod
    def getIcon(filterStrategy: TextFilterStrategy) -> javax.swing.Icon:
        ...

    def getMultitermEvaluationMode(self) -> MultitermEvaluationMode:
        ...

    def getTermSplitter(self) -> TermSplitter:
        ...

    def getTextFilterFactory(self) -> TextFilterFactory:
        ...

    def getTextFilterStrategy(self) -> TextFilterStrategy:
        ...

    def isCaseSensitive(self) -> bool:
        ...

    def isGlobbingAllowed(self) -> bool:
        ...

    def isInverted(self) -> bool:
        ...

    def isMultiterm(self) -> bool:
        ...

    @staticmethod
    def restoreFromXML(element: org.jdom.Element) -> FilterOptions:
        ...

    def shouldUsePath(self) -> bool:
        ...

    def toXML(self) -> org.jdom.Element:
        ...

    @property
    def multitermEvaluationMode(self) -> MultitermEvaluationMode:
        ...

    @property
    def filterStateIcon(self) -> javax.swing.Icon:
        ...

    @property
    def textFilterStrategy(self) -> TextFilterStrategy:
        ...

    @property
    def termSplitter(self) -> TermSplitter:
        ...

    @property
    def caseSensitive(self) -> jpype.JBoolean:
        ...

    @property
    def multiterm(self) -> jpype.JBoolean:
        ...

    @property
    def delimitingCharacter(self) -> jpype.JChar:
        ...

    @property
    def filterDescription(self) -> java.lang.String:
        ...

    @property
    def inverted(self) -> jpype.JBoolean:
        ...

    @property
    def globbingAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def textFilterFactory(self) -> TextFilterFactory:
        ...


class TextFilterFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getTextFilter(self, text: typing.Union[java.lang.String, str]) -> TextFilter:
        """
        The factory's method for creating a text filter.
        
        :param java.lang.String or str text: the text used to create the filter
        :return: the filter
        :rtype: TextFilter
        """

    @property
    def textFilter(self) -> TextFilter:
        ...


class TextFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFilterText(self) -> str:
        ...

    def isSubFilterOf(self, filter: TextFilter) -> bool:
        """
        Returns true if this filter is a more specific filter of the given filter.  This is 
        specific to the implementation.   Some filters cannot be sub-filters of another filter, 
        such as the 'matches exactly' filter.  Contrastingly, a 'starts with' filter can have
        a sub-filter; for example, for a 'starts with' filter, 'cat' is a sub-filter of 'ca', as
        'cat' starts with 'ca'.
        
        :param TextFilter filter: the potential parent filter
        :return: true if this filter is a more specific filter of the given filter.
        :rtype: bool
        """

    def matches(self, text: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def subFilterOf(self) -> jpype.JBoolean:
        ...

    @property
    def filterText(self) -> java.lang.String:
        ...


class ContainsTextFilterFactory(TextFilterFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class TermSplitter(java.lang.Object):
    """
    Interface for classes that need to split strings into a series of individual terms.
    """

    class_: typing.ClassVar[java.lang.Class]

    def split(self, input: typing.Union[java.lang.String, str]) -> jpype.JArray[java.lang.String]:
        """
        Returns a given string an array of terms.
        
        :param java.lang.String or str input: the string to split
        :return: array of terms
        :rtype: jpype.JArray[java.lang.String]
        """


class ContainsTextFilter(MatchesPatternTextFilter):
    """
    A filter that will pass text when it contains the filter text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterText: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class FilterListener(java.lang.Object):
    """
    An interface that will be called when the text filter changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def filterChanged(self, text: typing.Union[java.lang.String, str]):
        ...


class MultitermEvaluationMode(java.lang.Enum[MultitermEvaluationMode]):

    class_: typing.ClassVar[java.lang.Class]
    AND: typing.Final[MultitermEvaluationMode]
    OR: typing.Final[MultitermEvaluationMode]

    def getDescription(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MultitermEvaluationMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[MultitermEvaluationMode]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class FilterOptionsEditorDialog(docking.DialogComponentProvider):
    """
    Dialog that allows the user to select options related to table filtering. It consists
    of the following sections:
     
            Filter Strategy:         Allows the user to define how filter terms are applied to strings. 
            Filter Options:            Various generic filter settings.
            Multi-Term Filtering:    Options defining how to interpret filter text when multiple terms
                                    are entered.
    """

    @typing.type_check_only
    class FilterStrategyPanel(javax.swing.JPanel):
        """
        Contains widgets for specifying how to interpret filter terms. Possible selections are:
                - Contains
                - Starts With
                - Matches Exactly
                - Regular Expression
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getFilterStrategy(self) -> TextFilterStrategy:
            ...

        def setFilterStrategy(self, filterStrategy: TextFilterStrategy):
            ...

        @property
        def filterStrategy(self) -> TextFilterStrategy:
            ...

        @filterStrategy.setter
        def filterStrategy(self, value: TextFilterStrategy):
            ...


    @typing.type_check_only
    class BooleanPanel(javax.swing.JPanel):
        """
        Contains widgets for controlling various filtering attributes. The following options are
        provided: 
                - Case Sensitive
                - Allow Globbing
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def isCaseSensitive(self) -> bool:
            ...

        def isGlobbing(self) -> bool:
            ...

        def setCaseSensitive(self, val: typing.Union[jpype.JBoolean, bool]):
            ...

        def setCaseSensitiveCBEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
            ...

        def setGlobbing(self, val: typing.Union[jpype.JBoolean, bool]):
            ...

        def setGlobbingCBEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
            ...

        @property
        def caseSensitive(self) -> jpype.JBoolean:
            ...

        @caseSensitive.setter
        def caseSensitive(self, value: jpype.JBoolean):
            ...

        @property
        def globbing(self) -> jpype.JBoolean:
            ...

        @globbing.setter
        def globbing(self, value: jpype.JBoolean):
            ...


    @typing.type_check_only
    class InvertPanel(javax.swing.JPanel):
        """
        Contains widgets for setting whether the filter should be inverted.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def isInverted(self) -> bool:
            ...

        @property
        def inverted(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class PathPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def shouldUsePath(self) -> bool:
            ...


    @typing.type_check_only
    class MultiTermPanel(docking.widgets.InlineComponentTitledPanel):
        """
        Contains widgets for configuring multi-term filtering. This has two main
        sections for setting the delimiter and setting the mode. The former allows the user to 
        select a delimiter from a predefined set of characters. The latter allows them to 
        define how multiple terms are logically applied; eg: 'AND' means that all filter terms
        must be matched, 'OR' means any single term must match.
        """

        @typing.type_check_only
        class DelimiterListCellRenderer(docking.widgets.list.GComboBoxCellRenderer[java.lang.String]):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getDelimiter(self) -> str:
            ...

        def getEvalMode(self) -> MultitermEvaluationMode:
            ...

        def isMultitermEnabled(self) -> bool:
            ...

        def setDelimiter(self, delimiter: typing.Union[jpype.JChar, int, str]):
            """
            Sets the character to use for the delimiter. If the character is not found in 
            the set of acceptable delimiters, the delimiter is not changed.
            
            :param jpype.JChar or int or str delimiter: the character to use as the delimiter
            """

        def setEvalMode(self, evalMode: MultitermEvaluationMode):
            """
            Sets the evaluation mode to what is given. This is done by activating the
            appropriate radio button associated with that mode.
            
            :param MultitermEvaluationMode evalMode: the mode
            """

        def setMultitermEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
            ...

        def setOptionsEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
            ...

        @property
        def multitermEnabled(self) -> jpype.JBoolean:
            ...

        @multitermEnabled.setter
        def multitermEnabled(self, value: jpype.JBoolean):
            ...

        @property
        def delimiter(self) -> jpype.JChar:
            ...

        @delimiter.setter
        def delimiter(self, value: jpype.JChar):
            ...

        @property
        def evalMode(self) -> MultitermEvaluationMode:
            ...

        @evalMode.setter
        def evalMode(self, value: MultitermEvaluationMode):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterOptions: FilterOptions):
        ...

    def getResultFilterOptions(self) -> FilterOptions:
        ...

    @property
    def resultFilterOptions(self) -> FilterOptions:
        ...


class FilterTextField(javax.swing.JPanel):
    """
    A text field that is meant to be used in conjunction with tables that allow filter text.  This
    text field will change its background color when it contains text.  Additionally, this text
    field will flash its background color when the associated component gains focus.  This is done
    to remind the user that there is a filter applied.
    """

    @typing.type_check_only
    class TraversalKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FlashFocusListener(java.awt.event.FocusAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FilterDocumentListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BackgroundFlashTimer(javax.swing.Timer, java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, component: java.awt.Component):
        """
        Constructs this text field with the given component.  ``component`` may be null, but
        then this field will be unable to flash in response to focus events (see the header
        documentation).
        
        :param java.awt.Component component: The component needed to listen for focus changes, may be null.
        """

    @typing.overload
    def __init__(self, component: java.awt.Component, columns: typing.Union[jpype.JInt, int]):
        """
        Constructs this text field with the given component and the preferred visible column
        width.  ``component`` may be null, but then this field will be able to flash in
        response to focus events (see the header documentation).
        
        :param java.awt.Component component: The component needed to listen for focus changes, may be null.
        :param jpype.JInt or int columns: The number of preferred visible columns (see JTextField)
        """

    def addEnterListener(self, callback: utility.function.Callback):
        """
        Adds the listener to this filter field that will be called when the user presses the
        enter key.
        
         
        Note: this listener cannot be anonymous, as the underlying storage mechanism may be
        using a weak data structure.  This means that you will need to store the listener in
        a field inside of your class.
        
        :param utility.function.Callback callback: the listener
        """

    def addFilterListener(self, l: FilterListener):
        """
        Adds the filter listener to this filter field that will be called when the filter
        contents change.
        
         
        Note: this listener cannot be anonymous, as the underlying storage mechanism may be
        using a weak data structure.  This means that you will need to store the listener in
        a field inside of your class.
        
        :param FilterListener l: the listener
        """

    @typing.overload
    def alert(self):
        """
        This method will signal to the users if a filter is currently applied (has text).  For
        example, the default implementation will 'flash' the filter by changing its background
        color multiple times.
         
        
        Note: this method will not perform the alert if the minimum time between alerts
        has not passed.  To force the alter to take place, call :meth:`alert(boolean) <.alert>` with a
        value of ``true``.
        """

    @typing.overload
    def alert(self, forceAlert: typing.Union[jpype.JBoolean, bool]):
        """
        This is the same as :meth:`alert() <.alert>` with the exception that a ``true`` value for
        ``forceAlter`` will guarantee that the alert will happen.  A ``false`` value
        will not perform the alert if the minimum time between alerts has not passed.
        
        :param jpype.JBoolean or bool forceAlert: true signals to force the alter to take place.
        
        .. seealso::
        
            | :obj:`.alert()`
        """

    def getAccessibleNamePrefix(self) -> str:
        """
        Returns the accessible name prefix set by a previous call to 
        :meth:`setAccessibleNamePrefix(String) <.setAccessibleNamePrefix>`.  This will be null if not set.
        
        :return: the prefix
        :rtype: str
        """

    def getText(self) -> str:
        ...

    def isEditable(self) -> bool:
        ...

    def removeEnterListener(self, callback: utility.function.Callback):
        ...

    def removeFilterListener(self, l: FilterListener):
        ...

    def setAccessibleNamePrefix(self, prefix: typing.Union[java.lang.String, str]):
        """
        Sets the accessible name prefix for the focusable components in the filter panel.
        
        :param java.lang.String or str prefix: the base name for these components. A suffix will be added to further
        describe the sub component.
        """

    def setEditable(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setFocusComponent(self, component: java.awt.Component):
        ...

    def setText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def accessibleNamePrefix(self) -> java.lang.String:
        ...

    @accessibleNamePrefix.setter
    def accessibleNamePrefix(self, value: java.lang.String):
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @editable.setter
    def editable(self, value: jpype.JBoolean):
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...


class MatchesExactlyTextFilter(MatchesPatternTextFilter):
    """
    A filter that will pass text when it matches exactly.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterText: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool], allowGlobbing: typing.Union[jpype.JBoolean, bool]):
        ...


class InvertedTextFilter(TextFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filter: TextFilter):
        ...


class FindsPatternTextFilter(AbstractPatternTextFilter):
    """
    A text filter that uses a pattern and performs a 'find' using that pattern.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, filterText: typing.Union[java.lang.String, str]):
        ...



__all__ = ["AbstractPatternTextFilter", "StartsWithTextFilter", "AbstractRegexBasedTermSplitter", "TextFilterStrategy", "MatchesExactlyTextFilterFactory", "StartsWithTextFilterFactory", "MatchesPatternTextFilter", "ClearFilterLabel", "CharacterTermSplitter", "RegularExpressionTextFilterFactory", "FilterOptions", "TextFilterFactory", "TextFilter", "ContainsTextFilterFactory", "TermSplitter", "ContainsTextFilter", "FilterListener", "MultitermEvaluationMode", "FilterOptionsEditorDialog", "FilterTextField", "MatchesExactlyTextFilter", "InvertedTextFilter", "FindsPatternTextFilter"]
