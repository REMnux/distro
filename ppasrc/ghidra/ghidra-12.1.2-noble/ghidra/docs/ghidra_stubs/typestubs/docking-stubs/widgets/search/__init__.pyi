from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.table
import ghidra.util.layout
import ghidra.util.table.column
import ghidra.util.task
import ghidra.util.worker
import java.awt # type: ignore
import java.lang # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore


class SearchLocationContext(java.lang.Comparable[SearchLocationContext]):
    """
    A class to hold context representation for :obj:`SearchLocation`s.
    
    
    .. seealso::
    
        | :obj:`SearchLocationContextBuilder`
    """

    @typing.type_check_only
    class Part(java.lang.Object):
        """
        A class that represents one or more characters within the full text of this context class
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BasicPart(SearchLocationContext.Part):
        """
        A basic string part that has no decoration
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatchPart(SearchLocationContext.Part):
        """
        A string part of the overall text of this context that matches client-defined text
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    EMPTY_CONTEXT: typing.Final[SearchLocationContext]

    @staticmethod
    @typing.overload
    def get(text: typing.Union[java.lang.String, str]) -> SearchLocationContext:
        """
        A factory method to create a context instance with the given text.  The context created this
        way will have no special HTML formatting applied by :meth:`getBoldMatchingText() <.getBoldMatchingText>`, as no
        matching parts will be defined.
        
        :param java.lang.String or str text: the text
        :return: the context
        :rtype: SearchLocationContext
        """

    @staticmethod
    @typing.overload
    def get(context: SearchLocationContext) -> SearchLocationContext:
        """
        A factory method to provided as a convenience to handle null context objects.
        
        :param SearchLocationContext context: the context to verify is not null
        :return: the given context or the :obj:`.EMPTY_CONTEXT` if the given context is null
        :rtype: SearchLocationContext
        """

    @typing.overload
    def getBoldMatchingText(self) -> str:
        """
        Returns HTML text for this context.  Any matching items embedded in the returned string will 
        be bold.  Any non-negative line number will be prepended to the text.
        
        :return: the text
        :rtype: str
        """

    @typing.overload
    def getBoldMatchingText(self, includeLineNumber: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns HTML text for this context.  Any matching items embedded in the returned string will 
        be bold.
        
        :param jpype.JBoolean or bool includeLineNumber: if true, any non-negative line number will be prepended to the text.
        :return: the text
        :rtype: str
        """

    def getDebugText(self) -> str:
        """
        Returns text that is helpful for debugging, such as printing to a console.
        
        :return: the text
        :rtype: str
        """

    def getLineNumber(self) -> int:
        """
        Returns the line number or -1 if the value has not been set.
        
        :return: the line number
        :rtype: int
        """

    def getMatches(self) -> java.util.List[java.lang.String]:
        """
        Returns any sub-strings of this context's overall text that match client-defined input
        
        See the :obj:`SearchLocationContextBuilder` for how to define matching text pieces
        
        :return: the matching strings
        :rtype: java.util.List[java.lang.String]
        """

    @typing.overload
    def getPlainText(self) -> str:
        """
        The full plain text of this context. Any non-negative line number will be prepended to the 
        text.
        
        :return: the text
        :rtype: str
        """

    @typing.overload
    def getPlainText(self, includeLineNumber: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns the plain text of this context, without html markup.
        
        :param jpype.JBoolean or bool includeLineNumber: if true, any non-negative line number will be prepended to the text.
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
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def matches(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def debugText(self) -> java.lang.String:
        ...


class SearchLocationContextBuilder(java.lang.Object):
    """
    A builder for :obj:`SearchLocationContext` objects.  Use :meth:`append(String) <.append>` for normal
    text pieces.  Use :meth:`appendMatch(String) <.appendMatch>` for text that is meant to be rendered specially
    by the context class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def append(self, text: typing.Union[java.lang.String, str]) -> SearchLocationContextBuilder:
        """
        Appends the given text to this builder.
        
        :param java.lang.String or str text: the text
        :return: this builder
        :rtype: SearchLocationContextBuilder
        """

    def appendMatch(self, text: typing.Union[java.lang.String, str]) -> SearchLocationContextBuilder:
        """
        Appends the given text to this builder.   This text represents a client-defined 'match' that
        will be rendered with markup when :meth:`SearchLocationContext.getBoldMatchingText() <SearchLocationContext.getBoldMatchingText>` is
        called.
        
        :param java.lang.String or str text: the text
        :return: this builder
        :rtype: SearchLocationContextBuilder
        """

    def build(self) -> SearchLocationContext:
        """
        Builds a :obj:`SearchLocationContext` using the text supplied via the ``append``
        methods.
        
        :return: the context
        :rtype: SearchLocationContext
        """

    def isEmpty(self) -> bool:
        """
        Returns true if no text has been added to this builder.
        
        :return: true if no text has been added to this builder
        :rtype: bool
        """

    def lineNumber(self, line: typing.Union[jpype.JInt, int]) -> SearchLocationContextBuilder:
        """
        Sets an optional line number for clients that use numbered lines.  The line number will be 
        prepended to the text form of the context.
        
        :param jpype.JInt or int line: the line number
        :return: this builder
        :rtype: SearchLocationContextBuilder
        """

    def newline(self) -> SearchLocationContextBuilder:
        """
        Adds a newline character to the previously added text.
        
        :return: this builder
        :rtype: SearchLocationContextBuilder
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class TextComponentSearchLocation(docking.widgets.SearchLocation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SearchLocationContextRenderer(ghidra.util.table.column.AbstractGColumnRenderer[SearchLocationContext]):
    """
    A renderer for :obj:`SearchLocationContext`.  This renderer handles the complexity of rendering
    html text with clipping.
    """

    @typing.type_check_only
    class HtmlTruncatingLayout(ghidra.util.layout.AbstractLayoutManager):
        """
        A layout manager that positions 2 labels: a leading label with html and a trailing label
        with an ellipsis, which may not be visible.  JLabels rendering html will not show an
        ellipsis when clipped.   We use these 2 labels here to show when the leading html label's
        text is clipped.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    def renderHtmlContext(self, data: docking.widgets.table.GTableCellRenderingData, context: SearchLocationContext) -> java.awt.Component:
        ...

    def renderPlainContext(self, data: docking.widgets.table.GTableCellRenderingData, context: SearchLocationContext) -> java.awt.Component:
        ...


class SearchResults(java.lang.Object):
    """
    A collection of :obj:`SearchLocation`s created when the user has performed a find operation on 
    the :obj:`FindDialog`.  The dialog will find all results and then use the results to move to the 
    next and previous locations as requested.  The user may also choose to show all results in a 
    table.  
     
    
    The searcher uses a worker queue to manage activating and deactivating highlights, which may 
    require reload operations on the originally searched text.
    """

    @typing.type_check_only
    class FindJob(ghidra.util.worker.Job):
        """
        A worker :obj:`Job` that allows subclasses to add follow-on jobs to be performed as long
        as the work is not cancelled.
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self) -> None:
            ...

        @typing.overload
        def __init__(self, parent: SearchResults.FindJob) -> None:
            ...

        @typing.overload
        def __init__(self, parent: SearchResults.FindJob, r: ghidra.util.task.MonitoredRunnable) -> None:
            ...

        def thenRun(self, r: ghidra.util.task.MonitoredRunnable) -> SearchResults.FindJob:
            ...

        def thenRunSwing(self, r: java.lang.Runnable) -> SearchResults.FindJob:
            ...

        def thenWait(self, waitFor: java.util.function.BooleanSupplier, maxWaitTime: java.time.Duration) -> SearchResults.FindJob:
            ...


    class ActivationJob(SearchResults.FindJob):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...


    class SwingJob(SearchResults.FindJob):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, r: java.lang.Runnable) -> None:
            ...


    @typing.type_check_only
    class WaitJob(SearchResults.FindJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def activate(self) -> None:
        """
        Activates this set of search results.  This will restore highlights to the source of the 
        search.
        """

    def deactivate(self) -> None:
        """
        Deactivates this set of search results.  This will clear this results' highlights from the 
        source of the search.
        """

    def dispose(self) -> None:
        ...

    def getActiveLocation(self) -> docking.widgets.SearchLocation:
        """
        :return: the active search location or null.  The active location is typically the search
        location that contains the user's cursor.
        :rtype: docking.widgets.SearchLocation
        """

    def getLocations(self) -> java.util.List[docking.widgets.SearchLocation]:
        """
        Returns all search locations in this set of search results
        
        :return: the location
        :rtype: java.util.List[docking.widgets.SearchLocation]
        """

    def getName(self) -> str:
        """
        Returns the name of this set of search results.  This is a short description, such as a 
        filename or function name.  This should be null for text components that do not change 
        contents based on some external source of data, such as a file.
        
        :return: the name or null
        :rtype: str
        """

    def isEmpty(self) -> bool:
        ...

    def setActiveLocation(self, location: docking.widgets.SearchLocation) -> None:
        """
        Sets the active location, which will be highlighted differently than the other search 
        matches.  This method will ensure that this search results object is active (see 
        :meth:`activate() <.activate>`.  This method will also move the cursor to the given location.
        
        :param docking.widgets.SearchLocation location: the location
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def locations(self) -> java.util.List[docking.widgets.SearchLocation]:
        ...

    @property
    def activeLocation(self) -> docking.widgets.SearchLocation:
        ...

    @activeLocation.setter
    def activeLocation(self, value: docking.widgets.SearchLocation):
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class TextComponentSearcher(FindDialogSearcher):
    """
    A class to find text matches in the given :obj:`TextComponent`.  This class will search for all
    matches and cache the results for future requests when the user presses Next or Previous.  All
    matches will be highlighted in the text component.  The match containing the cursor will be a 
    different highlight color than the others.  When the find dialog is closed, all highlights are
    removed.
     
    
    If :meth:`searchAll(String, boolean) <.searchAll>` is called, then the search results will not be cached, as 
    they are when :meth:`search(String, CursorPosition, boolean, boolean) <.search>` is used.  The expectation
    is that clients will cache the search results themselves.
    """

    @typing.type_check_only
    class SearchTask(ghidra.util.task.Task):

        @typing.type_check_only
        class Line(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def lineNumber(self) -> int:
                ...

            def offset(self) -> int:
                ...

            def text(self) -> str:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, editorPane: javax.swing.JEditorPane) -> None:
        ...

    def getEditorPane(self) -> javax.swing.JEditorPane:
        ...

    def hasSearchResults(self) -> bool:
        ...

    def isBusy(self) -> bool:
        ...

    def isStale(self) -> bool:
        ...

    def setEditorPane(self, editorPane: javax.swing.JEditorPane) -> None:
        ...

    @property
    def stale(self) -> jpype.JBoolean:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def editorPane(self) -> javax.swing.JEditorPane:
        ...

    @editorPane.setter
    def editorPane(self, value: javax.swing.JEditorPane):
        ...


class TextComponentSearchResults(SearchResults):

    @typing.type_check_only
    class DocumentChangeListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CaretChangeListener(javax.swing.event.CaretListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchResultsHighlighterWrapper(javax.swing.text.DefaultHighlighter):
        """
        A class that allows us to replace any already installed highlighter.  This also allows us to
        add and remove highlighters, depending upon the active search.
         
        
        Note: any non-search highlighters installed after this wrapper is created may be overwritten
        as the usr interacts with the search.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchResultsHighlightPainter(javax.swing.text.DefaultHighlighter.DefaultHighlightPainter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, c: java.awt.Color) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def activate(self) -> None:
        """
        Triggers the potentially asynchronous activation of this set of search results. When that is
        finished, we then restore our highlights.  This is needed in the case that the implementor
        is using a document that does not match our search results.  Some subclasses use 
        asynchronous loading of their document.
        """


class FindDialogSearcher(java.lang.Object):
    """
    A simple interface for the :obj:`FindDialog` so that it can work for different search clients.
     
    
    The :obj:`CursorPosition` object used by this interface is one that implementations can extend 
    to add extra context to use when searching.  The implementation is responsible for creating the
    locations and these locations will later be handed back to the searcher.
     
    
    The :obj:`FindDialog` should use a single searcher for the life of the dialog.  This allows all
    search results generated by that dialog to share the same worker queue for running background 
    operations related to managing search results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self) -> None:
        """
        Disposes this searcher.
        """

    def getCursorPosition(self) -> docking.widgets.CursorPosition:
        """
        The current cursor position.  Used to search for the next item.
        
        :return: the cursor position.
        :rtype: docking.widgets.CursorPosition
        """

    def getEnd(self) -> docking.widgets.CursorPosition:
        """
        The end cursor position.  This is used when a search is wrapped while searching backwards to 
        start at the end position.
        
        :return: the end position.
        :rtype: docking.widgets.CursorPosition
        """

    def getStart(self) -> docking.widgets.CursorPosition:
        """
        Returns the start cursor position.  This is used when a search is wrapped to start at the 
        beginning of the search range.
        
        :return: the start position.
        :rtype: docking.widgets.CursorPosition
        """

    def search(self, text: typing.Union[java.lang.String, str], cursorPosition: docking.widgets.CursorPosition, searchForward: typing.Union[jpype.JBoolean, bool], useRegex: typing.Union[jpype.JBoolean, bool]) -> SearchResults:
        """
        Perform a search for the next item in the given direction starting at the given cursor 
        position.
        
        :param java.lang.String or str text: the search text.
        :param docking.widgets.CursorPosition cursorPosition: the current cursor position.
        :param jpype.JBoolean or bool searchForward: true if searching forward.
        :param jpype.JBoolean or bool useRegex: true if the search text is a regular expression; false if the text is literal.
        :return: the search result or null if no match was found.
        :rtype: SearchResults
        """

    def searchAll(self, text: typing.Union[java.lang.String, str], useRegex: typing.Union[jpype.JBoolean, bool]) -> SearchResults:
        """
        Search for all matches.
        
        :param java.lang.String or str text: the search text.
        :param jpype.JBoolean or bool useRegex: true if the search text is a regular expression; false if the text is literal.
        :return: all search results or an empty list.
        :rtype: SearchResults
        """

    @property
    def cursorPosition(self) -> docking.widgets.CursorPosition:
        ...

    @property
    def start(self) -> docking.widgets.CursorPosition:
        ...

    @property
    def end(self) -> docking.widgets.CursorPosition:
        ...



__all__ = ["SearchLocationContext", "SearchLocationContextBuilder", "TextComponentSearchLocation", "SearchLocationContextRenderer", "SearchResults", "TextComponentSearcher", "TextComponentSearchResults", "FindDialogSearcher"]
