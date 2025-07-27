from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class ProgramPlugin(ghidra.framework.plugintool.Plugin):
    """
    Base class to handle common program events: Program Open/Close, Program Activated,
    Program Location, Program Selection, and Program Highlight.   This class has fields related to
    these events: ``currentProgram``, ``currentLocation``, ``currentSelection`` and
    ``currentHighlight``.
     
    
    Subclasses should override the following methods if they are interested in the corresponding
    events:
     
    * :meth:`programOpened(Program) <.programOpened>`
    * :meth:`programClosed(Program) <.programClosed>`
    * :meth:`locationChanged(ProgramLocation) <.locationChanged>`
    * :meth:`selectionChanged(ProgramSelection) <.selectionChanged>`
    * :meth:`highlightChanged(ProgramSelection) <.highlightChanged>`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        """
        Constructs a new program plugin
        
        :param ghidra.framework.plugintool.PluginTool plugintool: tool        the parent tool for this plugin
        """

    @typing.overload
    @deprecated("call ProgramPlugin(PluginTool) instead")
    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool, consumeLocationChange: typing.Union[jpype.JBoolean, bool], consumeSelectionChange: typing.Union[jpype.JBoolean, bool]):
        """
        Calling this constructor is works the same as calling :obj:`ProgramPlugin`.
        
        
        .. deprecated::
        
        call :meth:`ProgramPlugin(PluginTool) <.ProgramPlugin>` instead
        :param ghidra.framework.plugintool.PluginTool plugintool: the tool
        :param jpype.JBoolean or bool consumeLocationChange: not used
        :param jpype.JBoolean or bool consumeSelectionChange: not used
        """

    @typing.overload
    @deprecated("call ProgramPlugin(PluginTool) instead")
    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool, consumeLocationChange: typing.Union[jpype.JBoolean, bool], consumeSelectionChange: typing.Union[jpype.JBoolean, bool], consumeHighlightChange: typing.Union[jpype.JBoolean, bool]):
        """
        Calling this constructor is works the same as calling :obj:`ProgramPlugin`.
        
        
        .. deprecated::
        
        call :meth:`ProgramPlugin(PluginTool) <.ProgramPlugin>` instead
        :param ghidra.framework.plugintool.PluginTool plugintool: the tool
        :param jpype.JBoolean or bool consumeLocationChange: not used
        :param jpype.JBoolean or bool consumeSelectionChange: not used
        :param jpype.JBoolean or bool consumeHighlightChange: not used
        """

    def getCurrentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgramHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getProgramSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    def processEvent(self, event: ghidra.framework.plugintool.PluginEvent):
        """
        Process the plugin event.
         
        
        When a program closed event or focus changed event comes in, the locationChanged() and
        selectionChanged() methods are called with null arguments; currentProgram and
        currentLocation are cleared.
         
        
        Note: if the subclass overrides processEvent(), it should call super.processEvent().
        """

    @property
    def currentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def programSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def programHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class PluginCategoryNames(java.lang.Object):
    """
    A listing of commonly used :obj:`PluginDescription` category names.
     
    
    Note - the Front End tool automatically include plugins that: 1) implement 
    :obj:`ApplicationLevelPlugin`, have the :obj:`PluginStatus.RELEASED`, and do not have the 
    :obj:`.EXAMPLES` category.  If you wish to create an :obj:`ApplicationLevelPlugin` that is not
    automatically included in the Front End, the easiest way to do that is to mark its status as
    :obj:`PluginStatus.STABLE`.
    """

    class_: typing.ClassVar[java.lang.Class]
    ANALYSIS: typing.Final = "Analysis"
    COMMON: typing.Final = "Common"
    CODE_VIEWER: typing.Final = "Code Viewer"
    DEBUGGER: typing.Final = "Debugger"
    DIAGNOSTIC: typing.Final = "Diagnostic"
    EXAMPLES: typing.Final = "Examples"
    FRAMEWORK: typing.Final = "Framework"
    GRAPH: typing.Final = "Graph"
    NAVIGATION: typing.Final = "Navigation"
    SEARCH: typing.Final = "Search"
    SELECTION: typing.Final = "Selection"
    PROGRAM_ORGANIZATION: typing.Final = "Program Organization"


class GenericPluginCategoryNames(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    COMMON: typing.Final = "Common"
    SUPPORT: typing.Final = "Support"
    TESTING: typing.Final = "Testing"
    MISC: typing.Final = "Miscellaneous"
    EXAMPLES: typing.Final = "Examples"

    def __init__(self):
        ...



__all__ = ["ProgramPlugin", "PluginCategoryNames", "GenericPluginCategoryNames"]
