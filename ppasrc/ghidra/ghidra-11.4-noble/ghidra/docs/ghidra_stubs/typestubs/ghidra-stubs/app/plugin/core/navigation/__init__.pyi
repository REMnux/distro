from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.menu
import docking.options
import ghidra.app.context
import ghidra.app.nav
import ghidra.app.plugin
import ghidra.app.services
import ghidra.app.util.viewer.field
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


class NextPrevCodeUnitPlugin(ghidra.framework.plugintool.Plugin):
    """
    The NextPrevCodeUnitPlugin generates a GoTo event based on where the cursor
    is located in the program. The GoTo events provided by this plugin are:
     
    * Next-Previous Instruction
    * Next-Previous Defined Data
    * Next-Previous Undefined Data
    * Next-Previous Function
    * Next-Previous Non-Function
    * Next-Previous Label
    * Next-Previous Bookmark
    """

    @typing.type_check_only
    class InvertStateAction(docking.action.ToggleDockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, subGroup: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ToggleDirectionAction(ghidra.app.context.NavigatableContextAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class NextPreviousFunctionAction(AbstractNextPreviousAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class NextPreviousBookmarkAction(docking.menu.MultiStateDockingAction[java.lang.String]):

    class_: typing.ClassVar[java.lang.Class]
    ALL_BOOKMARK_TYPES: typing.Final = "All Bookmark Types"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...

    def setDirection(self, isForward: typing.Union[jpype.JBoolean, bool]):
        ...

    def setInverted(self, isInverted: typing.Union[jpype.JBoolean, bool]):
        ...


class GoToAddressLabelPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.options.OptionsChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pluginTool: ghidra.framework.plugintool.PluginTool):
        ...

    def getMaximumGotoEntries(self) -> int:
        ...

    @property
    def maximumGotoEntries(self) -> jpype.JInt:
        ...


class NavigationHistoryPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.NavigationHistoryService, ghidra.app.nav.NavigatableRemovalListener, ghidra.framework.options.OptionsChangeListener):
    """
    ``NavigationHistoryPlugin`` is used in conjunction with other plugins to cause program
    viewer plugins to change their focus to a certain address. As viewer plugins are directed to one
    or more addresses it maintains information about where the viewers have been to support ability
    for the viewers to go back to a previous "focus" point.
    
    Services Provided: NavigationHistoryService Events Consumed: ProgramLocationPluginEvent,
    ProgramPluginEvent Event Produced: HistoryChangePluginEvent Actions: None.
    """

    @typing.type_check_only
    class HistoryList(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def writeDataState(self, saveState: ghidra.framework.options.SaveState, navigatable: ghidra.app.nav.Navigatable, historyList: NavigationHistoryPlugin.HistoryList):
        ...


class NextPrevHighlightRangePlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to go to the next or previous highlighted range in the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class FindAppliedDataTypesService(java.lang.Object):
    """
    A simple service to trigger a search for applied datatypes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def findAndDisplayAppliedDataTypeAddresses(self, dataType: ghidra.program.model.data.DataType):
        """
        Tells this service to find all places where the given datatype is applied **and** will
        display the results of the search.
        
        :param ghidra.program.model.data.DataType dataType: The datatype which to base the search upon.
        """

    @typing.overload
    def findAndDisplayAppliedDataTypeAddresses(self, dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str]):
        """
        Tells this service to find all places where the given datatype is applied **and** will
        display the results of the search.
        
        :param ghidra.program.model.data.DataType dataType: The datatype which to base the search upon.
        :param java.lang.String or str fieldName: the sub-field for which to search
        """

    @typing.overload
    def findAndDisplayAppliedDataTypeAddresses(self, dataType: ghidra.program.model.data.DataType, fieldMatcher: ghidra.app.services.FieldMatcher):
        """
        Tells this service to find all places where the given datatype is applied **and** will
        display the results of the search.
         
        
        The supplied field matcher will be used to restrict matches to the given field.  The matcher
        may be 'empty', supplying only the data type for which to search.  In this case, all uses
        of the type will be matched, regardless of field.
        
        :param ghidra.program.model.data.DataType dataType: The datatype which to base the search upon.
        :param ghidra.app.services.FieldMatcher fieldMatcher: the field matcher.
        """


class NextPreviousLabelAction(AbstractNextPreviousAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class FunctionUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getCallingConventionSignatureOffset(function: ghidra.program.model.listing.Function) -> int:
        ...

    @staticmethod
    def getFunctionNameStringInfo(function: ghidra.program.model.listing.Function, functionSignatureString: typing.Union[java.lang.String, str]) -> ghidra.app.util.viewer.field.FieldStringInfo:
        """
        Returns a FieldStringInfo object for the given function's name.  This info contains
        the name string and its location in the function signature.
        
        :param ghidra.program.model.listing.Function function: The function from which to get the name.
        :param java.lang.String or str functionSignatureString: The function signature string from which to get the name
        string.
        :return: Returns a FieldStringInfo object for the given function's name.
        :rtype: ghidra.app.util.viewer.field.FieldStringInfo
        """

    @staticmethod
    def getFunctionParameterStringInfos(function: ghidra.program.model.listing.Function, functionSignatureString: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.app.util.viewer.field.FieldStringInfo]:
        """
        Returns a FieldStringInfo object for the given function's parameters.  This info contains
        the parameter string and their respective locations in the function signature.  Each
        returned FieldStringInfo object will contain a single string retrievable from 
        :meth:`FieldStringInfo.getFieldString() <FieldStringInfo.getFieldString>` that is a space-separated combination of the 
        parameter's datatype and name.
        
        :param ghidra.program.model.listing.Function function: The function from which to get the function parameter strings.
        :param java.lang.String or str functionSignatureString: The function signature string from which to get the 
        parameter strings.
        :return: Returns a FieldStringInfo object for the given function's parameter strings.
        :rtype: jpype.JArray[ghidra.app.util.viewer.field.FieldStringInfo]
        """

    @staticmethod
    def getFunctionReturnTypeStringInfo(function: ghidra.program.model.listing.Function, functionSignatureString: typing.Union[java.lang.String, str]) -> ghidra.app.util.viewer.field.FieldStringInfo:
        """
        Returns a FieldStringInfo object for the given function's return type.  This info contains
        the return type string and its location in the function signature.
        
        :param ghidra.program.model.listing.Function function: The function from which to get the return type.
        :param java.lang.String or str functionSignatureString: The function signature string from which to get the return
        type string.
        :return: Returns a FieldStringInfo object for the given function's return type.
        :rtype: ghidra.app.util.viewer.field.FieldStringInfo
        """


class ProviderNavigationPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class NextPreviousInstructionAction(AbstractNextPreviousAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class NextHighlightedRangeAction(ghidra.app.nav.NextRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], navOptions: NavigationOptions):
        ...


class NextPreviousUndefinedAction(AbstractNextPreviousAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class NextPreviousSameBytesAction(AbstractNextPreviousAction):
    """
    Navigates to the same byte pattern value under the current code unit.  When negated, the search
    will only consider a single byte, as it seems more useful to be able to skip runs of a 
    particular byte.
    """

    class_: typing.ClassVar[java.lang.Class]


class AbstractNextPreviousAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class ProgramStartingLocationPlugin(ghidra.app.plugin.ProgramPlugin):

    class NonActiveProgramState(java.lang.Enum[ProgramStartingLocationPlugin.NonActiveProgramState]):

        class_: typing.ClassVar[java.lang.Class]
        NEWLY_OPENED: typing.Final[ProgramStartingLocationPlugin.NonActiveProgramState]
        RESTORED: typing.Final[ProgramStartingLocationPlugin.NonActiveProgramState]
        FIRST_ANALYSIS_COMPLETED: typing.Final[ProgramStartingLocationPlugin.NonActiveProgramState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramStartingLocationPlugin.NonActiveProgramState:
            ...

        @staticmethod
        def values() -> jpype.JArray[ProgramStartingLocationPlugin.NonActiveProgramState]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class PreviousSelectedRangeAction(ghidra.app.nav.PreviousRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, ownerName: typing.Union[java.lang.String, str], navOptions: NavigationOptions):
        ...


class NextPrevSelectedRangePlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to go to the next or previous selected range in the program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class NextPreviousDefinedDataAction(AbstractNextPreviousAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]):
        ...


class NextSelectedRangeAction(ghidra.app.nav.NextRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, ownerName: typing.Union[java.lang.String, str], navOptions: NavigationOptions):
        ...


class NavigationOptions(ghidra.framework.options.OptionsChangeListener):

    class RangeNavigationEnum(java.lang.Enum[NavigationOptions.RangeNavigationEnum]):

        class_: typing.ClassVar[java.lang.Class]
        TopOfRangeOnly: typing.Final[NavigationOptions.RangeNavigationEnum]
        TopAndBottomOfRange: typing.Final[NavigationOptions.RangeNavigationEnum]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> NavigationOptions.RangeNavigationEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[NavigationOptions.RangeNavigationEnum]:
            ...


    class ExternalNavigationEnum(java.lang.Enum[NavigationOptions.ExternalNavigationEnum]):

        class_: typing.ClassVar[java.lang.Class]
        NavigateToLinkage: typing.Final[NavigationOptions.ExternalNavigationEnum]
        NavigateToExternalProgram: typing.Final[NavigationOptions.ExternalNavigationEnum]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> NavigationOptions.ExternalNavigationEnum:
            ...

        @staticmethod
        def values() -> jpype.JArray[NavigationOptions.ExternalNavigationEnum]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def __init__(self, optionsService: docking.options.OptionsService):
        ...

    def dispose(self):
        ...

    def isFollowIndirectionEnabled(self) -> bool:
        ...

    def isGoToRestrictedToCurrentProgram(self) -> bool:
        ...

    def isGotoExternalProgramEnabled(self) -> bool:
        ...

    def isGotoTopAndBottomOfRangeEnabled(self) -> bool:
        ...

    def preferCurrentAddressSpace(self) -> bool:
        ...

    @property
    def gotoExternalProgramEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def gotoTopAndBottomOfRangeEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def goToRestrictedToCurrentProgram(self) -> jpype.JBoolean:
        ...

    @property
    def followIndirectionEnabled(self) -> jpype.JBoolean:
        ...


class NextPrevAddressPlugin(ghidra.framework.plugintool.Plugin):
    """
    ``NextPrevAddressPlugin`` allows the user to go back and forth in
    the history list and to clear it
    """

    @typing.type_check_only
    class NextPreviousAction(docking.menu.MultiActionDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NavigationAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NextPreviousFunctionAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new instance of the plugin
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """


class PreviousHighlightedRangeAction(ghidra.app.nav.PreviousRangeAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], navOptions: NavigationOptions):
        ...


class ProgramStartingLocationOptions(ghidra.framework.options.OptionsChangeListener):
    """
    Class for managing the options associated with the :obj:`ProgramStartingLocationPlugin`
    """

    class StartLocationType(java.lang.Enum[ProgramStartingLocationOptions.StartLocationType]):

        class_: typing.ClassVar[java.lang.Class]
        LOWEST_ADDRESS: typing.Final[ProgramStartingLocationOptions.StartLocationType]
        LOWEST_CODE_BLOCK: typing.Final[ProgramStartingLocationOptions.StartLocationType]
        SYMBOL_NAME: typing.Final[ProgramStartingLocationOptions.StartLocationType]
        LAST_LOCATION: typing.Final[ProgramStartingLocationOptions.StartLocationType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramStartingLocationOptions.StartLocationType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ProgramStartingLocationOptions.StartLocationType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    START_LOCATION_SUB_OPTION: typing.Final = "Starting Program Location"
    START_LOCATION_TYPE_OPTION: typing.Final = "Starting Program Location.Start At: "
    START_SYMBOLS_OPTION: typing.Final = "Starting Program Location.Start Symbols: "
    UNDERSCORE_OPTION: typing.Final = "Starting Program Location.Use Underscores:"
    AFTER_ANALYSIS_SUB_OPTION: typing.Final = "After Initial Analysis"
    ASK_TO_MOVE_OPTION: typing.Final = "After Initial Analysis.Ask To Reposition Program"
    AUTO_MOVE_OPTION: typing.Final = "After Initial Analysis.Auto Reposition If Not Moved"
    ASK_TO_MOVE_DESCRIPTION: typing.Final = "When initial analysis completed, asks the user if they want to reposition the program to a newly discovered starting symbol."
    AUTO_MOVE_DESCRIPTION: typing.Final = "When initial analysis is completed, automatically repositions the program to a newly discovered starting symbol, provided the user hasn\'t manually moved."

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        """
        Removes the options listener
        """

    def getStartLocationType(self) -> ProgramStartingLocationOptions.StartLocationType:
        """
        Returns the StartLocationType (lowest address, lowest code address, staring symbol, or
        last location)
        
        :return: the StartLocationType
        :rtype: ProgramStartingLocationOptions.StartLocationType
        """

    def getStartingSymbolNames(self) -> java.util.List[java.lang.String]:
        """
        Returns a list of possible starting symbol names. The symbols are returned in order 
        of preference.
        
        :return: a list of starting symbols.
        :rtype: java.util.List[java.lang.String]
        """

    def shouldAskToRepostionAfterAnalysis(self) -> bool:
        """
        Returns true if the user should be asked after first analysis if they would like the
        program to be repositioned to a newly discovered starting symbol (e.g. "main")
        
        :return: true if the user should be asked after first analysis if they would like the
        program to be repositioned to a newly discovered starting symbol (e.g. "main")
        :rtype: bool
        """

    def shouldAutoRepositionIfNotMoved(self) -> bool:
        """
        Returns true if the program should be repositioned to a newly discovered starting symbol 
        (e.g. "main") when the first analysis is completed, provided the user hasn't manually
        changed the program's location. Note that this option has precedence over the 
        :meth:`shouldAskToRepostionAfterAnalysis() <.shouldAskToRepostionAfterAnalysis>` option and the user will only be asked 
        if they have manually moved the program.
        
        :return: true if the program should be repositioned to a newly discovered starting symbol 
        (e.g. "main") when the first analysis is completed, provided the user hasn't manually
        changed the program's location.
        :rtype: bool
        """

    def useUnderscorePrefixes(self) -> bool:
        """
        Returns true if the list of starting symbol names should also be search for with "_" and
        "__" prepended.
        
        :return: true if the list of starting symbol names should also be search for with "_" and
        "__" prepended.
        :rtype: bool
        """

    @property
    def startingSymbolNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def startLocationType(self) -> ProgramStartingLocationOptions.StartLocationType:
        ...



__all__ = ["NextPrevCodeUnitPlugin", "NextPreviousFunctionAction", "NextPreviousBookmarkAction", "GoToAddressLabelPlugin", "NavigationHistoryPlugin", "NextPrevHighlightRangePlugin", "FindAppliedDataTypesService", "NextPreviousLabelAction", "FunctionUtils", "ProviderNavigationPlugin", "NextPreviousInstructionAction", "NextHighlightedRangeAction", "NextPreviousUndefinedAction", "NextPreviousSameBytesAction", "AbstractNextPreviousAction", "ProgramStartingLocationPlugin", "PreviousSelectedRangeAction", "NextPrevSelectedRangePlugin", "NextPreviousDefinedDataAction", "NextSelectedRangeAction", "NavigationOptions", "NextPrevAddressPlugin", "PreviousHighlightedRangeAction", "ProgramStartingLocationOptions"]
