from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme
import ghidra.app.merge.tool
import ghidra.app.nav
import ghidra.app.services
import ghidra.app.util.viewer.multilisting
import ghidra.framework.data
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class DataTypeArchiveMergeManagerPlugin(MergeManagerPlugin):
    """
    Plugin that provides a merge component provider for data type archives.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, mergeManager: DataTypeArchiveMergeManager, dataTypeArchive: ghidra.program.model.listing.DataTypeArchive):
        """
        Constructor for plugin that handles multi-user merge of data type archives.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param DataTypeArchiveMergeManager mergeManager: the merge manager that will control the merge process
        :param ghidra.program.model.listing.DataTypeArchive dataTypeArchive: the data type archive
        """


class ProgramSpecificAddressTranslator(ghidra.app.util.viewer.multilisting.AddressTranslator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addProgramAddress(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        ...


class MergeConstants(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    RESULT: typing.Final = 0
    LATEST: typing.Final = 1
    MY: typing.Final = 2
    ORIGINAL: typing.Final = 3
    RESULT_TITLE: typing.Final = "Result"
    ORIGINAL_TITLE: typing.Final = "Original"
    LATEST_TITLE: typing.Final = "Latest"
    MY_TITLE: typing.Final = "Checked Out"
    CONFLICT_COLOR: typing.Final[generic.theme.GColor]
    HIGHLIGHT_COLOR: typing.Final[java.awt.Color]
    RESOLVED_LATEST_DTS: typing.Final = "ResolvedLatestDataTypes"
    RESOLVED_MY_DTS: typing.Final = "ResolvedMyDataTypes"
    RESOLVED_ORIGINAL_DTS: typing.Final = "ResolvedOriginalDataTypes"
    RESOLVED_CODE_UNITS: typing.Final = "ResolvedCodeUnits"
    PICKED_LATEST_CODE_UNITS: typing.Final = "PickedLatestCodeUnits"
    PICKED_MY_CODE_UNITS: typing.Final = "PickedMyCodeUnits"
    PICKED_ORIGINAL_CODE_UNITS: typing.Final = "PickedOriginalCodeUnits"
    RESOLVED_LATEST_SYMBOLS: typing.Final = "ResolvedLatestSymbols"
    RESOLVED_MY_SYMBOLS: typing.Final = "ResolvedMySymbols"
    RESOLVED_ORIGINAL_SYMBOLS: typing.Final = "ResolvedOriginalSymbols"


class MergeProgressPanel(javax.swing.JPanel):
    """
    The MergeProgressPanel displays the name of each merge phase along with an icon indicating
    whether the phase is Pending, In Progress or Completed.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFINED_ICON: typing.ClassVar[javax.swing.Icon]
    IN_PROGRESS_ICON: typing.ClassVar[javax.swing.Icon]
    COMPLETED_ICON: typing.ClassVar[javax.swing.Icon]

    def __init__(self):
        """
        Constructor for a merge progress panel.
        """

    def addInfo(self, phase: jpype.JArray[java.lang.String]) -> javax.swing.JPanel:
        """
        Adds a new phase name and its associated icon to the panel.
        The last string in the array will be the name displayed for this phase.
        
        :param jpype.JArray[java.lang.String] phase: array of strings indicating this phase. 
        The first string indicates the primary phase. EAch subsequent string indicates 
        another sub-phase of the phase indicated by the previous string.
        The last string indicates this phase.
        :return: the panel that was added which displays this phase's name and status
        :rtype: javax.swing.JPanel
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def setCompleted(self, phase: jpype.JArray[java.lang.String]):
        """
        Indicates a particular phase or sub-phase whose status icon is to be changed to 
        indicate that it is completed.
        
        :param jpype.JArray[java.lang.String] phase: array which indicates this phase or sub-phase.
        """

    def setInProgress(self, phase: jpype.JArray[java.lang.String]):
        """
        Indicates a particular phase or sub-phase whose status icon is to be changed to 
        indicate that it is in progress.
        
        :param jpype.JArray[java.lang.String] phase: array which indicates this phase or sub-phase.
        """


@typing.type_check_only
class MergeNavigatable(ghidra.app.nav.Navigatable):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MergeManagerPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ProgramaticUseOnly, ghidra.framework.model.DomainObjectListener):
    """
    Plugin that provides a merge component provider.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, mergeManager: MergeManager, domainObject: ghidra.framework.model.DomainObject):
        """
        Constructor for plugin that handles multi-user merge of programs.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool with the active program to be merged
        :param MergeManager mergeManager: the merge manager that will control the merge process
        :param ghidra.framework.model.DomainObject domainObject: the current domain object
        """

    def closeAllDomainObjects(self, ignoreChanges: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @typing.overload
    def closeDomainObject(self) -> bool:
        ...

    @typing.overload
    def closeDomainObject(self, domainObject: ghidra.framework.model.DomainObject, ignoreChanges: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def createProvider(self) -> MergeManagerProvider:
        """
        Creates the provider that will be displayed in the merge tool. This shows the merge
        progress to the user and lets the user resolve conflicts.
        Any class that extends this plugin must provide its own MergeManagerProvider here that will 
        be shown to the user for the merge.
        
        :return: the merge provider associated with this plugin.
        :rtype: MergeManagerProvider
        """

    def getAllOpenDomainObjects(self) -> jpype.JArray[ghidra.framework.model.DomainObject]:
        ...

    @staticmethod
    def getCategory() -> str:
        ...

    def getCurrentDomainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    @staticmethod
    def getDescription() -> str:
        ...

    @staticmethod
    def getDescriptiveName() -> str:
        ...

    def getSearchPriority(self, domainObject: ghidra.framework.model.DomainObject) -> int:
        ...

    def isVisible(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        ...

    @typing.overload
    def openDomainObject(self, domainFile: ghidra.framework.model.DomainFile) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def openDomainObject(self, df: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def openDomainObject(self, domainFile: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int], state: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def openDomainObject(self, domainObject: ghidra.framework.model.DomainObject):
        ...

    @typing.overload
    def openDomainObject(self, domainObject: ghidra.framework.model.DomainObject, current: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def openDomainObject(self, domainObject: ghidra.framework.model.DomainObject, state: typing.Union[jpype.JInt, int]):
        ...

    def releaseDomainObject(self, domainObject: ghidra.framework.model.DomainObject, persistentOwner: java.lang.Object):
        ...

    def setCurrentDomainObject(self, domainObject: ghidra.framework.model.DomainObject):
        ...

    def setPersistentOwner(self, domainObject: ghidra.framework.model.DomainObject, owner: java.lang.Object) -> bool:
        ...

    def setSearchPriority(self, domainObject: ghidra.framework.model.DomainObject, priority: typing.Union[jpype.JInt, int]):
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def allOpenDomainObjects(self) -> jpype.JArray[ghidra.framework.model.DomainObject]:
        ...

    @property
    def searchPriority(self) -> jpype.JInt:
        ...

    @property
    def currentDomainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    @currentDomainObject.setter
    def currentDomainObject(self, value: ghidra.framework.model.DomainObject):
        ...


class PhaseProgressPanel(javax.swing.JPanel):
    """
    The PhaseProgressPanel provides a title, progress bar and message for the current phase that is 
    in progress
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str]):
        ...

    def removeMessage(self):
        """
        Removes the message from being displayed by this panel.
        Setting the message text will cause it to get added again.
        """

    def removeProgress(self):
        """
        Removes the progress bar from being displayed by this panel.
        Setting progress will cause it to get added again.
        """

    def setMessage(self, message: typing.Union[java.lang.String, str]):
        """
        Sets the progress message within this panel.
        
        :param java.lang.String or str message: the new message text to be displayed.
        """

    def setProgress(self, progressPercentage: typing.Union[jpype.JInt, int]):
        """
        Fills in the progress bar to the indicated percent.
        
        :param jpype.JInt or int progressPercentage: total percent of the progress bar that should be filled in.
        """

    def setTitle(self, newTitle: typing.Union[java.lang.String, str]):
        """
        Sets the title line displayed by this panel.
        
        :param java.lang.String or str newTitle: the new title string
        """


class MergeResolver(java.lang.Object):
    """
    Interface for resolving domain object merge conflicts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self):
        """
        Notification that the apply button was hit.
        """

    def cancel(self):
        """
        Notification that the merge process was canceled.
        """

    def getDescription(self) -> str:
        """
        Get the description of what this MergeResolver does.
        """

    def getName(self) -> str:
        """
        Get the name of this MergeResolver.
        """

    def getPhases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        """
        Gets identifiers for the merge phases handled by this MergeResolver.
        If the merge has no sub-phases then return an array with a single string array. 
        Each inner String array indicates a path for a single merge phase.
        Each outer array element represents a phase whose progress we wish to indicate.
         
        Examples:
         
        So for a simple phase which has no sub-phases return 
        ``
        new String[][] {new String[] {"Phase A"}}
        ``
         
        So for a phase with 2 sub-phases return 
        ``
        new String[][] { new String[] {"Phase A"}, 
                        new String[] {"Phase A", "Sub-Phase 1},
                        new String[] {"Phase A", "Sub-Phase 2} }
        ``.
        
        :return: an array of phases.
        :rtype: jpype.JArray[jpype.JArray[java.lang.String]]
        """

    def merge(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Perform the merge process.
        
        :param ghidra.util.task.TaskMonitor monitor: monitor that allows the user to cancel the merge
        operation
        :raises java.lang.Exception: if the merge encounters an error and the merge process
        should not continue.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def phases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        ...


class MergeManager(ghidra.framework.data.DomainObjectMergeManager):
    """
    Top level object that manages each step of the merge/resolve conflicts
    process.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resultDomainObject: ghidra.framework.model.DomainObject, myDomainObject: ghidra.framework.model.DomainObject, originalDomainObject: ghidra.framework.model.DomainObject, latestDomainObject: ghidra.framework.model.DomainObject, latestChangeSet: ghidra.program.model.listing.DomainObjectChangeSet, myChangeSet: ghidra.program.model.listing.DomainObjectChangeSet):
        ...

    def clearStatusText(self):
        """
        Clear the status text on the merge dialog.
        """

    def getDomainObject(self, version: typing.Union[jpype.JInt, int]) -> ghidra.framework.model.DomainObject:
        """
        Returns one of the four programs involved in the merge as indicated by the version.
        
        :param jpype.JInt or int version: the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
        :return: the indicated program version or null if a valid version isn't specified.
        :rtype: ghidra.framework.model.DomainObject
        
        .. seealso::
        
            | :obj:`MergeConstants`
        """

    def getMergeProgressPanel(self) -> MergeProgressPanel:
        """
        gets the default merge progress panel that indicates all the phases and their current status.
        
        :return: the merge panel that indicates progress.
        :rtype: MergeProgressPanel
        """

    def getMergeResolverByName(self, name: typing.Union[java.lang.String, str]) -> MergeResolver:
        """
        Returns the named merge resolver from the ones used directly by the MergeManager.
        
        :param java.lang.String or str name: the name of the desired merge resolver
        :return: the merge resolver or null.
        :rtype: MergeResolver
        """

    def getMergeTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        For Junit tests
        
        :return: the merge tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getMonitorComponent(self) -> javax.swing.JComponent:
        """
        Gets the TaskMonitor component that is displayed at the bottom of the merge tool.
        
        :return: the task monitor component.
        :rtype: javax.swing.JComponent
        """

    def getResolveInformation(self, infoType: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Gets the resolve information object for the indicated standardized name.
        This is how information is passed between merge managers.
         
        For example:
         
        the data type merger knows what data type in the result is equivalent 
        to a given data type from my checked out program. The code unit and
        function mergers need to be able to get this information so they
        don't unknowingly re-introduce a data type that was already eliminated
        by a data type conflict.
        
        :param java.lang.String or str infoType: the string indicating the type of resolve information
        :return: the object for the named string or null
        :rtype: java.lang.Object
        """

    def isMergeToolVisible(self) -> bool:
        """
        Determines if the modal merge tool is currently displayed on the screen.
        
        :return: true if the merge tool is displayed.
        :rtype: bool
        """

    def isPromptingUser(self) -> bool:
        """
        Determines whether or not the user is being prompted to resolve a conflict.
        
        :return: true if the user is being prompted for input.
        :rtype: bool
        """

    def merge(self) -> bool:
        """
        Convenience method for Junit tests.
        """

    def processingCompleted(self) -> bool:
        """
        Return whether the merge process has completed. (Needed for Junit testing
        only.)
        """

    def removeComponent(self, comp: javax.swing.JComponent):
        """
        Removes the component that is used to resolve conflicts. This method
        is called by the MergeResolvers when user input is no longer required
        using the specified component.
        
        :param javax.swing.JComponent comp: component to show; if component is null, show the 
        default component and do not block
        """

    def setApplyEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Enable the apply button according to the "enabled" parameter.
        """

    def setCompleted(self, mergePhase: jpype.JArray[java.lang.String]):
        """
        The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase completes.
        The string array should match one that the returned by MergeResolver.getPhases().
        
        :param jpype.JArray[java.lang.String] mergePhase: identifier for the merge phase to change to completed status.
        
        .. seealso::
        
            | :obj:`MergeResolver`
        """

    def setInProgress(self, mergePhase: jpype.JArray[java.lang.String]):
        """
        The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase begins.
        The string array should match one that the returned by MergeResolver.getPhases().
        
        :param jpype.JArray[java.lang.String] mergePhase: identifier for the merge phase to change to in progress status.
        
        .. seealso::
        
            | :obj:`MergeResolver`
        """

    def setResolveInformation(self, infoType: typing.Union[java.lang.String, str], infoObject: java.lang.Object):
        """
        Sets the resolve information object for the indicated standardized name.
        This is how information is passed between merge managers.
        
        :param java.lang.String or str infoType: the string indicating the type of resolve information
        :param java.lang.Object infoObject: the object for the named string. This information is
        determined by the merge manager that creates it.
        
        .. seealso::
        
            | :obj:`.getResolveInformation(String)`
        """

    def setStatusText(self, msg: typing.Union[java.lang.String, str]):
        """
        Set the status text on the merge dialog.
        """

    @staticmethod
    @typing.overload
    def showBlockingError(title: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str]):
        """
        Display a blocking error popup.  When used from a :obj:`MergeResolver` task it will 
        prevent that task from exiting/progressing until the error popup is dismissed.
        
        :param java.lang.String or str title: popup title
        :param java.lang.String or str msg: error message
        """

    @staticmethod
    @typing.overload
    def showBlockingError(title: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], e: java.lang.Exception):
        """
        Display a blocking error popup.  When used from a :obj:`MergeResolver` task it will 
        prevent that task from exiting/progressing until the error popup is dismissed.
        
        :param java.lang.String or str title: popup title
        :param java.lang.String or str msg: error message
        :param java.lang.Exception e: exception
        """

    def showComponent(self, comp: javax.swing.JComponent, componentID: typing.Union[java.lang.String, str], helpLoc: ghidra.util.HelpLocation):
        """
        Show the component that is used to resolve conflicts. This method
        is called by the MergeResolvers when user input is required. If the
        component is not null, this method blocks until the user either 
        cancels the merge process or resolves a conflict. If comp is null,
        then the default component is displayed, and the method does not
        wait for user input.
        
        :param javax.swing.JComponent comp: component to show; if component is null, show the 
        default component and do not block
        :param java.lang.String or str componentID: id or name for the component
        """

    def showDefaultMergePanel(self, description: typing.Union[java.lang.String, str]):
        """
        Show the default merge panel. The default merge panel now shows the status of each phase
        of the merge and also the progress in the current phase.
        
        :param java.lang.String or str description: description of current merge process near the top of the merge tool.
        """

    def showMonitorComponent(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Shows/hides the monitor component at the bottom of the merge tool.
        
        :param jpype.JBoolean or bool show: true means to show the task monitor at the bottom of the merge tool.
        """

    def showProgressIcon(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Shows/hides the progress icon (spinning globe) at the bottom of the merge tool.
        
        :param jpype.JBoolean or bool show: true means to show the icon.
        """

    @typing.overload
    def updateProgress(self, description: typing.Union[java.lang.String, str]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param java.lang.String or str description: a message describing what is currently occurring in this phase.
        Null indicates to use the default message.
        """

    @typing.overload
    def updateProgress(self, currentProgressPercentage: typing.Union[jpype.JInt, int]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param jpype.JInt or int currentProgressPercentage: the progress percentage completed for the current phase.
        This should be a value from 0 to 100.
        """

    @typing.overload
    def updateProgress(self, currentProgressPercentage: typing.Union[jpype.JInt, int], progressMessage: typing.Union[java.lang.String, str]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param jpype.JInt or int currentProgressPercentage: the progress percentage completed for the current phase.
        This should be a value from 0 to 100.
        :param java.lang.String or str progressMessage: a message indicating what is currently occurring in this phase.
        """

    @property
    def resolveInformation(self) -> java.lang.Object:
        ...

    @property
    def promptingUser(self) -> jpype.JBoolean:
        ...

    @property
    def mergeToolVisible(self) -> jpype.JBoolean:
        ...

    @property
    def mergeResolverByName(self) -> MergeResolver:
        ...

    @property
    def monitorComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def mergeTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject:
        ...

    @property
    def mergeProgressPanel(self) -> MergeProgressPanel:
        ...


class ProgramMergeManagerPlugin(MergeManagerPlugin, ghidra.app.services.ProgramManager):
    """
    Plugin that provides a merge component provider.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, mergeManager: ProgramMultiUserMergeManager, program: ghidra.program.model.listing.Program):
        """
        Constructor for plugin that handles multi-user merge of programs.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool with the active program to be merged
        :param ProgramMultiUserMergeManager mergeManager: the merge manager that will control the merge process
        :param ghidra.program.model.listing.Program program: the current program
        """

    def getSearchPriority(self, p: ghidra.program.model.listing.Program) -> int:
        ...

    def setSearchPriority(self, p: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int]):
        ...

    @property
    def searchPriority(self) -> jpype.JInt:
        ...


class ProgramMultiUserMergeManager(MergeManager):
    """
    Top level object that manages each step of the merge/resolve conflicts process.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resultProgram: ghidra.program.model.listing.Program, myProgram: ghidra.program.model.listing.Program, originalProgram: ghidra.program.model.listing.Program, latestProgram: ghidra.program.model.listing.Program, latestChangeSet: ghidra.program.model.listing.ProgramChangeSet, myChangeSet: ghidra.program.model.listing.ProgramChangeSet):
        ...

    def getListingMergePanel(self) -> ghidra.app.merge.tool.ListingMergePanel:
        """
        Returns the listing merge panel.
         
        
        This is the panel containing the four listing windows: result, latest, my, and original. The
        four listings are the center component of :obj:`JPanel` with a :obj:`BorderLayout`.
        
        :return: the merge panel
        :rtype: ghidra.app.merge.tool.ListingMergePanel
        """

    def getProgram(self, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Returns one of the four programs involved in the merge as indicated by the version.
        
        :param jpype.JInt or int version: the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
        :return: the indicated program version or null if a valid version isn't specified.
        :rtype: ghidra.program.model.listing.Program
        
        .. seealso::
        
            | :obj:`MergeConstants`
        """

    def isMergeToolVisible(self) -> bool:
        """
        Determines if the modal merge tool is currently displayed on the screen.
        
        :return: true if the merge tool is displayed.
        :rtype: bool
        """

    def isShowListingPanel(self) -> bool:
        """
        Determine if the listing panels should be rendered.
         
        
        NOTE: This is provided for testing performance reasons only.
        
        :return: true if listing panels should be rendered
        :rtype: bool
        """

    def isShowingListingMergePanel(self) -> bool:
        """
        Determines if the four program Listing merge panel is currently displayed in the merge tool.
        
        :return: true if the Listing merge panel is displayed.
        :rtype: bool
        """

    def refreshListingMergePanel(self, resultAddress: ghidra.program.model.address.Address, latestAddress: ghidra.program.model.address.Address, myAddress: ghidra.program.model.address.Address, originalAddress: ghidra.program.model.address.Address):
        """
        Show the listing merge panel with each listing positioned to the indicated address.
         
        
        A null can be passed for any address to indicate that listing should be empty.
        
        :param ghidra.program.model.address.Address resultAddress: the address for positioning the Result program's listing.
        :param ghidra.program.model.address.Address latestAddress: the address for positioning the Latest program's listing.
        :param ghidra.program.model.address.Address myAddress: the address for positioning the My program's listing.
        :param ghidra.program.model.address.Address originalAddress: the address for positioning the Original program's listing.
        """

    def removeListingMergePanel(self):
        """
        Remove the listing merge panel from the merge manager.
        """

    def showComponent(self, comp: javax.swing.JComponent, componentID: typing.Union[java.lang.String, str], helpLoc: ghidra.util.HelpLocation):
        """
        Show the component that is used to resolve conflicts.
         
        
        This method is called by the MergeResolvers when user input is required. If the component is
        not null, this method blocks until the user either cancels the merge process or resolves a
        conflict. If comp is null, then the default component is displayed, and the method does not
        wait for user input.
        
        :param javax.swing.JComponent comp: component to show; if component is null, show the default component and do not
                    block
        :param java.lang.String or str componentID: id or name for the component
        """

    def showDefaultMergePanel(self, description: typing.Union[java.lang.String, str]):
        """
        Show the default merge panel.
         
        
        The default merge panel now shows the status of each phase of the merge and also the progress
        in the current phase.
        
        :param java.lang.String or str description: description of current merge process near the top of the merge tool.
        """

    @typing.overload
    def showListingMergePanel(self, goToAddress: ghidra.program.model.address.Address):
        """
        Show the listing merge panel.
        
        :param ghidra.program.model.address.Address goToAddress: the address to goto.
        """

    @typing.overload
    def showListingMergePanel(self, resultAddress: ghidra.program.model.address.Address, latestAddress: ghidra.program.model.address.Address, myAddress: ghidra.program.model.address.Address, originalAddress: ghidra.program.model.address.Address):
        """
        Show the listing merge panel with each listing positioned to the indicated address.
         
        
        A null can be passed for any address to indicate that listing should be empty.
        
        :param ghidra.program.model.address.Address resultAddress: the address for positioning the Result program's listing.
        :param ghidra.program.model.address.Address latestAddress: the address for positioning the Latest program's listing.
        :param ghidra.program.model.address.Address myAddress: the address for positioning the My program's listing.
        :param ghidra.program.model.address.Address originalAddress: the address for positioning the Original program's listing.
        """

    @property
    def listingMergePanel(self) -> ghidra.app.merge.tool.ListingMergePanel:
        ...

    @property
    def mergeToolVisible(self) -> jpype.JBoolean:
        ...

    @property
    def showingListingMergePanel(self) -> jpype.JBoolean:
        ...

    @property
    def showListingPanel(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class DataTypeArchiveMergeManager(MergeManager):
    """
    Top level object that manages each step of the merge/resolve conflicts
    process.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, resultDtArchive: ghidra.program.model.data.DataTypeManagerDomainObject, myDtArchive: ghidra.program.model.data.DataTypeManagerDomainObject, originalDtArchive: ghidra.program.model.data.DataTypeManagerDomainObject, latestDtArchive: ghidra.program.model.data.DataTypeManagerDomainObject, latestChangeSet: ghidra.program.model.listing.DataTypeArchiveChangeSet, myChangeSet: ghidra.program.model.listing.DataTypeArchiveChangeSet):
        ...

    def getDataTypeArchive(self, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.DataTypeArchive:
        """
        Returns one of the four programs involved in the merge as indicated by the version.
        
        :param jpype.JInt or int version: the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
        :return: the indicated program version or null if a valid version isn't specified.
        :rtype: ghidra.program.model.listing.DataTypeArchive
        
        .. seealso::
        
            | :obj:`MergeConstants`
        """

    @property
    def dataTypeArchive(self) -> ghidra.program.model.listing.DataTypeArchive:
        ...


@typing.type_check_only
class MergeManagerProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Component that displays merge components as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: MergeManagerPlugin, title: typing.Union[java.lang.String, str]):
        ...

    def setCurrentProgress(self, currentPercentProgress: typing.Union[jpype.JInt, int]):
        """
        Sets the percentage of the progress meter that is filled in for the current phase progress area.
        
        :param jpype.JInt or int currentPercentProgress: the percentage of the progress bar to fill in from 0 to 100.
        """

    def updateProgressDetails(self, message: typing.Union[java.lang.String, str]):
        """
        Sets the message below the progress meter in the current phase progress area.
        
        :param java.lang.String or str message: the new text message to display. If null, then the default message is displayed.
        """

    def updateProgressTitle(self, newTitle: typing.Union[java.lang.String, str]):
        """
        Sets the title for the current phase progress area.
        
        :param java.lang.String or str newTitle: the new title
        """


class DataTypeManagerOwner(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Gets the associated data type manager.
        
        :return: the data type manager.
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...


class MergeProgressModifier(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setCompleted(self, mergePhase: jpype.JArray[java.lang.String]):
        """
        The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase completes.
        The string array should match one that the returned by MergeResolver.getPhases().
        
        :param jpype.JArray[java.lang.String] mergePhase: identifier for the merge phase to change to completed status.
        
        .. seealso::
        
            | :obj:`MergeResolver`
        """

    def setInProgress(self, mergePhase: jpype.JArray[java.lang.String]):
        """
        The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase begins.
        The string array should match one that the returned by MergeResolver.getPhases().
        
        :param jpype.JArray[java.lang.String] mergePhase: identifier for the merge phase to change to in progress status.
        
        .. seealso::
        
            | :obj:`MergeResolver`
        """

    @typing.overload
    def updateProgress(self, progressMessage: typing.Union[java.lang.String, str]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param java.lang.String or str progressMessage: a message indicating what is currently occurring in this phase.
        Null indicates to use the default message.
        """

    @typing.overload
    def updateProgress(self, currentProgressPercentage: typing.Union[jpype.JInt, int]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param jpype.JInt or int currentProgressPercentage: the progress percentage completed for the current phase.
        This should be a value from 0 to 100.
        """

    @typing.overload
    def updateProgress(self, currentProgressPercentage: typing.Union[jpype.JInt, int], progressMessage: typing.Union[java.lang.String, str]):
        """
        Updates the current phase progress area in the default merge panel.
        
        :param jpype.JInt or int currentProgressPercentage: the progress percentage completed for the current phase.
        This should be a value from 0 to 100.
        :param java.lang.String or str progressMessage: a message indicating what is currently occurring in this phase.
        """



__all__ = ["DataTypeArchiveMergeManagerPlugin", "ProgramSpecificAddressTranslator", "MergeConstants", "MergeProgressPanel", "MergeNavigatable", "MergeManagerPlugin", "PhaseProgressPanel", "MergeResolver", "MergeManager", "ProgramMergeManagerPlugin", "ProgramMultiUserMergeManager", "DataTypeArchiveMergeManager", "MergeManagerProvider", "DataTypeManagerOwner", "MergeProgressModifier"]
