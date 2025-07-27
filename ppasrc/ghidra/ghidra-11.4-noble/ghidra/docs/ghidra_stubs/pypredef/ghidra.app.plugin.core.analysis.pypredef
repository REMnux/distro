from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
import docking.widgets.table
import generic.cache
import generic.concurrent
import ghidra.app.context
import ghidra.app.decompiler.parallel
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.services
import ghidra.app.tablechooser
import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.rtti.types
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.app.util.importer
import ghidra.app.util.query
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.table.column
import ghidra.util.task
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


E = typing.TypeVar("E")
T = typing.TypeVar("T")


class ObjectiveC1_MessageAnalyzer(ghidra.app.services.AbstractAnalyzer):

    @typing.type_check_only
    class CurrentState(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnalysisOptionsDialog(docking.DialogComponentProvider, java.beans.PropertyChangeListener):
    """
    Dialog to show the panel for the auto analysis options.
    """

    class_: typing.ClassVar[java.lang.Class]


class OneShotAnalysisCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Background task to artificially kick off Auto analysis by
    calling anything that analyzes bytes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, analyzer: ghidra.app.services.Analyzer, set: ghidra.program.model.address.AddressSetView, log: ghidra.app.util.importer.MessageLog):
        ...


class GolangSymbolAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Analyzes Golang binaries for RTTI and function symbol information by following references from
    the root GoModuleData instance.
    """

    @typing.type_check_only
    class FixupDuffAlternateEntryPointsBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
        """
        A background command that runs later, it copies the function signature information from the
        main entry point of the duff function to any unnamed functions that are within the footprint
        of the main function.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, funcData: ghidra.app.util.bin.format.golang.rtti.GoFuncData, duffFunc: ghidra.program.model.listing.Function):
            ...


    @typing.type_check_only
    class FixGcWriteBarrierFlagBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, goBinary: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper, markupSession: ghidra.app.util.bin.format.golang.structmapping.MarkupSession):
            ...


    @typing.type_check_only
    class FixClosureFuncArgsBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
        """
        Partially fixup closure func signatures by matching a closure func (*.func1) with a
        closure struct ( struct { F uintptr; X0 blah... } ), and giving the func a context param
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, goBinary: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper):
            ...


    @typing.type_check_only
    class PropagateRttiBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
        """
        A background command that runs after reference analysis, it applies functions signature
        overrides to callsites that have a RTTI type parameter that return a specialized
        type instead of a void*.
        """

        @typing.type_check_only
        class RttiFuncInfo(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, funcName: typing.Union[java.lang.String, str], rttiParamIndex: typing.Union[jpype.JInt, int], returnTypeMapper: java.util.function.Function[ghidra.app.util.bin.format.golang.rtti.types.GoType, ghidra.program.model.data.DataType]):
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def funcName(self) -> ghidra.app.util.bin.format.golang.rtti.GoSymbolName:
                ...

            def hashCode(self) -> int:
                ...

            def returnTypeMapper(self) -> java.util.function.Function[ghidra.app.util.bin.format.golang.rtti.types.GoType, ghidra.program.model.data.DataType]:
                ...

            def rttiParamIndex(self) -> int:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class CallSiteInfo(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def calledFunc(self) -> ghidra.program.model.listing.Function:
                ...

            def callingFunc(self) -> ghidra.program.model.listing.Function:
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def ref(self) -> ghidra.program.model.symbol.Reference:
                ...

            def register(self) -> ghidra.program.model.lang.Register:
                ...

            def returnTypeMapper(self) -> java.util.function.Function[ghidra.app.util.bin.format.golang.rtti.types.GoType, ghidra.program.model.data.DataType]:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, goBinary: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper, markupSession: ghidra.app.util.bin.format.golang.structmapping.MarkupSession):
            ...


    @typing.type_check_only
    class GolangAnalyzerOptions(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        fixupGcWriteBarrierFlag: jpype.JBoolean


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isAlreadyAnalyzed(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if Golang analysis has already been performed for the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to check
        :return: true if analysis has already been performed, false if not yet
        :rtype: bool
        """


@typing.type_check_only
class AnalyzeProgramStrategy(java.lang.Object):
    """
    A simple interface for analyzing a program.
    """

    class_: typing.ClassVar[java.lang.Class]


class StoredAnalyzerTimes(ghidra.framework.options.CustomOption):
    """
    ``StoredAnalyzerTimes`` provides a custom option container for 
    accumulated analysis times for named tasks.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPTIONS_LIST: typing.Final = "Program Information.Analysis Times"
    OPTION_NAME: typing.Final = "Times"

    def __init__(self):
        ...

    def addTime(self, taskName: typing.Union[java.lang.String, str], t: typing.Union[jpype.JLong, int]):
        """
        Add the specified time corresponding to the specified analysis taskName
        
        :param java.lang.String or str taskName: analysis task name
        :param jpype.JLong or int t: time increment in milliseconds
        """

    @typing.overload
    def clear(self):
        """
        Clear all task entries and times
        """

    @typing.overload
    def clear(self, taskName: typing.Union[java.lang.String, str]):
        """
        Clear time entry corresponding to specified taskName
        
        :param java.lang.String or str taskName: analysis task name
        """

    @staticmethod
    def getStoredAnalyzerTimes(program: ghidra.program.model.listing.Program) -> StoredAnalyzerTimes:
        """
        Get the StoredAnalyzerTimes options data from the specified program
        
        :param ghidra.program.model.listing.Program program: program
        :return: StoredAnalyzerTimes option data
        :rtype: StoredAnalyzerTimes
        """

    def getTaskNames(self) -> jpype.JArray[java.lang.String]:
        """
        Get all task names for which time entries exist
        
        :return: array of task names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getTime(self, taskName: typing.Union[java.lang.String, str]) -> int:
        """
        Get the accumulated time for the specified analysis taskName
        
        :param java.lang.String or str taskName: analysis task name
        :return: accumulated task time in milliseconds or null if entry not found
        :rtype: int
        """

    def getTotalTime(self) -> int:
        """
        Get the total accumulated task time for all task entries
        in milliseconds
        
        :return: total accumuated task time in milliseconds
        :rtype: int
        """

    def isEmpty(self) -> bool:
        """
        Determine if any task times exist
        
        :return: true if no task times available, else false
        :rtype: bool
        """

    @staticmethod
    def setStoredAnalyzerTimes(program: ghidra.program.model.listing.Program, times: StoredAnalyzerTimes):
        """
        Set the updated StoredAnalyzerTimes option data on the specified program
        
        :param ghidra.program.model.listing.Program program: program
        :param StoredAnalyzerTimes times: StoredAnalyzerTimes option data
        """

    @property
    def taskNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def totalTime(self) -> jpype.JLong:
        ...

    @property
    def time(self) -> jpype.JLong:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class SwiftTypeMetadataAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnalysisOptionsUpdater(java.lang.Object):
    """
    An object that allows analyzers to rename options.   This is required to move old options stored
    in the program to the new equivalent option.   This class is not required for options that have
    simply been removed.
     
    
    Notes:
     
    * 
    Replacement options must be registered with one of the register methods of this class.
    
    * 
    This is intended for use with the UI;  access analysis options from the API will not use this
    replacer.  This means that any client, such as script, retrieving the old option value will not
    work for new programs that no longer have that old option registered.  Further, for programs
    that have the old options saved, but no longer registered, changing the old option value will
    have no effect.
    
    * 
    Old option values will only be used if they are non-default and the new option value is default.
    
    * 
    Clients can change the type of the option if they wish using
    :meth:`registerReplacement(String, String, Function) <.registerReplacement>`.
    """

    class ReplaceableOption(java.lang.Object):
        """
        A simple object that contains the new and old option name along with the replacer function 
        that will handle the option replacement.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def registerReplacement(self, newOptionName: typing.Union[java.lang.String, str], oldOptionName: typing.Union[java.lang.String, str]):
        """
        Register the given old option name to be replaced with the new option name.  The 
        replacement strategy used in this case will be to return the old value for the new option.
        
        :param java.lang.String or str newOptionName: the new option name
        :param java.lang.String or str oldOptionName: the old option name
        """

    @typing.overload
    def registerReplacement(self, newOptionName: typing.Union[java.lang.String, str], oldOptionName: typing.Union[java.lang.String, str], replacer: java.util.function.Function[java.lang.Object, java.lang.Object]):
        """
        Register the given old option name to be replaced with the new option name.  The given 
        replacer function will be called with the old option value to get the new option value.
        
        :param java.lang.String or str newOptionName: the new option name
        :param java.lang.String or str oldOptionName: the old option name
        :param java.util.function.Function[java.lang.Object, java.lang.Object] replacer: the function to update the update the old option value
        """


@typing.type_check_only
class MinGWPseudoRelocList(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class AnalysisOptionsEditor(ghidra.framework.options.OptionsEditor, java.beans.PropertyChangeListener):
    ...
    class_: typing.ClassVar[java.lang.Class]


class EmbeddedMediaAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class StoredAnalyzerTimesPropertyEditor(java.beans.PropertyEditorSupport, ghidra.framework.options.CustomOptionsEditor):
    """
    ``StoredAnalyzerTimesPropertyEditor`` implements a custom option
    editor panel for :obj:`StoredAnalyzerTimes`.  Ability to edit values
    is disabled with panel intended for display purpose only.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnalysisEnablementTableModel(docking.widgets.table.GDynamicColumnTableModel[AnalyzerEnablementState, java.lang.Object]):
    """
    Table model for analyzer enablement state.
    """

    @typing.type_check_only
    class AnalyzerEnabledColumn(docking.widgets.table.AbstractDynamicTableColumn[AnalyzerEnablementState, java.lang.Boolean, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnalyzerNameColumn(docking.widgets.table.AbstractDynamicTableColumn[AnalyzerEnablementState, java.lang.String, java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnabledColumnTableCellRenderer(ghidra.util.table.column.GColumnRenderer[java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnalyzerNameTableCellRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, panel: AnalysisPanel, analyzerStates: java.util.List[AnalyzerEnablementState]):
        ...

    def setData(self, analyzerStates: java.util.List[AnalyzerEnablementState]):
        ...


class CliMetadataTokenAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Finds CLI metadata tokens and renders them significantly more useful to the human user versus the CLI Virtual Execution System.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractDemanglerAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    The base demangler analyzer.  Implementations of this analyzer will attempt to demangle
    symbols in the binary being analyzed.
    
     
    Default implementations of this class exist for Microsoft and GNU.   These two analyzers will
    only be enabled when the program being analyzed has an architecture that fits each respective
    analyzer.  Users can subclass this analyzer to easily control the demangling behavior from
    the analyzer UI.
    
     
    This analyzer will call each implementation's
    :meth:`doDemangle(MangledContext, MessageLog) <.doDemangle>` method for each symbol.
    See the various protected methods of this class for points at which behavior can be overridden.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...


class AutoAnalysisManager(java.lang.Object):
    """
    AutoAnalysisPlugin
    
    Provides support for auto analysis tasks.
    Manages a pipeline or priority of tasks to run given some event has occurred.
    """

    @typing.type_check_only
    class AnalysisTaskWrapper(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class JointTaskMonitor(ghidra.util.task.TaskMonitor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnalysisWorkerCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program], ghidra.util.task.CancelledListener):
        """
        ``AnalysisWorkerCommand`` facilitates the controlled callback to an AnalysisWorker.
        In a Headed environment a modal task dialog will be used to block user input if the
        worker was scheduled with analyzeChanges==false
        """

        @typing.type_check_only
        class WorkerBlockerTask(ghidra.util.task.Task, ghidra.util.task.CancelledListener, java.lang.Runnable):
            """
            ``WorkerBlockerTask`` provides the means to block user input via a
            modal dialog while an analysis worker has either disabled or suspended auto-analysis
            (i.e., ignoring change events).
            """

            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addListener(self, listener: AutoAnalysisManagerListener):
        ...

    def addTool(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def blockAdded(self, set: ghidra.program.model.address.AddressSetView):
        ...

    def cancelQueuedTasks(self):
        """
        Tell all the tasks that they are canceled.
        """

    @typing.overload
    def codeDefined(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def codeDefined(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def createFunction(self, target: ghidra.program.model.address.Address, findFunctionStart: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def createFunction(self, targetSet: ghidra.program.model.address.AddressSetView, findFunctionStarts: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def createFunction(self, targetSet: ghidra.program.model.address.AddressSetView, findFunctionStarts: typing.Union[jpype.JBoolean, bool], priority: ghidra.app.services.AnalysisPriority):
        ...

    def dataDefined(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def disassemble(self, target: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def disassemble(self, targetSet: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def disassemble(self, targetSet: ghidra.program.model.address.AddressSetView, priority: ghidra.app.services.AnalysisPriority):
        ...

    def dispose(self):
        ...

    def externalAdded(self, extAddr: ghidra.program.model.address.Address):
        """
        Identify external addresses which need to be analyzed
        NOTE: This is a convenience method for blockAdded
        
        :param ghidra.program.model.address.Address extAddr: external address or null for all externals
        """

    @typing.overload
    def functionDefined(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def functionDefined(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def functionModifierChanged(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def functionModifierChanged(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def functionSignatureChanged(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def functionSignatureChanged(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @staticmethod
    def getAnalysisManager(program: ghidra.program.model.listing.Program) -> AutoAnalysisManager:
        ...

    def getAnalysisTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Returns the tool being used for analysis.  **This can be null** if analysis has never
        been run or if the tool that previously ran analysis has been closed.
        
        :return: the tool being used for analysis.
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getAnalyzer(self, analyzerName: typing.Union[java.lang.String, str]) -> ghidra.app.services.Analyzer:
        ...

    def getDataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    def getMessageLog(self) -> ghidra.app.util.importer.MessageLog:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        
        
        :return: program this analysis manager is attached to
        :rtype: ghidra.program.model.listing.Program
        """

    def getProtectedLocations(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the set of addresses that have been protected from clearing
        
        :return: protected locations
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    def getSharedAnalsysThreadPool() -> generic.concurrent.GThreadPool:
        """
        Returns a thread pool that is meant to be shared amongst Analyzers that wish to run
        in parallel.  Normally, this will only be used by one analyzer at a time.   However, if
        multiple tools are running, then they will share this pool.
        
        :return: the shared analysis thread pool
        :rtype: generic.concurrent.GThreadPool
        """

    def getTaskTime(self, map: collections.abc.Mapping, taskName: typing.Union[java.lang.String, str]) -> int:
        """
        Get the time taken by a named task
        The names of tasks that have run can be retrieved using getTimedTasks
        
        :param collections.abc.Mapping map: the times by task names
        :param java.lang.String or str taskName: the task name
        :return: the time taken by a named task
        :rtype: int
        """

    def getTaskTimesString(self) -> str:
        """
        Get a summary of the time for each task that ran for this auto analysis run
        
        :return: the string summary
        :rtype: str
        """

    def getTimedTasks(self) -> jpype.JArray[java.lang.String]:
        """
        Get the names of the tasks that have run
        
        :return: an array of task names
        :rtype: jpype.JArray[java.lang.String]
        """

    def getTotalTimeInMillis(self) -> int:
        """
        Get the total time of the last autoAnalysis run
        
        :return: time in milliseconds of last run
        :rtype: int
        """

    @staticmethod
    def hasAutoAnalysisManager(program: ghidra.program.model.listing.Program) -> bool:
        ...

    @typing.overload
    def initializeOptions(self):
        ...

    @typing.overload
    def initializeOptions(self, options: ghidra.framework.options.Options):
        ...

    def isAnalyzing(self) -> bool:
        """
        Returns true if the analyzer is still executing.
        
        :return: true if the analyzer is still executing
        :rtype: bool
        """

    def reAnalyzeAll(self, restrictSet: ghidra.program.model.address.AddressSetView):
        """
        Tell analyzers that all the addresses in the set should be re-analyzed when analysis runs.
        Invoking this method provides consistency in re-analyzing all or a subset of the existing things in a program.
        
        NOTE: This will not kick off analysis nor wait, but it will get scheduled.
        
        :param ghidra.program.model.address.AddressSetView restrictSet: - null to do the entire program, or a set of address to be re-analyzed fully
        """

    def registerAnalyzerOptions(self):
        ...

    def registerOptions(self):
        ...

    def removeListener(self, listener: AutoAnalysisManagerListener):
        ...

    def removeTool(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def restoreDefaultOptions(self):
        ...

    def scheduleOneTimeAnalysis(self, analyzer: ghidra.app.services.Analyzer, set: ghidra.program.model.address.AddressSetView):
        ...

    def scheduleWorker(self, worker: AnalysisWorker, workerContext: java.lang.Object, analyzeChanges: typing.Union[jpype.JBoolean, bool], workerMonitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Schedule an analysis worker to run while auto analysis is suspended.  Invocation will block
        until callback is completed or cancelled.  If an analysis task is busy, it will be allowed to
        complete before the worker callback occurs.  This method will cause the AnalysisWorker to
        run at the highest priority (reserved priority value of 0).  Within headed environments when analyzeChanges
        is false, a modal task dialog will be displayed while the callback is active to prevent the
        user from initiating additional program changes.  If this worker invokes startAnalysis, it will
        yield to ALL pending analysis.
         
        Known Limitations:
         
        * If ad-hoc background threads are making program changes, their associated
        program change events could be ignored by the AutoAnalysisManager
        * In headless environments, or if the target program is not open within a tool which
        contains the AutoAnalysisPlugin, all invocations will perform the callback immediately
        without regard to other threads which may be changing the program
        
        
        :param AnalysisWorker worker: the worker instance to be invoked while analysis is inactive.
        :param java.lang.Object workerContext: any data required by the worker to complete its task or null if worker
        instance will retain the necessary state.
        :param jpype.JBoolean or bool analyzeChanges: if false program changes which occur while the worker is running will not trigger
        follow-on analysis of those changes.  If false it is critical that the worker be associated with a modal
        task dialog which will prevent unrelated concurrent changes being made to the program while
        the worker is active.
        :param ghidra.util.task.TaskMonitor workerMonitor: the worker's monitor
        :return: boolean value returned by worker.analysisWorkerCallback
        :rtype: bool
        :raises java.lang.reflect.InvocationTargetException: if worker throws exception while running (see cause)
        :raises java.lang.InterruptedException: if caller's thread is interrupted.  If this occurs a cancel
        condition will be forced on the workerMonitor so that the worker will stop running.
        :raises CancelledException: if the job is cancelled
        
        .. seealso::
        
            | :obj:`AnalysisPriority`for priority values
        """

    def setDebug(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIgnoreChanges(self, state: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Alter the current program change listener state for this auto-analysis manager.
        NOTE: method only has an affect only when invoked within the analysis thread
        (i.e., by an Analyzer or AnalysisWorker)
        
        :param jpype.JBoolean or bool state: if true subsequent program changes will not trigger auto-analysis, if
        false program changes could trigger auto-analysis on those changes
        :return: previous state
        :rtype: bool
        """

    def setProtectedLocation(self, addr: ghidra.program.model.address.Address):
        """
        Add a location that is know good code to be protected from clearing for this Analysis run only.
        
        :param ghidra.program.model.address.Address addr: address to protect
        """

    def setProtectedLocations(self, set: ghidra.program.model.address.AddressSet):
        """
        Add a set of known good code locations to be protected from clearing for this Analysis run only.
        
        :param ghidra.program.model.address.AddressSet set: of addresses to protect
        """

    @typing.overload
    def startAnalysis(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Start auto-analysis in the current thread if it is ENABLED and not yet running.
        WARNING! If auto analysis is actively running or is DISABLED/SUSPENDED, this method will return immediately.
        NOTE: If invoked directly or indirectly by an Analyzer a yield will be
        performed in which all queued tasks of a higher priority (smaller priority value) than the current
        task will be executed prior to this method returning.  AnalysisWorker's should use the
        yield method so that their limit-priority may be established during the yield.
         
        
        If analysis is performed, a summary of task execution times will be printed to the log.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        """

    @typing.overload
    def startAnalysis(self, monitor: ghidra.util.task.TaskMonitor, printTaskTimes: typing.Union[jpype.JBoolean, bool]):
        """
        Start auto-analysis in the current thread if it is ENABLED and not yet running.
        WARNING! If auto analysis is actively running or is DISABLED/SUSPENDED, this method will return immediately.
        NOTE: If invoked directly or indirectly by an Analyzer a yield will be
        performed in which all queued tasks of a higher priority (smaller priority value) than the current
        task will be executed prior to this method returning.  AnalysisWorker's should use the
        yield method so that their limit-priority may be established during the yield.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :param jpype.JBoolean or bool printTaskTimes: if true and analysis is performed, a summary of task execution times
        will be printed to the log.
        """

    def startBackgroundAnalysis(self) -> bool:
        """
        Start auto-analysis in background (only supported in tool environment when
        AutoAnalysisManagerPlugin installed)
        
        :return: true if successfully scheduled background task or auto-analysis is already
        scheduled/running.
        :rtype: bool
        """

    def waitForAnalysis(self, limitPriority: typing.Union[java.lang.Integer, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Allows all queued auto-analysis tasks with a priory value less than the specified
        limitPriority (lower values are considered to be a higher-priority) to complete.
        Any previously yielded tasks will remain in a yielded state.
        NOTE: This method should generally only be used by GhidraScripts.  Using this method
        is not recommended for Analyzers or their subordinate threads.  Invoking this method
        from a Analyzer subordinate thread will likely produce a deadlock situation.
        
        :param java.lang.Integer or int limitPriority: property limit threshold - all tasks with a lower priority value
        (i.e., lower values correspond to higher priority) will be permitted to run.  A value
        of null will allow all pending analysis to complete (excluding any tasks which had
        previously yielded).
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :raises IllegalStateException: if not invoked from the analysis thread.
        """

    @property
    def analyzing(self) -> jpype.JBoolean:
        ...

    @property
    def messageLog(self) -> ghidra.app.util.importer.MessageLog:
        ...

    @property
    def analyzer(self) -> ghidra.app.services.Analyzer:
        ...

    @property
    def timedTasks(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def dataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def taskTimesString(self) -> java.lang.String:
        ...

    @property
    def totalTimeInMillis(self) -> jpype.JInt:
        ...

    @property
    def protectedLocations(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def analysisTool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


class FindPossibleReferencesPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to find all possible references to the address at the
    current cursor location.  A reference is some set of bytes that
    when treated as an address would be the address of the current
    cursor location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class TransientProgramProperties(java.lang.Object):
    """
    Mechanism to associate values with a currently open program.  Values will be released when
    the program is closed, or when the current analysis session is finished.
     
    
    Values that are linked to things in a Program that are subject to be reverted during a
    transaction roll-back should probably not be stored in a PROGRAM scoped property.  (example:
    DataTypes, CodeUnits, etc)  ANALYSIS_SESSION scoped properties are protected from rollback
    by the active transaction that is held during the session.
    """

    class SCOPE(java.lang.Enum[TransientProgramProperties.SCOPE]):

        class_: typing.ClassVar[java.lang.Class]
        PROGRAM: typing.Final[TransientProgramProperties.SCOPE]
        ANALYSIS_SESSION: typing.Final[TransientProgramProperties.SCOPE]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TransientProgramProperties.SCOPE:
            ...

        @staticmethod
        def values() -> jpype.JArray[TransientProgramProperties.SCOPE]:
            ...


    class PropertyValueSupplier(java.lang.Object, typing.Generic[T, E]):
        """
        A checked :obj:`Supplier`
        """

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> T:
            ...


    @typing.type_check_only
    class Property(java.lang.Record, java.io.Closeable):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def key(self) -> java.lang.Object:
            ...

        def scope(self) -> TransientProgramProperties.SCOPE:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> java.lang.Object:
            ...


    @typing.type_check_only
    class PerProgramProperties(ghidra.framework.model.DomainObjectClosedListener, AutoAnalysisManagerListener, java.io.Closeable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getProperty(program: ghidra.program.model.listing.Program, key: java.lang.Object, scope: TransientProgramProperties.SCOPE, clazz: java.lang.Class[T], supplier: TransientProgramProperties.PropertyValueSupplier[T, E]) -> T:
        """
        Returns a property value that has been associated with the specified program.
         
        
        If the property wasn't present, the :obj:`PropertyValueSupplier` will be used to 
        create the value and associate it with the program.
        
        :param T: type of the property value.  If the property value is :obj:`Closeable`, it
        will be :meth:`closed <Closeable.close>` when released.:param E: type of the exception the supplier throws:param ghidra.program.model.listing.Program program: :obj:`Program`
        :param java.lang.Object key: property key
        :param TransientProgramProperties.SCOPE scope: :obj:`SCOPE` lifetime of property.  If an analysis session is NOT active,
        requesting :obj:`SCOPE.ANALYSIS_SESSION` will throw an IllegalArgumentException.  If the
        requested scope does not match the scope of the already existing value, an 
        IllegalArgumentException will be thrown.
        :param java.lang.Class[T] clazz: type of the property value
        :param TransientProgramProperties.PropertyValueSupplier[T, E] supplier: :obj:`PropertyValueSupplier` callback that will create the property 
        value if it is not present
        :return: property value
        :rtype: T
        :raises IllegalArgumentException: if scope == ANALYSIS_SESSION and there is no active analysis
        session, OR, if the requested scope does not match the scope used to an earlier call for
        the same property
        :raises E: same exception type that the supplier throws
        """

    @staticmethod
    def hasProperty(program: ghidra.program.model.listing.Program, key: java.lang.Object) -> bool:
        """
        Returns true if the specified property is present.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        :param java.lang.Object key: property key
        :return: boolean true if property is present.
        :rtype: bool
        """

    @staticmethod
    def removeProgramProperties(program: ghidra.program.model.listing.Program):
        """
        Release all properties for the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program`
        """


class ConstantPropagationAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, processorName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, processorName: typing.Union[java.lang.String, str], type: ghidra.app.services.AnalyzerType):
        ...

    def analyzeLocation(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Analyze a single location
        
        :param ghidra.program.model.listing.Program program: - program to analyze
        :param ghidra.program.model.address.Address start: - location to start flowing constants
        :param ghidra.program.model.address.AddressSetView set: - restriction set of addresses to analyze
        :param ghidra.util.task.TaskMonitor monitor: - monitor to check canceled
        :return: - set of addresses actually flowed to
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException:
        """

    def analyzeSet(self, program: ghidra.program.model.listing.Program, todoSet: ghidra.program.model.address.AddressSet, monitor: ghidra.util.task.TaskMonitor):
        """
        Analyze all addresses in todoSet
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.AddressSet todoSet: addresses that are not in functions
        :param ghidra.util.task.TaskMonitor monitor: to cancel
        :raises CancelledException:
        """

    @staticmethod
    def claimProcessor(processorName: typing.Union[java.lang.String, str]):
        """
        Called to register a more specific analyzer.
        
        :param java.lang.String or str processorName:
        """

    def createData(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        ...

    def flowConstants(self, program: ghidra.program.model.listing.Program, flowStart: ghidra.program.model.address.Address, flowSet: ghidra.program.model.address.AddressSetView, symEval: ghidra.program.util.SymbolicPropogator, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Actually use the setup evaluator to flow the constants
        
        :param ghidra.program.model.address.Address flowStart: - address to start flowing at
        :param ghidra.program.model.address.AddressSetView flowSet: - address set to restrict constant flowing to
        :param ghidra.program.util.SymbolicPropogator symEval: - symbolic propagator to be used
        :param ghidra.util.task.TaskMonitor monitor: - monitor to check canceled
        :return: the address set of instructions which were followed
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException:
        """

    @staticmethod
    def isClaimedProcessor(processorName: typing.Union[java.lang.String, str]) -> bool:
        """
        Called to register a more specific analyzer.
        
        :param java.lang.String or str processorName:
        """

    def markDataAsConstant(self, data: ghidra.program.model.listing.Data):
        ...


class DWARFAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def isAlreadyImported(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if DWARF has already been imported into the specified program.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to check
        :return: true if DWARF has already been imported, false if not yet
        :rtype: bool
        """


class ExternalSymbolResolverAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    :obj:`Analyzer` to link unresolved symbols
    
    
    .. seealso::
    
        | :obj:`ExternalSymbolResolver`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new :obj:`ExternalSymbolResolverAnalyzer`
        """


class ObjectiveC1_ClassAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class MinGWPseudoRelocationHandler(java.lang.Object):
    """
    MinGW pseudo-relocation handler
    """

    @typing.type_check_only
    class ExternalIATSymbolMap(java.util.HashMap[ghidra.program.model.address.Address, MinGWPseudoRelocationHandler.ExternalIATSymbol]):
        """
        Maps IAT addresses to EXTERNAL block allocation identified by :obj:`ExternalIATSymbol`
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalIATSymbol(java.lang.Record):
        """
        External Import Address List (IAT) Symbol Record
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def extAddr(self) -> ghidra.program.model.address.Address:
            ...

        def extLoc(self) -> ghidra.program.model.symbol.ExternalLocation:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]


class OperandReferenceAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Check operand references to memory locations looking for
    Data
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], analyzerType: ghidra.app.services.AnalyzerType):
        ...


@typing.type_check_only
class AnalyzeAllOpenProgramsTask(ghidra.util.task.Task):

    @typing.type_check_only
    class DefaultAnalyzeProgramStrategy(AnalyzeProgramStrategy):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyAnalysisBackgroundCommand(AnalysisBackgroundCommand):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mgr: AutoAnalysisManager):
            ...


    @typing.type_check_only
    class BottomUpCancelledListener(ghidra.util.task.CancelledListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TopDownCancelledListener(ghidra.util.task.CancelledListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnalysisOptions(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ProgramID(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScrollingOptionDialog(docking.widgets.OptionDialog):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]


class ObjectiveC2_ClassAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UpdateAlignmentAction(docking.action.ToggleDockingAction, ghidra.app.util.query.AddressAlignmentListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, model: FindReferencesTableModel, alignment: typing.Union[jpype.JInt, int]):
        ...

    def alignmentChanged(self):
        ...

    def alignmentPermissionChanged(self):
        ...


class AnalyzerEnablementState(java.lang.Object):
    """
    Row objects for the analyzer enablement table
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, analyzer: ghidra.app.services.Analyzer, enabled: typing.Union[jpype.JBoolean, bool], defaultEnablement: typing.Union[jpype.JBoolean, bool]):
        ...

    def getName(self) -> str:
        """
        Returns the analyzer name
        
        :return: the analyzer name
        :rtype: str
        """

    def isDefaultEnablement(self) -> bool:
        """
        Returns if the analyzer's enablement is the default enablement state
        
        :return: if the analyzer's enablement is the default enablement state
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        Returns if the analyzer is currently enabled
        
        :return: if the analyzer is currently enabled
        :rtype: bool
        """

    def isPrototype(self) -> bool:
        """
        Returns true if the analyzer is a prototype
        
        :return: true if the analyzer is a prototype
        :rtype: bool
        """

    def setEnabled(self, enabled: typing.Union[java.lang.Boolean, bool]):
        """
        Sets the enablement state for the analyzer
        
        :param java.lang.Boolean or bool enabled: the new enablement state
        """

    @property
    def defaultEnablement(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def prototype(self) -> jpype.JBoolean:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...


@typing.type_check_only
class RegisterContextBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def clearBitAt(self, instr: ghidra.program.model.listing.Instruction, bit: ghidra.program.model.scalar.Scalar, rightShiftFactor: typing.Union[jpype.JInt, int]) -> bool:
        """
        The specified instr has cleared the specified bit for this context reg.
        If setting fails the value will be left in an unknown state.
        
        :param ghidra.program.model.listing.Instruction instr: instruction which has made the bit modification
        :param ghidra.program.model.scalar.Scalar bit: the bit to be cleared.
        :param jpype.JInt or int rightShiftFactor: value will be subtracted from specified bit to determine actual bit
        to be cleared.
        :return: false if clear not possible (caused by instr not having a fall-through or
        this is a multi-bit register without a previous value setting, or bit is null).
        :rtype: bool
        """

    @typing.overload
    def clearBitAt(self, instr: ghidra.program.model.listing.Instruction, bit: typing.Union[jpype.JInt, int]) -> bool:
        """
        The specified instr has cleared the specified bit for this context reg.
        If setting fails the value will be left in an unknown state.
        
        :param ghidra.program.model.listing.Instruction instr: instruction which has made the bit modification
        :param jpype.JInt or int bit: the bit to be cleared.
        :return: false if clear not possible (caused by instr not having a fall-through or
        this is a multi-bit register without a previous value setting, or bit is null).
        :rtype: bool
        """

    @typing.overload
    def setBitAt(self, instr: ghidra.program.model.listing.Instruction, bit: ghidra.program.model.scalar.Scalar, rightShiftFactor: typing.Union[jpype.JInt, int]) -> bool:
        """
        The specified instr has set the specified bit for this context reg.
        If setting fails the value will be left in an unknown state.
        
        :param ghidra.program.model.listing.Instruction instr: instruction which has made the bit modification
        :param ghidra.program.model.scalar.Scalar bit: the bit to be set.
        :param jpype.JInt or int rightShiftFactor: value will be subtracted from specified bit to determine actual bit
        to be set.
        :return: false if setting not possible (caused by instr not having a fall-through or
        this is a multi-bit register without a previous value setting, or bit is null).
        :rtype: bool
        """

    @typing.overload
    def setBitAt(self, instr: ghidra.program.model.listing.Instruction, bit: typing.Union[jpype.JInt, int]) -> bool:
        """
        The specified instr has set the specified bit for this context reg.
        If setting fails the value will be left in an unknown state.
        
        :param ghidra.program.model.listing.Instruction instr: instruction which has made the bit modification
        :param jpype.JInt or int bit: the bit to be set.
        :return: false if setting not possible (caused by instr not having a fall-through or
        this is a multi-bit register without a previous value setting, or bit is null).
        :rtype: bool
        """


class PefAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def added(self, program: ghidra.program.model.listing.Program, functionSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Creates a reference on any operand that uses
        reads an offset from r2.
        """


class SegmentedCallingConventionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AutoAnalysisPlugin(ghidra.framework.plugintool.Plugin, AutoAnalysisManagerListener):
    """
    AutoAnalysisPlugin
    
    Provides support for auto analysis tasks. Manages a pipeline or priority of
    tasks to run given some event has occurred.
    """

    @typing.type_check_only
    class OneShotAnalyzerAction(ghidra.app.context.ListingContextAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, analyzer: ghidra.app.services.Analyzer):
            ...


    @typing.type_check_only
    class FirstTimeAnalyzedCallback(AutoAnalysisManagerListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def getCategory() -> str:
        ...

    @staticmethod
    def getDescription() -> str:
        ...

    @staticmethod
    def getDescriptiveName() -> str:
        ...


class MachoFunctionStartsAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    An analyzer that creates functions at addresses defined by the Mach-O LC_FUNCTION_STARTS 
    load command.
     
    
    NOTE: It's been observed that not all reported function starts are indeed real functions, so
    this analyzer runs with a lower priority so it doesn't create functions where it shouldn't
    (like on a switch table that Ghidra discovers in an early stage of analysis).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new :obj:`MachoFunctionStartsAnalyzer`
        """


class DefaultDataTypeManagerService(ghidra.app.plugin.core.datamgr.archive.DefaultDataTypeArchiveService, ghidra.app.services.DataTypeManagerService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NonReturningFunctionNames(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AnalysisScheduler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getName(self) -> str:
        ...

    def getPriority(self) -> int:
        ...

    def optionsChanged(self, options: ghidra.framework.options.Options):
        ...

    def registerOptions(self, options: ghidra.framework.options.Options):
        ...

    def runAnalyzer(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        ...

    def runCanceled(self):
        """
        Notify this analyzer that a run has been canceled.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class AnalysisTaskList(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, analysisMgr: AutoAnalysisManager, name: typing.Union[java.lang.String, str]):
        ...

    def add(self, analyzer: ghidra.app.services.Analyzer):
        ...

    def clear(self):
        ...

    def iterator(self) -> java.util.Iterator[AnalysisScheduler]:
        ...

    @typing.overload
    def notifyAdded(self, addr: ghidra.program.model.address.Address):
        ...

    @typing.overload
    def notifyAdded(self, set: ghidra.program.model.address.AddressSetView):
        ...

    def notifyAnalysisEnded(self, program: ghidra.program.model.listing.Program):
        """
        Notifies each analyzer in the list that the analysis session has ended.
        """

    @typing.overload
    def notifyRemoved(self, set: ghidra.program.model.address.AddressSetView):
        ...

    @typing.overload
    def notifyRemoved(self, addr: ghidra.program.model.address.Address):
        ...

    def notifyResume(self):
        ...

    def optionsChanged(self, options: ghidra.framework.options.Options):
        ...

    def registerOptions(self, options: ghidra.framework.options.Options):
        ...


class ArmSymbolAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PefDebugAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class AnalysisPanel(javax.swing.JPanel, java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]
    PROTOTYPE: typing.Final = " (Prototype)"
    COLUMN_ANALYZER_IS_ENABLED: typing.Final = 0
    LAST_USED_OPTIONS_CONFIG: typing.Final = "LAST_USED_OPTIONS_CONFIG"

    def hasChangedValues(self) -> bool:
        ...

    def setToLastUsedAnalysisOptionsIfProgramNotAnalyzed(self):
        ...

    def updateOptionForAllPrograms(self, analyzerName: typing.Union[java.lang.String, str], enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Updates the enablement of the given analyzer for all programs being analyzed.
         
        
        A couple notes about this:
             
        1. 
            When a user toggles the status of an analyzer we need to update that status for
        EVERY open program. We don't want a situation where a user turns a particular
        analyzer off, but it's only turned off for the selected program.
        
        2. 
        Programs with different architectures may have different available analyzers, but we
        don't worry about that here because this class is only handed programs with
        similar architectures. If this were to ever change we would need to revisit this.
        
        
        
        :param java.lang.String or str analyzerName: the name of the analyzer to update
        :param jpype.JBoolean or bool enabled: if true, enable the analyzer; otherwise disable it
        """


class ElfScalarOperandAnalyzer(ScalarOperandAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FindReferencesTableModel(ghidra.app.util.query.AlignedObjectBasedPreviewTableModel[ReferenceAddressPair]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fromAddr: ghidra.program.model.address.Address, provider: ghidra.framework.plugintool.ServiceProvider, prog: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def __init__(self, fromAddresses: ghidra.program.model.address.AddressSetView, tool: ghidra.framework.plugintool.PluginTool, prog: ghidra.program.model.listing.Program):
        ...


class ObjectiveC2_MessageAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AutoAnalysisManagerListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def analysisEnded(self, manager: AutoAnalysisManager, isCancelled: typing.Union[jpype.JBoolean, bool]):
        ...


class MingwRelocationAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnalysisBackgroundCommand(ghidra.framework.cmd.MergeableBackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Background task to artificially kick off Auto analysis by
    calling anything that analyzes bytes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mgr: AutoAnalysisManager, markAsAnalyzed: typing.Union[jpype.JBoolean, bool]):
        """
        Background Command to perform Auto Analysis on a program.
        
        :param AutoAnalysisManager mgr: the program's AutoAnalysisManager.
        :param jpype.JBoolean or bool markAsAnalyzed: true to set the analyzed flag after analysis.
        """


class AnalysisTask(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, scheduler: AnalysisScheduler, log: ghidra.app.util.importer.MessageLog):
        ...


class DataOperandReferenceAnalyzer(OperandReferenceAnalyzer):
    """
    Check operand references to memory locations looking for
    Data
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AnalysisWorker(java.lang.Object):
    """
    ``AnalysisWorker`` provides an analysis callback which will be 
    invoked while analysis is suspended.
    """

    class_: typing.ClassVar[java.lang.Class]

    def analysisWorkerCallback(self, program: ghidra.program.model.listing.Program, workerContext: java.lang.Object, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Analysis worker callback which performs the desired changes to program
        while analysis is suspended.
        
        :param ghidra.program.model.listing.Program program: target program
        :param java.lang.Object workerContext: worker context provided to AutoAnalysisManager when
        worker was scheduled.
        :param ghidra.util.task.TaskMonitor monitor: worker monitor
        :return: final return to blocked invocation of scheduleWorker or false
        if worker was cancelled
        :rtype: bool
        :raises CancelledException: operation was cancelled
        :raises java.lang.Exception: if worker exception occurs
        
        .. seealso::
        
            | :obj:`AutoAnalysisManager.scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)`
        """

    def getWorkerName(self) -> str:
        """
        Returns worker name to be used for analysis task monitor.
        Name should be very short.
        
        :return: worker name
        :rtype: str
        """

    @property
    def workerName(self) -> java.lang.String:
        ...


class NoReturnFunctionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProjectPathChooserEditor(java.beans.PropertyEditorSupport):
    """
    Bean editor to show a text field and a browse button to bring
    up a Domain File Chooser dialog.  The path of the chosen domain file is returned as
    a String value.
    """

    @typing.type_check_only
    class ProjectFileChooserPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TextListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], filter: ghidra.framework.model.DomainFileFilter):
        ...


class GolangStringAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Analyzer that finds Golang strings (and optionally slices) and marks up the found instances.
     
    
    The char[] data for Golang strings does not contain null terminators, so the normal logic already
    built into Ghidra to find terminated strings doesn't work.
     
    
    This implementation looks for data that matches what a Golang string 
    struct { char* data, long len } would look like, and follows the pointer to the char[] data 
    and creates a fixed-length string at that location using the length info from the struct.
     
    
    The string struct is found in a couple of different ways:
     
    * References from an instruction (see markupStaticStructRefsInFunction)
    * Iterating through data segments and making educated guesses (see markupDataSegmentStructs)
    
    Some char[] data is only referenced from Golang string structs that exist temporarily
    in registers after being set by an instruction that statically references the char[] data,
    and an instruction that statically contains the length. (see tryCreateInlineString) 
     
    
    Because slice structures can look like string structs, possible string struct locations are also
    examined for slice-ness.  When marking a struct as a slice instead of as a string, the data
    pointed to by the slice is not marked up because there is no information about the size of the
    elements that the slice points to.
    """

    @typing.type_check_only
    class GolangStringAnalyzerOptions(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ScalarOperandAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...


class ConstantPropagationContextEvaluator(ghidra.program.util.ContextEvaluatorAdapter):
    """
    The ConstantPropogatorEvaluator is used as the evaluator for the SymbolicPropagator when finding constant
    references and laying them down for a generic processor.  Extend this class to add additional checks
    and behaviors necessary for a unique processor such as the PowerPC.
     
    This implementation checks values that are problematic and will not make references to those locations.
        0-256, 0xffffffff, 0xffff, 0xfffffffe
    For some embedded processors these locations or these locations in certain address spaces are OK,
    so the evaluateConstant and evaluateReference should be overridden.
     
    The base implementation supports setting of an option to trust values read from writable memory.
     
    An addressset of locations that were computed jump flows where the flow is unknown is
    available in a destination address set.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, trustMemoryWrite: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param ghidra.util.task.TaskMonitor monitor: TODO
        :param jpype.JBoolean or bool trustMemoryWrite: - true to trust values read from memory that is marked writable
        """

    @typing.overload
    def __init__(self, monitor: ghidra.util.task.TaskMonitor, trustWriteMemOption: typing.Union[jpype.JBoolean, bool], minStoreLoadRefAddress: typing.Union[jpype.JLong, int], minSpeculativeRefAddress: typing.Union[jpype.JLong, int], maxSpeculativeRefAddress: typing.Union[jpype.JLong, int]):
        ...

    def allowAccess(self, context: ghidra.program.util.VarnodeContext, addr: ghidra.program.model.address.Address) -> bool:
        """
        Trust access to writable memory based on initialized option.
        """

    def evaluateConstant(self, context: ghidra.program.util.VarnodeContext, instr: ghidra.program.model.listing.Instruction, pcodeop: typing.Union[jpype.JInt, int], constant: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.address.Address:
        """
        If you override this method, and the default behavior of checking 0-256 and mask values is desired,
        call super.evaluateConstant() in your overriden method.
        """

    def evaluateDestination(self, context: ghidra.program.util.VarnodeContext, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Add instructions to destination set for unknown computed branches.
        """

    def evaluateReference(self, context: ghidra.program.util.VarnodeContext, instr: ghidra.program.model.listing.Instruction, pcodeop: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType) -> bool:
        """
        If you override this method, and the default behavior of checking 0-256 and mask values is desired,
        call super.evaluateReference() in your overriden method.
        """

    def getDestinationSet(self) -> ghidra.program.model.address.AddressSet:
        """
        The computed destination set is useful if follow on switch analysis is to be done.
        
        :return: a set of destinations that have computed flow where the flow is unknown
        :rtype: ghidra.program.model.address.AddressSet
        """

    def setCreateComplexDataFromPointers(self, doCreateData: typing.Union[jpype.JBoolean, bool]) -> ConstantPropagationContextEvaluator:
        """
        Set option to create complex data for pointers if the datatype is known
        
        :param jpype.JBoolean or bool doCreateData: true to create complex data types if the data type is known
        :return: this
        :rtype: ConstantPropagationContextEvaluator
        """

    def setMaxSpeculativeOffset(self, maxSpeculativeRefAddress: typing.Union[jpype.JLong, int]) -> ConstantPropagationContextEvaluator:
        """
        Set maximum speculative memory offset for references
        
        :param jpype.JLong or int maxSpeculativeRefAddress: maximum address offset
        :return: this
        :rtype: ConstantPropagationContextEvaluator
        """

    def setMinSpeculativeOffset(self, minSpeculativeRefAddress: typing.Union[jpype.JLong, int]) -> ConstantPropagationContextEvaluator:
        """
        Set minimum speculative memory offset for references
        
        :param jpype.JLong or int minSpeculativeRefAddress: minimum address offset
        :return: this
        :rtype: ConstantPropagationContextEvaluator
        """

    def setMinStoreLoadOffset(self, minStoreLoadRefAddress: typing.Union[jpype.JLong, int]) -> ConstantPropagationContextEvaluator:
        """
        Set maximum speculative memory offset for references
        
        :param jpype.JLong or int minStoreLoadRefAddress: maximum address offset
        :return: this
        :rtype: ConstantPropagationContextEvaluator
        """

    def setTrustWritableMemory(self, trustWriteableMemOption: typing.Union[jpype.JBoolean, bool]) -> ConstantPropagationContextEvaluator:
        """
        Set option to trust reads from memory that is marked writeable
        
        :param jpype.JBoolean or bool trustWriteableMemOption: true to trust values read from memory that is marked writable
        :return: this
        :rtype: ConstantPropagationContextEvaluator
        """

    @property
    def destinationSet(self) -> ghidra.program.model.address.AddressSet:
        ...


class FindNoReturnFunctionsAnalyzer(ghidra.app.services.AbstractAnalyzer):
    """
    Identifies functions to which Jump references exist and converts the
    associated branching instruction flow to a CALL-RETURN
    """

    @typing.type_check_only
    class NoReturnLocations(ghidra.app.tablechooser.AddressableRowObject):

        class_: typing.ClassVar[java.lang.Class]

        def getExplanation(self) -> str:
            ...

        def getNoReturnAddr(self) -> ghidra.program.model.address.Address:
            ...

        def getWhyAddr(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def noReturnAddr(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def whyAddr(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def explanation(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], analyzerType: ghidra.app.services.AnalyzerType):
        ...

    def added(self, prog: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Called when a function has been added. Looks at address for call
        reference
        
        :raises CancelledException: if monitor is cancelled
        """


class ApplyDataArchiveAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ReferenceAddressPair(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: ghidra.program.model.address.Address, destination: ghidra.program.model.address.Address):
        ...

    def getDestination(self) -> ghidra.program.model.address.Address:
        ...

    def getSource(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def destination(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def source(self) -> ghidra.program.model.address.Address:
        ...


class ObjectiveC2_DecompilerMessageAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SwitchAnalysisDecompileConfigurer(ghidra.app.decompiler.parallel.DecompileConfigurer):
    """
    A configurer for performing switch analysis.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p: ghidra.program.model.listing.Program):
        ...


class ConventionAnalysisDecompileConfigurer(ghidra.app.decompiler.parallel.DecompileConfigurer):
    """
    A configurer for performing calling convention analysis.
    """

    class_: typing.ClassVar[java.lang.Class]


class DecompilerSwitchAnalyzer(ghidra.app.services.AbstractAnalyzer):

    @typing.type_check_only
    class FindFunctionCallback(generic.concurrent.QCallback[ghidra.program.model.address.Address, ghidra.program.model.listing.Function]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS: typing.Final = 60

    def __init__(self):
        ...


class DecompilerFunctionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]
    OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS: typing.Final = 60

    def __init__(self):
        ...


class DecompilerCallConventionAnalyzer(ghidra.app.services.AbstractAnalyzer):

    @typing.type_check_only
    class DecompilerFactory(generic.cache.CountingBasicFactory[ghidra.app.decompiler.DecompInterface]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ParallelDecompilerCallback(generic.concurrent.QRunnable[ghidra.program.model.address.Address]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS: typing.Final = 60

    def __init__(self):
        ...



__all__ = ["ObjectiveC1_MessageAnalyzer", "AnalysisOptionsDialog", "OneShotAnalysisCommand", "GolangSymbolAnalyzer", "AnalyzeProgramStrategy", "StoredAnalyzerTimes", "SwiftTypeMetadataAnalyzer", "AnalysisOptionsUpdater", "MinGWPseudoRelocList", "AnalysisOptionsEditor", "EmbeddedMediaAnalyzer", "StoredAnalyzerTimesPropertyEditor", "AnalysisEnablementTableModel", "CliMetadataTokenAnalyzer", "AbstractDemanglerAnalyzer", "AutoAnalysisManager", "FindPossibleReferencesPlugin", "TransientProgramProperties", "ConstantPropagationAnalyzer", "DWARFAnalyzer", "ExternalSymbolResolverAnalyzer", "ObjectiveC1_ClassAnalyzer", "MinGWPseudoRelocationHandler", "OperandReferenceAnalyzer", "AnalyzeAllOpenProgramsTask", "ObjectiveC2_ClassAnalyzer", "UpdateAlignmentAction", "AnalyzerEnablementState", "RegisterContextBuilder", "PefAnalyzer", "SegmentedCallingConventionAnalyzer", "AutoAnalysisPlugin", "MachoFunctionStartsAnalyzer", "DefaultDataTypeManagerService", "NonReturningFunctionNames", "AnalysisScheduler", "AnalysisTaskList", "ArmSymbolAnalyzer", "PefDebugAnalyzer", "AnalysisPanel", "ElfScalarOperandAnalyzer", "FindReferencesTableModel", "ObjectiveC2_MessageAnalyzer", "AutoAnalysisManagerListener", "MingwRelocationAnalyzer", "AnalysisBackgroundCommand", "AnalysisTask", "DataOperandReferenceAnalyzer", "AnalysisWorker", "NoReturnFunctionAnalyzer", "ProjectPathChooserEditor", "GolangStringAnalyzer", "ScalarOperandAnalyzer", "ConstantPropagationContextEvaluator", "FindNoReturnFunctionsAnalyzer", "ApplyDataArchiveAnalyzer", "ReferenceAddressPair", "ObjectiveC2_DecompilerMessageAnalyzer", "SwitchAnalysisDecompileConfigurer", "ConventionAnalysisDecompileConfigurer", "DecompilerSwitchAnalyzer", "DecompilerFunctionAnalyzer", "DecompilerCallConventionAnalyzer"]
