from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.services
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.util.task
import java.awt # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.lang.ref # type: ignore
import java.net # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore


C = typing.TypeVar("C")
K = typing.TypeVar("K")
R = typing.TypeVar("R")
T = typing.TypeVar("T")
U = typing.TypeVar("U")


class DefaultTransactionCoalescer(TransactionCoalescer, typing.Generic[T, U]):

    @typing.type_check_only
    class Coalescer(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, description: typing.Union[java.lang.String, str]):
            ...


    class DefaultCoalescedTx(TransactionCoalescer.CoalescedTx):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, obj: T, factory: TransactionCoalescer.TxFactory[T, U], delayMs: typing.Union[jpype.JInt, int]):
        ...


class AbstractMappedMemoryBytesVisitor(java.lang.Object):
    """
    An object for visiting the memory of mapped programs on a block-by-block basis
    
     
    
    The task for reading portions of program memory from the perspective of a trace, via the static
    mapping service turns out to be fairly onerous. This class attempts to ease that logic. In its
    simplest use, the client need only implement :meth:`visitData(Address, byte[], int) <.visitData>` and provide
    a reference to the mapping service. Then, calling :meth:`visit(Trace, long, AddressSetView) <.visit>`
    will result in several calls to :meth:`visitData(Address, byte[], int) <.visitData>`, which will provide the
    bytes from the mapped programs, along with the trace address where they apply.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mappingService: ghidra.app.services.DebuggerStaticMappingService, buffer: jpype.JArray[jpype.JByte]):
        """
        Construct a visitor object
        
        :param ghidra.app.services.DebuggerStaticMappingService mappingService: the mapping service
        :param jpype.JArray[jpype.JByte] buffer: a buffer for the data. This is passed directly into
                    :meth:`visitData(Address, byte[], int) <.visitData>`. If a mapped range exceeds the buffer
                    size, the range is broken down into smaller pieces.
        """

    def visit(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], hostView: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Visit a trace's mapped programs
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snapshot for the mappings
        :param ghidra.program.model.address.AddressSetView hostView: the address set (per the trace's "host" platform)
        :return: true if any range was visited
        :rtype: bool
        :raises MemoryAccessException: upon the first read failure
        """


class BackgroundUtils(java.lang.Enum[BackgroundUtils]):

    class AsyncBackgroundCommand(ghidra.framework.cmd.BackgroundCommand[T], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class PluginToolExecutorService(java.util.concurrent.AbstractExecutorService):

        class TaskOpt(java.lang.Enum[BackgroundUtils.PluginToolExecutorService.TaskOpt]):

            class_: typing.ClassVar[java.lang.Class]
            CAN_CANCEL: typing.Final[BackgroundUtils.PluginToolExecutorService.TaskOpt]
            HAS_PROGRESS: typing.Final[BackgroundUtils.PluginToolExecutorService.TaskOpt]
            IS_MODAL: typing.Final[BackgroundUtils.PluginToolExecutorService.TaskOpt]
            IS_BACKGROUND: typing.Final[BackgroundUtils.PluginToolExecutorService.TaskOpt]

            @staticmethod
            def valueOf(name: typing.Union[java.lang.String, str]) -> BackgroundUtils.PluginToolExecutorService.TaskOpt:
                ...

            @staticmethod
            def values() -> jpype.JArray[BackgroundUtils.PluginToolExecutorService.TaskOpt]:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], obj: ghidra.framework.model.DomainObject, delay: typing.Union[jpype.JInt, int], *opts: BackgroundUtils.PluginToolExecutorService.TaskOpt):
            ...

        def getLastMonitor(self) -> ghidra.util.task.TaskMonitor:
            ...

        @property
        def lastMonitor(self) -> ghidra.util.task.TaskMonitor:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def asyncModal(tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool], futureProducer: java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]]) -> java.util.concurrent.CompletableFuture[T]:
        """
        Launch a task with an attached monitor dialog
         
         
        
        The returned future includes error handling, so even if the task completes in error, the
        returned future will just complete with null. If further error handling is required, then the
        ``futureProducer`` should make the future available. This differs from
        :meth:`async(PluginTool, DomainObject, String, boolean, boolean, boolean, BiFunction) <.async>`
        in that it doesn't use the tool's task manager, so it can run in parallel with other tasks.
        There is not currently a supported method to run multiple non-modal tasks concurrently, since
        they would have to share a single task monitor component.
        
        :param T: the type of the result:param ghidra.framework.plugintool.PluginTool tool: the tool for displaying the dialog
        :param java.lang.String or str name: a name / title for the task
        :param jpype.JBoolean or bool hasProgress: true if the dialog should include a progress bar
        :param jpype.JBoolean or bool canCancel: true if the dialog should include a cancel button
        :param java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]] futureProducer: a function to start the task
        :return: a future which completes when the task is finished.
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    @staticmethod
    def async_(tool: ghidra.framework.plugintool.PluginTool, obj: T, name: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], futureProducer: java.util.function.BiFunction[T, ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[typing.Any]]) -> BackgroundUtils.AsyncBackgroundCommand[T]:
        """
        Launch a task with an attached monitor dialog
         
         
        
        The returned future includes error handling, so even if the task completes in error, the
        returned future will just complete with null. If further error handling is required, then the
        ``futureProducer`` should make the future available. Because this uses the tool's task
        scheduler, only one task can be pending at a time, even if the current stage is running on a
        separate executor, because the tool's task execution thread will wait on the future result.
        You may run stages in parallel, or include stages on which the final stage does not depend;
        however, once the final stage completes, the dialog will disappear, even though other stages
        may remain executing in the background. See
        :meth:`asyncModal(PluginTool, String, boolean, boolean, Function) <.asyncModal>`.
        
        :param T: the type of the result:param ghidra.framework.plugintool.PluginTool tool: the tool for displaying the dialog and scheduling the task
        :param T obj: an object on which to open a transaction
        :param java.lang.String or str name: a name / title for the task
        :param jpype.JBoolean or bool hasProgress: true if the task has progress
        :param jpype.JBoolean or bool canCancel: true if the task can be cancelled
        :param jpype.JBoolean or bool isModal: true to display a modal dialog, false to use the tool's background monitor
        :param java.util.function.BiFunction[T, ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[typing.Any]] futureProducer: a function to start the task
        :return: a future which completes when the task is finished.
        :rtype: BackgroundUtils.AsyncBackgroundCommand[T]
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BackgroundUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[BackgroundUtils]:
        ...


class ManagedDomainObject(java.lang.AutoCloseable):

    @typing.type_check_only
    class ObjectState(java.lang.Runnable):

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> ghidra.framework.model.DomainObject:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CLEANER: typing.Final[java.lang.ref.Cleaner]

    def __init__(self, file: ghidra.framework.model.DomainFile, okToUpgrade: typing.Union[jpype.JBoolean, bool], okToRecover: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        ...

    def get(self) -> ghidra.framework.model.DomainObject:
        ...


class TransactionCoalescer(java.lang.Object):

    class TxFactory(java.util.function.BiFunction[T, java.lang.String, U], typing.Generic[T, U]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class CoalescedTx(java.lang.AutoCloseable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def start(self, description: typing.Union[java.lang.String, str]) -> TransactionCoalescer.CoalescedTx:
        ...


class MiscellaneousUtils(java.lang.Enum[MiscellaneousUtils]):

    class_: typing.ClassVar[java.lang.Class]
    HEX_BIT64: typing.Final[java.lang.String]

    @staticmethod
    def getEditorComponent(editor: java.beans.PropertyEditor) -> java.awt.Component:
        """
        Obtain a swing component which may be used to edit the property.
         
         
        
        This has was originally stolen from :meth:`EditorState.getEditorComponent() <EditorState.getEditorComponent>`, which seems
        entangled with Ghidra's whole options system. Can that be factored out? Since then, the two
        have drifted apart.
        
        :param java.beans.PropertyEditor editor: the editor for which to obtain an interactive component for editing
        :return: the component
        :rtype: java.awt.Component
        """

    @staticmethod
    def lengthMin(a: typing.Union[jpype.JLong, int], b: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def lengthToString(length: typing.Union[jpype.JLong, int]) -> str:
        ...

    @staticmethod
    def parseLength(text: typing.Union[java.lang.String, str], defaultVal: typing.Union[jpype.JLong, int]) -> int:
        """
        Parses a value from 1 to ``1<<64``. Any value outside the range is "clipped" into the
        range.
         
         
        
        Note that a returned value of 0 indicates 2 to the power 64, which is just 1 too high to fit
        into a 64-bit long.
        
        :param java.lang.String or str text: the text to parse
        :param jpype.JLong or int defaultVal: the default value should parsing fail altogether
        :return: the length, where 0 indicates ``1 << 64``.
        :rtype: int
        """

    @staticmethod
    def revalidateLengthByRange(range: ghidra.program.model.address.AddressRange, length: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def rigFocusAndEnter(c: java.awt.Component, runnable: java.lang.Runnable):
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MiscellaneousUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[MiscellaneousUtils]:
        ...


class DebouncedRowWrappedEnumeratedColumnTableModel(docking.widgets.table.RowWrappedEnumeratedColumnTableModel[C, K, R, T], typing.Generic[C, K, R, T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, name: typing.Union[java.lang.String, str], colType: java.lang.Class[C], keyFunc: java.util.function.Function[T, K], wrapper: java.util.function.Function[T, R], getter: java.util.function.Function[R, T]):
        ...


class ProgramLocationUtils(java.lang.Enum[ProgramLocationUtils]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def fixLocation(loc: ghidra.program.util.ProgramLocation, matchSnap: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.util.ProgramLocation:
        """
        Swap out the trace view of a :obj:`ProgramLocation` if it is not the canonical view
         
         
        
        If the program location is not associated with a trace, the same location is returned.
        Otherwise, this ensures that the given view is the canonical one for the same trace. If
        matchSnap is true, the view is only replaced when the replacement shares the same snap.
        
        :param location: a location possibly in a trace view:param jpype.JBoolean or bool matchSnap: true to only replace is snap matches, false to always replace
        :return: the adjusted location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @staticmethod
    def replaceAddress(loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        ...

    @staticmethod
    def replaceProgram(loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program) -> ghidra.program.util.ProgramLocation:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramLocationUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[ProgramLocationUtils]:
        ...


class ProgramURLUtils(java.lang.Enum[ProgramURLUtils]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDomainFileFromOpenProject(project: ghidra.framework.model.Project, url: java.net.URL) -> ghidra.framework.model.DomainFile:
        """
        Get the domain file for the given URL from the given project or any of its open views.
         
         
        
        The URL may point to a file in a local or shared project. If the URL points to a shared
        project and there is a local checkout of the file, this will return the checked out copy,
        even though it may not be the latest from the repository (or maybe even hijacked). If the
        containing project is not currently open, this will return ``null``.
        
        :param ghidra.framework.model.Project project: the active project
        :param java.net.URL url: the URL of the domain file
        :return: the domain file, or null
        :rtype: ghidra.framework.model.DomainFile
        """

    @staticmethod
    def getUrlFromProgram(program: ghidra.program.model.listing.Program) -> java.net.URL:
        """
        Get any URL for the given program, preferably its URL in a shared project.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the URL or null, if the program does not belong to a project
        :rtype: java.net.URL
        """

    @staticmethod
    def isProjectDataURL(data: ghidra.framework.model.ProjectData, url: java.net.URL) -> bool:
        ...

    @staticmethod
    def openDomainFileFromOpenProject(programManager: ghidra.app.services.ProgramManager, project: ghidra.framework.model.Project, url: java.net.URL, state: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Open the domain file for the given URL from the given project or any of its open views.
         
         
        
        This uses :meth:`getDomainFileFromOpenProject(Project, URL) <.getDomainFileFromOpenProject>` to locate the domain file, so
        see its behavior and caveats. It opens the default version of the file. If the file does not
        exist, or its project is not currently open, this returns ``null``.
        
        :param ghidra.app.services.ProgramManager programManager: the program manager
        :param ghidra.framework.model.Project project: the active project
        :param java.net.URL url: the URL fo the domain file
        :param jpype.JInt or int state: the initial open state of the program in the manager
        :return: the program or null
        :rtype: ghidra.program.model.listing.Program
        
        .. seealso::
        
            | :obj:`.getDomainFileFromOpenProject(Project, URL)`
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramURLUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[ProgramURLUtils]:
        ...



__all__ = ["DefaultTransactionCoalescer", "AbstractMappedMemoryBytesVisitor", "BackgroundUtils", "ManagedDomainObject", "TransactionCoalescer", "MiscellaneousUtils", "DebouncedRowWrappedEnumeratedColumnTableModel", "ProgramLocationUtils", "ProgramURLUtils"]
