from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api
import ghidra.debug.api.target
import ghidra.program.model.listing
import ghidra.trace.model
import ghidra.trace.model.target.schema
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class TraceRmiLaunchOffer(java.lang.Object):
    """
    An offer to launch a program with a given mechanism
     
     
    
    Typically each offer is configured with the program it's going to launch, and knows how to work a
    specific connector and platform to obtain a target executing the program's image. The mechanisms
    may vary wildly from platform to platform.
    """

    class LaunchResult(java.lang.Record, java.lang.AutoCloseable):
        """
        The result of launching a program
         
         
        
        The launch may not always be completely successful. Instead of tearing things down, partial
        launches are left in place, in case the user wishes to repair/complete the steps manually. If
        the result includes a connection, then at least that was successful. If not, then the caller
        can choose how to treat the terminal sessions. If the cause of failure was an exception, it
        is included. If the launch succeeded, but module mapping failed, the result will include a
        trace and the exception. If an error occurred in the shell script, it may not be communicated
        here, but instead displayed only in the terminal.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, sessions: collections.abc.Mapping, acceptor: TraceRmiAcceptor, connection: TraceRmiConnection, trace: ghidra.trace.model.Trace, exception: java.lang.Throwable):
            ...

        def acceptor(self) -> TraceRmiAcceptor:
            ...

        def connection(self) -> TraceRmiConnection:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def exception(self) -> java.lang.Throwable:
            ...

        def hashCode(self) -> int:
            ...

        def program(self) -> ghidra.program.model.listing.Program:
            ...

        def sessions(self) -> java.util.Map[java.lang.String, TerminalSession]:
            ...

        def showTerminals(self):
            ...

        def toString(self) -> str:
            ...

        def trace(self) -> ghidra.trace.model.Trace:
            ...


    class RelPrompt(java.lang.Enum[TraceRmiLaunchOffer.RelPrompt]):
        """
        When programmatically customizing launch configuration, describes callback timing relative to
        prompting the user.
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[TraceRmiLaunchOffer.RelPrompt]
        """
        The user is not prompted for parameters. This will be the only callback.
        """

        BEFORE: typing.Final[TraceRmiLaunchOffer.RelPrompt]
        """
        The user will be prompted. This callback can pre-populate suggested parameters. Another
        callback will be issued if the user does not cancel.
        """

        AFTER: typing.Final[TraceRmiLaunchOffer.RelPrompt]
        """
        The user has confirmed the parameters. This callback can validate or override the users
        parameters. Overriding the user is discouraged. This is the final callback.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceRmiLaunchOffer.RelPrompt:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceRmiLaunchOffer.RelPrompt]:
            ...


    class PromptMode(java.lang.Enum[TraceRmiLaunchOffer.PromptMode]):

        class_: typing.ClassVar[java.lang.Class]
        ALWAYS: typing.Final[TraceRmiLaunchOffer.PromptMode]
        """
        The user is always prompted for parameters.
        """

        NEVER: typing.Final[TraceRmiLaunchOffer.PromptMode]
        """
        The user is never prompted for parameters.
        """

        ON_ERROR: typing.Final[TraceRmiLaunchOffer.PromptMode]
        """
        The user is prompted after an error.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceRmiLaunchOffer.PromptMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceRmiLaunchOffer.PromptMode]:
            ...


    class LaunchConfigurator(java.lang.Object):
        """
        Callbacks for custom configuration when launching a program
        """

        class_: typing.ClassVar[java.lang.Class]
        NOP: typing.Final[TraceRmiLaunchOffer.LaunchConfigurator]

        def configureLauncher(self, offer: TraceRmiLaunchOffer, arguments: collections.abc.Mapping, relPrompt: TraceRmiLaunchOffer.RelPrompt) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
            """
            Re-write the launcher arguments, if desired
            
            :param TraceRmiLaunchOffer offer: the offer that will create the target
            :param collections.abc.Mapping arguments: the arguments suggested by the offer or saved settings
            :param TraceRmiLaunchOffer.RelPrompt relPrompt: describes the timing of this callback relative to prompting the user
            :return: the adjusted arguments
            :rtype: java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]
            """

        def getPromptMode(self) -> TraceRmiLaunchOffer.PromptMode:
            """
            Determine whether the user should be prompted to confirm launch parameters
            
            :return: the prompt mode
            :rtype: TraceRmiLaunchOffer.PromptMode
            """

        @property
        def promptMode(self) -> TraceRmiLaunchOffer.PromptMode:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getConfigName(self) -> str:
        """
        A name so that this offer can be recognized later
         
         
        
        The name is saved to configuration files, so that user preferences and priorities can be
        memorized. The opinion will generate each offer fresh each time, so it's important that the
        "same offer" have the same configuration name. Note that the name *cannot* depend on
        the program name, but can depend on the model factory and program language and/or compiler
        spec. This name cannot contain semicolons (``;``).
        
        :return: the configuration name
        :rtype: str
        """

    def getDescription(self) -> str:
        """
        Get an HTML description of the connector
        
        :return: the description
        :rtype: str
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Get the location for additional help about this specific offer
         
         
        
        The default is just the entry on Trace RMI launchers in general.
        
        :return: the location
        :rtype: ghidra.util.HelpLocation
        """

    def getIcon(self) -> javax.swing.Icon:
        """
        Get the icon displayed in the UI for this offer
         
         
        
        Please take care when overriding this that the icon still clearly indicates the target will
        be executed. Changing it, e.g., to the same icon as "Step" would be an unwelcome prank. A
        more reasonable choice would be the standard ``"icon.debugger"`` plus an overlay, or the
        branding of the underlying technology, e.g., QEMU or GDB.
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getMenuGroup(self) -> str:
        """
        Get the menu group for the offer
         
         
        
        Especially for entries immediately under to "Debugger.Debug [imagePath]", specifies the menu
        group. A package that introduces a large number of offers should instead consider
        :meth:`sub menus <.getMenuPath>`.
        
        :return: the menu group
        :rtype: str
        """

    def getMenuOrder(self) -> str:
        """
        Controls the position in the menu (within its group) of the entry
         
         
        
        The menus will always be presented in the same order, barring any changes to the plugins or
        launcher properties. Groups are alphabetized and visually separated. Then sub groups are
        alphabetized, but *not* visually separated. Finally, offers are alphabetized by their
        final path element, usually the title.
         
         
        
        The order of entries in the quick-launch drop-down menu is always most-recently to
        least-recently used. An entry that has never been used does not appear in the quick launch
        menu.
        
        :return: the sub-group name for ordering in the menu
        :rtype: str
        """

    def getMenuPath(self) -> java.util.List[java.lang.String]:
        """
        Get the menu path subordinate to "Debugger.Debug [imagePath]" for this offer.
         
         
        
        By default, this is just the title, i.e., the same as in the quick-launch drop-down menu. A
        package that introduces a large number of offers should override this method to organize
        them. A general rule of thumb is "no more than seven." Except at the level immediately under
        "Debug [imagePath]," no more than seven items should be presented to the user. In some cases,
        it may be more appropriate to group things using :meth:`menu groups <.getMenuGroup>` rather
        than sub menus.
         
         
        
        Organization is very much a matter of taste, but consider that you are cooperating with other
        packages to populate the launcher menu. The top level is especially contentious, but sub
        menus, if named appropriately, are presumed to belong to a single package.
        
        :return: the path
        :rtype: java.util.List[java.lang.String]
        """

    def getParameters(self) -> java.util.Map[java.lang.String, LaunchParameter[typing.Any]]:
        """
        Get the parameter descriptions for the launcher
        
        :return: the parameters
        :rtype: java.util.Map[java.lang.String, LaunchParameter[typing.Any]]
        """

    def getTitle(self) -> str:
        """
        Get the text displayed in the quick-launch drop-down menu.
         
         
        
        No two offers should ever have the same title, even if they appear in different sub-menus.
        Otherwise, the user cannot distinguish the offers in the quick-launch drop-down menu.
        
        :return: the menu title
        :rtype: str
        """

    def imageParameter(self) -> LaunchParameter[typing.Any]:
        """
        If present, get the parameter via which this offer expects to receive the current program
        
        :return: the parameter, or null
        :rtype: LaunchParameter[typing.Any]
        """

    @typing.overload
    def launchProgram(self, monitor: ghidra.util.task.TaskMonitor, configurator: TraceRmiLaunchOffer.LaunchConfigurator) -> TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the program using the offered mechanism
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :param TraceRmiLaunchOffer.LaunchConfigurator configurator: the configuration callback
        :return: the launch result
        :rtype: TraceRmiLaunchOffer.LaunchResult
        """

    @typing.overload
    def launchProgram(self, monitor: ghidra.util.task.TaskMonitor) -> TraceRmiLaunchOffer.LaunchResult:
        """
        Launch the program using the offered mechanism
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :return: the launch result
        :rtype: TraceRmiLaunchOffer.LaunchResult
        """

    def requiresImage(self) -> bool:
        """
        Check if this offer requires an open program
        
        :return: true if required
        :rtype: bool
        """

    def supportsImage(self) -> bool:
        """
        Check if this offer presents a parameter for the open program
        
        :return: true if present
        :rtype: bool
        """

    @property
    def configName(self) -> java.lang.String:
        ...

    @property
    def menuOrder(self) -> java.lang.String:
        ...

    @property
    def menuPath(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def title(self) -> java.lang.String:
        ...

    @property
    def menuGroup(self) -> java.lang.String:
        ...

    @property
    def parameters(self) -> java.util.Map[java.lang.String, LaunchParameter[typing.Any]]:
        ...


class RemoteMethod(java.lang.Object):
    """
    A remote method registered by the back-end debugger.
     
     
    
    Remote methods must describe the parameters names and types at a minimum. They should also
    provide a display name and description for the method itself and each of its parameters. These
    methods should not return a result. Instead, any "result" should be recorded into a trace. The
    invocation can result in an error, which is communicated by an exception that can carry only a
    message string. Choice few methods should return a result, for example, the ``execute``
    method with output capture. That output generally does not belong in a trace, so the only way to
    communicate it back to the front end is to return it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def action(self) -> ghidra.debug.api.target.ActionName:
        """
        A string that hints at the UI action this method achieves.
        
        :return: the action
        :rtype: ghidra.debug.api.target.ActionName
        """

    @staticmethod
    def checkType(paramName: typing.Union[java.lang.String, str], schName: ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName, sch: ghidra.trace.model.target.schema.TraceObjectSchema, arg: java.lang.Object):
        """
        Check the type of an argument.
         
         
        
        This is a hack, because :obj:`TraceObjectSchema` expects :obj:`TraceObject`, or a
        primitive. We instead need :obj:`TraceObject`. I'd add the method to the schema, except that
        trace stuff is not in its dependencies.
        
        :param java.lang.String or str paramName: the name of the parameter
        :param ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName schName: the name of the parameter's schema
        :param ghidra.trace.model.target.schema.TraceObjectSchema sch: the type of the parameter
        :param java.lang.Object arg: the argument
        """

    def description(self) -> str:
        """
        A description of the method.
         
         
        
        This is the text for tooltips or other information presented by actions whose purpose is to
        invoke this method. If the back-end command name is well known to its users, this text should
        include that name.
        
        :return: the description
        :rtype: str
        """

    def display(self) -> str:
        """
        A title to display in the UI for this action.
        
        :return: the title
        :rtype: str
        """

    def icon(self) -> javax.swing.Icon:
        """
        The icon to display in menu's and in the prompt dialog.
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def invoke(self, arguments: collections.abc.Mapping) -> java.lang.Object:
        """
        Invoke the remote method and wait for its completion.
         
         
        
        This method cannot be invoked from the Swing thread. This is to avoid locking up the user
        interface. If you are on the Swing thread, consider :meth:`invokeAsync(Map) <.invokeAsync>` instead. You
        can chain the follow-up actions and then schedule any UI updates on the Swing thread using
        :obj:`AsyncUtils.SWING_EXECUTOR`.
        
        :param collections.abc.Mapping arguments: the keyword arguments to the remote method
        :raises IllegalArgumentException: if the arguments are not valid
        :return: the returned value
        :rtype: java.lang.Object
        """

    def invokeAsync(self, arguments: collections.abc.Mapping) -> RemoteAsyncResult:
        """
        Invoke the remote method, getting a future result.
         
         
        
        This invokes the method asynchronously. The returned objects is a :obj:`CompletableFuture`,
        whose getters are overridden to prevent blocking the Swing thread for more than 1 second. Use
        of this method is not recommended, if it can be avoided; however, you should not create a
        thread whose sole purpose is to invoke this method. UI actions that need to invoke a remote
        method should do so using this method, but they must be sure to handle errors using, e.g.,
        using :meth:`CompletableFuture.exceptionally(Function) <CompletableFuture.exceptionally>`, lest the actions fail silently.
        
        :param collections.abc.Mapping arguments: the keyword arguments to the remote method
        :return: the future result
        :rtype: RemoteAsyncResult
        :raises IllegalArgumentException: if the arguments are not valid
        """

    def name(self) -> str:
        """
        The name of the method.
        
        :return: the name
        :rtype: str
        """

    def okText(self) -> str:
        """
        Text to display in the OK button of any prompt dialog.
        
        :return: the text
        :rtype: str
        """

    def parameters(self) -> java.util.Map[java.lang.String, RemoteParameter]:
        """
        The methods parameters.
         
         
        
        Parameters are all keyword-style parameters. This returns a map of names to parameter
        descriptions.
        
        :return: the parameter map
        :rtype: java.util.Map[java.lang.String, RemoteParameter]
        """

    def retType(self) -> ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName:
        """
        Get the schema for the return type.
         
        **NOTE:** Most methods should return void, i.e., either they succeed, or they throw/raise
        an error message. One notable exception is "execute," which may return the console output
        from executing a command. In most cases, the method should only cause an update to the trace
        database. That effect is its result.
        
        :return: the schema name for the method's return type.
        :rtype: ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName
        """

    def validate(self, arguments: collections.abc.Mapping) -> ghidra.trace.model.Trace:
        """
        Validate the given argument.
         
         
        
        This method is for checking parameter sanity before they are marshalled to the back-end. This
        is called automatically during invocation. Clients can use this method to pre-test or
        validate in the UI, when invocation is not yet desired.
        
        :param collections.abc.Mapping arguments: the arguments
        :return: the trace if any object arguments were given, or null
        :rtype: ghidra.trace.model.Trace
        :raises IllegalArgumentException: if the arguments are not valid
        """


class TraceRmiAcceptor(java.lang.Object):
    """
    An acceptor to receive a single Trace RMI connection from a back-end
    """

    class_: typing.ClassVar[java.lang.Class]

    def accept(self) -> TraceRmiConnection:
        """
        Accept a single connection
         
         
        
        This acceptor is no longer valid after the connection is accepted. If accepting the
        connection fails, e.g., because of a timeout, this acceptor is no longer valid.
        
        :return: the connection, if successful
        :rtype: TraceRmiConnection
        :raises IOException: if there was an error
        :raises CancelledException: if :meth:`cancel() <.cancel>` is called, usually from the user canceling
        """

    def cancel(self):
        """
        Cancel the connection
         
         
        
        If a different thread has called :meth:`accept() <.accept>`, it will fail. In this case, both
        :meth:`TraceRmiServiceListener.acceptCancelled(TraceRmiAcceptor) <TraceRmiServiceListener.acceptCancelled>` and
        :meth:`TraceRmiServiceListener.acceptFailed(TraceRmiAcceptor, Exception) <TraceRmiServiceListener.acceptFailed>` may be invoked.
        """

    def getAddress(self) -> java.net.SocketAddress:
        """
        Get the address (and port) where the acceptor is listening
        
        :return: the socket address
        :rtype: java.net.SocketAddress
        """

    def isClosed(self) -> bool:
        """
        Check if the acceptor is actually still accepting.
        
        :return: true if not accepting anymore
        :rtype: bool
        """

    def setTimeout(self, millis: typing.Union[jpype.JInt, int]):
        """
        Set the timeout
        
        :param jpype.JInt or int millis: the number of milliseconds after which an :meth:`accept() <.accept>` will time out.
        :raises SocketException: if there's a protocol error
        """

    @property
    def address(self) -> java.net.SocketAddress:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...


class TraceRmiConnection(java.lang.AutoCloseable):
    """
    A connection to a TraceRmi back end
    
     
    
    TraceRmi is a two-way request-reply channel, usually over TCP. The back end, i.e., the trace-rmi
    plugin hosted in the target platform's actual debugger, is granted a fixed set of
    methods/messages for creating and populating a :obj:`Trace`. Each such trace is designated as a
    target. The back end provides a set of methods for the front-end to use to control the connection
    and its targets. For a given connection, the methods are fixed, but each back end may provide a
    different set of methods to best describe/model its command set. The same methods are applicable
    to all of the back end's target. While uncommon, one back end may create several targets. E.g.,
    if a target creates a child process, and the back-end debugger is configured to remain attached
    to both parent and child, then it should create and publish a second target.
    """

    class_: typing.ClassVar[java.lang.Class]

    def forceCloseTrace(self, trace: ghidra.trace.model.Trace):
        """
        Forcefully remove the given trace from the connection.
         
         
        
        This removes the back end's access to the given trace and removes this connection from the
        trace's list of consumers (thus, freeing it if this was the only remaining consumer.) For all
        intents and purposes, the given trace is no longer a target for this connection.
         
         
        
        **NOTE:** This method should only be used if gracefully killing the target has failed. In
        some cases, it may be better to terminate the entire connection (See :meth:`close() <.close>`) or to
        terminate the back end debugger. The back end gets no notification that its trace was
        forcefully removed. However, subsequent requests involving that trace will result in errors.
        
        :param ghidra.trace.model.Trace trace: the trace to remove
        """

    def forciblyCloseTransactions(self, target: ghidra.debug.api.target.Target):
        """
        Forcibly commit all transactions this connection has on the given trace
         
         
        
        This may cause undefined behavior in the back-end, especially if it still needs the
        transaction.
        
        :param ghidra.debug.api.target.Target target: the the target
        """

    def getDescription(self) -> str:
        """
        Get the client-given description of this connection
         
         
        
        If the connection is still being negotiated, this will return a string indicating that.
        
        :return: the description
        :rtype: str
        """

    def getLastSnapshot(self, trace: ghidra.trace.model.Trace) -> int:
        """
        Get the last snapshot created by the back end for the given trace.
         
         
        
        Back ends that support timeless or time-travel debugging have not been integrated yet, but in
        those cases, we anticipate this method returning the current snapshot (however the back end
        defines that with respect to its own definition of time), whether or not it is the last
        snapshot it created. If the back end has not created a snapshot yet, 0 is returned.
        
        :param ghidra.trace.model.Trace trace: 
        :return: the snapshot number
        :rtype: int
        :raises NoSuchElementException: if the given trace is not a target for this connection
        """

    def getMethods(self) -> RemoteMethodRegistry:
        """
        Get the methods provided by the back end
        
        :return: the method registry
        :rtype: RemoteMethodRegistry
        """

    def getRemoteAddress(self) -> java.net.SocketAddress:
        """
        Get the address of the back end debugger
        
        :return: the address, usually IP of the host and port for the trace-rmi plugin.
        :rtype: java.net.SocketAddress
        """

    def getTargets(self) -> java.util.Collection[ghidra.debug.api.target.Target]:
        """
        Get all the valid targets created by this connection
        
        :return: the collection of valid targets
        :rtype: java.util.Collection[ghidra.debug.api.target.Target]
        """

    @typing.overload
    def isBusy(self) -> bool:
        """
        Check if the connection has a transaction open on any of its targets
         
         
        
        This generally means the connection has an open transaction. If *does not* indicate
        the execution state of the target/debuggee.
        
        :return: true if busy
        :rtype: bool
        """

    @typing.overload
    def isBusy(self, target: ghidra.debug.api.target.Target) -> bool:
        """
        Check if the given target has a transaction open
        
        :param ghidra.debug.api.target.Target target: the target
        :return: true if busy
        :rtype: bool
        """

    def isClosed(self) -> bool:
        """
        Check if the connection has been closed
        
        :return: true if closed, false if still open/valid
        :rtype: bool
        """

    def isTarget(self, trace: ghidra.trace.model.Trace) -> bool:
        """
        Check if the given trace represents one of this connection's targets.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: true if the trace is a target, false otherwise.
        :rtype: bool
        """

    def waitClosed(self):
        """
        Wait for the connection to become closed.
         
         
        
        This is usually just for clean-up purposes during automated testing.
        """

    def waitForTrace(self, timeoutMillis: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.Trace:
        """
        Wait for the first trace created by the back end.
         
         
        
        Typically, a connection handles only a single target. A shell script handles launching the
        back-end debugger, creating its first target, and connecting back to the front end via
        TraceRmi. If a secondary target does appear, it usually happens only after the initial target
        has run. Thus, this method is useful for waiting on and getting and handle to that initial
        target.
        
        :param jpype.JLong or int timeoutMillis: the number of milliseconds to wait for the target
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        :raises TimeoutException: if no trace is created after the given timeout. This usually
                    indicates there was an error launching the initial target, e.g., the target's
                    binary was not found on the target's host.
        """

    @property
    def lastSnapshot(self) -> jpype.JLong:
        ...

    @property
    def methods(self) -> RemoteMethodRegistry:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def closed(self) -> jpype.JBoolean:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def targets(self) -> java.util.Collection[ghidra.debug.api.target.Target]:
        ...

    @property
    def remoteAddress(self) -> java.net.SocketAddress:
        ...

    @property
    def target(self) -> jpype.JBoolean:
        ...


class RemoteMethodRegistry(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def all(self) -> java.util.Map[java.lang.String, RemoteMethod]:
        ...

    def get(self, name: typing.Union[java.lang.String, str]) -> RemoteMethod:
        ...

    def getByAction(self, action: ghidra.debug.api.target.ActionName) -> java.util.Set[RemoteMethod]:
        ...

    @property
    def byAction(self) -> java.util.Set[RemoteMethod]:
        ...


class RemoteAsyncResult(java.util.concurrent.CompletionStage[java.lang.Object], java.util.concurrent.Future[java.lang.Object]):
    """
    The future result of invoking a :obj:`RemoteMethod`.
     
     
    
    While this can technically result in an object, returning values from remote methods is highly
    discouraged. This has led to several issues in the past, including duplication of information
    (and a lot of it) over the connection. Instead, most methods should just update the trace
    database, and the client can retrieve the relevant information from it. One exception might be
    the ``execute`` method. This is typically for executing a CLI command with captured output.
    There is generally no place for such output to go into the trace, and the use cases for such a
    method to return the output are compelling. For other cases, perhaps the most you can do is
    return a :obj:`TraceObject`, so that a client can quickly associate the trace changes with the
    method. Otherwise, please return null/void/None for all methods.
     
     
    
    **NOTE:** To avoid the mistake of blocking the Swing thread on an asynchronous result, the
    :meth:`get() <.get>` methods have been overridden to check for the Swing thread. If invoked on the
    Swing thread with a timeout greater than 1 second, an assertion error will be thrown. Please use
    a non-swing thread, e.g., a task thread or script thread, to wait for results, or chain
    callbacks.
    """

    class_: typing.ClassVar[java.lang.Class]


class LaunchParameter(java.lang.Record, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: java.lang.Class[T], name: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], choices: java.util.List[T], defaultValue: ghidra.debug.api.ValStr[T], decoder: ghidra.debug.api.ValStr.Decoder[T]):
        ...

    @staticmethod
    @typing.overload
    def choices(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], choices: collections.abc.Sequence, defaultValue: ghidra.debug.api.ValStr[T]) -> LaunchParameter[T]:
        ...

    @typing.overload
    def choices(self) -> java.util.List[T]:
        ...

    @staticmethod
    def create(type: java.lang.Class[T], name: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], defaultValue: ghidra.debug.api.ValStr[T], decoder: ghidra.debug.api.ValStr.Decoder[T]) -> LaunchParameter[T]:
        ...

    def decode(self, string: typing.Union[java.lang.String, str]) -> ghidra.debug.api.ValStr[T]:
        ...

    def decoder(self) -> ghidra.debug.api.ValStr.Decoder[T]:
        ...

    def defaultValue(self) -> ghidra.debug.api.ValStr[T]:
        ...

    def description(self) -> str:
        ...

    def display(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def get(self, arguments: collections.abc.Mapping) -> ghidra.debug.api.ValStr[T]:
        ...

    def hashCode(self) -> int:
        ...

    @staticmethod
    @typing.overload
    def mapOf(parameters: collections.abc.Sequence) -> java.util.Map[java.lang.String, LaunchParameter[typing.Any]]:
        ...

    @staticmethod
    @typing.overload
    def mapOf(*parameters: LaunchParameter[typing.Any]) -> java.util.Map[java.lang.String, LaunchParameter[typing.Any]]:
        ...

    def name(self) -> str:
        ...

    def required(self) -> bool:
        ...

    def set(self, arguments: collections.abc.Mapping, value: ghidra.debug.api.ValStr[T]):
        ...

    def toString(self) -> str:
        ...

    def type(self) -> java.lang.Class[T]:
        ...

    @staticmethod
    def validateArguments(parameters: collections.abc.Mapping, arguments: collections.abc.Mapping) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        ...


class TraceRmiError(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class RemoteParameter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def description(self) -> str:
        ...

    def display(self) -> str:
        ...

    def getDefaultValue(self) -> java.lang.Object:
        ...

    def name(self) -> str:
        ...

    def required(self) -> bool:
        ...

    def type(self) -> ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName:
        ...

    @property
    def defaultValue(self) -> java.lang.Object:
        ...


class TerminalSession(java.lang.AutoCloseable):
    """
    A terminal with some back-end element attached to it
    """

    class_: typing.ClassVar[java.lang.Class]

    def content(self) -> str:
        """
        Get the terminal contents as a string (no attributes)
        
        :return: the content
        :rtype: str
        """

    def description(self) -> str:
        """
        Provide a human-readable description of the session
        
        :return: the description
        :rtype: str
        """

    def isTerminated(self) -> bool:
        """
        Check whether the terminal session is terminated or still active
        
        :return: true for terminated, false for active
        :rtype: bool
        """

    def show(self):
        """
        Ensure the session is visible
         
         
        
        The window should be displayed and brought to the front.
        """

    def terminal(self) -> ghidra.app.services.Terminal:
        """
        The handle to the terminal
        
        :return: the handle
        :rtype: ghidra.app.services.Terminal
        """

    def terminate(self):
        """
        Terminate the session without closing the terminal
        
        :raises IOException: if an I/O issue occurs during termination
        """

    def title(self) -> str:
        """
        Get the current title of the terminal
        
        :return: the title
        :rtype: str
        """

    @property
    def terminated(self) -> jpype.JBoolean:
        ...


class TraceRmiServiceListener(java.lang.Object):
    """
    A listener for Trace RMI Service events
    """

    class ConnectMode(java.lang.Enum[TraceRmiServiceListener.ConnectMode]):
        """
        The mechanism for creating a connection
        """

        class_: typing.ClassVar[java.lang.Class]
        CONNECT: typing.Final[TraceRmiServiceListener.ConnectMode]
        """
        The connection was established via :meth:`TraceRmiService.connect(SocketAddress) <TraceRmiService.connect>`
        """

        ACCEPT_ONE: typing.Final[TraceRmiServiceListener.ConnectMode]
        """
        The connection was established via :meth:`TraceRmiService.acceptOne(SocketAddress) <TraceRmiService.acceptOne>`
        """

        SERVER: typing.Final[TraceRmiServiceListener.ConnectMode]
        """
        The connection was established by the server. See :meth:`TraceRmiService.startServer() <TraceRmiService.startServer>`
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceRmiServiceListener.ConnectMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceRmiServiceListener.ConnectMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def acceptCancelled(self, acceptor: TraceRmiAcceptor):
        """
        The client cancelled an inbound acceptor via :meth:`TraceRmiAcceptor.cancel() <TraceRmiAcceptor.cancel>`
        
        :param TraceRmiAcceptor acceptor: the acceptor that was cancelled
        """

    def acceptFailed(self, acceptor: TraceRmiAcceptor, e: java.lang.Exception):
        """
        The service failed to complete an inbound connection
        
        :param TraceRmiAcceptor acceptor: the acceptor that failed
        :param java.lang.Exception e: the exception causing the failure
        """

    def connected(self, connection: TraceRmiConnection, mode: TraceRmiServiceListener.ConnectMode, acceptor: TraceRmiAcceptor):
        """
        A new connection has been established
        
        :param TraceRmiConnection connection: the new connection
        :param TraceRmiServiceListener.ConnectMode mode: the mechanism creating the connection
        :param TraceRmiAcceptor acceptor: if by :meth:`TraceRmiService.acceptOne(SocketAddress) <TraceRmiService.acceptOne>`, the acceptor that
                    created this connection
        """

    def disconnected(self, connection: TraceRmiConnection):
        """
        A connection was lost or closed
         
         
        
        **TODO**: Do we care to indicate why?
        
        :param TraceRmiConnection connection: the connection that has been closed
        """

    def serverStarted(self, address: java.net.SocketAddress):
        """
        The server has been started on the given address
        
        :param java.net.SocketAddress address: the server's address
        """

    def serverStopped(self):
        """
        The server has been stopped
        """

    def targetPublished(self, connection: TraceRmiConnection, target: ghidra.debug.api.target.Target):
        """
        A new target was created by a Trace RMI connection
         
         
        
        The added benefit of this method compared to the :obj:`TargetPublicationListener` is that it
        identifies *which connection*
        
        :param TraceRmiConnection connection: the connection creating the target
        :param ghidra.debug.api.target.Target target: the target
        
        .. seealso::
        
            | :obj:`TargetPublicationListener.targetPublished(Target)`
        
            | :obj:`TargetPublicationListener.targetWithdrawn(Target)`
        """

    def transactionClosed(self, connection: TraceRmiConnection, target: ghidra.debug.api.target.Target, aborted: typing.Union[jpype.JBoolean, bool]):
        """
        A transaction was closed for the given target
         
         
        
        Note, this is different than listening for transactions on the :obj:`Trace` domain object,
        because this only includes those initiated *by the connection*.
        
        :param TraceRmiConnection connection: the connection that closed the transaction
        :param ghidra.debug.api.target.Target target: the target whose trace was modified
        :param jpype.JBoolean or bool aborted: if the transaction was aborted. This should only be true in catastrophic
                    cases.
        """

    def transactionOpened(self, connection: TraceRmiConnection, target: ghidra.debug.api.target.Target):
        """
        A transaction was opened for the given target
         
         
        
        Note, this is different than listening for transactions on the :obj:`Trace` domain object,
        because this only includes those initiated *by the connection*.
        
        :param TraceRmiConnection connection: the connection that initiated the transaction
        :param ghidra.debug.api.target.Target target: the target whose trace is to be modified
        """

    def waitingAccept(self, acceptor: TraceRmiAcceptor):
        """
        The service is waiting for an inbound connection
         
         
        
        The acceptor remains valid until one of three events occurs:
        :meth:`connected(TraceRmiConnection, ConnectMode, TraceRmiAcceptor) <.connected>`,
        :meth:`acceptCancelled(TraceRmiAcceptor) <.acceptCancelled>`, or
        :meth:`acceptFailed(TraceRmiAcceptor, Exception) <.acceptFailed>`.
        
        :param TraceRmiAcceptor acceptor: the acceptor waiting
        """



__all__ = ["TraceRmiLaunchOffer", "RemoteMethod", "TraceRmiAcceptor", "TraceRmiConnection", "RemoteMethodRegistry", "RemoteAsyncResult", "LaunchParameter", "TraceRmiError", "RemoteParameter", "TerminalSession", "TraceRmiServiceListener"]
