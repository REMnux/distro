from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import generic.jar
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util.exception
import ghidra.util.table.column
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import org.jgrapht.graph # type: ignore
import org.osgi.framework # type: ignore
import org.osgi.framework.wiring # type: ignore
import org.phidias.compile # type: ignore


COLUMN_TYPE = typing.TypeVar("COLUMN_TYPE")


class OSGiException(ghidra.util.exception.UsrException):
    """
    Wrapper for exceptions originating with an OSGi operation.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Create an exception with given ``message`` and ``cause``.
        
        :param java.lang.String or str message: a contextual message
        :param java.lang.Throwable cause: the original exception
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Create an exception with given ``message``.
        
        :param java.lang.String or str message: a contextual message
        """


class OSGiUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BundleStatusComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Component for managing OSGi bundle status
    """

    @typing.type_check_only
    class RemoveBundlesTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnableAndActivateBundlesTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DeactivateAndDisableBundlesTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActivateDeactivateBundleTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyBundleStatusChangeRequestListener(BundleStatusChangeRequestListener):
        """
        Listener that responds to change requests from the :obj:`BundleStatusTableModel`.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str], bundleHost: BundleHost):
        """
        :obj:`BundleStatusComponentProvider` visualizes bundle status and exposes actions for
        adding, removing, enabling, disabling, activating, and deactivating bundles.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param java.lang.String or str owner: the owner name
        :param BundleHost bundleHost: the bundle host
        """

    def dispose(self):
        ...

    def setBundleFilesForTesting(self, bundleFiles: java.util.List[generic.jar.ResourceFile]):
        """
        This is for testing only!  during normal execution, statuses are only added through
        BundleHostListener bundle(s) added events.
        
         
        Each new bundle will be enabled and writable
        
        :param java.util.List[generic.jar.ResourceFile] bundleFiles: the files to use
        """


class GhidraBundleActivator(org.osgi.framework.BundleActivator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GhidraJarBundle(GhidraBundle):
    """
    Proxy to an ordinary OSGi Jar bundle.  :meth:`GhidraJarBundle.build(PrintWriter) <GhidraJarBundle.build>` does nothing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bundleHost: BundleHost, file: generic.jar.ResourceFile, enabled: typing.Union[jpype.JBoolean, bool], systemBundle: typing.Union[jpype.JBoolean, bool]):
        """
        :obj:`GhidraJarBundle` wraps an ordinary OSGi bundle .jar.
        
        :param BundleHost bundleHost: the :obj:`BundleHost` instance this bundle will belong to
        :param generic.jar.ResourceFile file: the jar file
        :param jpype.JBoolean or bool enabled: true to start enabled
        :param jpype.JBoolean or bool systemBundle: true if this is a Ghidra system bundle
        """


class BundleStatus(java.lang.Comparable[BundleStatus]):
    """
    The BundleStatus class represents the runtime state and user preferences for bundles.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fileExists(self) -> bool:
        """
        
        
        :return: true if the bundle file exists
        :rtype: bool
        """

    def getFile(self) -> generic.jar.ResourceFile:
        """
        
        
        :return: the bundle file
        :rtype: generic.jar.ResourceFile
        """

    def getLocationIdentifier(self) -> str:
        """
        
        
        :return: the bundle's location identifier
        :rtype: str
        """

    def getPathAsString(self) -> str:
        """
        
        
        :return: the bundle file path, using $USER and $GHIDRA_HOME when appropriate
        :rtype: str
        """

    def getSummary(self) -> str:
        """
        
        
        :return: the bundle's build summary
        :rtype: str
        """

    def getType(self) -> GhidraBundle.Type:
        """
        
        
        :return: the bundle type
        :rtype: GhidraBundle.Type
        
        .. seealso::
        
            | :obj:`GhidraBundle.Type`
        """

    def isActive(self) -> bool:
        """
        
        
        :return: true if the bundle is active
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        
        
        :return: true if the bundle is enabled
        :rtype: bool
        """

    def isReadOnly(self) -> bool:
        """
        
        
        :return: true if the bundle is read only
        :rtype: bool
        """

    def setActive(self, isActive: typing.Union[jpype.JBoolean, bool]):
        """
        Set the bundle's status to active or inactive.
        
        :param jpype.JBoolean or bool isActive: true for active, false for inactive
        """

    def setEnabled(self, isEnabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set the bundle's status to enabled or disabled.
        
        :param jpype.JBoolean or bool isEnabled: true to set status to enabled
        """

    def setSummary(self, summary: typing.Union[java.lang.String, str]):
        """
        Set the bundle's build summary.
        
        :param java.lang.String or str summary: the build summary
        """

    @property
    def summary(self) -> java.lang.String:
        ...

    @summary.setter
    def summary(self, value: java.lang.String):
        ...

    @property
    def file(self) -> generic.jar.ResourceFile:
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @active.setter
    def active(self, value: jpype.JBoolean):
        ...

    @property
    def readOnly(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> GhidraBundle.Type:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def pathAsString(self) -> java.lang.String:
        ...

    @property
    def locationIdentifier(self) -> java.lang.String:
        ...


class BundleHost(java.lang.Object):
    """
    Hosts the embedded OSGi framework and manages :obj:`GhidraBundle`s.
     
     
    
    
    Note: :obj:`GhidraBundle`, its implementations, and this class constitute a bridge between 
    OSGi's :obj:`Bundle` and Ghidra.
     
    *  unqualified, "bundle" will mean :obj:`GhidraBundle`
    *  use of OSGi types, including :obj:`Bundle` and :obj:`Framework`, should be package scoped 
    (not public)
    *  bundle lifecycle is simplified to "active"(same as OSGi "active" state) and "inactive" 
    (OSGi "uninstalled" state)
    """

    @typing.type_check_only
    class BundleEdge(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BundleDependencyGraph(org.jgrapht.graph.DirectedMultigraph[GhidraBundle, BundleHost.BundleEdge]):
        """
        Utility class to build a dependency graph from bundles where capabilities map to 
        requirements.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyBundleListener(org.osgi.framework.BundleListener):
        """
        The ``BundleListener`` that notifies :obj:`BundleHostListener`s of bundle activation 
        changes.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    ACTIVATING_BUNDLE_ERROR_MSG: typing.Final = "activating bundle"

    def __init__(self):
        ...

    def activateAll(self, bundles: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, console: java.io.PrintWriter):
        """
        Activate a set of bundles and any dependencies in topological order.  This method doesn't 
        rely on the framework, and so will add non-active dependencies.
         
         
        To load bundles without loading inactive dependencies, call 
        :meth:`activateInStages(Collection, TaskMonitor, PrintWriter) <.activateInStages>`.
        
        :param collections.abc.Sequence bundles: bundles to activate
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :param java.io.PrintWriter console: where to write build messages
        """

    def activateInStages(self, bundles: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, console: java.io.PrintWriter):
        """
        Activate a set of bundles in dependency topological order by resolving against currently
        active bundles in stages.  **No bundles outside those requested will be activated.**
         
         
        To have inactive dependencies loaded, call 
        :meth:`activateAll(Collection, TaskMonitor, PrintWriter) <.activateAll>`.
        
        :param collections.abc.Sequence bundles: bundles to activate
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :param java.io.PrintWriter console: where to write build messages
        """

    @typing.overload
    def activateSynchronously(self, bundle: org.osgi.framework.Bundle):
        """
        Activate a bundle. Either an exception is thrown or the bundle will be in "ACTIVE" state.
        
        :param org.osgi.framework.Bundle bundle: the bundle
        :raises GhidraBundleException: if there's a problem activating
        """

    @typing.overload
    def activateSynchronously(self, bundleLocation: typing.Union[java.lang.String, str]):
        """
        Activate a bundle. Either an exception is thrown or the bundle will be in "ACTIVE" state.
        
        :param java.lang.String or str bundleLocation: the bundle location identifier
        :raises java.lang.InterruptedException: if the wait is interrupted
        :raises GhidraBundleException: if there's a problem activating
        """

    @typing.overload
    def add(self, bundleFile: generic.jar.ResourceFile, enabled: typing.Union[jpype.JBoolean, bool], systemBundle: typing.Union[jpype.JBoolean, bool]) -> GhidraBundle:
        """
        Create a new GhidraBundle and add to the list of managed bundles.
        
        :param generic.jar.ResourceFile bundleFile: the bundle file
        :param jpype.JBoolean or bool enabled: if the new bundle should be enabled
        :param jpype.JBoolean or bool systemBundle: if the new bundle is a system bundle
        :return: a new GhidraBundle
        :rtype: GhidraBundle
        """

    @typing.overload
    def add(self, bundleFiles: java.util.List[generic.jar.ResourceFile], enabled: typing.Union[jpype.JBoolean, bool], systemBundle: typing.Union[jpype.JBoolean, bool]) -> java.util.Collection[GhidraBundle]:
        """
        Create new GhidraBundles and add to the list of managed bundles.  All GhidraBundles created 
        with the same ``enabled`` and ``systemBundle`` values.
        
        :param java.util.List[generic.jar.ResourceFile] bundleFiles: a list of new bundle files to add
        :param jpype.JBoolean or bool enabled: if the new bundles should be enabled
        :param jpype.JBoolean or bool systemBundle: if the new bundles are system bundles
        :return: the new bundle objects
        :rtype: java.util.Collection[GhidraBundle]
        """

    def addListener(self, bundleHostListener: BundleHostListener):
        """
        Add a listener for OSGi framework events.
        
        :param BundleHostListener bundleHostListener: the listener
        """

    def canResolveAll(self, requirements: collections.abc.Sequence) -> bool:
        """
        Attempt to resolve ``requirements`` against the currently active bundles.
        
        :param collections.abc.Sequence requirements: a list of :obj:`BundleRequirement` objects
        :return: true if all of the requirements can be resolved
        :rtype: bool
        """

    @typing.overload
    def deactivateSynchronously(self, bundle: org.osgi.framework.Bundle):
        """
        Deactivate a bundle. Either an exception is thrown or the bundle will be in "UNINSTALLED" 
        state.
        
        :param org.osgi.framework.Bundle bundle: the bundle
        :raises GhidraBundleException: if there's a problem activating
        """

    @typing.overload
    def deactivateSynchronously(self, bundleLocation: typing.Union[java.lang.String, str]):
        """
        Deactivate a bundle. Either an exception is thrown or the bundle will be in "UNINSTALLED" 
        state.
        
        :param java.lang.String or str bundleLocation: the bundle location identifier
        :raises java.lang.InterruptedException: if the wait is interrupted
        :raises GhidraBundleException: if there's a problem activating
        """

    def disable(self, bundle: GhidraBundle) -> bool:
        """
        Disable a bundle and notify listeners.
        
        :param GhidraBundle bundle: the bundle to disable
        :return: true if the bundle was enabled
        :rtype: bool
        """

    @typing.overload
    def enable(self, bundleFile: generic.jar.ResourceFile) -> bool:
        """
        If a :obj:`GhidraBundle` hasn't already been added for ``bundleFile``, add it now as a 
        non-system bundle.
         
         
        Enable the bundle.
        
        :param generic.jar.ResourceFile bundleFile: the bundle file to (add and) enable
        :return: false if the bundle was already enabled
        :rtype: bool
        """

    @typing.overload
    def enable(self, bundle: GhidraBundle) -> bool:
        """
        Enable a bundle and notify listeners.
        
        :param GhidraBundle bundle: the bundle to enable
        :return: false if the bundle was already enabled
        :rtype: bool
        """

    def getBundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Return the list of currently managed bundle files.
        
        :return: all the bundle files
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    def getEnabledBundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Return the list of currently managed enabled bundle files.
        
        :return: all the enabled bundle files
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    def getExistingGhidraBundle(self, bundleFile: generic.jar.ResourceFile) -> GhidraBundle:
        """
        Assuming there is currently a bundle managed with file ``bundleFile``, return its 
        :obj:`GhidraBundle`, otherwise show an error dialog and return ``null``.
        
        :param generic.jar.ResourceFile bundleFile: the bundleFile of the sought bundle
        :return: a :obj:`GhidraBundle` or ``null``
        :rtype: GhidraBundle
        """

    def getGhidraBundle(self, bundleFile: generic.jar.ResourceFile) -> GhidraBundle:
        """
        If there is currently a bundle managed with file ``bundleFile``, return its 
        :obj:`GhidraBundle`, otherwise return ``null``.
        
        :param generic.jar.ResourceFile bundleFile: the bundleFile of the sought bundle
        :return: a :obj:`GhidraBundle` or ``null``
        :rtype: GhidraBundle
        """

    def getGhidraBundles(self) -> java.util.Collection[GhidraBundle]:
        """
        Return all of the currently managed bundles.
        
        :return: all the bundles
        :rtype: java.util.Collection[GhidraBundle]
        """

    @staticmethod
    def getOsgiDir() -> java.nio.file.Path:
        """
        A subdirectory of the user settings directory for storing OSGi artifacts.
        
        :return: the path
        :rtype: java.nio.file.Path
        """

    def install(self, bundle: GhidraBundle) -> org.osgi.framework.Bundle:
        """
        Try to install a bundle.
        
        :param GhidraBundle bundle: the bundle to install
        :return: the OSGi bundle returned by the framework
        :rtype: org.osgi.framework.Bundle
        :raises GhidraBundleException: if install fails
        """

    @typing.overload
    def remove(self, bundleFile: generic.jar.ResourceFile):
        """
        Remove a bundle from the list of managed bundles.
        
        :param generic.jar.ResourceFile bundleFile: the file of the bundle to remove
        """

    @typing.overload
    def remove(self, bundleLocation: typing.Union[java.lang.String, str]):
        """
        Remove a bundle from the list of managed bundles.
        
        :param java.lang.String or str bundleLocation: the location id of the bundle to remove
        """

    @typing.overload
    def remove(self, bundle: GhidraBundle):
        """
        Remove a bundle from the list of managed bundles.
        
        :param GhidraBundle bundle: the bundle to remove
        """

    @typing.overload
    def remove(self, bundles: collections.abc.Sequence):
        """
        Remove bundles from the list of managed bundles.
        
        :param collections.abc.Sequence bundles: the bundles to remove
        """

    def removeListener(self, bundleHostListener: BundleHostListener):
        """
        Remove a listener for OSGi framework events.
        
        :param BundleHostListener bundleHostListener: the listener
        """

    def resolve(self, requirements: java.util.List[org.osgi.framework.wiring.BundleRequirement]) -> java.util.List[org.osgi.framework.wiring.BundleWiring]:
        """
        Attempt to resolve a list of BundleRequirements with active Bundle capabilities.
        
        :param java.util.List[org.osgi.framework.wiring.BundleRequirement] requirements: list of requirements -- satisfied requirements are removed as 
        capabilities are found
        :return: list of :obj:`BundleWiring` objects corresponding to matching capabilities
        :rtype: java.util.List[org.osgi.framework.wiring.BundleWiring]
        """

    def restoreManagedBundleState(self, saveState: ghidra.framework.options.SaveState, tool: ghidra.framework.plugintool.PluginTool):
        """
        Restore the list of managed bundles from ``saveState`` and each bundle's state.
         
         
        Bundles that had been active are reactivated.
         
         
        Note: This is done once on startup after system bundles have been added.
        
        :param ghidra.framework.options.SaveState saveState: the state object
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """

    def saveManagedBundleState(self, saveState: ghidra.framework.options.SaveState):
        """
        Save the list of managed bundles and each bundle's state.
        
        :param ghidra.framework.options.SaveState saveState: the state object
        """

    def startFramework(self):
        """
        Start the framework.
        
        :raises OSGiException: framework failures
        :raises IOException: filesystem setup
        """

    def stopFramework(self):
        """
        Stop the OSGi framework.
         
         
        This may wait for up to 5 seconds for the framework to fully stop.  If that timeout 
        passes an error will be logged.
        """

    @property
    def enabledBundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        ...

    @property
    def bundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        ...

    @property
    def ghidraBundles(self) -> java.util.Collection[GhidraBundle]:
        ...

    @property
    def ghidraBundle(self) -> GhidraBundle:
        ...

    @property
    def existingGhidraBundle(self) -> GhidraBundle:
        ...


class BuildError(java.lang.Object):
    """
    An error produced during :meth:`GhidraBundle.build() <GhidraBundle.build>` with a timestamp.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceFile: generic.jar.ResourceFile):
        """
        Construct an object to record error message produced for ``sourceFile``.
        
        :param generic.jar.ResourceFile sourceFile: the file causing this error
        """

    def append(self, s: typing.Union[java.lang.String, str]):
        """
        Append the given string to the current error message.
        
        :param java.lang.String or str s: the string to append
        """

    def getLastModified(self) -> int:
        """
        The last modified time of the source for this build error.
        
        :return: the last modified time of the source for this build error
        :rtype: int
        """

    @property
    def lastModified(self) -> jpype.JLong:
        ...


class GhidraPlaceholderBundle(GhidraBundle):
    """
    :obj:`GhidraPlaceholderBundle` represents invalid bundle paths in the GUI.
    """

    class_: typing.ClassVar[java.lang.Class]


class GhidraBundle(java.lang.Object):
    """
    Proxy for an OSGi bundle that may require being built.
    """

    @typing.type_check_only
    class Type(java.lang.Enum[GhidraBundle.Type]):
        """
        A :obj:`GhidraBundle` can be
         
        * a Bndtools .bnd script
        * an OSGi bundle .jar file
        * a directory of Java source
        """

        class_: typing.ClassVar[java.lang.Class]
        BND_SCRIPT: typing.Final[GhidraBundle.Type]
        JAR: typing.Final[GhidraBundle.Type]
        SOURCE_DIR: typing.Final[GhidraBundle.Type]
        INVALID: typing.Final[GhidraBundle.Type]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GhidraBundle.Type:
            ...

        @staticmethod
        def values() -> jpype.JArray[GhidraBundle.Type]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def build(self, writer: java.io.PrintWriter) -> bool:
        """
        Build OSGi bundle if needed and if possible.
        
        :param java.io.PrintWriter writer: console for build messages to user
        :return: true if build happened, false if already built or could not build
        :rtype: bool
        :raises java.lang.Exception: if the build cannot complete
        """

    @typing.overload
    def build(self) -> bool:
        """
        Same as :meth:`build(PrintWriter) <.build>` with writer = :obj:`System.err`.
        
        :return: true if build happened, false if already built
        :rtype: bool
        :raises java.lang.Exception: if the build cannot complete
        """

    def getAllCapabilities(self) -> java.util.List[org.osgi.framework.wiring.BundleCapability]:
        """
        Returns all bundle capabilities.
        
        :return: the capabilities
        :rtype: java.util.List[org.osgi.framework.wiring.BundleCapability]
        :raises GhidraBundleException: if there is an exception parsing / loading bundle capabilities
        """

    def getAllRequirements(self) -> java.util.List[org.osgi.framework.wiring.BundleRequirement]:
        """
        Returns all bundle requirements.
        
        :return: the requirements
        :rtype: java.util.List[org.osgi.framework.wiring.BundleRequirement]
        :raises GhidraBundleException: if there is an exception parsing / loading bundle requirements
        """

    def getFile(self) -> generic.jar.ResourceFile:
        """
        The file where this bundle is loaded from.
        
        :return: the file from where this bundle is loaded
        :rtype: generic.jar.ResourceFile
        """

    def getLocationIdentifier(self) -> str:
        """
        Return the location identifier of the bundle that this GhidraBundle represents.
         
         
        The location identifier is used by the framework, e.g. it is passed to
        :obj:`org.osgi.framework.BundleContext.installBundle` when the bundle is first installed.
         
         
        Although the bundle location is a URI, outside of interactions with the framework, the 
        bundle location should remain opaque.
        
        :return: location identifier of this bundle
        :rtype: str
        """

    def getOSGiBundle(self) -> org.osgi.framework.Bundle:
        """
        Get the OSGi bundle represented by this GhidraBundle or null if it isn't in the "installed" 
        state.
        
        :return: a Bundle or null
        :rtype: org.osgi.framework.Bundle
        """

    @staticmethod
    def getType(file: jpype.protocol.SupportsPath) -> GhidraBundle.Type:
        """
        Get the type of a GhidraBundle from its file.
        
        :param jpype.protocol.SupportsPath file: a bundle file
        :return: the type
        :rtype: GhidraBundle.Type
        """

    def isActive(self) -> bool:
        """
        True if this bundle is active.
        
        :return: true if this bundle is active
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        True if this bundle is enabled.
        
        :return: true if this bundle is enabled
        :rtype: bool
        """

    def isSystemBundle(self) -> bool:
        """
        If a bundle is a "system bundle" it cannot be removed and its contends cannot be edited.
        
        :return: true if this is a system bundle
        :rtype: bool
        """

    @property
    def file(self) -> generic.jar.ResourceFile:
        ...

    @property
    def oSGiBundle(self) -> org.osgi.framework.Bundle:
        ...

    @property
    def systemBundle(self) -> jpype.JBoolean:
        ...

    @property
    def allRequirements(self) -> java.util.List[org.osgi.framework.wiring.BundleRequirement]:
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @property
    def allCapabilities(self) -> java.util.List[org.osgi.framework.wiring.BundleCapability]:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @property
    def locationIdentifier(self) -> java.lang.String:
        ...


class OSGiParallelLock(java.io.Closeable):
    """
    A file-based lock used to protect modifications to OSGi shared resources from other
    instances of Ghidra running in parallel
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new OSGi file-based lock
        """


class BundleMap(java.lang.Object):
    """
    A thread-safe container that maps :obj:`GhidraBundle`s by file and bundle location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, bundle: GhidraBundle):
        """
        Maps associations between a bundle, its file, and its bundle location.
        
        :param GhidraBundle bundle: a GhidraBundle object
        """

    def addAll(self, bundles: collections.abc.Sequence):
        """
        Maps bundles in a collection.
         
         
        This is the same as calling :meth:`BundleMap.add(GhidraBundle) <BundleMap.add>` for each bundle in ``bundles``.
        
        :param collections.abc.Sequence bundles: a collection of GhidraBundle objects
        """

    def computeAllIfAbsent(self, bundleFiles: collections.abc.Sequence, ctor: java.util.function.Function[generic.jar.ResourceFile, GhidraBundle]) -> java.util.Collection[GhidraBundle]:
        """
        Creates and maps bundles from files in a collection that aren't already mapped.
        
        :param collections.abc.Sequence bundleFiles: a collection of bundle files
        :param java.util.function.Function[generic.jar.ResourceFile, GhidraBundle] ctor: a constructor for a GhidraBundle given a bundle file
        :return: the newly created GhidraBundle objects
        :rtype: java.util.Collection[GhidraBundle]
        """

    def get(self, bundleFile: generic.jar.ResourceFile) -> GhidraBundle:
        """
        Returns the bundle with the given file.
        
        :param generic.jar.ResourceFile bundleFile: a bundle file
        :return: the bundle found or null
        :rtype: GhidraBundle
        """

    def getBundleAtLocation(self, location: typing.Union[java.lang.String, str]) -> GhidraBundle:
        """
        Returns the bundle with the given location.
        
        :param java.lang.String or str location: a bundle location
        :return: the bundle found or null
        :rtype: GhidraBundle
        """

    def getBundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Returns the currently mapped bundle files.
        
        :return: the currently mapped bundle files
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    def getGhidraBundles(self) -> java.util.Collection[GhidraBundle]:
        """
        Returns the currently mapped bundles.
        
        :return: the currently mapped bundles
        :rtype: java.util.Collection[GhidraBundle]
        """

    @typing.overload
    def remove(self, bundle: GhidraBundle):
        """
        Removes the mappings of a bundle.
        
        :param GhidraBundle bundle: a GhidraBundle object
        """

    @typing.overload
    def remove(self, bundleLocation: typing.Union[java.lang.String, str]) -> GhidraBundle:
        """
        Removes the mapping for a bundle with a given bundle location.
        
        :param java.lang.String or str bundleLocation: a bundle location
        :return: the bundle removed
        :rtype: GhidraBundle
        """

    @typing.overload
    def remove(self, bundleFile: generic.jar.ResourceFile) -> GhidraBundle:
        """
        Removes the mapping for a bundle with a given file.
        
        :param generic.jar.ResourceFile bundleFile: a bundle file
        :return: the bundle removed
        :rtype: GhidraBundle
        """

    def removeAll(self, bundles: collections.abc.Sequence):
        """
        Removes all mappings of each bundle from a collection.
         
        This is the same as calling :meth:`remove(GhidraBundle) <.remove>` for each bundle in ``bundles``.
        
        :param collections.abc.Sequence bundles: a collection of GhidraBundle objects
        """

    @property
    def bundleFiles(self) -> java.util.Collection[generic.jar.ResourceFile]:
        ...

    @property
    def ghidraBundles(self) -> java.util.Collection[GhidraBundle]:
        ...

    @property
    def bundleAtLocation(self) -> GhidraBundle:
        ...


class GhidraBundleException(OSGiException):
    """
    :obj:`GhidraBundleException`s store the context associated with exceptions thrown during bundle operations.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bundle: org.osgi.framework.Bundle, msg: typing.Union[java.lang.String, str], cause: org.osgi.framework.BundleException):
        """
        Construct a new exception originating with ``bundle``.
        
        :param org.osgi.framework.Bundle bundle: the bundle (if available)
        :param java.lang.String or str msg: a contextual message
        :param org.osgi.framework.BundleException cause: the original exception
        """

    @typing.overload
    def __init__(self, bundleLocation: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str], cause: org.osgi.framework.BundleException):
        """
        Construct a new exception originating with the bundle having location identifier ``bundleLocation``.
        
        :param java.lang.String or str bundleLocation: the bundle location identifier (since no bundle is available)
        :param java.lang.String or str msg: a contextual message
        :param org.osgi.framework.BundleException cause: the original exception
        """

    @typing.overload
    def __init__(self, bundleLocation: typing.Union[java.lang.String, str], msg: typing.Union[java.lang.String, str]):
        """
        Construct a new exception originating with the bundle having location identifier ``bundleLocation``.
        
        :param java.lang.String or str bundleLocation: the bundle location identifier (since no bundle is available)
        :param java.lang.String or str msg: a contextual message
        """

    def getBundle(self) -> org.osgi.framework.Bundle:
        """
        
        
        :return: the associated bundle, or null.  If null, the bundle location identifier will be non-null
        :rtype: org.osgi.framework.Bundle
        """

    def getBundleLocation(self) -> str:
        """
        When no :obj:`Bundle` is available, :meth:`getBundle() <.getBundle>` will return ``null``.
        
        :return: the bundle location identifier of the offending bundle.
        :rtype: str
        """

    @property
    def bundle(self) -> org.osgi.framework.Bundle:
        ...

    @property
    def bundleLocation(self) -> java.lang.String:
        ...


class BundleStatusChangeRequestListener(java.lang.Object):
    """
    events thrown by BundleStatus component when buttons are clicked
    """

    class_: typing.ClassVar[java.lang.Class]

    def bundleActivationChangeRequest(self, status: BundleStatus, newValue: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when the user requests that a bundle is activated/deactivated.
        
        :param BundleStatus status: the current status
        :param jpype.JBoolean or bool newValue: true if activated, false if deactivated
        """

    def bundleEnablementChangeRequest(self, status: BundleStatus, newValue: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when the user requests that a bundle is enabled/disabled.
        
        :param BundleStatus status: the current status
        :param jpype.JBoolean or bool newValue: true if enabled, false if disabled
        """


class GhidraSourceBundle(GhidraBundle):
    """
    Represents a Java source directory that is compiled on build to an OSGi bundle.
     
     
    A manifest and :obj:`BundleActivator` are generated if not already present.
    """

    @typing.type_check_only
    class DiscrepancyCallback(java.lang.Object):
        """
        Used to report source and class file deviation
        """

        class_: typing.ClassVar[java.lang.Class]

        def found(self, sourceFile: generic.jar.ResourceFile, classFiles: collections.abc.Sequence):
            """
            Invoked when there is a discrepancy between ``sourceFile`` and its corresponding 
            class file(s), ``classFiles``
            
            :param generic.jar.ResourceFile sourceFile: the source file or null to indicate the class files have no 
            corresponding source
            :param collections.abc.Sequence classFiles: corresponding class file(s)
            :raises java.lang.Throwable: an exception
            """


    @typing.type_check_only
    class MyBundleJavaManager(org.phidias.compile.BundleJavaManager):

        class_: typing.ClassVar[java.lang.Class]

        def getClassLoader(self) -> java.lang.ClassLoader:
            """
            Since the JavaCompiler tasks can close the class loader returned by this method, make 
            sure we're returning a copy.
            """

        @property
        def classLoader(self) -> java.lang.ClassLoader:
            ...


    @typing.type_check_only
    class Summary(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ClassMapper(java.lang.Object):
        """
        Index *.class files in a directory by class name, e.g.
         
         
            "A" -> [directory/A.class]
            "B" -> [directory/B.class, directory/B$inner.class]
         
         
         
        A list of classes are then processed with :obj:`ClassMapper.findAndRemove`.
         
         
        After processing, "extras" are handled with :obj:`ClassMapper.extraClassFiles`.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bundleHost: BundleHost, sourceDirectory: generic.jar.ResourceFile, enabled: typing.Union[jpype.JBoolean, bool], systemBundle: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new GhidraSourceBundle.
        
        :param BundleHost bundleHost: the instance this bundle will belong to
        :param generic.jar.ResourceFile sourceDirectory: the source bundle directory
        :param jpype.JBoolean or bool enabled: true to start enabled
        :param jpype.JBoolean or bool systemBundle: true if this is a Ghidra system bundle
        """

    def classNameForScript(self, sourceFile: generic.jar.ResourceFile) -> str:
        """
        Return the class name corresponding to a script in this source bundle.
        
        :param generic.jar.ResourceFile sourceFile: a source file from this bundle
        :return: the class name
        :rtype: str
        :raises java.lang.ClassNotFoundException: if ``sourceFile`` isn't contained in this bundle
        """

    def getAllErrors(self) -> java.util.Map[generic.jar.ResourceFile, BuildError]:
        """
        Get the mapping from source file to BuildError.
        
        :return: the error file map
        :rtype: java.util.Map[generic.jar.ResourceFile, BuildError]
        """

    @staticmethod
    def getCompiledBundlesDir() -> java.nio.file.Path:
        """
        Source bundles are compiled to a path relative to the user's settings directory:  
         ``<user settings>/osgi/compiled-bundles/<sourceDirHash>``
        
        :return: the destination for compiled source bundles
        :rtype: java.nio.file.Path
        
        .. seealso::
        
            | :obj:`BundleHost.getOsgiDir`
        """

    def getErrors(self, sourceFile: generic.jar.ResourceFile) -> BuildError:
        """
        Get any errors associated with building the given source file.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :return: the build error or null if no errors
        :rtype: BuildError
        """

    def getNewSources(self) -> java.util.List[generic.jar.ResourceFile]:
        """
        Used just after :obj:`.build` to get the newly compiled source files.
        
        :return: new source files
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def sourceDirHash(sourceDir: generic.jar.ResourceFile) -> str:
        """
        When a source bundle doesn't have a manifest, Ghidra computes the bundle's symbolic name as 
        a hash of the source directory path.
         
         
        This hash is also used as the final path component of the compile destination:
         
         ``<user settings>/osgi/compiled-bundles/<sourceDirHash>``
        
        :param generic.jar.ResourceFile sourceDir: the source directory
        :return: a string hash of the source directory path
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getCompiledBundlesDir`
        """

    @property
    def allErrors(self) -> java.util.Map[generic.jar.ResourceFile, BuildError]:
        ...

    @property
    def newSources(self) -> java.util.List[generic.jar.ResourceFile]:
        ...

    @property
    def errors(self) -> BuildError:
        ...


class BundleHostListener(java.lang.Object):
    """
    Listener for OSGi framework events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def bundleActivationChange(self, bundle: GhidraBundle, newActivation: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when a bundle is activated or deactivated.
        
        :param GhidraBundle bundle: the bundle
        :param jpype.JBoolean or bool newActivation: true if activated, false if deactivated
        """

    def bundleAdded(self, bundle: GhidraBundle):
        """
        Invoked when a bundle is added to :obj:`BundleHost`
        
        :param GhidraBundle bundle: the bundle
        """

    def bundleBuilt(self, bundle: GhidraBundle, summary: typing.Union[java.lang.String, str]):
        """
        Invoked when a bundle is built.
        
        :param GhidraBundle bundle: the bundle
        :param java.lang.String or str summary: a summary of the build, or null if nothing changed (build returned false)
        """

    def bundleEnablementChange(self, bundle: GhidraBundle, newEnablement: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when a bundle is enabled or disabled.
        
        :param GhidraBundle bundle: the bundle
        :param jpype.JBoolean or bool newEnablement: true if enabled, false if disabled
        """

    def bundleException(self, exception: GhidraBundleException):
        """
        Invoked when :obj:`BundleHost` excepts during bundle activation/deactivation.
        
        :param GhidraBundleException exception: the exception thrown
        """

    def bundleRemoved(self, bundle: GhidraBundle):
        """
        Invoked when a bundle is removed from :obj:`BundleHost`
        
        :param GhidraBundle bundle: the bundle
        """

    def bundlesAdded(self, bundles: collections.abc.Sequence):
        """
        Invoked when a number of bundles is added at once. A listener should implement this method
        to avoid repeated invocation of :obj:`.bundleAdded` in quick succession.
        
        :param collections.abc.Sequence bundles: the bundles
        """

    def bundlesRemoved(self, bundles: collections.abc.Sequence):
        """
        Invoked when a number of bundles is removed at once. A listener should implement this method
        to avoid repeated invocation of :obj:`.bundleRemoved` in quick succession.
        
        :param collections.abc.Sequence bundles: the bundles
        """


class BundleStatusTableModel(docking.widgets.table.GDynamicColumnTableModel[BundleStatus, java.util.List[BundleStatus]]):
    """
    Model for :obj:`BundleStatus` objects.
    """

    @typing.type_check_only
    class MyBundleHostListener(BundleHostListener):
        """
        when bundles are added or removed, update the table.
        when bundles change enablement or activation, update rows.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Column(docking.widgets.table.AbstractDynamicTableColumn[BundleStatus, COLUMN_TYPE, java.util.List[BundleStatus]], typing.Generic[COLUMN_TYPE]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OSGiStatusColumn(BundleStatusTableModel.Column[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BundleTypeColumn(BundleStatusTableModel.Column[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnabledColumn(BundleStatusTableModel.Column[java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BundleFileColumn(BundleStatusTableModel.Column[generic.jar.ResourceFile]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BuildSummaryColumn(BundleStatusTableModel.Column[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BundleFileRenderer(ghidra.util.table.column.AbstractGColumnRenderer[generic.jar.ResourceFile]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def addListener(self, listener: BundleStatusChangeRequestListener):
        """
        Add a change request listener.
         
         
        When the user requests a change to the status of a bundle, each listener is called.
        
        :param BundleStatusChangeRequestListener listener: the listener to add
        """

    def getRowObjects(self, modelRowIndices: jpype.JArray[jpype.JInt]) -> java.util.List[BundleStatus]:
        """
        return the row objects corresponding an array of model row indices.
        
        :param jpype.JArray[jpype.JInt] modelRowIndices: row indices
        :return: status objects
        :rtype: java.util.List[BundleStatus]
        """

    def removeListener(self, listener: BundleStatusChangeRequestListener):
        """
        Remove change request listener.
        
        :param BundleStatusChangeRequestListener listener: the listener to remove
        """

    @property
    def rowObjects(self) -> java.util.List[BundleStatus]:
        ...



__all__ = ["OSGiException", "OSGiUtils", "BundleStatusComponentProvider", "GhidraBundleActivator", "GhidraJarBundle", "BundleStatus", "BundleHost", "BuildError", "GhidraPlaceholderBundle", "GhidraBundle", "OSGiParallelLock", "BundleMap", "GhidraBundleException", "BundleStatusChangeRequestListener", "GhidraSourceBundle", "BundleHostListener", "BundleStatusTableModel"]
