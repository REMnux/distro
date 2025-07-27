from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.util.classfinder
import ghidra.util.exception
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class DefaultPluginsConfiguration(ghidra.framework.plugintool.PluginsConfiguration):
    """
    A configuration that includes all plugins on the classpath.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PluginPackageState(java.lang.Enum[PluginPackageState]):

    class_: typing.ClassVar[java.lang.Class]
    NO_PLUGINS_LOADED: typing.Final[PluginPackageState]
    SOME_PLUGINS_LOADED: typing.Final[PluginPackageState]
    ALL_PLUGINS_LOADED: typing.Final[PluginPackageState]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PluginPackageState:
        ...

    @staticmethod
    def values() -> jpype.JArray[PluginPackageState]:
        ...


class UndoRedoToolState(java.lang.Object):

    @typing.type_check_only
    class PluginState(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def restoreUndoRedoState(self, domainObject: ghidra.framework.model.DomainObject):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugins: java.util.List[ghidra.framework.plugintool.Plugin], domainObject: ghidra.framework.model.DomainObject):
        """
        Construct a TransientPluginState
        
        :param java.util.List[ghidra.framework.plugintool.Plugin] plugins: array of plugins to get transient state for
        """

    def restoreTool(self, domainObject: ghidra.framework.model.DomainObject):
        """
        Restore the tool's state.
        """


class PluginDescription(java.lang.Comparable[PluginDescription]):
    """
    Class to hold meta information about a plugin, derived from meta-data attached to
    each :obj:`Plugin` using a :obj:`@PluginInfo <PluginInfo>` annotation.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def createPluginDescription(pluginClass: java.lang.Class[typing.Any], status: PluginStatus, pluginPackage: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], shortDescription: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]) -> PluginDescription:
        """
        Constructs a new PluginDescription for the given plugin class.
         
        
        Deprecated, use :obj:`@PluginInfo <PluginInfo>` instead.
        
        :param java.lang.Class[typing.Any] pluginClass: the class of the plugin
        :param PluginStatus status: the status, UNSTABLE, STABLE, RELEASED, DEBUG, or EXAMPLE
        :param java.lang.String or str pluginPackage: the package to which the plugin belongs (see :obj:`PluginPackage`
                subclasses for examples)
        :param java.lang.String or str category: the category to which the plugin belongs (see :obj:`PluginCategoryNames`
        :param java.lang.String or str shortDescription: a brief description of what the plugin does
        :param java.lang.String or str description: the long description of what the plugin does
        :return: the new (or cached) PluginDescription
        :rtype: PluginDescription
        """

    @staticmethod
    @typing.overload
    @deprecated(", use PluginInfo instead.")
    def createPluginDescription(pluginClassParam: java.lang.Class[typing.Any], status: PluginStatus, pluginPackage: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], shortDescription: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], isSlowInstallation: typing.Union[jpype.JBoolean, bool]) -> PluginDescription:
        """
        Constructs a new PluginDescription for the given plugin class.
        
        
        .. deprecated::
        
        , use :obj:`@PluginInfo <PluginInfo>` instead.
        :param java.lang.Class[typing.Any] pluginClassParam: the class of the plugin
        :param PluginStatus status: the status, UNSTABLE, STABLE, RELEASED, DEBUG, or EXAMPLE
        :param java.lang.String or str pluginPackage: the package to which the plugin belongs (see :obj:`PluginPackage`
                subclasses for examples)
        :param java.lang.String or str category: the category to which the plugin belongs (see :obj:`PluginCategoryNames`
        :param java.lang.String or str shortDescription: a brief description of what the plugin does
        :param java.lang.String or str description: the long description of what the plugin does
        :param jpype.JBoolean or bool isSlowInstallation: true signals that this plugin loads slowly
        :return: the new (or cached) PluginDescription
        :rtype: PluginDescription
        """

    def getCategory(self) -> str:
        """
        Return the category for the plugin.
        
        :return: the category
        :rtype: str
        """

    def getDescription(self) -> str:
        """
        Return the description of the plugin.
        
        :return: ``"<None>"`` if no description was specified
        :rtype: str
        """

    def getEventsConsumed(self) -> java.util.List[java.lang.Class[ghidra.framework.plugintool.PluginEvent]]:
        ...

    def getEventsProduced(self) -> java.util.List[java.lang.Class[ghidra.framework.plugintool.PluginEvent]]:
        ...

    def getModuleName(self) -> str:
        """
        Return the name of the module that contains the plugin.
        
        :return: the module name
        :rtype: str
        """

    def getName(self) -> str:
        """
        Return the name of the plugin.
        
        :return: the name of the plugin.
        :rtype: str
        """

    def getPluginClass(self) -> java.lang.Class[ghidra.framework.plugintool.Plugin]:
        """
        Return the class of the plugin.
        
        :return: plugin class object
        :rtype: java.lang.Class[ghidra.framework.plugintool.Plugin]
        """

    @staticmethod
    def getPluginDescription(c: java.lang.Class[ghidra.framework.plugintool.Plugin]) -> PluginDescription:
        """
        Fetches the :obj:`PluginDescription` for the specified Plugin class.
         
        
        If the PluginDescription is found in the static cache, it is returned directly,
        otherwise a new instance is created (using annotation data attached to the Plugin
        class) and it is cached for later use.
        
        :param java.lang.Class[ghidra.framework.plugintool.Plugin] c: Plugin's class
        :return: :obj:`PluginDescription`
        :rtype: PluginDescription
        """

    def getPluginPackage(self) -> PluginPackage:
        ...

    def getServicesProvided(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    def getServicesRequired(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    def getShortDescription(self) -> str:
        """
        Set the short description for what the plugin does.
        
        :return: short description
        :rtype: str
        """

    def getSourceLocation(self) -> str:
        """
        Get the location for the source file for the plugin.
        
        :return: path to the source file
        :rtype: str
        """

    def getStatus(self) -> PluginStatus:
        """
        Returns the development status of the plugin.
        
        :return: the status.
        :rtype: PluginStatus
        """

    def isInCategory(self, parentCategory: typing.Union[java.lang.String, str]) -> bool:
        """
        Return whether the plugin is in the given category.
        
        :param java.lang.String or str parentCategory: category to check
        :return: true if the plugin is in the category
        :rtype: bool
        """

    def isSlowInstallation(self) -> bool:
        """
        Returns true if this plugin requires a noticeable amount of time to load when installed.
        
        :return: true if this plugin requires a noticeable amount of time to load when installed.
        :rtype: bool
        """

    @property
    def servicesProvided(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    @property
    def inCategory(self) -> jpype.JBoolean:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def eventsConsumed(self) -> java.util.List[java.lang.Class[ghidra.framework.plugintool.PluginEvent]]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def pluginClass(self) -> java.lang.Class[ghidra.framework.plugintool.Plugin]:
        ...

    @property
    def shortDescription(self) -> java.lang.String:
        ...

    @property
    def servicesRequired(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    @property
    def pluginPackage(self) -> PluginPackage:
        ...

    @property
    def eventsProduced(self) -> java.util.List[java.lang.Class[ghidra.framework.plugintool.PluginEvent]]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def slowInstallation(self) -> jpype.JBoolean:
        ...

    @property
    def sourceLocation(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.lang.String:
        ...

    @property
    def status(self) -> PluginStatus:
        ...


class PluginPackage(ghidra.util.classfinder.ExtensionPoint, java.lang.Comparable[PluginPackage]):

    class_: typing.ClassVar[java.lang.Class]
    UTILITY_PRIORITY: typing.Final = 0
    CORE_PRIORITY: typing.Final = 1
    FEATURE_PRIORITY: typing.Final = 4
    MISCELLANIOUS_PRIORITY: typing.Final = 6
    DEVELOPER_PRIORITY: typing.Final = 8
    EXAMPLES_PRIORITY: typing.Final = 10
    EXPERIMENTAL_PRIORITY: typing.Final = 12

    @staticmethod
    def exists(packageName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the system has found a plugin package for the given name
        
        :param java.lang.String or str packageName: the package name
        :return: true if the system has found a plugin package for the given name
        :rtype: bool
        """

    def getActivationLevel(self) -> PluginStatus:
        """
        The minimum level required to activate plugins when the entire package is activated by the
        user.
        
        :return: the minimum level
        :rtype: PluginStatus
        """

    def getDescription(self) -> str:
        ...

    def getIcon(self) -> javax.swing.Icon:
        ...

    def getName(self) -> str:
        ...

    @staticmethod
    def getPluginPackage(packageName: typing.Union[java.lang.String, str]) -> PluginPackage:
        """
        Returns the existing plugin package with the given name.  If no package exists, then the
        :obj:`MiscellaneousPluginPackage` will be returned.
        
        :param java.lang.String or str packageName: the package name
        :return: the package
        :rtype: PluginPackage
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def activationLevel(self) -> PluginStatus:
        ...


class PluginConstructionException(ghidra.util.exception.UsrException):
    """
    Exception thrown when a an error occurs during the construction
    of a plugin.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, className: typing.Union[java.lang.String, str], details: typing.Union[java.lang.String, str]):
        """
        Construct a new exception.
        
        :param java.lang.String or str className: name of the plugin class that failed to load
        :param java.lang.String or str details: details of the construction failure
        """


class PluginStatus(java.lang.Enum[PluginStatus]):

    class_: typing.ClassVar[java.lang.Class]
    RELEASED: typing.Final[PluginStatus]
    STABLE: typing.Final[PluginStatus]
    UNSTABLE: typing.Final[PluginStatus]
    HIDDEN: typing.Final[PluginStatus]
    DEPRECATED: typing.Final[PluginStatus]
    """
    Developers should include in the plugin description the version when the plugin became
    deprecated and, if subject to removal, the version that removal is expected.
    """


    def getDescription(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PluginStatus:
        ...

    @staticmethod
    def values() -> jpype.JArray[PluginStatus]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class PluginEventListener(java.lang.Object):
    """
    Listener that is notified when an event is generated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def eventSent(self, event: ghidra.framework.plugintool.PluginEvent):
        """
        Notification that the given plugin event was sent.
        
        :param ghidra.framework.plugintool.PluginEvent event: plugin event that was sent
        """


class TransientToolState(java.lang.Object):

    @typing.type_check_only
    class PluginState(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugins: java.util.List[ghidra.framework.plugintool.Plugin]):
        """
        Construct a TransientPluginState
        
        :param java.util.List[ghidra.framework.plugintool.Plugin] plugins: array of plugins to get transient state for
        """

    def restoreTool(self):
        """
        Restore the tool's state.
        """


class PluginException(ghidra.util.exception.UsrException):
    """
    Exception thrown if plugin was not found.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, className: typing.Union[java.lang.String, str], details: typing.Union[java.lang.String, str]):
        """
        Construct PluginException with a detail message.
        
        :param java.lang.String or str className: class name of the plugin
        :param java.lang.String or str details: the reason the addPlugin failed.
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Construct a PluginException with the given message.
        
        :param java.lang.String or str message: message that is returned in the getMessage() method
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Construct a PluginException with the given message and cause.
        
        :param java.lang.String or str message: the exception message
        :param java.lang.Throwable cause: the exception cause
        """

    def getPluginException(self, e: PluginException) -> PluginException:
        """
        Creates a new PluginException by appending the message from 
        this exception to the message of the given exception if it
        is not null. If e is null, returns this exception.
        
        :param PluginException e: exception whose message will be appended to this
        exceptions message if e is not null
        :return: this exception if e is null, or a new exception
        :rtype: PluginException
        """

    @property
    def pluginException(self) -> PluginException:
        ...


class PluginUtils(java.lang.Object):
    """
    Utility class for plugin-related methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def assertUniquePluginName(pluginClass: java.lang.Class[ghidra.framework.plugintool.Plugin]):
        """
        Ensures the specified Plugin has a unique name among all Plugin classes
        found in the current ClassSearcher's reach.
        
        :param java.lang.Class[ghidra.framework.plugintool.Plugin] pluginClass: Class
        :raises PluginException: throws exception if Plugin class is not uniquely named
        """

    @staticmethod
    def forName(pluginClassName: typing.Union[java.lang.String, str]) -> java.lang.Class[ghidra.framework.plugintool.Plugin]:
        """
        Returns the Class for a Plugin, by class name.
        
        :param java.lang.String or str pluginClassName: String class name
        :return: Class that is a Plugin, never null.
        :rtype: java.lang.Class[ghidra.framework.plugintool.Plugin]
        :raises PluginException: if specified class does not exist or is not a Plugin.
        """

    @staticmethod
    def getDefaultProviderForServiceClass(serviceClass: java.lang.Class[typing.Any]) -> java.lang.Class[ghidra.framework.plugintool.Plugin]:
        """
        Returns the Plugin Class that is specified as being the defaultProvider for a
        Service, or null if no default provider is specified.
        
        :param java.lang.Class[typing.Any] serviceClass: Service interface class
        :return: Plugin class that provides the specified service
        :rtype: java.lang.Class[ghidra.framework.plugintool.Plugin]
        """

    @staticmethod
    def getPluginNameFromClass(pluginClass: java.lang.Class[ghidra.framework.plugintool.Plugin]) -> str:
        """
        Returns the name of a Plugin based on its class.
        
        :param java.lang.Class[ghidra.framework.plugintool.Plugin] pluginClass: Class to get name from
        :return: String name, based on Class's getSimpleName()
        :rtype: str
        """

    @staticmethod
    def instantiatePlugin(pluginClass: java.lang.Class[T], tool: ghidra.framework.plugintool.PluginTool) -> T:
        """
        Returns a new instance of a :obj:`Plugin`.
        
        :param java.lang.Class[T] pluginClass: Specific Plugin Class
        :param ghidra.framework.plugintool.PluginTool tool: The :obj:`PluginTool` that is the parent of the new Plugin
        :return: a new Plugin instance, never NULL.
        :rtype: T
        :raises PluginException: if problem constructing the Plugin instance.
        """


class ServiceListener(java.lang.Object):
    """
    Notifications for when services are added to or removed from a PluginTool.
    """

    class_: typing.ClassVar[java.lang.Class]

    def serviceAdded(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Notifies the listener that a service has been added to the tool.
        
        :param java.lang.Class[typing.Any] interfaceClass: the interface class that the given service implements.
        :param java.lang.Object service: the implementation of the service.
        """

    def serviceRemoved(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Notifies the listener that a service has been removed from the tool.
        
        :param java.lang.Class[typing.Any] interfaceClass: the interface class that the given service implements.
        :param java.lang.Object service: the implementation of the service.
        """



__all__ = ["DefaultPluginsConfiguration", "PluginPackageState", "UndoRedoToolState", "PluginDescription", "PluginPackage", "PluginConstructionException", "PluginStatus", "PluginEventListener", "TransientToolState", "PluginException", "PluginUtils", "ServiceListener"]
