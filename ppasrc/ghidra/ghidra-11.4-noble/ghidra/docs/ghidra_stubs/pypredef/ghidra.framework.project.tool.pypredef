from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.util.image
import ghidra.framework.model
import ghidra.framework.plugintool
import java.awt # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.jdom # type: ignore


@typing.type_check_only
class ExtensionManager(java.lang.Object):
    """
    A class to manage saving and restoring of known extension used by this tool.
    """

    @typing.type_check_only
    class PluginPath(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def isFrom(self, dir: jpype.protocol.SupportsPath) -> bool:
            ...

        @property
        def from_(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]


class GhidraToolTemplate(ghidra.framework.model.ToolTemplate):
    """
    Implementation for a tool template that has the class names of the
    plugins that are part of the tool, and the tool's icon.
    """

    class_: typing.ClassVar[java.lang.Class]
    TEMPLATE_NAME: typing.ClassVar[java.lang.String]

    @typing.overload
    def __init__(self, root: org.jdom.Element, path: typing.Union[java.lang.String, str]):
        """
        Constructor.
        
        :param org.jdom.Element root: XML element that contains the tool template data
        :param java.lang.String or str path: the path of the template
        """

    @typing.overload
    def __init__(self, iconURL: docking.util.image.ToolIconURL, toolElement: org.jdom.Element, supportedDataTypes: jpype.JArray[java.lang.Class[typing.Any]]):
        ...

    def getIconURL(self) -> docking.util.image.ToolIconURL:
        """
        Get the icon URL.
        """

    def setIconURL(self, url: docking.util.image.ToolIconURL):
        ...

    @property
    def iconURL(self) -> docking.util.image.ToolIconURL:
        ...

    @iconURL.setter
    def iconURL(self, value: docking.util.image.ToolIconURL):
        ...


class ToolManagerImpl(ghidra.framework.model.ToolManager, java.beans.PropertyChangeListener):
    """
    Tool manager that knows about all the running tools for each workspace
    in the project; the tool manager is responsible for launching new tools,
    and managing connections among tools.
    """

    @typing.type_check_only
    class ToolSaveStatus(java.lang.Enum[ToolManagerImpl.ToolSaveStatus]):

        class_: typing.ClassVar[java.lang.Class]
        AUTO_SAVE_MODE: typing.Final[ToolManagerImpl.ToolSaveStatus]
        ASK_SAVE_MODE: typing.Final[ToolManagerImpl.ToolSaveStatus]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ToolManagerImpl.ToolSaveStatus:
            ...

        @staticmethod
        def values() -> jpype.JArray[ToolManagerImpl.ToolSaveStatus]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, project: ghidra.framework.model.Project):
        ...

    def canAutoSave(self, tool: ghidra.framework.plugintool.PluginTool) -> bool:
        ...

    def clearWorkspaceChanged(self):
        """
        Clear the flag so the user does not get prompted to save the
        project; flag gets set to true when a workspace is created, and
        a workspace is created when a new project is created.
        """

    def dispose(self):
        ...

    def dumpConnectionList(self):
        """
        Debug method for printing out the list of connections.
        """

    def getTool(self, toolName: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.PluginTool:
        """
        Called by WorkspaceImpl when it is restoring its state.
        
        :param java.lang.String or str toolName: the name of the tool
        :return: the tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def getToolServices(self) -> ghidra.framework.model.ToolServices:
        """
        Get any tool services available from this tool
        
        :return: ToolServices list of tool services this tool can provide.
        :rtype: ghidra.framework.model.ToolServices
        """

    def hasChanged(self) -> bool:
        """
        Return whether any tools have changed, or if any tools were
        added or removed from any of the workspaces.
        
        :return: true if any tools in this workspace have changed
        :rtype: bool
        """

    def restoreFromXml(self, root: org.jdom.Element):
        """
        restores the object from an XML element
        
        :param org.jdom.Element root: root element of saved XML state
        """

    def saveSessionTools(self) -> bool:
        """
        Save the tools that are opened and changed, that will be brought back up when the project
        is reopened
        
        :return: true if the session was saved
        :rtype: bool
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        Saves this object to an XML element
        
        :return: the element containing the tool XML
        :rtype: org.jdom.Element
        """

    def toolSaved(self, tool: ghidra.framework.plugintool.PluginTool, toolChanged: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def toolServices(self) -> ghidra.framework.model.ToolServices:
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...


@typing.type_check_only
class ToolConnectionImpl(ghidra.framework.model.ToolConnection, ghidra.framework.model.ToolListener):
    """
    Implementation for representing connections between two tools.
    Acts as the middle man for the connection in order to filter the
    events.
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Indicates whether some other object is "equal to" this one.
        """

    def hashCode(self) -> int:
        """
        Returns a hash code value for the object. This method is
        supported for the benefit of hashtables such as those provided by
        ``java.util.Hashtable``.
        """

    def restoreFromXml(self, root: org.jdom.Element):
        """
        restores the ToolConnection from an XML element
        
        :param org.jdom.Element root: XML element to restore ToolConnection from.
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        Saves the Tool Connection into an XML element.
        """

    def toString(self) -> str:
        """
        Returns a string representation of the object. In general, the
        ``toString`` method returns a string that
        "textually represents" this object. The result should
        be a concise but informative representation that is easy for a
        person to read.
        """


@typing.type_check_only
class ConnectionDescriptor(java.io.Serializable):
    """
    Class to describe the connection between two tools for a specific event.
    This class is used by the ToolSetImpl when it serializes itself.
    """

    class_: typing.ClassVar[java.lang.Class]

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Indicates whether some other object is "equal to" this one.
        """

    def hashCode(self) -> int:
        """
        Returns a hash code value for the object. This method is
        supported for the benefit of hashtables such as those provided by
        ``java.util.Hashtable``.
        """

    def toString(self) -> str:
        """
        Returns a string representation of the object. In general, the
        ``toString`` method returns a string that
        "textually represents" this object. The result should
        be a concise but informative representation that is easy for a
        person to read.
        """


class GhidraTool(ghidra.framework.plugintool.PluginTool):
    """
    Tool created by the workspace when the user chooses to create a new
    tool. Its ToolConfigProvider shows all Plugins with the exception of
    those plugins that can be added to the Front End tool only.
    """

    class_: typing.ClassVar[java.lang.Class]
    autoSave: typing.ClassVar[jpype.JBoolean]

    @typing.overload
    def __init__(self, project: ghidra.framework.model.Project, name: typing.Union[java.lang.String, str]):
        """
        Construct a new Ghidra Tool.
        
        :param ghidra.framework.model.Project project: the project associated with the tool
        :param java.lang.String or str name: the name of the tool
        """

    @typing.overload
    def __init__(self, project: ghidra.framework.model.Project, template: GhidraToolTemplate):
        """
        Construct a new GhidraTool using an existing template.
        
        :param ghidra.framework.model.Project project: project that is the associated with the tool.
        :param GhidraToolTemplate template: the template to use when creating the tool
        """


@typing.type_check_only
class GhidraPluginsConfiguration(ghidra.framework.plugintool.PluginsConfiguration):
    """
    A configuration that allows all general plugins and application plugins.  Plugins that may only
    exist at the application level are filtered out.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OpenFileDropHandlerFactory(docking.DropTargetFactory):
    """
    A basic DropTargetFactory that provides functionality for dragging files onto Ghidra to be 
    opened.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createDropTargetHandler(self, component: java.awt.Component) -> docking.DropTargetHandler:
        ...


@typing.type_check_only
class WorkspaceImpl(ghidra.framework.model.Workspace):
    """
    WorkspaceImpl
     
    Implementation of a Workspace.
    """

    class_: typing.ClassVar[java.lang.Class]

    def restoreFromXml(self, root: org.jdom.Element):
        """
        restores the object from an XML element
        
        :param org.jdom.Element root: an XML element to restore from
        """

    def saveToXml(self) -> org.jdom.Element:
        """
        saves the object to an XML element
        
        :return: an XML element containing the saved state
        :rtype: org.jdom.Element
        """

    def toString(self) -> str:
        """
        Returns a string representation of the object. In general, the
        ``toString`` method returns a string that
        "textually represents" this object. The result should
        be a concise but informative representation that is easy for a
        person to read.
        
        :return: a string representation of the object.
        :rtype: str
        """


@typing.type_check_only
class ToolServicesImpl(ghidra.framework.model.ToolServices):
    """
    Implementation of service used to manipulate tools.
    """

    class_: typing.ClassVar[java.lang.Class]


class SelectChangedToolDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, toolList: java.util.List[ghidra.framework.plugintool.PluginTool]):
        ...



__all__ = ["ExtensionManager", "GhidraToolTemplate", "ToolManagerImpl", "ToolConnectionImpl", "ConnectionDescriptor", "GhidraTool", "GhidraPluginsConfiguration", "OpenFileDropHandlerFactory", "WorkspaceImpl", "ToolServicesImpl", "SelectChangedToolDialog"]
