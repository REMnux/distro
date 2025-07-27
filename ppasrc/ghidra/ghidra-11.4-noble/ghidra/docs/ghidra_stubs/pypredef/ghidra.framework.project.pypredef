from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.io
import ghidra.framework.model
import java.lang # type: ignore
import java.net # type: ignore


class DefaultProject(ghidra.framework.model.Project):
    """
    Implementation for a Project.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLocalToolChest(self) -> ghidra.framework.model.ToolChest:
        """
        Get the local tool chest for the user logged in.
        
        :return: the tool chest
        :rtype: ghidra.framework.model.ToolChest
        """

    def getProjectLocator(self) -> ghidra.framework.model.ProjectLocator:
        """
        Get the project URL for this project.
        """

    def getToolServices(self) -> ghidra.framework.model.ToolServices:
        """
        Get the tool services for this project.
        """

    def removeProjectView(self, url: java.net.URL):
        """
        Remove the view from this project.
        """

    @property
    def localToolChest(self) -> ghidra.framework.model.ToolChest:
        ...

    @property
    def toolServices(self) -> ghidra.framework.model.ToolServices:
        ...

    @property
    def projectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...


class DefaultProjectManager(ghidra.framework.model.ProjectManager):
    """
    Implementation for a ProjectManager; creates, opens,
    and deletes Projects. It also keeps track of recently opened projects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDefaultTools(self, toolChest: ghidra.framework.model.ToolChest):
        """
        Add the default tools to the given tool chest.  This method does not attempt to merge the
        user's previous tools, as does :meth:`installTools(ToolChest) <.installTools>`.
        
        :param ghidra.framework.model.ToolChest toolChest: tool chest which to add the default tools
        """

    def deleteProject(self, projectLocator: ghidra.framework.model.ProjectLocator) -> bool:
        """
        Delete the project in the given location and remove it from the list of known projects.
        
        :return: false if no project was deleted.
        :rtype: bool
        """

    def getLastOpenedProject(self) -> ghidra.framework.model.ProjectLocator:
        """
        Get the last opened (active) project.
        
        :return: project last opened by the user; returns NULL if a project
        was never opened OR the last opened project is no longer valid
        :rtype: ghidra.framework.model.ProjectLocator
        """

    def getRecentProjects(self) -> jpype.JArray[ghidra.framework.model.ProjectLocator]:
        """
        Get list of project locations that user most recently opened.
        
        :return: list of project locations
        :rtype: jpype.JArray[ghidra.framework.model.ProjectLocator]
        """

    def projectExists(self, projectLocator: ghidra.framework.model.ProjectLocator) -> bool:
        """
        Returns true if the specified project exists.
        """

    def rememberProject(self, projectLocator: ghidra.framework.model.ProjectLocator):
        """
        Keep the specified project on the list of known projects.
        """

    def setLastOpenedProject(self, projectLocator: ghidra.framework.model.ProjectLocator):
        """
        Update the last opened project preference.
        """

    @property
    def recentProjects(self) -> jpype.JArray[ghidra.framework.model.ProjectLocator]:
        ...

    @property
    def lastOpenedProject(self) -> ghidra.framework.model.ProjectLocator:
        ...

    @lastOpenedProject.setter
    def lastOpenedProject(self, value: ghidra.framework.model.ProjectLocator):
        ...


@typing.type_check_only
class ToolChestImpl(ghidra.framework.model.ToolChest):
    """
    Implementation for the Project ToolChest.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getToolTemplate(self, toolName: typing.Union[java.lang.String, str]) -> ghidra.framework.model.ToolTemplate:
        """
        Get the tool template for the given tool name.
        
        :return: null if there is no tool template for the given
        toolName.
        :rtype: ghidra.framework.model.ToolTemplate
        """

    def getToolTemplates(self) -> jpype.JArray[ghidra.framework.model.ToolTemplate]:
        """
        Get the ToolConfigs from the tool chest.
        
        :return: zero-length array if there are no ToolConfigs in the
        tool chest.
        :rtype: jpype.JArray[ghidra.framework.model.ToolTemplate]
        """

    def remove(self, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Remove tool template from the tool chest.
        
        :return: true if the template was removed from the tool chest.
        :rtype: bool
        """

    def toString(self) -> str:
        """
        Returns a string representation of the object. In general, the
        ``toString`` method returns a string that
        "textually represents" this object. The result should
        be a concise but informative representation that is easy for a
        person to read.
        """

    @property
    def toolTemplate(self) -> ghidra.framework.model.ToolTemplate:
        ...

    @property
    def toolTemplates(self) -> jpype.JArray[ghidra.framework.model.ToolTemplate]:
        ...


@typing.type_check_only
class ProjectJarWriter(generic.io.JarWriter):
    """
    Class to write files in a project to a jar output stream.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProjectDataService(java.lang.Object):
    """
    Interface for providing the ProjectData
    """

    class_: typing.ClassVar[java.lang.Class]

    def getProjectData(self) -> ghidra.framework.model.ProjectData:
        """
        Returns the ProjectData for the currently open project.
        """

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData:
        ...



__all__ = ["DefaultProject", "DefaultProjectManager", "ToolChestImpl", "ProjectJarWriter", "ProjectDataService"]
