from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.wizard
import ghidra.framework.client
import ghidra.framework.model
import ghidra.framework.plugintool
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore
import utility.function


class ProjectWizardData(java.lang.Object):
    """
    Wizard data for the :obj:`ProjectWizardModel` and its steps for the "new project" wizard. It
    is also used by the :obj:`ProjectChooseRepositoryWizardModel` for the wizards to convert a 
    non-shared project to shared and for changing the repository/server info of an existing 
    shared project.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def allowAnonymousAccess(self) -> bool:
        ...

    def getProjectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...

    def getProjectUsers(self) -> jpype.JArray[ghidra.framework.remote.User]:
        ...

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    def getRepositoryName(self) -> str:
        ...

    def getServer(self) -> ghidra.framework.client.RepositoryServerAdapter:
        ...

    def getServerInfo(self) -> ghidra.framework.model.ServerInfo:
        ...

    def isNewRepository(self) -> bool:
        ...

    def isSharedProject(self) -> bool:
        ...

    def setAllowAnonymousAccess(self, allowAnonymousAccess: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIsNewRepository(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIsSharedProject(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setProjectLocator(self, locator: ghidra.framework.model.ProjectLocator):
        ...

    def setProjectUsers(self, projectUsers: jpype.JArray[ghidra.framework.remote.User]):
        ...

    def setRepository(self, repository: ghidra.framework.client.RepositoryAdapter):
        ...

    def setRepositoryName(self, repositoryName: typing.Union[java.lang.String, str]):
        ...

    def setServer(self, server: ghidra.framework.client.RepositoryServerAdapter):
        ...

    def setServerInfo(self, serverInfo: ghidra.framework.model.ServerInfo):
        ...

    @property
    def newRepository(self) -> jpype.JBoolean:
        ...

    @property
    def server(self) -> ghidra.framework.client.RepositoryServerAdapter:
        ...

    @server.setter
    def server(self, value: ghidra.framework.client.RepositoryServerAdapter):
        ...

    @property
    def serverInfo(self) -> ghidra.framework.model.ServerInfo:
        ...

    @serverInfo.setter
    def serverInfo(self, value: ghidra.framework.model.ServerInfo):
        ...

    @property
    def sharedProject(self) -> jpype.JBoolean:
        ...

    @property
    def projectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...

    @projectLocator.setter
    def projectLocator(self, value: ghidra.framework.model.ProjectLocator):
        ...

    @property
    def repositoryName(self) -> java.lang.String:
        ...

    @repositoryName.setter
    def repositoryName(self, value: java.lang.String):
        ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @repository.setter
    def repository(self, value: ghidra.framework.client.RepositoryAdapter):
        ...

    @property
    def projectUsers(self) -> jpype.JArray[ghidra.framework.remote.User]:
        ...

    @projectUsers.setter
    def projectUsers(self, value: jpype.JArray[ghidra.framework.remote.User]):
        ...


class ServerStep(docking.wizard.WizardStep[ProjectWizardData]):
    """
    Wizard step in the new project wizard for choosing the Ghidra server when creating a shared
    project.
    """

    class_: typing.ClassVar[java.lang.Class]


class SelectProjectStep(docking.wizard.WizardStep[ProjectWizardData]):
    """
    Wizard step in the new project wizard for choosing the new project's root folder location and
    naming the project.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProjectChooseRepositoryWizardModel(docking.wizard.WizardModel[ProjectWizardData]):
    """
    Wizard model for either converting a non-shared project to a share project OR for moving
    a shared project to a different server/repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], server: ghidra.framework.model.ServerInfo):
        ...

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...


class RepositoryPanel(javax.swing.JPanel):
    """
    Panel that shows a list of existing repositories, or allows the user
    to enter the name of a new repository to be created. Used by the :obj:`RepositoryStep` of
    either the new project wizard, the "convert to shared" wizard, or the "change repository"
    wizard.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, statusChangedCallback: utility.function.Callback, repositoryNames: jpype.JArray[java.lang.String], readOnlyServerAccess: typing.Union[jpype.JBoolean, bool]):
        ...

    def getRepositoryName(self) -> str:
        ...

    def isCreateRepositorySelected(self) -> bool:
        ...

    @property
    def createRepositorySelected(self) -> jpype.JBoolean:
        ...

    @property
    def repositoryName(self) -> java.lang.String:
        ...


class SelectProjectPanel(javax.swing.JPanel):
    """
    Panel that allows the project directory and name to be specified for a
    new project. A checkbox indicates whether the project should be created
    as a shared project. Used by the :obj:`SelectProjectStep` of the new project wizard.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, statusChangedCallback: utility.function.Callback):
        """
        Construct a new panel.
        
        :param utility.function.Callback statusChangedCallback: callback
        """


class ProjectTypePanel(javax.swing.JPanel):
    """
    Gui panel for choosing the project type in a new project wizard. Used by the
    :obj:`ProjectTypeStep`.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProjectWizardModel(docking.wizard.WizardModel[ProjectWizardData]):
    """
    Wizard model for creating new Ghidra projects.
    """

    class_: typing.ClassVar[java.lang.Class]
    STANDARD_BORDER: typing.Final[javax.swing.border.Border]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getProjectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...

    @property
    def projectLocator(self) -> ghidra.framework.model.ProjectLocator:
        ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter:
        ...


class ServerInfoPanel(javax.swing.JPanel):
    """
    Panel that allows the user to specify the host name and port
    number for the remote repository server. Used by the :obj:`ServerStep` of
    either the new project wizard, the "convert to shared" wizard, or the "change repository"
    wizard.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, statusChangedCallback: utility.function.Callback):
        ...

    def getPortNumber(self) -> int:
        ...

    def getServerName(self) -> str:
        ...

    def getStatusMessge(self) -> str:
        ...

    def isValidInformation(self) -> bool:
        ...

    def setServerInfo(self, info: ghidra.framework.model.ServerInfo):
        """
        Set the field values using the given server info.
        """

    @property
    def validInformation(self) -> jpype.JBoolean:
        ...

    @property
    def serverName(self) -> java.lang.String:
        ...

    @property
    def statusMessge(self) -> java.lang.String:
        ...

    @property
    def portNumber(self) -> jpype.JInt:
        ...


class ProjectAccessStep(docking.wizard.WizardStep[ProjectWizardData]):
    """
    Wizard step for configuring user access in a Ghidra server repository. Used by the
    "new project", the "convert to shared" and the "change repository" wizards. This step
    only gets shown if the user creates a new repository.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.wizard.WizardModel[ProjectWizardData], tool: ghidra.framework.plugintool.PluginTool):
        ...


class ProjectTypeStep(docking.wizard.WizardStep[ProjectWizardData]):
    """
    Wizard step in the new project wizard for choosing the type of project.
    """

    class_: typing.ClassVar[java.lang.Class]


class RepositoryStep(docking.wizard.WizardStep[ProjectWizardData]):
    """
    Wizard step in the new project wizard selecting or creating a new repository in a Ghidra server.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ProjectWizardData", "ServerStep", "SelectProjectStep", "ProjectChooseRepositoryWizardModel", "RepositoryPanel", "SelectProjectPanel", "ProjectTypePanel", "ProjectWizardModel", "ServerInfoPanel", "ProjectAccessStep", "ProjectTypeStep", "RepositoryStep"]
