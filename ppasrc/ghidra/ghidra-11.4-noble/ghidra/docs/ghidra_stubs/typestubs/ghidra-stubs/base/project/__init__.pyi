from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.opinion
import ghidra.framework.client
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.project
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.io # type: ignore
import java.lang # type: ignore


class GhidraProject(java.lang.Object):
    """
    Helper class for using Ghidra in a "batch" mode. This class provides methods
    for importing, opening, saving, and analyzing program.
     
    
    **Note: **Before using this class you must initialize the Ghidra system.  See
    :obj:`Application.initializeApplication` for more information.
    """

    @typing.type_check_only
    class GhidraProjectManager(ghidra.framework.project.DefaultProjectManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def analyze(program: ghidra.program.model.listing.Program):
        """
        Invokes the auto-analyzer on the program. Depending on which analyzers
        are in the classpath, generally will disassemble at entry points, and
        create and analyze functions that are called.
        
        :param ghidra.program.model.listing.Program program: the program to analyze.
        """

    @typing.overload
    def analyze(self, program: ghidra.program.model.listing.Program, debug: typing.Union[jpype.JBoolean, bool]):
        """
        Debug version of the auto_analyzer. Same as regular analyzer except that
        any stack traces are not trapped.
        
        :param ghidra.program.model.listing.Program program: the program to be analyzed
        :param jpype.JBoolean or bool debug: true to allow stack traces to propagate out.
        """

    def checkPoint(self, program: ghidra.program.model.listing.Program):
        """
        Creates a checkpoint in the program. Any changes since the last
        checkpoint can be instantly undone by calling the rollback command.
        
        :param ghidra.program.model.listing.Program program: the program to be checkpointed.
        """

    @typing.overload
    def close(self):
        """
        Closes the ghidra project, closing (without saving!) any open programs in
        that project. Also deletes the project if created as a temporary project.
        """

    @typing.overload
    def close(self, program: ghidra.program.model.listing.Program):
        """
        Closes the given program. Any changes in the program will be lost.
        
        :param ghidra.program.model.listing.Program program: the program to close.
        """

    @staticmethod
    def createProject(projectDirPath: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str], temporary: typing.Union[jpype.JBoolean, bool]) -> GhidraProject:
        """
        Creates a new non-shared Ghidra project to be used for storing programs.
         
         
        **Note:  Calling this method will delete any existing project files on disk that 
        match the given project name. 
        **
        
        :param java.lang.String or str projectDirPath: the directory path to contain the new Ghidra project.
        :param java.lang.String or str projectName: the name of the project to be created.
        :param jpype.JBoolean or bool temporary: if true, deletes the project when it is closed - useful for testing.
        :return: an open ghidra project.
        :rtype: GhidraProject
        :raises IOException: if there was a problem accessing the project
        """

    def execute(self, cmd: ghidra.framework.cmd.Command, program: ghidra.program.model.listing.Program):
        """
        Executes the give command on the program.
        
        :param ghidra.framework.cmd.Command cmd: the command to be applied to the program.
        :param ghidra.program.model.listing.Program program: the program on which the command is to be applied.
        """

    def getAnalysisOptions(self, program: ghidra.program.model.listing.Program) -> ghidra.framework.options.Options:
        """
        :return: a PropertList containing all the analysis option properties that
        can be set. Changing the value of the analysis properties will affect
        what happens when the analyze call is made.
        :rtype: ghidra.framework.options.Options
        
        
        :param ghidra.program.model.listing.Program program: the program whose analysis options are to be set.
        """

    def getProject(self) -> ghidra.framework.model.Project:
        """
        :return: the underlying Project instance or null if project was opened for
        READ access only.
        :rtype: ghidra.framework.model.Project
        """

    def getProjectData(self) -> ghidra.framework.model.ProjectData:
        """
        :return: the underlying ProjectData instance.
        :rtype: ghidra.framework.model.ProjectData
        """

    def getProjectManager(self) -> ghidra.framework.project.DefaultProjectManager:
        """
        Returns the project manager
        
        :return: the project manager
        :rtype: ghidra.framework.project.DefaultProjectManager
        """

    def getRootFolder(self) -> ghidra.framework.model.DomainFolder:
        """
        :return: the root folder for the Ghidra project.
        :rtype: ghidra.framework.model.DomainFolder
        """

    @staticmethod
    def getServerRepository(host: typing.Union[java.lang.String, str], port: typing.Union[jpype.JInt, int], repositoryName: typing.Union[java.lang.String, str], createIfNeeded: typing.Union[jpype.JBoolean, bool]) -> ghidra.framework.client.RepositoryAdapter:
        """
        Get/Create shared repository.
        
        :param java.lang.String or str host: Ghidra Server host
        :param jpype.JInt or int port: Ghidra Server port (0 = use default port)
        :param java.lang.String or str repositoryName: The repository name
        :param jpype.JBoolean or bool createIfNeeded: if true repository will be created if it does not exist
        :raises DuplicateNameException: if the repository name already exists
        :return: A :obj:`handle <RepositoryAdapter>` to the new repository
        :rtype: ghidra.framework.client.RepositoryAdapter
        """

    @typing.overload
    def importProgram(self, file: jpype.protocol.SupportsPath, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def importProgram(self, file: jpype.protocol.SupportsPath, processor: ghidra.program.model.lang.Processor) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def importProgram(self, file: jpype.protocol.SupportsPath, loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader]) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def importProgram(self, file: jpype.protocol.SupportsPath, loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def importProgram(self, file: jpype.protocol.SupportsPath) -> ghidra.program.model.listing.Program:
        ...

    def importProgramFast(self, file: jpype.protocol.SupportsPath) -> ghidra.program.model.listing.Program:
        ...

    def openProgram(self, folderPath: typing.Union[java.lang.String, str], programName: typing.Union[java.lang.String, str], readOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Program:
        """
        Opens a program.
        
        :param java.lang.String or str folderPath: the path of the program within the project. ("/" is root)
        :param java.lang.String or str programName: the name of the program to open.
        :param jpype.JBoolean or bool readOnly: flag if the program will only be read and not written.
        :return: an open program.
        :rtype: ghidra.program.model.listing.Program
        :raises IOException: if there was a problem accessing the program
        """

    @staticmethod
    @typing.overload
    def openProject(projectsDir: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str]) -> GhidraProject:
        """
        Returns an instance of an open Ghidra Project that can be used to
        open/save programs.
        
        :param java.lang.String or str projectsDir: the directory containing the Ghidra project.
        :param java.lang.String or str projectName: the name of the ghidra project.
        :return: an open ghidra project.
        :rtype: GhidraProject
        :raises NotFoundException: if the file for the project was
        not found.
        :raises NotOwnerException: if the project owner is not the user
        :raises LockException: if the project is already opened by another user
        :raises IOException: if an IO-related problem occurred
        """

    @staticmethod
    @typing.overload
    def openProject(projectsDir: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str], restoreProject: typing.Union[jpype.JBoolean, bool]) -> GhidraProject:
        """
        Returns an instance of an open Ghidra Project that can be used to
        open/save programs.
        
        :param java.lang.String or str projectsDir: the directory containing the Ghidra project.
        :param java.lang.String or str projectName: the name of the ghidra project.
        :param jpype.JBoolean or bool restoreProject: if true the project tool state is restored
        :return: an open ghidra project.
        :rtype: GhidraProject
        :raises NotFoundException: if the file for the project was not found.
        :raises NotOwnerException: if the project owner is not the user
        :raises LockException: if the project is already opened by another user
        :raises IOException: if an IO-related problem occurred
        """

    def rollback(self, program: ghidra.program.model.listing.Program):
        """
        Rolls back any changes to the program since the last checkpoint.
        
        :param ghidra.program.model.listing.Program program: the program to be rolled back.
        """

    def save(self, program: ghidra.program.model.listing.Program):
        """
        Saves any changes in the program back to its file. If the program does
        not have an associated file (it was created), then it is an error to call
        this method, use saveAs instead.
        Any open transaction will be terminated.
        
        :param ghidra.program.model.listing.Program program: the program to be saved.
        :raises IOException: if there was a problem accessing the program
        """

    def saveAs(self, program: ghidra.program.model.listing.Program, folderPath: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], overWrite: typing.Union[jpype.JBoolean, bool]):
        """
        Saves the given program to the project with the given name.
        
        :param ghidra.program.model.listing.Program program: the program to be saved
        :param java.lang.String or str folderPath: the path where to save the program.
        :param java.lang.String or str name: the name to save the program as.
        :param jpype.JBoolean or bool overWrite: if true, any existing program with that name will be
                    over-written.
        :raises DuplicateFileException: if a file exists with that name and overwrite is false or overwrite failed
        :raises InvalidNameException: the name is null or has invalid characters.
        :raises IOException: if there was a problem accessing the program
        """

    def saveAsPackedFile(self, program: ghidra.program.model.listing.Program, file: jpype.protocol.SupportsPath, overWrite: typing.Union[jpype.JBoolean, bool]):
        """
        Saves the given program to as a packed file.
        
        :param ghidra.program.model.listing.Program program: the program to be saved
        :param jpype.protocol.SupportsPath file: the packed file destination.
        :param jpype.JBoolean or bool overWrite: if true, any existing program with that name will be
                    over-written.
        :raises InvalidNameException: the name is null or has invalid characters.
        :raises IOException: if there was a problem accessing the program
        """

    def setDeleteOnClose(self, toDelete: typing.Union[jpype.JBoolean, bool]):
        """
        Updates the flag passed to this project at construction time.
        
        :param jpype.JBoolean or bool toDelete: true to delete on close; false in the opposite condition
        """

    @property
    def projectManager(self) -> ghidra.framework.project.DefaultProjectManager:
        ...

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData:
        ...

    @property
    def rootFolder(self) -> ghidra.framework.model.DomainFolder:
        ...

    @property
    def analysisOptions(self) -> ghidra.framework.options.Options:
        ...

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...



__all__ = ["GhidraProject"]
