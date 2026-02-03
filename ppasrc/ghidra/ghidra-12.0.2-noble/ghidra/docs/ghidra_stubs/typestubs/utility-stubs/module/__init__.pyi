from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.framework
import java.io # type: ignore
import java.lang # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import utility.application


class ModuleManifestFile(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    MODULE_MANIFEST_FILE_NAME: typing.Final = "Module.manifest"

    @typing.overload
    def __init__(self, moduleRootDir: jpype.protocol.SupportsPath):
        ...

    @typing.overload
    def __init__(self, moduleRootDir: generic.jar.ResourceFile):
        ...

    def excludeFromGhidraJar(self) -> bool:
        ...

    def getDataSearchIgnoreDirs(self) -> java.util.Set[java.lang.String]:
        ...

    def getFatJars(self) -> java.util.Set[java.lang.String]:
        ...

    def getModuleFileIPs(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    def getModuleName(self) -> str:
        ...

    @staticmethod
    def hasModuleManifest(moduleRootDir: jpype.protocol.SupportsPath) -> bool:
        ...

    @property
    def dataSearchIgnoreDirs(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def fatJars(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def moduleName(self) -> java.lang.String:
        ...

    @property
    def moduleFileIPs(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...


class ModuleUtilities(java.lang.Object):
    """
    Utility methods for module related things.
    """

    class_: typing.ClassVar[java.lang.Class]
    MANIFEST_FILE_NAME: typing.Final = "Module.manifest"
    MANIFEST_FILE_NAME_UNINSTALLED: typing.Final = "Module.manifest.uninstalled"
    MODULE_LIST: typing.Final = "MODULE_LIST"

    def __init__(self):
        ...

    @staticmethod
    def findJarModuleRootDirectories(rootDir: generic.jar.ResourceFile, moduleRootDirs: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Searches the given jar root directory for module root directories.  Uses a "module list"
        file to locate the module root directories. Adds any discovered module root directories
        to the given collection.
        
        :param generic.jar.ResourceFile rootDir: The jar directory to start looking for module root directories in.
        :param collections.abc.Sequence moduleRootDirs: A collection to add discovered module root directories to.
        :return: The given collection with any discovered modules added.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        :raises IOException: if there was a problem reading the module list file.
        """

    @staticmethod
    @typing.overload
    def findModuleRootDirectories(rootDir: generic.jar.ResourceFile, moduleRootDirs: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Searches the given root directory for module root directories.  Adds any discovered module
        root directories to the given collection.
        
        :param generic.jar.ResourceFile rootDir: The directory to start looking for module root directories in.
        :param collections.abc.Sequence moduleRootDirs: A collection to add discovered module root directories to.
        :return: The given collection with any discovered modules added.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    @typing.overload
    def findModuleRootDirectories(rootDirs: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Searches the given root directories for module root directories.  Adds any discovered module
        root directories to the returned collection.
        
         
        Note: if you need to control the type of collection used to store the module roots, then
        call :meth:`findModuleRootDirectories(Collection, Collection) <.findModuleRootDirectories>`.
        
        :param collections.abc.Sequence rootDirs: The directories to look for module root directories in.
        :return: a new collection with any discovered modules added.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    @typing.overload
    def findModuleRootDirectories(rootDirs: collections.abc.Sequence, moduleRootDirs: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Searches the given root directories for module root directories.  Adds any discovered module
        root directories to the given collection.
        
        :param collections.abc.Sequence rootDirs: The directories to look for module root directories in.
        :param collections.abc.Sequence moduleRootDirs: A collection to add discovered module root directories to.
        :return: The given collection with any discovered modules added.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    @typing.overload
    def findModules(appRootDirs: collections.abc.Sequence, moduleRootDirs: collections.abc.Sequence) -> java.util.Map[java.lang.String, ghidra.framework.GModule]:
        """
        Searches for modules in a given collection of module root directories.
        
        :param collections.abc.Sequence appRootDirs: The collection of application root directories associated with the given
        list of module root directories.
        :param collections.abc.Sequence moduleRootDirs: A collection of module root directories to search for modules in.
        :return: The discovered modules as a map (mapping module name to module for convenience).
        :rtype: java.util.Map[java.lang.String, ghidra.framework.GModule]
        """

    @staticmethod
    @typing.overload
    def findModules(appRootDirs: collections.abc.Sequence, moduleRootDirs: collections.abc.Sequence, moduleFilter: java.util.function.Predicate[ghidra.framework.GModule]) -> java.util.Map[java.lang.String, ghidra.framework.GModule]:
        """
        Searches for modules in a given collection of module root directories.
        
        :param collections.abc.Sequence appRootDirs: The collection of application root directories associated with the given
        list of module root directories.
        :param collections.abc.Sequence moduleRootDirs: A collection of module root directories to search for modules in.
        :param java.util.function.Predicate[ghidra.framework.GModule] moduleFilter: a predicate used to filter modules; a given module will not be included
        when the predicate returns false.
        :return: The discovered modules as a map (mapping module name to module for convenience).
        :rtype: java.util.Map[java.lang.String, ghidra.framework.GModule]
        """

    @staticmethod
    def findRepo(f: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Returns a file that is the repository folder containing the given file.  As an example,
        given a repo structure of:
        
         
        ``/userdir/repoRoot/repoDir/.git``
        
        
         
        then this method, given will produce the following results (input -> output):
        
        
         
        ``/userdir/repoRoot/repoDir/.git -> /userdir/repoRoot/repoDir``
         
        ``/userdir/repoRoot/repoDir -> /userdir/repoRoot/repoDir``
        
        :param jpype.protocol.SupportsPath f: the child file of the desired repo
        :return: a file that is the repo folder of the repository containing the given file; null
                if the given file is not under a repo directory
        :rtype: java.io.File
        """

    @staticmethod
    def findRepoRoot(f: jpype.protocol.SupportsPath) -> java.io.File:
        """
        Returns a file that is the root folder of the repository containing the given file.  'Root'
        here means a folder that contains a repository folder.  As an example, given a repo
        structure of:
        
         
        ``/userdir/repoRoot/repoDir/.git``
        
        
         
        then this method, given will produce the following results (input -> output):
        
        
         
        ``/userdir/repoRoot/repoDir/.git -> /userdir/repoRoot``
         
        ``/userdir/repoRoot/repoDir -> /userdir/repoRoot``
         
        ``/userdir/repoRoot -> /userdir/repoRoot``
        
        :param jpype.protocol.SupportsPath f: the child file of the desired repo
        :return: a file that is the root folder of the repository containing the given file; null
                if the given file is not under a repo directory or itself a repo root
        :rtype: java.io.File
        """

    @staticmethod
    def getModule(pathName: typing.Union[java.lang.String, str]) -> java.nio.file.Path:
        """
        Returns the path of the module containing the given path string, if it is parented by a
        module root directory.
         
        
        For example, given a module path of ``/some/dir/features/cool_module/``, then this
        method will return that module path, given these paths:
         
        
         
        
        ``/some/dir/features/cool_module``
        
        ``/some/dir/features/cool_module/some/child/dir``
         
        
         
        and null for these paths:
         
        
         
        
        ``/some/random/path``
        
        ``/some/dir/features/``
        
        :param java.lang.String or str pathName: the path name to check
        :return: the module root directory; null if the path is not in a module
        :rtype: java.nio.file.Path
        
        .. seealso::
        
            | :obj:`.isModuleDirectory(Path)`
        """

    @staticmethod
    def getModuleBinDirectories(modules: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Gets the directory locations of the .class files and resources from the given modules.
        
        :param collections.abc.Sequence modules: The modules to get the compiled .class and resources directories of.
        :return: A collection of directories containing classes and resources from the given modules.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    def getModuleLibDirectories(modules: collections.abc.Sequence) -> java.util.Collection[generic.jar.ResourceFile]:
        """
        Gets the library directories from the given modules.
         
        
        In :meth:`release mode <SystemUtilities.isInReleaseMode>`, we expect these directories to
        be in each module's ``lib`` subdirectory.
         
        
        If not in release mode (i.e., :meth:`development mode <SystemUtilities.isInDevelopmentMode>`,
        :meth:`testing mode <SystemUtilities.isInTestingMode>`, etc), we expect these directories to
        be in each module's ``build/libs`` subdirectory.
         
        
        NOTE: If Eclipse is being used this method may still return jars built by Gradle.  It is up
        to the caller of this method to determine if they should be used instead of the classes
        compiled by Eclipse.
        
        :param collections.abc.Sequence modules: The modules to get the library directories of.
        :return: A collection of library directories from the given modules.
        :rtype: java.util.Collection[generic.jar.ResourceFile]
        """

    @staticmethod
    def isExternalModule(module: ghidra.framework.GModule, layout: utility.application.ApplicationLayout) -> bool:
        """
        Checks to see if the given :obj:`module <GModule>` is external to the Ghidra installation
        directory
        
        :param ghidra.framework.GModule module: the module to check
        :param utility.application.ApplicationLayout layout: Ghidra's layout
        :return: true if the given :obj:`module <GModule>` is external to the Ghidra installation
        directory
        :rtype: bool
        """

    @staticmethod
    def isInModule(pathName: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given path is parented by a module root directory.
         
        
        For example, given a module path of ``/some/dir/features/cool_module/``, then this
        method will return true for these paths:
         
        
         
        
        ``/some/dir/features/cool_module``
        
        ``/some/dir/features/cool_module/some/child/dir``
         
        
         
        and false for these paths:
         
        
         
        
        ``/some/random/path``
        
        ``/some/dir/features/``
        
        :param java.lang.String or str pathName: the path name to check
        :return: true if the given path is parented by a module root directory.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isModuleDirectory(Path)`
        """

    @staticmethod
    @typing.overload
    def isModuleDirectory(dir: generic.jar.ResourceFile) -> bool:
        """
        Checks if the given directory is a module.
        
        :param generic.jar.ResourceFile dir: the directory to check.
        :return: true if the given directory is a module
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isModuleDirectory(path: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given path is a module root directory.
        
        :param jpype.protocol.SupportsPath path: the path to check
        :return: true if the given path is a module root directory.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isUninstalled(path: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given module has been uninstalled.
        
        :param java.lang.String or str path: the module path to check
        :return: true if uninstalled
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isUninstalled(dir: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given module has been uninstalled.
        
        :param jpype.protocol.SupportsPath dir: the module dir to check
        :return: true if uninstalled
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isUninstalled(dir: generic.jar.ResourceFile) -> bool:
        """
        Returns true if the given module has been uninstalled.
        
        :param generic.jar.ResourceFile dir: the module dir to check
        :return: true if uninstalled
        :rtype: bool
        """


class ClasspathFilter(java.util.function.Predicate[ghidra.framework.GModule]):
    """
    A predicate used to filter modules using the classpath.   Only modules included in the classpath
    will pass this filter.  Any modules not on the classpath may be included by calling
    :meth:`ClasspathFilter(Predicate) <.ClasspathFilter>` with a predicate that allows other module paths.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor to allow only modules on the classpath.
        """

    @typing.overload
    def __init__(self, additionalPaths: java.util.function.Predicate[java.nio.file.Path]):
        """
        Constructor that allows any module to be included whose path passed the given predicate.  If
        the predicate returns false, then a given module will only be included if it is in the
        classpath.
        
        :param java.util.function.Predicate[java.nio.file.Path] additionalPaths: a predicate that allows additional module paths (they do not need to
        be on the system classpath)
        """



__all__ = ["ModuleManifestFile", "ModuleUtilities", "ClasspathFilter"]
