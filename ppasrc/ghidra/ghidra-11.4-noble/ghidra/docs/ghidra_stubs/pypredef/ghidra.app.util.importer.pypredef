from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra.app.util
import ghidra.app.util.bin
import ghidra.app.util.opinion
import ghidra.formats.gfilesystem
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class LibrarySearchPathManager(java.lang.Object):
    """
    A simple class for managing the library search path and avoiding duplicate directories.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def addPath(path: typing.Union[java.lang.String, str]) -> bool:
        """
        Adds the specified library search path ``path`` to the end of the path search list
        
        :param java.lang.String or str path: the library search path to add
        :return: true if the path was appended, false if the path was a duplicate
        :rtype: bool
        """

    @staticmethod
    def getLibraryFsrlList(program: ghidra.program.model.listing.Program, log: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a :obj:`List` of :obj:`FSRL`s to search for libraries
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program` being loaded
        :param MessageLog log: The log
        :param ghidra.util.task.TaskMonitor monitor: A cancellable monitor
        :return: a :obj:`List` of :obj:`FSRL`s to search for libraries
        :rtype: java.util.List[ghidra.formats.gfilesystem.FSRL]
        :raises CancelledException: if the user cancelled the operation
        """

    @staticmethod
    def getLibraryPaths() -> jpype.JArray[java.lang.String]:
        """
        Returns an array of library search paths
        
        :return: an array of library search paths
        :rtype: jpype.JArray[java.lang.String]
        """

    @staticmethod
    def reset():
        """
        Resets the library search path to the default values
        """

    @staticmethod
    def setLibraryPaths(paths: jpype.JArray[java.lang.String]):
        """
        Sets the library search paths to the given array
        
        :param jpype.JArray[java.lang.String] paths: the new library search paths
        """


class LibrarySearchPathDummyOption(ghidra.app.util.Option):
    """
    A dummy :obj:`Option` used to render a button that will allow the user to edit the global
    list of library search paths
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`LibrarySearchPathDummyOption`
        
        :param java.lang.String or str name: The name of the option
        """


class MultipleProgramsException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class LcsHintLoadSpecChooser(LoadSpecChooser):
    """
    Chooses a :obj:`LoadSpec` for a :obj:`Loader` to use based on a provided :obj:`Language` and
    :obj:`CompilerSpec`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec):
        """
        Creates a new :obj:`LcsHintLoadSpecChooser`.
         
        
        NOTE: It is assumed that the given :obj:`Language` is valid and it supports the given 
        :obj:`CompilerSpec`.
        
        :param ghidra.program.model.lang.Language language: The :obj:`Language` to use (should not be null)
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The :obj:`CompilerSpec` to use (f null default compiler spec will be used)
        """


class LoaderArgsOptionChooser(OptionChooser):
    """
    An option chooser that applies loader options that were passed in as command line arguments.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loaderFilter: SingleLoaderFilter):
        ...


class OptionChooser(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_OPTIONS: typing.Final[OptionChooser]

    def choose(self, optionChoices: java.util.List[ghidra.app.util.Option], addressFactory: ghidra.program.model.address.AddressFactory) -> java.util.List[ghidra.app.util.Option]:
        ...


class LoadSpecChooser(java.lang.Object):
    """
    Chooses a :obj:`LoadSpec` for a :obj:`Loader` to use based on some criteria
    """

    class_: typing.ClassVar[java.lang.Class]
    CHOOSE_THE_FIRST_PREFERRED: typing.Final[LoadSpecChooser]
    """
    Chooses the first "preferred" :obj:`LoadSpec`
    
    
    .. seealso::
    
        | :obj:`LoadSpec.isPreferred()`
    """


    def choose(self, loaderMap: ghidra.app.util.opinion.LoaderMap) -> ghidra.app.util.opinion.LoadSpec:
        """
        Chooses a :obj:`LoadSpec` for a :obj:`Loader` to use based on some criteria
        
        :param ghidra.app.util.opinion.LoaderMap loaderMap: A :obj:`LoaderMap`
        :return: The chosen :obj:`LoadSpec`, or null if one could not be found
        :rtype: ghidra.app.util.opinion.LoadSpec
        """


class DomainFolderOption(ghidra.app.util.Option):
    """
    An :obj:`Option` used to specify a :obj:`DomainFolder`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], arg: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`DomainFolderOption`
        
        :param java.lang.String or str name: The name of the option
        :param java.lang.String or str arg: The option's command line argument (could be null)
        """


class CsHintLoadSpecChooser(LoadSpecChooser):
    """
    Chooses a :obj:`LoadSpec` for a :obj:`Loader` to use based on a provided :obj:`CompilerSpec`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, compilerSpecID: ghidra.program.model.lang.CompilerSpecID):
        """
        Creates a new :obj:`CsHintLoadSpecChooser`
        
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecID: The :obj:`CompilerSpecID` to use (should not be null)
        """

    @typing.overload
    def __init__(self, compilerSpecID: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`CsHintLoadSpecChooser`
        
        :param java.lang.String or str compilerSpecID: The :obj:`CompilerSpecID` to use (should not be null)
        """


class SingleLoaderFilter(java.util.function.Predicate[ghidra.app.util.opinion.Loader]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, single: java.lang.Class[ghidra.app.util.opinion.Loader]):
        """
        Create a new single loader filter from the given loader class.
        
        :param java.lang.Class[ghidra.app.util.opinion.Loader] single: The loader class used for this filter.
        """

    @typing.overload
    def __init__(self, single: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]):
        """
        Create a new single loader filter from the given loader class and loader command line
        argument list.
        
        :param java.lang.Class[ghidra.app.util.opinion.Loader] single: The loader class used for this filter.
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: The loader arguments used for this filter.  Could be null if there
                        are not arguments.
        """

    def getLoaderArgs(self) -> java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]:
        """
        Gets the loader arguments tied to the loader in this filter.
        
        :return: The loader arguments tied to the loader in this filter.  Could be null if there
                are no arguments.
        :rtype: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]
        """

    @property
    def loaderArgs(self) -> java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]:
        ...


class AutoImporter(java.lang.Object):
    """
    Utility methods to do :obj:`Program` imports automatically (without requiring user interaction)
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def importAsBinary(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the :obj:`BinaryLoader`, using the given
        language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program` is 
        not saved to a project.  That is the responsibility of the caller (see 
        :meth:`Loaded.save(Project, MessageLog, TaskMonitor) <Loaded.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program` with :meth:`Loaded.release(Object) <Loaded.release>` when it is no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for the :obj:`Loaded` result. The :obj:`Loaded` result 
        should be queried for its true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`Loaded` :obj:`Program` (created but not saved)
        :rtype: ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importAsBinary(bytes: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`ByteProvider` bytes with the :obj:`BinaryLoader`, 
        using the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program` is 
        not saved to a project.  That is the responsibility of the caller (see 
        :meth:`Loaded.save(Project, MessageLog, TaskMonitor) <Loaded.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program` with :meth:`Loaded.release(Object) <Loaded.release>` when it is no longer needed.
        
        :param ghidra.app.util.bin.ByteProvider bytes: The bytes to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it the :obj:`Loaded` result. The :obj:`Loaded` result 
        should be queried for its true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`Loaded` :obj:`Program` (created but not saved)
        :rtype: ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByLookingForLcs(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the best matching :obj:`Loader` that
        supports the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByLookingForLcs(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the best matching :obj:`Loader` that
        supports the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingBestGuess(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the best matching :obj:`Loader` for the
        :obj:`File`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingBestGuess(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the best matching :obj:`Loader` for the
        :obj:`File`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingBestGuess(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the give :obj:`bytes <ByteProvider>` with the best matching 
        :obj:`Loader` for the :obj:`ByteProvider`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingSpecificLoaderClass(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the given type of :obj:`Loader`.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Class[ghidra.app.util.opinion.Loader] loaderClass: The :obj:`Loader` class to use
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: A :obj:`List` of optional :obj:`Loader`-specific arguments
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingSpecificLoaderClass(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the given type of :obj:`Loader`.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Class[ghidra.app.util.opinion.Loader] loaderClass: The :obj:`Loader` class to use
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: A :obj:`List` of optional :obj:`Loader`-specific arguments
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importByUsingSpecificLoaderClassAndLcs(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the given type of :obj:`Loader`, language,
        and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Class[ghidra.app.util.opinion.Loader] loaderClass: The :obj:`Loader` class to use
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: A :obj:`List` of optional :obj:`Loader`-specific arguments
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        """

    @staticmethod
    @typing.overload
    def importByUsingSpecificLoaderClassAndLcs(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the given type of :obj:`Loader`, language,
        and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Class[ghidra.app.util.opinion.Loader] loaderClass: The :obj:`Loader` class to use
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: A :obj:`List` of optional :obj:`Loader`-specific arguments
        :param ghidra.program.model.lang.Language language: The desired :obj:`Language`
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The desired :obj:`compiler specification <CompilerSpec>`
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        """

    @staticmethod
    @typing.overload
    def importFresh(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.util.function.Predicate[ghidra.app.util.opinion.Loader] loaderFilter: A :obj:`Predicate` used to choose what :obj:`Loader`(s) get used
        :param LoadSpecChooser loadSpecChooser: A :obj:`LoadSpecChooser` used to choose what :obj:`LoadSpec`(s) get
        used
        :param java.lang.String or str importNameOverride: The name to use for the imported thing.  Null to use the 
        :obj:`Loader`'s preferred name.
        :param OptionChooser optionChooser: A :obj:`OptionChooser` used to choose what :obj:`Loader` options get
        used
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importFresh(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.util.function.Predicate[ghidra.app.util.opinion.Loader] loaderFilter: A :obj:`Predicate` used to choose what :obj:`Loader`(s) get used
        :param LoadSpecChooser loadSpecChooser: A :obj:`LoadSpecChooser` used to choose what :obj:`LoadSpec`(s) get
        used
        :param java.lang.String or str importNameOverride: The name to use for the imported thing.  Null to use the 
        :obj:`Loader`'s preferred name.
        :param OptionChooser optionChooser: A :obj:`OptionChooser` used to choose what :obj:`Loader` options get
        used
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """

    @staticmethod
    @typing.overload
    def importFresh(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`bytes <ByteProvider>` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(Project, Object, MessageLog, TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.release(Object) <LoadResults.release>` when they are no longer needed.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.util.function.Predicate[ghidra.app.util.opinion.Loader] loaderFilter: A :obj:`Predicate` used to choose what :obj:`Loader`(s) get used
        :param LoadSpecChooser loadSpecChooser: A :obj:`LoadSpecChooser` used to choose what :obj:`LoadSpec`(s) get
        used
        :param java.lang.String or str importNameOverride: The name to use for the imported thing.  Null to use the 
        :obj:`Loader`'s preferred name.
        :param OptionChooser optionChooser: A :obj:`OptionChooser` used to choose what :obj:`Loader` options get
        used
        :param java.lang.Object consumer: A consumer
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one ore more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        """


class MessageLog(java.lang.Object):
    """
    A simple class to handle logging messages and exceptions.  A maximum message count size 
    constraint can be set to clip messages after a certain number, but still keep incrementing
    a running total.
     
     
    In addition to logging messages, clients can also set a status message.  This message may
    later used as the primary error message when reporting to the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def appendException(self, t: java.lang.Throwable):
        """
        Appends the exception to the log
        
        :param java.lang.Throwable t: the exception to append to the log
        """

    @typing.overload
    def appendMsg(self, message: typing.Union[java.lang.String, str]):
        """
        Appends the message to the log
        
        :param java.lang.String or str message: the message
        """

    @typing.overload
    def appendMsg(self, originator: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Appends the message to the log
        
        :param java.lang.String or str originator: the originator of the message
        :param java.lang.String or str message: the message
        """

    @typing.overload
    def appendMsg(self, lineNum: typing.Union[jpype.JInt, int], message: typing.Union[java.lang.String, str]):
        """
        Appends the message and line number to the log
        
        :param jpype.JInt or int lineNum: the line number that generated the message
        :param java.lang.String or str message: the message
        """

    def clear(self):
        """
        Clears all messages from this log and resets the count
        """

    def clearStatus(self):
        """
        Clear status message
        """

    def copyFrom(self, log: MessageLog):
        """
        Copies the contents of one message log into this one
        
        :param MessageLog log: the log to copy from
        """

    @deprecated("use appendMsg(String)")
    def error(self, originator: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Readable method for appending error messages to the log.
        
         
        Currently does nothing different than :meth:`appendMsg(String, String) <.appendMsg>`.
        
        :param java.lang.String or str originator: the originator of the message
        :param java.lang.String or str message: the message
        
        .. deprecated::
        
        use :meth:`appendMsg(String) <.appendMsg>`
        """

    def getStatus(self) -> str:
        """
        Returns a stored status message
        
        :return: stored status message
        :rtype: str
        """

    def hasMessages(self) -> bool:
        """
        Returns true if this log has messages
        
        :return: true if this log has messages
        :rtype: bool
        """

    def setStatus(self, status: typing.Union[java.lang.String, str]):
        """
        Stores a status message that can be used elsewhere (i.e., populate warning dialogs)
        
        :param java.lang.String or str status: the status message
        """

    def write(self, owner: java.lang.Class[typing.Any], messageHeader: typing.Union[java.lang.String, str]):
        """
        Writes this log's contents to the application log
        
        :param java.lang.Class[typing.Any] owner: the owning class whose name will appear in the log message
        :param java.lang.String or str messageHeader: the message header that will appear before the log messages
        """

    @property
    def status(self) -> java.lang.String:
        ...

    @status.setter
    def status(self, value: java.lang.String):
        ...



__all__ = ["LibrarySearchPathManager", "LibrarySearchPathDummyOption", "MultipleProgramsException", "LcsHintLoadSpecChooser", "LoaderArgsOptionChooser", "OptionChooser", "LoadSpecChooser", "DomainFolderOption", "CsHintLoadSpecChooser", "SingleLoaderFilter", "AutoImporter", "MessageLog"]
