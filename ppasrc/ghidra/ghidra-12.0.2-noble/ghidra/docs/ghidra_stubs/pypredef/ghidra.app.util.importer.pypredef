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

    @typing.overload
    def __init__(self, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec):
        """
        Creates a new :obj:`LcsHintLoadSpecChooser`.
         
        
        NOTE: It is assumed that the given :obj:`Language` is valid and it supports the given 
        :obj:`CompilerSpec`.
        
        :param ghidra.program.model.lang.Language language: The :obj:`Language` to use (should not be null)
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: The :obj:`CompilerSpec` to use (if null default compiler spec will be 
        used)
        :raises LanguageNotFoundException: if there was a problem getting the language
        """

    @typing.overload
    def __init__(self, languageId: ghidra.program.model.lang.LanguageID, compilerSpecId: ghidra.program.model.lang.CompilerSpecID):
        """
        Creates a new :obj:`LcsHintLoadSpecChooser`.
         
        
        NOTE: It is assumed that the given :obj:`LanguageID` is valid and it supports the given 
        :obj:`CompilerSpecID`.
        
        :param ghidra.program.model.lang.LanguageID languageId: The :obj:`LanguageID` to use (should not be null)
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecId: The :obj:`CompilerSpecID` to use (if null default compiler spec will 
        be used)
        :raises LanguageNotFoundException: if there was a problem getting the language
        """


@deprecated("Use ProgramLoader.Builder.loaderArgs(List) instead")
class LoaderArgsOptionChooser(OptionChooser):
    """
    An option chooser that applies loader options that were passed in as command line arguments.
    
    
    .. deprecated::
    
    Use :meth:`ProgramLoader.Builder.loaderArgs(List) <ProgramLoader.Builder.loaderArgs>` instead
    """

    class_: typing.ClassVar[java.lang.Class]

    @deprecated("Use ProgramLoader.Builder.loaderArgs(List) instead")
    def __init__(self, loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]):
        """
        Creates a new :obj:`LoaderArgsOptionChooser`
        
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: The :obj:`Loader` arguments
        
        .. deprecated::
        
        Use :meth:`ProgramLoader.Builder.loaderArgs(List) <ProgramLoader.Builder.loaderArgs>` instead
        """


class ProgramLoader(java.lang.Object):
    """
    Used to load (import) a new :obj:`Program`
    """

    class Builder(java.lang.Object):
        """
        A class to configure and perform a :obj:`Program` load
        """

        class_: typing.ClassVar[java.lang.Class]

        def addLoaderArg(self, name: typing.Union[java.lang.String, str], value: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Adds the given :obj:`Loader` argument to use during import.
            
            :param java.lang.String or str name: A single :obj:`Loader` argument name to use during import.
            :param java.lang.String or str value: The value that corresponds to the argument ``name``
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def compiler(self, id: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the compiler to use during import.
             
            
            By default, the processor's default compiler is used.
            
            :param java.lang.String or str id: The compiler spec id to use during import. A ``null`` value will result in
            the language's default compiler being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def compiler(self, id: ghidra.program.model.lang.CompilerSpecID) -> ProgramLoader.Builder:
            """
            Sets the compiler to use during import.
             
            
            By default, the processor's default compiler is used.
            
            :param ghidra.program.model.lang.CompilerSpecID id: The :obj:`CompilerSpecID` to use during import. A ``null`` value will 
            result in the language's default compiler being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def compiler(self, cspec: ghidra.program.model.lang.CompilerSpec) -> ProgramLoader.Builder:
            """
            Sets the compiler to use during import.
             
            
            By default, the processor's default compiler is used.
            
            :param ghidra.program.model.lang.CompilerSpec cspec: The :obj:`CompilerSpec` to use during import. A ``null`` value will 
            result in the language's default compiler being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def language(self, id: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the language to use during import.
             
            
            By default, the first "preferred" language is used.
            
            :param java.lang.String or str id: The language id to use during import. A ``null`` value will result in the
            first "preferred" language being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def language(self, id: ghidra.program.model.lang.LanguageID) -> ProgramLoader.Builder:
            """
            Sets the language to use during import.
             
            
            By default, the first "preferred" language is used.
            
            :param ghidra.program.model.lang.LanguageID id: The :obj:`LanguageID` to use during import. A ``null`` value will result 
            in the first "preferred" language being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def language(self, language: ghidra.program.model.lang.Language) -> ProgramLoader.Builder:
            """
            Sets the language to use during import.
             
            
            By default, the first "preferred" language is used.
            
            :param ghidra.program.model.lang.Language language: The :obj:`Language` to use during import. A ``null`` value will 
            result in the first "preferred" language being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def load(self) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
            """
            Loads the specified :meth:`source <.source>` with this :obj:`Builder`'s 
            current configuration
            
            :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` 
            :obj:`Program`s (created but not saved)
            :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
            :raises IOException: if there was an IO-related problem loading
            :raises LanguageNotFoundException: if there was a problem getting the language
            :raises CancelledException: if the operation was cancelled
            :raises VersionException: if there was an issue with database versions, probably due to a 
            failed language upgrade
            :raises LoadException: if there was a problem loading
            """

        def loaderArgs(self, args: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]) -> ProgramLoader.Builder:
            """
            Sets the :obj:`Loader` arguments to use during import.
             
            
            By default, no :obj:`Loader` arguments are used.
            
            :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] args: A :obj:`List` of :obj:`Loader` argument name/value :obj:`Pair`s to use 
            during import. A ``null`` value will result in no :obj:`Loader` arguments being
            used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def loaders(self, filter: java.util.function.Predicate[ghidra.app.util.opinion.Loader]) -> ProgramLoader.Builder:
            """
            Sets the acceptable :obj:`Loader`s to use during import.
             
            
            By default, all :obj:`Loader`s are accepted (:obj:`LoaderService.ACCEPT_ALL`).
            
            :param java.util.function.Predicate[ghidra.app.util.opinion.Loader] filter: A filter used to limit the :obj:`Loader`s used during import. A 
            ``null`` value will revert back to the default (:obj:`LoaderService.ACCEPT_ALL`).
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def loaders(self, cls: java.lang.Class[ghidra.app.util.opinion.Loader]) -> ProgramLoader.Builder:
            """
            Sets the acceptable :obj:`Loader` to use during import.
             
            
            By default, all :obj:`Loader`s are accepted (:obj:`LoaderService.ACCEPT_ALL`).
            
            :param java.lang.Class[ghidra.app.util.opinion.Loader] cls: The class of the :obj:`Loader` to use during import. A ``null`` value 
            will revert back to the default (:obj:`LoaderService.ACCEPT_ALL`).
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def loaders(self, clsName: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the acceptable :obj:`Loader` to use during import.
             
            
            By default, all :obj:`Loader`s are accepted (:obj:`LoaderService.ACCEPT_ALL`).
            
            :param java.lang.String or str clsName: The class name of the :obj:`Loader` to use during import. A ``null``
            value will revert back to the default (:obj:`LoaderService.ACCEPT_ALL`).
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            :raises InvalidInputException: if the given loader class name did not correspond to a
            :obj:`Loader`
            """

        @typing.overload
        def loaders(self, cls: java.util.List[java.lang.Class[ghidra.app.util.opinion.Loader]]) -> ProgramLoader.Builder:
            """
            Sets the :obj:`Loader`s to use during import.
             
            
            By default, all :obj:`Loader`s are accepted (:obj:`LoaderService.ACCEPT_ALL`).
            
            :param java.util.List[java.lang.Class[ghidra.app.util.opinion.Loader]] cls: A :obj:`List` of classes of :obj:`Loader`s to use during import. A 
            ``null`` value will revert back to the default (:obj:`LoaderService.ACCEPT_ALL`).
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def log(self, messageLog: MessageLog) -> ProgramLoader.Builder:
            """
            Sets the :obj:`log <MessageLog>` to use during import.
             
            
            By default, no log is used.
            
            :param MessageLog messageLog: The :obj:`log <MessageLog>` to use during import. A ``null`` value
            will result in not logging.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def mirror(self, shouldMirror: typing.Union[jpype.JBoolean, bool]) -> ProgramLoader.Builder:
            """
            Sets whether or not the absolute filesystem path of each :obj:`Loaded` :obj:`Program`
            should be mirrored in the project, rooted at the specified
            :meth:`project folder path <.projectFolderPath>`.
             
            
            By default, mirroring is off.
            
            :param jpype.JBoolean or bool shouldMirror: True if filesystem mirroring should happen; otherwise, false.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def monitor(self, mon: ghidra.util.task.TaskMonitor) -> ProgramLoader.Builder:
            """
            Sets the :obj:`TaskMonitor` to use during import.
             
            
            By default, :obj:`TaskMonitor.DUMMY` is used.
            
            :param ghidra.util.task.TaskMonitor mon: The :obj:`TaskMonitor` to use during import. A ``null`` value will result
            in :obj:`TaskMonitor.DUMMY` being used.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def name(self, name: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the name to use for the imported :obj:`Program`.
             
            
            The default is the :obj:`Loader`'s preferred name.
            
            :param java.lang.String or str name: The name to use for the imported :obj:`Program`. A ``null`` value will
            revert the name to the :obj:`Loader`'s preferred name.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def project(self, p: ghidra.framework.model.Project) -> ProgramLoader.Builder:
            """
            Sets the :obj:`Project`. Loaders can use this to take advantage of existing 
            :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
            libraries.
             
            
            By default, no :obj:`Project` is associated with the :obj:`ProgramLoader`.
            
            :param ghidra.framework.model.Project p: The :obj:`Project`. A ``null`` value will unset the project.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        def projectFolderPath(self, path: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the project folder path to load into.
             
            
            The default project folder path is the root of the project (``"/"``).
            
            :param java.lang.String or str path: The project folder path. A ``null`` value will revert the path back to 
            the default value of (``"/"``).
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def source(self, p: ghidra.app.util.bin.ByteProvider) -> ProgramLoader.Builder:
            """
            Sets the required import source to the given :obj:`ByteProvider`.
             
            
            NOTE: Any previously defined sources will be overwritten.
             
            
            NOTE: Ownership of the given :obj:`ByteProvider` is not transfered to this 
            :obj:`Builder`, so it is the responsibility of the caller to properly 
            :meth:`close <ByteProvider.close>` it when done.
            
            :param ghidra.app.util.bin.ByteProvider p: The :obj:`ByteProvider` to import. A ``null`` value will unset the source.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def source(self, f: ghidra.formats.gfilesystem.FSRL) -> ProgramLoader.Builder:
            """
            Sets the required import source to the given :obj:`FSRL`
             
            
            NOTE: Any previously defined sources will be overwritten
            
            :param ghidra.formats.gfilesystem.FSRL f: The :obj:`FSRL` to import. A ``null`` value will unset the source.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def source(self, f: jpype.protocol.SupportsPath) -> ProgramLoader.Builder:
            """
            Sets the required import source to the given :obj:`File`
             
            
            NOTE: Any previously defined sources will be overwritten
            
            :param jpype.protocol.SupportsPath f: The :obj:`File` to import. A ``null`` value will unset the source.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def source(self, b: jpype.JArray[jpype.JByte]) -> ProgramLoader.Builder:
            """
            Sets the required import source to the given bytes
             
            
            NOTE: :meth:`load() <.load>` will fail if a :meth:`name(String) <.name>` is not set
             
            
            NOTE: Any previously defined sources will be overwritten
            
            :param jpype.JArray[jpype.JByte] b: The bytes to import. A ``null`` value will unset the source.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """

        @typing.overload
        def source(self, path: typing.Union[java.lang.String, str]) -> ProgramLoader.Builder:
            """
            Sets the required import source to the given filesystem path
             
            
            NOTE: Any previously defined sources will be overwritten
            
            :param java.lang.String or str path: The filesystem path to import. A ``null`` value will unset the source.
            :return: This :obj:`Builder`
            :rtype: ProgramLoader.Builder
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def builder() -> ProgramLoader.Builder:
        """
        Gets a new :obj:`ProgramLoader` :obj:`Builder` which can be used to load a new 
        :obj:`Program`
        
        :return: A new :obj:`ProgramLoader` :obj:`Builder` which can be used to load a new 
        :obj:`Program`
        :rtype: ProgramLoader.Builder
        """


@deprecated("Use ProgramLoader.Builder.loaderArgs(List) instead")
class OptionChooser(java.lang.Object):
    """
    Chooses which :obj:`Loader` options to use
    
    
    .. deprecated::
    
    Use :meth:`ProgramLoader.Builder.loaderArgs(List) <ProgramLoader.Builder.loaderArgs>` instead
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_OPTIONS: typing.Final[OptionChooser]

    @deprecated("Use ProgramLoader.Builder.loaderArgs(List) instead")
    def choose(self, optionChoices: java.util.List[ghidra.app.util.Option], addressFactory: ghidra.program.model.address.AddressFactory) -> java.util.List[ghidra.app.util.Option]:
        """
        Chooses which :obj:`Loader` options to use
        
        :param java.util.List[ghidra.app.util.Option] optionChoices: A :obj:`List` of available :obj:`Loader` options
        :param ghidra.program.model.address.AddressFactory addressFactory: The address factory
        :return: The :obj:`List` of :obj:`Loader` options to use
        :rtype: java.util.List[ghidra.app.util.Option]
        
        .. deprecated::
        
        Use :meth:`ProgramLoader.Builder.loaderArgs(List) <ProgramLoader.Builder.loaderArgs>` instead
        """

    @deprecated("Use ProgramLoader.Builder.loaderArgs(List) instead")
    def getArgs(self) -> java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]:
        """
        Gets the :obj:`Loader` arguments associated with this :obj:`OptionChooser`
        
        :return: The :obj:`Loader` arguments associated with this :obj:`OptionChooser`
        :rtype: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]
        :raises UnsupportedOperationException: if a subclass has not implemented this method
        
        .. deprecated::
        
        Use :meth:`ProgramLoader.Builder.loaderArgs(List) <ProgramLoader.Builder.loaderArgs>` instead
        """

    @property
    def args(self) -> java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]:
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

    def getCompilerSpecId(self) -> ghidra.program.model.lang.CompilerSpecID:
        """
        Gets the desired :obj:`CompilerSpecID` associated with this chooser
        
        :return: the desired :obj:`CompilerSpecID` associated with this chooser, or ``null`` to
        mean "any"
        :rtype: ghidra.program.model.lang.CompilerSpecID
        """

    def getLanguageId(self) -> ghidra.program.model.lang.LanguageID:
        """
        Gets the desired :obj:`LanguageID` associated with this chooser
        
        :return: the desired :obj:`LanguageID` associated with this chooser, or ``null`` to mean
        "any"
        :rtype: ghidra.program.model.lang.LanguageID
        """

    @property
    def languageId(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def compilerSpecId(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...


class DomainFolderOption(ghidra.app.util.Option):
    """
    An :obj:`Option` used to specify a :obj:`DomainFolder`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], arg: typing.Union[java.lang.String, str], hidden: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`DomainFolderOption`
        
        :param java.lang.String or str name: The name of the option
        :param java.lang.String or str arg: The option's command line argument (could be null)
        :param jpype.JBoolean or bool hidden: true if this option should be hidden from the user; otherwise, false
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


@deprecated("Use ProgramLoader.Builder.loaders(Class) instead")
class SingleLoaderFilter(java.util.function.Predicate[ghidra.app.util.opinion.Loader]):
    """
    Filters on one specific loader
    
    
    .. deprecated::
    
    Use :meth:`ProgramLoader.Builder.loaders(Class) <ProgramLoader.Builder.loaders>` instead
    """

    class_: typing.ClassVar[java.lang.Class]

    @deprecated("Use ProgramLoader.Builder.loaders(Class) instead")
    def __init__(self, single: java.lang.Class[ghidra.app.util.opinion.Loader]):
        """
        Create a new single loader filter from the given loader class.
        
        :param java.lang.Class[ghidra.app.util.opinion.Loader] single: The loader class used for this filter.
        
        .. deprecated::
        
        Use :meth:`ProgramLoader.Builder.loaders(Class) <ProgramLoader.Builder.loaders>` instead
        """


@deprecated("Use ProgramLoader")
class AutoImporter(java.lang.Object):
    """
    Utility methods to do :obj:`Program` imports automatically (without requiring user interaction)
    
    
    .. deprecated::
    
    Use :obj:`ProgramLoader`
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importAsBinary(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the :obj:`BinaryLoader`, using the given
        language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program` is 
        not saved to a project.  That is the responsibility of the caller (see 
        :meth:`Loaded.save(TaskMonitor) <Loaded.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program` with :meth:`Loaded.close() <Loaded.close>` when it is no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`Loaded` 
        :obj:`Program`, used to ensure the underlying :obj:`Program` is only closed when every 
        consumer is done with it (see :meth:`Loaded.close() <Loaded.close>`).
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
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importAsBinary(bytes: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`ByteProvider` bytes with the :obj:`BinaryLoader`, 
        using the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program` is 
        not saved to a project.  That is the responsibility of the caller (see 
        :meth:`Loaded.save(TaskMonitor) <Loaded.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program` with :meth:`Loaded.close() <Loaded.close>` when it is no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`Loaded` 
        :obj:`Program`, used to ensure the underlying :obj:`Program` is only closed when every 
        consumer is done with it (see :meth:`Loaded.close() <Loaded.close>`).
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
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByLookingForLcs(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the best matching :obj:`Loader` that
        supports the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByLookingForLcs(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the best matching :obj:`Loader` that
        supports the given language and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingBestGuess(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the best matching :obj:`Loader` for the
        :obj:`File`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
        :param jpype.protocol.SupportsPath file: The :obj:`File` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingBestGuess(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the best matching :obj:`Loader` for the
        :obj:`File`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The :obj:`FSRL` to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingBestGuess(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the give :obj:`bytes <ByteProvider>` with the best matching 
        :obj:`Loader` for the :obj:`ByteProvider`'s format.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
        :param ghidra.app.util.bin.ByteProvider provider: The bytes to import
        :param ghidra.framework.model.Project project: The :obj:`Project`.  Loaders can use this to take advantage of existing
        :obj:`DomainFolder`s and :obj:`DomainFile`s to do custom behaviors such as loading
        libraries. Could be null if there is no project.
        :param java.lang.String or str projectFolderPath: A suggested project folder path for the :obj:`Loaded` 
        :obj:`Program`s. This is just a suggestion, and a :obj:`Loader` implementation 
        reserves the right to change it for each :obj:`Loaded` result. The :obj:`Loaded` results 
        should be queried for their true project folder paths using 
        :meth:`Loaded.getProjectFolderPath() <Loaded.getProjectFolderPath>`.
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingSpecificLoaderClass(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the given type of :obj:`Loader`.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingSpecificLoaderClass(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the given type of :obj:`Loader`.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingSpecificLoaderClassAndLcs(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with the given type of :obj:`Loader`, language,
        and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importByUsingSpecificLoaderClassAndLcs(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], loaderClass: java.lang.Class[ghidra.app.util.opinion.Loader], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with the given type of :obj:`Loader`, language,
        and compiler specification.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to close the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importFresh(file: jpype.protocol.SupportsPath, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`File` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importFresh(fsrl: ghidra.formats.gfilesystem.FSRL, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`FSRL` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
        """

    @staticmethod
    @typing.overload
    @deprecated("Use ProgramLoader")
    def importFresh(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: typing.Union[java.lang.String, str], consumer: java.lang.Object, messageLog: MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate[ghidra.app.util.opinion.Loader], loadSpecChooser: LoadSpecChooser, importNameOverride: typing.Union[java.lang.String, str], optionChooser: OptionChooser) -> ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]:
        """
        Automatically imports the given :obj:`bytes <ByteProvider>` with advanced options.
         
        
        Note that when the import completes, the returned :obj:`Loaded` :obj:`Program`s are not 
        saved to a project.  That is the responsibility of the caller (see 
        :meth:`LoadResults.save(TaskMonitor) <LoadResults.save>`).
         
        
        It is also the responsibility of the caller to release the returned :obj:`Loaded` 
        :obj:`Program`s with :meth:`LoadResults.close() <LoadResults.close>` when they are no longer needed.
        
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
        :param java.lang.Object consumer: A reference to the object "consuming" the returned :obj:`LoadResults`, used
        to ensure the underlying :obj:`Program`s are only closed when every consumer is done
        with it (see :meth:`LoadResults.close() <LoadResults.close>`).
        :param MessageLog messageLog: The log
        :param ghidra.util.task.TaskMonitor monitor: A task monitor
        :return: The :obj:`LoadResults` which contains one or more :obj:`Loaded` :obj:`Program`s 
        (created but not saved)
        :rtype: ghidra.app.util.opinion.LoadResults[ghidra.program.model.listing.Program]
        :raises IOException: if there was an IO-related problem loading
        :raises CancelledException: if the operation was cancelled
        :raises DuplicateNameException: if the load resulted in a :obj:`Program` naming conflict
        :raises InvalidNameException: if an invalid :obj:`Program` name was used during load
        :raises VersionException: if there was an issue with database versions, probably due to a 
        failed language upgrade
        :raises LoadException: if nothing was loaded
        
        .. deprecated::
        
        Use :obj:`ProgramLoader`
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



__all__ = ["LibrarySearchPathManager", "LibrarySearchPathDummyOption", "MultipleProgramsException", "LcsHintLoadSpecChooser", "LoaderArgsOptionChooser", "ProgramLoader", "OptionChooser", "LoadSpecChooser", "DomainFolderOption", "CsHintLoadSpecChooser", "SingleLoaderFilter", "AutoImporter", "MessageLog"]
