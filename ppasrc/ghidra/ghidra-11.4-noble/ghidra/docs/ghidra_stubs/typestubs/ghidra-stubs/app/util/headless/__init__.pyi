from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.stl
import ghidra
import ghidra.app.script
import ghidra.framework.project
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore


@typing.type_check_only
class HeadlessErrorLogger(ghidra.util.ErrorLogger):
    """
    Custom headless error logger which is used when log4j is disabled.
    """

    class_: typing.ClassVar[java.lang.Class]


class GhidraScriptRunner(ghidra.GhidraLaunchable):
    """
    A simple class for running scripts outside of Ghidra.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HeadlessTimedTaskMonitor(ghidra.util.task.TaskMonitor):
    """
    Monitor used by Headless Analyzer for "timeout" functionality
    """

    @typing.type_check_only
    class TimeOutTask(java.util.TimerTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class AnalyzeHeadless(ghidra.GhidraLaunchable):
    """
    Launcher entry point for running headless Ghidra.
    """

    @typing.type_check_only
    class Arg(java.lang.Enum[AnalyzeHeadless.Arg]):
        """
        Headless command line arguments.
         
        
        NOTE: Please update 'analyzeHeadlessREADME.html' if changing command line parameters
        """

        class_: typing.ClassVar[java.lang.Class]
        IMPORT: typing.Final[AnalyzeHeadless.Arg]
        PROCESS: typing.Final[AnalyzeHeadless.Arg]
        PRE_SCRIPT: typing.Final[AnalyzeHeadless.Arg]
        POST_SCRIPT: typing.Final[AnalyzeHeadless.Arg]
        SCRIPT_PATH: typing.Final[AnalyzeHeadless.Arg]
        PROPERTIES_PATH: typing.Final[AnalyzeHeadless.Arg]
        SCRIPT_LOG: typing.Final[AnalyzeHeadless.Arg]
        LOG: typing.Final[AnalyzeHeadless.Arg]
        OVERWRITE: typing.Final[AnalyzeHeadless.Arg]
        RECURSIVE: typing.Final[AnalyzeHeadless.Arg]
        READ_ONLY: typing.Final[AnalyzeHeadless.Arg]
        DELETE_PROJECT: typing.Final[AnalyzeHeadless.Arg]
        NO_ANALYSIS: typing.Final[AnalyzeHeadless.Arg]
        PROCESSOR: typing.Final[AnalyzeHeadless.Arg]
        CSPEC: typing.Final[AnalyzeHeadless.Arg]
        ANALYSIS_TIMEOUT_PER_FILE: typing.Final[AnalyzeHeadless.Arg]
        KEYSTORE: typing.Final[AnalyzeHeadless.Arg]
        CONNECT: typing.Final[AnalyzeHeadless.Arg]
        PASSWORD: typing.Final[AnalyzeHeadless.Arg]
        COMMIT: typing.Final[AnalyzeHeadless.Arg]
        OK_TO_DELETE: typing.Final[AnalyzeHeadless.Arg]
        MAX_CPU: typing.Final[AnalyzeHeadless.Arg]
        LIBRARY_SEARCH_PATHS: typing.Final[AnalyzeHeadless.Arg]
        LOADER: typing.Final[AnalyzeHeadless.Arg]
        LOADER_ARGS: typing.Final[AnalyzeHeadless.Arg]

        def matches(self, arg: typing.Union[java.lang.String, str]) -> bool:
            ...

        def usage(self) -> str:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AnalyzeHeadless.Arg:
            ...

        @staticmethod
        def values() -> jpype.JArray[AnalyzeHeadless.Arg]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def launch(self, layout: ghidra.GhidraApplicationLayout, args: jpype.JArray[java.lang.String]):
        """
        The entry point of 'analyzeHeadless.bat'. Parses the command line arguments to the script
        and takes the appropriate headless actions.
        
        :param jpype.JArray[java.lang.String] args: Detailed list of arguments is in 'analyzeHeadlessREADME.html'
        """

    @staticmethod
    def usage(execCmd: typing.Union[java.lang.String, str]):
        """
        Prints out the usage details and exits the Java application with an exit code that
        indicates error.
        
        :param java.lang.String or str execCmd: the command used to run the headless analyzer from the calling method.
        """


class HeadlessOptions(java.lang.Object):
    """
    Options for headless analyzer.
     
    
    Option state may be adjusted to reflect assumed options
    during processing.  If multiple invocations of either
    :meth:`HeadlessAnalyzer.processLocal(String, String, String, List) <HeadlessAnalyzer.processLocal>` or
    :meth:`HeadlessAnalyzer.processURL(java.net.URL, List) <HeadlessAnalyzer.processURL>` are performed,
    these options should be reset and adjusted as necessary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def enableAnalysis(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Auto-analysis is enabled by default following import.  This method can be
        used to change the enablement of auto-analysis.
        
        :param jpype.JBoolean or bool enabled: True if auto-analysis should be enabled; otherwise, false.
        """

    def enableOverwriteOnConflict(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        During import, the default behavior is to skip the import if a conflict occurs 
        within the destination folder.  This method can be used to force the original 
        conflicting file to be removed prior to import.
        If the pre-existing file is versioned, the commit option must also be
        enabled to have the overwrite remove the versioned file.
        
        :param jpype.JBoolean or bool enabled: if true conflicting domain files will be removed from the 
        project prior to importing the new file.
        """

    def enableReadOnlyProcessing(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        When readOnly processing is enabled, any changes made by script or analyzers
        are discarded when the Headless Analyzer exits.  When used with import mode,
        the imported program file will not be saved to the project or repository.
        
        :param jpype.JBoolean or bool enabled: if true, enables readOnly processing or import
        """

    @typing.overload
    def enableRecursiveProcessing(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        This method can be used to enable recursive processing of files during
        ``-import`` or ``-process`` modes.  In order for recursive processing of 
        files to occur, the user must have specified a project folder to process or a directory or 
        supported :obj:`GFileSystem` container file to import
        
        :param jpype.JBoolean or bool enabled: if true, enables recursive import/processing
        """

    @typing.overload
    def enableRecursiveProcessing(self, enabled: typing.Union[jpype.JBoolean, bool], depth: typing.Union[java.lang.Integer, int]):
        """
        This method can be used to enable recursive processing of files during
        ``-import`` or ``-process`` modes.  In order for recursive processing of 
        files to occur, the user must have specified a project folder to process or a directory or 
        supported :obj:`GFileSystem` container file to import
        
        :param jpype.JBoolean or bool enabled: if true, enables recursive import/processing
        :param java.lang.Integer or int depth: maximum container recursion depth (could be null to use default)
        """

    def reset(self):
        """
        Resets the options to its default settings.
        """

    def setClientCredentials(self, userID: typing.Union[java.lang.String, str], keystorePath: typing.Union[java.lang.String, str], allowPasswordPrompt: typing.Union[jpype.JBoolean, bool]):
        """
        Set Ghidra Server client credentials to be used with "shared" projects.
        
        :param java.lang.String or str userID: optional userId to use if server permits the user to use
        a userId which differs from the process owner name.
        :param java.lang.String or str keystorePath: file path to keystore file containing users private key
        to be used with PKI or SSH based authentication.
        :param jpype.JBoolean or bool allowPasswordPrompt: if true the user may be prompted for passwords
        via the console (stdin).  Please note that the Java console will echo 
        the password entry to the terminal which may be undesirable.
        :raises IOException: if an error occurs while opening the specified keystorePath.
        """

    def setCommitFiles(self, commit: typing.Union[jpype.JBoolean, bool], comment: typing.Union[java.lang.String, str]):
        """
        Enable committing of processed files to the repository which backs the specified
        project.
        
        :param jpype.JBoolean or bool commit: if true imported files will be committed
        :param java.lang.String or str comment: optional comment to use when committing
        """

    def setDeleteCreatedProjectOnClose(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Set project delete flag which allows temporary projects created
        to be deleted upon completion.  This option has no effect if a 
        Ghidra URL or an existing project was specified.  This option
        will be assumed when importing with the readOnly option enabled.
        
        :param jpype.JBoolean or bool enabled: if true a created project will be deleted when 
        processing is complete.
        """

    def setLanguageAndCompiler(self, languageId: typing.Union[java.lang.String, str], compilerSpecId: typing.Union[java.lang.String, str]):
        """
        Sets the language and compiler spec from the provided input. Any null value will attempt
        a "best-guess" if possible.
        
        :param java.lang.String or str languageId: The language to set.
        :param java.lang.String or str compilerSpecId: The compiler spec to set.
        :raises InvalidInputException: if the language and compiler spec combination is not valid.
        """

    def setLoader(self, loaderName: typing.Union[java.lang.String, str], loaderArgs: java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]]):
        """
        Sets the loader to use for imports, as well as any loader-specific arguments.  A null loader 
        will attempt "best-guess" if possible.  Loader arguments are not supported if a "best-guess"
        is made.
        
        :param java.lang.String or str loaderName: The name (simple class name) of the loader to use.
        :param java.util.List[generic.stl.Pair[java.lang.String, java.lang.String]] loaderArgs: A list of loader-specific arguments.  Could be null if there are none.
        :raises InvalidInputException: if an invalid loader name was specified, or if loader arguments
        were specified but a loader was not.
        """

    def setMaxCpu(self, cpu: typing.Union[jpype.JInt, int]):
        """
        Sets the maximum number of cpu cores to use during headless processing.
        
        :param jpype.JInt or int cpu: The maximum number of cpu cores to use during headless processing.
            Setting it to 0 or a negative integer is equivalent to setting it to 1.
        """

    def setOkToDelete(self, deleteOk: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def setPerFileAnalysisTimeout(self, stringInSecs: typing.Union[java.lang.String, str]):
        """
        Set analyzer timeout on a per-file basis.
        
        :param java.lang.String or str stringInSecs: timeout value in seconds (as a String)
        :raises InvalidInputException: if the timeout value was not a valid value
        """

    @typing.overload
    def setPerFileAnalysisTimeout(self, secs: typing.Union[jpype.JInt, int]):
        ...

    def setPostScripts(self, postScripts: java.util.List[java.lang.String]):
        """
        Set the ordered list of scripts to execute immediately following import and
        and analysis of a program.  If import not performed,
        these scripts will execute once following any pre-scripts.
        
        :param java.util.List[java.lang.String] postScripts: list of script names
        """

    def setPostScriptsWithArgs(self, postScripts: java.util.List[generic.stl.Pair[java.lang.String, jpype.JArray[java.lang.String]]]):
        """
        Set the ordered list of scripts to execute immediately following import and
        and analysis of a program.  If import not performed,
        these scripts will execute once following any pre-scripts.
        
        :param java.util.List[generic.stl.Pair[java.lang.String, jpype.JArray[java.lang.String]]] postScripts: list of script names/script argument pairs
        """

    def setPreScripts(self, preScripts: java.util.List[java.lang.String]):
        """
        Set the ordered list of scripts to execute immediately following import and
        prior to analyzing an imported program.  If import not performed,
        these scripts will execute once prior to any post-scripts.
        
        :param java.util.List[java.lang.String] preScripts: list of script names
        """

    def setPreScriptsWithArgs(self, preScripts: java.util.List[generic.stl.Pair[java.lang.String, jpype.JArray[java.lang.String]]]):
        """
        Set the ordered list of scripts and their arguments to execute immediately following import 
        and prior to analyzing an imported program.  If import not performed,
        these scripts will execute once prior to any post-scripts.
        
        :param java.util.List[generic.stl.Pair[java.lang.String, jpype.JArray[java.lang.String]]] preScripts: list of script names/script argument pairs
        """

    @typing.overload
    def setPropertiesFileDirectories(self, newPaths: java.util.List[java.lang.String]):
        """
        Sets one or more locations to find .properties files associated with GhidraScripts.
         
        Typically, .properties files should be located in the same directory as their corresponding 
        scripts. However, this method may need to be used when circumstances make it impossible to
        have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
        
        :param java.util.List[java.lang.String] newPaths: potential locations of .properties file(s)
        """

    @typing.overload
    def setPropertiesFileDirectories(self, paths: typing.Union[java.lang.String, str]):
        """
        List of valid .properties file directory paths, separated by a ';'.
         
        Typically, .properties files should be located in the same directory as their corresponding 
        scripts. However, this method may need to be used when circumstances make it impossible to
        have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
        
        :param java.lang.String or str paths: String representation of directories (each separated by ';')
        """

    def setPropertiesFileDirectory(self, path: typing.Union[java.lang.String, str]):
        """
        Sets a single location for .properties files associated with GhidraScripts.
         
        Typically, .properties files should be located in the same directory as their corresponding 
        scripts. However, this method may need to be used when circumstances make it impossible to
        have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
        
        :param java.lang.String or str path: location of .properties file(s)
        """

    def setRunScriptsNoImport(self, runScriptsOnly: typing.Union[jpype.JBoolean, bool], filename: typing.Union[java.lang.String, str]):
        """
        Set to run scripts (and optionally, analysis) without importing a
        program.  Scripts will run on specified folder or program that already
        exists in the project.
        
        :param jpype.JBoolean or bool runScriptsOnly: if true, no imports will occur and scripts
                                (and analysis, if enabled) will run on the specified existing program
                                or directory of programs.
        :param java.lang.String or str filename: name of specific project file or folder to be processed (the location
                            is passed in elsewhere by the user).  If null, user has not specified
                            a file to process -- therefore, the entire directory will be processed.
                            The filename should not include folder path elements which should be 
                        specified separately via project or URL specification.
        :raises IllegalArgumentException: if the specified filename is invalid and contains the
        path separator character '/'.
        """

    @typing.overload
    def setScriptDirectories(self, newPaths: java.util.List[java.lang.String]):
        """
        Set the script source directories to be searched for secondary scripts.
        The default set of enabled script directories within the Ghidra installation 
        will be appended to the specified list of newPaths.
        Individual Paths may be constructed relative to Ghidra installation directory,
        User home directory, or absolute system paths.  Examples:
         
            Path.GHIDRA_HOME + "/Ghidra/Features/Base/ghidra_scripts"
            Path.USER_HOME + "/Ghidra/Features/Base/ghidra_scripts"
            "/shared/ghidra_scripts"
         
        
        :param java.util.List[java.lang.String] newPaths: list of directories to be searched.
        """

    @typing.overload
    def setScriptDirectories(self, paths: typing.Union[java.lang.String, str]):
        """
        List of valid script directory paths separated by a ';'.
        The default set of enabled script directories within the Ghidra installation 
        will be appended to the specified list of newPaths.
        Individual Paths may be constructed relative to Ghidra installation directory,
        User home directory, or absolute system paths.  Examples:
         
                Path.GHIDRA_HOME + "/Ghidra/Features/Base/ghidra_scripts"
            Path.USER_HOME + "/Ghidra/Features/Base/ghidra_scripts"
                "/shared/ghidra_scripts"
         
        
        :param java.lang.String or str paths: semicolon (';') separated list of directory paths
        """


class HeadlessAnalyzer(java.lang.Object):
    """
    The class used kick-off and interact with headless processing.  All headless options have been
    broken out into their own class: :obj:`HeadlessOptions`.  This class is intended to be used
    one of two ways:
     
    * Used by :obj:`AnalyzeHeadless` to perform headless analysis based on arguments specified
    on the command line.
    * Used by another tool as a library to perform headless analysis.
    
     
    
    Note: This class is not thread safe.
    """

    @typing.type_check_only
    class HeadlessProject(ghidra.framework.project.DefaultProject):
        """
        Ghidra project class required to gain access to specialized project constructor
        for URL connection.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HeadlessGhidraProjectManager(ghidra.framework.project.DefaultProjectManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def checkAnalysisTimedOut(self) -> bool:
        """
        Checks to see if the most recent analysis timed out.
        
        :return: true if the most recent analysis timed out; otherwise, false.
        :rtype: bool
        """

    @staticmethod
    def getInstance() -> HeadlessAnalyzer:
        """
        Gets a headless analyzer instance, with the assumption that the application has already been
        initialized.  If this is called before the application has been initialized, it will
        initialize the application with no logging.
        
        :return: An instance of a new headless analyzer.
        :rtype: HeadlessAnalyzer
        :raises IOException: if there was a problem reading the application.properties file (only possible
            if the application had not be initialized).
        """

    @staticmethod
    def getLoggableInstance(logFile: jpype.protocol.SupportsPath, scriptLogFile: jpype.protocol.SupportsPath, useLog4j: typing.Union[jpype.JBoolean, bool]) -> HeadlessAnalyzer:
        """
        Gets a headless analyzer, initializing the application if necessary with the specified
        logging parameters.  An :obj:`IllegalStateException` will be thrown if the application has
        already been initialized or a headless analyzer has already been retrieved.  In these cases,
        the headless analyzer should be gotten with :meth:`HeadlessAnalyzer.getInstance() <HeadlessAnalyzer.getInstance>`.
        
        :param jpype.protocol.SupportsPath logFile: The desired application log file.  If null, the default application log file
        will be used (see :obj:`Application.initializeLogging`).
        :param jpype.protocol.SupportsPath scriptLogFile: The desired scripting log file.  If null, the default scripting log file
        will be used (see :obj:`Application.initializeLogging`).
        :param jpype.JBoolean or bool useLog4j: true if log4j is to be used; otherwise, false.  If this class is being used by
            another tool as a library, using log4j might interfere with that tool.
        :return: An instance of a new headless analyzer.
        :rtype: HeadlessAnalyzer
        :raises java.lang.IllegalStateException: if an application or headless analyzer instance has already been initialized.
        :raises IOException: if there was a problem reading the application.properties file.
        """

    def getOptions(self) -> HeadlessOptions:
        """
        Gets the headless analyzer's options.
        
        :return: The headless analyer's options.
        :rtype: HeadlessOptions
        """

    def processLocal(self, projectLocation: typing.Union[java.lang.String, str], projectName: typing.Union[java.lang.String, str], rootFolderPath: typing.Union[java.lang.String, str], filesToImport: java.util.List[java.io.File]):
        """
        Process the optional import file/directory list and process each imported file:
         
        1. execute ordered list of pre-scripts
        2. perform auto-analysis if not disabled
        3. execute ordered list of post-scripts
        
        If no import files or directories have been specified the ordered list
        of pre/post scripts will be executed once.
        
        :param java.lang.String or str projectLocation: directory path of project
                                If project exists it will be opened, otherwise it will be created.
        :param java.lang.String or str projectName: project name
        :param java.lang.String or str rootFolderPath: root folder for imports
        :param java.util.List[java.io.File] filesToImport: directories and files to be imported (null or empty is acceptable if
                                we are in -process mode)
        :raises IOException: if there was an IO-related problem.  If caused by a failure to obtain a
        write-lock on the project the exception cause will a ``LockException``.
        """

    def processURL(self, ghidraURL: java.net.URL, filesToImport: java.util.List[java.io.File]):
        """
        Process the optional import file/directory list and process each imported file:
         
        1. execute ordered list of pre-scripts
        2. perform auto-analysis if not disabled
        3. execute ordered list of post-scripts
        
        If no import files or directories have been specified the ordered list
        of pre/post scripts will be executed once.
        
        :param java.net.URL ghidraURL: ghidra URL for existing server repository and optional
                        folder path
        :param java.util.List[java.io.File] filesToImport: directories and files to be imported (null or empty
                            is acceptable if we are in -process mode)
        :raises IOException: if there was an IO-related problem
        :raises MalformedURLException: specified URL is invalid
        """

    def reset(self):
        """
        Resets the state of the headless analyzer to the default settings.
        """

    @property
    def options(self) -> HeadlessOptions:
        ...


class HeadlessScript(ghidra.app.script.GhidraScript):
    """
    This class is analogous to GhidraScript, except that is only meant to be used with
    the HeadlessAnalyzer.  That is, if a user writes a script that extends HeadlessScript,
    it should only be run in the Headless environment.
    """

    class HeadlessContinuationOption(java.lang.Enum[HeadlessScript.HeadlessContinuationOption]):
        """
        Options for controlling disposition of program after the current script completes.
        """

        class_: typing.ClassVar[java.lang.Class]
        CONTINUE: typing.Final[HeadlessScript.HeadlessContinuationOption]
        """
        Continue running scripts and/or analysis; ``-import`` and ``-process`` 
        modes complete normally.
        """

        CONTINUE_THEN_DELETE: typing.Final[HeadlessScript.HeadlessContinuationOption]
        """
        Continue running scripts and/or analysis; 
        ``-import`` mode does not save program, 
        ``-process`` mode deletes program.
        """

        ABORT_AND_DELETE: typing.Final[HeadlessScript.HeadlessContinuationOption]
        """
        Abort any scripts or analysis that come after this script;
        ``-import`` mode does not save program, ``-process`` mode deletes program.
        """

        ABORT: typing.Final[HeadlessScript.HeadlessContinuationOption]
        """
        Abort any scripts or analysis that come after this script; ``-import`` mode does 
        save program (but it may not be processed completely),
        ``-process`` mode completes normally, minus scripts or analysis that 
        runs after the ABORT request.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> HeadlessScript.HeadlessContinuationOption:
            ...

        @staticmethod
        def values() -> jpype.JArray[HeadlessScript.HeadlessContinuationOption]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def analysisTimeoutOccurred(self) -> bool:
        """
        Returns whether analysis for the current program has timed out.
         
        
        Analysis will time out only in the case where:
         
        1. the users has set an analysis timeout period using the -analysisTimeoutPerFile
        parameter
        2. analysis is enabled and has completed
        3. the current script is being run as a postScript (since postScripts run after
        analysis)
        
        
        :return: whether analysis timeout occurred
        :rtype: bool
        :raises ImproperUseException: if not in headless mode or headless instance not set
        """

    def enableHeadlessAnalysis(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Enables or disables analysis according to the passed-in boolean value.
         
        
        A script that calls this method should run as a 'preScript', since preScripts
        execute before analysis would typically run. Running the script as a 'postScript'
        is ineffective, since the stage at which analysis would have happened has already 
        passed.
         
        
        This change will persist throughout the current HeadlessAnalyzer session, unless
        changed again (in other words, once analysis is enabled via script for one program,
        it will also be enabled for future programs in the current session, unless changed).
        
        :param jpype.JBoolean or bool b: true to enable analysis, false to disable analysis
        :raises ImproperUseException: if not in headless mode or headless instance not set
        
        .. seealso::
        
            | :obj:`.isHeadlessAnalysisEnabled()`
        """

    def getHeadlessContinuationOption(self) -> HeadlessScript.HeadlessContinuationOption:
        """
        Returns the continuation option for the current script (if one has not been set in this
        script, the option defaults to CONTINUE).
         
        
        The continuation option specifies whether to continue or abort follow-on processing,
        and whether to delete or keep the current program.
        
        :return: the current HeadlessContinuationOption
        :rtype: HeadlessScript.HeadlessContinuationOption
        
        .. seealso::
        
            | :obj:`.setHeadlessContinuationOption(HeadlessContinuationOption)`
        """

    def getStoredHeadlessValue(self, key: typing.Union[java.lang.String, str]) -> java.lang.Object:
        """
        Get stored value by key from the HeadlessAnalyzer instance.
         
        
        This method, along with the 'storedHeadlessValue' method, is useful for debugging and 
        testing the Headless Analyzer (when the user has directly instantiated the HeadlessAnalyzer
        instead of running it from analyzeHeadless.sh or analyzeHeadless.bat). This method is
        intended to allow a HeadlessScript to store variables that reflect the current state of 
        processing (at the time the script is being run). Storing variables in the HeadlessAnalyzer
        instance may be the only way to access the state of processing during cases when the user 
        is forced to run in -readOnly mode, or if there is a value that is only accessible at the 
        scripts stage.
        
        :param java.lang.String or str key: key to retrieve the desired stored value
        :return: stored Object, or null if none exists for that key
        :rtype: java.lang.Object
        :raises ImproperUseException: if not in headless mode or headless instance not set
        
        .. seealso::
        
            | :obj:`.storeHeadlessValue(String, Object)`
        
            | :obj:`.headlessStorageContainsKey(String)`
        """

    def headlessStorageContainsKey(self, key: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns whether the specified key was stored in the HeadlessAnalyzer instance.
        
        :param java.lang.String or str key: value of key to check for in Headless Analyzer instance
        :return: true if the specified key exists
        :rtype: bool
        :raises ImproperUseException: if not in headless mode or headless instance not set
        
        .. seealso::
        
            | :obj:`.storeHeadlessValue(String, Object)`
        
            | :obj:`.getStoredHeadlessValue(String)`
        """

    def isHeadlessAnalysisEnabled(self) -> bool:
        """
        Returns whether analysis is currently enabled or disabled in the HeadlessAnalyzer.
        
        :return: whether analysis has been enabled or not
        :rtype: bool
        :raises ImproperUseException: if not in headless mode or headless instance not set
        
        .. seealso::
        
            | :obj:`.enableHeadlessAnalysis(boolean)`
        """

    def isImporting(self) -> bool:
        """
        Returns whether the headless analyzer is currently set to -import mode or not (if not,
        it is in -process mode). The use of -import mode implies that binaries are actively being
        imported into the project (with optional scripts/analysis). The use of -process mode implies
        that existing project files are being processed (using scripts and/or analysis).
        
        :return: whether we are in -import mode or not
        :rtype: bool
        :raises ImproperUseException: if not in headless mode or headless instance not set
        """

    def setHeadlessContinuationOption(self, option: HeadlessScript.HeadlessContinuationOption):
        """
        Sets the continuation option for this script
         
        
        The continuation option specifies whether to continue or abort follow-on processing,
        and whether to delete or keep the current program.
        
        :param HeadlessScript.HeadlessContinuationOption option: HeadlessContinuationOption set by this script
        
        .. seealso::
        
            | :obj:`.getHeadlessContinuationOption()`
        """

    def setHeadlessImportDirectory(self, importDir: typing.Union[java.lang.String, str]):
        """
        Changes the path *in the Ghidra project* where imported files are saved. 
        The passed-in path is assumed to be relative to the project root. For example,
        if the directory structure for the Ghidra project looks like this:
         
         
                MyGhidraProject:
                /dir1
                    /innerDir1
                    /innerDir2
         
         
        Then the following usage would ensure that any files imported after this call would
        be saved in the ``MyGhidraProject:/dir1/innerDir2`` folder.
         
                setHeadlessImportDirectory("dir1/innerDir2");
         
        In contrast, the following usages would add new folders to the Ghidra project and save
        the imported files into the newly-created path:
         
                setHeadlessImportDirectory("innerDir2/my/folder");
         
        changes the directory structure to:
         
                MyGhidraProject:
                /dir1
                    /innerDir1
                    /innerDir2
                    /my
                        /folder
         
        and:
         
                setHeadlessImportDirectory("newDir/saveHere");
         
        changes the directory structure to:
         
                MyGhidraProject:
                /dir1
                    /innerDir1
                    /innerDir2
                /newDir
                    /saveHere
         
        As in the examples above, if the desired folder does not already exist, it is created.
         
        
        A change in the import save folder will persist throughout the current HeadlessAnalyzer 
        session, unless changed again (in other words, once the import directory has been changed, 
        it will remain the 'save' directory for import files in the current session, unless changed).
         
        
        To revert back to the default import location (that which was specified via command line),
        pass the null object as the argument to this method, as below:
         
                setHeadlessImportDirectory(null);    // Sets import save directory to default
         
        If a file with the same name already exists in the desired location, it will only be 
        overwritten if "-overwrite" is true.
         
        
        This method is only applicable when using the HeadlessAnalyzer ``-import`` mode and 
        is ineffective in ``-process`` mode.
        
        :param java.lang.String or str importDir: the absolute path (relative to root) where inputs will be saved
        :raises ImproperUseException: if not in headless mode or headless instance not set
        :raises IOException: if there are issues creating the folder
        :raises InvalidNameException: if folder name is invalid
        """

    def storeHeadlessValue(self, key: typing.Union[java.lang.String, str], value: java.lang.Object):
        """
        Stores a key/value pair in the HeadlessAnalyzer instance for later use.
         
        
        This method, along with the 'getStoredHeadlessValue' method, is useful for debugging and 
        testing the Headless Analyzer (when the user has directly instantiated the HeadlessAnalyzer
        instead of running it from analyzeHeadless.sh or analyzeHeadless.bat). This method is
        intended to allow a HeadlessScript to store variables that reflect the current state of 
        processing (at the time the script is being run). Storing variables in the HeadlessAnalyzer
        instance may be the only way to access the state of processing during cases when the user 
        is forced to run in -readOnly mode, or if there is a value that is only accessible at the 
        scripts stage.
        
        :param java.lang.String or str key: storage key in String form
        :param java.lang.Object value: value to store
        :raises ImproperUseException: if not in headless mode or headless instance not set
        
        .. seealso::
        
            | :obj:`.getStoredHeadlessValue(String)`
        
            | :obj:`.headlessStorageContainsKey(String)`
        """

    @property
    def storedHeadlessValue(self) -> java.lang.Object:
        ...

    @property
    def headlessContinuationOption(self) -> HeadlessScript.HeadlessContinuationOption:
        ...

    @headlessContinuationOption.setter
    def headlessContinuationOption(self, value: HeadlessScript.HeadlessContinuationOption):
        ...

    @property
    def headlessAnalysisEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def importing(self) -> jpype.JBoolean:
        ...



__all__ = ["HeadlessErrorLogger", "GhidraScriptRunner", "HeadlessTimedTaskMonitor", "AnalyzeHeadless", "HeadlessOptions", "HeadlessAnalyzer", "HeadlessScript"]
