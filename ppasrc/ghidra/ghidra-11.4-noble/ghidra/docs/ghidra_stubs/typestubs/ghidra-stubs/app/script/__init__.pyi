from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import generic.jar
import ghidra.app.plugin.core.osgi
import ghidra.app.tablechooser
import ghidra.features.base.values
import ghidra.framework.cmd
import ghidra.framework.generic.auth
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.exception
import ghidra.util.task
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.regex # type: ignore
import javax.swing # type: ignore
import javax.tools # type: ignore
import org.apache.logging.log4j.message # type: ignore


R = typing.TypeVar("R")
T = typing.TypeVar("T")


@typing.type_check_only
class GhidraScriptUnsupportedClassVersionError(java.lang.RuntimeException):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraScriptInfoManager(java.lang.Object):
    """
    A utility class for managing script directories and ScriptInfo objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def alreadyExists(self, scriptName: typing.Union[java.lang.String, str]) -> bool:
        """
        Looks through all of the current :obj:`ScriptInfo`s to see if one already exists with 
        the given name.
        
        :param java.lang.String or str scriptName: The name to check
        :return: true if the name is not taken by an existing :obj:`ScriptInfo`.
        :rtype: bool
        """

    def clearMetadata(self):
        """
        clear ScriptInfo metadata cached by GhidraScriptUtil
        """

    def containsMetadata(self, scriptFile: generic.jar.ResourceFile) -> bool:
        """
        Returns true if a ScriptInfo object exists for
        the specified script file.
        
        :param generic.jar.ResourceFile scriptFile: the script file
        :return: true if a ScriptInfo object exists
        :rtype: bool
        """

    def dispose(self):
        """
        clear stored metadata
        """

    def findScriptInfoByName(self, scriptName: typing.Union[java.lang.String, str]) -> ScriptInfo:
        """
        Uses the given name to find a matching script.  This method only works because of the
        limitation that all script names in Ghidra must be unique.  If the given name has multiple
        script matches, then a warning will be logged.
        
        :param java.lang.String or str scriptName: The name for which to find a script
        :return: The ScriptInfo that has the given name
        :rtype: ScriptInfo
        """

    @typing.overload
    def getExistingScriptInfo(self, script: generic.jar.ResourceFile) -> ScriptInfo:
        """
        Get :obj:`ScriptInfo` for ``script`` under the assumption that it's already managed.
        
        :param generic.jar.ResourceFile script: the script
        :return: info or null if the assumption was wrong. If null is returned, an error dialog is shown
        :rtype: ScriptInfo
        """

    @typing.overload
    def getExistingScriptInfo(self, scriptName: typing.Union[java.lang.String, str]) -> ScriptInfo:
        """
        Returns the existing script info for the given name.  The script environment limits 
        scripts such that names are unique.  If this method returns a non-null value, then the 
        name given name is taken.
        
        :param java.lang.String or str scriptName: the name of the script for which to get a ScriptInfo
        :return: a ScriptInfo matching the given name; null if no script by that name is known to
                the script manager
        :rtype: ScriptInfo
        """

    def getScriptInfo(self, scriptFile: generic.jar.ResourceFile) -> ScriptInfo:
        """
        Returns the script info object for the specified script file,
        construct a new one if necessary.
         
         
        Only call this method if you expect to be creating ScriptInfo objects.
        Prefer getExistingScriptInfo instead.
        
        :param generic.jar.ResourceFile scriptFile: the script file
        :return: the script info object for the specified script file
        :rtype: ScriptInfo
        """

    def getScriptInfoIterable(self) -> java.lang.Iterable[ScriptInfo]:
        """
        get all scripts
        
        :return: an iterable over all script info objects
        :rtype: java.lang.Iterable[ScriptInfo]
        """

    def refreshDuplicates(self):
        """
        Updates every known script's duplicate value.
        """

    def removeMetadata(self, scriptFile: generic.jar.ResourceFile):
        """
        Removes the ScriptInfo object for the specified file
        
        :param generic.jar.ResourceFile scriptFile: the script file
        """

    @property
    def scriptInfo(self) -> ScriptInfo:
        ...

    @property
    def existingScriptInfo(self) -> ScriptInfo:
        ...

    @property
    def scriptInfoIterable(self) -> java.lang.Iterable[ScriptInfo]:
        ...


class ResourceFileJavaFileManager(javax.tools.JavaFileManager):
    """
    A :obj:`JavaFileManager` that works with Ghidra's :obj:`ResourceFile`s.
     
     
    This class is used to dynamically compile Ghidra scripts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceDirs: java.util.List[generic.jar.ResourceFile], filesToAvoid: java.util.Set[generic.jar.ResourceFile]):
        """
        Create a :obj:`JavaFileManager` for use by the :obj:`JavaCompiler`.
        
        :param java.util.List[generic.jar.ResourceFile] sourceDirs: the directories containing source
        :param java.util.Set[generic.jar.ResourceFile] filesToAvoid: known "bad" files to hide from the compiler
        """


class GhidraScriptProvider(ghidra.util.classfinder.ExtensionPoint, java.lang.Comparable[GhidraScriptProvider]):
    """
    A provider that can compile, interpret, load, etc., Ghidra Scripts from a given language.
     
     
    
    **NOTE:** ALL GhidraScriptProvider CLASSES MUST END IN "ScriptProvider". If not, the
    ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createNewScript(self, newScript: generic.jar.ResourceFile, category: typing.Union[java.lang.String, str]):
        """
        Creates a new script using the specified file.
        
        :param generic.jar.ResourceFile newScript: the new script file
        :param java.lang.String or str category: the script category
        :raises IOException: if an error occurs writing the file
        """

    def deleteScript(self, scriptSource: generic.jar.ResourceFile) -> bool:
        """
        Deletes the script file and unloads the script from the script manager.
        
        :param generic.jar.ResourceFile scriptSource: the script source file
        :return: true if the script was completely deleted and cleaned up
        :rtype: bool
        """

    def getBlockCommentEnd(self) -> java.util.regex.Pattern:
        """
        Returns a Pattern that matches block comment closings.
         
         
        
        If block comments are not supported by this provider, then this returns null.
        
        :return: the Pattern for block comment closings, null if block comments are not supported
        :rtype: java.util.regex.Pattern
        """

    def getBlockCommentStart(self) -> java.util.regex.Pattern:
        """
        Returns a Pattern that matches block comment openings.
         
         
        
        If block comments are not supported by this provider, then this returns null.
        
        :return: the Pattern for block comment openings, null if block comments are not supported
        :rtype: java.util.regex.Pattern
        """

    def getCommentCharacter(self) -> str:
        """
        Returns the comment character.
         
         
        
        For example, "//" or "#".
        
        :return: the comment character
        :rtype: str
        """

    def getDescription(self) -> str:
        """
        Returns a description for this type of script.
        
        :return: a description for this type of script
        :rtype: str
        """

    def getExtension(self) -> str:
        """
        Returns the file extension for this type of script.
         
         
        
        For example, ".java" or ".py".
        
        :return: the file extension for this type of script
        :rtype: str
        """

    def getRuntimeEnvironmentName(self) -> str:
        """
        Returns an optional runtime environment name of a :obj:`GhidraScriptProvider` that scripts
        can specify they require to run under. Useful for when more than one
        :obj:`GhidraScriptProvider` uses the same file extension.
        
        :return: an optional runtime environment name of a :obj:`GhidraScriptProvider` that scripts
        can specify they require to run under (could be null if there is no requirement)
        :rtype: str
        
        .. seealso::
        
            | :obj:`ScriptInfo.AT_RUNTIME`
        """

    def getScriptInstance(self, sourceFile: generic.jar.ResourceFile, writer: java.io.PrintWriter) -> GhidraScript:
        """
        Returns a GhidraScript instance for the specified source file.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :param java.io.PrintWriter writer: the print writer to write warning/error messages. If the error prevents
                    success, throw an exception instead. The caller will print the error.
        :return: a GhidraScript instance for the specified source file
        :rtype: GhidraScript
        :raises GhidraScriptLoadException: when the script instance cannot be created
        """

    @property
    def extension(self) -> java.lang.String:
        ...

    @property
    def runtimeEnvironmentName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def blockCommentStart(self) -> java.util.regex.Pattern:
        ...

    @property
    def blockCommentEnd(self) -> java.util.regex.Pattern:
        ...

    @property
    def commentCharacter(self) -> java.lang.String:
        ...


class AbstractPythonScriptProvider(GhidraScriptProvider):
    """
    An abstract :obj:`GhidraScriptProvider` used to provide common functionality to different
    types of Python script implementations
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AskDialog(docking.DialogComponentProvider, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    STRING: typing.Final = 0
    INT: typing.Final = 1
    LONG: typing.Final = 2
    DOUBLE: typing.Final = 3
    BYTES: typing.Final = 4

    @typing.overload
    def __init__(self, dialogTitle: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int], defaultValue: java.lang.Object):
        ...

    @typing.overload
    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], type: typing.Union[jpype.JInt, int], choices: java.util.List[T], defaultValue: java.lang.Object):
        ...

    def getChoiceValue(self) -> T:
        ...

    def getTextFieldValue(self) -> str:
        ...

    def getValueAsString(self) -> str:
        ...

    def isCanceled(self) -> bool:
        ...

    @property
    def canceled(self) -> jpype.JBoolean:
        ...

    @property
    def valueAsString(self) -> java.lang.String:
        ...

    @property
    def textFieldValue(self) -> java.lang.String:
        ...

    @property
    def choiceValue(self) -> T:
        ...


class UnsupportedScriptProvider(GhidraScriptProvider):
    """
    A stub provider for unsupported scripts. These will typically be scripts with supported
    extensions but unsupported :obj:`ScriptInfo.AT_RUNTIME` tags.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, baseProvider: GhidraScriptProvider):
        """
        Creates a new :obj:`UnsupportedScriptProvider` that is derived from the given base provider.
        The base provider is any provider with a compatible extension, but without the required
        :obj:`ScriptInfo.AT_RUNTIME` tag.
        
        :param GhidraScriptProvider baseProvider: The base :obj:`GhidraScriptProvider`
        """


class SelectLanguageDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]):
        ...

    def getSelectedLanguage(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    def setSelectedLanguage(self, language: ghidra.program.model.lang.LanguageCompilerSpecPair):
        ...

    def show(self):
        ...

    def wasCancelled(self) -> bool:
        ...

    @property
    def selectedLanguage(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        ...

    @selectedLanguage.setter
    def selectedLanguage(self, value: ghidra.program.model.lang.LanguageCompilerSpecPair):
        ...


class JavaScriptProvider(GhidraScriptProvider):
    """
    The provider for Ghidra Scripts written in Java
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Create a new :obj:`JavaScriptProvider` associated with the current bundle host used by
        scripting.
        """

    def getBundleForSource(self, sourceFile: generic.jar.ResourceFile) -> ghidra.app.plugin.core.osgi.GhidraSourceBundle:
        """
        Get the :obj:`GhidraSourceBundle` containing the given source file, assuming it already
        exists.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :return: the bundle
        :rtype: ghidra.app.plugin.core.osgi.GhidraSourceBundle
        """

    def loadClass(self, sourceFile: generic.jar.ResourceFile, writer: java.io.PrintWriter) -> java.lang.Class[typing.Any]:
        """
        Activate and build the :obj:`GhidraSourceBundle` containing ``sourceFile`` then load the
        script's class from its class loader.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :param java.io.PrintWriter writer: the target for build messages
        :return: the loaded :obj:`Class` object
        :rtype: java.lang.Class[typing.Any]
        :raises java.lang.Exception: if build, activation, or class loading fail
        """

    @property
    def bundleForSource(self) -> ghidra.app.plugin.core.osgi.GhidraSourceBundle:
        ...


class ResourceFileJavaFileObject(javax.tools.JavaFileObject):
    """
    A :obj:`JavaFileObject` that works with Ghidra's :obj:`ResourceFileJavaFileManager`.
     
     
    This class is used to dynamically compile Ghidra scripts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceRoot: generic.jar.ResourceFile, file: generic.jar.ResourceFile, kind: javax.tools.JavaFileObject.Kind):
        """
        Represents a :obj:`ResourceFile` for a :obj:`JavaCompiler` via a :obj:`ResourceFileJavaFileManager`
        
        :param generic.jar.ResourceFile sourceRoot: the root source directory
        :param generic.jar.ResourceFile file: the file
        :param javax.tools.JavaFileObject.Kind kind: the kind
        """

    def getFile(self) -> generic.jar.ResourceFile:
        """
        
        
        :return: the :obj:`ResourceFile` this object represents
        :rtype: generic.jar.ResourceFile
        """

    @property
    def file(self) -> generic.jar.ResourceFile:
        ...


class GhidraScriptConstants(java.lang.Object):
    """
    A class to hold constants to be shared for clients of this package.
     
     
    This class should not depend on any classes in this package in order to prevent static
    loading of data.
    """

    class_: typing.ClassVar[java.lang.Class]
    USER_SCRIPTS_DIR_PROPERTY: typing.Final = "ghidra.user.scripts.dir"
    """
    The system property that overrides the location of the source directory used to store
    Ghidra scripts
    """

    DEFAULT_SCRIPT_NAME: typing.Final = "NewScript"
    """
    Default name of new scripts
    """



class GhidraScriptLoadException(ghidra.util.exception.UsrException):
    """
    An exception for when a script provider cannot create a script instance
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Construct an exception with a custom message and cause
         
         
        
        Note that the error message displayed to the user does not automatically include details from
        the cause. The client must provide details from the cause in the message as needed.
        
        :param java.lang.String or str message: the error message including details and possible remedies
        :param java.lang.Throwable cause: the exception causing this one
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Construct an exception with a message
        
        :param java.lang.String or str message: the error message including details and possible remedies
        """

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Construct an exception with a cause
         
         
        
        This will copy the cause's message into this exception's message.
        
        :param java.lang.Throwable cause: the exception causing this one
        """


class StringTransformer(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, s: typing.Union[java.lang.String, str]) -> T:
        ...


class MultipleOptionsDialog(docking.DialogComponentProvider, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def show(self):
        ...


class ScriptMessage(org.apache.logging.log4j.message.Message):
    """
    A simple :obj:`Message` implementation that allows us to use the filtering capability
    of log4j.  This class has a formatted and unformatted message.  log4j writes the formatted
    message out.  Our formatted message is the original message given to us.   We use the
    unformatted message, in conjunction with a regex filter to allow for filtering such that
    the script log file only has script messages.
    
     
    See log4j-appender-rolling-file-scripts.xml
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class GhidraState(java.lang.Object):
    """
    Represents the current state of a Ghidra tool
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, project: ghidra.framework.model.Project, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection):
        """
        Constructs a new Ghidra state.
        
        :param ghidra.framework.plugintool.PluginTool tool: the current tool
        :param ghidra.framework.model.Project project: the current project
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.program.util.ProgramLocation location: the current location
        :param ghidra.program.util.ProgramSelection selection: the current selection
        :param ghidra.program.util.ProgramSelection highlight: the current highlight
        """

    @typing.overload
    def __init__(self, state: GhidraState):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JByte, int]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JShort, int]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JFloat, float]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JDouble, float]):
        ...

    @typing.overload
    def addEnvironmentVar(self, name: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...

    def getCurrentAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the address of the current location
        :rtype: ghidra.program.model.address.Address
        """

    def getCurrentHighlight(self) -> ghidra.program.util.ProgramSelection:
        """
        
        
        :return: the currently highlighted selection
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        
        
        :return: the current location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getCurrentProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the current program.
        
        :return: the current program
        :rtype: ghidra.program.model.listing.Program
        """

    def getCurrentSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        
        
        :return: the current selection
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getEnvironmentNames(self) -> java.util.Set[java.lang.String]:
        ...

    def getEnvironmentVar(self, name: typing.Union[java.lang.String, str]) -> java.lang.Object:
        ...

    def getProject(self) -> ghidra.framework.model.Project:
        """
        Returns the current project.
        
        :return: the current project
        :rtype: ghidra.framework.model.Project
        """

    def getTool(self) -> ghidra.framework.plugintool.PluginTool:
        """
        Returns the current tool.
        
        :return: the current tool
        :rtype: ghidra.framework.plugintool.PluginTool
        """

    def removeEnvironmentVar(self, name: typing.Union[java.lang.String, str]):
        ...

    def setCurrentAddress(self, address: ghidra.program.model.address.Address):
        """
        If it differs, set the current location to the given address and fire a :obj:`ProgramLocationPluginEvent`.
        
        :param ghidra.program.model.address.Address address: the address
        """

    def setCurrentHighlight(self, highlight: ghidra.program.util.ProgramSelection):
        """
        Set the currently highlighted selection and fire a :obj:`ProgramHighlightPluginEvent`.
        
        :param ghidra.program.util.ProgramSelection highlight: the selection
        """

    def setCurrentLocation(self, location: ghidra.program.util.ProgramLocation):
        """
        If it differs, set the current location and fire a :obj:`ProgramLocationPluginEvent`.
        
        :param ghidra.program.util.ProgramLocation location: the location
        """

    def setCurrentProgram(self, program: ghidra.program.model.listing.Program):
        """
        Sets the current program.
        
        :param ghidra.program.model.listing.Program program: the new program object
        """

    def setCurrentSelection(self, selection: ghidra.program.util.ProgramSelection):
        """
        Set the current selection and fire a :obj:`ProgramSelectionPluginEvent`.
        
        :param ghidra.program.util.ProgramSelection selection: the selection
        """

    @property
    def currentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @currentProgram.setter
    def currentProgram(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def environmentNames(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def environmentVar(self) -> java.lang.Object:
        ...

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...

    @property
    def currentSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @currentSelection.setter
    def currentSelection(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def currentHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @currentHighlight.setter
    def currentHighlight(self, value: ghidra.program.util.ProgramSelection):
        ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool:
        ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @currentLocation.setter
    def currentLocation(self, value: ghidra.program.util.ProgramLocation):
        ...

    @property
    def currentAddress(self) -> ghidra.program.model.address.Address:
        ...

    @currentAddress.setter
    def currentAddress(self, value: ghidra.program.model.address.Address):
        ...


class ScriptInfo(java.lang.Object):
    """
    This class parses the meta-data about a script.
    """

    class_: typing.ClassVar[java.lang.Class]
    DELIMITTER: typing.Final = "."
    """
    The delimiter used in categories and menu paths.
    """

    METADATA: typing.Final[jpype.JArray[java.lang.String]]

    def getAuthor(self) -> str:
        """
        Returns the script author information.
        
        :return: the script author information.
        :rtype: str
        """

    def getCategory(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the script category path.
        
        :return: the script category path
        :rtype: jpype.JArray[java.lang.String]
        """

    def getDescription(self) -> str:
        """
        Returns the script description.
        
        :return: the script description
        :rtype: str
        """

    def getErrorMessage(self) -> str:
        """
        
        
        :return: a generic error message
        :rtype: str
        """

    def getImportPackage(self) -> str:
        """
        Returns the script imports
        
        :return: the script imports
        :rtype: str
        """

    def getKeyBinding(self) -> javax.swing.KeyStroke:
        """
        Returns the script key binding.
        
        :return: the script key binding
        :rtype: javax.swing.KeyStroke
        """

    def getKeyBindingErrorMessage(self) -> str:
        """
        
        
        :return: an error resulting from parsing keybinding metadata
        :rtype: str
        """

    def getMenuPath(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the script menu path.
        
        :return: the script menu path
        :rtype: jpype.JArray[java.lang.String]
        """

    def getMenuPathAsString(self) -> str:
        """
        Returns the script menu path as a string.
        For example,"Path1->Path2->Path3".
        
        :return: the script menu path as a string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of the script.
        The name of the script is the file name.
        
        :return: the name of the script
        :rtype: str
        """

    def getProvider(self) -> GhidraScriptProvider:
        """
        Returns the :obj:`GhidraScriptProvider` currently associated with the script
        
        :return: The :obj:`GhidraScriptProvider` currently associated with the script
        :rtype: GhidraScriptProvider
        """

    def getRuntimeEnvironmentName(self) -> str:
        """
        Returns the name of the required runtime environment
        
        :return: the name of the required runtime environment
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScriptProvider.getRuntimeEnvironmentName()`
        """

    def getSourceFile(self) -> generic.jar.ResourceFile:
        """
        Returns the script source file.
        
        :return: the script source file
        :rtype: generic.jar.ResourceFile
        """

    def getToolBarImage(self, scaled: typing.Union[jpype.JBoolean, bool]) -> javax.swing.Icon:
        """
        Returns the script tool bar icon.
        
        :param jpype.JBoolean or bool scaled: true if the icon should be scaled to 16x16.
        :return: the script tool bar icon
        :rtype: javax.swing.Icon
        """

    def getToolTipText(self) -> str:
        """
        Returns a string designed to be used as a tool tip for describing this script
        
        :return: a string designed to be used as a tool tip
        :rtype: str
        """

    def hasErrors(self) -> bool:
        """
        
        
        :return: true if the script either has compiler errors, or is a duplicate
        :rtype: bool
        """

    def hasUnsupportedProvider(self) -> bool:
        """
        Returns true if this script has an :obj:`UnsupportedScriptProvider`. This will typically
        happen when a script defines a wrong :obj:`ScriptInfo.AT_RUNTIME` tag.
        
        :return: True if this script has an :obj:`UnsupportedScriptProvider`; otherwise, false
        :rtype: bool
        """

    def isCategory(self, otherCategory: jpype.JArray[java.lang.String]) -> bool:
        """
        Returns true if 'cat' is a category.
        
        :param jpype.JArray[java.lang.String] otherCategory: the script category
        :return: true if 'cat' is a category
        :rtype: bool
        """

    def isCompileErrors(self) -> bool:
        """
        Returns true if the script has compile errors.
        
        :return: true if the script has compile errors
        :rtype: bool
        """

    def isDuplicate(self) -> bool:
        """
        Returns true if this script is a duplicate.
        When two or more scripts exists with the same name, this
        is considered a duplicate script.
        
        :return: true if this script is a duplicate
        :rtype: bool
        """

    def refresh(self):
        """
        Setting the toolbar image to null forces it to be reloaded on the next request.
        """

    def setCompileErrors(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the script has compile errors.
        
        :param jpype.JBoolean or bool b: true if the script has compile errors
        """

    def setDuplicate(self, isDuplicate: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the script is a duplicate.
        
        :param jpype.JBoolean or bool isDuplicate: true if the script is a duplicate
        """

    @property
    def runtimeEnvironmentName(self) -> java.lang.String:
        ...

    @property
    def keyBinding(self) -> javax.swing.KeyStroke:
        ...

    @property
    def menuPath(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def author(self) -> java.lang.String:
        ...

    @property
    def importPackage(self) -> java.lang.String:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def toolBarImage(self) -> javax.swing.Icon:
        ...

    @property
    def menuPathAsString(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def compileErrors(self) -> jpype.JBoolean:
        ...

    @compileErrors.setter
    def compileErrors(self, value: jpype.JBoolean):
        ...

    @property
    def duplicate(self) -> jpype.JBoolean:
        ...

    @duplicate.setter
    def duplicate(self, value: jpype.JBoolean):
        ...

    @property
    def sourceFile(self) -> generic.jar.ResourceFile:
        ...

    @property
    def provider(self) -> GhidraScriptProvider:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def keyBindingErrorMessage(self) -> java.lang.String:
        ...

    @property
    def category(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...


class ImproperUseException(java.lang.RuntimeException):
    """
    Exception class to be used when API calls are improperly used (i.e., GhidraScript.askProjectFolder() method is
    being used in Headless mode).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructs a new improper use exception with the specified detail message.
        
        :param java.lang.String or str msg: the detail message
        """

    @typing.overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Constructs a new exception with the specified cause
        
        :param java.lang.Throwable cause: the cause of the exception
        """


class GhidraScriptProperties(java.lang.Object):
    """
    Handles processing for .properties files associated with a GhidraScript (.properties file and
    script should share the same basename).
     
     
    This should only be called/used by the GhidraScript class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def containsKey(self, keyString: typing.Union[java.lang.String, str]) -> bool:
        """
        
        
        :param java.lang.String or str keyString: a property name
        :return: true if the key exists in the property file
        :rtype: bool
        """

    def containsValue(self, valueString: typing.Union[java.lang.String, str]) -> bool:
        """
        
        
        :param java.lang.String or str valueString: a value string
        :return: true if any property has the given value
        :rtype: bool
        """

    def getFilename(self) -> str:
        """
        
        
        :return: the properties file name
        :rtype: str
        """

    def getValue(self, keyString: typing.Union[java.lang.String, str]) -> str:
        """
        
        
        :param java.lang.String or str keyString: the property name
        :return: the value of the key in the properties file, or an empty string if no property exists
        :rtype: str
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if there are no properties
        :rtype: bool
        """

    def keySet(self) -> java.util.Set[java.lang.String]:
        """
        
        
        :return: the property names for all properties
        :rtype: java.util.Set[java.lang.String]
        """

    @property
    def filename(self) -> java.lang.String:
        ...

    @property
    def value(self) -> java.lang.String:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class GhidraScriptUtil(java.lang.Object):
    """
    A utility class for managing script directories and ScriptInfo objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    USER_SCRIPTS_DIR: typing.ClassVar[java.lang.String]
    """
    User's home scripts directory
    """


    def __init__(self):
        ...

    @staticmethod
    def acquireBundleHostReference() -> ghidra.app.plugin.core.osgi.BundleHost:
        """
        When running the GUI, :obj:`GhidraScriptUtil` manages a single :obj:`BundleHost` instance.
        
        :return: the BundleHost singleton
        :rtype: ghidra.app.plugin.core.osgi.BundleHost
        """

    @staticmethod
    def createNewScript(provider: GhidraScriptProvider, parentDirectory: generic.jar.ResourceFile, scriptDirectories: java.util.List[generic.jar.ResourceFile]) -> generic.jar.ResourceFile:
        """
        Creates a new script with a unique name using the specified provider in the 
        specified directory.
        
        :param GhidraScriptProvider provider: the Ghidra script provider
        :param generic.jar.ResourceFile parentDirectory: the directory where the new script will be created.
        :param java.util.List[generic.jar.ResourceFile] scriptDirectories: The list of directories containing scripts (used to find a 
                unique name).
        :return: the newly created script file
        :rtype: generic.jar.ResourceFile
        :raises IOException: if an i/o error occurs
        """

    @staticmethod
    def dispose():
        """
        dispose of the bundle host and providers list
        """

    @staticmethod
    def findScriptByName(scriptName: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Search the currently managed scripts for one with the given name.
        
        :param java.lang.String or str scriptName: the name
        :return: the first file found or null if none are found
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def findSourceDirectoryContaining(sourceFile: generic.jar.ResourceFile) -> generic.jar.ResourceFile:
        """
        Search the currently managed source directories for the given script file.
        
        :param generic.jar.ResourceFile sourceFile: the source file
        :return: the source directory if found, or null if not
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getBaseName(script: generic.jar.ResourceFile) -> str:
        """
        Returns the base name give a script file.
        For example, given "C:\Temp\SomeClass.java",
        it will return "SomeClass".
        
        :param generic.jar.ResourceFile script: the script
        :return: the base name
        :rtype: str
        """

    @staticmethod
    def getBundleHost() -> ghidra.app.plugin.core.osgi.BundleHost:
        """
        
        
        :return: the bundle host used for scripting
        :rtype: ghidra.app.plugin.core.osgi.BundleHost
        """

    @staticmethod
    def getEnabledScriptSourceDirectories() -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of the current enabled script directories.
        
        :return: a list of the current enabled script directories
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    @deprecated("accessing class file directly precludes OSGi wiring according to requirements and capabilities")
    def getExplodedCompiledSourceBundlePaths() -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns the list of exploded bundle directories
        
        :return: the list
        :rtype: java.util.List[generic.jar.ResourceFile]
        
        .. deprecated::
        
        accessing class file directly precludes OSGi wiring according to requirements and capabilities
        """

    @staticmethod
    def getProvider(scriptFile: generic.jar.ResourceFile) -> GhidraScriptProvider:
        """
        Returns the corresponding Ghidra script provider for the specified script file.
        
        :param generic.jar.ResourceFile scriptFile: the script file
        :return: the Ghidra script provider or :obj:`UnsupportedScriptProvider` if the script file
        does not exist or no provider matches
        :rtype: GhidraScriptProvider
        """

    @staticmethod
    def getProviders() -> java.util.List[GhidraScriptProvider]:
        """
        Returns a list of all supported Ghidra script providers
        
        :return: a list of all supported Ghidra script providers
        :rtype: java.util.List[GhidraScriptProvider]
        """

    @staticmethod
    def getScriptSourceDirectories() -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of the current script directories.
        
        :return: a list of the current script directories
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def getSystemScriptDirectories() -> java.util.List[generic.jar.ResourceFile]:
        """
        Returns a list of the default script directories.
        
        :return: a list of the default script directories
        :rtype: java.util.List[generic.jar.ResourceFile]
        """

    @staticmethod
    def getUserScriptDirectory() -> generic.jar.ResourceFile:
        ...

    @staticmethod
    def hasScriptProvider(scriptFile: generic.jar.ResourceFile) -> bool:
        """
        Returns true if a provider exists that can process the specified file.
        
        :param generic.jar.ResourceFile scriptFile: the script file
        :return: true if a provider exists that can process the specified file
        :rtype: bool
        """

    @staticmethod
    def initialize(aBundleHost: ghidra.app.plugin.core.osgi.BundleHost, extraSystemPaths: java.util.List[java.lang.String]):
        """
        Initialize state of GhidraScriptUtil with user, system, and optional extra system paths.
        
        :param ghidra.app.plugin.core.osgi.BundleHost aBundleHost: the host to use
        :param java.util.List[java.lang.String] extraSystemPaths: additional system paths for this run, can be null
        """

    @staticmethod
    def isSystemScript(file: generic.jar.ResourceFile) -> bool:
        """
        Determine if the specified file is contained within the Ghidra installation.
        
        :param generic.jar.ResourceFile file: script file or directory
        :return: true if file contained within Ghidra installation area
        :rtype: bool
        """

    @staticmethod
    def newScriptInfo(file: generic.jar.ResourceFile) -> ScriptInfo:
        ...

    @staticmethod
    def releaseBundleHostReference():
        """
        release the reference the BundleHost reference.  When no references remain, 
        :meth:`dispose() <.dispose>` is called.
        """


class GhidraScript(ghidra.program.flatapi.FlatProgramAPI):
    """
    
    **************************
    Ghidra Script Development.
    **************************
    
    In order to write a script:
     
    1. Ghidra script must be written in Java.
    2. Your script class must extend ghidra.app.script.GhidraScript.
    3. You must implement the run() method. This is where you insert your
    script-specific code.
    4. You should create a description comment at the top of the file. Each description
    line should start with"//".
    
     
    
    
    When you create a new script using the script manager,
    you will automatically receive a source code stub (as shown below).
     
    // TODO write a description for this script
    
        public class NewScript extends GhidraScript {
    
            public void run() throws Exception {
                // TODO Add User Code Here
            }
        }
     
     
    ===================
    Ghidra Script State
    ===================
    
         
        All scripts, when run, will be handed the current state in the form of class instance
        variable. These variables are:
         
        1. currentProgram: the active program
        2. currentAddress: the address of the current cursor location in the tool
        3. currentLocation: the program location of the current cursor location
        in the tool, or null if no program location exists
        4. currentSelection: the current selection in the tool, or null
        if no selection exists
        5. currentHighlight: the current highlight in the tool, or null
        if no highlight exists
    
    
     
    ===================
    Hello World Example
    ===================
    
    This example, when run, will simply print "Hello World" into the Ghidra console.
     
        public class HelloWorldScript extends GhidraScript {
            public void run() throws Exception {
                println("Hello World!");
            }
        }
     
    All scripts, when run, will be handed the current state and are automatically
    run in a separate thread.
     
    
    
    
    .. seealso::
    
        | :obj:`ghidra.app.script.GhidraState`
    
        | :obj:`ghidra.program.model.listing.Program`
    """

    @typing.type_check_only
    class DIRECTORY(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class AnalysisMode(java.lang.Enum[GhidraScript.AnalysisMode]):

        class_: typing.ClassVar[java.lang.Class]
        ENABLED: typing.Final[GhidraScript.AnalysisMode]
        """
        ENABLED - Script will run normally with Auto-Analysis responding to changes
        """

        DISABLED: typing.Final[GhidraScript.AnalysisMode]
        """
        DISABLED - Script will coordinate with AutoAnalysisManager to run with
        analysis disabled (change events will be ignored).  Script will wait for any
        pending analysis to complete.  Within headed environments an additional modal task dialog
        will be displayed while the script is active to prevent the user from initiating
        additional program changes.
        """

        SUSPENDED: typing.Final[GhidraScript.AnalysisMode]
        """
        SUSPENDED - Script will coordinate with AutoAnalysisManager to run with
        analysis suspended (change events will be analyzed after script execution completes).
        Script will wait for any pending analysis to complete.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GhidraScript.AnalysisMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[GhidraScript.AnalysisMode]:
            ...


    @typing.type_check_only
    class CancellableFunction(java.lang.Object, typing.Generic[T, R]):

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, t: T) -> R:
            ...


    @typing.type_check_only
    class ScriptStatusListener(ghidra.util.StatusListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def askAddress(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Returns an Address, using the String parameters for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid Address value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        for an address value. If the same popup has been run before in the same session,
        the address input field will be pre-populated with the last-used address. If not,
        the    address input field will be pre-populated with the .properties value (if it
        exists).
        2. In the headless environment, this method returns an Address representing the
        .properties value (if it exists), or throws an Exception if there is an invalid or
        missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                    second part of the variable name (in headless mode or when using .properties file)
        :return: the user-specified Address value
        :rtype: ghidra.program.model.address.Address
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid Address
                    specified in the .properties file
        """

    @typing.overload
    def askAddress(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Returns an Address, using the String parameters for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid Address value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        for an address value. If the same popup has been run before in the same session,
        the address input field will be pre-populated with the last-used address. If not,
        the    address input field will be pre-populated with the .properties value (if it
        exists).
        2. In the headless environment, this method returns an Address representing the
        .properties value (if it exists), or throws an Exception if there is an invalid or
        missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                    second part of the variable name (in headless mode or when using .properties file)
        :param java.lang.String or str defaultValue: the optional default address as a String - if null is passed or an invalid
                    address is given no default will be shown in dialog
        :return: the user-specified Address value
        :rtype: ghidra.program.model.address.Address
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid Address
                    specified in the .properties file
        """

    def askBytes(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Returns a byte array, using the String parameters for guidance. The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents valid bytes, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the
        user for a byte pattern. If the same popup has been run before in the same session,
        the byte pattern input field will be pre-populated with    the last-used bytes string.
        If not, the byte pattern input field will be pre-populated with the .properties
        value (if it exists).
        2. In the headless environment, this method returns a byte array representing the
        .properties byte pattern value (if it exists), or throws an Exception if there is
        an invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable
                    name (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the
                    second part of the variable name (in headless mode or when using .properties file)
        :return: the user-specified byte array
        :rtype: jpype.JArray[jpype.JByte]
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid bytes
                    string specified in the .properties file
        """

    def askChoice(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T], defaultValue: T) -> T:
        """
        Returns an object that represents one of the choices in the given list. The actual behavior
        of the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid choice, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        to choose from the given list of objects. The pre-chosen choice will be the last
        user-chosen value (if the dialog has been run before). If that does not exist, the
        pre-chosen value is the .properties value. If that does not exist or is invalid,
        then the 'defaultValue' parameter is used (as long as it is not null).
        2. In the headless environment, this method returns an object representing the
        .properties value (if it exists and is a valid choice), or throws an Exception if
        there is an invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :param java.util.List[T] choices: set of choices (toString() value of each object will be displayed in the dialog)
        :param T defaultValue: the default value to display in the input field; may be
                            null, but must be a valid choice if non-null.
        :return: the user-selected value
        :rtype: T
        :raises CancelledException: if the user hit the 'cancel' button
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    choice
                    specified in the .properties file
        """

    @typing.overload
    def askChoices(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T]) -> java.util.List[T]:
        """
        Returns an array of Objects representing one or more choices from the given list. The actual
        behavior of the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents valid choices, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a pop-up dialog that presents the user
        with checkbox choices (to allow a more flexible option where the user can pick
        some, all, or none).
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the choices to return. The method will look in the .properties file
        by searching for a property name equal to a space-separated concatenation of the
        String parameters (title + " " + message). If that property name exists and
        represents a list (one or more) of valid choice(s) in the form
        "choice1;choice2;choice3;..." (<-- note the quotes surrounding the choices), then
        an Object array of those choices is returned. Otherwise, an Exception is thrown if
        there is an invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display with the choices (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :param java.util.List[T] choices: set of choices (toString() value of each object will be displayed in the dialog)
        :return: the user-selected value(s); an empty list if no selection was made
        :rtype: java.util.List[T]
        :raises CancelledException: if the user hits the 'cancel' button
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    set of
                    choices specified in the .properties file
        """

    @typing.overload
    def askChoices(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], choices: java.util.List[T], choiceLabels: java.util.List[java.lang.String]) -> java.util.List[T]:
        """
        Returns an array of Objects representing one or more choices from the given list. The user
        specifies the choices as Objects, also passing along a corresponding array of String
        representations for each choice (used as the checkbox label). The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents valid choices, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a pop-up dialog that presents the user
        with checkbox choices (to allow a more flexible option where the user can pick
        some, all, or none).
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the choices to return. The method will look in the .properties file
        by searching for a property name equal to a space-separated concatenation of the
        String parameters (title + " " + message). If that property name exists and
        represents a list (one or more) of valid choice(s) in the form
        "choice1;choice2;choice3;..." (<-- note the quotes surrounding the choices), then
        an Object array of those choices is returned. Otherwise, an Exception is thrown if
        there is an invalid or missing .properties value. NOTE: the choice names for
        this method must match those in the stringRepresentationOfChoices array.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display with the choices (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :param java.util.List[T] choices: set of choices
        :param java.util.List[java.lang.String] choiceLabels: the String representation for each choice, used for
                    checkbox labels
        :return: the user-selected value(s); null if no selection was made
        :rtype: java.util.List[T]
        :raises CancelledException: if the user hits the 'cancel' button
        :raises IllegalArgumentException: if choices is empty; if in headless mode,
                there was a missing or invalid set of choices    specified in the .properties file
        """

    def askDirectory(self, title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns a directory File object, using the String parameters for guidance. The actual
        behavior of the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + approveButtonText).
        If that property name exists and its value represents a valid **absolute path** of a valid
        directory File, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a file chooser dialog that allows the
        user to select a directory. If the file chooser dialog has been run before in the
        same session, the directory selection will be pre-populated with the last-selected
        directory. If not, the directory selection will be pre-populated with the
        .properties    value (if it exists).
        2. In the headless environment, this method returns a directory File representing
        the .properties value (if it exists), or throws an Exception if there is an invalid
        or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would be
                    "Open" or "Save") or the second part of the variable name (in headless mode or
                    when using .properties file)
        :return: the selected directory or null if no tool was available
        :rtype: java.io.File
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid
                        directory name specified in the .properties file
        """

    def askDomainFile(self, title: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Returns a DomainFile, using the title parameter for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is the
        title String parameter.  If that property name exists and its value represents a valid
        domain file, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog listing all domain files
        in the current project, allowing the user to select one.
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the name of the DomainFile to return. The method will look in the
        .properties file by searching for a property name equal to the 'title' parameter. If
        that property name exists and its value represents a valid DomainFile in the project,
        then that value is returned. Otherwise, an Exception is thrown if there is an invalid
        or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in headless
                mode or when using .properties file)
        :return: the user-selected domain file
        :rtype: ghidra.framework.model.DomainFile
        :raises CancelledException: if the operation is cancelled
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    domain
                    file specified in the .properties file
        """

    def askDouble(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> float:
        """
        Returns a double, using the String parameters for guidance. The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid double value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
            for a double value. If the same popup has been run before in the same session, the
            double input field will be pre-populated with the last-used double. If not, the
            double input field will be pre-populated with the .properties value (if it exists).
        
        2. In the headless environment, this method returns a double value representing the
        .properties value (if it exists), or throws an Exception if there is an    invalid or
        missing .properties value.
        
         
        
        Note that in both headless and GUI modes, you may specify "PI" or "E" and get the
        corresponding floating point value to 15 decimal places.
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :return: the user-specified double value
        :rtype: float
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or    invalid double
                    specified in the .properties file
        """

    def askFile(self, title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns a File object, using the String parameters for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + approveButtonText).
        If that property name exists and its value represents a valid **absolute path** of a valid
        File, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a file chooser dialog that allows the
            user to select a file. If the file chooser dialog has been run before in the same
            session, the File selection will be pre-populated with the last-selected file. If
            not, the File selection will be pre-populated with the .properties value (if it
            exists).
        
        2. In the headless environment, this method returns a File object representing    the
            .properties    String value, or throws an Exception if there is an invalid or missing
            .properties value.
        
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using using .properties file)
        :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would
                    be "Open" or "Save") or the second part of the variable name (in headless mode
                    or when using .properties file)
        :return: the selected file or null if no tool was available
        :rtype: java.io.File
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid file
                    name specified in the .properties file
        """

    def askInt(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
        """
        Returns an int, using the String parameters for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid int value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
            for an int value. If the same popup has been run before in the same session, the int
            input field will be pre-populated with the last-used int. If not, the int input
            field will be pre-populated with the .properties value (if it exists).
        
        2. In the headless environment, this method returns an int value representing the
            .properties value (if it exists), or throws an Exception if there is an invalid
            or missing .properties value.
        
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :return: the user-specified int value
        :rtype: int
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid int
                    specified in the .properties file
        """

    def askLanguage(self, title: typing.Union[java.lang.String, str], approveButtonText: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Returns a LanguageCompilerSpecPair, using the String parameters for guidance. The actual
        behavior of the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid LanguageCompilerSpecPair value,
        then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a language table dialog and returns
        the selected language. If the same popup has been run before in the same session,
        the last-used language will be pre-selected. If not, the language specified in the
        .properties file will be pre-selected (if it exists).
        2. In the headless environment, this method returns a LanguageCompilerSpecPair
        representing the .properties value (if it exists), or throws an Exception if there
        is an invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str approveButtonText: the approve button text (in GUI mode - typically, this would be
                    "Open" or "Save") or the second part of the variable name (in headless mode or
                    when using .properties file)
        :return: the selected LanguageCompilerSpecPair
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        :raises CancelledException: if the user hit the 'cancel' button
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    language
                    specified in the .properties file
        """

    def askLong(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
        """
        Returns a long, using the String parameters for guidance.  The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid long value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
            for a long value. If the same popup has been run before in the same session, the
            long input field will be pre-populated with the last-used long. If not, the long
            input field will be pre-populated with the .properties value (if it exists).
        
        2. In the headless environment, this method returns a long value representing the
        .properties value (if it exists), or throws an Exception if there is an invalid or
        missing .properties    value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the    variable name (in headless mode or when using .properties file)
        :return: the user-specified long value
        :rtype: int
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    long
                    specified in the .properties file
        """

    def askPassword(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str]) -> ghidra.framework.generic.auth.Password:
        """
        Returns a :obj:`Password`, using the String input parameters for guidance. This method can
        only be used in headed mode.
         
        
        In the GUI environment, this method displays a password popup dialog that prompts the user
        for a password. There is no pre-population of the input. If the user cancels the dialog, it
        is immediately disposed, and any input to that dialog is cleared from memory. If the user
        completes the dialog, then the password is returned in a wrapped buffer. The buffer can be
        cleared by calling :meth:`Password.close() <Password.close>`; however, it is meant to be used in a
        ``try-with-resources`` block. The pattern does not guarantee protection of the password,
        but it will help you avoid some typical pitfalls:
        
         
        String user = askString("Login", "Username:");
        Project project;
        try (Password password = askPassword("Login", "Password:")) {
            project = doLoginAndOpenProject(user, password.getPasswordChars());
        }
         
        
        The buffer will be zero-filled upon leaving the ``try-with-resources`` block. If, in the
        sample, the ``doLoginAndOpenProject`` method or any part of its implementation needs to
        retain the password, it must make a copy. It is then the implementation's responsibility to
        protect its copy.
        
        :param java.lang.String or str title: the title of the dialog
        :param java.lang.String or str prompt: the prompt to the left of the input field, or null to display "Password:"
        :return: the password
        :rtype: ghidra.framework.generic.auth.Password
        :raises CancelledException: if the user cancels
        :raises ImproperUseException: if in headless mode
        """

    @typing.overload
    def askProgram(self, title: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Program:
        """
        Returns a Program, using the title parameter for guidance. The actual behavior of the
        method depends on your environment, which can be GUI or headless. If in headless mode,
        the program will not be upgraded (see :meth:`askProgram(String, boolean) <.askProgram>` if you want
        more control). In GUI mode, the user will be prompted to upgrade.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is the
        title String parameter.  If that property name exists and its value represents a valid
        program, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        to select a program.
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the name of the program to return. The method will look in the
        .properties file by searching for a property name equal to the 'title' parameter. If
        that property name exists and its value represents a valid Program in the project,
        then that value    is returned. Otherwise, an Exception is thrown if there is an
        invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in
                    headless mode)
        :return: the user-selected Program with this script as the consumer if a program was
        selected. Null is returned if a program is not selected. NOTE: It is very important that
        the program instance returned by this method ALWAYS be properly released when no longer
        needed.  The script which invoked this method must be
        specified as the consumer upon release (i.e., ``program.release(this)`` - failure to
        properly release the program may result in improper project disposal.  If the program was
        opened by the tool, the tool will be a second consumer responsible for its own release.
        :rtype: ghidra.program.model.listing.Program
        :raises VersionException: if the Program is out-of-date from the version of Ghidra and an
        upgrade was not been performed. In non-headless mode, the user will have already been
        notified via a popup dialog.
        :raises IOException: if there is an error accessing the Program's DomainObject
        :raises CancelledException: if the program open operation is cancelled
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    program
                    specified in the .properties file
        """

    @typing.overload
    def askProgram(self, title: typing.Union[java.lang.String, str], upgradeIfNeeded: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.listing.Program:
        """
        Returns a Program, using the title parameter for guidance with the option to upgrade
        if needed. The actual behavior of the method depends on your environment, which can be
        GUI or headless. You can control whether or not the program is allowed to upgrade via
        the ``upgradeIfNeeded`` parameter.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is the
        title String parameter.  If that property name exists and its value represents a valid
        program, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        to select a program.
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the name of the program to return. The method will look in the
        .properties file by searching for a property name equal to the 'title' parameter. If
        that property name exists and its value represents a valid Program in the project,
        then that value    is returned. Otherwise, an Exception is thrown if there is an
        invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the pop-up dialog (in GUI mode) or the variable name (in
                    headless mode)
        :param jpype.JBoolean or bool upgradeIfNeeded: if true, program will be upgraded if needed and possible. If false,
        the program will only be upgraded after first prompting the user. In headless mode, it will
        attempt to upgrade only if the parameter is true.
        :return: the user-selected Program with this script as the consumer if a program was
        selected. Null is returned if a program is not selected. NOTE: It is very important that
        the program instance returned by this method ALWAYS be properly released when no longer
        needed.  The script which invoked this method must be
        specified as the consumer upon release (i.e., ``program.release(this)`` - failure to
        properly release the program may result in improper project disposal.  If the program was
        opened by the tool, the tool will be a second consumer responsible for its own release.
        :rtype: ghidra.program.model.listing.Program
        :raises VersionException: if the Program is out-of-date from the version of GHIDRA and an
        upgrade was not been performed. In non-headless mode, the user will have already been
        notified via a popup dialog.
        :raises IOException: if there is an error accessing the Program's DomainObject
        :raises CancelledException: if the program open operation is cancelled
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    program
                    specified in the .properties file
        """

    def askProjectFolder(self, title: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
        """
        Returns a DomainFolder object, using the supplied title string for guidance.  The actual
        behavior of the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is the
        title String parameter.  If that property name exists and its value represents a valid
        project folder, then the .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a file chooser dialog that allows the
        user to select a project folder. The selected folder will be returned.
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the name of the project folder to return. The method will look in
        the .properties    file by searching for a property name equal to the 'title' parameter.
        If that property name exists and its value represents a valid DomainFolder in the
        project, then that value is returned. Otherwise, an Exception is thrown if there is
        an invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (GUI) or the variable name    (headless or when
                    using .properties file)
        :return: the selected project folder or null if there was an invalid .properties value
        :rtype: ghidra.framework.model.DomainFolder
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid    project
                    folder specified in the .properties file
        """

    @typing.overload
    def askString(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a String, using the String input parameters for guidance. The actual behavior of
        the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid String value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
            for a String value. If the same popup has been run before in the same session, the
            String input field will be pre-populated with the last-used String. If not, the
            String input field will be pre-populated with the .properties value (if it exists).
        
        2. In the headless environment, this method returns a String value    representing the
        .properties value (if it exists), or throws an Exception if there is an invalid or
        missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable    name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :return: the user-specified String value
        :rtype: str
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IndexOutOfBoundsException: if in headless mode and arguments are being used, but not
                enough arguments were passed in to accommodate the request.
        :raises IllegalArgumentException: if in headless mode, there was an invalid String
                    specified in the arguments, or an invalid or missing String specified in the
                .properties file
        """

    @typing.overload
    def askString(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], defaultValue: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a String, using the String input parameters for guidance. The actual behavior of the
        method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + message).
        If that property name exists and its value represents a valid String value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        for a String value. The pre-populated value for the String input field will be the
        last-used String (if the dialog has been run before). If that does not exist, the
        pre-populated value is the .properties value. If that does    not exist or is invalid,
        then the 'defaultValue' parameter is used (as long as it is not    null or the empty
        String).
        2. In the headless environment, this method returns a String value representing the
        .properties value (if it exists). Otherwise, if the 'defaultValue' parameter is
        not null or an empty String, it is returned. In all other cases, an exception
        is thrown.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode or when using .properties file)
        :param java.lang.String or str message: the message to display next to the input field (in GUI mode) or the second
                    part of the variable name (in headless mode or when using .properties file)
        :param java.lang.String or str defaultValue: the optional default value
        :return: the user-specified String value
        :rtype: str
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid String
                    specified in the .properties file
        """

    def askValues(self, title: typing.Union[java.lang.String, str], optionalMessage: typing.Union[java.lang.String, str], values: ghidra.features.base.values.GhidraValuesMap) -> ghidra.features.base.values.GhidraValuesMap:
        """
        Prompts for multiple values at the same time. To use this method, you must first
        create a :obj:`GhidraValuesMap` and define the values that will be supplied by this method.
        In the GUI environment, this will result in a single dialog with an entry for each value
        defined in the values map. This method returns a GhidraValuesMap with the values supplied by
        the user in GUI mode or command line arguments in headless mode. If the user cancels the
        dialog, a cancelled exception will be thrown, and unless it is explicity caught by the
        script, will terminate the script. Also, if the values map has a :obj:`ValuesMapValidator`,
        the values will be validated when the user presses the "OK" button and will only exit the
        dialog if the validate check passes. Otherwise, the validator should have reported an error
        message in the dialog and the dialog will remain visible.
        
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next arguments in the array and advance the array index until all values in the values map
        have been satisfied and so the next call to an ask method will get the next argument after
        those consumed by this call.
        
        :param java.lang.String or str title: the title of the dialog if in GUI mode
        :param java.lang.String or str optionalMessage: an optional message that is displayed in the dialog, just above the
        list of name/value pairs
        :param ghidra.features.base.values.GhidraValuesMap values: the GhidraValuesMap containing the values to include in the dialog.
        :return: the GhidraValuesMap with values set from user input in the dialog (This is the same
        instance that was passed in, so you don't need to use this)
        :rtype: ghidra.features.base.values.GhidraValuesMap
        :raises CancelledException: if the user hit the 'cancel' button in GUI mode
        """

    def askYesNo(self, title: typing.Union[java.lang.String, str], question: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns a boolean value, using the String parameters for guidance. The actual behavior of
        the method depends on your environment, which can be GUI or headless.
         
        
        Regardless of environment -- if script arguments have been set, this method will use the
        next argument in the array and advance the array index so the next call to an ask method
        will get the next argument.  If there are no script arguments and a .properties file
        sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
        Script1.java), then this method will then look there for the String value to return.
        The method will look in the .properties file by searching for a property name that is a
        space-separated concatenation of the input String parameters (title + " " + question).
        If that property name exists and its value represents a valid boolean value, then the
        .properties value will be used in the following way:
         
        1. In the GUI environment, this method displays a popup dialog that prompts the user
        with a yes/no dialog with the specified title and question. Returns true if the user
        selects "yes" to the question or false if the user selects "no".
        2. In the headless environment, if a .properties file sharing the same base name as the
        Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
        looks there for the boolean value to return. The method will look in the .properties
        file by searching for a property name that is a space-separated concatenation of the
        String parameters (title + " " + question). If that property name exists and its
        value represents a valid boolean value (either 'true' or 'false', case insensitive),
        then that value    is returned. Otherwise, an Exception is thrown if there is an
        invalid or missing .properties value.
        
        
        :param java.lang.String or str title: the title of the dialog (in GUI mode) or the first part of the variable name
                    (in headless mode)
        :param java.lang.String or str question: the question to display to the user (in GUI mode) or the second part of the
                    variable name (in headless mode)
        :return: true if the user selects "yes" to the question (in GUI mode) or "true" (in headless
                    mode)
        :rtype: bool
        :raises IllegalArgumentException: if in headless mode, there was a missing or invalid boolean
                    specified in the .properties file
        """

    def cleanup(self, success: typing.Union[jpype.JBoolean, bool]):
        """
        A callback for scripts to perform any needed cleanup after the script is finished
        
        :param jpype.JBoolean or bool success: true if the script was successful
        """

    @typing.overload
    def clearBackgroundColor(self, address: ghidra.program.model.address.Address):
        """
        Clears the background of the Listing at the given address to the given color.  See the
        Listing help page in Ghidra help for more information.
         
        
        This method is unavailable in headless mode.
         
        
        Note: you can use the :obj:`ColorizingService` directly to access more color changing
        functionality.  See the source code of this method to learn how to access services from
        a script.
        
        :param ghidra.program.model.address.Address address: The address at which to clear the color
        :raises ImproperUseException: if this method is run in headless mode
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(AddressSetView, Color)`
        
            | :obj:`.clearBackgroundColor(AddressSetView)`
        
            | :obj:`ColorizingService`
        """

    @typing.overload
    def clearBackgroundColor(self, addresses: ghidra.program.model.address.AddressSetView):
        """
        Clears the background of the Listing at the given addresses to the given color.  See the
        Listing help page in Ghidra help for more information.
         
        
        This method is unavailable in headless mode.
         
        
        Note: you can use the :obj:`ColorizingService` directly to access more color changing
        functionality.  See the source code of this method to learn how to access services from
        a script.
        
        :param ghidra.program.model.address.AddressSetView addresses: The address at which to clear the color
        :raises ImproperUseException: if this method is run in headless mode
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(AddressSetView, Color)`
        
            | :obj:`.clearBackgroundColor(AddressSetView)`
        
            | :obj:`ColorizingService`
        """

    def closeProgram(self, program: ghidra.program.model.listing.Program):
        """
        Closes the specified program in the current tool.
        
        :param ghidra.program.model.listing.Program program: the program to close
        """

    def createHighlight(self, set: ghidra.program.model.address.AddressSetView):
        """
        Sets this script's highlight state (both the local variable
        ``currentHighlight`` and the
        ``GhidraState``'s currentHighlight) to the given address set.  Also sets the tool's highlight
        if the tool exists. (Same as calling setCurrentHightlight(set);
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to include in the highlight.  May be null.
        """

    @typing.overload
    def createProgram(self, programName: typing.Union[java.lang.String, str], languageID: ghidra.program.model.lang.LanguageID, compilerSpecID: ghidra.program.model.lang.CompilerSpecID) -> ghidra.program.model.listing.Program:
        """
        Creates a new program with specified name and language name. The actual language object
        is located using the language name provided.
         
        
        Please note: the program is not automatically saved into the program.
        
        :param java.lang.String or str programName: the program name
        :param ghidra.program.model.lang.LanguageID languageID: the language ID
        :param ghidra.program.model.lang.CompilerSpecID compilerSpecID: the compiler Spec ID
        :return: the new unsaved program
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: the language name is invalid or an I/O error occurs
        """

    @typing.overload
    def createProgram(self, programName: typing.Union[java.lang.String, str], languageID: ghidra.program.model.lang.LanguageID) -> ghidra.program.model.listing.Program:
        """
        Creates a new program with specified name and language name. The actual language object
        is located using the language name provided.
         
        
        Please note: the program is not automatically saved into the program.
        
        :param java.lang.String or str programName: the program name
        :param ghidra.program.model.lang.LanguageID languageID: the language name
        :return: the new unsaved program
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: the language name is invalid or an I/O error occurs
        """

    @typing.overload
    def createProgram(self, programName: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
        """
        Creates a new program with specified name and language. It uses the default compilerSpec
        for the given language.
         
        
        Please note: the program is not automatically saved into the project.
        
        :param java.lang.String or str programName: the program name
        :param ghidra.program.model.lang.Language language: the language
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compilerSpec to use.
        :return: the new unsaved program
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: the language name is invalid or an I/O error occurs
        """

    def createSelection(self, set: ghidra.program.model.address.AddressSetView):
        """
        Calling this method is equivalent to calling :meth:`setCurrentSelection(AddressSetView) <.setCurrentSelection>`.
        
        :param ghidra.program.model.address.AddressSetView set: the addresses
        """

    @typing.overload
    def createTableChooserDialog(self, title: typing.Union[java.lang.String, str], executor: ghidra.app.tablechooser.TableChooserExecutor) -> ghidra.app.tablechooser.TableChooserDialog:
        """
        Creates a TableChooserDialog that allows the script to display a list of addresses (and
        associated column data) in a table and also provides the capability to execute an
        action from a selection in the table.
         
        
        This method is unavailable in headless mode.
        
        :param java.lang.String or str title: the title of the dialog
        :param ghidra.app.tablechooser.TableChooserExecutor executor: the TableChooserExecuter to be used to apply operations on table entries.
        :return: a new TableChooserDialog.
        :rtype: ghidra.app.tablechooser.TableChooserDialog
        :raises ImproperUseException: if this method is run in headless mode
        """

    @typing.overload
    def createTableChooserDialog(self, title: typing.Union[java.lang.String, str], executor: ghidra.app.tablechooser.TableChooserExecutor, isModal: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.tablechooser.TableChooserDialog:
        """
        Creates a TableChooserDialog that allows the script to display a list of addresses (and
        associated column data) in a table and also provides the capability to execute an
        action from a selection in the table.
         
        
        This method is unavailable in headless mode.
        
        :param java.lang.String or str title: of the dialog
        :param ghidra.app.tablechooser.TableChooserExecutor executor: the TableChooserExecuter to be used to apply operations on table entries.
        :param jpype.JBoolean or bool isModal: indicates whether the dialog should be modal or not
        :return: a new TableChooserDialog.
        :rtype: ghidra.app.tablechooser.TableChooserDialog
        :raises ImproperUseException: if this method is run in headless mode; if this script is
                                    run directly via Java or another script where the state does
                                    not include a tool.
        """

    def execute(self, runState: GhidraState, runMonitor: ghidra.util.task.TaskMonitor, runWriter: java.io.PrintWriter):
        """
        Execute/run script and :obj:`.doCleanup` afterwards.
        
        :param GhidraState runState: state object
        :param ghidra.util.task.TaskMonitor runMonitor: the monitor to use during run
        :param java.io.PrintWriter runWriter: the target of script "print" statements
        :raises java.lang.Exception: if the script excepts
        """

    def getAnalysisOptionDefaultValue(self, program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the default value for the given analysis option.  Returns empty string if
        invalid option.
        
        :param ghidra.program.model.listing.Program program: the program for which we want to retrieve the default value for the
                    given analysis option
        :param java.lang.String or str analysisOption: the analysis option for which we want to retrieve the default value
        :return: String representation of default value (returns empty string if analysis option
                    is invalid).
        :rtype: str
        """

    def getAnalysisOptionDefaultValues(self, program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns a mapping of the given analysis options to their default values in String form.
        An individual option is mapped to the empty String if the option is invalid.
        
        :param ghidra.program.model.listing.Program program: the program for which to retrieve default values for the
                            given analysis options
        :param java.util.List[java.lang.String] analysisOptions: the analysis options for which to retrieve default values
        :return: mapping from analysis options to their default values.  An individual option
                        will be mapped to an empty String if the option is invalid.
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getAnalysisOptionDescription(self, program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]) -> str:
        """
        Returns the description of an analysis option name, as provided by the analyzer. This
        method returns an empty string if no description is available.
        
        :param ghidra.program.model.listing.Program program: the program to get the analysis option description from
        :param java.lang.String or str analysisOption: the analysis option to get the description for
        :return: the analysis description, or empty String if none has been provided
        :rtype: str
        """

    def getAnalysisOptionDescriptions(self, program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Returns descriptions mapping to the given list of analysis option names. This method
        returns an empty string for an analysis option if no description is available.
        
        :param ghidra.program.model.listing.Program program: the program to get the analysis option description from
        :param java.util.List[java.lang.String] analysisOptions: the lists of analysis options to get the description for
        :return: mapping between each analysis options and its description (description is empty
                    string if none has been provided).
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getCategory(self) -> str:
        """
        Returns the category for this script.
        
        :return: the category for this script
        :rtype: str
        """

    def getCodeUnitFormat(self) -> ghidra.program.model.listing.CodeUnitFormat:
        """
        Returns the code unit format established for the code browser listing
        or a default format if no tool (e.g., headless).
         
        
        This format object may be used to format any code unit (instruction/data) using
        the same option settings.
        
        :return: code unit format when in GUI mode, default format in headless
        :rtype: ghidra.program.model.listing.CodeUnitFormat
        """

    def getCurrentAnalysisOptionsAndValues(self, program: ghidra.program.model.listing.Program) -> java.util.Map[java.lang.String, java.lang.String]:
        """
        Gets the given program's ANALYSIS_PROPERTIES and returns a HashMap of the
        program's analysis options to current values (values represented as strings).
         
        
        The string "(default)" is appended to the value if it represents the
        default value for the option it is assigned to.
        
        :param ghidra.program.model.listing.Program program: the program to get analysis options from
        :return: mapping of analysis options to current settings (represented as strings)
        :rtype: java.util.Map[java.lang.String, java.lang.String]
        """

    def getDefaultLanguage(self, processor: ghidra.program.model.lang.Processor) -> ghidra.program.model.lang.Language:
        """
        Returns the default language provider for the specified processor name.
        
        :param ghidra.program.model.lang.Processor processor: the processor
        :return: the default language provider for the specified processor name
        :rtype: ghidra.program.model.lang.Language
        :raises LanguageNotFoundException: if no language provider exists for the processor
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Language`
        """

    def getDemangled(self, mangled: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a demangled version of the mangled string.
        
        :param java.lang.String or str mangled: the mangled string to demangled
        :return: a demangled version of the mangled string, or null if it could not be demangled
        :rtype: str
        """

    def getEOLCommentAsRendered(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the EOL comment at the specified address.  If you want the raw text,
        then you must call :meth:`getEOLComment(Address) <.getEOLComment>`.  This method returns the text as
        seen in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the EOL comment at the specified address or null if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getEOLComment(Address)`
        """

    def getGhidraVersion(self) -> str:
        """
        Returns the version of the Ghidra being run.
        
        :return: the version of the Ghidra being run
        :rtype: str
        """

    def getLanguage(self, languageID: ghidra.program.model.lang.LanguageID) -> ghidra.program.model.lang.Language:
        """
        Returns the language provider for the specified language name.
        
        :param ghidra.program.model.lang.LanguageID languageID: the language name
        :return: the language provider for the specified language name
        :rtype: ghidra.program.model.lang.Language
        :raises LanguageNotFoundException: if no language provider exists
        
        .. seealso::
        
            | :obj:`ghidra.program.model.lang.Language`
        """

    def getPlateCommentAsRendered(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the PLATE comment at the specified address, as rendered.  Comments support
        annotations, which are displayed differently than the raw text.  If you want the raw text,
        then you must call :meth:`getPlateComment(Address) <.getPlateComment>`.  This method returns the text as
        seen in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the PLATE comment at the specified address or null
                    if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getPlateComment(Address)`
        """

    def getPostCommentAsRendered(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the POST comment at the specified address.  If you want the raw text,
        then you must call :meth:`getPostComment(Address) <.getPostComment>`.  This method returns the text as
        seen in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the POST comment at the specified address or null if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getPostComment(Address)`
        """

    def getPreCommentAsRendered(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the PRE comment at the specified address.  If you want the raw text,
        then you must call :meth:`getPreComment(Address) <.getPreComment>`.  This method returns the text as
        seen in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the PRE comment at the specified address or null
                if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getPreComment(Address)`
        """

    def getRepeatableCommentAsRendered(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the repeatable comment at the specified address.  If you want the raw text,
        then you must call :meth:`getRepeatableComment(Address) <.getRepeatableComment>`.  This method returns the text as
        seen in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the repeatable comment at the specified address or null if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getRepeatableComment(Address)`
        """

    def getReusePreviousChoices(self) -> bool:
        """
        Returns whether scripts will reuse previously selected values when showing the various
        ``ask`` methods.
        
        :return: true to reuse values; false to not reuse previous values
        :rtype: bool
        """

    def getScriptAnalysisMode(self) -> GhidraScript.AnalysisMode:
        """
        Determines the behavior of Auto-Analysis while this script is executed and the manner
        in which this script is executed.  If a script overrides this method and returns DISABLED
        or SUSPENDED, this script will execute as an AnalysisWorker.  Note that this will only
        work reliably when the script is working with the currentProgram only and is not opening
        and changing other programs.  If multiple programs will be modified
        and auto-analysis should be disabled/suspended, the AutoAnalysisManager.scheduleWorker
        method should be used with the appropriate AutoAnalysisManager instance.
        
        :return: the analysis mode associated with this script.
        :rtype: GhidraScript.AnalysisMode
        
        .. seealso::
        
            | :obj:`AutoAnalysisManager.getAnalysisManager(Program)`
        
            | :obj:`AutoAnalysisManager.scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)`
        
            | :obj:`AutoAnalysisManager.setIgnoreChanges(boolean)`
        """

    def getScriptArgs(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the script-specific arguments
        
        :return: The script-specific arguments.  Could be an empty array, but won't be null.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getScriptName(self) -> str:
        """
        Returns name of script
        
        :return: name of script
        :rtype: str
        """

    def getSourceFile(self) -> generic.jar.ResourceFile:
        """
        Returns the script source file.
        
        :return: the script source file
        :rtype: generic.jar.ResourceFile
        """

    def getState(self) -> GhidraState:
        """
        Returns the state object for this script after first synchronizing its state with its
        corresponding convenience variables.
        
        :return: the state object
        :rtype: GhidraState
        """

    def getUserName(self) -> str:
        """
        Returns the username of the user running the script.
        
        :return: the username of the user running the script
        :rtype: str
        """

    @typing.overload
    def goTo(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Sends a 'goto' event that navigates the listing to the specified
        address.
        
        :param ghidra.program.model.address.Address address: the address to 'goto'
        :return: true if the address is valid
        :rtype: bool
        """

    @typing.overload
    def goTo(self, symbol: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Sends a 'goto' event that navigates the listing to the specified symbol.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to 'goto'
        :return: true if the symbol is valid
        :rtype: bool
        """

    @typing.overload
    def goTo(self, function: ghidra.program.model.listing.Function) -> bool:
        """
        Sends a 'goto' event that navigates the listing to the specified function.
        
        :param ghidra.program.model.listing.Function function: the function to 'goto'
        :return: true if the function is valid
        :rtype: bool
        """

    def importFile(self, file: jpype.protocol.SupportsPath) -> ghidra.program.model.listing.Program:
        """
        Attempts to import the specified file. It attempts to detect the format and
        automatically import the file. If the format is unable to be determined, then
        null is returned.  For more control over the import process, :obj:`AutoImporter` may be
        directly called.
         
        
        NOTE: The returned :obj:`Program` is not automatically saved into the current project.
         
        
        NOTE: It is the responsibility of the script that calls this method to release the returned
        :obj:`Program` with :meth:`DomainObject.release(Object consumer) <DomainObject.release>` when it is no longer
        needed, where ``consumer`` is ``this``.
        
        :param jpype.protocol.SupportsPath file: the file to import
        :return: the newly imported program, or null
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: if any exceptions occur while importing
        """

    def importFileAsBinary(self, file: jpype.protocol.SupportsPath, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.listing.Program:
        """
        Imports the specified file as raw binary.  For more control over the import process,
        :obj:`AutoImporter` may be directly called.
         
        
        NOTE: It is the responsibility of the script that calls this method to release the returned
        :obj:`Program` with :meth:`DomainObject.release(Object consumer) <DomainObject.release>` when it is no longer
        needed, where ``consumer`` is ``this``.
        
        :param jpype.protocol.SupportsPath file: the file to import
        :param ghidra.program.model.lang.Language language: the language of the new program
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compilerSpec to use for the import.
        :return: the newly created program, or null
        :rtype: ghidra.program.model.listing.Program
        :raises java.lang.Exception: if any exceptions occur when importing
        """

    def isAnalysisOptionDefaultValue(self, program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str], analysisValue: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns a boolean value representing whether the specified value for the specified
        analysis option is actually the default value for that option.
        
        :param ghidra.program.model.listing.Program program: the program for which we want to verify the analysis option value
        :param java.lang.String or str analysisOption: the analysis option whose value we want to verify
        :param java.lang.String or str analysisValue: the analysis value to be compared to the option's default value
        :return: whether the given value for the given option is default or not
        :rtype: bool
        """

    def isRunningHeadless(self) -> bool:
        """
        Returns whether this script is running in a headless (Non GUI) environment.
         
        
        This method should not be using GUI type script calls like showAddress()
        
        :return: true if the script is running without a GUI.
        :rtype: bool
        """

    def openProgram(self, program: ghidra.program.model.listing.Program):
        """
        Opens the specified program in the current tool.
        
        :param ghidra.program.model.listing.Program program: the program to open
        """

    def parseAddress(self, val: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Parses an address from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The address that was parsed from the string.
        :rtype: ghidra.program.model.address.Address
        :raises IllegalArgumentException: if there was a problem parsing an address from the string.
        """

    def parseBoolean(self, val: typing.Union[java.lang.String, str]) -> bool:
        """
        Parses a boolean from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The boolean that was parsed from the string.
        :rtype: bool
        :raises IllegalArgumentException: if the parsed value is not a valid boolean.
        """

    def parseBytes(self, val: typing.Union[java.lang.String, str]) -> jpype.JArray[jpype.JByte]:
        """
        Parses bytes from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The bytes that were parsed from the string.
        :rtype: jpype.JArray[jpype.JByte]
        :raises IllegalArgumentException: if there was a problem parsing bytes from the string.
        """

    def parseChoice(self, val: typing.Union[java.lang.String, str], validChoices: java.util.List[T]) -> T:
        """
        Parses a choice from a string.
        
        :param java.lang.String or str val: The string to parse.
        :param java.util.List[T] validChoices: An array of valid choices.
        :return: The choice
        :rtype: T
        :raises IllegalArgumentException: if the parsed string was not a valid choice.
        """

    @typing.overload
    def parseChoices(self, s: typing.Union[java.lang.String, str], validChoices: java.util.List[T]) -> java.util.List[T]:
        """
        Parses choices from a string.  The string must be surrounded by quotes, with a ';' as the
        separator.
        
        :param java.lang.String or str s: The string to parse.
        :param java.util.List[T] validChoices: An array of valid choices.
        :return: The choices, if they found in the array of choices.
        :rtype: java.util.List[T]
        :raises IllegalArgumentException: if the parsed string did not contain any valid choices.
        """

    @typing.overload
    def parseChoices(self, val: typing.Union[java.lang.String, str], validChoices: java.util.List[T], stringRepresentationOfValidChoices: java.util.List[java.lang.String]) -> java.util.List[T]:
        """
        Parses choices from a string.
        
        :param java.lang.String or str val: The string to parse.
        :param java.util.List[T] validChoices: A list of valid choices.
        :param java.util.List[java.lang.String] stringRepresentationOfValidChoices: An corresponding array of valid choice string
                representations.
        :return: The choices
        :rtype: java.util.List[T]
        :raises IllegalArgumentException: if the parsed string did not contain any valid choices.
        """

    def parseDirectory(self, val: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Parses a directory from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The directory that was parsed from the string.
        :rtype: java.io.File
        :raises IllegalArgumentException: if the parsed value is not a valid directory.
        """

    def parseDomainFile(self, val: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFile:
        """
        Parses a DomainFile from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The DomainFile that was parsed from the string.
        :rtype: ghidra.framework.model.DomainFile
        :raises IllegalArgumentException: if the parsed value is not a valid DomainFile.
        """

    def parseDouble(self, val: typing.Union[java.lang.String, str]) -> float:
        """
        Parses a double from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The double that was parsed from the string.
        :rtype: float
        :raises IllegalArgumentException: if the parsed value is not a valid double.
        """

    def parseInt(self, val: typing.Union[java.lang.String, str]) -> int:
        """
        Parses an integer from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The integer that was parsed from the string.
        :rtype: int
        :raises IllegalArgumentException: if the parsed value is not a valid integer.
        """

    def parseLanguageCompileSpecPair(self, val: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Parses a LanguageCompilerSpecPair from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The directory that was parsed from the LanguageCompilerSpecPair.
        :rtype: ghidra.program.model.lang.LanguageCompilerSpecPair
        :raises IllegalArgumentException: if the parsed value is not a valid LanguageCompilerSpecPair.
        """

    def parseLong(self, val: typing.Union[java.lang.String, str]) -> int:
        """
        Parses a long from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The long that was parsed from the string.
        :rtype: int
        :raises IllegalArgumentException: if the parsed value is not a valid long.
        """

    def parseProjectFolder(self, val: typing.Union[java.lang.String, str]) -> ghidra.framework.model.DomainFolder:
        """
        Parses a ProjectFolder from a string.
        
        :param java.lang.String or str val: The string to parse.
        :return: The ProjectFolder that was parsed from the string.
        :rtype: ghidra.framework.model.DomainFolder
        :raises IllegalArgumentException: if the parsed value is not a valid ProjectFolder.
        """

    def popup(self, message: typing.Union[java.lang.String, str]):
        """
        Displays a popup dialog with the specified message. The dialog title
        will be the name of this script.
         
        
        In headless mode, the message is displayed in the log output.
        
        :param java.lang.String or str message: the message to display in the dialog
        """

    def print(self, message: typing.Union[java.lang.String, str]):
        """
        Prints the message to the console - no line feed
         
        
        **Note: This method will not print out the name of the script,
        as does :meth:`println(String) <.println>`**
         
        
        If you would like the name of the script to precede you message, then you must add that
        yourself.  The :meth:`println(String) <.println>` does this via the following code:
         
            String messageWithSource = getScriptName() + "> " + message;
         
        
        :param java.lang.String or str message: the message to print
        
        .. seealso::
        
            | :obj:`.printf(String, Object...)`
        """

    def printerr(self, message: typing.Union[java.lang.String, str]):
        """
        Prints the error message to the console followed by a line feed.
        
        :param java.lang.String or str message: the error message to print
        """

    def printf(self, message: typing.Union[java.lang.String, str], *args: java.lang.Object):
        """
        A convenience method to print a formatted String using Java's ``printf``
        feature, which is similar to that of the C programming language.
        For a full description on Java's
        ``printf`` usage, see :obj:`java.util.Formatter`.
         
        
        For examples, see the included ``FormatExampleScript``.
         
        
        **Note: This method will not:**
         
        * print out the name of the script, as does :meth:`println(String) <.println>`
        * print a newline
        
        If you would like the name of the script to precede you message, then you must add that
        yourself.  The :meth:`println(String) <.println>` does this via the following code:
         
            String messageWithSource = getScriptName() + "> " + message;
         
        
        :param java.lang.String or str message: the message to format
        :param jpype.JArray[java.lang.Object] args: formatter arguments (see above)
        
        .. seealso::
        
            | :obj:`String.format(String, Object...)`
        
            | :obj:`java.util.Formatter`
        
            | :obj:`.print(String)`
        
            | :obj:`.println(String)`
        """

    @typing.overload
    def println(self):
        """
        Prints a newline.
        
        
        .. seealso::
        
            | :obj:`.printf(String, Object...)`
        """

    @typing.overload
    def println(self, message: typing.Union[java.lang.String, str]):
        """
        Prints the message to the console followed by a line feed.
        
        :param java.lang.String or str message: the message to print
        
        .. seealso::
        
            | :obj:`.printf(String, Object...)`
        """

    def removeHighlight(self):
        """
        Clears the current highlight. Sets this script's highlight state (both the local variable
        currentHighlight and the ghidraState's currentHighlight) to null.  Also clears the tool's
        highlight if the tool exists.
        """

    def removeSelection(self):
        """
        Clears the current selection.  Calling this method is equivalent to calling
        :meth:`setCurrentSelection(AddressSetView) <.setCurrentSelection>` with a null or empty AddressSet.
        """

    def resetAllAnalysisOptions(self, program: ghidra.program.model.listing.Program):
        """
        Reset all analysis options to their default values.
        
        :param ghidra.program.model.listing.Program program: the program for which all analysis options should be reset
        """

    def resetAnalysisOption(self, program: ghidra.program.model.listing.Program, analysisOption: typing.Union[java.lang.String, str]):
        """
        Reset one analysis option to its default value.
        
        :param ghidra.program.model.listing.Program program: the program for which the specified analysis options should be reset
        :param java.lang.String or str analysisOption: the specified analysis option to reset (invalid options will be
                    ignored)
        """

    def resetAnalysisOptions(self, program: ghidra.program.model.listing.Program, analysisOptions: java.util.List[java.lang.String]):
        """
        Resets a specified list of analysis options to their default values.
        
        :param ghidra.program.model.listing.Program program: the program for which the specific analysis options should be reset
        :param java.util.List[java.lang.String] analysisOptions: the specified analysis options to reset (invalid options
                    will be ignored)
        """

    @typing.overload
    def runCommand(self, cmd: ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]) -> bool:
        """
        Runs the specified command using the current program.
        
        :param ghidra.framework.cmd.Command[ghidra.program.model.listing.Program] cmd: the command to run
        :return: true if the command successfully ran
        :rtype: bool
        """

    @typing.overload
    def runCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]) -> bool:
        """
        Runs the specified background command using the current program.
        The command will be given the script task monitor.
        
        :param ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program] cmd: the background command to run
        :return: true if the background command successfully ran
        :rtype: bool
        """

    @typing.overload
    def runScript(self, scriptName: typing.Union[java.lang.String, str]):
        """
        Runs a script by name (allows current state to be changed by script).
         
        
        It attempts to locate the script in the directories
        defined in ``GhidraScriptUtil.getScriptDirectories()``.
         
        
        The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
        this calling script.  Also, any changes to the state by the script being run will be
        reflected in this calling script's state.
        
        :param java.lang.String or str scriptName: the name of the script to run
        :raises IllegalArgumentException: if the script does not exist
        :raises java.lang.Exception: if any exceptions occur while running the script
        
        .. seealso::
        
            | :obj:`.runScriptPreserveMyState(String)`
        
            | :obj:`.runScript(String, GhidraState)`
        """

    @typing.overload
    def runScript(self, scriptName: typing.Union[java.lang.String, str], scriptArguments: jpype.JArray[java.lang.String]):
        """
        Runs a script by name with the provided arguments (allows current state to be changed by
        script).
         
        
        It attempts to locate the script in the directories
        defined in ``GhidraScriptUtil.getScriptDirectories()``.
         
        
        The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
        this calling script.  Also, any changes to the state by the script being run will be
        reflected in this calling script's state.
        
        :param java.lang.String or str scriptName: the name of the script to run
        :param jpype.JArray[java.lang.String] scriptArguments: the arguments to pass to the script
        :raises IllegalArgumentException: if the script does not exist
        :raises java.lang.Exception: if any exceptions occur while running the script
        
        .. seealso::
        
            | :obj:`.runScriptPreserveMyState(String)`
        
            | :obj:`.runScript(String, GhidraState)`
        """

    @typing.overload
    def runScript(self, scriptName: typing.Union[java.lang.String, str], scriptState: GhidraState):
        """
        Runs a script by name using the given state.
         
        
        It attempts to locate the script in the directories
        defined in ``GhidraScriptUtil.getScriptDirectories()``.
         
        
        The script being run uses the given :obj:`GhidraState` (e.g., script variables)
        Any changes to the state by the script being run will be reflected in the given state
        object.  If the given object is the current state, this scripts state may be changed
        by the called script.
        
        :param java.lang.String or str scriptName: the name of the script to run
        :param GhidraState scriptState: the Ghidra state
        :raises IllegalArgumentException: if the script does not exist
        :raises java.lang.Exception: if any exceptions occur while running the script
        
        .. seealso::
        
            | :obj:`.runScriptPreserveMyState(String)`
        
            | :obj:`.runScript(String)`
        """

    @typing.overload
    def runScript(self, scriptName: typing.Union[java.lang.String, str], scriptArguments: jpype.JArray[java.lang.String], scriptState: GhidraState):
        """
        Runs a script by name with the given arguments using the given state.
         
        
        It attempts to locate the script in the directories
        defined in ``GhidraScriptUtil.getScriptDirectories()``.
         
        
        The script being run uses the given :obj:`GhidraState` (e.g., script variables)
        Any changes to the state by the script being run will be reflected in the given state
        object.  If the given object is the current state, this scripts state may be changed
        by the called script.
        
        :param java.lang.String or str scriptName: the name of the script to run
        :param jpype.JArray[java.lang.String] scriptArguments: the arguments to pass to the script
        :param GhidraState scriptState: the Ghidra state
        :raises IllegalArgumentException: if the script does not exist
        :raises java.lang.Exception: if any exceptions occur while running the script
        
        .. seealso::
        
            | :obj:`.runScriptPreserveMyState(String)`
        
            | :obj:`.runScript(String)`
        """

    def runScriptPreserveMyState(self, scriptName: typing.Union[java.lang.String, str]) -> GhidraState:
        """
        Runs a script by name (does not allow current state to change).
         
        
        It attempts to locate the script in the directories
        defined in ``GhidraScriptUtil.getScriptDirectories()``.
         
        
        The script being run uses the same :obj:`GhidraState` (e.g., script variables) as
        this calling script.  However, any changes to the state by the script being run will NOT
        be reflected in this calling script's state.
        
        :param java.lang.String or str scriptName: the name of the script to run
        :return: a GhidraState object containing the final state of the run script.
        :rtype: GhidraState
        :raises IllegalArgumentException: if the script does not exist
        :raises java.lang.Exception: if any exceptions occur while running the script
        
        .. seealso::
        
            | :obj:`.runScript(String)`
        
            | :obj:`.runScript(String, GhidraState)`
        """

    def set(self, state: GhidraState, monitor: ghidra.util.task.TaskMonitor, writer: java.io.PrintWriter):
        """
        Set the context for this script.
        
        :param GhidraState state: state object
        :param ghidra.util.task.TaskMonitor monitor: the monitor to use during run
        :param java.io.PrintWriter writer: the target of script "print" statements
        """

    def setAnalysisOption(self, program: ghidra.program.model.listing.Program, optionName: typing.Union[java.lang.String, str], optionValue: typing.Union[java.lang.String, str]):
        """
        Allows user to set one analysis option by passing in the analysis option to
        be changed and the new value of that option. This method does the work of
        converting the option value to its actual object type (if needed).
        
        :param ghidra.program.model.listing.Program program: the program for which analysis options should be set
        :param java.lang.String or str optionName: the name of the option to be set
        :param java.lang.String or str optionValue: the new value of the option
        """

    def setAnalysisOptions(self, program: ghidra.program.model.listing.Program, analysisSettings: collections.abc.Mapping):
        """
        Allows user to set analysis options by passing a mapping of analysis option to
        desired value.  This method does the work of converting the option value to its
        actual object type (if needed).
        
        :param ghidra.program.model.listing.Program program: the program for which analysis options should be set
        :param collections.abc.Mapping analysisSettings: a mapping from analysis options to desired new settings
        """

    def setAnonymousServerCredentials(self) -> bool:
        """
        Enable use of anonymous read-only user connection to Ghidra Server in place of
        fixed username/password credentials.
         
        
        NOTE: Only used for Headless environment, other GUI environments should
        continue to prompt user for login credentials as needed.
        
        :return: true if active project is either private or shared project is
        connected to its server repository.  False is returned if not active
        project or an active shared project failed to connect.
        :rtype: bool
        """

    @typing.overload
    def setBackgroundColor(self, address: ghidra.program.model.address.Address, color: java.awt.Color):
        """
        Sets the background of the Listing at the given address to the given color.  See the
        Listing help page in Ghidra help for more information.
         
        
        This method is unavailable in headless mode.
         
        
        Note: you can use the :obj:`ColorizingService` directly to access more color changing
        functionality.  See the source code of this method to learn how to access services from
        a script.
        
        :param ghidra.program.model.address.Address address: The address at which to set the color
        :param java.awt.Color color: The color to set
        :raises ImproperUseException: if this method is run in headless mode
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(AddressSetView, Color)`
        
            | :obj:`.clearBackgroundColor(Address)`
        
            | :obj:`ColorizingService`
        """

    @typing.overload
    def setBackgroundColor(self, addresses: ghidra.program.model.address.AddressSetView, color: java.awt.Color):
        """
        Sets the background of the Listing at the given addresses to the given color.  See the
        Listing help page in Ghidra help for more information.
         
        
        This method is unavailable in headless mode.
         
        
        Note: you can use the :obj:`ColorizingService` directly to access more color changing
        functionality.  See the source code of this method to learn how to access services from
        a script.
        
        :param ghidra.program.model.address.AddressSetView addresses: The addresses at which to set the color
        :param java.awt.Color color: The color to set
        :raises ImproperUseException: if this method is run in headless mode
        
        .. seealso::
        
            | :obj:`.setBackgroundColor(Address, Color)`
        
            | :obj:`.clearBackgroundColor(AddressSetView)`
        
            | :obj:`ColorizingService`
        """

    def setCurrentHighlight(self, addressSet: ghidra.program.model.address.AddressSetView):
        """
        Sets the highlight state to the given address set.
         
        
        The actual behavior of the method depends on your environment, which can be GUI or
        headless:
         
        1. In the GUI environment this method will set the :obj:`.currentHighlight`
        variable to the given value, update the:obj:`GhidraState`'s highlight variable,
        and will set the Tool's highlight to the given value.
        2. In the headless environment this method will set the :obj:`.currentHighlight`
        variable to    the given value and update the GhidraState's highlight variable.
        
        
        :param ghidra.program.model.address.AddressSetView addressSet: the set of addresses to include in the highlight.  If this value is null,
        the current highlight will be cleared and the variables set to null.
        """

    def setCurrentLocation(self, address: ghidra.program.model.address.Address):
        """
        Set the script :obj:`.currentAddress`, :obj:`.currentLocation`, and update state object.
        
        :param ghidra.program.model.address.Address address: the new address
        """

    def setCurrentSelection(self, addressSet: ghidra.program.model.address.AddressSetView):
        """
        Sets the selection state to the given address set.
         
        
        The actual behavior of the method depends on your environment, which can be GUI or
        headless:
         
        1. In the GUI environment this method will set the :obj:`.currentSelection`
        variable to the given value, update the:obj:`GhidraState`'s selection
        variable,and will set the Tool's selection to the given value.
        2. In the headless environment this method will set the :obj:`.currentSelection`
        variable to the given value and update the GhidraState's selection variable.
        
        
        :param ghidra.program.model.address.AddressSetView addressSet: the set of addresses to include in the selection.  If this value is null,
        the current selection will be cleared and the variables set to null.
        """

    def setPotentialPropertiesFileLocations(self, locations: java.util.List[generic.jar.ResourceFile]):
        """
        Set potential locations of .properties files for scripts (including subscripts).
        This should be used when the .properties file is not located in the same directory
        as the script, and the user has supplied one or more potential locations for the
        .properties file(s).
        
        :param java.util.List[generic.jar.ResourceFile] locations: directories that contain .properties files
        """

    def setPropertiesFile(self, propertiesFile: jpype.protocol.SupportsPath):
        """
        Explicitly set the .properties file (used if a ResourceFile representing the
        GhidraScript is not available -- i.e., if running GhidraScript from a .class file
        or instantiating the actual GhidraScript object directly).
        
        :param jpype.protocol.SupportsPath propertiesFile: the actual .properties file for this GhidraScript
        :raises IOException: if there is an exception reading the properties
        """

    def setPropertiesFileLocation(self, dirLocation: typing.Union[java.lang.String, str], basename: typing.Union[java.lang.String, str]):
        """
        Explicitly set the .properties file location and basename for this script (used
        if a ResourceFile representing the GhidraScript is not available -- i.e., if
        running GhidraScript from a .class file or instantiating the actual GhidraScript
        object directly).
        
        :param java.lang.String or str dirLocation: String representation of the path to the .properties file
        :param java.lang.String or str basename: base name of the file
        :raises IOException: if there is an exception loading the new properties file
        """

    def setReusePreviousChoices(self, reuse: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the user's previously selected values should be used when showing the various
        ``ask`` methods.   This is true by default, meaning that previous choices will be shown
        instead of any provided default value.
        
        :param jpype.JBoolean or bool reuse: true to reuse values; false to not reuse previous values
        """

    def setScriptArgs(self, scriptArgs: jpype.JArray[java.lang.String]):
        """
        Sets script-specific arguments
        
        :param jpype.JArray[java.lang.String] scriptArgs: The script-specific arguments to use.  For no scripts, use null or an
        empty array.
        """

    def setServerCredentials(self, username: typing.Union[java.lang.String, str], password: typing.Union[java.lang.String, str]) -> bool:
        """
        Establishes fixed login credentials for Ghidra Server access.
         
        
        NOTE: Only used for Headless environment, other GUI environments should
        continue to prompt user for login credentials as needed.
        
        :param java.lang.String or str username: login name or null if not applicable or to use default name
        :param java.lang.String or str password: login password
        :return: true if active project is either private or shared project is
        connected to its server repository.  False is returned if not active
        project or an active shared project failed to connect.
        :rtype: bool
        """

    def setSourceFile(self, sourceFile: generic.jar.ResourceFile):
        """
        Set associated source file
        
        :param generic.jar.ResourceFile sourceFile: the source file
        """

    def setToolStatusMessage(self, msg: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Display a message in tools status bar.
         
        
        This method is unavailable in headless mode.
        
        :param java.lang.String or str msg: the text to display.
        :param jpype.JBoolean or bool beep: if true, causes the tool to beep.
        :raises ImproperUseException: if this method is run in headless mode
        """

    @typing.overload
    def show(self, addresses: jpype.JArray[ghidra.program.model.address.Address]):
        """
        Displays the address array in a table component. The table contains an address
        column, a label column, and a preview column.
         
        
        This method is unavailable in headless mode.
        
        :param jpype.JArray[ghidra.program.model.address.Address] addresses: the address array to display
        :raises ImproperUseException: if this method is run in headless mode
        """

    @typing.overload
    def show(self, title: typing.Union[java.lang.String, str], addresses: ghidra.program.model.address.AddressSetView):
        """
        Displays the given AddressSet in a table, in a dialog.
         
        
        This method is unavailable in headless mode.
        
        :param java.lang.String or str title: The title of the table
        :param ghidra.program.model.address.AddressSetView addresses: The addresses to display
        :raises ImproperUseException: if this method is run in headless mode
        """

    @typing.overload
    def toHexString(self, b: typing.Union[jpype.JByte, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a hex string representation of the byte.
        
        :param jpype.JByte or int b: the integer
        :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
        :param jpype.JBoolean or bool header: true if "0x" should be prepended
        :return: the hex formatted string
        :rtype: str
        """

    @typing.overload
    def toHexString(self, s: typing.Union[jpype.JShort, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a hex string representation of the short.
        
        :param jpype.JShort or int s: the short
        :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
        :param jpype.JBoolean or bool header: true if "0x" should be prepended
        :return: the hex formatted string
        :rtype: str
        """

    @typing.overload
    def toHexString(self, i: typing.Union[jpype.JInt, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a hex string representation of the integer.
        
        :param jpype.JInt or int i: the integer
        :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
        :param jpype.JBoolean or bool header: true if "0x" should be prepended
        :return: the hex formatted string
        :rtype: str
        """

    @typing.overload
    def toHexString(self, l: typing.Union[jpype.JLong, int], zeropad: typing.Union[jpype.JBoolean, bool], header: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a hex string representation of the long.
        
        :param jpype.JLong or int l: the long
        :param jpype.JBoolean or bool zeropad: true if the value should be zero padded
        :param jpype.JBoolean or bool header: true if "0x" should be prepended
        :return: the hex formatted string
        :rtype: str
        """

    @property
    def scriptArgs(self) -> jpype.JArray[java.lang.String]:
        ...

    @scriptArgs.setter
    def scriptArgs(self, value: jpype.JArray[java.lang.String]):
        ...

    @property
    def plateCommentAsRendered(self) -> java.lang.String:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def sourceFile(self) -> generic.jar.ResourceFile:
        ...

    @sourceFile.setter
    def sourceFile(self, value: generic.jar.ResourceFile):
        ...

    @property
    def preCommentAsRendered(self) -> java.lang.String:
        ...

    @property
    def defaultLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def eOLCommentAsRendered(self) -> java.lang.String:
        ...

    @property
    def repeatableCommentAsRendered(self) -> java.lang.String:
        ...

    @property
    def codeUnitFormat(self) -> ghidra.program.model.listing.CodeUnitFormat:
        ...

    @property
    def state(self) -> GhidraState:
        ...

    @property
    def demangled(self) -> java.lang.String:
        ...

    @property
    def currentAnalysisOptionsAndValues(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def runningHeadless(self) -> jpype.JBoolean:
        ...

    @property
    def userName(self) -> java.lang.String:
        ...

    @property
    def scriptAnalysisMode(self) -> GhidraScript.AnalysisMode:
        ...

    @property
    def reusePreviousChoices(self) -> jpype.JBoolean:
        ...

    @reusePreviousChoices.setter
    def reusePreviousChoices(self, value: jpype.JBoolean):
        ...

    @property
    def ghidraVersion(self) -> java.lang.String:
        ...

    @property
    def postCommentAsRendered(self) -> java.lang.String:
        ...

    @property
    def scriptName(self) -> java.lang.String:
        ...

    @property
    def category(self) -> java.lang.String:
        ...


@typing.type_check_only
class SelectAllCheckBox(java.awt.event.ActionListener):

    class_: typing.ClassVar[java.lang.Class]

    def addCheckBox(self, newCB: javax.swing.JCheckBox):
        ...

    def setSelectAllCheckBox(self, selAllCB: javax.swing.JCheckBox):
        ...



__all__ = ["GhidraScriptUnsupportedClassVersionError", "GhidraScriptInfoManager", "ResourceFileJavaFileManager", "GhidraScriptProvider", "AbstractPythonScriptProvider", "AskDialog", "UnsupportedScriptProvider", "SelectLanguageDialog", "JavaScriptProvider", "ResourceFileJavaFileObject", "GhidraScriptConstants", "GhidraScriptLoadException", "StringTransformer", "MultipleOptionsDialog", "ScriptMessage", "GhidraState", "ScriptInfo", "ImproperUseException", "GhidraScriptProperties", "GhidraScriptUtil", "GhidraScript", "SelectAllCheckBox"]
