from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.menu
import docking.widgets
import docking.widgets.pathmanager
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.terminal
import ghidra.app.services
import ghidra.debug.api
import ghidra.debug.api.tracermi
import ghidra.debug.spi.tracermi
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.pty
import ghidra.util
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.net # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore
import utility.function


T = typing.TypeVar("T")


class TraceRmiBackEnd(java.util.concurrent.CompletableFuture[java.lang.Integer], ghidra.app.plugin.core.terminal.TerminalListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class UnixShellScriptTraceRmiLaunchOpinion(AbstractTraceRmiLaunchOpinion):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PowerShellScriptTraceRmiLaunchOpinion(AbstractTraceRmiLaunchOpinion):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractTraceRmiLaunchOffer(ghidra.debug.api.tracermi.TraceRmiLaunchOffer):

    @typing.type_check_only
    class PtyTerminalSession(java.lang.Record, ghidra.debug.api.tracermi.TerminalSession):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def pty(self) -> ghidra.pty.Pty:
            ...

        def session(self) -> ghidra.pty.PtySession:
            ...

        def terminal(self) -> ghidra.app.services.Terminal:
            ...

        def toString(self) -> str:
            ...

        def waiter(self) -> java.lang.Thread:
            ...


    @typing.type_check_only
    class NullPtyTerminalSession(java.lang.Record, ghidra.debug.api.tracermi.TerminalSession):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def pty(self) -> ghidra.pty.Pty:
            ...

        def terminal(self) -> ghidra.app.services.Terminal:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class TerminateSessionTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, session: ghidra.debug.api.tracermi.TerminalSession):
            ...


    @typing.type_check_only
    class ImageParamSetter(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        @staticmethod
        def get(param: ghidra.debug.api.tracermi.LaunchParameter[typing.Any]) -> AbstractTraceRmiLaunchOffer.ImageParamSetter:
            ...

        def setImage(self, map: collections.abc.Mapping, program: ghidra.program.model.listing.Program):
            ...


    @typing.type_check_only
    class StringImageParamSetter(AbstractTraceRmiLaunchOffer.ImageParamSetter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, param: ghidra.debug.api.tracermi.LaunchParameter[java.lang.String]):
            ...


    @typing.type_check_only
    class FileImageParamSetter(AbstractTraceRmiLaunchOffer.ImageParamSetter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, param: ghidra.debug.api.tracermi.LaunchParameter[ghidra.framework.plugintool.AutoConfigState.PathIsFile]):
            ...


    class NoStaticMappingException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...


    class EarlyTerminationException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    PREFIX_PARAM_EXTTOOL: typing.Final = "env:GHIDRA_LANG_EXTTOOL_"
    DEFAULT_TIMEOUT_MILLIS: typing.Final = 10000
    DEFAULT_CONNECTION_TIMEOUT_MILLIS: typing.Final[jpype.JInt]

    def __init__(self, plugin: TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def getLauncherArgs(self, prompt: typing.Union[jpype.JBoolean, bool], configurator: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchConfigurator, lastExc: java.lang.Throwable) -> java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]:
        """
        Obtain the launcher arguments
         
         
        
        This should either call :meth:`promptLauncherArgs(LaunchConfigurator, Throwable) <.promptLauncherArgs>` or
        :meth:`loadLastLauncherArgs(boolean) <.loadLastLauncherArgs>`. Note if choosing the latter, the user will not be
        prompted to confirm.
        
        :param jpype.JBoolean or bool prompt: true to prompt the user, false to use saved arguments
        :param ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchConfigurator configurator: the rules for configuring the launcher
        :param java.lang.Throwable lastExc: if retrying, the last exception to display as an error message
        :return: the chosen arguments, or null if the user cancels at the prompt
        :rtype: java.util.Map[java.lang.String, ghidra.debug.api.ValStr[typing.Any]]
        """

    @typing.overload
    def getLauncherArgs(self, prompt: typing.Union[jpype.JBoolean, bool]) -> java.util.Map[java.lang.String, typing.Any]:
        ...

    @property
    def launcherArgs(self) -> java.util.Map[java.lang.String, typing.Any]:
        ...


class UnixShellScriptTraceRmiLaunchOffer(AbstractScriptTraceRmiLaunchOffer):
    """
    A launcher implemented by a simple UNIX shell script.
     
     
    
    The script must start with an attributes header in a comment block. See
    :obj:`ScriptAttributesParser`.
    """

    class_: typing.ClassVar[java.lang.Class]
    HASH: typing.Final = "#"
    HASH_LEN: typing.Final[jpype.JInt]
    SHEBANG: typing.Final = "#!"

    @staticmethod
    def create(plugin: TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program, script: jpype.protocol.SupportsPath) -> UnixShellScriptTraceRmiLaunchOffer:
        """
        Create a launch offer from the given shell script.
        
        :param TraceRmiLauncherServicePlugin plugin: the launcher service plugin
        :param ghidra.program.model.listing.Program program: the current program, usually the target image. In general, this should be used
                    for at least two purposes. 1) To populate the default command line. 2) To ensure
                    the target image is mapped in the resulting target trace.
        :param jpype.protocol.SupportsPath script: the script file that implements this offer
        :return: the offer
        :rtype: UnixShellScriptTraceRmiLaunchOffer
        :raises FileNotFoundException: if the script file does not exist
        """


class BatchScriptTraceRmiLaunchOpinion(AbstractTraceRmiLaunchOpinion):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LaunchFailureDialog(docking.widgets.OptionDialog):

    class ErrPromptResponse(java.lang.Enum[LaunchFailureDialog.ErrPromptResponse]):

        class_: typing.ClassVar[java.lang.Class]
        KEEP: typing.Final[LaunchFailureDialog.ErrPromptResponse]
        RETRY: typing.Final[LaunchFailureDialog.ErrPromptResponse]
        TERMINATE: typing.Final[LaunchFailureDialog.ErrPromptResponse]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> LaunchFailureDialog.ErrPromptResponse:
            ...

        @staticmethod
        def values() -> jpype.JArray[LaunchFailureDialog.ErrPromptResponse]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def show(result: ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult, helpLocation: ghidra.util.HelpLocation) -> LaunchFailureDialog.ErrPromptResponse:
        ...


class AbstractScriptTraceRmiLaunchOffer(AbstractTraceRmiLaunchOffer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program, script: jpype.protocol.SupportsPath, configName: typing.Union[java.lang.String, str], attrs: ScriptAttributesParser.ScriptAttributes):
        ...


class TraceRmiLaunchDialog(ghidra.app.plugin.core.debug.gui.AbstractDebuggerParameterDialog[ghidra.debug.api.tracermi.LaunchParameter[typing.Any]]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], buttonText: typing.Union[java.lang.String, str], buttonIcon: javax.swing.Icon):
        ...


class PowerShellScriptTraceRmiLaunchOffer(AbstractScriptTraceRmiLaunchOffer):
    """
    A launcher implemented by a Window PowerShell file.
     
     
    
    The script must start with an attributes header in a comment block. See
    :obj:`ScriptAttributesParser`.
    """

    class_: typing.ClassVar[java.lang.Class]
    REM: typing.Final = "#"
    REM_LEN: typing.Final[jpype.JInt]

    @staticmethod
    def create(plugin: TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program, script: jpype.protocol.SupportsPath) -> PowerShellScriptTraceRmiLaunchOffer:
        """
        Create a launch offer from the given PowerShell file.
        
        :param TraceRmiLauncherServicePlugin plugin: the launcher service plugin
        :param ghidra.program.model.listing.Program program: the current program, usually the target image. In general, this should be used
                    for at least two purposes. 1) To populate the default command line. 2) To ensure
                    the target image is mapped in the resulting target trace.
        :param jpype.protocol.SupportsPath script: the PowerShell file that implements this offer
        :return: the offer
        :rtype: PowerShellScriptTraceRmiLaunchOffer
        :raises FileNotFoundException: if the batch file does not exist
        """


class TraceRmiLauncherServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.TraceRmiLauncherService, ghidra.framework.options.OptionsChangeListener):

    @typing.type_check_only
    class AbstractLaunchTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offer: ghidra.debug.api.tracermi.TraceRmiLaunchOffer):
            ...


    @typing.type_check_only
    class ReLaunchTask(TraceRmiLauncherServicePlugin.AbstractLaunchTask):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offer: ghidra.debug.api.tracermi.TraceRmiLaunchOffer):
            ...


    @typing.type_check_only
    class ConfigureAndLaunchTask(TraceRmiLauncherServicePlugin.AbstractLaunchTask):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offer: ghidra.debug.api.tracermi.TraceRmiLaunchOffer):
            ...


    class FieldIndex(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dt: ghidra.program.model.data.Composite):
            ...

        @staticmethod
        def fromData(data: ghidra.program.model.listing.Data) -> TraceRmiLauncherServicePlugin.FieldIndex:
            ...

        def getField(self, data: ghidra.program.model.listing.Data, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Data:
            ...


    @typing.type_check_only
    class ConfigLast(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def configName(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def last(self) -> int:
            ...

        def program(self) -> ghidra.program.model.listing.Program:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def extractFirstFsrl(program: ghidra.program.model.listing.Program) -> str:
        ...

    @staticmethod
    def getProgramPath(program: ghidra.program.model.listing.Program, isLocal: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    def tryProgramJvmClass(program: ghidra.program.model.listing.Program) -> str:
        ...

    @staticmethod
    def tryProgramPath(path: typing.Union[java.lang.String, str]) -> java.io.File:
        ...


class ScriptPathsPropertyEditor(docking.widgets.pathmanager.AbstractTypedPropertyEditor[java.lang.String]):

    @typing.type_check_only
    class ScriptPathsEditor(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ScriptPathsDialog(docking.widgets.pathmanager.AbstractPathsDialog):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScriptPathsPanel(docking.widgets.pathmanager.PathnameTablePanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, paths: jpype.JArray[java.lang.String], resetCallback: utility.function.Callback):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LaunchAction(docking.menu.MultiActionDockingAction):

    @typing.type_check_only
    class MenuActionDockingToolbarButton(docking.menu.MultipleActionDockingToolbarButton):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, action: docking.action.MultiActionDockingActionIf):
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Launch"
    ICON: typing.Final[javax.swing.Icon]
    GROUP: typing.Final = "Dbg1. General"
    HELP_ANCHOR: typing.Final = "launch_tracermi"

    def __init__(self, plugin: TraceRmiLauncherServicePlugin):
        ...


class ScriptAttributesParser(java.lang.Object):
    """
    A parser for reading attributes from a script header
    """

    class ParseException(java.lang.Exception):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, loc: ScriptAttributesParser.Location, message: typing.Union[java.lang.String, str]):
            ...

        def getLocation(self) -> ScriptAttributesParser.Location:
            ...

        @property
        def location(self) -> ScriptAttributesParser.Location:
            ...


    @typing.type_check_only
    class Location(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def fileName(self) -> str:
            ...

        def hashCode(self) -> int:
            ...

        def lineNo(self) -> int:
            ...


    @typing.type_check_only
    class OptType(ghidra.debug.api.ValStr.Decoder[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def cls(self) -> java.lang.Class[T]:
            ...

        def createParameter(self, name: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool], defaultValue: ghidra.debug.api.ValStr[T]) -> ghidra.debug.api.tracermi.LaunchParameter[T]:
            ...

        def decode(self, loc: ScriptAttributesParser.Location, str: typing.Union[java.lang.String, str]) -> T:
            ...

        @staticmethod
        def parse(loc: ScriptAttributesParser.Location, typeName: typing.Union[java.lang.String, str], userEnums: collections.abc.Mapping) -> ScriptAttributesParser.OptType[typing.Any]:
            ...

        def withCastDefault(self, defaultValue: ghidra.debug.api.ValStr[java.lang.Object]) -> ScriptAttributesParser.TypeAndDefault[T]:
            ...


    @typing.type_check_only
    class BaseType(ScriptAttributesParser.OptType[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]
        STRING: typing.Final[ScriptAttributesParser.BaseType[java.lang.String]]
        INT: typing.Final[ScriptAttributesParser.BaseType[java.math.BigInteger]]
        BOOL: typing.Final[ScriptAttributesParser.BaseType[java.lang.Boolean]]
        PATH: typing.Final[ScriptAttributesParser.BaseType[java.nio.file.Path]]
        DIR: typing.Final[ScriptAttributesParser.BaseType[ghidra.framework.plugintool.AutoConfigState.PathIsDir]]
        FILE: typing.Final[ScriptAttributesParser.BaseType[ghidra.framework.plugintool.AutoConfigState.PathIsFile]]

        @staticmethod
        def parse(loc: ScriptAttributesParser.Location, typeName: typing.Union[java.lang.String, str]) -> ScriptAttributesParser.BaseType[typing.Any]:
            ...

        @staticmethod
        def parseNoErr(typeName: typing.Union[java.lang.String, str]) -> ScriptAttributesParser.BaseType[typing.Any]:
            ...

        def withCastChoices(self, choices: java.util.List[typing.Any]) -> ScriptAttributesParser.UserType[T]:
            ...

        def withChoices(self, choices: java.util.List[T]) -> ScriptAttributesParser.UserType[T]:
            ...


    @typing.type_check_only
    class UserType(java.lang.Record, ScriptAttributesParser.OptType[T], typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def base(self) -> ScriptAttributesParser.BaseType[T]:
            ...

        def choices(self) -> java.util.List[T]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class TypeAndDefault(java.lang.Record, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def createParameter(self, name: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool]) -> ghidra.debug.api.tracermi.LaunchParameter[T]:
            ...

        def defaultValue(self) -> ghidra.debug.api.ValStr[T]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        @staticmethod
        def parse(loc: ScriptAttributesParser.Location, typeName: typing.Union[java.lang.String, str], defaultString: typing.Union[java.lang.String, str], userEnums: collections.abc.Mapping) -> ScriptAttributesParser.TypeAndDefault[typing.Any]:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ScriptAttributesParser.OptType[T]:
            ...


    class TtyCondition(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def isActive(self, args: collections.abc.Mapping) -> bool:
            ...

        @property
        def active(self) -> jpype.JBoolean:
            ...


    @typing.type_check_only
    class ConstTtyCondition(java.lang.Enum[ScriptAttributesParser.ConstTtyCondition], ScriptAttributesParser.TtyCondition):

        class_: typing.ClassVar[java.lang.Class]
        ALWAYS: typing.Final[ScriptAttributesParser.ConstTtyCondition]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ScriptAttributesParser.ConstTtyCondition:
            ...

        @staticmethod
        def values() -> jpype.JArray[ScriptAttributesParser.ConstTtyCondition]:
            ...


    @typing.type_check_only
    class EqualsTtyCondition(java.lang.Record, ScriptAttributesParser.TtyCondition):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def param(self) -> ghidra.debug.api.tracermi.LaunchParameter[typing.Any]:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> java.lang.Object:
            ...


    @typing.type_check_only
    class BoolTtyCondition(java.lang.Record, ScriptAttributesParser.TtyCondition):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def param(self) -> ghidra.debug.api.tracermi.LaunchParameter[java.lang.Boolean]:
            ...

        def toString(self) -> str:
            ...


    class ScriptAttributes(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, title: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], menuPath: java.util.List[java.lang.String], menuGroup: typing.Union[java.lang.String, str], menuOrder: typing.Union[java.lang.String, str], icon: javax.swing.Icon, helpLocation: ghidra.util.HelpLocation, parameters: collections.abc.Mapping, dependencies: java.util.Set[java.lang.String], extraTtys: collections.abc.Mapping, timeoutMillis: typing.Union[jpype.JInt, int], imageOpt: ghidra.debug.api.tracermi.LaunchParameter[typing.Any]):
            ...

        def dependencies(self) -> java.util.Set[java.lang.String]:
            ...

        def description(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def extraTtys(self) -> java.util.Map[java.lang.String, ScriptAttributesParser.TtyCondition]:
            ...

        def hashCode(self) -> int:
            ...

        def helpLocation(self) -> ghidra.util.HelpLocation:
            ...

        def icon(self) -> javax.swing.Icon:
            ...

        def imageOpt(self) -> ghidra.debug.api.tracermi.LaunchParameter[typing.Any]:
            ...

        def menuGroup(self) -> str:
            ...

        def menuOrder(self) -> str:
            ...

        def menuPath(self) -> java.util.List[java.lang.String]:
            ...

        def parameters(self) -> java.util.Map[java.lang.String, ghidra.debug.api.tracermi.LaunchParameter[typing.Any]]:
            ...

        def timeoutMillis(self) -> int:
            ...

        def title(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ENV_GHIDRA_HOME: typing.Final = "GHIDRA_HOME"
    ENV_MODULE_HOME: typing.Final = "MODULE_HOME"
    ENV_MODULE_HOME_PAT: typing.Final = "MODULE_%s_HOME"
    ENV_GHIDRA_TRACE_RMI_ADDR: typing.Final = "GHIDRA_TRACE_RMI_ADDR"
    ENV_GHIDRA_TRACE_RMI_HOST: typing.Final = "GHIDRA_TRACE_RMI_HOST"
    ENV_GHIDRA_TRACE_RMI_PORT: typing.Final = "GHIDRA_TRACE_RMI_PORT"
    AT_ARG: typing.Final = "@arg"
    AT_ARGS: typing.Final = "@args"
    AT_DEPENDS: typing.Final = "@depends"
    AT_DESC: typing.Final = "@desc"
    AT_ENUM: typing.Final = "@enum"
    AT_ENV: typing.Final = "@env"
    AT_HELP: typing.Final = "@help"
    AT_ICON: typing.Final = "@icon"
    AT_IMAGE_OPT: typing.Final = "@image-opt"
    AT_MENU_GROUP: typing.Final = "@menu-group"
    AT_MENU_ORDER: typing.Final = "@menu-order"
    AT_MENU_PATH: typing.Final = "@menu-path"
    AT_TITLE: typing.Final = "@title"
    AT_TIMEOUT: typing.Final = "@timeout"
    AT_TTY: typing.Final = "@tty"
    KEY_ARGS: typing.Final = "args"
    PREFIX_ARG: typing.Final = "arg:"
    PREFIX_ENV: typing.Final = "env:"
    MSGPAT_DUPLICATE_TAG: typing.Final = "%s: Duplicate %s"
    MSGPAT_INVALID_ARG_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use :type \"Display\" \"Tool Tip\""
    MSGPAT_INVALID_ARGS_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use \"Display\" \"Tool Tip\""
    MSGPAT_INVALID_ENUM_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use NAME:type Choice1 [ChoiceN...]"
    MSGPAT_INVALID_ENV_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use NAME:type=default \"Display\" \"Tool Tip\""
    MSGPAT_INVALID_HELP_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use Topic#anchor"
    MSGPAT_INVALID_TIMEOUT_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use [milliseconds]"
    MSGPAT_INVALID_TTY_BAD_VAL: typing.Final = "%s: In %s: Parameter \'%s\' has type %s, but \'%s\' cannot be parsed as such"
    MSGPAT_INVALID_TTY_NO_PARAM: typing.Final = "%s: In %s: No such parameter \'%s\'"
    MSGPAT_INVALID_TTY_NOT_BOOL: typing.Final = "%s: In %s: Parameter \'%s\' must have bool type"
    MSGPAT_INVALID_TTY_SYNTAX: typing.Final = "%s: Invalid %s syntax. Use TTY_TARGET [if env:OPT [== VAL]]"

    def __init__(self):
        ...

    def parseComment(self, loc: ScriptAttributesParser.Location, comment: typing.Union[java.lang.String, str]):
        """
        Process a line in the metadata comment block
        
        :param ScriptAttributesParser.Location loc: the location, for error reporting
        :param java.lang.String or str comment: the comment, excluding any comment delimiters
        """

    def parseFile(self, script: jpype.protocol.SupportsPath) -> ScriptAttributesParser.ScriptAttributes:
        """
        Parse the header of the given script file
        
        :param jpype.protocol.SupportsPath script: the file
        :return: the parsed attributes
        :rtype: ScriptAttributesParser.ScriptAttributes
        :raises FileNotFoundException: if the script file could not be found
        """

    def parseStream(self, stream: java.io.InputStream, scriptName: typing.Union[java.lang.String, str]) -> ScriptAttributesParser.ScriptAttributes:
        """
        Parse the header from the give input stream
        
        :param java.io.InputStream stream: the stream from of the input stream file
        :param java.lang.String or str scriptName: the name of the script file
        :return: the parsed attributes
        :rtype: ScriptAttributesParser.ScriptAttributes
        :raises IOException: if there was an issue reading the stream
        """

    @staticmethod
    def processArguments(commandLine: java.util.List[java.lang.String], env: collections.abc.Mapping, script: jpype.protocol.SupportsPath, parameters: collections.abc.Mapping, args: collections.abc.Mapping, dependencies: java.util.Set[java.lang.String], address: java.net.SocketAddress):
        """
        Convert an arguments map into a command line and environment variables
        
        :param java.util.List[java.lang.String] commandLine: a mutable list to add command line parameters into
        :param collections.abc.Mapping env: a mutable map to place environment variables into. This should likely be
                    initialized to :meth:`System.getenv() <System.getenv>` so that Ghidra's environment is inherited
                    by the script's process.
        :param jpype.protocol.SupportsPath script: the script file
        :param collections.abc.Mapping parameters: the descriptions of the parameters
        :param collections.abc.Mapping args: the arguments to process
        :param java.util.Set[java.lang.String] dependencies: a set of module names this script needs
        :param java.net.SocketAddress address: the address of the listening TraceRmi socket
        """


class BatchScriptTraceRmiLaunchOffer(AbstractScriptTraceRmiLaunchOffer):
    """
    A launcher implemented by a simple DOS/Windows batch file.
    
     
    
    The script must start with an attributes header in a comment block. See
    :obj:`ScriptAttributesParser`.
    """

    class_: typing.ClassVar[java.lang.Class]
    REM: typing.Final = "::"
    REM_LEN: typing.Final[jpype.JInt]

    @staticmethod
    def create(plugin: TraceRmiLauncherServicePlugin, program: ghidra.program.model.listing.Program, script: jpype.protocol.SupportsPath) -> BatchScriptTraceRmiLaunchOffer:
        """
        Create a launch offer from the given batch file.
        
        :param TraceRmiLauncherServicePlugin plugin: the launcher service plugin
        :param ghidra.program.model.listing.Program program: the current program, usually the target image. In general, this should be used
                    for at least two purposes. 1) To populate the default command line. 2) To ensure
                    the target image is mapped in the resulting target trace.
        :param jpype.protocol.SupportsPath script: the batch file that implements this offer
        :return: the offer
        :rtype: BatchScriptTraceRmiLaunchOffer
        :raises FileNotFoundException: if the batch file does not exist
        """


class AbstractTraceRmiLaunchOpinion(ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["TraceRmiBackEnd", "UnixShellScriptTraceRmiLaunchOpinion", "PowerShellScriptTraceRmiLaunchOpinion", "AbstractTraceRmiLaunchOffer", "UnixShellScriptTraceRmiLaunchOffer", "BatchScriptTraceRmiLaunchOpinion", "LaunchFailureDialog", "AbstractScriptTraceRmiLaunchOffer", "TraceRmiLaunchDialog", "PowerShellScriptTraceRmiLaunchOffer", "TraceRmiLauncherServicePlugin", "ScriptPathsPropertyEditor", "LaunchAction", "ScriptAttributesParser", "BatchScriptTraceRmiLaunchOffer", "AbstractTraceRmiLaunchOpinion"]
