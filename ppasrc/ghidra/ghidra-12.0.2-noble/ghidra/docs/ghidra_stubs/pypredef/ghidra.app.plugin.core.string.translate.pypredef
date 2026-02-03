from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore


class ClearTranslationAction(AbstractTranslateAction):
    """
    Action for clearing translated strings.
    """

    @typing.type_check_only
    class ClearTranslationTask(ghidra.program.util.ProgramTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        ...


class ToggleShowTranslationAction(AbstractTranslateAction):
    """
    Action for toggling whether or not to display translated strings or the original string.
    """

    @typing.type_check_only
    class ToggleShowTranslationTask(ghidra.program.util.ProgramTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        ...


class ManualStringTranslationService(ghidra.app.services.StringTranslationService):
    """
    This class allows users to manually translate strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def setTranslatedValue(program: ghidra.program.model.listing.Program, stringLocation: ghidra.program.util.ProgramLocation, newValue: typing.Union[java.lang.String, str]):
        """
        Helper method called by Defined String table model to set the value for a single item.
         
        
        This method is here to keep it adjacent to the manual string translation logic.
        
        :param ghidra.program.model.listing.Program program: current :obj:`Program`
        :param ghidra.program.util.ProgramLocation stringLocation: :obj:`ProgramLocation` of the string to set new translation
        :param java.lang.String or str newValue: String manual translated value
        """


class TranslateStringsPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin that provides string translation services on :obj:`Data` items that are
    strings or arrays of chars.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class TranslateAction(AbstractTranslateAction):
    """
    Action for invoking string translation services.  One of the actions will be created for
    each discovered :obj:`StringTranslationService` by the :obj:`TranslateStringsPlugin`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], service: ghidra.app.services.StringTranslationService):
        ...


class AbstractTranslateAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], codeViewerMenuData: docking.action.MenuData, dataListMenuData: docking.action.MenuData):
        ...



__all__ = ["ClearTranslationAction", "ToggleShowTranslationAction", "ManualStringTranslationService", "TranslateStringsPlugin", "TranslateAction", "AbstractTranslateAction"]
