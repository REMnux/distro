from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.util.viewer.field
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class CommentHistoryPanel(javax.swing.JPanel):
    """
    Panel that shows comment history for a particular comment type; uses
    a JTextPane to show information in different colors and fonts for
    readability.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getHistory(self) -> str:
        ...

    @property
    def history(self) -> java.lang.String:
        ...


class CommentsDialog(docking.ReusableDialogComponentProvider, java.awt.event.KeyListener):
    """
    Dialog for setting the comments for a CodeUnit.
    """

    @typing.type_check_only
    class PopupListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnnotationAdapterWrapper(java.lang.Comparable[CommentsDialog.AnnotationAdapterWrapper]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, handler: ghidra.app.util.viewer.field.AnnotatedStringHandler):
            ...

        @typing.overload
        def getPrototypeString(self) -> str:
            ...

        @typing.overload
        def getPrototypeString(self, contained: typing.Union[java.lang.String, str]) -> str:
            ...

        @property
        def prototypeString(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getEnterMode(self) -> bool:
        ...

    def setEnterMode(self, enterMode: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def enterMode(self) -> jpype.JBoolean:
        ...

    @enterMode.setter
    def enterMode(self, value: jpype.JBoolean):
        ...


class CommentsPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.options.OptionsChangeListener):
    """
    Class to handle end comments for a code unit in a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def updateOptions(self):
        ...


class CommentHistoryDialog(docking.DialogComponentProvider):
    """
    Dialog to show comment history; has a tab for each comment type to show
    history of changes to the comment.
    """

    class_: typing.ClassVar[java.lang.Class]


class CommentsActionFactory(java.lang.Object):

    @typing.type_check_only
    class SetCommentsAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EditCommentsAction(CommentsActionFactory.SetCommentsAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getEditCommentsAction(dialog: CommentsDialog, name: typing.Union[java.lang.String, str]) -> docking.action.DockingAction:
        ...

    @staticmethod
    def getSetCommentsAction(dialog: CommentsDialog, name: typing.Union[java.lang.String, str], actionName: typing.Union[java.lang.String, str], commentType: ghidra.program.model.listing.CommentType) -> docking.action.DockingAction:
        ...

    @staticmethod
    def isCommentSupported(loc: ghidra.program.util.ProgramLocation) -> bool:
        ...


class DecompilerCommentsActionFactory(CommentsActionFactory):

    @typing.type_check_only
    class DecompilerSetCommentsAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DecompilerEditCommentsAction(DecompilerCommentsActionFactory.DecompilerSetCommentsAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["CommentHistoryPanel", "CommentsDialog", "CommentsPlugin", "CommentHistoryDialog", "CommentsActionFactory", "DecompilerCommentsActionFactory"]
