from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.text # type: ignore


class SelectBeginningOfLineAction(javax.swing.text.TextAction):

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class SelectEndOfLineAction(javax.swing.text.TextAction):

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class BeginningOfLineAction(javax.swing.text.TextAction):

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class DeleteToEndOfWordAction(javax.swing.text.TextAction):
    """
    An action to delete from the cursor position to the end of the current word.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class DeleteToStartOfWordAction(javax.swing.text.TextAction):
    """
    An action to delete from the cursor position to the beginning of the current word, backwards.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class EndOfLineAction(javax.swing.text.TextAction):

    class_: typing.ClassVar[java.lang.Class]
    KEY_STROKE: typing.Final[javax.swing.KeyStroke]

    def __init__(self):
        ...


class SystemKeyBindings(java.lang.Object):
    """
    Default key strokes for System actions.
    """

    class_: typing.ClassVar[java.lang.Class]
    HELP_KEY1: typing.Final[javax.swing.KeyStroke]
    HELP_KEY2: typing.Final[javax.swing.KeyStroke]
    HELP_INFO_KEY: typing.Final[javax.swing.KeyStroke]
    CONTEXT_MENU_KEY1: typing.Final[javax.swing.KeyStroke]
    CONTEXT_MENU_KEY2: typing.Final[javax.swing.KeyStroke]
    FOCUS_NEXT_WINDOW_KEY: typing.Final[javax.swing.KeyStroke]
    FOCUS_PREVIOUS_WINDOW_KEY: typing.Final[javax.swing.KeyStroke]
    FOCUS_NEXT_COMPONENT_KEY: typing.Final[javax.swing.KeyStroke]
    FOCUS_PREVIOUS_COMPONENT_KEY: typing.Final[javax.swing.KeyStroke]
    FOCUS_INFO_KEY: typing.Final[javax.swing.KeyStroke]
    FOCUS_CYCLE_INFO_KEY: typing.Final[javax.swing.KeyStroke]
    UPDATE_KEY_BINDINGS_KEY: typing.Final[javax.swing.KeyStroke]
    COMPONENT_THEME_INFO_KEY: typing.Final[javax.swing.KeyStroke]
    ACTION_CHOOSER_KEY: typing.Final[javax.swing.KeyStroke]



__all__ = ["SelectBeginningOfLineAction", "SelectEndOfLineAction", "BeginningOfLineAction", "DeleteToEndOfWordAction", "DeleteToStartOfWordAction", "EndOfLineAction", "SystemKeyBindings"]
