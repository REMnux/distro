from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore
import java.lang # type: ignore


@typing.type_check_only
class NumberMenuKeyHandler(MenuKeyHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MenuKeyProcessor(java.lang.Object):
    """
    Handles the processing of key events while menus or popup menus are open.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def processMenuKeyEvent(event: java.awt.event.KeyEvent) -> bool:
        """
        Checks the given event to see if it has a registered action to perform while a menu is open.
        If a menu is open and a handler exists, the handler will be called.
        
        :param java.awt.event.KeyEvent event: the event to check
        :return: true if the event triggered a handler
        :rtype: bool
        """


@typing.type_check_only
class PageDownMenuKeyHandler(MenuKeyHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MenuKeyHandler(java.lang.Object):
    """
    The interface for work to be done on an open menu.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class HomeMenuKeyHandler(MenuKeyHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EndMenuKeyHandler(MenuKeyHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class PageUpMenuKeyHandler(MenuKeyHandler):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["NumberMenuKeyHandler", "MenuKeyProcessor", "PageDownMenuKeyHandler", "MenuKeyHandler", "HomeMenuKeyHandler", "EndMenuKeyHandler", "PageUpMenuKeyHandler"]
