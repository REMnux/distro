from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.help
import generic.theme
import java.lang # type: ignore


class GhidraHelpService(docking.help.HelpManager):
    """
    Ghidra's help service.   This class knows how to find help for the various modules that 
    make up Ghidra.
    """

    @typing.type_check_only
    class HelpThemeListener(generic.theme.ThemeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def install():
        ...



__all__ = ["GhidraHelpService"]
