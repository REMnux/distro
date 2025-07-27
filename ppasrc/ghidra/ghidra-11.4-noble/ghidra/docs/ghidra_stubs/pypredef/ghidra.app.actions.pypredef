from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.context
import java.lang # type: ignore
import javax.swing # type: ignore


class AbstractFindReferencesDataTypeAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Find References To"
    DEFAULT_KEY_STROKE: typing.Final[javax.swing.KeyStroke]


class AbstractFindReferencesToAddressAction(ghidra.app.context.NavigatableContextAction):
    """
    Only shows addresses to the code unit at the address for the current context.  This differs
    from the normal 'find references' action in that it will find references by inspecting 
    context for more information, potentially searching for more than just direct references to 
    the code unit at the current address.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Show References To Address"



__all__ = ["AbstractFindReferencesDataTypeAction", "AbstractFindReferencesToAddressAction"]
