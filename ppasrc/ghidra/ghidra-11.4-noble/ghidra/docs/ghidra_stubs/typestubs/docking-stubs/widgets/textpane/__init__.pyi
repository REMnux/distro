from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import javax.swing # type: ignore


class GHtmlTextPane(javax.swing.JTextPane):
    """
    A JTextPane for rendering HTML, as well as copying WYSIWYG text copying.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getSelectedText(self) -> str:
        """
        Overridden to allow copying HTML content in its display form, without formatting.  The
        default Java copy action will call this method.
        """

    @property
    def selectedText(self) -> java.lang.String:
        ...



__all__ = ["GHtmlTextPane"]
