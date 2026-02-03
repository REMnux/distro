from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.lang # type: ignore


class TextLayoutGraphics(java.awt.Graphics2D):
    """
    Graphics used to render copied text data.  This class is not a true graphics object, but is
    instead used to grab text being painted so that clients can later use that text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def flush(self):
        """
        Format text into a string for rendering.
        """

    def getBuffer(self) -> str:
        ...

    @property
    def buffer(self) -> java.lang.String:
        ...


@typing.type_check_only
class TextInfo(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["TextLayoutGraphics", "TextInfo"]
