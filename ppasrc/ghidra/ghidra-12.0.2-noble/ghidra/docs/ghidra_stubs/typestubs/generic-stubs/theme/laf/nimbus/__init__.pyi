from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import javax.swing.plaf.nimbus # type: ignore


class SelectedTreePainter(javax.swing.plaf.nimbus.AbstractRegionPainter):
    """
    Nimbus selected tree row painter
    """

    @typing.type_check_only
    class MyPaintContext(javax.swing.plaf.nimbus.AbstractRegionPainter.PaintContext):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["SelectedTreePainter"]
