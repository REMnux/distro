from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.support
import ghidra.app.util.viewer.listingpanel
import java.lang # type: ignore


class MultiBlendedListingBackgroundColorModel(ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addModel(self, m: docking.widgets.fieldpanel.support.BackgroundColorModel):
        ...

    def removeModel(self, m: docking.widgets.fieldpanel.support.BackgroundColorModel):
        ...



__all__ = ["MultiBlendedListingBackgroundColorModel"]
