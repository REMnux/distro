from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import java.lang # type: ignore
import javax.swing # type: ignore


class GRadioButton(javax.swing.JRadioButton, docking.widgets.GComponent):
    """
    A :obj:`JRadioButton` that disables HTML rendering.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a blank radio button with HTML rendering disabled.
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Creates a radio button with the specified icon, with HTML rendering disabled.
        
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, a: javax.swing.Action):
        """
        Creates a radio button with properties taken from the specified Action, with HTML rendering
        disabled.
        
        :param javax.swing.Action a: :obj:`Action`
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a radio button with the specified icon and selected state, with HTML rendering 
        disabled.
        
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a radio button with the specified text, with HTML rendering disabled.
        
        :param java.lang.String or str text: string to be displayed by the label
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a radio button with the specified text and selected state, with HTML rendering
        disabled.
        
        :param java.lang.String or str text: string to be displayed by the label
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Creates a radio button that has the specified text and icon, with HTML rendering disabled.
        
        :param java.lang.String or str text: string to be displayed by the label
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a radio button that has the specified text, icon, and selected state, with
        HTML rendering disabled.
        
        :param java.lang.String or str text: string to be displayed by the label
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """


class BrowseButton(javax.swing.JButton):
    """
    A button meant to be used to show a chooser dialog.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "BrowseButton"
    TOOLTIP_TEXT: typing.Final = "Browse"

    def __init__(self):
        ...


class GButton(javax.swing.JButton):
    """
    A drop-in replacement for :obj:`JButton` that correctly installs a disabled icon.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        ...

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        ...



__all__ = ["GRadioButton", "BrowseButton", "GButton"]
