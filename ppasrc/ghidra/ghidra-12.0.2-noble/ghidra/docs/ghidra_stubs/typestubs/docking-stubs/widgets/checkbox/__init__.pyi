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


class GHtmlCheckBox(javax.swing.JCheckBox, docking.widgets.GComponent):
    """
    A :obj:`JCheckBox` that allows HTML rendering.
     
    
    See also:
     
    +----------------------+----------------+-------------------------+
    |        Class         | HTML rendering |       Description       |
    +======================+================+=========================+
    |:obj:`GCheckBox`      |NO              |HTML disabled JCheckBox  |
    +----------------------+----------------+-------------------------+
    |:obj:`GHtmlCheckBox`  |YES             |HTML allowed JCheckBox   |
    +----------------------+----------------+-------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a check box with no text or icon, with HTML rendering allowed.
         
        
        See :meth:`JCheckBox.JCheckBox() <JCheckBox.JCheckBox>`
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Creates a check box with an icon, with HTML rendering allowed.
         
        
        See :meth:`JCheckBox.JCheckBox(Icon) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with an icon and initial selected state, with HTML rendering allowed.
         
        
        See :meth:`JCheckBox.JCheckBox(Icon, boolean) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a check box with the specified text, with HTML rendering allowed.
         
        
        See :meth:`JCheckBox.JCheckBox(String) <JCheckBox.JCheckBox>`
        
        :param java.lang.String or str text: text of the check box
        """

    @typing.overload
    def __init__(self, a: javax.swing.Action):
        """
        Creates a check box where properties are taken from the
        Action supplied, with HTML rendering allowed.
         
        
        See :meth:`JCheckBox.JCheckBox(Action) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Action a: ``Action`` used to specify the new check box
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with the specified text and initial selected state, with HTML
        rendering allowed.
        
        :param java.lang.String or str text: text of the check box.
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Creates a check box with the specified text and icon, with HTML rendering allowed.
        
        :param java.lang.String or str text: text of the check box
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with the specified text and icon and initial selected state,
        with HTML rendering allowed.
        
        :param java.lang.String or str text: text of the check box
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """


class GCheckBox(javax.swing.JCheckBox, docking.widgets.GComponent):
    """
    A :obj:`JCheckBox` that has HTML rendering disabled.
     
    
    See also:
     
    +----------------------+----------------+-------------------------+
    |        Class         | HTML rendering |       Description       |
    +======================+================+=========================+
    |:obj:`GCheckBox`      |NO              |HTML disabled JCheckBox  |
    +----------------------+----------------+-------------------------+
    |:obj:`GHtmlCheckBox`  |YES             |HTML allowed JCheckBox   |
    +----------------------+----------------+-------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a check box with no text or icon, with HTML rendering disabled.
         
        
        See :meth:`JCheckBox.JCheckBox() <JCheckBox.JCheckBox>`
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Creates a check box with an icon, with HTML rendering disabled.
         
        
        See :meth:`JCheckBox.JCheckBox(Icon) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with an icon and initial selected state, with HTML rendering disabled.
         
        
        See :meth:`JCheckBox.JCheckBox(Icon, boolean) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a check box with the specified text, with HTML rendering disabled.
         
        
        See :meth:`JCheckBox.JCheckBox(String) <JCheckBox.JCheckBox>`
        
        :param java.lang.String or str text: text of the check box
        """

    @typing.overload
    def __init__(self, a: javax.swing.Action):
        """
        Creates a check box where properties are taken from the
        Action supplied, with HTML rendering disabled.
         
        
        See :meth:`JCheckBox.JCheckBox(Action) <JCheckBox.JCheckBox>`
        
        :param javax.swing.Action a: ``Action`` used to specify the new check box
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with the specified text and initial selected state, with HTML
        rendering disabled.
        
        :param java.lang.String or str text: text of the check box.
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Creates a check box with the specified text and icon, with HTML rendering disabled.
        
        :param java.lang.String or str text: text of the check box
        :param javax.swing.Icon icon: image to display
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a check box with the specified text and icon and initial selected state,
        with HTML rendering disabled.
        
        :param java.lang.String or str text: text of the check box
        :param javax.swing.Icon icon: image to display
        :param jpype.JBoolean or bool selected: initial selection state, true means selected
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        See :meth:`JCheckBox.setText(String) <JCheckBox.setText>`.
         
        
        Overridden to warn about HTML text in non-HTML enabled checkbox.
        
        :param java.lang.String or str text: string this label will display
        """



__all__ = ["GHtmlCheckBox", "GCheckBox"]
