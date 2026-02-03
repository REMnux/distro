from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import java.awt # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.text # type: ignore
import javax.swing.text.html # type: ignore


class AbstractHtmlLabel(javax.swing.JLabel, docking.widgets.GComponent, java.beans.PropertyChangeListener):
    """
    Base class for labels that render html using a custom rendering kit.
     
    
    This implementation uses custom html rendering.  This custom rendering allows for basic
    formatting while eliminating potentially unsafe html tags.  If for some reason this custom
    rendering is deficient, clients can instead use a standard Java :obj:`JLabel`.
     
    
    Clients do not need to prefix label text with "<html>", as is required for a standard
    JLabel.
    """

    @typing.type_check_only
    class GHtmlLabelEditorKit(javax.swing.text.html.HTMLEditorKit):

        class_: typing.ClassVar[java.lang.Class]

        def createDefaultDocument(self, defaultFont: java.awt.Font, foreground: java.awt.Color) -> javax.swing.text.Document:
            ...


    @typing.type_check_only
    class GHtmlLabelDocument(javax.swing.text.html.HTMLDocument):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ss: javax.swing.text.html.StyleSheet, font: java.awt.Font, bg: java.awt.Color):
            ...


    @typing.type_check_only
    class GHtmlLabelReader(javax.swing.text.html.HTMLDocument.HTMLReader):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, htmlDocument: javax.swing.text.html.HTMLDocument, offset: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class ViewWrapper(javax.swing.text.View):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getOriginalText(self) -> str:
        """
        Returns the original text of the label.
         
        
        The :meth:`getText() <.getText>` method for this class can return a value that is missing the leading
        <html> tag.
        
        :return: text of this label
        :rtype: str
        """

    @property
    def originalText(self) -> java.lang.String:
        ...


class GIconLabel(GLabel, docking.widgets.GComponent):
    """
    A label that only contains an image and no text.
     
    
    See also:
     
    +---------------------------+--------------+----------------+--------------------------------------------+
    |           Class           | Mutable text | HTML rendering |                Description                 |
    +===========================+==============+================+============================================+
    |:obj:`GLabel`              |Immutable     |NO              |Non-html unchangeable label                 |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDLabel`             |Mutable       |NO              |Non-html changeable label                   |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlLabel`          |Immutable     |YES             |Html unchangeable label                     |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDHtmlLabel`         |Mutable       |YES             |Html changeable label                       |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GIconLabel`          |N/A           |NO              |Label that only has an icon image, no text  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |Other components of note:  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GCheckBox`           |              |NO              |Non-html checkbox                           |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlCheckBox`       |              |YES             |Html checkbox                               |
    +---------------------------+--------------+----------------+--------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a immutable label with no image and no text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel() <JLabel.JLabel>`.
        """

    @typing.overload
    def __init__(self, image: javax.swing.Icon):
        """
        Creates a immutable label with the specified image, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(Icon) <JLabel.JLabel>`.
        
        :param javax.swing.Icon image: icon to be displayed by the label
        """

    @typing.overload
    def __init__(self, image: javax.swing.Icon, horizontalAlignment: typing.Union[jpype.JInt, int]):
        """
        Creates a immutable label with the specified image and horizontal alignment, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(Icon, int) <JLabel.JLabel>`.
        
        :param javax.swing.Icon image: icon to be displayed by the label
        :param jpype.JInt or int horizontalAlignment: One of
                :obj:`SwingConstants.LEFT`,
                :obj:`SwingConstants.CENTER`,
                :obj:`SwingConstants.RIGHT`,
                :obj:`SwingConstants.LEADING`,
                :obj:`SwingConstants.TRAILING`
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        This is a half-way method of turning this label into an immutable instance.
         
        
        If the user has a type of "GIconLabel", they will see the deprecated warning on calls to setText().
         
        
        If there are calls to setText() with any non-null or non-empty value, a
        warning will be printed in the log.
        
        :param java.lang.String or str text: string this label will NOT display
        """


class GDLabel(javax.swing.JLabel, docking.widgets.GComponent):
    """
    A 'dynamic' label (the text can be changed), with HTML rendering disabled.
     
    
    See also:
     
    +---------------------------+--------------+----------------+--------------------------------------------+
    |           Class           | Mutable text | HTML rendering |                Description                 |
    +===========================+==============+================+============================================+
    |:obj:`GLabel`              |Immutable     |NO              |Non-html unchangeable label                 |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDLabel`             |Mutable       |NO              |Non-html changeable label                   |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlLabel`          |Immutable     |YES             |Html unchangeable label                     |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDHtmlLabel`         |Mutable       |YES             |Html changeable label                       |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GIconLabel`          |N/A           |NO              |Label that only has an icon image, no text  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |Other components of note:  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GCheckBox`           |              |NO              |Non-html checkbox                           |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlCheckBox`       |              |YES             |Html checkbox                               |
    +---------------------------+--------------+----------------+--------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a label with no image and no text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel() <JLabel.JLabel>`.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a label with the specified text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], horizontalAlignment: typing.Union[jpype.JInt, int]):
        """
        Creates a label with the specified text and horizontal alignment, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String, int) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        :param jpype.JInt or int horizontalAlignment: One of
                :obj:`SwingConstants.LEFT`,
                :obj:`SwingConstants.CENTER`,
                :obj:`SwingConstants.RIGHT`,
                :obj:`SwingConstants.LEADING`,
                :obj:`SwingConstants.TRAILING`
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, horizontalAlignment: typing.Union[jpype.JInt, int]):
        """
        Creates a label with the specified text, image and horizontal alignment, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String, Icon, int) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        :param javax.swing.Icon icon: image to be displayed by the label
        :param jpype.JInt or int horizontalAlignment: One of
                :obj:`SwingConstants.LEFT`,
                :obj:`SwingConstants.CENTER`,
                :obj:`SwingConstants.RIGHT`,
                :obj:`SwingConstants.LEADING`,
                :obj:`SwingConstants.TRAILING`
        """


class GLabel(javax.swing.JLabel, docking.widgets.GComponent):
    """
    An immutable label (the text can NOT be changed), with HTML rendering disabled.
     
    
    See also:
     
    +---------------------------+--------------+----------------+--------------------------------------------+
    |           Class           | Mutable text | HTML rendering |                Description                 |
    +===========================+==============+================+============================================+
    |:obj:`GLabel`              |Immutable     |NO              |Non-html unchangeable label                 |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDLabel`             |Mutable       |NO              |Non-html changeable label                   |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlLabel`          |Immutable     |YES             |Html unchangeable label                     |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDHtmlLabel`         |Mutable       |YES             |Html changeable label                       |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GIconLabel`          |N/A           |NO              |Label that only has an icon image, no text  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |Other components of note:  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GCheckBox`           |              |NO              |Non-html checkbox                           |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlCheckBox`       |              |YES             |Html checkbox                               |
    +---------------------------+--------------+----------------+--------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a immutable label with no image and no text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel() <JLabel.JLabel>`.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a immutable label with the specified text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], horizontalAlignment: typing.Union[jpype.JInt, int]):
        """
        Creates a immutable label with the specified text and horizontal alignment, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String, int) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        :param jpype.JInt or int horizontalAlignment: One of
                :obj:`SwingConstants.LEFT`,
                :obj:`SwingConstants.CENTER`,
                :obj:`SwingConstants.RIGHT`,
                :obj:`SwingConstants.LEADING`,
                :obj:`SwingConstants.TRAILING`
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon, horizontalAlignment: typing.Union[jpype.JInt, int]):
        """
        Creates a immutable label with the specified text, image and horizontal alignment, 
        with HTML rendering disabled.
         
        
        See :meth:`JLabel.JLabel(String, Icon, int) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: non-html string to be displayed by the label
        :param javax.swing.Icon icon: image to be displayed by the label
        :param jpype.JInt or int horizontalAlignment: One of
                :obj:`SwingConstants.LEFT`,
                :obj:`SwingConstants.CENTER`,
                :obj:`SwingConstants.RIGHT`,
                :obj:`SwingConstants.LEADING`,
                :obj:`SwingConstants.TRAILING`
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        This is a half-way method of turning this label into an immutable instance.
         
        
        If the user has a type of "GLabel", they will see the deprecated warning on calls to setText().
         
        
        If there are calls to setText() after the initial value has been set by the constructor, a
        warning will be printed in the log.
        
        :param java.lang.String or str text: string this label will display
        """


class GDHtmlLabel(AbstractHtmlLabel):
    """
    A 'dynamic' label (the text can be changed), with HTML rendering allowed.
     
    
    Clients do not need to prefix label text with "<html>", as is required for a standard
    JLabel.
     
    
    See also:
     
    +---------------------------+--------------+----------------+--------------------------------------------+
    |           Class           | Mutable text | HTML rendering |                Description                 |
    +===========================+==============+================+============================================+
    |:obj:`GLabel`              |Immutable     |NO              |Non-html unchangeable label                 |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDLabel`             |Mutable       |NO              |Non-html changeable label                   |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlLabel`          |Immutable     |YES             |Html unchangeable label                     |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDHtmlLabel`         |Mutable       |YES             |Html changeable label                       |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GIconLabel`          |N/A           |NO              |Label that only has an icon image, no text  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |Other components of note:  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GCheckBox`           |              |NO              |Non-html checkbox                           |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlCheckBox`       |              |YES             |Html checkbox                               |
    +---------------------------+--------------+----------------+--------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a label with no image and no text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering allowed.
         
        
        See :meth:`JLabel.JLabel() <JLabel.JLabel>`.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a label with the specified text, with :obj:`SwingConstants.LEADING` horizontal
        alignment, with HTML rendering allowed.
         
        
        See :meth:`JLabel.JLabel(String) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: string to be displayed by the label
        """


class GHtmlLabel(AbstractHtmlLabel):
    """
    An immutable label (the text can NOT be changed), with HTML rendering allowed.
     
    
    Clients do not need to prefix label text with "<html>", as is required for a standard
    JLabel.
    
     
    
    See also:
     
    +---------------------------+--------------+----------------+--------------------------------------------+
    |           Class           | Mutable text | HTML rendering |                Description                 |
    +===========================+==============+================+============================================+
    |:obj:`GLabel`              |Immutable     |NO              |Non-html unchangeable label                 |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDLabel`             |Mutable       |NO              |Non-html changeable label                   |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlLabel`          |Immutable     |YES             |Html unchangeable label                     |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GDHtmlLabel`         |Mutable       |YES             |Html changeable label                       |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GIconLabel`          |N/A           |NO              |Label that only has an icon image, no text  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |Other components of note:  |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GCheckBox`           |              |NO              |Non-html checkbox                           |
    +---------------------------+--------------+----------------+--------------------------------------------+
    |:obj:`GHtmlCheckBox`       |              |YES             |Html checkbox                               |
    +---------------------------+--------------+----------------+--------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a immutable label with no image and no text, with :obj:`SwingConstants.LEADING`
        horizontal alignment, with HTML rendering allowed.
         
        
        See :meth:`JLabel.JLabel() <JLabel.JLabel>`.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Creates a immutable label with the specified text, with :obj:`SwingConstants.LEADING`
        horizontal alignment, with HTML rendering allowed.
         
        
        See :meth:`JLabel.JLabel(String) <JLabel.JLabel>`.
        
        :param java.lang.String or str text: string to be displayed by the label
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        This is a half-way method of turning this label into an immutable instance.
         
        
        If the user has a type of "GHtmlLabel", they will see the deprecated warning on calls to
        setText().
         
        
        If there are calls to setText() after the initial value has been set by the  constructor, a
        warning will be printed in the log.
        
        :param java.lang.String or str text: string this label will display
        """



__all__ = ["AbstractHtmlLabel", "GIconLabel", "GDLabel", "GLabel", "GDHtmlLabel", "GHtmlLabel"]
