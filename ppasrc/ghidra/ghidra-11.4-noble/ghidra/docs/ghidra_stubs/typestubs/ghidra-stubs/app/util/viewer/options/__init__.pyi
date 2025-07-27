from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.label
import generic.theme
import ghidra.framework.options
import java.awt # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class ScreenElement(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getColor(self) -> java.awt.Color:
        ...

    def getColorOptionName(self) -> str:
        ...

    def getDefaultColor(self) -> generic.theme.GColor:
        ...

    def getName(self) -> str:
        ...

    def getStyle(self) -> int:
        ...

    def getStyleOptionName(self) -> str:
        ...

    def getThemeColorId(self) -> str:
        ...

    def setColor(self, color: java.awt.Color):
        ...

    def setStyle(self, style: typing.Union[jpype.JInt, int]):
        ...

    @property
    def defaultColor(self) -> generic.theme.GColor:
        ...

    @property
    def colorOptionName(self) -> java.lang.String:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @color.setter
    def color(self, value: java.awt.Color):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def themeColorId(self) -> java.lang.String:
        ...

    @property
    def styleOptionName(self) -> java.lang.String:
        ...

    @property
    def style(self) -> jpype.JInt:
        ...

    @style.setter
    def style(self, value: jpype.JInt):
        ...


class ListingDisplayOptionsEditor(ghidra.framework.options.OptionsEditor):
    """
    Class for editing Listing display properties.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_FONT_ID: typing.Final = "font.listing.base"

    def __init__(self, options: ghidra.framework.options.Options):
        """
        Constructs a new ListingDisplayOptionsEditor.
        
        :param ghidra.framework.options.Options options: the options object to edit
        """

    def isResizable(self) -> bool:
        """
        Returns true if this component has "good" resizing behavior.  Components
        that do not have this property will be placed in a scrolled pane.
        
        :return: true if resizable
        :rtype: bool
        """

    @property
    def resizable(self) -> jpype.JBoolean:
        ...


class OptionsGui(javax.swing.JPanel):
    """
    Class for displaying and manipulating field colors and fonts.
    """

    @typing.type_check_only
    class FontRenderer(docking.widgets.label.GDLabel, javax.swing.ListCellRenderer[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SimpleLayoutModel(docking.widgets.fieldpanel.LayoutModel):
        """
        Simple layoutModel to be used for the preview panel.
        """

        class_: typing.ClassVar[java.lang.Class]

        def getLayout(self, index: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.Layout:
            ...

        @property
        def layout(self) -> docking.widgets.fieldpanel.Layout:
            ...


    @typing.type_check_only
    class LayoutBuilder(java.lang.Object):
        """
        Class to create the layouts for the preview panel.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScreenElementTextField(docking.widgets.fieldpanel.field.ClippingTextField):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    BACKGROUND: typing.Final[ScreenElement]
    COMMENT_AUTO: typing.Final[ScreenElement]
    ADDRESS: typing.Final[ScreenElement]
    BAD_REF_ADDR: typing.Final[ScreenElement]
    BYTES: typing.Final[ScreenElement]
    CONSTANT: typing.Final[ScreenElement]
    LABELS_UNREFD: typing.Final[ScreenElement]
    ENTRY_POINT: typing.Final[ScreenElement]
    COMMENT_EOL: typing.Final[ScreenElement]
    EXT_REF_RESOLVED: typing.Final[ScreenElement]
    EXT_REF_UNRESOLVED: typing.Final[ScreenElement]
    FIELD_NAME: typing.Final[ScreenElement]
    FUN_CALL_FIXUP: typing.Final[ScreenElement]
    FUN_NAME: typing.Final[ScreenElement]
    FUN_PARAMS: typing.Final[ScreenElement]
    FUN_TAG: typing.Final[ScreenElement]
    FUN_AUTO_PARAMS: typing.Final[ScreenElement]
    FUN_RET_TYPE: typing.Final[ScreenElement]
    COMMENT_REPEATABLE: typing.Final[ScreenElement]
    COMMENT_REF_REPEAT: typing.Final[ScreenElement]
    LABELS_LOCAL: typing.Final[ScreenElement]
    MNEMONIC: typing.Final[ScreenElement]
    MNEMONIC_OVERRIDE: typing.Final[ScreenElement]
    MNEMONIC_UNIMPL: typing.Final[ScreenElement]
    FLOW_ARROW_ACTIVE: typing.Final[ScreenElement]
    FLOW_ARROW_NON_ACTIVE: typing.Final[ScreenElement]
    FLOW_ARROW_SELECTED: typing.Final[ScreenElement]
    LABELS_PRIMARY: typing.Final[ScreenElement]
    LABELS_NON_PRIMARY: typing.Final[ScreenElement]
    COMMENT_PLATE: typing.Final[ScreenElement]
    COMMENT_POST: typing.Final[ScreenElement]
    COMMENT_PRE: typing.Final[ScreenElement]
    SEPARATOR: typing.Final[ScreenElement]
    VARIABLE: typing.Final[ScreenElement]
    PARAMETER_CUSTOM: typing.Final[ScreenElement]
    PARAMETER_DYNAMIC: typing.Final[ScreenElement]
    XREF: typing.Final[ScreenElement]
    XREF_OFFCUT: typing.Final[ScreenElement]
    XREF_READ: typing.Final[ScreenElement]
    XREF_WRITE: typing.Final[ScreenElement]
    XREF_OTHER: typing.Final[ScreenElement]
    REGISTERS: typing.Final[ScreenElement]
    UNDERLINE: typing.Final[ScreenElement]
    PCODE_LINE_LABEL: typing.Final[ScreenElement]
    PCODE_ADDR_SPACE: typing.Final[ScreenElement]
    PCODE_RAW_VARNODE: typing.Final[ScreenElement]
    PCODE_USEROP: typing.Final[ScreenElement]

    def __init__(self, font: java.awt.Font, listener: java.beans.PropertyChangeListener):
        """
        Constructor
        
        :param java.awt.Font font: the base font for the fields.
        :param java.beans.PropertyChangeListener listener: the listener to be notified when options change.
        """

    def getBaseFont(self) -> java.awt.Font:
        ...

    def setBaseFont(self, font: java.awt.Font):
        ...

    def updateDisplay(self):
        """
        Regenerates the fields for the sample text panel.
        """

    @property
    def baseFont(self) -> java.awt.Font:
        ...

    @baseFont.setter
    def baseFont(self, value: java.awt.Font):
        ...



__all__ = ["ScreenElement", "ListingDisplayOptionsEditor", "OptionsGui"]
