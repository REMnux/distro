from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore


E = typing.TypeVar("E")


class GComboBox(javax.swing.JComboBox[E], docking.widgets.GComponent, typing.Generic[E]):
    """
    A :obj:`JComboBox` that disables HTML rendering.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an empty combobox with a default data model.
         
        
        See :meth:`JComboBox.JComboBox() <JComboBox.JComboBox>`
        """

    @typing.overload
    def __init__(self, aModel: javax.swing.ComboBoxModel[E]):
        """
        Creates a combobox using the specified model.
         
        
        See :meth:`JComboBox.JComboBox(ComboBoxModel) <JComboBox.JComboBox>`
        
        :param javax.swing.ComboBoxModel[E] aModel: the :obj:`ComboBoxModel` of generic type ``E``
        """

    @typing.overload
    def __init__(self, items: jpype.JArray[E]):
        """
        Creates a combobox using the specified items.
         
        
        See :meth:`JComboBox.JComboBox(Object[]) <JComboBox.JComboBox>`
        
        :param jpype.JArray[E] items: array of objects of generic type ``E`` to insert into the combo box
        """

    @typing.overload
    def __init__(self, items: java.util.Vector[E]):
        """
        Creates a combobox using the specified items.
         
        
        See :meth:`JComboBox.JComboBox(Vector) <JComboBox.JComboBox>`
        
        :param java.util.Vector[E] items: a vector containing objects of generic type ``E`` to insert into the combo box
        """


class GhidraComboBox(javax.swing.JComboBox[E], docking.widgets.GComponent, typing.Generic[E]):
    """
    GhidraComboBox adds the following features:
    
     
    
    1) ActionListeners are only invoked when the <Enter> key is pressed within the text-field
    of the combo-box. In normal JComboBox case, the ActionListeners are notified when an item is
    selected from the list.
    
     
    
    2) Adds the auto-completion feature. As a user types in the field, the combo box suggest the
    nearest matching entry in the combo box model. This is enabled by default.
    
     
    
    It also fixes the following bug:
    
     
    
    A normal JComboBox has a problem (feature?) that if you have a dialog with a button and
    JComboBox and you edit the comboText field and then hit the button, the button sometimes does
    not work.
    
     
    
    When the combobox loses focus, and its text has changed, it generates an actionPerformed event
    as though the user pressed <Enter> in the combo text field.  This has a bizarre effect if
    you have added an actionPerformed listener to the combobox and in your callback you adjust the
    enablement state of the button that you pressed (which caused the text field to lose focus) in
    that you end up changing the button's internal state(by calling setEnabled(true or false)) in
    the middle of the button press.
    """

    @typing.type_check_only
    class PassThroughActionListener(java.awt.event.ActionListener):
        """
        Listener on the editor's JTextField that then calls any registered action
        listener on this combobox
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PassThroughKeyListener(java.awt.event.KeyListener):
        """
        Listener on the editor's JTextField that then calls any registered editor key
        listener on this combobox
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PassThroughDocumentListener(javax.swing.event.DocumentListener):
        """
        Listener on the editor's JTextField's document that then calls any registered document
        listener on this combobox
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatchingItemsDocumentListener(javax.swing.event.DocumentListener):
        """
        Listener to perform matching of items as the user types
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor.
        """

    @typing.overload
    def __init__(self, model: javax.swing.ComboBoxModel[E]):
        """
        Construct a new GhidraComboBox using the given model.
        
        :param javax.swing.ComboBoxModel[E] model: the model
        """

    @typing.overload
    def __init__(self, items: jpype.JArray[E]):
        """
        Construct a new GhidraComboBox and populate a default model with the given items.
        
        :param jpype.JArray[E] items: the items
        """

    @typing.overload
    def __init__(self, items: collections.abc.Sequence):
        """
        Construct a new GhidraComboBox and populate a default model with the given items.
        
        :param collections.abc.Sequence items: the items
        """

    def addDocumentListener(self, l: javax.swing.event.DocumentListener):
        """
        Adds a document listener to the editor component's document.
        
        :param javax.swing.event.DocumentListener l: the listener to add
        """

    def addEditorKeyListener(self, l: java.awt.event.KeyListener):
        """
        Adds a KeyListener to the combobox's editor component.
        
        :param java.awt.event.KeyListener l: the listener to add
        """

    @typing.overload
    def addToModel(self, item: E):
        """
        Adds the given item to the combobox's data model.
        
        :param E item: the item to add
        """

    @typing.overload
    def addToModel(self, items: collections.abc.Sequence):
        """
        Adds all the  given item to the combobox's data model.
        
        :param collections.abc.Sequence items: the item to add
        """

    def associateLabel(self, label: javax.swing.JLabel):
        """
        Convenience method for associating a label with the editor component.
        
        :param javax.swing.JLabel label: the label to associate
        """

    def clearModel(self):
        """
        Removes all the items from the combobox data model.
        """

    def containsItem(self, item: E) -> bool:
        """
        Returns true if the combobox contains the given item.
        
        :param E item: the item to check
        :return: true if the combobox contains the given item.
        :rtype: bool
        """

    def getText(self) -> str:
        """
        Returns the text in combobox's editor text component
        
        :return: the text in combobox's editor text component
        :rtype: str
        """

    def getTextField(self) -> javax.swing.JTextField:
        ...

    def removeDocumentListener(self, l: javax.swing.event.DocumentListener):
        """
        Removes a document listener from the editor component's document
        
        :param javax.swing.event.DocumentListener l: the listener to remove
        """

    def removeEditorKeyListener(self, l: java.awt.event.KeyListener):
        """
        Removes a KeyListener from the combobox's editor component.
        
        :param java.awt.event.KeyListener l: the listener to remove
        """

    def selectAll(self):
        """
        Selects the text in the text field editor used by this combo box.
        
        
        .. seealso::
        
            | :obj:`JTextField.selectAll()`
        """

    def setAutoCompleteEnabled(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        This enables or disables auto completion. When on, the combobox will attempt to auto-fill
        the input text box with drop-down items that start with the text entered. This behavior
        may not be desirable when the drop-down list is more than just a list of previously typed
        strings. Auto completion is on by default.
        
        :param jpype.JBoolean or bool enable: if true, auto completion is on, otherwise it is off.
        """

    @deprecated("use setColumns(int)")
    def setColumnCount(self, columnCount: typing.Union[jpype.JInt, int]):
        """
        Sets the size of the text field editor used by this combo box.
        
        :param jpype.JInt or int columnCount: The number of columns for the text field editor
        
        .. deprecated::
        
        use :meth:`setColumns(int) <.setColumns>`
        
        .. seealso::
        
            | :obj:`JTextField.setColumns(int)`
        """

    def setColumns(self, columns: typing.Union[jpype.JInt, int]):
        """
        Sets the number of column's in the editor's component (JTextField).
        
        :param jpype.JInt or int columns: the number of columns to show
        
        .. seealso::
        
            | :obj:`JTextField.setColumns(int)`
        """

    def setDocument(self, document: javax.swing.text.Document):
        """
        Sets document to be used by the combobox's editor component.
        
        :param javax.swing.text.Document document: the document to be set
        """

    def setEnterKeyForwarding(self, forwardEnter: typing.Union[jpype.JBoolean, bool]):
        """
        HACK ALERT:  By default, the JComboBoxUI forwards the <Enter> key actions to the root
        pane of the JComboBox's container (which is used primarily by any installed 'default
        button'). The problem is that the forwarding does not happen always.  In the case that the
        <Enter> key will trigger a selection in the combo box, the action is NOT forwarded.
         
        
        By default Ghidra disables the forwarding altogether, since most users of
        :obj:`GhidraComboBox` will add an action listener to handle <Enter> actions.
         
        
        To re-enable the default behavior, set the ``forwardEnter`` value to true.
        
        :param jpype.JBoolean or bool forwardEnter: true to enable default <Enter> key handling.
        """

    def setSelectionEnd(self, selectionEnd: typing.Union[jpype.JInt, int]):
        """
        Sets the selection end in the editor's text field.
        
        :param jpype.JInt or int selectionEnd: the end of the selection
        
        .. seealso::
        
            | :obj:`JTextField.setSelectionEnd(int)`
        """

    def setSelectionStart(self, selectionStart: typing.Union[jpype.JInt, int]):
        """
        Sets the selection start in the editor's text field.
        
        :param jpype.JInt or int selectionStart: the start of the selection
        
        .. seealso::
        
            | :obj:`JTextField.setSelectionStart(int)`
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text on the combobox's editor text component
        
        :param java.lang.String or str text: the text to set
        """

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def textField(self) -> javax.swing.JTextField:
        ...



__all__ = ["GComboBox", "GhidraComboBox"]
