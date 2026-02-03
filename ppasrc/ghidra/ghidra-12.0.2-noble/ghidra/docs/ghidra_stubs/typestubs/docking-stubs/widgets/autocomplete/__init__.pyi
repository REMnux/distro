from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


T = typing.TypeVar("T")


class AutocompletionListener(java.lang.Object, typing.Generic[T]):
    """
    A listener for autocompletion events.
    
    
    .. seealso::
    
        | :obj:`TextFieldAutocompleter`
    """

    class_: typing.ClassVar[java.lang.Class]

    def completionActivated(self, e: AutocompletionEvent[T]):
        """
        The user has activated a suggested item.
         
         
        
        This means the user has explicitly activate the item, i.e., pressed enter on or clicked the
        item.
        
        :param AutocompletionEvent[T] e: the event describing the activation
        """

    def completionSelected(self, ev: AutocompletionEvent[T]):
        """
        The user has selected a suggested item.
         
         
        
        This means the user has highlighted an item, but has *not* activated that item.
        
        :param AutocompletionEvent[T] ev: the event describing the selection
        """


class AutocompletionCellRenderer(javax.swing.ListCellRenderer[T], typing.Generic[T]):
    """
    This is a default list cell renderer for the :obj:`TextFieldAutocompleter` suitable for
    extension if a user wishes to customize it.
     
    Mostly, this just composes Swing's :obj:`DefaultListCellRenderer`, except it allows each
    suggested item to specify its own text, font, icon, foreground color, and background color. Of
    course, the display text may also use HTML tags for fine formatting.
    
    
    .. seealso::
    
        | :obj:`TextFieldAutocompleter`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: TextFieldAutocompleter[T]):
        """
        Create a renderer owned by the given autocompleter.
        
        :param TextFieldAutocompleter[T] owner: the autocompleter that uses (or will use) this renderer.
        """


class TextFieldAutocompleter(java.lang.Object, typing.Generic[T]):
    """
    An autocompleter that may be attached to one or more :obj:`JTextField`.
    
     
    
    Each autocompleter instance has one associated window (displaying the list of suggestions) and
    one associated model (generating the list of suggestions). Thus, the list can only be active on
    one of the attached text fields at a time. This is usually the desired behavior, and it allows
    for one autocompleter to be reused on many fields. Behavior is undefined when multiple
    autocompleters are attached to the same text field. More likely, you should implement a composite
    model if you wish to present completions from multiple models on a single text field.
    
     
    
    By default, the autocompleter is activated when the user presses CTRL-SPACE, at which point, the
    model is queried for possible suggestions. The completer gives the model all the text preceding
    the current field's caret. This behavior can be changed by overriding the
    :meth:`getPrefix(JTextField) <.getPrefix>` method. This may be useful, e.g., to obtain a prefix for the
    current word, rather than the full field contents, preceding the caret. The list is displayed
    such that its top-left corner is placed directly under the current field's caret. As the user
    continues typing, the suggestions are re-computed, and the list tracks with the caret. This
    positioning behavior can be modified by overriding the :meth:`getCompletionWindowPosition() <.getCompletionWindowPosition>`
    method. As a convenience, the :meth:`getCaretPositionOnScreen(JTextField) <.getCaretPositionOnScreen>` method is available
    to compute the default position.
    
     
    
    Whether or not the list is currently displayed, when the user presses CTRL-SPACE, if only one
    completion is possible, it is automatically activated. This logic is applied again and again,
    until either no suggestions are given, or more than one suggestion is given (or until the
    autocompleter detects an infinite loop). This behavior can by modified on an item-by-item basis
    by overriding the :meth:`getCompletionCanDefault(T) <.getCompletionCanDefault>` method.
    This same behavior can be activated by calling the :meth:`startCompletion(JTextField) <.startCompletion>` method,
    which may be useful, e.g., to bind a different key sequence to start autocompletion.
    
     
    
    The appearance of each item in the suggestion list can be modified by overriding the various
    ``getCompletion...`` methods. Note that it's possible for an item to be displayed one way,
    but cause the insertion of different text. In any case, it is best to ensure any modification
    produces an intuitive behavior.
    
     
    
    The simplest use case is to create a text field, create an autocompleter with a custom model, and
    then attach and show.
    
    ``JTextField field = new JTextField();AutocompletionModel<String> model = new AutocompletionModel<String>() {    &#64;Override    public Collection<String> computeCompletions(String text) {        // ... Populate the completion list based on the given prefix.    }}TextFieldAutocompleter<String> completer = new TextFieldAutocompleter<String>(model);completer.attachTo(field);// ... Add the field to, e.g., a dialog, and show.``
    """

    @typing.type_check_only
    class ResizeListener(java.awt.event.MouseAdapter):
        """
        A mouse listener that resizes the auto-completion list window
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyListener(java.awt.event.FocusListener, java.awt.event.KeyListener, javax.swing.event.DocumentListener, java.awt.event.MouseListener, javax.swing.event.CaretListener, javax.swing.event.ListSelectionListener):
        """
        A listener to handle all the callbacks
        """

        class_: typing.ClassVar[java.lang.Class]

        def fakeFocusGained(self, field: javax.swing.JTextField):
            ...


    class TextFieldAutocompleterDemo(java.lang.Object):
        """
        A demonstration of the autocompleter on a single text field.
        
         
        
        The autocompleter offers the tails from a list of strings that start with the text before the
        caret.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def main(args: jpype.JArray[java.lang.String]):
            ...


    class DualTextAutocompleterDemo(java.lang.Object):
        """
        A demonstration of the autocompleter on two linked text fields.
        
         
        
        This demo was designed to test whether the autocompleter and the :obj:`TextFieldLinker`
        could be composed correctly.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def main(args: jpype.JArray[java.lang.String]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: AutocompletionModel[T]):
        """
        Create a new autocompleter associated with the given model.
        
        :param AutocompletionModel[T] model: the model giving the suggestions.
        """

    def addAutocompletionListener(self, l: AutocompletionListener[T]):
        """
        Register the given auto-completion listener
        
        :param AutocompletionListener[T] l: the listener to register
        """

    def attachTo(self, field: javax.swing.JTextField) -> bool:
        """
        Attach the autocompleter to the given text field.
        
         
        
        If this method is never called, then the autocompleter can never appear.
        
        :param javax.swing.JTextField field: the field that will gain this autocompletion feature
        :return: true, if this field is not already attached
        :rtype: bool
        """

    def detachFrom(self, field: javax.swing.JTextField) -> bool:
        """
        Deprive the given field of this autocompleter.
        
        :param javax.swing.JTextField field: the field that will lose this autocompletion feature
        :return: true, if this field was actually attached
        :rtype: bool
        """

    def dispose(self):
        ...

    def flushUpdates(self):
        """
        If a completion list update is pending, run it immediately
        """

    def getAutocompletionListeners(self) -> jpype.JArray[AutocompletionListener[T]]:
        """
        Get all the registered auto-completion listeners
        
        :return: an array of registered listeners
        :rtype: jpype.JArray[AutocompletionListener[T]]
        """

    def getListeners(self, listenerType: java.lang.Class[T]) -> jpype.JArray[T]:
        """
        Get all registered listeners of the given type
        
        :param java.lang.Class[T] listenerType: the type of listeners to get
        :return: an array of registered listeners
        :rtype: jpype.JArray[T]
        """

    def getSuggestions(self) -> java.util.List[T]:
        """
        Get the list of suggestions as ordered on screen
        
        :return: an immutable copy of the list
        :rtype: java.util.List[T]
        """

    def isCompletionListVisible(self) -> bool:
        """
        Check if the completion list window is visible.
        
         
        
        If it is visible, this implies that the user is actively using the autocompleter.
        
        :return: true if shown, false if hidden.
        :rtype: bool
        """

    def removeAutocompletionListener(self, l: AutocompletionListener[T]):
        """
        Unregister the given auto-completion listener
        
        :param AutocompletionListener[T] l: the listener to unregister
        """

    def select(self, index: typing.Union[jpype.JInt, int]):
        """
        Cause the suggestion at the given index to be selected
        
        :param jpype.JInt or int index: the index of the selection
        """

    def selectFirst(self):
        """
        Select the first suggestion
        """

    def selectLast(self):
        """
        Select the last suggestion
        """

    def selectNext(self):
        """
        Cause the next suggestion to be selected, wrapping if applicable
        """

    def selectPrev(self):
        """
        Cause the previous suggestion to be selected, wrapping if applicable
        """

    def setCompletionListVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Show or hide the completion list window
        
        :param jpype.JBoolean or bool visible: true to show, false to hide
        """

    def startCompletion(self, field: javax.swing.JTextField):
        """
        Starts the autocompleter on the given text field.
        
         
        
        First, this repeatedly attempts auto-activation. When there are many suggestions, or when
        auto-activation is prevented (see :meth:`getCompletionCanDefault(T) <.getCompletionCanDefault>`), a list is displayed (usually below the caret) containing the
        suggestions given the fields current contents. The list remains open until either the user
        cancels it (usually via ESC) or the user activates a suggestion.
        
         
        
        **NOTE:** The text field must already be attached.
        
        :param javax.swing.JTextField field: the field on which to start autocompletion.
        """

    def updateDisplayLocation(self):
        """
        Recompute the display location and move with list window.
        
         
        
        This is useful, e.g., when the window containing the associated text field(s) moves.
        """

    def updateNow(self):
        """
        Update the completion list immediately
        """

    @property
    def listeners(self) -> jpype.JArray[T]:
        ...

    @property
    def autocompletionListeners(self) -> jpype.JArray[AutocompletionListener[T]]:
        ...

    @property
    def suggestions(self) -> java.util.List[T]:
        ...

    @property
    def completionListVisible(self) -> jpype.JBoolean:
        ...

    @completionListVisible.setter
    def completionListVisible(self, value: jpype.JBoolean):
        ...


class AutocompletionModel(java.lang.Object, typing.Generic[T]):
    """
    A model to generate the suggested completions, given a viable prefix.
    """

    class_: typing.ClassVar[java.lang.Class]

    def computeCompletions(self, text: typing.Union[java.lang.String, str]) -> java.util.Collection[T]:
        """
        Compute a collection of possible completions to the given text (prefix).
        
        :param java.lang.String or str text: the prefix, i.e., the text to the left of the user's caret.
        :return: a (possibly null or empty) list of suggested completions.
         
        NOTE: there is no requirement that the returned items actually start with the given prefix;
        however, by default, the displayed text for the suggested item is inserted at the caret,
        without changing the surrounding text.
        :rtype: java.util.Collection[T]
        """


class AutocompletionEvent(java.lang.Object, typing.Generic[T]):
    """
    An event related to autocompletion, usually a completion being activated by the user.
    
    
    .. seealso::
    
        | :obj:`TextFieldAutocompleter`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sel: T, field: javax.swing.JTextField):
        """
        Create a new event on the given selection and text field.
        
        :param T sel: the currently-selected (or activated) item.
        :param javax.swing.JTextField field: the field having focus at the time of the event.
        """

    def cancel(self):
        """
        Prevent the actual completion action from taking place.
         
        Further listeners may still process this event, though.
        """

    def consume(self):
        """
        Prevent this event from being further processed.
         
        The actual completion action will still be completed, though.
        """

    def getField(self) -> javax.swing.JTextField:
        """
        Get the field having focus at the time of the event.
         
        If the autocompleter is attached to multiple fields, this can be used to identify which
        field produced the event.
        
        :return: the focused field
        :rtype: javax.swing.JTextField
        """

    def getSelection(self) -> T:
        """
        Get the item that was selected at the time of the event.
         
        For activation, this is the activated suggestion.
        
        :return: the selected suggestion.
        :rtype: T
        """

    def isCancelled(self) -> bool:
        """
        Check if the actual completion action will be performed.
        
        :return: true if the completion action has been cancelled.
        :rtype: bool
        """

    def isConsumed(self) -> bool:
        """
        Check if this event has been consumed by an earlier listener.
        
        :return: true if the event has been consumed, i.e., should not be further processed.
        :rtype: bool
        """

    @property
    def consumed(self) -> jpype.JBoolean:
        ...

    @property
    def selection(self) -> T:
        ...

    @property
    def field(self) -> javax.swing.JTextField:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...



__all__ = ["AutocompletionListener", "AutocompletionCellRenderer", "TextFieldAutocompleter", "AutocompletionModel", "AutocompletionEvent"]
