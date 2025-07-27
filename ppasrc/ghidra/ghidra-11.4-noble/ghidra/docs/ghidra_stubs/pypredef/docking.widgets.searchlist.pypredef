from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.list
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


T = typing.TypeVar("T")


class SearchListModel(javax.swing.ListModel[SearchListEntry[T]], typing.Generic[T]):
    """
    Interface for the model for :obj:`SearchList`. It is an extension of a JList's model to add
    the ability to group items into categories.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Clean up any resources held by the model
        """

    def getCategories(self) -> java.util.List[java.lang.String]:
        """
        Returns the list of categories in the order they were added to the model
        
        :return: the list of categories in the order they were added to the model
        :rtype: java.util.List[java.lang.String]
        """

    def setFilter(self, filter: java.util.function.BiPredicate[T, java.lang.String]):
        """
        Sets the filter for the model data to display.
        
        :param java.util.function.BiPredicate[T, java.lang.String] filter: the BiPredicate for the model data to display which will filter based on
        the item and its category
        """

    @property
    def categories(self) -> java.util.List[java.lang.String]:
        ...


class SearchListEntry(java.lang.Record, typing.Generic[T]):
    """
    An record to hold the list item and additional information needed to properly render the item.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, value: T, category: typing.Union[java.lang.String, str], showCategory: typing.Union[jpype.JBoolean, bool], drawSeparator: typing.Union[jpype.JBoolean, bool]):
        ...

    def category(self) -> str:
        ...

    def drawSeparator(self) -> bool:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def showCategory(self) -> bool:
        ...

    def toString(self) -> str:
        ...

    def value(self) -> T:
        ...


class DefaultSearchListModel(javax.swing.AbstractListModel[SearchListEntry[T]], SearchListModel[T], typing.Generic[T]):
    """
    Default implementation of the :obj:`SearchListModel`. Since this model's primary purpose is 
    to also implement the :obj:`ListModel`, this class extends the AbstractListModel.
    This model's primary type is T, but it implements the list model on ``SearchListEntry<T>``
    to provide more information for the custom rendering that groups items into categories.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, category: typing.Union[java.lang.String, str], items: java.util.List[T]):
        """
        Adds the list of items to the given category. If the category already exists, these items
        will be added to any items already associated with that cateogry.
        
        :param java.lang.String or str category: the category to add the items to
        :param java.util.List[T] items: the list of items to add to and be associated with the given category
        """

    def clearData(self):
        """
        Removes all categories and items from this model
        """

    def fireDataChanged(self):
        """
        Provides a way to kick the list display to update.
        """

    def getAllItems(self) -> java.util.List[SearchListEntry[T]]:
        """
        Returns a list of all item entries regardless of the current filter.
        
        :return: a list of all item entries
        :rtype: java.util.List[SearchListEntry[T]]
        """

    def getDisplayedItems(self) -> java.util.List[SearchListEntry[T]]:
        """
        Returns a list of all displayed item entries (only ones matching the current filter).
        
        :return: a list of all display item entries
        :rtype: java.util.List[SearchListEntry[T]]
        """

    @property
    def allItems(self) -> java.util.List[SearchListEntry[T]]:
        ...

    @property
    def displayedItems(self) -> java.util.List[SearchListEntry[T]]:
        ...


class SearchList(javax.swing.JPanel, typing.Generic[T]):
    """
    Component for displaying and selecting from a filterable list of items that are grouped into
    categories. Similar to a JList, but with filtering and grouping.
    """

    @typing.type_check_only
    class SearchListRenderer(javax.swing.ListCellRenderer[SearchListEntry[T]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultItemRenderer(docking.widgets.list.GListCellRenderer[SearchListEntry[T]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchListDataListener(javax.swing.event.ListDataListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TextFieldKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ListKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchListDocumentListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultFilter(java.util.function.BiPredicate[T, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: SearchListModel[T], chosenItemCallback: java.util.function.BiConsumer[T, java.lang.String]):
        """
        Construct a new SearchList given a model and an chosen item callback.
        
        :param SearchListModel[T] model: the model containing the group list items
        :param java.util.function.BiConsumer[T, java.lang.String] chosenItemCallback: the callback to be notified when an item is chosen (enter key 
        pressed)
        """

    def chooseItem(self):
        ...

    def dispose(self):
        """
        Disposes the component and clears all the model data
        """

    def getFilterField(self) -> javax.swing.JTextField:
        ...

    def getFilterText(self) -> str:
        """
        Returns the current filter text
        
        :return: the current filter text
        :rtype: str
        """

    def getModel(self) -> SearchListModel[T]:
        """
        Returns the search list model.
        
        :return: the model
        :rtype: SearchListModel[T]
        """

    def getSelectedItem(self) -> T:
        """
        Gets the currently selected item.
        
        :return: the currently selected item.
        :rtype: T
        """

    def setDisplayNameFunction(self, nameFunction: java.util.function.BiFunction[T, java.lang.String, java.lang.String]):
        ...

    def setFilterText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the current filter text
        
        :param java.lang.String or str text: the text to set as the current filter
        """

    def setInitialSelection(self):
        """
        Resets the selection to the first element
        """

    def setItemRenderer(self, itemRenderer: javax.swing.ListCellRenderer[SearchListEntry[T]]):
        """
        Sets a custom sub-renderer for displaying list items. Note: this renderer is only used to
        render the item, not the category.
        
        :param javax.swing.ListCellRenderer[SearchListEntry[T]] itemRenderer: the sub_renderer for rendering the list items, but not the entire line
        which includes the category.
        """

    def setMouseHoverSelection(self):
        ...

    def setSelectedItem(self, t: T):
        ...

    def setSelectionCallback(self, consumer: java.util.function.Consumer[T]):
        """
        Sets a consumer to be notified whenever the selected item changes.
        
        :param java.util.function.Consumer[T] consumer: the consumer to be notified whenever the selected item changes.
        """

    def setShowCategories(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets an option to display categories in the list or not.
        
        :param jpype.JBoolean or bool b: true to show categories, false to not shoe them
        """

    def setSingleClickMode(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets an option for the list to respond to either double or single mouse clicks. By default,
        it responds to a double click.
        
        :param jpype.JBoolean or bool b: true for single click mode, false for double click mode
        """

    @property
    def selectedItem(self) -> T:
        ...

    @selectedItem.setter
    def selectedItem(self, value: T):
        ...

    @property
    def model(self) -> SearchListModel[T]:
        ...

    @property
    def filterText(self) -> java.lang.String:
        ...

    @filterText.setter
    def filterText(self, value: java.lang.String):
        ...

    @property
    def filterField(self) -> javax.swing.JTextField:
        ...



__all__ = ["SearchListModel", "SearchListEntry", "DefaultSearchListModel", "SearchList"]
