from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import docking.widgets.indexedscrollpane
import ghidra.app.nav
import ghidra.app.services
import ghidra.app.util.viewer.listingpanel
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing.event # type: ignore


class AddressIndexMapConverter(AddressIndexMap):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addressIndexMap: AddressIndexMap, mapProgram: ghidra.program.model.listing.Program, otherProgram: ghidra.program.model.listing.Program):
        ...


class ScrollpaneAlignedHorizontalLayout(java.awt.LayoutManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, scroller: docking.widgets.indexedscrollpane.IndexedScrollPane):
        ...


class FieldNavigator(ghidra.app.services.ButtonPressedListener, ghidra.app.services.FieldMouseHandlerService):
    """
    Helper class to navigate to an address when user double clicks in a 
    Field.  This class will find :obj:`FieldMouseHandlerExtension`s by using the :obj:`ClassSearcher`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, navigatable: ghidra.app.nav.Navigatable):
        ...


class AddressIndexMap(java.lang.Object):
    """
    This class maps a set of address ranges into a contiguous set of indexes from 0 to the
    total size of the address set. This is used primarily by the listing panel to simplify the
    display and scrolling logic.
    
    Because of the nature of the listing display, not all addresses have displayable content.  For
    example, a closed data structure can consume thousands of addresses where only the first address
    has anything to display while the structure is closed.  This can cause poor scrollbar behavior.
    To fix this, a new method :meth:`removeUnviewableAddressRanges(AddressSet) <.removeUnviewableAddressRanges>` was added that
    removes those ranges from the index mapping, but the original addresses are also maintained for
    purposes of determining "gap" addresses (an address is a gap address if the original address set
    does not include its immediate predecessor.)  The original addresses are also used so that this
    index mapping can be reset and then given a different set of address ranges to remove as not viewable.
    (Useful for when data is open/closed or created/deleted)
    """

    class_: typing.ClassVar[java.lang.Class]
    PERCENT_DIVIDER: typing.ClassVar[java.math.BigInteger]
    DEFAULT_UNVIEWABLE_GAP_SIZE: typing.ClassVar[java.math.BigInteger]

    @typing.overload
    def __init__(self):
        """
        Constructs an empty AddressIndexMap
        """

    @typing.overload
    def __init__(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Constructs an AddressIndexMap for the given address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the address set to index.
        """

    def getAddress(self, index: java.math.BigInteger) -> ghidra.program.model.address.Address:
        """
        Returns the i'th address in the set.
        
        :param java.math.BigInteger index: the index of the address to retrieve.
        :return: the address associated with the given index
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressSet(self, sel: docking.widgets.fieldpanel.support.FieldSelection) -> ghidra.program.model.address.AddressSet:
        """
        Returns the Address set corresponding to the set of indexes
        
        :param docking.widgets.fieldpanel.support.FieldSelection sel: the FieldSelection containing the set of indexes to include.
        :return: the AddressSet for the given field selection.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getFieldSelection(self, set: ghidra.program.model.address.AddressSetView) -> docking.widgets.fieldpanel.support.FieldSelection:
        """
        Returns a FieldSelection containing the set of indexes represented by the
        given address set
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to convert into a set of indexes.
        :return: a FieldSelection for the given address set.
        :rtype: docking.widgets.fieldpanel.support.FieldSelection
        """

    def getIndex(self, addr: ghidra.program.model.address.Address) -> java.math.BigInteger:
        """
        Returns the index for the given address.  If the address is not mapped, null will be returned
        
        :param ghidra.program.model.address.Address addr: the address for which to retrieve the index.
        :return: the index associated with the given address.
        :rtype: java.math.BigInteger
        """

    def getIndexAtOrAfter(self, addr: ghidra.program.model.address.Address) -> java.math.BigInteger:
        """
        Returns the index for the given address.  If the address is not mapped, the result is
        defined as follows:
            if the address is less than the smallest address in the map, then null is returned
            if the address is greater than the largest address in the map, then a value one bigger than
                the index of the largest address in the map.
            if the address is in a "gap", then the index of the next largest address that is in the
                    map is returned.
        
        :param ghidra.program.model.address.Address addr: the address for which to retrieve the index.
        :return: the associated index for the given address or if there is none, then the index
                of then next address greater than the given address or null if there is none.
        :rtype: java.math.BigInteger
        """

    def getIndexCount(self) -> java.math.BigInteger:
        """
        Returns the total number of addresses
        
        :return: the number of addresses in the view
        :rtype: java.math.BigInteger
        """

    def getIndexedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the total set of addresses in this index mapping (not including those that have been closed)
        
        :return: the total set of addresses in this index mapping (not including those that have been closed)
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getMaxIndex(self, addr: ghidra.program.model.address.Address) -> java.math.BigInteger:
        """
        Returns the maximum address for the range containing the given address.
        
        :param ghidra.program.model.address.Address addr: the address to find its containing range's max address.
        :return: the maximum address for the range containing the given address.
        :rtype: java.math.BigInteger
        """

    def getMinIndex(self, addr: ghidra.program.model.address.Address) -> java.math.BigInteger:
        """
        Returns the minimum address for the range containing the given address.
        
        :param ghidra.program.model.address.Address addr: the address to find its containing range's min address.
        :return: the minimum address for the range containing the given address.
        :rtype: java.math.BigInteger
        """

    def getMiniumUnviewableGapSize(self) -> java.math.BigInteger:
        """
        Returns the suggested minimum size of address ranges that contain no viewable code units (i.e.
        collapsed data).  Ranges larger that this should be removed from the index mapping to get
        better scrollbar behavior. Currently this is 1% of the total viewed address space.
        
        :return: the suggested minimum size for a range of addresses with no viewable content.
        :rtype: java.math.BigInteger
        """

    def getOriginalAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the total set of addresses in this map include addresses that have been closed
        
        :return: the total set of addresses in the map including addresses that have been closed
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def isGapAddress(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if the given address is the first address after gap of missing addresses.
        
        :param ghidra.program.model.address.Address address: the address to check for being a gap address
        :return: true if the given address is the first address after gap of missing addresses.
        :rtype: bool
        """

    def isGapIndex(self, index: java.math.BigInteger) -> bool:
        """
        Returns true if address of the given index is not the successor of the
        previous index's address.
        
        :param java.math.BigInteger index: the index to test for gap in the address set.
        :return: true if the given index represents the first address after a gap in the address set.
        :rtype: bool
        """

    def removeUnviewableAddressRanges(self, addressSet: ghidra.program.model.address.AddressSet):
        """
        Removes the given addresses from the set of addresses that get mapped into indexes.  This
        is used to remove large number of addresses that are contained in closed data in order to
        make scrollbars scroll smoothly.
         
        
        The original address set is maintained to determine the gap addresses and also for resetting
        the index map to the entire set of addresses
        
        :param ghidra.program.model.address.AddressSet addressSet: the set of addresses to remove from the set of addresses that get mapped.
        """

    def reset(self) -> AddressIndexMap:
        """
        Resets the mapping to the entire original address set.
        """

    @property
    def gapIndex(self) -> jpype.JBoolean:
        ...

    @property
    def gapAddress(self) -> jpype.JBoolean:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def maxIndex(self) -> java.math.BigInteger:
        ...

    @property
    def indexAtOrAfter(self) -> java.math.BigInteger:
        ...

    @property
    def indexCount(self) -> java.math.BigInteger:
        ...

    @property
    def indexedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def index(self) -> java.math.BigInteger:
        ...

    @property
    def fieldSelection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @property
    def minIndex(self) -> java.math.BigInteger:
        ...

    @property
    def originalAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def miniumUnviewableGapSize(self) -> java.math.BigInteger:
        ...


class ScrollpanelResizeablePanelLayout(java.awt.LayoutManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, scroller: docking.widgets.indexedscrollpane.IndexedScrollPane):
        ...


class OpenCloseManager(java.lang.Object):
    """
    Manages the open/close state of structures and arrays at specific addresses.
    """

    @typing.type_check_only
    class NoProgressMonitor(ghidra.util.task.TaskMonitorAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addChangeListener(self, l: javax.swing.event.ChangeListener):
        """
        Adds a change listener to be notified when a location is open or closed.
        
        :param javax.swing.event.ChangeListener l: the listener to be notified.
        """

    @typing.overload
    def closeAllData(self, program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def closeAllData(self, data: ghidra.program.model.listing.Data, monitor: ghidra.util.task.TaskMonitor):
        ...

    def closeData(self, data: ghidra.program.model.listing.Data):
        """
        Marks the given data as open.  This method notifies listeners of changes.
        
        :param ghidra.program.model.listing.Data data: The data to open.
        """

    def getOpenIndex(self, address: ghidra.program.model.address.Address, path: jpype.JArray[jpype.JInt]) -> int:
        """
        Returns the index of the component that is open at the given address.
        
        :param ghidra.program.model.address.Address address: the address to find the open index.
        :param jpype.JArray[jpype.JInt] path: the component path.
        """

    @typing.overload
    def isOpen(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Tests if the data at the given address is open
        
        :param ghidra.program.model.address.Address address: the address to test if open
        """

    @typing.overload
    def isOpen(self, address: ghidra.program.model.address.Address, path: jpype.JArray[jpype.JInt]) -> bool:
        """
        Test is the data at the given address and component path is open
        
        :param ghidra.program.model.address.Address address: the address to test
        :param jpype.JArray[jpype.JInt] path: the component path to test.
        """

    @typing.overload
    def isOpen(self, data: ghidra.program.model.listing.Data) -> bool:
        ...

    @typing.overload
    def openAllData(self, program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def openAllData(self, data: ghidra.program.model.listing.Data, monitor: ghidra.util.task.TaskMonitor):
        ...

    def openData(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Marks the given data as open.  This method notifies listeners of changes.
        
        :param ghidra.program.model.listing.Data data: The data to open.
        :return: true if the data location was opened (false if already open or can't be opened)
        :rtype: bool
        """

    def removeChangeListener(self, l: javax.swing.event.ChangeListener):
        """
        Removes the listener.
        
        :param javax.swing.event.ChangeListener l: the listener to remove.
        """

    def toggleOpen(self, data: ghidra.program.model.listing.Data):
        ...

    @property
    def open(self) -> jpype.JBoolean:
        ...


class VerticalPixelAddressMapImpl(ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap):
    """
    Maps vertical pixel locations to layouts on the currently displayed screen.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, layouts: java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout], map: AddressIndexMap):
        """
        Constructor.
        
        :param java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout] layouts: the set of layouts that are currently visible on the screen
        :param AddressIndexMap map: the map containing the addresses by index
        """

    def getLayoutIndexSize(self, i: typing.Union[jpype.JInt, int]) -> int:
        ...

    @property
    def layoutIndexSize(self) -> jpype.JInt:
        ...


class AddressBasedIndexMapper(docking.widgets.fieldpanel.listener.IndexMapper):
    """
    Implementation of IndexMapper that uses an old and new AddressIndexMap to map indexes 
    when the AddressIndexMap changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, from_: AddressIndexMap, to: AddressIndexMap):
        ...



__all__ = ["AddressIndexMapConverter", "ScrollpaneAlignedHorizontalLayout", "FieldNavigator", "AddressIndexMap", "ScrollpanelResizeablePanelLayout", "OpenCloseManager", "VerticalPixelAddressMapImpl", "AddressBasedIndexMapper"]
