package fchan

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// This queue is based on the "Unbounded Channel" described here:
// https://github.com/google/fchan-go/blob/master/writeup/writeup.pdf

const (
	segmentSize = 64 * 1024
)

type segment struct {
	id   uint64
	next *segment
	data [segmentSize]elem
}

func (s *segment) getNext() *segment {
	next := loadSegmentPtr(&s.next)
	if next == nil {
		n := &segment{id: s.id + 1}
		if casSegmentPtr(&s.next, nil, n) {
			next = n
		} else {
			next = loadSegmentPtr(&s.next)
		}
	}
	return next
}

type poison struct{}

// elem.ptr is:
// - nil if neither a sender nor a receiver has written to it
// - *interface{} if a sender has written its value to it
// - *interface{} (whose concrete type is *waiter) if a receiver has written its
//   waiter to it
// - *interface{} (whose concrete type is poison) if a non-blocking receiver has
//   poisoned the element
type elem struct {
	ptr *interface{}
}

// loadInterface loads an interface value from e. It should ONLY be called by a
// receiver who knows that the only possible existing values are nil or an
// interface left by a sender.
func (e *elem) loadInterface() (interface{}, bool) {
	iface := loadInterfacePtr(&e.ptr)
	if iface == nil {
		return nil, false
	}
	return *iface, true
}

// loadWaiter loads an interface value from e. It should ONLY be called by a
// sender who has already run e.casInterface, and thus knows that e contains
// either a waiter or poison left by a receiver. If a waiter is found, that
// waiter and true are returned. Otherwise, false is returned.
func (e *elem) loadWaiter() (*waiter, bool) {
	iface := loadInterfacePtr(&e.ptr)
	w, ok := (*iface).(*waiter)
	if ok {
		return w, true
	}
	return nil, false
}

// casInterface performs a CAS operation on e, expecting the old value to be
// nil.
func (e *elem) casInterface(val interface{}) bool {
	box := new(interface{})
	*box = val
	return casInterfacePtr(&e.ptr, nil, box)
}

// casWaiter performs a CAS operation on e, expecting the old value to be nil.
func (e *elem) casWaiter(w *waiter) bool {
	box := new(interface{})
	*box = w
	return casInterfacePtr(&e.ptr, nil, box)
}

// casPoison attempts to CAS a poison value into e, expecting the old value to
// be nil.
func (e *elem) casPoison() bool {
	box := new(interface{})
	*box = poison{}
	return casInterfacePtr(&e.ptr, nil, box)
}

type waiter struct {
	val interface{}
	wg  sync.WaitGroup
}

func newWaiter() *waiter {
	w := new(waiter)
	w.wg.Add(1)
	return w
}

func (w *waiter) wait() interface{} {
	w.wg.Wait()
	return w.val
}

func (w *waiter) put(val interface{}) {
	w.val = val
	w.wg.Done()
}

type Chan struct {
	hseg, tseg *segment
	head, tail uint64
}

func NewUnbounded() *Chan {
	seg := new(segment)
	return &Chan{hseg: seg, tseg: seg}
}

// adjust adjusts segptr by bumping it one segment at a time until it finds the
// segment with the given id.
func adjust(segptr **segment, id uint64) *segment {
	seg := loadSegmentPtr(segptr)

	for id != seg.id {
		next := seg.getNext()

		// Try to bump seg to the next segment
		if casSegmentPtr(segptr, seg, next) {
			// If we succeed, great - go around the loop again.
			seg = next
		} else {
			// If we fail, then somebody beat us to it, so we'll steal whatever
			// progress they made by loading the new q.queue value and continuing from
			// there.
			seg = loadSegmentPtr(segptr)
		}
	}

	return seg
}

// find searches through the list of segments starting at seg until it finds a
// segment with the given id.
func find(seg *segment, id uint64) *segment {
	for id != seg.id {
		seg = seg.getNext()
	}
	return seg
}

func (c *Chan) Send(val interface{}) {
	for {
		tailSegID, _ := splitIndex(atomic.LoadUint64(&c.tail))
		queue := adjust(&c.tseg, tailSegID)
		segID, cellIdx := splitIndex(atomic.AddUint64(&c.tail, 1) - 1)
		seg := find(queue, segID)
		cell := &seg.data[cellIdx]
		if cell.casInterface(val) {
			return
		}
		w, ok := cell.loadWaiter()
		if ok {
			w.put(val)
			return
		}
	}
}

func (c *Chan) Receive() (val interface{}) {
	headSegID, _ := splitIndex(atomic.LoadUint64(&c.head))
	queue := adjust(&c.hseg, headSegID)
	segID, cellIdx := splitIndex(atomic.AddUint64(&c.head, 1) - 1)
	seg := find(queue, segID)
	cell := &seg.data[cellIdx]
	if val, ok := cell.loadInterface(); ok {
		return val
	}
	w := newWaiter()
	if cell.casWaiter(w) {
		return w.wait()
	}
	val, _ = cell.loadInterface()
	return val
}

func (c *Chan) TryReceive() (val interface{}, ok bool) {
	headSegID, _ := splitIndex(atomic.LoadUint64(&c.head))
	queue := adjust(&c.hseg, headSegID)
	segID, cellIdx := splitIndex(atomic.AddUint64(&c.head, 1) - 1)
	seg := find(queue, segID)
	cell := &seg.data[cellIdx]
	if val, ok := cell.loadInterface(); ok {
		return val, true
	}
	if cell.casPoison() {
		return nil, false
	}
	val, _ = cell.loadInterface()
	return val, true
}

func splitIndex(idx uint64) (seg, cell uint64) {
	return idx / segmentSize, idx % segmentSize
}

func loadSegmentPtr(seg **segment) *segment {
	sptr := (*unsafe.Pointer)(unsafe.Pointer(seg))
	return (*segment)(atomic.LoadPointer(sptr))
}

func casSegmentPtr(seg **segment, old, new *segment) bool {
	sptr := (*unsafe.Pointer)(unsafe.Pointer(seg))
	optr := unsafe.Pointer(old)
	nptr := unsafe.Pointer(new)
	return atomic.CompareAndSwapPointer(sptr, optr, nptr)
}

func loadInterfacePtr(iface **interface{}) *interface{} {
	iptr := (*unsafe.Pointer)(unsafe.Pointer(iface))
	return (*interface{})(atomic.LoadPointer(iptr))
}

func casInterfacePtr(iface **interface{}, old, new *interface{}) bool {
	iptr := (*unsafe.Pointer)(unsafe.Pointer(iface))
	optr := unsafe.Pointer(old)
	nptr := unsafe.Pointer(new)
	return atomic.CompareAndSwapPointer(iptr, optr, nptr)
}
