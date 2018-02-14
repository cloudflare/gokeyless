package ttlcache

import (
	"container/list"
	"sync"
	"time"
)

type EvictCallback func(key string, value interface{})

// LRU cache with ttl
type LRU struct {
	size       int           // cache size
	defaultTTL time.Duration // default cache entry TTL
	table      map[string]*list.Element
	items      *list.List
	onEvict    EvictCallback
	sync.RWMutex
}

// entry holds a cache entry
type entry struct {
	key    string
	value  interface{}
	expiry time.Time
}

// NewLRU returns a new LRU cache.
func NewLRU(size int, defaultTTL time.Duration, onEvict EvictCallback) *LRU {
	if size <= 0 {
		return nil
	}

	c := &LRU{
		size:       size,
		defaultTTL: defaultTTL,
		table:      make(map[string]*list.Element),
		onEvict:    onEvict,
		items:      list.New(),
	}

	return c
}

// Set sets a value with key into the cache. Returns a boolean value indicating whether
// a new element is created.
func (c *LRU) Set(key string, value interface{}, ttl time.Duration) bool {
	if c == nil {
		return false
	}
	c.Lock()
	defer c.Unlock()
	checkTTL := func() {
		c.Lock()
		defer c.Unlock()
		if elem, ok := c.table[key]; ok {
			item := elem.Value.(*entry)
			if time.Now().After(item.expiry) {
				c.items.MoveToBack(elem)
			}
		}
	}

	if ttl == 0 {
		ttl = c.defaultTTL
	}
	expiry := time.Now().Add(ttl)
	time.AfterFunc(ttl, checkTTL)

	// check collision
	if elem, ok := c.table[key]; ok {
		c.items.MoveToFront(elem)
		item := elem.Value.(*entry)
		item.value = value
		item.expiry = expiry
		return false
	}

	// Add new
	e := &entry{key, value, expiry}
	elem := c.items.PushFront(e)
	c.table[key] = elem

	// Maintain the cache size
	// Note that we can't guarantee a stale cache entry is removed instead of a non-stale least referenced one.
	// Since we can't make sure the timer which moves stale elements around always fire in time before Add()
	if c.items.Len() > c.size {
		c.removeLastElement()
	}

	return true
}

// Get returns the cached value index by key. Return an additional boolean value indicating whether
// the returned element is stale
func (c *LRU) Get(key string) (value interface{}, stale bool) {
	if c == nil {
		return nil, false
	}
	c.Lock()
	defer c.Unlock()
	elem, ok := c.table[key]
	if ok {
		item := elem.Value.(*entry)
		stale = time.Now().After(item.expiry)
		if !stale {
			// moves non-stale elements to the front.
			c.items.MoveToFront(elem)
		} else {
			// moves non-stale elements to the back as evication candidate.
			c.items.MoveToBack(elem)
		}
		return item.value, stale

	}

	return nil, false
}

// Remove removes the element cached by key. Return a boolean value for whether a value is deleted.
func (c *LRU) Remove(key string) bool {
	if c == nil {
		return false
	}
	c.Lock()
	defer c.Unlock()
	elem, ok := c.table[key]
	if ok {
		c.removeElement(elem)
		return true
	}
	return false
}

func (c *LRU) removeElement(elem *list.Element) {
	c.items.Remove(elem)
	item := elem.Value.(*entry)
	delete(c.table, item.key)
	if c.onEvict != nil {
		c.onEvict(item.key, item.value)
	}
}

func (c *LRU) removeLastElement() {
	elem := c.items.Back()
	if elem != nil {
		c.removeElement(elem)
	}

}
