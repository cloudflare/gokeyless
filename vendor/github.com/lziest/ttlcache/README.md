## TTLCAche - LRU cache with TTL
[![Build Status](https://travis-ci.org/lziest/ttlcache.svg?branch=master)](https://travis-ci.org/lziest/ttlcache)
[![Coverage Status](http://codecov.io/github/lziest/ttlcache/coverage.svg?branch=master)](http://codecov.io/github/lziest/ttlcache?branch=master)
[![GoDoc](https://godoc.org/github.com/lziest/ttlcache?status.png)](https://godoc.org/github.com/lziest/ttlcache)

TTLCache is based on the implementation design of golang's groupcache lru, with cache entry TTL control. A expired
cache entry is preferred for cache eviction. When there is no expired entry, LRU principle takes effect. Cache `Get`s don't affect cache entry TTL.

It is thread-safe by a simple mutex lock.
