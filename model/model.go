// Package model provides business and other data.
package model

import (
	"math/rand/v2"
	"sync"
)

const (
	// StatusClientClosedConn is not declared in net/http.
	StatusClientClosedConn = 499
)

const (
	ErrSomethingWentWrong    Error = "something went wrong"
	ErrInvalidParam          Error = "invalid param"
	ErrInvalidUUID           Error = "invalid uuid"
	ErrHijackingNotSupported Error = "model: connection hijacking is not supported"
)

type Error string

func (e Error) Error() string {
	return string(e)
}

type Set[K comparable, V any] struct {
	mu  sync.RWMutex
	set map[K]V
}

func NewSet[K comparable, V any]() *Set[K, V] {
	return NewSetSize[K, V](0)
}

func NewSetSize[K comparable, V any](size int) *Set[K, V] {
	result := &Set[K, V]{
		set: make(map[K]V, size),
	}

	return result
}

func (s *Set[K, V]) Get(k K) (V, bool) {
	s.mu.RLock()
	v, ok := s.set[k]
	s.mu.RUnlock()

	return v, ok
}

func (s *Set[K, V]) Set(k K, v V) {
	s.mu.Lock()

	if s.set == nil {
		s.set = make(map[K]V)
	}

	s.set[k] = v
	s.mu.Unlock()
}

func (s *Set[K, V]) Remove(k K) {
	s.mu.Lock()
	delete(s.set, k)
	s.mu.Unlock()
}

func (s *Set[K, V]) Len() int {
	s.mu.RLock()
	l := len(s.set)
	s.mu.RUnlock()

	return l
}

func (s *Set[K, V]) Random() (V, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.set)
	if n == 0 {
		var v V
		return v, false
	}

	lim := rand.IntN(n)
	for k := range s.set {
		if lim == 0 {
			return s.set[k], true
		}

		lim--
	}

	// Unreachable.
	var v V

	return v, false
}

func (s *Set[K, V]) Keys() []K {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.set)
	if n == 0 {
		return nil
	}

	result := make([]K, 0, n)
	for k := range s.set {
		result = append(result, k)
	}

	return result
}

func (s *Set[K, V]) Values() []V {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.set)
	if n == 0 {
		return nil
	}

	result := make([]V, 0, n)
	for k := range s.set {
		result = append(result, s.set[k])
	}

	return result
}

// UnwrapErrs unwraps errs if it represents an unwrappable error.
//
// If errs can't be unwrapped, the result is nil.
func UnwrapErrs(errs error) []error {
	if jerr, ok := errs.(interface{ Unwrap() []error }); ok {
		return jerr.Unwrap()
	}

	return nil
}
