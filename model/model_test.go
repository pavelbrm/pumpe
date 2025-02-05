package model

import (
	"errors"
	"testing"

	should "github.com/stretchr/testify/assert"
)

type testCase[G, E any] struct {
	name  string
	given G
	exp   E
}

func TestSet_Get(t *testing.T) {
	type tcGiven struct {
		set *Set[string, string]
		k   string
	}

	type tcExpected struct {
		v  string
		ok bool
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "empty_literal",
			given: tcGiven{
				set: &Set[string, string]{},
				k:   "k_01",
			},
		},

		{
			name: "empty_constructor",
			given: tcGiven{
				set: NewSet[string, string](),
				k:   "k_01",
			},
		},

		{
			name: "not_found",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
			},
		},

		{
			name: "found",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_01", "v_01")
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
			},
			exp: tcExpected{
				v:  "v_01",
				ok: true,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, ok := tc.given.set.Get(tc.given.k)
			should.Equal(t, tc.exp.ok, ok)
			should.Equal(t, tc.exp.v, actual)
		})
	}
}

func TestSet_Set(t *testing.T) {
	type tcGiven struct {
		set *Set[string, string]
		k   string
		v   string
	}

	tests := []testCase[tcGiven, string]{
		{
			name: "empty_literal",
			given: tcGiven{
				set: &Set[string, string]{},
				k:   "k_01",
				v:   "v_01",
			},
			exp: "v_01",
		},

		{
			name: "empty_constructor",
			given: tcGiven{
				set: NewSet[string, string](),
				k:   "k_01",
				v:   "v_01",
			},
			exp: "v_01",
		},

		{
			name: "set_new_value",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
				v: "v_01",
			},
			exp: "v_01",
		},

		{
			name: "overwrite",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_01", "v_01")
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
				v: "v_01_overwritten",
			},
			exp: "v_01_overwritten",
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.given.set.Set(tc.given.k, tc.given.v)

			actual, ok := tc.given.set.Get(tc.given.k)
			should.Equal(t, true, ok)
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestSet_Remove(t *testing.T) {
	type tcGiven struct {
		set *Set[string, string]
		k   string
	}

	type tcExpected struct {
		v  string
		ok bool
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "empty_literal",
			given: tcGiven{
				set: &Set[string, string]{},
				k:   "k_01",
			},
		},

		{
			name: "empty_constructor",
			given: tcGiven{
				set: NewSet[string, string](),
				k:   "k_01",
			},
		},

		{
			name: "not_found",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
			},
		},

		{
			name: "delete",
			given: tcGiven{
				set: func() *Set[string, string] {
					set := NewSet[string, string]()
					set.Set("k_01", "v_01")
					set.Set("k_02", "v_02")

					return set
				}(),
				k: "k_01",
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.given.set.Remove(tc.given.k)

			actual, ok := tc.given.set.Get(tc.given.k)
			should.Equal(t, tc.exp.ok, ok)
			should.Equal(t, tc.exp.v, actual)
		})
	}
}

func TestSet_Len(t *testing.T) {
	tests := []testCase[*Set[string, string], int]{
		{
			name:  "empty_literal",
			given: &Set[string, string]{},
		},

		{
			name:  "empty_constructor",
			given: NewSet[string, string](),
		},

		{
			name: "one",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")

				return set
			}(),
			exp: 1,
		},

		{
			name: "two",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")
				set.Set("k_02", "v_02")

				return set
			}(),
			exp: 2,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.Len()
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestSet_Random(t *testing.T) {
	tests := []testCase[*Set[string, string], bool]{
		{
			name:  "empty_literal",
			given: &Set[string, string]{},
		},

		{
			name:  "empty_constructor",
			given: NewSet[string, string](),
		},

		{
			name: "single_item",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")

				return set
			}(),
			exp: true,
		},

		{
			name: "multiple_items",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")
				set.Set("k_02", "v_02")
				set.Set("k_03", "v_03")

				return set
			}(),
			exp: true,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, ok := tc.given.Random()
			should.Equal(t, tc.exp, ok)

			if !tc.exp {
				return
			}

			should.Equal(t, true, actual != "")
		})
	}
}

func TestSet_Keys(t *testing.T) {
	tests := []testCase[*Set[string, string], []string]{
		{
			name:  "nil_nil",
			given: &Set[string, string]{},
		},

		{
			name:  "empty_nil",
			given: NewSet[string, string](),
		},

		{
			name: "valid",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")
				set.Set("k_02", "v_02")
				set.Set("k_03", "v_03")

				return set
			}(),
			exp: []string{"k_01", "k_02", "k_03"},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.Keys()
			should.ElementsMatch(t, tc.exp, actual)
		})
	}
}

func TestSet_Values(t *testing.T) {
	tests := []testCase[*Set[string, string], []string]{
		{
			name:  "nil_nil",
			given: &Set[string, string]{},
		},

		{
			name:  "empty_nil",
			given: NewSet[string, string](),
		},

		{
			name: "valid",
			given: func() *Set[string, string] {
				set := NewSet[string, string]()
				set.Set("k_01", "v_01")
				set.Set("k_02", "v_02")
				set.Set("k_03", "v_03")

				return set
			}(),
			exp: []string{"v_01", "v_02", "v_03"},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.Values()
			should.ElementsMatch(t, tc.exp, actual)
		})
	}
}

func TestUnwrapErrs(t *testing.T) {
	tests := []testCase[error, []error]{
		{
			name: "nil_nil",
		},

		{
			name:  "non_unwrappable",
			given: Error("something_went_wrong"),
		},

		{
			name:  "valid",
			given: errors.Join(Error("error_01"), Error("error_02")),
			exp:   []error{Error("error_01"), Error("error_02")},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := UnwrapErrs(tc.given)
			should.Equal(t, tc.exp, actual)
		})
	}
}
