package parent

import "testing"

func TestSplitStreamName(t *testing.T) {
	cases := []struct {
		in         string
		base, name string
		ok         bool
	}{
		{"a.txt", "a.txt", "", true},
		{"a.txt::$DATA", "a.txt", "", true},
		{"a.txt:foo", "a.txt", "foo", true},
		{"a.txt:foo:$DATA", "a.txt", "foo", true},
		{"a.txt:foo:$data", "a.txt", "foo", true},
		{"a.txt:com.apple.metadata:_kMDItemUserTags:$DATA",
			"a.txt", "com.apple.metadata:_kMDItemUserTags", true},
		// Non-$DATA stream type → invalid.
		{"a.txt:foo:$INDEX_ALLOCATION", "", "", false},
		// Trailing colon with no type and no name → empty named stream
		// (treated as named, not default). Real clients don't send this.
		{"a.txt:", "a.txt", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		base, name, ok := splitStreamName(c.in)
		if base != c.base || name != c.name || ok != c.ok {
			t.Errorf("splitStreamName(%q) = (%q, %q, %v); want (%q, %q, %v)",
				c.in, base, name, ok, c.base, c.name, c.ok)
		}
	}
}
