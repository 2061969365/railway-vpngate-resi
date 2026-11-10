package singbox

import "testing"

func TestRenderResiUsername(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		template string
		ttl      int
		session  string
		want     string
		wantErr  bool
	}{
		{"rotation ignores template", "u", "{user}-{session}", 0, "s", "u", false},
		{"sticky without session placeholder", "u", "{user}", 300, "s", "u", false},
		{"sticky renders", "u", "{user}-{session}-{ttl}", 300, "abc", "u-abc-300", false},
		{"escaped braces", "u", "{{{user}}}-{session}", 300, "abc", "{u}-abc", false},
		{"unknown placeholder", "u", "{user}-{session}-{zone}", 300, "abc", "", true},
		{"unterminated", "u", "{session}-{user", 300, "abc", "", true},
		{"stray closing brace", "u", "{user}-{session}}", 300, "abc", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderResiUsername(tc.user, tc.template, tc.ttl, tc.session)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
