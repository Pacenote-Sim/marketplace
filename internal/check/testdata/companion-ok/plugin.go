// Package companionok is a well-behaved companion: it imports what the policy
// allows and dials nothing.
package companionok

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Lap is what it posts.
type Lap struct {
	Number int `json:"lap"`
}

// Body renders a lap for its plugin's route, with a link to the docs on its page.
func Body(ctx context.Context, lap int) (string, http.Header, error) {
	if ctx == nil {
		return "", nil, fmt.Errorf("no context")
	}
	b, err := json.Marshal(Lap{Number: lap})
	if err != nil {
		return "", nil, fmt.Errorf("marshal: %w", err)
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	page := strings.Join([]string{"<a href=\"https://www.pacenote.tech/docs/\">docs</a>", string(b)}, "\n")
	return page, h, nil
}
