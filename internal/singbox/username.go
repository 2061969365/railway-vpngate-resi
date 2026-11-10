package singbox

import (
	"fmt"
	"strconv"
	"strings"
)

// ResiTemplatePlaceholders are the only placeholders a residential username
// template may use.
var ResiTemplatePlaceholders = []string{"user", "session", "ttl"}

// RenderResiUsername renders the gateway username for rotation or sticky mode.
//
// Rotation (ttl <= 0) returns the plain user and never appends a session
// parameter. Sticky mode only renders when the template really carries
// {session}; otherwise rotation is kept rather than guessing a provider
// format. Unknown placeholders raise an error without echoing the rendered
// string (it may contain account material).
func RenderResiUsername(user, template string, ttl int, sessionID string) (string, error) {
	if ttl <= 0 {
		return user, nil
	}
	text := strings.TrimSpace(template)
	if !strings.Contains(text, "{session}") {
		return user, nil
	}
	var builder strings.Builder
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '{':
			if index+1 < len(text) && text[index+1] == '{' {
				builder.WriteByte('{')
				index++
				continue
			}
			end := strings.IndexByte(text[index+1:], '}')
			if end < 0 {
				return "", invalidTemplateError()
			}
			name := text[index+1 : index+1+end]
			switch name {
			case "user":
				builder.WriteString(user)
			case "session":
				builder.WriteString(sessionID)
			case "ttl":
				builder.WriteString(strconv.Itoa(ttl))
			default:
				return "", fmt.Errorf(
					"RESI_USER_TEMPLATE uses an unsupported placeholder {%s}; allowed: %s",
					name, placeholderList())
			}
			index += 1 + end
		case '}':
			if index+1 < len(text) && text[index+1] == '}' {
				builder.WriteByte('}')
				index++
				continue
			}
			return "", invalidTemplateError()
		default:
			builder.WriteByte(text[index])
		}
	}
	return builder.String(), nil
}

func invalidTemplateError() error {
	return fmt.Errorf("RESI_USER_TEMPLATE has an invalid format; allowed: %s", placeholderList())
}

func placeholderList() string {
	parts := make([]string, 0, len(ResiTemplatePlaceholders))
	for _, name := range ResiTemplatePlaceholders {
		parts = append(parts, "{"+name+"}")
	}
	return strings.Join(parts, ", ")
}
