package matchers

import "strings"

type Matcher interface {
	Match(conditionVal, resourceVal string) bool
}

type HasSuffix struct {}

func (hs HasSuffix) Match(conditionVal, resourceVal string) bool {
	return strings.HasSuffix(conditionVal, resourceVal)
}
