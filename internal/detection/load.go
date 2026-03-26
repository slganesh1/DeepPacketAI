package detection

import (
	"log"

	"DeepPacketAI/internal/storage"
)

// LoadUserRules fetches enabled user rules from the store and converts them
// to detection.Rule values. Errors in individual rules are logged and skipped.
func LoadUserRules(store storage.Store) []Rule {
	records, err := store.ListUserRules()
	if err != nil {
		log.Printf("detection: failed to load user rules: %v", err)
		return nil
	}

	var rules []Rule
	for _, rec := range records {
		if !rec.Enabled {
			continue
		}
		r, err := UserRuleFromJSON(rec.ID, rec.Name, rec.Description, rec.Protocol, rec.Severity, rec.ConditionJSON)
		if err != nil {
			log.Printf("detection: skipping rule %q: %v", rec.Name, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules
}
