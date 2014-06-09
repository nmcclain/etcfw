package etcfw

import (
	"crypto/sha256"
	"encoding/json"
	"io"
)

///////////////////////
func AppendRuleIfMissing(ourRuleSet IptRuleSet, newRule IptRule) (IptRuleSet, error) {
	for _, rule := range ourRuleSet.Rules {
		if rule.Text == newRule.Text {
			return ourRuleSet, nil
		}
	}
	ourRuleSet.Rules = append(ourRuleSet.Rules, newRule)
	return ourRuleSet, nil
}

///////////////////////
func ModifyChainDefault(ourRuleSet IptRuleSet, chainName string, newChainDefault string) (IptRuleSet, error) {
	for chainNum, chain := range ourRuleSet.Chains {
		if chain.Chain == chainName {
			ourRuleSet.Chains[chainNum].ChainDefault = newChainDefault
		}
	}
	return ourRuleSet, nil
}

///////////////////////
func GetRuleSetFingerprint(ourRuleSet IptRuleSet) (string, error) {
	jsonRuleSet, err := json.Marshal(ourRuleSet)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	io.WriteString(h, string(jsonRuleSet))
	fingerprint := string(h.Sum(nil))
	return fingerprint, nil
}
