package etcfw

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

///////////////////////
type IptRuleSet struct {
	TableName string
	Chains    []IptChain
	Rules     []IptRule
}
type IptRule struct {
	Text string
}
type IptChain struct {
	Chain        string
	ChainDefault string
}

///////////////////////
func LoadRulesFromIPT(tableName string) (IptRuleSet, error) {
	ourRuleSet := new(IptRuleSet)
	out, err := exec.Command("iptables-save", "-t", tableName).Output()
	if err != nil {
		return *ourRuleSet, err
	}
	lines := strings.Split(string(out), "\n")
	rules := make([]string, 0)
	for _, line := range lines {
		if len(line) < 1 {
			continue
		} else if line[0] == '#' {
			continue
		}
		rules = append(rules, line)
	}

	if rules[0] != "*"+tableName {
		return *ourRuleSet, errors.New("malformed iptables data - missing table name")
	}
	if rules[len(rules)-1] != "COMMIT" {
		return *ourRuleSet, errors.New("malformed iptables data - missing COMMIT")
	}
	iptRules := make([]IptRule, 0)
	iptChains := make([]IptChain, 0)

	for _, rule := range rules {
		if rule == "COMMIT" || rule == "*"+tableName {
			continue
		} else if rule[0] == ':' {
			re, _ := regexp.Compile(`^:(\S+)\s+(\S+)\s+`)
			matched := re.FindStringSubmatch(rule)
			iptChains = appendChainIfMissing(iptChains, matched[1], matched[2])
		} else if rule[0] == '-' && rule[1] == 'A' {
			newRule := new(IptRule)
			newRule.Text = rule
			iptRules = append(iptRules, *newRule)
		} else {
			return *ourRuleSet, errors.New(fmt.Sprintf("error parsing rule: %s", rule))
		}
	}
	ourRuleSet.TableName = tableName
	ourRuleSet.Rules = iptRules
	ourRuleSet.Chains = iptChains
	return *ourRuleSet, nil
}

///////////////////////
func SaveRulesToIPT(ourRuleSet IptRuleSet) error {
	ruleText := ""
	ruleText += fmt.Sprintf("*%s\n", ourRuleSet.TableName)
	for _, chain := range ourRuleSet.Chains {
		ruleText += fmt.Sprintf(":%s %s\n", chain.Chain, chain.ChainDefault)
	}
	for _, rule := range ourRuleSet.Rules {
		ruleText += fmt.Sprintf("%s\n", rule.Text)
	}
	ruleText += fmt.Sprintf("COMMIT\n")

	cmd := exec.Command("iptables-restore")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	//cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Start(); err != nil {
		return err
	}
	io.WriteString(stdin, ruleText)
	stdin.Close()
	cmd.Wait()

	return nil
}

///////////////////////
func appendChainIfMissing(iptChains []IptChain, newChainName string, newChainDefault string) []IptChain {
	for _, chain := range iptChains {
		if chain.Chain == newChainName {
			return iptChains
		}
	}
	newChain := new(IptChain)
	newChain.Chain = newChainName
	newChain.ChainDefault = newChainDefault
	return append(iptChains, *newChain)
}
