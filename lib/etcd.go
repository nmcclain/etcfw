package etcfw

import (
	"encoding/json"
	"github.com/coreos/go-etcd/etcd"
)

///////////////////////
func LoadRulesFromEtcD(etcdURL string, etcdKey string) (IptRuleSet, error) {
	ourRuleSet := new(IptRuleSet)
	etc := etcd.NewClient([]string{etcdURL})
	result, err := etc.Get(etcdKey, false, false)
	if err != nil {
		return *ourRuleSet, err
	}
	if err := json.Unmarshal([]byte(result.Node.Value), &ourRuleSet); err != nil {
		return *ourRuleSet, err
	}
	return *ourRuleSet, nil
}

///////////////////////
func SaveRulesToEtcD(ourRuleSet IptRuleSet, etcdURL string, etcdKey string) error {
	etc := etcd.NewClient([]string{etcdURL})

	jsonRuleSet, err := json.Marshal(ourRuleSet)
	if err != nil {
		return err
	}

	_, err = etc.Set(etcdKey, string(jsonRuleSet), 0)
	if err != nil {
		return err
	}

	return nil
}
