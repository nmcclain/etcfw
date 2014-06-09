package main

import (
	"etcfw/lib"
	"github.com/docopt/docopt-go"
	"log"
	"time"
)

var usage string = `etcfw: manage iptables with etcd

Usage:
  etcfw load [options] <etcd_key>
  etcfw save [options] <etcd_key>
  etcfw --version

Note: load is etcd->iptables, save is iptables->etcd.

Options:
  -s <update_secs>  Update frequency (seconds) [default: 300]. 
  -t <table>        Manage this table [default: filter].
  -e <etcd_url>     EtcD URL [default: http://127.0.0.1:4001].
  -v                Verbose output.
  -h, --help        Show this screen.
  --version         Show version.
`

///////////////////////
func main() {
	var err error

	args, err := docopt.Parse(usage, nil, true, "etcfw 0.1", false)
	if err != nil {
		log.Fatal(err)
	}
	verbose := args["-v"].(bool)
	etcdKey := args["<etcd_key>"].(string)
	iptTable := args["-t"].(string)
	etcdURL := args["-e"].(string)
	updateSecs, err := time.ParseDuration(args["-s"].(string) + "s")
	if err != nil {
		log.Fatal(err)
	} else if updateSecs < (500 * time.Millisecond) { // check yoself
		updateSecs = 500 * time.Millisecond
	}
	lastFingerprint := ""

	done := make(chan error)
	for {
		if args["load"].(bool) { // etcd -> IPTables
			go func() {
				if verbose {
					log.Printf("Loading iptables ruleset from etcd %s\n", etcdKey)
				}
				ruleSet, err := etcfw.LoadRulesFromEtcD(etcdURL, etcdKey)
				if err != nil {
					log.Fatal(err)
				}
				fingerprint, err := etcfw.GetRuleSetFingerprint(ruleSet)
				if err != nil {
					log.Fatal(err)
				}
				if fingerprint == lastFingerprint {
					if verbose {
						log.Printf("Skipping load to iptables - no changes in etcd\n")
					}
					done <- nil
					return
				} else {
					lastFingerprint = fingerprint
				}

				err = etcfw.SaveRulesToIPT(ruleSet)
				if err != nil {
					log.Fatal(err)
				}
				if verbose {
					log.Printf("Loaded iptables ruleset from etcd %s\n", etcdKey)
				}
				done <- nil
			}()

		} else if args["save"].(bool) { // IPTables -> etcd
			go func() {
				if verbose {
					log.Printf("Saving iptables %s ruleset to etcd %s\n", iptTable, etcdKey)
				}
				ruleSet, err := etcfw.LoadRulesFromIPT(iptTable)
				if err != nil {
					log.Fatal(err)
				}
				fingerprint, err := etcfw.GetRuleSetFingerprint(ruleSet)
				if err != nil {
					log.Fatal(err)
				}
				if fingerprint == lastFingerprint {
					if verbose {
						log.Printf("Skipping save to etcd - no changes in iptables\n")
					}
					done <- nil
					return
				} else {
					lastFingerprint = fingerprint
				}

				err = etcfw.SaveRulesToEtcD(ruleSet, etcdURL, etcdKey)
				if err != nil {
					log.Fatal(err)
				}
				if verbose {
					log.Printf("Saved iptables ruleset to etcd %s\n", etcdKey)
				}
				done <- nil
			}()
		}

		select {
		case <-done:
			if verbose {
				log.Printf("Sleeping %f seconds", updateSecs.Seconds())
			}
			time.Sleep(updateSecs)
		case <-time.After(10 * time.Second):
			log.Fatal("Operation timed out!")
		}
	}
}
