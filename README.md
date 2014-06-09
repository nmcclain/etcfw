etcfw
=====
# manage iptables with etcd

## Save filter table to EtcD:
```
  etcfw save firewalls/myhost
```

## Load filter table from EtcD:
```
  etcfw load firewalls/myhost
```

## Usage:
```
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
```
