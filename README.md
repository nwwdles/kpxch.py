# `kpxch` - KeePassXC NaCl helper

Provides command line access to KeePassXC using keepassxc-proxy ([KeePassXC Protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md)).

It can retrieve a password, username and other fields (custom fields must be prefixed with `KPH:`).

```txt
usage: kpxch [-h] [-e] [-u] [-p] [-s] [-i] [-f] [-l] [--client ID]
             [--state FILE] [--socket PATH] [-d] [-j] [-F SH]
             [--field-prefixes] [--shell-escape] [-0] [--field-sep SEP]
             [--entry-sep SEP]
             url [url ...]

KeePassXC NaCl helper.

positional arguments:
  url                   url(s) to print credentials for

optional arguments:
  -h, --help            show this help message and exit
  -e, --entry           print entry name
  -u, --username        print username
  -p, --password        print password (default)
  -s, --string-fields   print string fields
  -i, --uuid            print entry uuid
  -f, --all-fields      print all fields
  -l, --all-entries     print all matched entries, not just the first one
  --client ID           set client id string used for association. defaults to
                        'kpxc-getter'
  --state FILE          set saved association state path. defaults to
                        '/home/${USER}/.local/share/kpxc-getter/kpxc-
                        getter.state'. if client id is set, filename defaults
                        to ${client}.state
  --socket PATH         set socket path. defaults to
                        '/run/user/1000/kpxc_server'
  -d, --debug           print debug info
  -j, --json            print response in json format
  -F SH, --eval SH      print in format suitable for eval (possible values:
                        bash, fish)
  --field-prefixes      prepend fields with a field prefix (N - entry name, U
                        - username, etc.)
  --shell-escape        escape quotes, spaces, variables
  -0, --null-delimited  separate entries and fields with '\0'
  --field-sep SEP       set separator for entry fields
  --entry-sep SEP       set separator for entries
```

## Examples

```sh
# get sudo by hostname
kpxch "kpxch://sudo-$(hostname)" | sudo -S true
# "kpxch://sudo-$(hostname)" is an arbitrary URL for an entry.
# I recommend putting all info into the path part and not the protocol
# because protocol part can be ignored (if you set a checkbox in the settings).

# get borg repository password and path
credentials=$(kpxch -u -p "kpxch://borg-$(hostname)")
BORG_REPO=$(echo "$credentials" | sed '1q;d')         # get first line
BORG_PASSPHRASE=$(echo "$credentials" | sed '2q;d')   # second line
```
