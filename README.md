# kpxch

> KeePassXC Helper

Provides command line access to KeePassXC using [NaCl and keepassxc-proxy](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).

Currently it can retrieve passwords, usernames and other fields (custom fields must be prefixed with `KPH:` to be visible to kpxch).

Other parts of the protocol (link above) can also be implemented (I don't really plan to use them so I didn't add CLI args for them).

```txt
usage: kpxch [-h] [-e] [-u] [-p] [-s] [-i] [-f] [-l] [--client ID]
             [--state FILE] [--socket PATH] [-d] [-j] [--eval SH]
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
  -f, --full            print all entry fields
  -l, --all-entries     print all matched entries, not just the first one
  --client ID           set client id string used for association. defaults to
                        'kpxch'
  --state FILE          set saved association state path. defaults to
                        '${HOME}/.local/share/kpxch/kpxch.state'. if client id
                        is set and this argument isn't used, filename defaults
                        to ${clientId}.state
  --socket PATH         set socket path. defaults to
                        '/run/user/1000/kpxc_server'
  -d, --debug           print debug info
  -j, --json            print response in json format
  --eval SH             print in format suitable for eval (possible values:
                        bash, fish)
  --field-prefixes      prepend fields with a field prefix (N - entry name, U
                        - username, P - password, I - uuid, K - field key, V -
                        field value)
  --shell-escape        escape quotes, spaces, variables
  -0, --null-delimited  separate entries and fields with '\0'
  --field-sep SEP       set separator for entry fields
  --entry-sep SEP       set separator for entries
```

## Examples

Get sudo by hostname:

```sh
kpxch "kpxch://sudo-$(hostname)" | sudo -S true
```

Where `kpxch://sudo-$(hostname)` is an URL of your choice for the entry (`kpxch://` doesn't matter, entries can have `https://` or anything else for the protocol. Entries without a protocol in the URL may not work).

I recommend putting all relevant info that's needed to identify the entry into the path part and not the protocol because protocol part can be ignored if you set a checkbox in the KeePassXC settings.

Get borg repository password and path:

```sh
credentials=$(kpxch -u -p "kpxch://borg-$(hostname)")
BORG_REPO=$(echo "$credentials" | sed '1q;d')         # get first line
BORG_PASSPHRASE=$(echo "$credentials" | sed '2q;d')   # second line
```

Perhaps, a better way:

```sh
{
  read -r user
  read -r password
} < <(kpxch -u -p "https://something.com")
```
