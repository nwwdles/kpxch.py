#!/usr/bin/env python3
#
# The MIT License (MIT)
#
# Copyright (c) 2019 cupnoodles
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import pysodium
import json
import os
import base64
import socket
import logging
import argparse
import shlex


DEFAULT_SOCKET_PATH = os.path.join(os.getenv("XDG_RUNTIME_DIR"), "kpxc_server")
DEFAULT_CLIENT_ID = "kpxch"
DEFAULT_STATE_FILE = os.path.join(
    os.getenv("XDG_DATA_HOME"), "kpxch", DEFAULT_CLIENT_ID + ".state"
)

# region utils


def encode(val: bytes) -> str:
    return base64.b64encode(val).decode()


def decode(val: bytes) -> str:
    return base64.b64decode(val)


def get_nonce(prev_nonce: bytes = None):
    """Increment nonce or generate a new one"""
    if prev_nonce:
        return increment_nonce(prev_nonce)
    else:
        return pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)


def increment_nonce(nonce: bytes) -> bytes:
    # from shadowsocks under void license
    out = list(nonce)
    c = 1
    i = 0
    for i in range(pysodium.crypto_box_NONCEBYTES):
        c += nonce[i]
        out[i] = c & 0xFF
        c >>= 8
    return bytes(out)


def verify_expected_nonce(old_nonce: bytes, new_nonce: bytes):
    expected_nonce = increment_nonce(old_nonce)
    assert new_nonce == expected_nonce


# endregion

# region output


def make_field(value, shell_escape, prefix=None, shell_var=None, eval_format=None):
    if shell_var:
        if eval_format == "fish":
            return "set -l " + shell_var + " " + shlex.quote(value)
        else:
            return shell_var + "=" + shlex.quote(value)

    if shell_escape:
        value = shlex.quote(value)
    if prefix:
        value = prefix + value
    return value


def show_entry(entry: dict, args, entry_index=None):
    # TODO: move to arguments
    # var_format = args.var_format
    field_prefixes = args.field_prefixes
    shell_escape = args.shell_escape
    eval_format = args.eval_format
    null_delimited = args.null_delimited
    user_field_separator = args.user_field_separator
    user_entry_separator = args.user_entry_separator

    if eval_format:
        field_separator = "; "
        entry_separator = "\n"
    elif null_delimited:
        field_separator = "\0"
        entry_separator = "\0"
    else:
        field_separator = "\n"
        entry_separator = "\n"

    if user_field_separator:
        field_separator = user_field_separator
    if user_entry_separator:
        entry_separator = user_entry_separator

    to_print = []

    def add_field(value, field_prefix, eval_var):
        if not field_prefixes:
            field_prefix = None
        if not eval_format:
            eval_var = None
        else:
            if entry_index:
                eval_var = str(entry_index) + eval_var
            eval_var = "KPXC" + eval_var
        to_print.append(
            make_field(value, shell_escape, field_prefix, eval_var, eval_format)
        )

    if args.show_name or args.show_all:
        add_field(entry["name"], "N", "NAME")
    if args.show_username or args.show_all:
        add_field(entry["login"], "U", "LOGIN")
    if args.show_password or args.show_all:
        add_field(entry["password"], "P", "PASSWORD")
    if args.show_uuid or args.show_all:
        add_field(entry["uuid"], "I", "UUID")
    if args.show_stringfields or args.show_all:
        for string_field in entry["stringFields"]:
            for field_num, key in enumerate(string_field.keys()):
                add_field(key, "K", "KEY" + str(field_num))
                add_field(string_field[key], "V", "FIELD" + str(field_num))

    # if no fields were selected, default to password field
    if not to_print:
        add_field(entry["password"], "P", "PASSWORD")

    # finally, print
    for field in to_print:
        print(field, end=field_separator)

    print("", end=entry_separator)


# endregion


class Association:
    """Keeps the association state and loads/saves it to file.
    
    Association state consists of public/private/identifier keys
    and database ID."""

    def __init__(self):
        self.filename = None
        self.public_key = None
        self.private_key = None
        self.id_key = None
        self.db_id = None

    def load(self, filename=DEFAULT_STATE_FILE):
        """Load association info from the file or generate new info."""

        self.filename = filename

        try:
            with open(self.filename, "r") as f:
                logging.info("Loading keypairs.")
                data = json.load(f)
                self.private_key = decode(data["private_key"])
                self.public_key = decode(data["public_key"])
                self.id_key = decode(data["id_key"])
                self.db_id = data["db_id"]  # known only after association
        except FileNotFoundError as e:
            logging.info("Generating new keypairs.")
            self.public_key, self.private_key, self.id_key = self.generate()
        return self

    def save(self):
        """Save association info to file."""

        parentdir = os.path.dirname(self.filename)
        if not os.path.exists(parentdir):
            os.makedirs(parentdir)
        with open(self.filename, "w") as f:
            data = {
                "private_key": encode(self.private_key),
                "public_key": encode(self.public_key),
                "id_key": encode(self.id_key),
                "db_id": (self.db_id),
            }
            json.dump(data, f)

    @classmethod
    def generate(cls) -> (bytes, bytes, bytes):
        """Generate new keypair and ID key.
        
        They should be saved to file using Association.save()
        unless we want to reassociate again next time."""

        public_key, private_key = pysodium.crypto_kx_keypair()
        id_key = pysodium.randombytes(pysodium.crypto_box_PUBLICKEYBYTES)
        return public_key, private_key, id_key


class SocketConnection:
    def __init__(self):
        self.sock_timeout = None
        self.sock_buffer_size = None
        self.sock = None

    def connect(self, socket_path, timeout: int, buffer_size: int):
        """Initialize and connect to keepassxc-proxy socket."""

        # close old socket if present
        if self.sock:
            self.sock.close()

        self.sock_timeout = timeout
        self.sock_buffer_size = buffer_size
        self.socket_path = socket_path

        self.sock = self.init_sock(socket_path, timeout, buffer_size)

        return self

    @classmethod
    def init_sock(cls, socket_path: str, timeout: int, buffer_size: int) -> socket:
        """Connect to keepassxc-proxy socket."""

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)

        try:
            sock.connect(str(socket_path))
        except socket.error as message:
            sock.close()
            raise Exception(f"Could not connect to socket at {socket_path}")
        return sock

    def send_request(self, request: dict) -> dict:
        """Send request and get response json."""

        try:
            request = json.dumps(request)
            logging.debug("Request: " + str(request))
            self.sock.send(request.encode())
        except socket.error:
            return json.dumps({})

        try:
            resp, server = self.sock.recvfrom(self.sock_buffer_size)
            logging.debug("Response: " + str(resp.decode()))
            return json.loads(resp)
        except socket.timeout:
            logging.warning("Socket timeout.")
            return json.dumps({})


class Connection:
    def __init__(self, clientid=DEFAULT_CLIENT_ID, filename=DEFAULT_STATE_FILE):
        self.filename = filename
        self.clientid = clientid

        self.nonce = get_nonce()
        self.server_key = None

        self.association = Association().load(filename)
        self.socket_connection = SocketConnection()

    def connect(
        self,
        socket_path=DEFAULT_SOCKET_PATH,
        timeout: int = 60,
        buffer_size: int = 1024 * 1024,
    ):
        """Initialize and connect to keepassxc-proxy socket."""

        self.socket_connection.connect(socket_path, timeout, buffer_size)
        self.server_key = self.change_public_keys()
        self.reassociate()

        return self

    def get_private_key(self):
        return self.association.private_key

    def get_public_key(self):
        return self.association.public_key

    def get_id_key(self):
        return self.association.id_key

    def get_db_id(self):
        return self.association.db_id

    def set_db_id(self, db_id):
        self.association.db_id = db_id

    def save(self):
        self.association.save()

    def send_request(self, request: dict) -> dict:
        """Send request and get response json."""
        return self.socket_connection.send_request(request)

    # region REQUESTS
    #

    def send_message_request(self, msg: dict) -> (bytes, dict):
        """Send request with a message and get decoded response json."""

        action = msg["action"]
        msg = json.dumps(msg)
        encm = pysodium.crypto_box(
            msg.encode(), self.nonce, self.server_key, self.get_private_key()
        )
        request = {
            "action": action,
            "nonce": encode(self.nonce),
            "message": encode(encm),
            "clientID": self.clientid,
        }
        logging.debug("Sending message: " + str(msg))

        response = self.send_request(request)
        return self.decode_message(response)

    def decode_message(self, response: dict) -> (bytes, dict):
        """Decode response message.
        
        Also verifies the received/expected nonce."""

        try:
            nonce = decode(response["nonce"])
            msg_response = decode(response["message"])
            msg_response = pysodium.crypto_box_open(
                msg_response, nonce, self.server_key, self.get_private_key()
            ).decode()
            msg_response = json.loads(msg_response)
            logging.debug("Response message: " + str(msg_response))
            verify_expected_nonce(self.nonce, nonce)
            self.nonce = get_nonce(nonce)

        except KeyError as e:
            logging.warning("Invalid response: " + str(response))
            msg_response = {}

        return msg_response

    def change_public_keys(self) -> (bytes, dict):
        """Exchange public keys between database (server) and the client.
        
        This should be ran first. Received server key is used for all
        further communications."""

        request = {
            "action": "change-public-keys",
            "nonce": encode(self.nonce),
            "publicKey": encode(self.get_public_key()),
            "clientID": self.clientid,
        }
        response = self.send_request(request)
        nonce = decode(response["nonce"])
        server_key = decode(response["publicKey"])
        verify_expected_nonce(self.nonce, nonce)
        self.nonce = get_nonce(nonce)

        return server_key

    def generate_password(self) -> (bytes, dict):
        """Ask the server to generate a random password.
        
        Response contains a password."""

        request = {
            "action": "generate-password",
            "nonce": encode(self.nonce),
            "clientID": self.clientid,
        }
        response = self.send_request(request)
        return self.decode_message(response)

    # endregion

    # region MESSAGES

    def get_databasehash(self) -> (bytes, dict):
        msg = {"action": "get-databasehash"}
        return self.send_message_request(msg)

    def associate(self) -> (bytes, dict):
        """Send generated public key and ID key to the server.
        
        Only needs to be ran if not yet associated.
        Response contains database ID which should be saved."""

        msg = {
            "action": "associate",
            "key": encode(self.get_public_key()),
            "idKey": encode(self.get_id_key()),
        }
        return self.send_message_request(msg)

    def test_associate(self) -> (bytes, dict):
        """Send association info to server to see if it remembers us."""

        msg = {
            "action": "test-associate",
            "id": self.get_db_id(),  # saved db id
            "key": encode(self.get_id_key()),  # saved db id key
        }
        return self.send_message_request(msg)

    def get_logins(self, url, submit_url=None, http_auth=None) -> (bytes, dict):
        """Ask the server for entries for an url."""

        msg = {
            "action": "get-logins",
            "url": url,
            "submitUrl": submit_url,
            "httpAuth": http_auth,
            "keys": [{"id": (self.get_db_id()), "key": encode(self.get_id_key())}],
        }
        return self.send_message_request(msg)

    def set_login(
        self, url, submit_url, login, password, group, groupuuid, uuid
    ) -> (bytes, dict):
        msg = {
            "action": "set-login",
            "url": url,
            "submitUrl": submit_url,
            "id": self.get_id_key(),
            "nonce": encode(self.nonce),
            "login": login,
            "password": password,
            "group": group,
            "groupUuid": groupuuid,
            "uuid": uuid,
        }
        return self.send_message_request(msg)

    def lock_database(self) -> (bytes, dict):
        msg = {"action": "lock-database"}
        return self.send_message_request(msg)

    def get_database_groups(self) -> (bytes, dict):
        msg = {"action": "get-database-groups"}
        return self.send_message_request(msg)

    def create_new_group(self, group_name) -> (bytes, dict):
        msg = {"action": "create-new-group", "groupName": group_name}
        return self.send_message_request(msg)

    # endregion

    def is_associated(self) -> bool:
        resp = self.test_associate()
        return "id" in resp

    def reassociate(self):
        # check association
        associated = False

        if self.get_db_id():
            # If db id is present (was loaded from file),
            # the client was associated earlier.
            # So we check if it's still associated.
            associated = self.is_associated()

        if not associated:
            msg = self.associate()
            self.set_db_id(msg["id"])
            associated = self.is_associated()
            if associated:
                self.save()
            else:
                raise Exception("Couldn't associate")

    def get_entries_for_url(self, url, submit_url=None, http_auth=None) -> list:
        msg = self.get_logins(url, submit_url, http_auth)
        if "entries" in msg:
            return msg["entries"]
        else:
            return []


def parse_args(args_in=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="KeePassXC NaCl helper.",
        # epilog="Custom string fields should start with 'KPH: ', otherwise they can't be retrieved.",
    )

    # fields
    parser.add_argument(
        "-e", "--entry", action="store_true", dest="show_name", help="print entry name"
    )
    parser.add_argument(
        "-u",
        "--username",
        action="store_true",
        dest="show_username",
        help="print username",
    )
    parser.add_argument(
        "-p",
        "--password",
        action="store_true",
        dest="show_password",
        help="print password (default)",
    )
    parser.add_argument(
        "-s",
        "--string-fields",
        action="store_true",
        dest="show_stringfields",
        help="print string fields",
    )
    parser.add_argument(
        "-i", "--uuid", action="store_true", dest="show_uuid", help="print entry uuid"
    )
    parser.add_argument(
        "-f",
        "--full",
        action="store_true",
        dest="show_all",
        help="print all entry fields",
    )
    parser.add_argument(
        "-l",
        "--all-entries",
        action="store_true",
        dest="show_all_matches",
        help="print all matched entries, not just the first one",
    )

    # file/socket paths
    parser.add_argument(
        "--client",
        dest="client",
        help=f"set client id string used for association. defaults to '{DEFAULT_CLIENT_ID}'",
        metavar="ID",
        default=DEFAULT_CLIENT_ID,
    )

    state_filepath_shown = DEFAULT_STATE_FILE.replace(os.getenv("HOME"), "${HOME}")
    parser.add_argument(
        "--state",
        dest="file",
        help=f"set saved association state path. defaults to '{state_filepath_shown}'. if client id is set and this argument isn't used, filename defaults to ${{clientId}}.state",
    )

    parser.add_argument(
        "--socket",
        metavar="PATH",
        help=f"set socket path. defaults to '{DEFAULT_SOCKET_PATH}'",
        default=DEFAULT_SOCKET_PATH,
    )

    # output formatting
    parser.add_argument(
        "-d", "--debug", action="store_true", dest="debug", help="print debug info"
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print response in json format",
        dest="json",
    )
    parser.add_argument(
        "--eval",
        metavar="SH",
        dest="eval_format",
        help="print in format suitable for eval (possible values: bash, fish)",
    )
    parser.add_argument(
        "--field-prefixes",
        action="store_true",
        dest="field_prefixes",
        help="prepend fields with a field prefix (N - entry name, U - username, P - password, I - uuid, K - field key, V - field value)",
    )
    parser.add_argument(
        "--shell-escape",
        action="store_true",
        dest="shell_escape",
        help="escape quotes, spaces, variables",
    )
    parser.add_argument(
        "-0",
        "--null-delimited",
        action="store_true",
        dest="null_delimited",
        help="separate entries and fields with '\\0'",
    )
    parser.add_argument(
        "--field-sep",
        dest="user_field_separator",
        metavar="SEP",
        help="set separator for entry fields",
    )
    parser.add_argument(
        "--entry-sep",
        dest="user_entry_separator",
        metavar="SEP",
        help="set separator for entries",
    )

    parser.add_argument("url", nargs="+", help="url(s) to print credentials for")

    args = parser.parse_args(args_in)

    # if file path is not provided, determine it based on clientid
    args.file = args.file or os.path.join(
        os.getenv("XDG_DATA_HOME"), "kpxc-getter", args.client + ".state"
    )
    # TODO: check if XDG_DATA_HOME needs a fallback value

    return args


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    # get entries
    c = Connection(clientid=args.client, filename=args.file).connect(
        socket_path=args.socket
    )
    for url in args.url:
        entries = c.get_entries_for_url(url)
        if args.json:
            print(entries)
        else:
            if entries:
                if args.show_all_matches:
                    for i, entry in enumerate(entries):
                        show_entry(entry, args, i)
                else:
                    entry = entries[0]
                    show_entry(entry, args)


if __name__ == "__main__":
    main()
