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

DATA_SUBFOLDER_NAME = "kpxch"
DEFAULT_STATE_FOLDER = os.path.join(
    os.getenv("XDG_DATA_HOME") or os.path.join(os.getenv("HOME"), ".local", "share"),
    DATA_SUBFOLDER_NAME,
)
DEFAULT_STATE_FILE = os.path.join(DEFAULT_STATE_FOLDER, DEFAULT_CLIENT_ID + ".state")

STRING_FIELD_PREFIX = "KPH: "

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


def print_entry_formatted(entry, format_str=None, fields_format_str=None):
    if format_str:
        # --format '\n' is read as '\\n' forcing user to use $'\n'
        # this unescapes escaped sequences so that '\n' is read as newline
        format_str = bytes(format_str, "utf-8").decode("unicode_escape")
        out = format_str.format(
            name=entry["name"],
            login=entry["login"],
            password=entry["password"],
            uuid=entry["uuid"],
            index=entry["index"],
        )
        print(out, end="")

    if fields_format_str:
        fields_format_str = bytes(fields_format_str, "utf-8").decode("unicode_escape")
        for string_field in entry["stringFields"]:
            for key in string_field.keys():
                out = fields_format_str.format(
                    key=key,
                    value=string_field[key],
                    key_stripped=key.lstrip(STRING_FIELD_PREFIX),
                )
                print(out, end="")


def show_entry(entry: dict, args, entry_index=None):
    entry["index"] = entry_index or 0

    if args.format_str or args.fields_format_str:
        print_entry_formatted(entry, args.format_str, args.fields_format_str)
        return

    to_print = []
    if args.show_name or args.show_all:
        to_print.append(entry["name"])
    if args.show_username or args.show_all:
        to_print.append(entry["login"])
    if args.show_password or args.show_all:
        to_print.append(entry["password"])
    if args.show_uuid or args.show_all:
        to_print.append(entry["uuid"])
    if args.show_stringfields or args.show_all:
        for string_field in entry["stringFields"]:
            for field_num, key in enumerate(string_field.keys()):
                to_print.append(key)
                to_print.append(string_field[key])

    # if no fields were selected, default to password field
    if not to_print:
        to_print.append(entry["password"])

    for field in to_print:
        if args.shell_escape:
            print(shlex.quote(field))
        else:
            print(field)


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

    def load(self, filename):
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
    def __init__(self, clientid, filename):
        self.filename = filename
        self.clientid = clientid

        self.nonce = get_nonce()
        self.server_key = None

        self.association = Association().load(filename)
        self.socket_connection = SocketConnection()

    def connect(
        self, socket_path, timeout: int = 60, buffer_size: int = 1024 * 1024,
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
        encrypted_message = pysodium.crypto_box(
            msg.encode(), self.nonce, self.server_key, self.get_private_key()
        )
        request = {
            "action": action,
            "nonce": encode(self.nonce),
            "message": encode(encrypted_message),
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
        description="Command-line access to KeePassXC using NaCl and keepassxc-proxy.",
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
        "--list-all",
        action="store_true",
        dest="show_all_matches",
        help="print all matched entries, not just the first one",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print response in json format",
        dest="json",
    )
    parser.add_argument(
        "--shell-escape",
        action="store_true",
        dest="shell_escape",
        help="escape quotes, spaces, variables",
    )
    parser.add_argument(
        "--format",
        dest="format_str",
        metavar="F",
        help="set format for entry fields. Example: 'index: {index}\\nname: {name}\\nlogin: {login}\\npass: {password}\\nuuid: {uuid}\\n'. Don't forget the final newline (if you need it).",
    )
    parser.add_argument(
        "--fields-format",
        dest="fields_format_str",
        metavar="F",
        help="set format for entry string fields. Example: '{key}:{value}\\n'",
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
        # default value is applied later in order to react to client id
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

    parser.add_argument("url", nargs="+", help="url(s) to print credentials for")

    return parser.parse_args(args_in)


def main():
    args = parse_args()

    # args.fields_format_str = "{key_stripped}:{value}\n"

    # if file path is not provided, set it based on clientid
    if not args.file:
        args.file = os.path.join(DEFAULT_STATE_FOLDER, args.client + ".state")

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
