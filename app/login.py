#!/usr/bin/python
import argparse
import json

from constants import HOST_CONFIG_FILE, KEYS_DIR
from ssh_login import Login

# construct the argument parse and parse the arguments
_parser = argparse.ArgumentParser()


def command_line_arguments():
    """
    Set command line arguments to be taken from user
    :return:
    """
    _parser.add_argument('-l', '--list', nargs='+',
                         help='<Required> Set flag', required=True)
    _parser.add_argument("-A", "--access", required=True,
                         help="access to host => grant/revoke")


def get_host_credentials(hostname, all_json):
    """
    get provided host credentials
    :param hostname:
    :return:
    """
    return all_json.get(hostname)


if __name__ == "__main__":
    # force user to send command line arguments
    command_line_arguments()
    args = vars(_parser.parse_args())

    host_list = args.get('list')
    access = args.get('access')
    host_private_key = None
    client_ssh_public_key = None
    client_ssh_private_key = None

    for host in host_list:
        # read json and set credentials
        with open(HOST_CONFIG_FILE, 'r') as f:
            all_json = json.loads(f.read())

        host_credentials = get_host_credentials(host, all_json)
        if not host_credentials:
            raise RuntimeError("No host => {0} in host_info config file."
                               .format(host))

        if host_credentials.get('host_private_key'):
            host_private_key = KEYS_DIR + \
                               host_credentials.get('host_private_key')

        if host_credentials.get('client_ssh_private_key'):
            client_ssh_private_key = KEYS_DIR + \
                                     (host_credentials
                                      .get('client_ssh_private_key'))

        if host_credentials.get('client_ssh_public_key'):
            client_ssh_public_key = KEYS_DIR + \
                                    (host_credentials
                                     .get('client_ssh_public_key'))
        ssh_login = Login(username=host_credentials.get('username'),
                          password=host_credentials.get('password'), host=host,
                          private_key=host_private_key,
                          client_ssh_public_key=client_ssh_public_key,
                          client_ssh_private_key=client_ssh_private_key)
        if (access == 'grant'):
            res = ssh_login.check_password_less_login()
            if res == 'error':
                ssh_login.add_ssh_private_key()
                copy_res = ssh_login.copy_ssh_key_to_host()
                print("SSh access is granted to this user {0}".format(host))
            # code to show shell/terminal of the host after successful login
            # ssh_login.interact_host()

        elif (access == 'revoke'):
            ssh_login.revoke_access()
            print("SSH access is revoked from the user {0}".format(host))
