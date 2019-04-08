import subprocess
import sys
import pexpect
import logging
import os
from os import path


class CommandExecutor(object):
    @classmethod
    def execute_command(self, command, timeout=600):
        """
        Execute command on client machine
        :param command:
        :param timeout:
        :return:
        """
        ssh = subprocess.Popen(command,
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        result = ssh.stdout.readlines()
        if result == [] or result == "":
            error = ssh.stderr.readlines()
            return "error"
        else:
            return result


class SshKeygen(object):
    """SSH key generator"""

    def __init__(self, dir_path, client_public_key_name):
        self.dir_path = dir_path
        self.client_public_key_name = client_public_key_name
        self.client_public_key_path = dir_path + "/" + client_public_key_name

    def key_present(self):
        """
        Checks to see if there is an RSA already present
        :return: bool.
        """
        if "id_rsa" in os.listdir(self.client_public_key_path):
            return True
        else:
            return False

    def generate_ssh_key(self):
        """
        Generate a SSH Key.
        :return:
        """
        os.mkdir(self.dir_path)
        os.chdir(self.dir_path)
        if self.key_present():
            print("A key is already present.")
        else:
            # Genarate private key
            CommandExecutor.execute_command('cat /dev/zero | ssh-keygen -q -N ""')


class Login(object):
    """ Login to host without password"""

    def __init__(self, username, host, port=22,
                 password=None, private_key=None,
                 client_ssh_public_key=None,
                 client_ssh_private_key=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self._set_ssh_key(client_ssh_public_key, client_ssh_private_key)

    def _set_ssh_key(self, client_ssh_public_key, client_ssh_private_key):
        """
        set ssh key to be used to copy paste from
        client to host for password less login
        :return:
        """
        current_client_user = self._get_current_local_user()
        if client_ssh_public_key and path.exists(client_ssh_public_key):
            self.ssh_key = client_ssh_public_key
            self.ssh_private_key = client_ssh_private_key
        elif path.exists("/home/{}/.ssh/id_rsa".format(current_client_user)):
            self.ssh_key = ("/home/{}/.ssh/id_rsa.pub".
                            format(current_client_user))
            self.ssh_private_key = ("/home/{}/.ssh/id_rsa".
                                    format(current_client_user))
        else:
            ssh_keygen = SshKeygen("/tmp/{}/.ssh".format(current_client_user),
                                   "id_rsa.pub")
            ssh_keygen.generate_ssh_key()
            self.ssh_key = ssh_keygen.client_public_key_path
            self.ssh_private_key = ("/tmp/{}/.ssh/id_rsa".
                                    format(current_client_user))

    def _get_current_local_user(self):
        out = CommandExecutor.execute_command('whoami')
        if out == 'error':
            raise RuntimeError("Error in getting current user command.")
        return out[0].strip("\n")

    def check_password_less_login(self):
        """
        Try to login without password
        :param host:
        :param port:
        :param username:
        :return:
        """
        return CommandExecutor.execute_command(
            "ssh -oNumberOfPasswordPrompts=0 {}@{} ls /tmp"
            .format(self.username, self.host))

    def add_ssh_private_key(self):
        """
        Add ssh key in key ring
        :return:
        """
        return CommandExecutor.execute_command(
            "ssh-add {}".format(self.ssh_private_key))

    def copy_ssh_key_to_host(self):
        """
        Copy ssh public key to host for password less authentication
        # ex: sshpass -p passwd ssh-copy-id login@1.1.1.1
        :param host:
        :param port:
        :param passsword:
        :param ssh_key:
        :return:
        """
        print "SSH copy id"
        if self.password:
            print "Using password"
            cmd = ('ssh-copy-id -i {0} -o StrictHostKeyChecking=no {1}@{2}'
                   .format(self.ssh_key, self.username, self.host))
            out = (CommandExecutor.execute_command
                   ('sshpass -p ' + self.password + ' ' + cmd))
        elif self.ssh_key:
            print "Using ssh key"
            cmd = ("cat {0} | ssh -i {1} {2}@{3}"
                   "'mkdir -p ~/.ssh && cat >>  ~/.ssh/authorized_keys' "
                   .format(self.ssh_key, self.private_key,
                           self.username, self.host))
            out = CommandExecutor.execute_command(cmd)
        else:
            raise RuntimeError("Either password or private_key"
                               "required in config file.")
        return out

    def interact_host(self):
        """
        Give control of remote host to the user
        :param child:
        :return:
        """
        child = pexpect.spawn('ssh {}@{}'.format(self.username, self.host))
        child.interact()  # Give control of the child to the user.

    def revoke_access(self):
        """
        revoke access from the user
        """
        current_client_user = self._get_current_local_user()
        cmd = ("ssh {0}@{1} 'sed -i.bak '/{2}/d' ~/.ssh/authorized_keys'"
               .format(self.username, self.host, current_client_user))
        out = CommandExecutor.execute_command(cmd)
