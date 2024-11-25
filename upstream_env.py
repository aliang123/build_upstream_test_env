"""setup qemu upstream test env by this script"""

import os
import re
import json
import subprocess
import argparse
import time

QUIET = False
LOG_LVL = 4
JIRA_URL = "https://issues.redhat.com"
##Replace JIRA_ACCESS_TOKEN with your own jira token before the tests. ####
JIRA_ACCESS_TOKEN = "xxxxxxx"
#for gmail
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def _log(lvl, msg):
    """Print a message with level 'lvl' to Console"""
    if not QUIET and lvl <= LOG_LVL:
        print(msg)


def _log_debug(msg):
    """Print a message with level DEBUG to Console"""
    msg = "\033[96mDEBUG: " + msg + "\033[00m"
    _log(4, msg)


def _log_info(msg):
    """Print a message with level INFO to Console"""
    msg = "\033[92mINFO: " + msg + "\033[00m"
    _log(3, msg)


def _log_warn(msg):
    """Print a message with level WARN to Console"""
    msg = "\033[93mWARN: " + msg + "\033[00m"
    _log(2, msg)


def _log_error(msg):
    """Print a message with level ERROR to Console"""
    msg = "\033[91mERROR: " + msg + "\033[00m"
    _log(1, msg)


def add_ca_certificates():
    _log_info("Install Red Hat CA certificates:")
    install_ca = "curl -L -k 'https://certs.corp.redhat.com/certs/Current-IT-Root-CAs.pem' -o /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem && "
    install_ca += "update-ca-trust"
    if os.system(install_ca) != 0:
        _log_error("Failed to install Red Hat CA certificates.")


class Patch_Gmail(object):
    def __init__(self, label, tag):
        from googleapiclient.discovery import build
        creds = self.get_google_credentials()
        self.service = build("gmail", "v1", credentials=creds)
        self.label = label
        self.tag = tag

    def get_google_credentials(self):
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists("token.json"):
            _log_info("token exist")
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                _log_info("no token, will generate one")
                flow = InstalledAppFlow.from_client_secrets_file(
                    "credentials.json", SCOPES
                )
                creds = flow.run_local_server(port=0)
            with open("token.json", "w") as token:
                token.write(creds.to_json())
        return creds

    def get_message_id(self, messages):
        for message in messages:
            msg = self.service.users().messages().get(userId="me", id=message['id']).execute()
            headers = ",".join([json.dumps(item) for item in msg['payload']['headers']])
            pattern = r'\{"name": "Subject", "value": "\[PATCH.*?\}'
            match = re.search(pattern, headers)
            if self.tag in headers and match:
                for header in msg['payload']['headers']:
                    if header["name"] in ("Message-Id", "Message-ID"):
                        message_id = header["value"]
                        if "-" in message_id:
                            message_id.replace(message_id.split('-')[1], "1")
                        return message_id.strip("<>")

    def get_patch_from_label(self):
        results = self.service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
        for label in labels:
            if label["name"] == self.label:
                print (label["id"])
                res = self.service.users().messages().list(userId="me", labelIds=label["id"]).execute()
                messages = res.get("messages", [])
                if not messages:
                    print ("No mail")
                else:
                    msg_id = self.get_message_id(messages)
                    return msg_id

    def get_patch_from_inbox(self):
        results = self.service.users().messages().list(userId="me", maxResults=100).execute()
        messages = results.get("messages", [])
        if not messages:
            print ("No mail")
        else:
            msg_id = self.get_message_id(messages)
            return msg_id

    def get_patch_from_gmail(self):
        try:
            from googleapiclient.errors import HttpError
            # Call the Gmail API
            if self.label:
                patch = self.get_patch_from_label()
            else:
                patch = self.get_patch_from_inbox()
        except HttpError as error:
            # TODO(developer) - Handle errors from gmail API.
            print(f"An error occurred: {error}")
        return patch

def get_patch_from_jira(jira_id=None):
    _log_info("Fetch patch and apply it")
    _log_info("Get test patch:")
    from jira import JIRA
    jiraobj = JIRA(server=JIRA_URL, token_auth=JIRA_ACCESS_TOKEN)
    comments = jiraobj.comments(jira_id)
    for comment in comments:
        if "upstream" in comment.body:
             for line in comment.body.split("\n"):
                 if "@redhat" in line:
                     for item in line.split("/"):
                         if "@redhat" in item:
                             patch = item
                             break

    return patch

def apply_patch(source=None, jira_id=None, label=None, tag=None, msg_id=None):
    if source == "jira":
        msg_id = get_patch_from_jira(jira_id)
    elif source == "gmail":
        gmail_patch = Patch_Gmail(label, tag)
        msg_id = gmail_patch.get_patch_from_gmail()
    os.chdir(os.getcwd() + "/qemu")
    cmd = "b4 am %s" % msg_id
    result = subprocess.getoutput(cmd)
    mbox = result.split("\n")[-1].strip()
    os.system(mbox)

def build_qemu_pkg(aio=None, encrypt=None):
    if "/qemu" not in os.getcwd():
        os.chdir(os.getcwd() + "/qemu")
    if not os.path.exists("build"):
        os.system("mkdir build")
    os.chdir(os.getcwd() + "/build")
    _log_info("Build qemu package...")
    build_cmd = "../configure --target-list=x86_64-softmmu --enable-debug --enable-kvm --enable-seccomp --enable-slirp --enable-vnc"
    download_pkg = ""
    if aio == "io_uring":
        download_pkg = "liburing-devel"
        build_cmd = "../configure --target-list=x86_64-softmmu --enable-debug --enable-linux-io-uring"
    elif aio == "native":
        download_pkg = "liburing-devel"
        build_cmd = "../configure --target-list=x86_64-softmmu --enable-debug --enable-linux-aio"
    if encrypt == "yes":
        download_pkg = "gnutls-devel"
        build_cmd = "../configure --target-list=x86_64-softmmu --enable-debug --enable-gnutls"
    if download_pkg:
        os.system("yum install -y %s" % download_pkg)
    os.system(build_cmd)
    _log_info("Make and install qemu package...")
    os.system("make")
    os.system("make install")
    _log_info("Link qemu-system-x86_64 to qemu-kvm")
    os.system("rm -f /usr/libexec/qemu-kvm")
    time.sleep(30)
    os.system("ln -s /usr/local/bin/qemu-system-x86_64 /usr/libexec/qemu-kvm")
    time.sleep(30)

def get_os_release():
    res = subprocess.getoutput("cat /etc/os-release")
    match = re.search(r'\d+', res).group()
    if match:
        return match

def pkg_in_pip_lists(pkg):
    output = subprocess.getoutput("pip list")
    if pkg in output:
        return True

def install_deps(source=None):
    if os.system("rpm -q epel-release") != 0:
        _log_info("Installing epel-release")
        os_release = get_os_release()
        epel_pkg = "https://dl.fedoraproject.org/pub/epel/epel-release-latest-%s.noarch.rpm" % os_release
        os.system("dnf install -y %s" % epel_pkg)
    RPM_REQS=(
    "gcc",
    "gcc-c++",
    "python3-pip",
    "glibc-headers",
    "python3-devel",
    "net-tools",
    "iproute",
    "iputils",
    "nfs-utils",
    "sysstat",
    "bzip2",
    "openssl-devel",
    "libffi-devel",
    "glib2-devel",
    "libtool",
    "make",
    "ninja-build",
    "b4",
    "libseccomp-devel",
    "pixman-devel"
    )
    for rpm in RPM_REQS:
        if os.system("rpm -q %s" % rpm)!= 0:
            os.system("dnf install -y %s" % rpm)
    if not pkg_in_pip_lists("packaging"):
        os.system("pip install --ignore-installed packaging")
    if not pkg_in_pip_lists("sphinx"):
        os.system("pip install -U sphinx")
    if source =="gmail":
        gmail_pkg = "google-api-python-client google-auth-httplib2 google-auth-oauthlib"
        for pkg in gmail_pkg.split():
            if not pkg_in_pip_lists(pkg):
                os.system("pip install --upgrade %s" % pkg)
    if source == "jira" and not pkg_in_pip_lists("jira"):
        os.system("pip install --upgrade jira")


def install_upstream_qemu(aio=None, encrypt=None, source=None, jira_id=None, label=None, tag=None, patch_id=None):
    if os.system("rpm -q git") !=0:
        if os.system("yum install -y git") != 0:
            _log_error("Failed to install git related packages.")
    _log_info("Clone upstream qemu repo.")
    os.system("rm -rf qemu*")
    download_qemu = "git clone https://gitlab.com/qemu-project/qemu.git"
    if os.system(download_qemu) != 0:
        _log_error("Failed to clone qemu repo.")
    if source or patch_id:
        apply_patch(source, jira_id, label, tag, patch_id)
    build_qemu_pkg(aio, encrypt)

def main(argv):
    try:
        aio = argv.get("aio", None)
        encrypt=argv.get("encrypt", None)
        source = argv.get("source", None)
        jira_id=argv.get("jira_id", None)
        label = argv.get("label", None)
        tag = argv.get("tag", "qemu-devel@nongnu.org")
        patch_id = argv.get("patch_id", None)
        add_ca_certificates()
        install_deps(source)
        install_upstream_qemu(aio, encrypt, source, jira_id, label, tag, patch_id)
    except Exception as e:
        _log_error(str(e))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--aio", default=None, help="aio mode for you tests")
    parser.add_argument("--encrypt", default=None, help="encrypt or not")
    parser.add_argument("--source", default=None, help="test patch from jira issue or from mail")
    parser.add_argument("--jira_id", default=None,
            help=("the jira_id that needs upstream test."))
    parser.add_argument("--label", default=None, help="gmail label where you want to get the patch")
    parser.add_argument("--tag", default="qemu-devel@nongnu.org", help="gmail tag where you want to get the patch")
    parser.add_argument("--patch_id", default=None, help="patch id that needed to apply")
    config_args = vars(parser.parse_args())
    main(config_args)
