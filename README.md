# build_upstream_test_env
## 1. Introduction
Upstream_test.py: a script to build upstream env for qemu tests.

## 2. Usage
### run tests with latest upstream qemu code
#python3 Upstream_test.py

### run tests with aio mode: native
#python3 Upstream_test.py --aio=natvie

### run tests with aio mode: io_uring
#python3 Upstream_test.py --aio=io_uring

### run tests with tls/luks
#python3 Upstream_test.py --encrypt=yes

### run tests with upstream patch that provided via patch_id
#python3 Upstream_test.py --patch_id=20240911132630.461-1-XX@linux.rsss.com

### run tests with upstream patch that provided in a jira issues's comment
#python3 Upstream_test.py --source=jira --jira_id=RHEL-39948

### run tests with the latest upstream patch that provided in gmail
#python3 Upstream_test.py --source=gmail

### run tests with the latest upstream patch that provided labels in gmail
#python3 Upstream_test.py --source=gmail --label=qemu-devel

Note: \
before you use --source=gmail, create a credentials.json firstly, as in https://developers.google.com/gmail/api/quickstart/python \
before you use --source=jira, replace the JIRA_ACCESS_TOKEN with your own token
