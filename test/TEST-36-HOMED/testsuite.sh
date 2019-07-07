#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

NEWPASSWORD=xEhErW0ndafV4s homectl create test-user --disk-size=20M

homectl inspect test-user

PASSWORD=xEhErW0ndafV4s homectl activate test-user

homectl inspect test-user

PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Inline test"

homectl inspect test-user

homectl deactivate test-user

#PASSWORD=xEhErW0ndafV4s homectl resize test-user --disk-size=30M

PASSWORD=xEhErW0ndafV4s homectl activate test-user
PASSWORD=xEhErW0ndafV4s homectl deactivate test-user

PASSWORD=xEhErW0ndafV4s homectl update test-user --real-name="Offline test"

PASSWORD=xEhErW0ndafV4s homectl activate test-user
PASSWORD=xEhErW0ndafV4s homectl deactivate test-user

#PASSWORD=xEhErW0ndafV4s homectl resize test-user --disk-size=20M

homectl remove test-user

systemd-analyze log-level info

echo OK > /testok

exit 0
