# ssh-bastion

[![Build Status](https://badge.buildkite.com/0d91a446c11b7003dabf3aa93886e7e778b4417be3ef37619b.svg)](https://buildkite.com/lstoll/ssh-bastion)

nassh-relay based SSH bastion.

Supports auth with OpenID connect.

Relay options: `--proxy-host=addr --proxy-port=port`

URL format: `chrome-extension://pnhechapfaindjhompbnflcldabbghjo/html/nassh.html#user@host[:port][@proxyhost[:proxyport]]`