FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y openssh-server curl unzip netcat
RUN mkdir /var/run/sshd

RUN mkdir -p /tmp/vault && \
    curl -sLo  /tmp/vault/vault.zip https://releases.hashicorp.com/vault/1.0.3/vault_1.0.3_linux_amd64.zip && \
    unzip -d /usr/local/bin /tmp/vault/vault.zip && \
    rm -rf /tmp/vault

RUN useradd -ms /bin/bash sshkey
RUN useradd -ms /bin/bash vault

ADD ssh-server/sshd.sh /
ADD ssh-server/sshd_config /etc/ssh/sshd_config
ADD testdata/id_rsa.pub /home/sshkey/.ssh/authorized_keys

RUN chown -R sshkey /home/sshkey/.ssh && \
    chmod 0700 /home/sshkey/.ssh && \
    chmod 0600 /home/sshkey/.ssh/*

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

EXPOSE 22
CMD ["/sshd.sh"]
