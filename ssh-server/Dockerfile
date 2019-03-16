FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y openssh-server curl unzip netcat
RUN mkdir /var/run/sshd

RUN mkdir -p /tmp/vault && \
    curl -sLo  /tmp/vault/vault.zip https://releases.hashicorp.com/vault/1.0.3/vault_1.0.3_linux_amd64.zip && \
    unzip -d /usr/local/bin /tmp/vault/vault.zip && \
    rm -rf /tmp/vault

ADD sshd.sh /
ADD sshd_config /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

EXPOSE 22
CMD ["/sshd.sh"]
