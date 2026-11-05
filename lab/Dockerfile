# SPDX-License-Identifier: AGPL-3.0-or-later
# Test lab mail server: Dovecot 2.4 with Pigeonhole (IMAP, LMTP, ManageSieve) and Postfix submission,
# from Debian's own packages. Lab only: the users and passwords below are fixtures, never real ones.
FROM debian:trixie

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved postfix ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail && useradd -u 5000 -g vmail -d /srv/mail -s /usr/sbin/nologin vmail \
 && install -d -o vmail -g vmail /srv/mail

COPY dovecot/ /etc/dovecot/lab/
COPY postfix/ /etc/postfix/lab/
COPY entrypoint.sh /usr/local/sbin/lab-entrypoint
RUN chmod -R go-w /etc/dovecot/lab /etc/postfix/lab && /usr/local/sbin/lab-entrypoint configure

EXPOSE 993 465 587 4190
ENTRYPOINT ["/usr/local/sbin/lab-entrypoint"]
CMD ["run"]
