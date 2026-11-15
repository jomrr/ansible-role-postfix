# Ansible Role: postfix

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-postfix)
![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-postfix)
![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-postfix)
[![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-postfix/dev.yml?branch=dev&label=dev)](https://github.com/jomrr/ansible-role-postfix/actions/workflows/dev.yml?query=branch%3Adev)
[![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-postfix/main.yml?branch=main&label=main)](https://github.com/jomrr/ansible-role-postfix/actions/workflows/main.yml?query=branch%3Amain)

Install Postfix with authenticated TLS submission, sender authorization,
provider relays and file or SQL account lookups.

## Purpose

Install, configure, enable and start Postfix with local delivery, Dovecot SASL
and LMTP integration, authenticated TLS submission, per-user envelope sender
authorization, provider-specific relay credentials, optional archive copies and
PostfixAdmin-compatible MariaDB/MySQL or PostgreSQL account lookups. Unchanged
runs preserve the queue and do not restart the service.

## Scope

### Managed

- Postfix packages, lookup drivers, main.cf, master.cf, address tables and
  service state.
- Mandatory Dovecot authentication and TLS on every enabled SMTP listener by
  default, including SMTP and Fetchmail ports.
- Multiple authorized envelope sender identities per account and distinct
  provider credentials per sender.
- Provider transports with mandatory TLS and certificate hostname verification,
  including implicit TLS relays.
- A dedicated Fetchmail listener with source restrictions and
  local-recipient-only delivery.
- Local Unix delivery, local aliases, virtual recipients, Dovecot LMTP delivery
  and optional archive recipients.
- Queue lifetime and retry settings, connection and delivery logging, and daily
  log rotation.
- Public MX reception, Milter interfaces for DKIM and DMARC, and SMTP policy
  services such as SPF checks.

### Not Managed

- Dovecot, Fetchmail, PostfixAdmin, database servers, database schema migrations
  or account passwords.
- TLS certificate issuance, firewall rules, MX/PTR/SPF/DKIM/DMARC DNS records or
  Milter and policy daemons.
- Mailbox storage ownership, mailbox quotas, vacation responders or destructive
  queue operations.

## Requirements

- Postfix 3.6 or newer on AlmaLinux, Debian, Fedora, openSUSE Leap, openSUSE
  Tumbleweed or Ubuntu.
- Enabled authenticated listeners require a provisioned PEM certificate and
  private key, plus a running Dovecot SASL socket. Dovecot must allow the
  Postfix user to access its authentication and LMTP sockets.
- SQL mode requires an existing PostfixAdmin schema with the domain, mailbox,
  alias and alias_domain tables. Use a database login with SELECT privileges
  only. Provision it separately and protect remote connections with verified
  TLS.
- Dovecot authenticates account passwords and owns mailbox delivery. Configure
  its passdb/userdb against the same text-file or PostfixAdmin account source;
  full email addresses are the SASL identities in SQL mode.

## Dependencies

```yaml
collections:
  - name: community.general
    version: '>=12.0.0'
  - name: ansible.posix
    version: '>=2.0.0'
  - name: community.crypto
    version: '>=3.0.0'
  - name: containers.podman
    version: '>=1.20.0'
```

## Role Variables

### `postfix_hostname`

Type: `str`. Required: `false`.

Fully qualified hostname announced by the mail server.

Default:

```yaml
postfix_hostname: '{{ ansible_facts.fqdn }}'
```

### `postfix_origin`

Type: `str`. Required: `false`.

Domain appended to locally submitted unqualified addresses.

Default:

```yaml
postfix_origin: $myhostname
```

### `postfix_interfaces`

Type: `list`. Required: `false`.

Interfaces used by the standard SMTP and submission listeners.

Default:

```yaml
postfix_interfaces:
  - loopback-only
```

### `postfix_protocols`

Type: `str`. Required: `false`.

IP protocol families enabled by Postfix.

Default:

```yaml
postfix_protocols: all
```

### `postfix_local_domains`

Type: `list`. Required: `false`.

Domains delivered to local Unix accounts through the local delivery agent.

Default:

```yaml
postfix_local_domains:
  - $myhostname
  - localhost
```

### `postfix_trusted_networks`

Type: `list`. Required: `false`.

Networks permitted to connect when the standard SMTP listener is restricted.

Default:

```yaml
postfix_trusted_networks:
  - 127.0.0.0/8
  - '[::1]/128'
```

### `postfix_smtp_trusted_only`

Type: `bool`. Required: `false`.

Restrict standard SMTP reception to trusted networks; false permits public MX
reception.

Default:

```yaml
postfix_smtp_trusted_only: true
```

### `postfix_local_aliases`

Type: `dict`. Required: `false`.

Local aliases managed separately from distribution aliases.

Default:

```yaml
postfix_local_aliases:
  postmaster: root
```

### `postfix_smtp_enabled`

Type: `bool`. Required: `false`.

Enable the standard SMTP listener on port 25.

Default:

```yaml
postfix_smtp_enabled: true
```

### `postfix_smtp_auth_required`

Type: `bool`. Required: `false`.

Require TLS and Dovecot authentication on the standard SMTP listener.

Default:

```yaml
postfix_smtp_auth_required: true
```

### `postfix_submission_enabled`

Type: `bool`. Required: `false`.

Enable authenticated submission with mandatory STARTTLS.

Default:

```yaml
postfix_submission_enabled: false
```

### `postfix_submission_port`

Type: `int`. Required: `false`.

Port for authenticated STARTTLS submission.

Default:

```yaml
postfix_submission_port: 587
```

### `postfix_submissions_enabled`

Type: `bool`. Required: `false`.

Enable authenticated submission with implicit TLS.

Default:

```yaml
postfix_submissions_enabled: false
```

### `postfix_submissions_port`

Type: `int`. Required: `false`.

Port for authenticated implicit TLS submission.

Default:

```yaml
postfix_submissions_port: 465
```

### `postfix_dovecot_auth_socket`

Type: `str`. Required: `false`.

Dovecot authentication socket relative to the Postfix queue directory.

Default:

```yaml
postfix_dovecot_auth_socket: private/auth
```

### `postfix_tls_certificate`

Type: `str`. Required: `false`.

Certificate chain required by any listener enforcing authentication.

Default:

```yaml
postfix_tls_certificate: ''
```

### `postfix_tls_private_key`

Type: `str`. Required: `false`.

Private key required by either submission service.

Default:

```yaml
postfix_tls_private_key: ''
```

### `postfix_tls_ca_file`

Type: `str`. Required: `false`.

Additional trusted CA bundle for outgoing TLS; empty uses the platform bundle.

Default:

```yaml
postfix_tls_ca_file: ''
```

### `postfix_sender_authorization`

Type: `bool`. Required: `false`.

Reject SMTP envelope senders that do not belong to the authenticated user.

Default:

```yaml
postfix_sender_authorization: true
```

### `postfix_local_submitters`

Type: `dict`. Required: `false`.

Unix submitters and their permitted envelope senders; root is trusted.

Default:

```yaml
postfix_local_submitters:
  root:
    - '*'
```

### `postfix_account_backend`

Type: `str`. Required: `false`.

Account lookup backend for recipients, aliases and sender ownership.

Default:

```yaml
postfix_account_backend: files
```

### `postfix_virtual_domains`

Type: `list`. Required: `false`.

Domains accepted for virtual mailboxes and delivered through LMTP.

Default:

```yaml
postfix_virtual_domains: []
```

### `postfix_mailboxes`

Type: `list`. Required: `false`.

Valid virtual recipient addresses for the text-file backend.

Default:

```yaml
postfix_mailboxes: []
```

### `postfix_virtual_aliases`

Type: `dict`. Required: `false`.

Virtual aliases and their destination addresses for the text-file backend.

Default:

```yaml
postfix_virtual_aliases: {}
```

### `postfix_sender_logins`

Type: `dict`. Required: `false`.

Envelope sender addresses and authorized SASL identities for the text-file
backend.

Default:

```yaml
postfix_sender_logins: {}
```

### `postfix_dovecot_lmtp_transport`

Type: `str`. Required: `false`.

LMTP destination used for virtual mailbox delivery to Dovecot.

Default:

```yaml
postfix_dovecot_lmtp_transport: lmtp:unix:private/dovecot-lmtp
```

### `postfix_local_lmtp_enabled`

Type: `bool`. Required: `false`.

Deliver local Unix mailbox recipients through Dovecot LMTP as well.

Default:

```yaml
postfix_local_lmtp_enabled: false
```

### `postfix_providers`

Type: `list`. Required: `false`.

Named external providers with separate credentials and TLS transports.

Default:

```yaml
postfix_providers: []
```

### `postfix_provider_port`

Type: `int`. Required: `false`.

Default external provider port, with optional per-provider overrides.

Default:

```yaml
postfix_provider_port: 587
```

### `postfix_provider_tls`

Type: `str`. Required: `false`.

Default external provider TLS mode, with optional per-provider overrides.

Default:

```yaml
postfix_provider_tls: starttls
```

### `postfix_default_provider`

Type: `str`. Required: `false`.

Default provider name; empty permits direct SMTP delivery for unmatched senders.

Default:

```yaml
postfix_default_provider: ''
```

### `postfix_sender_relays`

Type: `dict`. Required: `false`.

Exact envelope sender addresses mapped to provider names.

Default:

```yaml
postfix_sender_relays: {}
```

### `postfix_transport_maps`

Type: `dict`. Required: `false`.

Additional recipient domain or address transport routes.

Default:

```yaml
postfix_transport_maps: {}
```

### `postfix_fetchmail_enabled`

Type: `bool`. Required: `false`.

Enable a dedicated trusted SMTP listener for Fetchmail delivery.

Default:

```yaml
postfix_fetchmail_enabled: false
```

### `postfix_fetchmail_auth_required`

Type: `bool`. Required: `false`.

Require TLS and Dovecot authentication in addition to trusted Fetchmail sources.

Default:

```yaml
postfix_fetchmail_auth_required: true
```

### `postfix_fetchmail_address`

Type: `str`. Required: `false`.

Numeric interface address for the dedicated Fetchmail listener.

Default:

```yaml
postfix_fetchmail_address: 127.0.0.1
```

### `postfix_fetchmail_port`

Type: `int`. Required: `false`.

Port of the dedicated Fetchmail listener.

Default:

```yaml
postfix_fetchmail_port: 2525
```

### `postfix_fetchmail_networks`

Type: `list`. Required: `false`.

Sources permitted on the Fetchmail listener; recipients must still be local.

Default:

```yaml
postfix_fetchmail_networks:
  - 127.0.0.1/32
  - '[::1]/128'
```

### `postfix_sender_bcc`

Type: `dict`. Required: `false`.

Envelope senders and their optional outgoing archive copy address.

Default:

```yaml
postfix_sender_bcc: {}
```

### `postfix_recipient_bcc`

Type: `dict`. Required: `false`.

Envelope recipients and their optional incoming archive copy address.

Default:

```yaml
postfix_recipient_bcc: {}
```

### `postfix_message_size_limit`

Type: `int`. Required: `false`.

Maximum accepted message size in bytes.

Default:

```yaml
postfix_message_size_limit: 10240000
```

### `postfix_maximal_queue_lifetime`

Type: `str`. Required: `false`.

Maximum time that undelivered messages remain queued.

Default:

```yaml
postfix_maximal_queue_lifetime: 5d
```

### `postfix_bounce_queue_lifetime`

Type: `str`. Required: `false`.

Maximum time that undeliverable bounce messages remain queued.

Default:

```yaml
postfix_bounce_queue_lifetime: 5d
```

### `postfix_minimal_backoff_time`

Type: `str`. Required: `false`.

Minimum delay between delivery retries.

Default:

```yaml
postfix_minimal_backoff_time: 300s
```

### `postfix_maximal_backoff_time`

Type: `str`. Required: `false`.

Maximum delay between delivery retries.

Default:

```yaml
postfix_maximal_backoff_time: 4000s
```

### `postfix_queue_run_delay`

Type: `str`. Required: `false`.

Interval between deferred-queue scans.

Default:

```yaml
postfix_queue_run_delay: 300s
```

### `postfix_log_file`

Type: `str`. Required: `false`.

Direct Postfix log file; empty uses the system mail syslog facility.

Default:

```yaml
postfix_log_file: /var/log/postfix.log
```

### `postfix_tls_loglevel`

Type: `int`. Required: `false`.

TLS connection summary logging level.

Default:

```yaml
postfix_tls_loglevel: 1
```

### `postfix_smtpd_milters`

Type: `list`. Required: `false`.

Milter endpoints for incoming SMTP, including DKIM and DMARC filters.

Default:

```yaml
postfix_smtpd_milters: []
```

### `postfix_non_smtpd_milters`

Type: `list`. Required: `false`.

Milter endpoints for local sendmail submissions.

Default:

```yaml
postfix_non_smtpd_milters: []
```

### `postfix_submission_milters`

Type: `list`. Required: `false`.

Milter endpoints for authenticated submission, including signing and From
checks.

Default:

```yaml
postfix_submission_milters: []
```

### `postfix_milter_default_action`

Type: `str`. Required: `false`.

Action when an enabled Milter is unavailable.

Default:

```yaml
postfix_milter_default_action: tempfail
```

### `postfix_smtp_policy_services`

Type: `list`. Required: `false`.

Policy service endpoints for public SMTP recipient checks, such as SPF.

Default:

```yaml
postfix_smtp_policy_services: []
```

### `postfix_backup`

Type: `bool`. Required: `false`.

Preserve previous managed files; backups may contain provider credentials.

Default:

```yaml
postfix_backup: false
```

### `postfix_database`

Type: `dict`. Required: `false`.

Shared native database connection options for the existing PostfixAdmin schema;
hosts is required for mysql or pgsql. Use a SELECT-only login and a Unix socket
or verified TLS.

Default:

```yaml
postfix_database: {}
```

### `postfix_database_queries`

Type: `dict`. Required: `false`.

Optional overrides of the PostfixAdmin domains, mailboxes, virtual_aliases,
alias_domains, alias_domain_catchalls, senders and alias_domain_senders queries.

Default:

```yaml
postfix_database_queries: {}
```

## Managed Files

- `/etc/postfix/main.cf` Role-owned service configuration; previous unmanaged
  settings are replaced.
- `/etc/postfix/master.cf` Role-owned listeners and transports, without chroot,
  including separate provider TLS modes.
- `/etc/postfix/ansible/` Address tables, compiled indexes and protected SQL
  connection settings.
- `/etc/logrotate.d/ansible-postfix` Daily rotation retaining fourteen
  compressed logs when postfix_log_file is nonempty.

## Check Mode

Existing installations support check mode without rebuilding tables or changing
service state.

- Initial check mode needs Postfix already installed so its native table type
  and version can be read.
- Native configuration checks and service actions execute during a normal
  converge.

## Service Behavior

Changed lookup tables are rebuilt before native checks and a service restart;
the service is enabled and started on every converge.

### Handlers

- Only changed address tables, local aliases and provider credentials are
  reindexed.
- SQL connection settings and service configuration changes restart Postfix
  without deleting queued mail.

## Security Notes

- Every enabled SMTP listener requires TLS and SASL by default, including port
  25 and the dedicated Fetchmail listener. Trusted networks do not bypass
  authentication. The default bind address is loopback-only.
- Submission always requires TLS and SASL. Authenticated SMTP and submission
  clients may relay using their authorized envelope identities; the Fetchmail
  listener only accepts local recipients, including for authenticated clients.
- Sender authorization binds SMTP MAIL FROM to a SASL identity. Local
  sendmail/postdrop uses a separate Unix-user permission table; only root is
  authorized by default. Root remains trusted and cannot be confined by an MTA
  role.
- Explicitly unauthenticated SMTP reception rejects known mailbox and sender
  identities through a separate sender-access map. The Fetchmail listener
  preserves original envelope senders; use dedicated Dovecot credentials for
  trusted fetching processes.
- The visible From header is separate from the envelope sender. Enforce header
  identity with an external Milter configured in postfix_submission_milters and
  postfix_non_smtpd_milters; header_checks cannot compare a header to the
  authenticated identity.
- Provider credentials use root-only files and compiled indexes; SQL connection
  files are root:postfix 0640. Secret-bearing tasks and argument values are
  redacted. Use Ansible Vault or an external secret lookup for credential
  values.
- Enabled provider relays require trusted TLS with hostname verification. Direct
  delivery uses opportunistic TLS for Internet interoperability. Milter failures
  temporarily reject mail by default.
- Archive copies contain full messages and require separately authorized archive
  recipients and retention policies. Native SMTP logs include addressing and
  delivery metadata but do not enable protocol or password debug logging.

## Operational Notes

- File mode uses postfix_mailboxes, postfix_virtual_aliases,
  postfix_sender_logins and postfix_virtual_domains. Address ownership values
  are lists of SASL identities, allowing shared identities without duplicating
  accounts.
- SQL mode reads active PostfixAdmin domains, mailboxes and aliases, including
  alias domains and catch-all aliases. Disabled domains and backup-MX domains
  are excluded from local mailbox delivery. PostfixAdmin owns schema changes;
  this role does not initialize, migrate or overwrite its tables.
- SQL lookups use the native Postfix proxymap service to share database
  connections between SMTP and delivery processes.
- The default SQL sender ownership query grants an alias to the identities
  listed in its goto field. Keep alias targets as authorized mailbox identities.
  Nested forwarding does not imply transitive sender permission. For delegated
  ownership or additional smtp_active policies, override the corresponding
  postfix_database_queries and Dovecot passdb rules.
- postfix_database contains shared native mysql_table or pgsql_table connection
  parameters. PostgreSQL connection URIs must include their own user, password
  and database; libpq URI settings supersede separate connection fields.
  postfix_database_queries overrides individual queries for custom table
  prefixes or permission policies.
- The role uses the distribution's native default_database_type for indexed text
  maps. No fixed hash or LMDB choice is required. Switching back to files
  removes the role-owned SQL connection files; optional backups are retained
  when postfix_backup is enabled.
- Each postfix_sender_relays key is an exact envelope sender address.
  Sender-specific credentials support different accounts at the same relay host.
  An empty postfix_default_provider allows unmatched senders to use direct SMTP
  delivery.
- postfix_fetchmail_networks controls the dedicated listener independently of
  postfix_trusted_networks. Fetchmail cannot relay to external recipients.
  Fetchmail must use STARTTLS and SMTP AUTH by default.
  postfix_fetchmail_auth_required=false explicitly permits unauthenticated
  reception from the configured trusted sources. Applications sending outbound
  mail use submission.
- Public MX reception requires postfix_interfaces: [all],
  postfix_smtp_trusted_only: false and postfix_smtp_auth_required: false, plus
  external firewall and DNS configuration. Public Internet mail servers
  generally cannot authenticate to a receiving MX. Configure incoming validation
  filters in postfix_smtpd_milters and postfix_smtp_policy_services, and signing
  filters in postfix_submission_milters and postfix_non_smtpd_milters.
- Dovecot's default LMTP endpoint is private/dovecot-lmtp under the Postfix
  queue directory. postfix_local_lmtp_enabled also sends local Unix mailbox
  delivery there; otherwise the packaged local delivery agent is used.
- Native postfix check runs before configuration-triggered restarts. It checks
  the installed configuration and queue permissions; Postfix has no complete
  single-file candidate validator for main.cf plus master.cf and lookup
  services. Successful native checks do not prove database, TLS, authentication
  or delivery endpoint availability.
- postqueue -p inspects queued mail, postqueue -f requests an immediate retry,
  and postconf -n displays effective nondefault settings. The role never flushes
  or deletes the queue automatically. Custom logfile parents must already exist.
- Molecule reuses each mail server across file, MariaDB and PostgreSQL
  configurations. Dovecot and certificate fixtures are installed once; the role
  installs Postfix and adds each SQL driver when first selected. One MariaDB and
  one PostgreSQL container serve the entire local dev matrix. No servers are
  recreated between backend checks.
- Molecule follows the Forgejo setup with official MariaDB and PostgreSQL images
  under platforms, separate server and dependency groups, and a role-only
  Converge play targeting postfix_servers. Molecule owns every container's
  create/destroy lifecycle. Prepare supplies Dovecot, certificates and database
  test data. Independent Dovecot fixture sockets allow setup before Postfix
  installation without creating its service user or spool directories. GitHub
  workflows use the unchanged Factory defaults.
- Each platform runs the full SMTP integration suite once, including all
  authenticated listeners, both provider TLS modes, queue retries, local sender
  permissions, LMTP and archives. Backend checks cover SQL account permissions
  and delivery plus disabled and unknown records; exception checks cover trusted
  unauthenticated reception. Initial idempotence, configuration recovery and
  final check mode each run once.
- GitHub Actions runs the same tests through the default scenario, with a
  six-platform matrix on main and a single-platform smoke run on dev. Each job
  reuses its mail server and database fixtures for all backends; the local dev
  scenario tests all six platforms together.

## Supported Platforms

| OS Family | Distribution | Version | Container Image |
| --------- | ------------ | ------- | --------------- |
| RedHat | AlmaLinux | latest | [jomrr/molecule-almalinux:latest](https://hub.docker.com/r/jomrr/molecule-almalinux) |
| Debian | Debian | latest | [jomrr/molecule-debian:latest](https://hub.docker.com/r/jomrr/molecule-debian) |
| RedHat | Fedora | latest | [jomrr/molecule-fedora:latest](https://hub.docker.com/r/jomrr/molecule-fedora) |
| Suse | OpenSuse Leap | latest | [jomrr/molecule-opensuse-leap:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-leap) |
| Suse | OpenSuse Tumbleweed | latest | [jomrr/molecule-opensuse-tumbleweed:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-tumbleweed) |
| Debian | Ubuntu | latest | [jomrr/molecule-ubuntu:latest](https://hub.docker.com/r/jomrr/molecule-ubuntu) |

## Example Playbook

### Local Unix mail without TCP listeners

Install an MTA for authorized local sendmail submissions. Enabling SMTP
listeners requires Dovecot and TLS material with the default policy.

```yaml
---
- name: Configure local mail
  hosts: mailservers
  gather_facts: true
  roles:
    - role: jomrr.postfix
      postfix_smtp_enabled: false
```

### File accounts with Dovecot and two provider identities

Dovecot, TLS material and archive mailboxes are provisioned separately. Each
named provider may use the same hostname with different credentials. Vault
variables contain the real secrets.

```yaml
---
- name: Configure submission and fetched mail
  hosts: mailservers
  gather_facts: true
  roles:
    - role: jomrr.postfix
      postfix_hostname: mail.example.org
      postfix_interfaces: [all]
      postfix_submission_enabled: true
      postfix_tls_certificate: /etc/ssl/mail/fullchain.pem
      postfix_tls_private_key: /etc/ssl/mail/key.pem
      postfix_fetchmail_enabled: true
      postfix_virtual_domains: [example.org]
      postfix_mailboxes: [alice@example.org, archive@example.org]
      postfix_virtual_aliases:
        sales@example.org: [alice@example.org]
      postfix_sender_logins:
        alice@example.org: [alice@example.org]
        sales@example.org: [alice@example.org]
      postfix_providers:
        - name: personal
          host: smtp.provider.example
          username: personal-account
          password: "{{ vault_personal_password }}"
        - name: business
          host: smtp.provider.example
          port: 465
          tls: wrapper
          username: business-account
          password: "{{ vault_business_password }}"
      postfix_sender_relays:
        alice@example.org: personal
        sales@example.org: business
      postfix_default_provider: personal
      postfix_sender_bcc:
        alice@example.org: archive@example.org
      postfix_recipient_bcc:
        alice@example.org: archive@example.org
```

### PostfixAdmin with a local MariaDB socket

PostfixAdmin maintains domains, recipients and aliases. Its schema and the
SELECT-only postfix database login already exist. The connection options
below are added to the same playbook as the submission and TLS settings
above.

```yaml
postfix_account_backend: mysql
postfix_database:
  hosts: unix:/run/mysqld/mysqld.sock
  dbname: postfixadmin
  user: postfix
  password: "{{ vault_postfix_database_password }}"
```

### PostfixAdmin with verified PostgreSQL TLS

Store the complete connection URI, including credentials and
sslmode=verify-full, in Ansible Vault. Reference the CA using sslrootcert in
the URI. The role applies the same PostfixAdmin queries to both backends.

```yaml
postfix_account_backend: pgsql
postfix_database:
  hosts: "{{ vault_postfix_postgresql_uri }}"
```

## References

- [Postfix SASL](https://www.postfix.org/SASL_README.html)
- [Postfix TLS](https://www.postfix.org/TLS_README.html)
- [Postfix lookup proxy](https://www.postfix.org/proxymap.8.html)
- [PostfixAdmin SQL integration](https://github.com/postfixadmin/postfixadmin/blob/master/DOCUMENTS/POSTFIX_CONF.txt)
- [Dovecot SASL](https://doc.dovecot.org/main/howto/sasl/postfix.html)
- [Dovecot LMTP](https://doc.dovecot.org/latest/howto/lmtp/postfix.html)

## Author

[Jonas Mauer](https://github.com/jomrr)

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2026 Jonas Mauer.
