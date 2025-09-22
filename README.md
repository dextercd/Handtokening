# Handtokening

Code Signing server written in Django/Python for remotely signing Windows programs with [`osslsigncode`](https://github.com/mtrojnar/osslsigncode).

It has a simple HTTP API to submit files for signing.

It automatically creates test signing resources, supports AV scans (ClamAV and VirusTotal), and keeps a log of every signing operation.

Most of the signing configuration is performed in the Django admin interface.
This is also where the signing logs can be viewed.

Tested on Debian 13 and Arch Linux.

## Deployment

It's not particularly hard to set up, but there are quite a lot of steps.
In summary:

* Create a system user under which the web service will run.
* Install osslsigncode and pcscd/CCID/OpenSC/libp11 for signing code with a hardware token.
* Set up ClamAV daemon for scanning incoming files.
* Create a Python virtualenv and install the application and dependencies in there.
* Configure polkit so the service user can communicate with pcscd.
* Generate a django-secret file with proper permissions set.
* Create an empty file as the sqlite3 database with proper permissions set.
* Deploy the systemd .service/.socket files.
* Write variables to the config file that are appropriate for your setup.
* Expose the service via a reverse proxy; sitting in front of the gunicorn socket.

There's an Ansible role to perform all these steps.
You can use this to automatically deploy the application or as a reference and perform the steps manually.

### Ansible sample config

Here's how I've deployed multiple test servers using the Ansible role:

<details>
<summary>ansible.cfg</summary>

```ini
[defaults]
inventory = hosts.ini
roles_path = /roles:/usr/share/ansible/roles:/etc/ansible/roles:[PATH TO]/handtokening/ansible_roles
vault_password_file = .vaultpass
```

</details>

<details>
<summary>handtokening.yml</summary>

```yml
- hosts: all
  vars_files:
    - handtokening-vars.yml
  tasks:
    - name: Install NGINX
      tags: nginx
      become: true
      ansible.builtin.package:
        name:
          - nginx

    - name: Enable NGINX
      tags: nginx
      become: true
      ansible.builtin.systemd:
        name: nginx.service
        state: started
        enabled: true

    - name: Make NGINX drop-in directory
      tags: nginx
      become: true
      ansible.builtin.file:
        path: /etc/nginx/conf.d
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: NGINX config
      tags: nginx
      become: true
      when: ansible_os_family == 'Archlinux'
      ansible.builtin.copy:
        content: |
          user http;
          worker_processes auto;
          worker_cpu_affinity auto;
          events {
              worker_connections 1024;
          }
          http {
              charset utf-8;
              sendfile on;
              tcp_nopush on;
              tcp_nodelay on;
              server_tokens off;
              log_not_found off;
              types_hash_max_size 4096;
              client_max_body_size 16M;
              # MIME
              include mime.types;
              default_type application/octet-stream;
              # logging
              access_log /var/log/nginx/access.log;
              error_log /var/log/nginx/error.log warn;
              # load configs
              include /etc/nginx/conf.d/*.conf;
              include /etc/nginx/sites-enabled/*;
          }
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: '0644'
      notify: Reload NGINX

    - name: Run Handtokening role
      ansible.builtin.include_role:
        name: handtokening
      tags: always

  handlers:
    - name: Reload NGINX
      become: true
      ansible.builtin.service:
        name: nginx
        state: reloaded
```

</details>

<details>
<summary>handtokening-vars.yml</summary>

```yml
ht_nginx: true
ht_nginx_reload_handler: "Reload NGINX"

ht_host_names:
  - localhost
  - ::1
  - 127.0.0.1
  - "{{ ansible_all_ipv4_addresses[0] }}"
```

</details>

Once this is set up, you can run the following command to deploy the application to all hosts listed in `hosts.ini`:

```sh
ansible-playbook handtokening.yml
```

In a production deployment, you should add/change the following options inside `handtokening-vars.yml`:

```yml
ht_secure: true
ht_host_names:
  - ht.example.com

ht_nginx: true

ht_nginx_server_listen: |
  listen 443 ssl;
  listen [::]:443 ssl;
  ssl_certificate     /etc/nginx/certs/handtokening.fullchain;
  ssl_certificate_key /etc/nginx/certs/handtokening.key;

ht_nginx_location_extra: |
  allow 127.0.0.1;
  allow ::1;
  deny all;

ht_nginx_location_sign_api_extra: 'allow all;'
```

This sets up TLS handling in NGINX and tells Handtokening that it's behind HTTPS.

The `*_extra` config variables are used to enable localhost only access to all Handtokening routes (e.g., the Django admin interface).
The signing API has `allow all;` so that it can be invoked from GitHub Actions, for example.

Of course, the above is just one way of doing things.
You're free to change any of the details or take a completely different approach.
See [defaults/main.yml](ansible_roles/handtokening/defaults/main.yml) for more information on the available role configuration variables.

Some useful environment variables aren't set by the Ansible role.
You can write to `/etc/handtokening/env.extra` to set or override Handtokening environment variables.

### Environment variables

With the standard Ansible role configuration, systemd will launch the service with environment variables from:

* `/etc/handtokening/env`
* `/etc/handtokening/env.extra`

The contents of the `env` file is determined by the Ansible role, and `env.extra` is an optional environment variables file where you can write your own configuration.

<details>
<summary>Detailed list of available environment variables</summary>

#### DJANGO_SETTINGS_MODULE

Standard Django variable: [#DJANGO\_SETTINGS\_MODULE](https://docs.djangoproject.com/en/5.2/topics/settings/#envvar-DJANGO_SETTINGS_MODULE).

Defaults to `handtokening.settings.local`.

Set to `handtokening.settings.prod` by the Ansible role.

This should be set to `handtokening.settings.prod` normally.
This module is responsible for loading settings from environment variables.
It also sets many of the default values listed below.

#### DJANGO_LOG_LEVEL

Determines the log level of the root logger. Set to `WARNING` by default.

#### UNSAFE_DEBUG

Used to set the standard Django variable: [#DEBUG](https://docs.djangoproject.com/en/5.2/ref/settings/#debug).

This should not be set to true on a production deployment,
as it makes the application return internal details when error occur.

#### OSSL_PROVIDER_PATH

Path to a OpenSSL provider module that allows OpenSSL use PKCS #11 modules.
This is passed to `osslsigncode` using the `-provider` option.

This is set to a operating system specific default or is not set if it couldn't be found.

#### OSSL_ENGINE_PATH

Path to a OpenSSL engine module that allows OpenSSL use PKCS #11 modules.
This is passed to `osslsigncode` using the `-pkcs11engine` option.

This is an older OpenSSL extension mechanism and is only used if `OSSL_PROVIDER_PATH` is not set.

This is set to a operating system specific default or is not set if it couldn't be found.

#### PKCS11_MODULE_PATH

The PKCS #11 module to use for pkcs11-enabled certificates if no certificate-specific module is configured.

Defaults to OpenSC's PKCS #11 module on Arch and Debian.

Set to the OpenSC PKCS #11 module by the Ansible role.

#### OSSLSIGNCODE_PATH

Defaults to `osslsigncode` which means it will look up the application on the `$PATH` list.

#### CLAMSCAN_PATH

Defaults to `/usr/bin/clamdscan`. You could change this to `/usr/bin/true` to skip ClamAV scans.

#### STATE_DIRECTORY

Normally set by systemd to `/var/lib/handtokening`.

#### CONFIGURATION_DIRECTORY

Normally set by systemd to `/etc/handtokening`.

#### RUNTIME_DIRECTORY

Normally set by systemd to `/run/handtokening`.

#### HOME

It's normally set by systemd to `/home/handtokening`.

Used to set the `STATIC_ROOT` variable unless it's set directly.

#### STATIC_ROOT

Standard Django variable: [#STATIC\_ROOT](https://docs.djangoproject.com/en/5.2/ref/settings/#static-root).

Used as the destination directory when running `django-admin collectstatic`.

#### STATIC_URL

Standard Django variable: [#STATIC\_URL](https://docs.djangoproject.com/en/5.2/ref/settings/#static-url)

Set to `static/` by default.

#### IPWARE_META_PRECEDENCE_ORDER

Comma separated list of sources from which the original requester IP address can be retrieved.
This should be properly configured so that the IP address in the logs is accurate and also can't be spoofed maliciously.

Automatically configured by Ansible to `HTTP_X_REAL_IP` if the `ht_nginx` role variable is set to `true`.

Set to `REMOTE_ADDR` if not configured.

#### ALLOWED_HOSTS

Standard Django variable: [#ALLOWED\_HOSTS](https://docs.djangoproject.com/en/5.2/ref/settings/#allowed-hosts)

Comma separated list of host names that the service should respond to.
Any request for a host name that's not on this list will be rejected.

Automatically configured by the Ansible role to the `ht_host_names` list.

#### USE_X_FORWARDED_HOST

Standard Django variable: [#USE\_X\_FORWARDED\_HOST](https://docs.djangoproject.com/en/5.2/ref/settings/#use-x-forwarded-host)

Set to `False` by default.

#### USE_X_FORWARDED_PORT

Standard Django variable: [#USE\_X\_FORWARDED\_PORT](https://docs.djangoproject.com/en/5.2/ref/settings/#use-x-forwarded-port)

Set to `False` by default.

#### SCRIPT_NAME

Subdirectory that the application is accessible under. Must match with the reverse proxy configuration.

It should start but NOT end with a trailing slash.

Automatically configured by the Ansible role using the `ht_path` variable.

#### SAMESITE

The [`SameSite`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value) value to add to cookies.
Defaults to `Lax`.

#### CSRF_COOKIE_AGE

Standard Django variable: [#CSRF\_COOKIE\_AGE](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-cookie-age)

Expiration time of the CSRF cookie. Defaults to 31449600 (1 year in seconds).

#### SESSION_COOKIE_AGE

Standard Django variable: [#SESSION\_COOKIE\_AGE](https://docs.djangoproject.com/en/5.2/ref/settings/#session-cookie-age)

Expiration time of the session cookie. Defaults to 31449600 (1 year in seconds).

#### COOKIE_SECURE

Whether to set the `Secure` flag on the cookies. This means the cookies are only transferred by the browser over https.

Set by the Ansible role to true if `ht_secure` is set to true.

Defaults to `False`.

#### LANGUAGE_COOKIE_NAME

Standard Django variable: [#LANGUAGE\_COOKIE\_NAME](https://docs.djangoproject.com/en/5.2/ref/settings/#language-cookie-name)

Set to `django_language` by default.

#### CSRF_COOKIE_NAME

Standard Django variable: [#CSRF\_COOKIE\_NAME](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-cookie-name)

Set to `csrftoken` by default.

#### SESSION_COOKIE_NAME

Standard Django variable: [#SESSION\_COOKIE\_NAME](https://docs.djangoproject.com/en/5.2/ref/settings/#session-cookie-name)

Set to `sessionid` by default.

#### CSRF_HEADER_NAME

Standard Django variable: [#CSRF\_HEADER\_NAME](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-header-name)

Set to `HTTP_X_CSRFTOKEN` by default.

#### CSRF_TRUSTED_ORIGINS

Standard Django variable: [#CSRF\_TRUSTED\_ORIGINS](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-trusted-origins)

#### SESSION_EXPIRE_AT_BROWSER_CLOSE

Standard Django variable: [#SESSION\_EXPIRE\_AT\_BROWSER\_CLOSE](https://docs.djangoproject.com/en/5.2/ref/settings/#session-expire-at-browser-close)

#### CSRF_USE_SESSIONS

Standard Django variable: [#CSRF\_USE\_SESSIONS](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-use-sessions)

#### SECURE_HSTS_INCLUDE_SUBDOMAINS

Standard Django variable: [#SECURE\_HSTS\_INCLUDE\_SUBDOMAINS](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-hsts-include-subdomains)

#### SECURE_HSTS_PRELOAD

Standard Django variable: [#SECURE\_HSTS\_PRELOAD](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-hsts-preload)

#### SECURE_HSTS_SECONDS

Standard Django variable: [#SECURE\_HSTS\_SECONDS](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-hsts-seconds)

#### SECURE_PROXY_SSL_HEADER

Standard Django variable: [#SECURE\_PROXY\_SSL\_HEADER](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-proxy-ssl-header)

Header name followed by value that specifies that the request started out as HTTP**S**.

Configured to `HTTP_X_FORWARDED_PROTO,https` by the Ansible role if `ht_nginx` is set to true.

Unset by default.

#### SECURE_SSL_HOST

Standard Django variable: [#SECURE\_SSL\_HOST](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-ssl-host)

#### SECURE_SSL_REDIRECT

Standard Django variable: [#SECURE\_SSL\_REDIRECT](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-ssl-redirect)

#### WEB_CONCURRENCY

Standard Gunicorn option: [#workers](https://docs.gunicorn.org/en/stable/settings.html#workers)

Amount of worker processes to spawn for handling incoming requests.

Set by the Ansible role to `ht_workers` (defaults to 4).

This is one of many environment variables read by Gunicorn.
Read its documentation to see what other options are available.
</details>

## Admin interface

The Ansible role deploys a `run-ht` script in the `handtokening` user's home directory for running administration commands with the right environment variables set.
All arguments provided to the script are passed to `systemd-run`.

The database migrations are automatically run when the service starts,
but you may want to run them manually the first time:

```sh
sudo ~handtokening/run-ht --pty --collect django-admin migrate
```

To create an admin user, run the following command and follow the interactive steps:

```sh
sudo ~handtokening/run-ht --pty --collect django-admin createsuperuser
```

See the [Django admin documenation](https://docs.djangoproject.com/en/5.2/ref/django-admin/) or run `django-admin help [<command>]` for more details.

Once an admin user is created, you can open the `/admin/login/` and sign in.
From here, you can create certificates, signing profiles, users/clients, and review signing logs.

You can add timestamping servers via the admin interface or run the following command to import a standard list of servers:

```sh
sudo ~handtokening/run-ht --pty --collect django-admin add_timestamp_server --add-standard-servers
```

Timestamp servers must be added to a signing profile before they're used.

## License

Handtokening code signing server.
Copyright (C) 2025  Dexter Castor Döpping

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
