
#!/home/umut/GitHub/jupyter-ldap-sync/.venv/bin python 

import asyncio
import json
import os
import ssl

import ldap
import json

from datetime import datetime, timezone
from functools import partial
from textwrap import dedent

from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat, HTTPHeaders
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.log import app_log
from tornado.options import define, options, parse_command_line



async def sync_users(ldap_url, base_dn, ldap_username, ldap_password, ldap_group, jupyter_url, token, sync_every, concurrency):
    print("sync_users:", ldap_url, base_dn, ldap_username, ldap_password, ldap_group, jupyter_url, token, sync_every, concurrency)

    # Initialize ldap connection
    try:
        l = ldap.initialize(ldap_url)
        l.set_option(ldap.OPT_REFERRALS, 0)
        l.simple_bind_s(ldap_username, ldap_password)
    except ldap.LDAPError as e:
        app_log.error(f"Error connecting to LDAP server: {e}")
        exit()
    
    # Get the group members from LDAP
    group_members = l.search_s(base_dn, ldap.SCOPE_SUBTREE, f'cn={ldap_group}', ['member'])

    # Check if the group exists in LDAP
    if not any(isinstance(sublist[0], str) for sublist in group_members if sublist):
        print(f"Group '{ldap_group}' not found in LDAP server")
        exit()
    
    # Turn from bytes to string
    member_dns = list(map(lambda x: x.decode('utf-8'), group_members[0][1]['member']))

    # Filter Faculty
    faculty = list(map(lambda x: x.split(',')[0].split('=')[1], filter(lambda x: 'OU=Faculty' in x, member_dns)))


    # Filter Students
    students = list(map(lambda x: x.split(',')[0].split('=')[1], filter(lambda x: 'OU=Class_' in x, member_dns)))


    print(faculty)
    print(students)



    # Extract CN from DN
    members = list(map(lambda x: x.split(',')[0].split('=')[1], member_dns))

    # Initialize JupyterHub API connection
    # client = AsyncHTTPClient()
    # headers = HTTPHeaders({
    #     'accept': 'application/json',
    #     'Content-Type': 'application/json',
    #     'authorization': 'token debf1479c83f48bb9967ba2871e9ced4',
    # })

    # # send a request to the JupyterHub API
    # request = HTTPRequest(
    #     url="https://jupyter.davidson.edu/hub/api/users",
    #     method='GET',
    #     headers=headers,
    # )
    # resp = await client.fetch(request)
    # print(resp.body)
    # return resp.body




def main():
    
    define(
        "ldap_url",
        default="ldap://huey.davidson.edu",
        help=dedent(
            """
            The LDAP Server URL.
            """
        ).strip(),
    )
    define(
        "base_dn",
        default="dc=davidson,dc=edu",
        help=dedent(
            """
            The LDAP Server search base_dn.
            """
        ).strip(),
    )
    define(
        "ldap_username",
        help=dedent(
            """
            The LDAP Server username.
            """
        ).strip(),
    )
    define(
        "ldap_password",
        help=dedent(
            """
            The LDAP Server password.
            """
        ).strip(),
    )
    define(
        "ldap_group",
        help=dedent(
            """
            The LDAP class-group to sync.
            """
        ).strip(),
    )
    define(
        "jupyter_url",
        help=dedent(
            """
            The JupyterHub API URL.
            """
        ).strip(),
    )
    define(
        "token",
        help=dedent(
            """
            The JupyterHub API token for authorization.
            """
        ).strip(),
    )
    define(
        "sync_every",
        type=int,
        default=60*15,
        help=dedent(
            """
            The interval (in seconds) for checking for idle servers to sync.
            """
        ).strip(),
    )
    define(
        "concurrency",
        type=int,
        default=10,
        help=dedent(
            """
            Limit the number of concurrent requests made to the Hub.

            Deleting a lot of users at the same time can slow down the Hub,
            so limit the number of API requests we have outstanding at any given time.
            """
        ).strip(),
    )

    parse_command_line()

    try:
        AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
    except ImportError as e:
        app_log.warning(
            f"Could not load pycurl: {e}\n"
            "pycurl is recommended if you have a large number of users."
        )

    loop = IOLoop.current()
    sync = partial(
        sync_users,
        ldap_url=options.ldap_url,
        base_dn=options.base_dn,
        ldap_username=options.ldap_username,
        ldap_password=options.ldap_password,
        ldap_group=options.ldap_group,
        jupyter_url=options.jupyter_url,
        token=options.token,
        sync_every=options.sync_every,
        concurrency=options.concurrency,
    )

    print(sync)

    
    loop.add_callback(sync)
    pc = PeriodicCallback(sync, options.sync_every * 1000)
    pc.start()
    try:
        loop.start()
    except KeyboardInterrupt:
        loop.stop()
    

    
if __name__ == "__main__":
    main()