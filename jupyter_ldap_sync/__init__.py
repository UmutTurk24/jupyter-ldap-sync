
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

async def get_ldap_users(ldap_url, base_dn, ldap_username, ldap_password, ldap_group):
    """
    Get the users from the LDAP group
    """
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
        app_log.error(f"Group '{ldap_group}' not found in LDAP server")
        exit()
    
    # Turn from bytes to string
    member_dns = list(map(lambda x: x.decode('utf-8'), group_members[0][1]['member']))
    # Extract CN from DN
    members = list(map(lambda x: x.split(',')[0].split('=')[1], member_dns))

    return members

async def test_jupyterhub_connection(jupyter_url, token):
    """
    Test the connection to the JupyterHub
    """
    try:
        await AsyncHTTPClient().fetch(HTTPRequest(
            url=f'{jupyter_url}/hub/api',
            method='GET',
            headers=HTTPHeaders({
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'authorization': f'token {token}',
            }),
        ))
    except Exception as e:
        app_log.error(f"Error connecting to JupyterHub: {e}")
        exit()

async def test_jupyterhub_group(jupyter_url, token, ldap_group, client):
    
    try: 
        url = f'{jupyter_url}/hub/api/groups/{ldap_group}'
        headers = HTTPHeaders({
            'accept': 'application/json',
            'authorization': f'token {token}',
        })
        
        await client.fetch(HTTPRequest(
            url=url,
            method='GET',
            headers=headers,
        ))
    except Exception as e:        
        app_log.info(f"Error retrieving the group information from JupyterHub: {e}\n \
                     Creating group {ldap_group} in JupyterHub.")
        
        url = f'{jupyter_url}/hub/api/groups/{ldap_group}'
        headers = HTTPHeaders({
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'authorization': f'token {token}',
        })
        response = await client.fetch(HTTPRequest(
            url=url,
            method='POST',
            headers=headers,
            body=json.dumps({}), # Expects a JSON object
        ))
    
async def get_current_group_members(jupyter_url, token, ldap_group, client):
    """
    Get the current members of the group in JupyterHub
    """
    current_members = []
    try:
        url = f"{jupyter_url}/hub/api/groups/{ldap_group}"
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'authorization': f'token {token}',
        }
        response = await client.fetch(HTTPRequest(
            url=url,
            method='GET',
            headers=headers,
        ))
        current_members = json.loads(response.body.decode('utf-8'))['users']
    except Exception as e:
        app_log.error(f"Error retrieving the current members of the group: {e}")
        exit()
    return current_members

async def get_all_users(jupyter_url, token, client):
    """
    Get all the users in JupyterHub
    """
    all_users = []
    try:
        url = f"{jupyter_url}/hub/api/users"
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'authorization': f'token {token}',
        }
        response = await client.fetch(HTTPRequest(
            url=url,
            method='GET',
            headers=headers,
        ))
        all_users = list(map(lambda x: x['name'], json.loads(response.body.decode('utf-8'))))
    except Exception as e:
        app_log.error(f"Error retrieving the current users of the JupyterHub: {e}")
        exit()
    return all_users

async def create_users(jupyter_url, token, users_to_create, client):  
    """
    Create users in JupyterHub
    """
    for member in users_to_create:
        try:
            url = f"{jupyter_url}/hub/api/users/{member}"
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'authorization': f'token {token}',
            }
            await client.fetch(HTTPRequest(
                url=url,
                method='POST',
                headers=headers,
                body=json.dumps({ 'name': member }),
            ))
        except Exception as e:
            app_log.error(f"Error creating user {member} in JupyterHub: {e}")

async def add_remove_users(jupyter_url, token, ldap_group, members_to_add, members_to_remove, client):
    """
    Add or remove users from the group in JupyterHub
    """
    try: 
        url = f"{jupyter_url}/hub/api/groups/{ldap_group}/users"

        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'authorization': f'token {token}',
        }
        json_data = json.dumps({ 'users': members_to_add })
        print(json_data)
        response = await client.fetch(HTTPRequest(
            url=url,
            method='POST',
            headers=headers,
            body=json_data,
        ))
        app_log.info(f"Added {len(members_to_add)} users to JupyterHub")

    except Exception as e:
        app_log.error(f"Error adding users to JupyterHub: {e}")
    
    # Remove the members from the group in JupyterHub
    for member in members_to_remove:
        try:
            url = f"{jupyter_url}/hub/api/groups/{ldap_group}/users/{member}"
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'authorization': f'token {token}',
            }
            response = await client.fetch(HTTPRequest(
                url=url,
                method='DELETE',
                headers=headers,
            ))
            app_log.info(f"Removed {member} users from JupyterHub")
        except Exception as e:
            app_log.error(f"Error removing user {member} from JupyterHub: {e}")

async def sync_users(ldap_url, base_dn, ldap_username, ldap_password, ldap_group, jupyter_url, token, sync_every):
    print("sync_users:", ldap_url, base_dn, ldap_username, ldap_password, ldap_group, jupyter_url, token, sync_every)

    # Get the group members from LDAP
    members = await get_ldap_users(ldap_url, base_dn, ldap_username, ldap_password, ldap_group)
    app_log.info(f"Found {len(members)} members in LDAP group '{ldap_group}'")

    # Check if JupyterHub is reachable
    await test_jupyterhub_connection(jupyter_url, token)

    # Retrieve the group information from JupyterHub 
    client = AsyncHTTPClient()
    
    # Check if the group exists in JupyterHub, if not create it.
    await test_jupyterhub_group(jupyter_url, token, ldap_group, client)
    
    # Get the current members for the group
    current_members = await get_current_group_members(jupyter_url, token, ldap_group, client)

    # Check if the members are already in the group
    members_to_add = list(set(members) - set(current_members))
    members_to_remove = list(set(current_members) - set(members))

    # Get all the users in JupyterHub
    all_users = await get_all_users(jupyter_url, token, client)
    
    # Check if the users are already in JupyterHub
    users_to_create = list(set(members_to_add) - set(all_users))

    # Create users in JupyterHub if they don't exist
    await create_users(jupyter_url, token, users_to_create, client)

    # Add the members to the group in JupyterHub
    await add_remove_users(jupyter_url, token, ldap_group, members_to_add, members_to_remove, client)

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
        default="https://jupyter.davidson.edu",
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