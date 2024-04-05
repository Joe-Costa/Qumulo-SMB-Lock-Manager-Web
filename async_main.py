from quart import Quart, render_template, request, jsonify
import requests
import urllib3
import os
import configparser
import json
import redis
import asyncio
import aiohttp

app = Quart(__name__)

# Load and apply the config file
config = configparser.ConfigParser()
config.read("async_main.conf")
CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]
TOKEN = config["CLUSTER"]["TOKEN"]
CONFIG_SAVE_FILE_LOCATION = os.path.join(os.getcwd(), '')
USE_SSL = config["CLUSTER"].getboolean('USE_SSL')
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}
required_rights = ['PRIVILEGE_FS_LOCK_READ', 'PRIVILEGE_SMB_FILE_HANDLE_READ', 'PRIVILEGE_SMB_FILE_HANDLE_WRITE']

redis_host = 'redis'  
redis_port = 6379  
redis_db = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)  

# Disable "Insecure HTTP" errors if certs are not available
if not USE_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lookup user name and rights
def verify_id_and_rights():
    url = f"https://{CLUSTER_ADDRESS}/api/v1/session/who-am-i"
    user_info = requests.get(url, headers=HEADERS, verify=False).json()
    who_am_i = user_info['name']
    user_rbac_privileges = user_info['privileges']
    matching_rights = [ x for x in required_rights if x in user_rbac_privileges]

    if set(matching_rights) == set(required_rights):
        user_has_rights = True
    else:
        user_has_rights = False
        # s = set(matching_rights)
        # missing_rights = [ x for x in required_rights if x not in s]
        # user_has_rights = f"User {who_am_i} is missing these required RBAC privileges:\n {missing_rights}"
    return who_am_i, user_has_rights

# place a verify_connectivity function
who_am_i, user_allowed = verify_id_and_rights()

# Default Flask route on page load
if user_allowed:
    @app.route('/')
    async def index():
        return await render_template('index.html', who_am_i=who_am_i, cluster_address=CLUSTER_ADDRESS)
else:
    @app.route('/')
    async def index():
        return await render_template('access_denied.html')

# Search function
@app.route('/search_files', methods=['POST'])
async def search_files():

    # Grab the user's input from the web UI
    form_data = await request.get_json()
    if form_data != None:
        query = form_data['query']
    else:
        query = ""

    # Grab all open file handles and the holder's auth ID
    open_files, handle_owner = await path_loader()

    smb_locks_raw = redis_db.get('smb_locks')  # Retrieve from Redis
    if smb_locks_raw:
        smb_locks = json.loads(smb_locks_raw)  # Deserialize
    else:
        smb_locks = {}  
    
    if query != "":
        matching_file_ids = [file_id for file_id, file_path in open_files.items() if query in file_path.lower()]
        lock_data = []
        for grant in smb_locks["grants"]:
            if grant["file_id"] in matching_file_ids:
                id = grant["file_id"]
                holder_ip_address = grant["owner_address"]
                if len(matching_file_ids) > 100:
                    owner = "Too many locks to show"
                else:
                    owner = await resolve_owner(handle_owner[id])
                    owner = owner.get('name')
                try:
                    file_path = open_files[id]
                except:
                    print(f"File Handle {id} already closed?")
                    continue
                if query in file_path.lower() or query in holder_ip_address.lower():
                    lock_data.append({
                        "file_id": grant.get("file_id", ""),
                        "file_path": file_path,
                        "mode": ", ".join(grant.get("mode", [])),
                        "user": owner,
                        "owner_address": grant.get("owner_address", ""),
                        "node_address": grant.get("node_address", "")
                    })

    # List every lock if user sends a blank search form
    else:
        lock_data = []
        for grant in smb_locks["grants"]:
            id = grant["file_id"]
            holder_ip_address = grant["owner_address"]
            if len(smb_locks.get('grants', [])) > 100:
                owner = "Too many locks to show"
            else:
                if id in handle_owner:
                    owner = (await resolve_owner(handle_owner[id])).get('name')
                else:
                    continue
            try:
                file_path = open_files[id]
            except:
                continue
            lock_data.append({
                "file_id": grant.get("file_id", ""),
                "file_path": file_path,
                "mode": ", ".join(grant.get("mode", [])),
                "user": owner,
                "owner_address": grant.get("owner_address", ""),
                "node_address": grant.get("node_address", "")
            })
    return jsonify(lock_data)

# Get all currently open SMB locks 
@app.route('/get_smb_locks', methods=['GET'])
async def get_smb_locks():

    url = f"https://{CLUSTER_ADDRESS}/api/v1/files/locks/smb/share-mode/"

    # Grab the initial API response
    try:
        response = requests.get(url, headers=HEADERS, verify=False)
        after_cursor = response.json().get('paging', {})
    ######  Most error handlers are still broken !! #####
    except:
        error = f"Error authenticating or reaching the cluster! {response.status_code} - {response.text}"
        return jsonify({"error": error}), 400

    # Load first page of locks in smb_locks or exit if status code is not 200
    if response.status_code == 200:
        smb_locks = response.json()
        redis_db.set('smb_locks', json.dumps(smb_locks))
    else:
        print(f"Error getting SMB locks! {response.status_code} - {response.text}")
        return None

    # Modify the URL with the pagination info after the first API response
    url = f"https://{CLUSTER_ADDRESS}/" + after_cursor['next'][1:]

    # Continue loading smb_locks as long as there are grants
    while response.json().get('grants'):
        response = requests.get(url, headers=HEADERS, verify=False)
        after_cursor = response.json().get('paging', {})
        if response.json().get('grants'):
            smb_locks = {'grants': smb_locks['grants'] + response.json()['grants']}
            redis_db.set('smb_locks', json.dumps(smb_locks))
        # Update url with the next page
        url = f"https://{CLUSTER_ADDRESS}/" + after_cursor['next'][1:]
    
    locks_count = len(smb_locks.get('grants', []))
    return jsonify({"locks_count": locks_count})

# @app.route('/get_smb_locks', methods=['GET'])
# async def get_smb_locks():
#     url = f"https://{CLUSTER_ADDRESS}/api/v1/files/locks/smb/share-mode/"

#     smb_locks = {'grants': []}  # Initialize smb_locks to collect data

#     async with aiohttp.ClientSession() as session:  # Use aiohttp's session
#         while url:
#             async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
#                 if response.status == 200:
#                     json_response = await response.json()

#                     # Extend the smb_locks list with new grants
#                     smb_locks['grants'].extend(json_response.get('grants', []))

#                     # Attempt to get the 'next' pagination URL
#                     next_page = json_response.get('paging', {}).get('next', None)
#                     if next_page:
#                         # Update the URL for the next iteration with the pagination info
#                         url = f"https://{CLUSTER_ADDRESS}/{next_page[1:]}"
#                     else:
#                         # No more pages, break the loop
#                         url = None
#                 else:
#                     # Handle non-200 responses
#                     error = f"Error retrieving SMB locks: {response.status} - {await response.text()}"
#                     return jsonify({"error": error}), 400

#     # After collecting all locks, save them in Redis
#     redis_db.set('smb_locks', json.dumps(smb_locks))
#     locks_count = len(smb_locks.get('grants', []))
#     return jsonify({"locks_count": locks_count})

# Convert auth IDs to usernames
async def resolve_owner(owner):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/identity/find"
    owner_json = {"auth_id": f"{owner}"}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=owner_json, headers=HEADERS, ssl=False) as response:  
            if response.status == 200:
                owner_name = await response.json()
                return owner_name
            else:
                # Need to fix this error handler still
                return {"error": f"Failed to resolve owner: HTTP {response.status}"}

# Load all currently held SMB file handles


async def fetch_page(session, url):
    """Fetch a single page and return the JSON response."""
    async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
        if response.status == 200:
            return await response.json()
        else:
            return None

async def fetch_all_pages(base_url):
    """Fetch all pages concurrently and return the combined list of handles."""
    async with aiohttp.ClientSession() as session:
        response = await fetch_page(session, base_url)
        if not response:
            return [], []

        handles = response['file_handles']
        next_page = response['paging'].get('next')

        tasks = []
        while next_page:
            url = f"https://{CLUSTER_ADDRESS}/api" + next_page
            task = asyncio.create_task(fetch_page(session, url))
            tasks.append(task)
            # Assuming the response structure allows us to fetch the next URL before fetching its content
            next_page = (await task).get('paging', {}).get('next')

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                handles.extend(result['file_handles'])

        return handles

async def path_loader():
    base_url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/files/?resolve_paths=true"
    handles = await fetch_all_pages(base_url)

    # Process handles to create mappings
    file_number_to_path = {handle["file_number"]: handle["handle_info"]["path"] for handle in handles}
    file_number_to_owner = {handle["file_number"]: handle["handle_info"]["owner"] for handle in handles}

    # After collecting all handles, save them in Redis
    redis_db.set('handles', json.dumps(handles))

    return file_number_to_path, file_number_to_owner

# Assitant function to close_handles() - This generates the complete JSON needed to close a handle
def find_handle(file_id):
    handles_raw = redis_db.get('handles')
    if handles_raw:
        handles = json.loads(handles_raw)
    else:
        handles = []
    for handle in handles:
        # Check if the current handle matches the file_id being sought
        if handle.get("file_number") == str(file_id):
            return handle
    # Return None if no matching handle is found
    return None

# Close file handle returned by JS from web UI
@app.route('/close_handles', methods=['POST'])
async def close_handles():
    data = await request.get_json()
    file_ids = data['file_ids']
    for id in file_ids:
        handle = find_handle(str(id))
        if handle:
            url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/files/close"
            headers = {
                "Authorization": f"Bearer {TOKEN}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=[handle], ssl=False) as response:
                    if response.status == 200:
                        pass
                        # return jsonify({"message": f"File handle of {handle['handle_info']['path']} has been closed"}), 200
                    else:
                        response_text = await response.text()
                        return jsonify({"error": f"Error closing file handle!! {response.status} - {response_text}"}), 500
        else:
            return jsonify({"error": "File handle not found"}), 404

    return jsonify({"message": "Selected locks have been released"}), 200


async def main():
    await hypercorn.asyncio.serve(app)


if __name__ == '__main__':
    client.loop.set_debug(True)
    client.loop.run_until_complete(main())