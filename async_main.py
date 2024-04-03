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

# Load the config file
config = configparser.ConfigParser()
config.read("smb_lock_mgr.conf")
CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]
TOKEN = config["CLUSTER"]["TOKEN"]
CONFIG_SAVE_FILE_LOCATION = os.path.join(os.getcwd(), '')
USE_SSL = config["CLUSTER"].getboolean('USE_SSL')
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

redis_host = 'localhost'  
redis_port = 6379  
redis_db = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)  

# Disable "Insecure HTTP" errors if certs are not available
if not USE_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default Flask route on page load
@app.route('/')
async def index():
    return await render_template('index.html')

# Search function
@app.route('/search_files', methods=['POST'])
async def search_files():

    # Grab the user's input from the web UI
    form_data = await request.form
    query = form_data['query'].lower()

    # Grab all open file handles and the holder's auth ID
    open_files, handle_owner = path_loader()

    smb_locks_raw = redis_db.get('smb_locks')  # Retrieve from Redis
    if smb_locks_raw:
        smb_locks = json.loads(smb_locks_raw)  # Deserialize
    else:
        smb_locks = {}  # Or some default value
    
    if query != "":
        matching_file_ids = [file_id for file_id, file_path in open_files.items() if query in file_path.lower()]
        lock_data = []
        for grant in smb_locks["grants"]:
            if grant["file_id"] in matching_file_ids:
                id = grant["file_id"]
                holder_ip_address = grant["owner_address"]
                if len(matching_file_ids) > 100:
                    owner = "Too many locks"
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
                owner = "Too many locks"
            else:
              owner = await resolve_owner(handle_owner[id]).get('name')
            try:
                file_path = open_files[id]
            except:
                print(f"File Handle {id} already closed?")
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
def path_loader():

    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/files/?resolve_paths=true"
    
    response = requests.get(url, headers=HEADERS, verify=False).json()
    handles = response['file_handles']
    redis_db.set('handles', json.dumps(handles))
    next = response['paging']['next']

    # If there are response pages to load, continue, esle return values
    if next != None:
        # Modify the url with pagination 'next' info for passes after the first response
        url = f"https://{CLUSTER_ADDRESS}/api" + next
        
        # Loop to handle API pagination
        while next:
            response = requests.get(url, headers=HEADERS, verify=False).json()
            next = response['paging']['next']
            if next != None:
                url = f"https://{CLUSTER_ADDRESS}/api" + next
            handles.extend(response['file_handles'])
            redis_db.set('handles', json.dumps(handles))

    # This contains a file ID to path k,v index of all open files, we need this to display paths in the
    # GUI since  /v1/files/locks/smb/share-mode/ does not resolve paths
    file_number_to_path = {handle["file_number"]: handle["handle_info"]["path"] for handle in handles}
    file_number_to_owner = {handle["file_number"]: handle["handle_info"]["owner"] for handle in handles}
    return file_number_to_path, file_number_to_owner

# Assitant function to close_handles() - This generates the complete JSON needed to close a handle
def find_handle(file_id):
    # Attempt to retrieve and deserialize the data from Redis
    handles_raw = redis_db.get('handles')
    if handles_raw:
        handles = json.loads(handles_raw)
    else:
        # If there's no data in Redis, initialize handles to an empty list
        handles = []

    # Iterate over the deserialized list of handles
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
            # print("HANDLE", handle)
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
                        # return jsonify({"message": f"File handle of {handle['handle_info']['path']} has been closed"})
                    else:
                        response_text = await response.text()
                        return jsonify({"error": f"Error closing file handle!! {response.status} - {response_text}"}), 500
        else:
            return jsonify({"error": "File handle not found"}), 404

    return jsonify({"message": "Selected locks have been closed"}), 200


async def main():
    await hypercorn.asyncio.serve(app)

if __name__ == '__main__':
    client.loop.set_debug(True)
    client.loop.run_until_complete(main())