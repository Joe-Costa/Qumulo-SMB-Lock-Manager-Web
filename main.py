from flask import Flask, render_template, request, jsonify
import requests
import urllib3

app = Flask(__name__)

token = "access-v1:foo..bar"
cluster_address = "my.server.co.com"
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}


# Disable InsecureRequestWarning from showing up in stdout; this is not needed if you have valid TLS certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default Flask route on page load
@app.route('/')
def index():
    return render_template('index3.html')

# Search function
@app.route('/search_files', methods=['POST'])
def search_files():

    # Grab the user's input from the web UI
    query = request.form['query'].lower()  
    
    
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
                    owner = resolve_owner(handle_owner[id]).get('name')
                # owner = resolve_owner(handle_owner[id])
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
              owner = resolve_owner(handle_owner[id]).get('name')
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
def get_smb_locks():
    global open_files
    global smb_locks
    global handle_owner

    url = f"https://{cluster_address}/api/v1/files/locks/smb/share-mode/"

    # Grab the initial API response
    try:
        response = requests.get(url, headers=headers, verify=False)
        after_cursor = response.json().get('paging', {})

    ######
    ######      this error handler is still broken !! #####
    ######
    except:
        error = f"Error authenticating or reaching the cluster! {response.status_code} - {response.text}"
        return jsonify({"error": error}), 400

    # Load first page of locks in smb_locks or exit if status code is not 200
    if response.status_code == 200:
        smb_locks = response.json()
    else:
        print(f"Error getting SMB locks! {response.status_code} - {response.text}")
        return None

    # Modify the URL with the pagination info after the first API response
    url = f"https://{cluster_address}/" + after_cursor['next'][1:]

    # Continue loading smb_locks as long as there are grants
    while response.json().get('grants'):
        response = requests.get(url, headers=headers, verify=False)
        after_cursor = response.json().get('paging', {})
        if response.json().get('grants'):
            smb_locks = {'grants': smb_locks['grants'] + response.json()['grants']}
        # Update url with the next page
        url = f"https://{cluster_address}/" + after_cursor['next'][1:]
    
    # open_handles = path_loader()
    open_files, handle_owner = path_loader()
    locks_count = len(smb_locks.get('grants', []))
    # print("OWNER", handle_owner)
    # return jsonify({"locks_count": locks_count},{"handle_count": handle_count})
    return jsonify({"locks_count": locks_count})

# Convert auth_id to user name
def resolve_owner(owner):
    url = f"https://{cluster_address}/api/v1/identity/find"
    owner_json = { "auth_id": f"{owner}"}
    # print("OWNER JSON", owner_json)
    owner_name = requests.post(url, headers=headers, json=owner_json, verify=False).json()
    # print("OWNER NAME",owner_name)
    return(owner_name)


# Load all currently held SMB file handles
def path_loader():

    global handles

    url = f"https://{cluster_address}/api/v1/smb/files/?resolve_paths=true"
    
    response = requests.get(url, headers=headers, verify=False).json()
    handles = response['file_handles']
    next = response['paging']['next']

    # If there are response pages to load, continue, esle return values
    if next != None:
        # Modify the url with pagination 'next' info for passes after the first response
        url = f"https://{cluster_address}/api" + next
        
        # Loop to handle API pagination
        while next:
            response = requests.get(url, headers=headers, verify=False).json()
            next = response['paging']['next']
            if next != None:
                url = f"https://{cluster_address}/api" + next
            handles.extend(response['file_handles'])

    # This contains a file ID to path k,v index of all open files, we need this to display paths in the
    # GUI since  /v1/files/locks/smb/share-mode/ does not resolve paths
    file_number_to_path = {handle["file_number"]: handle["handle_info"]["path"] for handle in handles}
    file_number_to_owner = {handle["file_number"]: handle["handle_info"]["owner"] for handle in handles}
    return file_number_to_path, file_number_to_owner

# Assitant function to close_handle()
def find_handle(file_id):
    global handles
    for keys in handles:
        if keys["file_number"] == str(file_id):
            return keys
    return None

# Close file handle returned by JS from web UI
@app.route('/close_handle', methods=['POST'])
def close_handle():
    file_id = request.json['file_id']
    handle = find_handle(file_id)
    if handle:
        url = f"https://{cluster_address}/api/v1/smb/files/close"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        response = requests.post(url, headers=headers, json=[handle], verify=False)
        if response.status_code == 200:
            return jsonify({"message": f"File handle of {handle['handle_info']['path']} has been closed"})
        else:
            return jsonify({"error": f"Error closing file handle!! {response.status_code} - {response.text}"}), 500
    else:
        return jsonify({"error": "File handle not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)
