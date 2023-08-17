#!/usr/bin/env python3
"""
Resolves ida:// and disas:// URIs to the correct IDA instance. Finds correct IDB file and opens IDA if not found.
Exit Codes:
1 - IDB not found
0 - Success
-1 - Settings file does not exist
-2 - Settings file was invalid
-3 - Platform not supported for opening IDA
-4 - Invalid URI to open
-5 - Too many invalid endpoints
-6 - Endpoint poll timed out
"""
import sys

import logging as log
from urllib.parse import urlparse, parse_qsl, unquote
from typing import Optional, Tuple, NoReturn
from pathlib import Path
from itertools import chain

import platform, os, json, time, traceback, random
import subprocess

import grpc
import heimdallr_grpc.heimdallr_pb2 as heimdallr_pb2
import heimdallr_grpc.heimdallr_pb2_grpc as heimdallr_pb2_grpc

# https://github.com/nlitsme/pyidbutil
import heimdallr_client.idblib as idblib

# Constants
idb_exts  = ["idb", "i64"]

idb_path = None
ida_location = None

# Per Platform Global Paths
heimdallr_path = None
idauser_path = None
def alert(title, error):
    if platform.system() == "Windows":
        from ctypes import windll
        windll.user32.MessageBoxW(0, error, title, 0)
    elif platform.system() == "Darwin":
        # Using enviroment variables for command injection hardening
        subprocess.run(['/usr/bin/osascript',
        '-e', 'set msg_title to (system attribute "msg_title")',
        '-e', 'set msg_error to (system attribute "msg_error")', 
        '-e' , f'Tell application "System Events" to display dialog msg_error with title msg_title'], env={'msg_title': title, 'msg_error': error})
    elif platform.system() == "Linux":
        import easygui # tk not installed by default in brew Python
        easygui.msgbox(error, title)

def error_message(error : str, exit_code : int) -> NoReturn:
    """Generic error message dialogue box to provide feedback to user on failure reasons.
    
    Args:
    - error : Error message to be displayed
    - exit_code : Exit code to exit with
    
    * DOES NOT RETURN *
    """
    title = "Heimdallr Error"
    error = str(error)
    
    alert(title, error)

    sys.exit(exit_code)

def set_global_paths() -> None:
    """Sets the appropriate global IDA User and Heimdallr config paths"""
    global heimdallr_path, idauser_path
    
    if platform.system() == "Windows":
        idauser_path = Path(os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/"))
        heimdallr_path = Path(os.path.expandvars("%APPDATA%/heimdallr/"))
    else:
        idauser_path = Path(os.path.expandvars("$HOME/.idapro/"))
        heimdallr_path = Path(os.path.expandvars("$HOME/.config/heimdallr/"))
    if not heimdallr_path.exists():
        heimdallr_path.mkdir(parents = True)


def load_settings() -> None:
    """Load the settings.json file containing:
    - Path to IDA Application
    - List of paths to search for IDBs for incoming URI requests
    
    Will exit if settings file does not exist (-1) or invalid (-2)
    """
    global idb_path, ida_location, heimdallr_path
    
    log.debug(f"IDA Directory: {idauser_path} ({idauser_path.exists()})")
    log.debug(f"Heimdallr Directory: {heimdallr_path} ({heimdallr_path.exists()})")

    settings_path = heimdallr_path / "settings.json"
    log.info(f"Loading settings from {settings_path}")
    if not settings_path.exists():
        error_message(f"Settings could not be loaded from {settings_path}", -1)    
    with open(settings_path) as fd:
        try:
            settings_dict = json.load(fd)
        except json.decoder.JSONDecodeError as e:
            log.exception("JSON Decoder Error!")
            error_message(f"Malformed settings file: \n{traceback.format_exception_only(e)[-1]}", -2)
        log.debug(f"Settings: \n{settings_dict}")
    try:
        idb_path = settings_dict["idb_path"]
        ida_location = settings_dict["ida_location"]
    except KeyError as e:
        error_message("Malformed settings file - did not contain required keys. Please try reinstalling plugin.", -2)
       
def get_history() -> list[str]:
    """Returns the history.json file containing recently opened IDBs. This is generated
    by the heimdallr_ida plugin on each launch from IDAs internal records."""
    global idauser_path
    history_path = idauser_path / "history.json"
    
    log.debug(f"History file at {history_path}")

    if not history_path.exists():
        log.warning("History file was not found")
        return None

    with open(history_path) as fd:
        history = json.load(fd)
    
    log.info(f"History file contains {len(history)} items")
    return history

def get_history_v2() -> Tuple[list[str], dict[str, str]]:
    """Returns the history.2.json file containing recently opened IDBs and hashes. This is generated
    by the heimdallr_ida plugin on each launch from IDAs internal records."""
    global idauser_path
    history_path = idauser_path / "history.2.json"
    
    log.debug(f"History file v2 at {history_path}")

    if not history_path.exists():
        log.warning("History file was not found")
        return None

    with open(history_path) as fd:
        history = json.load(fd)
    
    files = history['files']
    hash_table = history['hash_table']
    
    log.info(f"History file contains {len(files)} items")
    return files, hash_table

def find_rpc(db_name : Optional[str], file_hash : str) -> Optional[Tuple[str, Path]]:
    """
    Searches the rpc_endpoints directory for open IDA instances with a given name and optional MD5 hash for verification
    
    Args:
    - db_name - name of IDB - None if in compatability mode
    - file_hash - md5 hash of input file
    
    Returns:
    Optional tuple of:
    - String containing connection IP and port
    - Path to endpoint json (used to remove if not responding)

    None means file not found in open IDA instances

    Endpoint information is stored as a JSON dictionary containing
    - PID
    - gRPC connection address
    - IDB name
    - IDB Input File MD5 Hash
    
    Example JSON:

    {"pid": 48762, "address": "127.0.0.1:63227", "file_name": "test.i64", "file_hash": "b058de795064344a4074252e15b9fd39"}
    """
    global heimdallr_path
    
    rpc_path = heimdallr_path / "rpc_endpoints"

    if not rpc_path.exists():
        log.warning("RPC endpoint path was not found")
        return None
    
    for endpoint_path in rpc_path.glob('./*'):
        with open(endpoint_path, "r") as fd:
            endpoint = json.load(fd)

        # Validate json has something for us to look at
        if not endpoint or len(endpoint) == 0:
            continue
        
        # Validate db name matches the one we're looking for
        if db_name and endpoint.get("file_name", None) != db_name:
            continue
        
        # Validate we're checking input hash and if so, it matches what we're looking for
        if endpoint.get("file_hash", None) != file_hash:
            continue
        
        # Validate endpoint has address
        rpc_address = endpoint.get("address", None)
        if not rpc_address:
            log.error(f"Malformed RPC information at {endpoint_path}")
            continue
        
        log.info(f"Matching endpoint found for {endpoint.get('file_name')} - {endpoint_path}")
        return rpc_address, endpoint_path
    
    log.info(f"Endpoint not found for idb: {db_name} hash: {file_hash}")
    return None

def poll_rpc(db_name : str, file_hash : str, limit = 32) -> Optional[Tuple[str, Path]]:
    """
    Repeatedly searches the rpc_endpoints directory for open IDA instances with a given name and optional MD5 hash for verification.
    Used when waiting for IDA to open a file.

    Args:
    - db_name - name of IDB
    - file_hash - md5 hash of input file
    
    Returns:
    Optional tuple of:
    - String containing connection IP and port
    - Path to endpoint json (used to remove if not responding)

    None means timed out
    """
    # ToDo - Make this a watch style but unsure how to approach cross platform and this shouldn't be too
    backoff = 0.5
    timeout = time.time() + limit

    while (time.time() + backoff) < timeout:
        log.debug(f"Backoff: {backoff} Limit Time: {timeout}")
        time.sleep(backoff)
        result = find_rpc(db_name, file_hash)
        if result != None:
            return result
    log.error("Polling for valid gRPC instance failed")
    # Timed out waiting for IDA instance
    return None

def verify_db(idb_path : Path, file_hash : str) -> bool:
    """Verifies an IDBs input file matches a given hash. Expects that the file exists.
    
    Args:
    - idb_path - path to IDB
    - file_hash - md5 hash to match
    
    Returns:
    If the idb input file hash matches the given hash"""
    log.debug(f"Validating {idb_path} for input hash {file_hash}")
    result = False
    
    # Needs to be bytes mode otherwise unicode messes up decoding
    with open(idb_path, "r+b") as fd:
        idb = idblib.IDBFile(fd)
        idb_hash = idb.get_hash_fast().hex()
        if idb_hash == file_hash:
            result = True
    log.debug(f"Validation result: {result}")
    return result

def add_extension(path : Path, ext: str) -> Path:
    """Adds a file extension to Path type, returning a new Path with the extension"""
    str_path = str(path)
    new_path = str_path + ext
    return Path(new_path)

def search_history(db_name : Optional[str], file_hash : str) -> Optional[Path]:
    """Searches recently opened IDBs for the one requested
    
    Args:
    - db_name - name of database, none if in compatability mode
    - file_hash - md5 hash of input file
    
    Returns:
    Optional path to the matching IDB. None if not found.
    """
    files = None
    hash_table = None
    
    history = get_history_v2()
    if not history or len(history) != 2:
        files = get_history()
        if not files:
            return

    files, hash_table = history

    for path, hash in hash_table.items():
        log.debug(f"Checking {hash} against {file_hash}")
        if hash != file_hash:
            continue
        if db_name and db_name != path:
            continue
        return path

    for item in files:
        # Files opened in IDA for the first time don't have the IDB extension - this adds the extension where required.
        idb_path = Path(item)
        idb_name = idb_path.name
        
        if db_name and idb_name[-3:] not in idb_exts:
            # Adopt file extension from source URI if not in file
            # Happens when people open file for first time instead of db
            idb_path = add_extension(idb_path, db_name[-4:])
            idb_name = idb_path.name
        
        # Validate IDB still exists
        if not idb_path.exists():
            continue

        # Validate filename is the one we're looking for if valid
        if db_name and idb_name != db_name:
            continue
        
        # Validate db has expected input hash
        if not verify_db(idb_path, file_hash):
            continue
        
        log.info(f"Matching IDB found at {idb_path} in IDA history")
        return idb_path
    
    log.info(f"IDB not found in history: {db_name} hash: {file_hash}")
    return None

def search_idb_path(db_name : Optional[str], file_hash : str) -> Optional[Path]:
    """Searches IDB Path from settings file for matching IDB. Last resort.
    
    Args:
    - idb_name - name of IDB - None if in compatability mode
    - file_hash - md5 hash of input file
    
    Returns:
    Optional path to the matching IDB. None if not found.
    """
    global idb_path
    log.info(f"Searching {len(idb_path)} IDB paths for {db_name}")

    if not idb_path:
        log.error("IDB Path not set or empty")
        return None
    
    idb_path = map(Path, idb_path)
    for item in idb_path:
        if not item.exists():
            log.warning(f"{item} in IDB path did not exist")
            continue
        if db_name:
            glob = item.glob(f"**/{db_name}")
        else:
            glob = chain(item.glob(f"**/*.i64"), item.glob(f"**/*.idb"))
                
        for potential_idb in glob:
            if not verify_db(potential_idb, file_hash):
                continue
            log.info(f"Matching IDB found at {potential_idb} in IDB path")
            return potential_idb
    
    log.info(f"IDB not found in IDB Path: {db_name} hash: {file_hash}")
    return None

def search_idb(db_name : Optional[str], file_hash : str = None) -> Optional[Path]:
    """Searches for IDB. Looks first in IDA history, then falls back to IDB path from settings.
    
    Args:
    - idb_name - name of IDB - Optional in compatability mode
    - file_hash - md5 hash of input file
    
    Returns:
    Optional path to the matching IDB. None if not found.
    """
    path = search_history(db_name, file_hash)
    if path:
        return path
    
    path = search_idb_path(db_name, file_hash)
    if path:
        return path
    error_message(f"Unable to find {db_name}:{file_hash}", 1)    
    


def launch_ida(idb_name : str, file_hash : str) -> None:
    """Searches for IDB. Looks first in IDA history, then falls back to IDB path from settings.
    
    Args:
    - idb_name - name of IDB
    - file_hash - md5 hash of input file
    
    Returns:
    If the file was found and an IDA instance was opened

    Exits:
    On file not found or unsupported platform
    """
    # Search recents and path
    path = search_idb(idb_name, file_hash)
    if not path:
        sys.exit(1)

    log.info(f"Opening {path} in IDA ({ida_location})")
    if platform.system() == "Darwin":
        run_args = ['/usr/bin/open', '-n', f'{ida_location}', f'{path}']
        subprocess.run(run_args, check=True)
    elif platform.system() == "Linux" or platform.system() == "Windows":
        subprocess.run([ida_location, path], check=True)
    else:
        log.error(f"{platform.system()} is not supported for opening IDA")
        sys.exit(-3)
    
    log.info(f"IDA opened for {path}")

def not_exist_wait(path : Path, max_wait : Optional[int] = None) -> None:
    """Returns once a file no longer exists
    Used to lock access to files
    
    Args:
    - path - path to file
    - max_wait - maximum time to wait for file to exist

    Raises:
    TimeoutError if max_timeout is met
    
    """
    timeout = None
    if max_wait != None:
        timeout = time.time() + max_wait
    
    while path.exists():
        time.sleep(0.5)
        if max_wait and time.time() > timeout:
            raise TimeoutError("Ran out of time waiting for search lock")

def lock_search(idb_name : str, file_hash : str):
    """Adds an entry to `search.lock` which stops mutliple searches being executed at the same time.
    For example accidental double/triple clicks.

    Args:
    - idb_name - name of idb being searched for
    - file_hash - hash of idb being searched for
    """
    lock_path : Path = heimdallr_path / "search.lock"
    tmp_lock_path : Path = heimdallr_path / "search.lock.tmp"

    try:
        not_exist_wait(tmp_lock_path, max_wait = 10)
        if tmp_lock_path.exists():
            raise RuntimeError(f"Search lock already taken at {tmp_lock_path} - search already in progress?")
        
        tmp_lock_path.touch()
        locks = {}
        if lock_path.exists():
            with open(lock_path, "r") as fd:
                locks = json.load(fd)
        
        locks[os.getpid()] = (idb_name, file_hash)
        with open(tmp_lock_path, "w") as fd:
            json.dump(locks, fd)
            fd.flush()
            os.fsync(fd.fileno())
        
        os.replace(tmp_lock_path, lock_path)
    except Exception:
        if tmp_lock_path.exists():
            os.remove(tmp_lock_path)
        raise

def release_lock():
    """Remove current process entry from `search.lock`

    Args:
    - idb_name - name of idb being searched for
    - file_hash - hash of idb being searched for
    """
    lock_path : Path = heimdallr_path / "search.lock"
    tmp_lock_path : Path = heimdallr_path / "search.lock.tmp"

    try:
        not_exist_wait(tmp_lock_path, max_wait = 10)
        if tmp_lock_path.exists():
            raise RuntimeError(f"Search lock already taken at {tmp_lock_path} - search already in progress?")
        
        tmp_lock_path.touch()
        locks = {}
        if lock_path.exists():
            with open(lock_path, "r") as fd:
                locks = json.load(fd)
                
        pid_str = f'{os.getpid()}' 
        if pid_str in locks:
            locks.pop(pid_str) 
        
        with open(tmp_lock_path, "w") as fd:
            json.dump(locks, fd)
            fd.flush()
            os.fsync(fd.fileno())
        
        os.replace(tmp_lock_path, lock_path)
    except Exception:
        if tmp_lock_path.exists():
            os.remove(tmp_lock_path)
        raise

def check_lock(idb_name : str, file_hash : str) -> bool:
    """Chceks `search.lock` for an existing lock on our file

    Args:
    - idb_name - name of idb being searched for
    - file_hash - hash of idb being searched for
    """
    lock_path : Path = heimdallr_path / "search.lock"
    with open(lock_path, "r") as fd:
        locks : dict[str, Tuple[str, str]] = json.load(fd)
    our_pid = f'{os.getpid()}'
    if our_pid not in locks:
        raise RuntimeError("Search lock not taken before lock check")
    
    found = False
    for pid, (name, hash) in locks.items():
        if name != idb_name or hash != file_hash:
            continue
        found = True
        if pid != our_pid and our_pid > pid:
            return False
    return True



def run(url):
    db_name = None
    file_hash = None
    locked = False
    try:
        url = unquote(url)
        log.info(f"Trying to resolve URI: {url}")
        
        parsed_url = urlparse(url)
        log.debug(f"URL Parse result:\n{parsed_url}")

        if not parsed_url:
            error_message(f"Unable to parse url {url}", -4)

        if parsed_url.scheme != "ida" and parsed_url.scheme != "disas":
            error_message(f"Unexpected URL scheme {parsed_url.scheme}", -4)
        
        if not parsed_url.query:
            error_message("URL did not have any query info", -4)
        
        query = dict(parse_qsl(parsed_url.query))
        
        db_name = parsed_url.netloc
        file_hash = query.get("hash", None)
        type = query.get("type", None)
        
        if type != None and type != "ida": # Assume IDA if no type
            db_name = None # Drop name as it's not useful
        
        locked = True
        lock_search(db_name, file_hash)
        if not check_lock(db_name, file_hash):
            raise RuntimeError("Can only have request for single database at a time!")
        


        finished = False
        # Loop a few times incase there is a dead endpoint in our directory from a crashed IDA instance
        while not finished:

            # Look for open IDA instance with our results        
            result = find_rpc(db_name, file_hash)
            if not result:
                # Couldn't find a currently open IDA istance
                launch_ida(db_name, file_hash)
                
                result = poll_rpc(db_name, file_hash)
                if not result:
                    error_message(f"Could not find IDA instance when opening {idb_name}", -6)
                # Placebo sleep just to make sure IDA is going to be receptive to GUI manipulation            
            
            try:
                endpoint, path = result
                log.info(f"Connecting to {endpoint}")

                with grpc.insecure_channel(endpoint) as channel:
                    stub = heimdallr_pb2_grpc.idaRPCStub(channel)
                    # ToDo: Recreate selection in view
                    request = heimdallr_pb2.GoToRequest(address=query['offset'], size="0x00")
                    response : heimdallr_pb2.ResponseCode = None
                    view = query.get("view")
                    if view == "disasm":
                        response = stub.disasmGoTo(request)
                    elif view == "pseudo":
                        response = stub.pseudoGoTo(request)
                    else:
                        response = stub.genericGoTo(request)
                    log.info(f"RPC Response {response}")
                    finished = True
            except grpc.RpcError as rpc_error:
                # Clears stale connection records
                # ToDo: Make this less aggressive - i.e. 3 attempts before a record is removed
                if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                    log.error(f"{endpoint} not responding - deleting record")
                    path.unlink()
                else:
                    log.exception("Unhandled RPC exception!")
                    error_message(f"IDA connection error: {traceback.format_exception_only(rpc_error)[-1]}", -2)

        log.debug(f"RPC client received: {response.Response}" )
    finally:
        if locked:
            release_lock()

def start():
    try:
        global heimdallr_path
        set_global_paths()
        log.basicConfig(filename=heimdallr_path / "client.log", filemode="w", level=log.DEBUG)
        load_settings()
        run(''.join(sys.argv[1:]))
    except Exception as e:
        log.exception("Unhandled exception!")
        traceback.print_exception(e)
        error_message(traceback.format_exception_only(e)[-1], -1)
        
if __name__ == '__main__':
    start()
