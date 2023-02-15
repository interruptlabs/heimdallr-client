# Introduction 

**BETA SUPPORT ONLY - MAC OS SUPPORT ONLY - CROSS PLATFORM RELEASES WIP**

The Heimdallr client is registered as a system wide URI handler. This means that anywhere a URL can be invoked we can link to a location in IDA.

# Installation

1. Install [heimdallr-ida](https://github.com/interruptlabs/heimdallr-ida)
2. Install heimdallr-client with pip
    - Using git directly `pip3 install -e git+ssh://git@github.com/interruptlabs/heimdallr-client.git#egg=heimdallr_client`
    - From a cloned repo `pip3 install -e .`
3. Verify `settings.json` has been created in the relevant application directory
    - MacOS/Linux - `$HOME/.config/heimdallr/`
    - Windows - `%APPDATA%/heimdallr/`
4. Modify `settings.json` to be accurate for your system
    - `ida_location` is the location of your IDA Installation (should be automatically filled)
    - `idb_path` is an array of locations for the heimdallr client to search for corosponding idbs

## MacOS

In MacOS we can use AppleScript to act as a stub to forward URI requestst to our python client script. To configure this:

1. Locate path to `heimdallr_client` script
```
roberts@RobertS-IL-Mac heimdallr_client % whereis heimdallr_client
heimdallr_client: /opt/homebrew/bin/heimdallr_client
```
2. Open `./macos-stub/heimdallrd.scpt` in Script Editor (double click)
![example script window](images/Screenshot%202022-12-29%20at%2018.34.42.png)
3. Change the `heimdallr_client` path to be valid for your system
4. Export it as an Application (File -> Export...)
    a. Ensure "File Format" is "Application"
![example export window](images/Screenshot%202022-12-29%20at%2018.36.58.png)
5. Modify the `Info.plist` file to add the following text between it's first set of dictionary tags
```
    <key>CFBundleURLTypes</key>
    <array>
    <dict>
        <key>CFBundleURLName</key>
        <string>IDA URL</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>ida</string>
        </array>
    </dict>
    </array>
```
(an example Info.plist is in `./macos-stub/Info.plist`)
6. Move the Application Bundle to /Applications/ and resign it:
`codesign --force -s - /Applications/heimdallrd.app` 
7. Run the Application bundle (double click) to register it with the system as a URI handler.

# Usage

You should now be able to open ida:// URIs from anywhere in the system. This could be a Slack DM, a Confluence page, or a Obsidian note. The format is as follows (these):
`ida://a.out.i64?offset=0x100003f10&hash=fea074789acc4a748d2ba0c6d82a0f8f&view=pseudo`
These are automatically generated by creating a note with the [heimdallr-ida](https://github.com/interruptlabs/heimdallr-ida) plugin

The search behaviour for a matching IDB is as follows:
1. Search for an open IDA instance with this database already open
2. Search IDA recently open files for the location of the database
3. Search your `idb_path` for matching files

The search pattern is used to ensure links can be used easily within a team - so long as you have a database based on the same source file and is named the same.

IDBs are matched by both the database name and source file hash. As such **changing the database name will cause URIs to no longer be valid**.

You can make notes by highlighting the area of text in IDA you want to copy and pressing "Ctrl+Shift+N". The text will be added to a code block with a link back to where it came from and added to your clipboard.

This currently only works for the Disassembly and Pseudocode views.

