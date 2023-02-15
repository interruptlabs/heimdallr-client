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
