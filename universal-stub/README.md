# Introduction
** WARNING: STILL IN DEVELOPMENT **

This is a cross-platform URI stub based on Electron to forward URL events to the python-based `heimdallr_client.py`.

The [macos-stub](../macos-stub/README.md) is still recommended for MacOS users for lower overheads. Especially on ARM64 as the releases currently are x86 only which significantly impacts responsiveness due rosetta startup costs. 

If you dislike Electron, feel free to send over a [pull request](https://github.com/interruptlabs/heimdallr-client/pulls) with a platform specific method for your OS of choice.


# Install
1. Install the [heimdallr_client](../README.md) using pip
2. Download the platform specific stub from [releases](https://github.com/interruptlabs/heimdallr-client/releases)
3. Run the app once to allow it to register with the system as the `ida://` URI handler.
4. Locate the `heimdallr_client` binary on your file system
    - MacOS/Linux - `whereis heimdallr_client`
    - Windows - `pip show -f heimdallr-client` - Look for the "heimdallr_client.exe", path will be relative to the listed `location`

5. Add the binary location to `heimdallr_client` under `settings.json`
    - MacOS/Linux - `$HOME/.config/heimdallr/settings.json`
    - Windows - `%APPDATA%/heimdallr/settings.json`

Example Config:
```
{
"ida_location": "/Applications/IDA Core 8.1/ida64.app",
"idb_path": [
    "/Users/roberts/Projects/"
],
"heimdallr_client" : "/opt/homebrew/bin/heimdallr_client"
}
```

# Build your own / Development
If GitHub doesn't have a package for your directory, you can build with NPM

1. Install NPM
2. Build package
```
npm install .
npm run make
```
The binaries will be in `./out/make`