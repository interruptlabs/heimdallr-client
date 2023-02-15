module.exports = {
  "packagerConfig": {
    "protocols": [
      {
        "name": "IDA Heimdallr Deeplink",
        "schemes": ["ida"]
      }
    ]
  },
  rebuildConfig: {},
  makers: [
    {
      name: '@electron-forge/maker-squirrel',
      config: {},
    },
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin', 'darwin-arm64'],
    },
    {
      name: '@electron-forge/maker-deb',
      "config": {
        "mimeType": ["x-scheme-handler/ida"]
      }
    }
  ],
  publishers: [
    {
      name: '@electron-forge/publisher-github',
      config: {
        repository: {
          owner: 'interruptlabs',
          name: 'heimdallr-client'
        },
        prerelease: true
      }
    }
  ],
};
