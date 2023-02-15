module.exports = {
  "packagerConfig": {
    "protocols": [
      {
        "name": "IDA Heimdallr Deeplink",
        "schemes": ["ida-test"]
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
      platforms: ['darwin'],
    },
    {
      name: '@electron-forge/maker-deb',
      "config": {
        "mimeType": ["x-scheme-handler/ida-test"]
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
