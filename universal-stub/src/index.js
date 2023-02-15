// Modules to control application life and create native browser window
const { app } = require('electron')
const path = require('path')

if (process.defaultApp) {
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('ida', process.execPath, [path.resolve(process.argv[1])])
  }
} else {
    app.setAsDefaultProtocolClient('ida')
}
console.log(`You arrived from: ${process.argv[1]}\n`)
pyProc = require('child_process').spawn('heimdallr_client', [process.argv[1]])

if (pyProc != null) {
  console.log('child process success')
  pyProc.stdout.pipe(process.stdout)
  pyProc.on('exit', function() {
  app.exit(0)
})
} else{
  app.exit(1)
}

