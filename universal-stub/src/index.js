// Modules to control application life and create native browser window
const { app, dialog } = require('electron')
const path = require('path')


// Stop GPU process, optimise start speed
app.disableHardwareAcceleration()

if (process.platform == "win32") {
  config_path = path.join(process.env.APPDATA, "heimdallr/settings.json")
}else{
  config_path = path.join(process.env.HOME, ".config/heimdallr/settings.json")
}
console.log(config_path)

const fs = require('fs')
let rawdata = fs.readFileSync(config_path)
let config = JSON.parse(rawdata)

console.log(config)

if(!config.hasOwnProperty('heimdallr_client')){
  dialog.showErrorBox("Heidmallr Client setting not set!")
  app.exit(1)
}

heimdallr_client = config.heimdallr_client
console.log(heimdallr_client)

if (process.defaultApp) {
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('ida')
    heimdallrURL(process.argv[1])
  }
} else {
    app.setAsDefaultProtocolClient('ida')
}

function heimdallrURL(url){

  pyProc = require('child_process').spawnSync(heimdallr_client, [url], {shell: true})
  // dialog.showErrorBox('URL Done', url)


  if (pyProc != null) {
    console.log('child process success')
    console.log(pyProc.stderr.toString())
    console.log(pyProc.stdout.toString())
    
    // if (pyProc.stdout && pyProc.stdout.length > 0)  dialog.showErrorBox('stdout', pyProc.stdout.toString())
    if (pyProc.stderr && pyProc.stderr.length > 0)  dialog.showErrorBox('stderr', pyProc.stderr.toString())
    app.exit(0)
  } else{
    dialog.showErrorBox('Error', "Error running Python")
    app.exit(1)
  }
}


const gotTheLock = app.requestSingleInstanceLock()
exit_timeout = setTimeout(function(){ app.exit(0) }, 500);
if (!gotTheLock) {
  app.quit()
} else {
  app.on('second-instance', (event, commandLine, workingDirectory) => {
    clearTimeout(exit_timeout)
    heimdallrURL(`${commandLine.pop().slice(0,-1)}`)
  })
  
  app.on('open-url', (event, url) => {
    clearTimeout(exit_timeout)
    heimdallrURL(`${url}`)
  })
}
