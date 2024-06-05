# ssh-executor
Lib for local/remote ssh operations.
- connect
- exec statements (also with sudo, also with parsing output)
- send files through scp

# import
```
import (
  sshExecutor "github.com/NGRsoftlab/ssh-executor"
)
```

# examples
```
// exec "ls -la /home/myuser" command on remote "155.34.34.1"
out, _ := sshExecutor.GetSudoCommandsOutWithoutErr(
		sshExecutor.ConnectParams{
			Host:       "155.34.34.1",
			Port:       22,
			PrivateKey: MyConfig.SSHPrivateKey(), // MyConfig - smth like app configuration obj
		},
		time.Second * 30,
		time.Second * 30,
		"ls -la /home/myuser",
	)

// let's see command output
fmt.Println(out)
```
