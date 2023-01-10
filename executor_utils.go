package sshExecutor

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"

	errorLib "github.com/NGRsoftlab/error-lib"
	"github.com/NGRsoftlab/ngr-logging"
)

// There are some standard scenarios of using ssh or scp
/////////////////////////////////////////////////////////////////////

// recoverExecutor recovering from panic
func recoverExecutor() {
	if r := recover(); r != nil {
		logging.Logger.Warningf("executor recovered from: %v", r)
	}
}

// scanPipe stdPipe to text
func scanPipe(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	var scanningText string
	for scanner.Scan() {
		scanningText = scanningText + "\n" + scanner.Text()
	}
	return scanningText
}

// makeSshClientConfig get ssh client config (ssh.ClientConfig)
func makeSshClientConfig(user, password string, timeout time.Duration) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil },
		Timeout:         timeout,
	}
}

// makeSshTerminalModes get ssh.TerminalModes obj
func makeSshTerminalModes() ssh.TerminalModes {
	return ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
}

/////////////////////////////////////////////////////////////////////

// LocalExecContext local execution command with context
func LocalExecContext(timeout time.Duration, command string, params ...string) (output []byte, err error) {
	logging.Logger.Debugf("%s ::: %v", command, params)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, params...)
	output, err = cmd.Output()
	if err != nil {
		if output == nil {
			output = []byte("")
		}
		logging.Logger.Warningf("Error local exec: %s ::: %s", err.Error(), string(output))
		return output, errorLib.GlobalErrors.ErrSshCommands()
	}
	return
}

// GetSudoCommandsOutWithoutErr get result sudo (!) commands... output from ssh connection
func GetSudoCommandsOutWithoutErr(connParams ConnectParams,
	timeoutConn, timeoutCmd time.Duration, commands ...string) (output []byte, err error) {
	conn, err := GetSshConnection(connParams, timeoutConn)
	if err != nil {
		logging.Logger.Error(err)
		return output, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logging.Logger.Warningf("bad conn close: %s", errClose.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeoutCmd)

	go func(ctx context.Context) {
		defer cancel()
		output, err = conn.SendSudoCommandsWithoutErrOut(commands...)
	}(ctx)

	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logging.Logger.Error("ssh sudo commands timeout")
			return output, errorLib.GlobalErrors.ErrConnectionTimeout()
		case context.Canceled:
			logging.Logger.Info("ssh context cancelled by force, whole process is complete")
		}
	}

	if err != nil {
		logging.Logger.Errorf("ssh sudo commands error: %s", err.Error())
		return output, errorLib.GlobalErrors.ErrSshCommands()
	}

	return output, nil
}

// GetCommandOutWithErr get result command output (with errOut) from ssh connection
func GetCommandOutWithErr(connParams ConnectParams, kill chan *os.Signal,
	timeoutConn, timeoutCmd time.Duration, command string) (output []byte, errOutput []byte, duration time.Duration, err error) {
	defer func() {
		kill = nil
	}()

	conn, err := GetSshConnection(connParams, timeoutConn)
	if err != nil {
		logging.Logger.Error(err)
		return output, errOutput, 0, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logging.Logger.Warningf("bad conn close: %s", errClose.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeoutCmd)

	go func(ctx context.Context) {
		defer cancel()
		output, errOutput, duration, err = conn.SendOneCommandWithErrOut(kill, command)
	}(ctx)

	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logging.Logger.Error("ssh command timeout")
			kill <- &os.Kill
			return output, errOutput, duration, errorLib.GlobalErrors.ErrConnectionTimeout()
		case context.Canceled:
			logging.Logger.Info("ssh context cancelled by force, whole process is complete")
		}
	}

	if err != nil {
		logging.Logger.Errorf("ssh command error: %s", err.Error())
		return output, []byte(err.Error()), duration, errorLib.GlobalErrors.ErrSshCommands()
	}

	return output, errOutput, duration, nil
}

// SendFileWithScp get result command output (with errOut) from ssh connection
func SendFileWithScp(connParams ConnectParams, kill chan *os.Signal,
	timeoutConn, timeoutCmd time.Duration, pathParams FilePathParams) (time.Duration, error) {
	defer func() {
		kill = nil
	}()

	conn, err := GetSshConnection(connParams, timeoutConn)
	if err != nil {
		logging.Logger.Error(err)
		return 0, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logging.Logger.Warningf("bad conn close: %s", errClose.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeoutCmd)

	var duration time.Duration

	go func(ctx context.Context) {
		defer cancel()
		duration, err = conn.SendScpFile(kill, pathParams)
	}(ctx)

	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logging.Logger.Error("scp command timeout")
			kill <- &os.Kill
			return duration, errorLib.GlobalErrors.ErrConnectionTimeout()
		case context.Canceled:
			logging.Logger.Info("scp context cancelled by force, whole process is complete")
		}
	}

	if err != nil {
		logging.Logger.Errorf("scp command error: %s", err.Error())
		return duration, errorLib.GlobalErrors.ErrSshCommands()
	}

	return duration, nil
}
