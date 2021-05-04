package sshExecutor

import (
	errorLib "github.com/NGRsoftlab/error-lib"
	"github.com/NGRsoftlab/ngr-logging"

	"bufio"
	"context"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)

// There are some standard scenarios of using ssh or scp
/////////////////////////////////////////////////////////////////////

// Recovering from panic
func recoverExecutor() {
	if r := recover(); r != nil {
		logging.Logger.Warning("executor recovered from: ", r)
	}
}

// StdPipe to text
func scanPipe(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	var scanningText string
	for scanner.Scan() {
		scanningText = scanningText + "\n" + scanner.Text()
	}
	return scanningText
}

// Get ssh client config (ssh.ClientConfig)
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

// Get ssh.TerminalModes obj
func makeSshTerminalModes() ssh.TerminalModes {
	return ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
}

/////////////////////////////////////////////////////////////////////

// Local execution command with context
func LocalExecContext(timeout time.Duration, command string, params ...string) (output []byte, err error) {
	logging.Logger.Debug(command, " ::: ", params)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, params...)
	output, err = cmd.Output()
	if err != nil {
		logging.Logger.Warning("Error local exec: ", err, " ::: ", string(output))
		return output, errorLib.GlobalErrors.ErrSshCommands()
	}
	return
}

// Get result sudo (!) commands... output from ssh connection
func GetSudoCommandsOutWithoutErr(connParams ConnectParams,
	timeoutConn, timeoutCmd time.Duration, commands ...string) (output []byte, err error) {
	conn, err := GetSshConnection(connParams, timeoutConn)
	if err != nil {
		logging.Logger.Error(err)
		return output, err
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			logging.Logger.Warning("bad conn close: ", err)
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
			logging.Logger.Info("ssh conn canceled by timeout")
		}
	}

	if err != nil {
		logging.Logger.Error("ssh sudo commands error: ", err)
		return output, errorLib.GlobalErrors.ErrSshCommands()
	}

	return output, nil
}

// Get result command output (with errOut) from ssh connection
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
		err := conn.Close()
		if err != nil {
			logging.Logger.Warning("bad conn close: ", err)
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
			logging.Logger.Info("ssh conn canceled by timeout")
		}
	}

	if err != nil {
		logging.Logger.Error("ssh command error: ", err)
		return output, []byte(err.Error()), duration, errorLib.GlobalErrors.ErrSshCommands()
	}

	return output, errOutput, duration, nil
}

// Get result command output (with errOut) from ssh connection
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
		err := conn.Close()
		if err != nil {
			logging.Logger.Warning("bad conn close: ", err)
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
			logging.Logger.Error("ssh command timeout")
			kill <- &os.Kill
			return duration, errorLib.GlobalErrors.ErrConnectionTimeout()
		case context.Canceled:
			logging.Logger.Info("ssh conn canceled by timeout")
		}
	}

	if err != nil {
		logging.Logger.Error("ssh command error: ", err)
		return duration, errorLib.GlobalErrors.ErrSshCommands()
	}

	return duration, nil
}
