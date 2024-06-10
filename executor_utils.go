// Copyright © NGR Softlab 2020-2024
package sshExecutor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"
)

// There are some standard scenarios of using ssh or scp
/////////////////////////////////////////////////////////////////////

// recoverExecutor recovering from panic
func recoverExecutor() {
	if r := recover(); r != nil {
		logger.Errorf("fatal: recovery in %v\n", r)
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
func makeSshClientConfig(user, password, privateKey string, timeout time.Duration) *ssh.ClientConfig {
	var methods []ssh.AuthMethod
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			logger.Warningf("warning: parse private key %s\n", err.Error())
		} else {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, params...)
	output, err = cmd.Output()
	if err != nil {
		if output == nil {
			output = []byte("")
		}
		logger.Errorf("error: local exec err %s ::: out %s\n", err.Error(), string(output))
		return output, fmt.Errorf("local ssh command error: %s", err.Error())
	}
	return
}

// GetSudoCommandsOutWithoutErr get result sudo (!) commands... output from ssh connection
func GetSudoCommandsOutWithoutErr(connParams ConnectParams,
	timeoutConn, timeoutCmd time.Duration, commands ...string) (output []byte, err error) {
	conn, err := GetSshConnection(connParams, timeoutConn)
	if err != nil {
		logger.Errorf("error: ssh connection %s\n", err.Error())
		return output, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logger.Warningf("warning: conn close %s\n", errClose.Error())
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
			logger.Errorf("error: sudo conn deadline timeout\n")
			return output, errors.New("got sudo ssh connection deadline")
		case context.Canceled:
			logger.Infof("info: ssh context cancelled by force, whole process in compeleted\n")
		}
	}

	if err != nil {
		logger.Errorf("error: sudo ssh commands %s\n", err.Error())
		return output, fmt.Errorf("sudo ssh command error: %s", err.Error())
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
		logger.Errorf("error: ssh connection %s\n", err.Error())
		return output, errOutput, 0, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logger.Warningf("warning: conn close %s\n", errClose.Error())
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
			logger.Errorf("error: ssh command deadline %v\n", err)
			kill <- &os.Kill
			return output, errOutput, duration, errors.New("got ssh connection deadline")
		case context.Canceled:
			logger.Infof("info: ssh context cancelled by force, whole process is completed %v\n", err)
		}
	}

	if err != nil {
		logger.Errorf("error: ssh command %s\n", err.Error())
		return output, []byte(err.Error()), duration, fmt.Errorf("ssh command error: %s", err.Error())
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
		logger.Errorf("error: ssh conn %s\n", err.Error())
		return 0, err
	}

	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			logger.Warningf("warning: conn close %s\n", errClose.Error())
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
			logger.Error("error: scp command deadline\n")
			kill <- &os.Kill
			return duration, errors.New("got scp connection deadline")
		case context.Canceled:
			logger.Infof("info: scp context cancelled by force, whole process is completed %v\n", err)
		}
	}

	if err != nil {
		logger.Errorf("error: scp command %s\n", err.Error())
		return duration, fmt.Errorf("scp command error: %s", err.Error())
	}

	return duration, nil
}
