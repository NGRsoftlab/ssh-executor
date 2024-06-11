// Copyright © NGR Softlab 2020-2024
package sshExecutor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Connection ssh connection struct
type Connection struct {
	*ssh.Client
	password string
}

// GetSshConnection getting ssh connection
func GetSshConnection(connParams ConnectParams, timeout time.Duration) (connection *Connection, err error) {
	sshConfig := makeSshClientConfig(connParams.User, connParams.Psw, connParams.PrivateKey, timeout)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeout)

	var connClient *ssh.Client

	go func(ctx context.Context) {
		defer cancel()
		connClient, err = ssh.Dial("tcp", fmt.Sprintf("%v:%v", connParams.Host, connParams.Port), sshConfig)
		if err != nil {
			logger.Errorf("error: bad ssh conn %s\n", err.Error())
		}
	}(ctx)

	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logger.Errorf("error: got ssh connection timeout\n")
			return nil, errors.New("ssh connection timeout")
		case context.Canceled:
			logger.Infof("info: got ssh timeout cancelation\n")
		}
	}

	if err != nil || connClient == nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("invalid credentials for connection")
		} else {
			return nil, errors.New("invalid ip or port for connection")
		}
	}

	return &Connection{connClient, connParams.Psw}, nil
}

// SendSudoPassword checking for sudo password ask (with recovery, be careful)
func (conn *Connection) SendSudoPassword(in io.WriteCloser, out io.Reader, output *[]byte) {
	// recovery
	defer recoverExecutor()

	var (
		line string
		r    = bufio.NewReader(out)
	)
	for {
		b, err := r.ReadByte()
		if err != nil {
			break
		}

		*output = append(*output, b)

		if b == byte('\n') {
			line = ""
			continue
		}

		line += string(b)

		if strings.HasPrefix(line, "[sudo] password for ") && strings.HasSuffix(line, ": ") {
			_, err = in.Write([]byte(conn.password + "\n"))
			if err != nil {
				break
			}
		}
	}
}

// SendSudoCommandsWithoutErrOut sending many commands (may be with SUDO, without strErr output)
func (conn *Connection) SendSudoCommandsWithoutErrOut(commands ...string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		logger.Errorf("error: create session %s\n", err.Error())
		return nil, err
	}

	err = session.RequestPty("xterm", xTermHeight, xTermWidth, makeSshTerminalModes())
	if err != nil {
		_ = session.Close()
		logger.Errorf("error: pty term %s\n", err.Error())
		return nil, err
	}

	in, err := session.StdinPipe()
	if err != nil {
		logger.Errorf("error: session in pipe %s\n", err.Error())
		return nil, err
	}

	out, err := session.StdoutPipe()
	if err != nil {
		logger.Errorf("error: session out pipe %s\n", err.Error())
		return nil, err
	}

	var output []byte

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn.SendSudoPassword(in, out, &output)
	}()

	commandsString := strings.Join(commands, "; ")
	_, err = session.Output(commandsString)
	if err != nil {
		return nil, err
	}

	wg.Wait()

	return output, nil
}

// SendOneCommandWithErrOut sending one command (no SUDO, with strErr output, with killChan)
func (conn *Connection) SendOneCommandWithErrOut(kill chan *os.Signal, command string) ([]byte, []byte, time.Duration, error) {
	start := time.Now()

	session, err := conn.NewSession()
	if err != nil {
		logger.Errorf("error: session ssh %s\n", err.Error())
		return nil, nil, time.Since(start), err
	}

	if err := session.RequestPty("xterm", xTermHeight, xTermWidth, makeSshTerminalModes()); err != nil {
		_ = session.Close()
		logger.Errorf("error: terminal %s\n", err.Error())
		return nil, nil, time.Since(start), err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		logger.Errorf("error: session stdout pipe %s\n", err.Error())
		return nil, nil, time.Since(start), err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		logger.Errorf("error: session stderr pipe %s\n", err.Error())
		return nil, nil, time.Since(start), err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = session.Run(command)

		logger.Infof("info: command executed, returned error (if not nil) - %v\n", err)
		if kill != nil {
			kill <- &os.Kill
		}
		return
	}()

	if kill != nil {
		select {
		case <-kill:
			_ = session.Close()
			kill = nil
		}
	}

	wg.Wait()

	stdOut := []byte(scanPipe(stdout))
	stdErr := []byte(scanPipe(stderr))

	if err != nil {
		return stdOut, stdErr, time.Since(start), err
	}

	return stdOut, stdErr, time.Since(start), nil
}

// SendScpFile sending file (content = file string content) to rootFolder/folderName/fileName with scp
func (conn *Connection) SendScpFile(kill chan *os.Signal, pathParams FilePathParams) (time.Duration, error) {
	start := time.Now()

	session, err := conn.NewSession()
	if err != nil {
		logger.Errorf("error: session ssh %s\n", err.Error())
		return time.Since(start), err
	}

	defer func() { _ = session.Close() }()

	go func() {
		w, _ := session.StdinPipe()
		defer func() {
			if w != nil {
				_ = w.Close()
			}
		}()

		if pathParams.FolderName != "" {
			_, err = fmt.Fprintln(w, fmt.Sprintf("D0%s", pathParams.FolderRights),
				0, pathParams.FolderName) // mkdir (d-dir)
			if err != nil {
				logger.Errorf("error: session scp %s\n", err.Error())
				return
			}
		}

		if pathParams.FileName != "" {
			_, err = fmt.Fprintln(w, fmt.Sprintf("C0%s", pathParams.FileRights),
				len(pathParams.Content), pathParams.FileName) // touch file (c-create)
			if err != nil {
				logger.Errorf("error: session scp fprint touch %s\n", err.Error())
				return
			}
			_, err = fmt.Fprint(w, pathParams.Content) // add content to file
			if err != nil {
				logger.Errorf("error: session scp fprint print %s\n", err.Error())
				return
			}
		}

		_, err = fmt.Fprint(w, "\x00") // transfer end with \x00
		if err != nil {
			logger.Errorf("error: session scp %s\n", err.Error())
			return
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = session.Run("/usr/bin/scp -tr " + pathParams.RootFolder)

		logger.Infof("info: got scp session kill sig %v\n", err)
		if kill != nil {
			kill <- &os.Kill
		}
		return
	}()

	if kill != nil {
		select {
		case <-kill:
			_ = session.Close()
			kill = nil
		}
	}

	wg.Wait()

	if err != nil {
		return time.Since(start), err
	}
	return time.Since(start), nil
}
