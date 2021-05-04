package sshExecutor

import (
	errorLib "github.com/NGRsoftlab/error-lib"
	"github.com/NGRsoftlab/ngr-logging"

	"bufio"
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Ssh connection struct
type Connection struct {
	*ssh.Client
	password string
}

// Getting ssh connection
func GetSshConnection(connParams ConnectParams, timeout time.Duration) (connection *Connection, err error) {
	sshConfig := makeSshClientConfig(connParams.User, connParams.Psw, timeout)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		timeout)

	var connClient *ssh.Client

	go func(ctx context.Context) {
		defer cancel()
		connClient, err = ssh.Dial("tcp", fmt.Sprintf("%v:%v", connParams.Host, connParams.Port), sshConfig)
		if err != nil {
			logging.Logger.Error("bad ssh conn: ", err)
		}
	}(ctx)

	select {
	case <-ctx.Done():
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logging.Logger.Error("ssh conn timeout")
			return nil, errorLib.GlobalErrors.ErrConnectionTimeout()
		case context.Canceled:
			logging.Logger.Info("ssh conn canceled by timeout")
		}
	}

	if err != nil || connClient == nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errorLib.GlobalErrors.ErrBadAuthData()
		} else {
			return nil, errorLib.GlobalErrors.ErrBadIpOrPort()
		}
	}

	return &Connection{connClient, connParams.Psw}, nil
}

// Connection checking for sudo password ask (with recovery, be careful)
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

// Sending many commands (may be with SUDO, without strErr output)
func (conn *Connection) SendSudoCommandsWithoutErrOut(commands ...string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		logging.Logger.Error(err)
		return nil, err
	}

	err = session.RequestPty("xterm", xTermHeight, xTermWidth, makeSshTerminalModes())
	if err != nil {
		logging.Logger.Error(err)
		return nil, err
	}

	in, err := session.StdinPipe()
	if err != nil {
		logging.Logger.Error(err)
		return nil, err
	}

	out, err := session.StdoutPipe()
	if err != nil {
		logging.Logger.Error(err)
		return nil, err
	}

	var output []byte

	go conn.SendSudoPassword(in, out, &output)

	commandsString := strings.Join(commands, "; ")
	_, err = session.Output(commandsString)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// Sending one command (no SUDO, with strErr output, with killChan)
func (conn *Connection) SendOneCommandWithErrOut(kill chan *os.Signal, command string) ([]byte, []byte, time.Duration, error) {
	start := time.Now()

	session, err := conn.NewSession()
	if err != nil {
		logging.Logger.Error("Error session ssh: ", err)
		return nil, nil, time.Since(start), err
	}

	if err := session.RequestPty("xterm", xTermHeight, xTermWidth, makeSshTerminalModes()); err != nil {
		_ = session.Close()
		logging.Logger.Error("Error terminal: ", err)
		return nil, nil, time.Since(start), err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		logging.Logger.Error("Error session stdout: ", err)
		return nil, nil, time.Since(start), err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		logging.Logger.Error("Error session stderr: ", err)
		return nil, nil, time.Since(start), err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = session.Run(command)

		logging.Logger.Info("SEND SIGNAL", err)
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

// Sending file (content = file string content) to rootFolder/folderName/fileName with scp
func (conn *Connection) SendScpFile(kill chan *os.Signal, pathParams FilePathParams) (time.Duration, error) {
	start := time.Now()

	session, err := conn.NewSession()
	if err != nil {
		logging.Logger.Error("Error session ssh: ", err)
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
				logging.Logger.Error("Error session scp: ", err)
				return
			}
		}

		if pathParams.FileName != "" {
			_, err = fmt.Fprintln(w, fmt.Sprintf("C0%s", pathParams.FileRights),
				len(pathParams.Content), pathParams.FileName) // touch file (c-create)
			if err != nil {
				logging.Logger.Error("Error session scp: ", err)
				return
			}
			_, err = fmt.Fprint(w, pathParams.Content) // add content to file
			if err != nil {
				logging.Logger.Error("Error session scp: ", err)
				return
			}
		}

		_, err = fmt.Fprint(w, "\x00") // transfer end with \x00
		if err != nil {
			logging.Logger.Error("Error session scp: ", err)
			return
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = session.Run("/usr/bin/scp -tr " + pathParams.RootFolder)
		logging.Logger.Info("SEND SIGNAL", err)
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
