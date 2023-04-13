package sshExecutor

import (
	"fmt"
	"os"
	"testing"
	"time"

	errorLib "github.com/NGRsoftlab/error-lib"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name       string
	inputOpt   []string // not used
	inputData  interface{}
	outputData interface{}
	failError  error
	mustFail   bool
}

// ok values for tests
// TODO: change to real creds for ok tests (!)
const okHost, okPort, okUser, okPsw = "127.0.0.1", 22, "test", "test"
const connTimeout, cmdTimeout = time.Second * 30, time.Second * 30

/////////////////////////////////////////////////
func TestLocalExecContext(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		command string
		params  []string
		timeout time.Duration
	}

	testCases := []*testCase{
		{
			name: "bad command",
			inputData: testInfo{
				command: "hhhh",
				params:  []string{"test"},
				timeout: cmdTimeout,
			},
			failError: errorLib.GlobalErrors.ErrSshCommands(),
			mustFail:  true,
		},
		{
			name: "ok case (same windows&linux)",
			inputData: testInfo{
				command: "arp",
				params:  []string{"-a"},
				timeout: cmdTimeout,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			output, err := LocalExecContext((tc.inputData).(testInfo).timeout,
				(tc.inputData).(testInfo).command,
				(tc.inputData).(testInfo).params...)

			tt.Log("out:", string(output))

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}

/////////////////////////////////////////////////
func TestGetConnection(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams ConnectParams
		timeout    time.Duration
	}

	testCases := []*testCase{
		{
			name: "bad empty auth data",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: "",
					Psw:  "",
				},
				timeout: connTimeout,
			},
			failError: errorLib.GlobalErrors.ErrBadAuthData(),
			mustFail:  true,
		},
		{
			name: "bad host connection",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: "999.999.999.999",
					Port: 22,
					User: okUser,
					Psw:  okPsw,
				},
				timeout: connTimeout,
			},
			failError: errorLib.GlobalErrors.ErrBadIpOrPort(),
			mustFail:  true,
		},
		{
			name: "bad username/password connection",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: "___",
					Psw:  "___",
				},
				timeout: connTimeout,
			},
			failError: errorLib.GlobalErrors.ErrBadAuthData(),
			mustFail:  true,
		},
		{
			name: "bad port connection (not free, not ssh port)",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: 8123,
					User: "___",
					Psw:  "___",
				},
				timeout: connTimeout,
			},
			failError: errorLib.GlobalErrors.ErrConnectionTimeout(),
			mustFail:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			_, err := GetSshConnection((tc.inputData).(testInfo).connParams, (tc.inputData).(testInfo).timeout)

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}

/////////////////////////////////////////////////
func TestGetSudoCommandsWithoutErrOut(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams ConnectParams
		commands   []string
	}

	testCases := []*testCase{
		{
			name: "bad empty auth data",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: "",
					Psw:  "",
				},
				commands: []string{},
			},
			failError: errorLib.GlobalErrors.ErrBadAuthData(),
			mustFail:  true,
		},
		{
			name: "bad ip",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: "999.999.99.99",
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{},
			},
			failError: errorLib.GlobalErrors.ErrBadIpOrPort(),
			mustFail:  true,
		},
		{
			name: "bad port (not ssh or not free)",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: 8123,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{},
			},
			failError: errorLib.GlobalErrors.ErrConnectionTimeout(),
			mustFail:  true,
		},
		{
			name: "bad command",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{"adgsgsdgdfsjn earyery34"},
			},
			failError: errorLib.GlobalErrors.ErrSshCommands(),
			mustFail:  true,
		},
		{
			name: "bad endless command",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{"sudo journalctl -fu test_test_test"},
			},
			failError: errorLib.GlobalErrors.ErrConnectionTimeout(),
			mustFail:  true,
		},
		{
			name: "ok case",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{"sudo arp -a"},
			},
		},
		{
			name: "ok case (no commands)",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				commands: []string{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			output, err := GetSudoCommandsOutWithoutErr((tc.inputData).(testInfo).connParams,
				connTimeout,
				cmdTimeout,
				(tc.inputData).(testInfo).commands...)

			tt.Log("out:", string(output))

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}

/////////////////////////////////////////////////
func TestGetCommandOutWithErr(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams ConnectParams
		kill       chan *os.Signal
		command    string
	}

	testCases := []*testCase{
		{
			name: "bad empty auth data",

			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: "",
					Psw:  "",
				},
				kill:    make(chan *os.Signal),
				command: "",
			},
			failError: errorLib.GlobalErrors.ErrBadAuthData(),
			mustFail:  true,
		},
		{
			name: "bad ip",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: "999.999.99.99",
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "",
			},
			failError: errorLib.GlobalErrors.ErrBadIpOrPort(),
			mustFail:  true,
		},
		{
			name: "bad port (not ssh or not free)",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: 8123,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "",
			},
			failError: errorLib.GlobalErrors.ErrConnectionTimeout(),
			mustFail:  true,
		},
		{
			name: "bad command",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "hhhhhhhhhh",
			},
			failError: errorLib.GlobalErrors.ErrSshCommands(),
			mustFail:  true,
		},
		{
			name: "bad endless command",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "journalctl -fu test_test",
			},
			failError: errorLib.GlobalErrors.ErrConnectionTimeout(),
			mustFail:  true,
		},
		{
			name: "ok case",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "arp -a",
			},
		},
		{
			name: "ok case (empty command)",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill:    make(chan *os.Signal),
				command: "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			output, errOut, duration, err := GetCommandOutWithErr((tc.inputData).(testInfo).connParams,
				(tc.inputData).(testInfo).kill,
				connTimeout,
				cmdTimeout,
				(tc.inputData).(testInfo).command)

			tt.Log("out:", string(output))
			tt.Log("errOut:", string(errOut))
			tt.Log("duration:", duration)

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}

/////////////////////////////////////////////////
func TestSendFileWithScp(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams     ConnectParams
		kill           chan *os.Signal
		filePathParams FilePathParams
	}

	testCases := []*testCase{
		{
			name: "bad empty auth data",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: "",
					Psw:  "",
				},
				kill: make(chan *os.Signal),
				filePathParams: FilePathParams{
					RootFolder:   "",
					FolderName:   "",
					FileName:     "",
					FolderRights: "755",
					FileRights:   "777",
					Content:      "",
				},
			},
			failError: errorLib.GlobalErrors.ErrBadAuthData(),
			mustFail:  true,
		},
		{
			name: "bad root path",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill: make(chan *os.Signal),
				filePathParams: FilePathParams{
					RootFolder:   "@@@",
					FolderName:   "",
					FileName:     "",
					FolderRights: "755",
					FileRights:   "777",
					Content:      "",
				},
			},
			failError: errorLib.GlobalErrors.ErrSshCommands(),
			mustFail:  true,
		},
		{
			name: "ok case",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill: make(chan *os.Signal),
				filePathParams: FilePathParams{
					RootFolder:   "/home",
					FolderName:   "",
					FileName:     "test.txt",
					FolderRights: "755",
					FileRights:   "777",
					Content:      "hi guys",
				},
			},
		},
		{
			name: "ok case new folder",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill: make(chan *os.Signal),
				filePathParams: FilePathParams{
					RootFolder:   "/home",
					FolderName:   "test_scp",
					FileName:     "test.txt",
					FolderRights: "755",
					FileRights:   "777",
					Content:      "hi guys",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			duration, err := SendFileWithScp((tc.inputData).(testInfo).connParams,
				(tc.inputData).(testInfo).kill,
				connTimeout,
				cmdTimeout,
				(tc.inputData).(testInfo).filePathParams)

			tt.Log("duration:", duration)

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}

/////////////////////////////////////////////////
func TestGetCommandOutWithErr2(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams ConnectParams
		kill       chan *os.Signal
		command    string
	}

	testCases := []*testCase{
		{
			name: "ok?",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: okHost,
					Port: okPort,
					User: okUser,
					Psw:  okPsw,
				},
				kill: make(chan *os.Signal),
				command: "python3" + " " + fmt.Sprintf("%v%v/%v", "/home",
					"test", "mg8-----.py"),
			},
			mustFail:  true,
			failError: errorLib.GlobalErrors.ErrSshCommands(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			output, errOut, duration, err := GetCommandOutWithErr((tc.inputData).(testInfo).connParams,
				(tc.inputData).(testInfo).kill,
				connTimeout,
				cmdTimeout,
				(tc.inputData).(testInfo).command)

			tt.Log("out:", string(output))
			tt.Log("errOut:", string(errOut))
			tt.Log("duration:", duration)

			if tc.mustFail {
				assert.Equal(tt, tc.failError, err)
				assert.Error(tt, err)
				return
			}
			if !assert.NoError(tt, err) {
				return
			}
		})
	}
}
