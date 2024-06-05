// Copyright © NGR Softlab 2020-2024
package sshExecutor

import (
	"errors"
	"testing"
	"time"

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

func TestGetSshConnection(t *testing.T) {
	t.Parallel()

	type testInfo struct {
		connParams ConnectParams
		timeout    time.Duration
	}

	testCases := []*testCase{
		{
			name: "bad host connection",
			inputData: testInfo{
				connParams: ConnectParams{
					Host: "999.999.999.999",
					Port: 22,
					User: "test",
					Psw:  "test",
				},
				timeout: connTimeout,
			},
			failError: errors.New("invalid ip or port for connection"),
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
