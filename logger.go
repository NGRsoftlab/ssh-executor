// Copyright © NGR Softlab 2020-2024
package sshExecutor

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})

	Debug(args ...interface{})
	Info(args ...interface{})
	Warning(args ...interface{})
	Error(args ...interface{})
}

var (
	logger Logger = &logrus.Logger{
		Out:   io.MultiWriter(os.Stderr),
		Level: logrus.DebugLevel,
		Formatter: &logrus.TextFormatter{
			FullTimestamp:          true,
			TimestampFormat:        "2006-01-02 15:04:05",
			ForceColors:            true,
			DisableLevelTruncation: true,
		},
		ReportCaller: true,
	}
)

func SetLogger(l Logger) {
	logger = l
}
