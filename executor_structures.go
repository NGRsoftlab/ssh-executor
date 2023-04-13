package sshExecutor

// Ssh term sizes
const (
	xTermHeight = 80
	xTermWidth  = 40
)

// FilePathParams params for scp file sending
type FilePathParams struct {
	RootFolder   string
	FolderName   string
	FolderRights string
	FileName     string
	FileRights   string
	Content      string
}

// ConnectParams params for ssh connection
type ConnectParams struct {
	Host string
	Port int
	User string
	Psw  string
}
