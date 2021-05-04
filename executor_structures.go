package sshExecutor

// Ssh term sizes
const (
	xTermHeight = 80
	xTermWidth  = 40
)

// Params for scp file sending
type FilePathParams struct {
	RootFolder   string
	FolderName   string
	FolderRights string
	FileName     string
	FileRights   string
	Content      string
}

// Params for ssh connection
type ConnectParams struct {
	Host string
	Port string
	User string
	Psw  string
}
