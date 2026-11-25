package protocol

// RemoteConfigurationErr indicates a failure to resolve or connect to a remote keyserver.
type RemoteConfigurationErr struct {
	Err error
}

func (rce RemoteConfigurationErr) Error() string {
	return rce.Err.Error()
}
