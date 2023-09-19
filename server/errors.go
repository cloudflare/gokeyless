package server

type RemoteConfigurationErr struct {
	Err error
}

func (rce RemoteConfigurationErr) Error() string {
	return rce.Err.Error()
}
