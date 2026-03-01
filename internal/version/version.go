package version

import "strings"

var (
	Version    = "dev"
	Commit     = "unknown"
	BuildTime  = ""
	SourceRepo = "https://github.com/2high4schooltoday/new-mail-client"
)

type Info struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuildTime  string `json:"build_time"`
	SourceRepo string `json:"source_repo"`
}

func Current() Info {
	out := Info{
		Version:    strings.TrimSpace(Version),
		Commit:     strings.TrimSpace(Commit),
		BuildTime:  strings.TrimSpace(BuildTime),
		SourceRepo: strings.TrimSpace(SourceRepo),
	}
	if out.Version == "" {
		out.Version = "dev"
	}
	if out.Commit == "" {
		out.Commit = "unknown"
	}
	if out.SourceRepo == "" {
		out.SourceRepo = "https://github.com/2high4schooltoday/new-mail-client"
	}
	return out
}
