package main

import (
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
)

func request(pi l.Input) l.Output {
	return l.PluginError("request failed")
}

func revoke(pi l.Input) l.Output {
	return l.PluginError("revocation failed")
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:       "0.1.0",
		Author:        "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		Actions: map[string]l.Action{
			"request": request,
			"revoke": revoke,
		},
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "cert_valid_duration", Type: "string", Default: "11"},
		},
		RequestParams: []l.RequestParamsDescriptor{},
	}
	l.PluginRun(pluginDescriptor)
}
