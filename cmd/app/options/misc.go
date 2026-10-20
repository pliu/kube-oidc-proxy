// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/spf13/pflag"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
)

type MiscOptions struct{}

func NewMiscOptions(nfs *cliflag.NamedFlagSets) *MiscOptions {
	m := &MiscOptions{}
	return m.AddFlags(nfs.FlagSet("Misc"))
}

func (m *MiscOptions) AddFlags(fs *pflag.FlagSet) *MiscOptions {
	globalflag.AddGlobalFlags(fs, AppName)
	fs.Bool("version", false, "Print version information and quit")
	return m
}

func (m *MiscOptions) PrintVersionAndExit() {
	info := apimachineryversion.Info{
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}

	// go build stamps the module version and the VCS state of the checkout
	// into the binary.
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.GitVersion = bi.Main.Version
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.GitCommit = s.Value
			case "vcs.time":
				info.BuildDate = s.Value
			case "vcs.modified":
				info.GitTreeState = "clean"
				if s.Value == "true" {
					info.GitTreeState = "dirty"
				}
			}
		}
	}

	fmt.Printf("%s version: %#v\n", AppName, info)

	os.Exit(0)
}
