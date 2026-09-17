package main

import (
	"embed"
	"runtime"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if runtime.GOOS != "windows" {
		panic("This launcher only supports Windows")
	}

	hideConsole()
	enableDpiAwareness()

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Bee - 蜜罐渗透测试平台",
		Width:     1280,
		Height:    800,
		MinWidth:  900,
		MinHeight: 600,
		Frameless: false,
		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 12, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		OnDomReady: app.domReady,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		app.logError("wails run failed: %v", err)
	}
}