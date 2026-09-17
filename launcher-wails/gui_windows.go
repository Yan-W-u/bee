//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procFreeConsole                   = kernel32.NewProc("FreeConsole")
	procSetProcessDpiAwarenessContext = kernel32.NewProc("SetProcessDpiAwarenessContext")

	user32                    = syscall.NewLazyDLL("user32.dll")
	procFindWindowW           = user32.NewProc("FindWindowW")
	procSetWindowLongPtrW     = user32.NewProc("SetWindowLongPtrW")
	procGetWindowLongPtrW     = user32.NewProc("GetWindowLongPtrW")
	procSetWindowPos          = user32.NewProc("SetWindowPos")

	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")

	dwmapi                           = syscall.NewLazyDLL("dwmapi.dll")
	procDwmSetWindowAttribute        = dwmapi.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea = dwmapi.NewProc("DwmExtendFrameIntoClientArea")
)

const (
	WS_CAPTION                     = 0x00C00000
	WS_THICKFRAME                  = 0x00040000
	WS_MAXIMIZEBOX                 = 0x00010000
	WS_MINIMIZEBOX                 = 0x00020000
	WS_SYSMENU                     = 0x00080000
	WS_BORDER                      = 0x00800000
	WS_DLGFRAME                    = 0x00400000
	WS_EX_CLIENTEDGE               = 0x00000200
	WS_EX_WINDOWEDGE               = 0x00000100

	HWND_TOP       = 0
	SWP_NOMOVE     = 0x0002
	SWP_NOSIZE     = 0x0001
	SWP_FRAMECHANGED = 0x0020
	SWP_SHOWWINDOW   = 0x0040

	DWMWA_USE_IMMERSIVE_DARK_MODE  = 20
	DWMWA_WINDOW_CORNER_PREFERENCE = 33
	DWMWA_BORDER_COLOR             = 34
	DWMWA_CAPTION_COLOR            = 35

	DWMWCP_DEFAULT    = 0
	DWMWCP_DONOTROUND = 1
	DWMWCP_ROUND      = 2
	DWMWCP_ROUNDSMALL = 3
)

const (
	GWL_STYLE   uintptr = ^uintptr(15) // -16
	GWL_EXSTYLE uintptr = ^uintptr(19) // -20
	DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 uintptr = ^uintptr(3) // -4

	SW_HIDE            = 0
	SW_SHOWMINNOACTIVE = 7
)

type dwmMargin struct {
	cxLeftWidth    int32
	cxRightWidth   int32
	cyTopHeight    int32
	cyBottomHeight int32
}

// hideConsole detaches the process from its console window so the launcher can
// run as a background/GUI application without showing a terminal.
func hideConsole() {
	_, _, _ = procFreeConsole.Call()
}

// enableDpiAwareness opts the process into per-monitor DPI awareness before
// Wails creates the WebView2 window, ensuring crisp text on high-DPI displays.
func enableDpiAwareness() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		_, _, _ = procSetProcessDpiAwarenessContext.Call(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
	}
}

// findMainWindow returns the HWND of the window with the given title prefix.
func findMainWindow(title string) uintptr {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
	return hwnd
}

// makeWindowModern keeps the standard window caption (so the window is draggable
// and has minimize/maximize/close buttons) but paints the title bar and border
// dark to match the application theme.
func makeWindowModern(hwnd uintptr) {
	if hwnd == 0 {
		return
	}

	var darkMode uint32 = 1
	_, _, _ = procDwmSetWindowAttribute.Call(
		hwnd,
		uintptr(DWMWA_USE_IMMERSIVE_DARK_MODE),
		uintptr(unsafe.Pointer(&darkMode)),
		uintptr(4),
	)

	var cornerPref uint32 = DWMWCP_ROUND
	_, _, _ = procDwmSetWindowAttribute.Call(
		hwnd,
		uintptr(DWMWA_WINDOW_CORNER_PREFERENCE),
		uintptr(unsafe.Pointer(&cornerPref)),
		uintptr(4),
	)

	// Match the title bar and border to the app's background colour (R:10, G:10, B:12).
	var borderColor uint32 = 0xFF0A0A0C
	_, _, _ = procDwmSetWindowAttribute.Call(
		hwnd,
		uintptr(DWMWA_BORDER_COLOR),
		uintptr(unsafe.Pointer(&borderColor)),
		uintptr(4),
	)

	var captionColor uint32 = 0xFF0A0A0C
	_, _, _ = procDwmSetWindowAttribute.Call(
		hwnd,
		uintptr(DWMWA_CAPTION_COLOR),
		uintptr(unsafe.Pointer(&captionColor)),
		uintptr(4),
	)

	var m dwmMargin
	_, _, _ = procDwmExtendFrameIntoClientArea.Call(hwnd, uintptr(unsafe.Pointer(&m)))

	_, _, _ = procSetWindowPos.Call(
		hwnd,
		uintptr(HWND_TOP),
		0, 0, 0, 0,
		uintptr(SWP_NOMOVE|SWP_NOSIZE|SWP_FRAMECHANGED|SWP_SHOWWINDOW),
	)
}

// runElevated runs program with the "runas" verb, which requests administrator
// privileges via UAC. This is used to start Docker Desktop when the Windows
// service is stopped and the current process is not elevated.
func runElevated(program, args string, showCmd int) error {
	progPtr, err := syscall.UTF16PtrFromString(program)
	if err != nil {
		return err
	}
	var argsPtr *uint16
	if args != "" {
		argsPtr, err = syscall.UTF16PtrFromString(args)
		if err != nil {
			return err
		}
	}
	opPtr, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(opPtr)),
		uintptr(unsafe.Pointer(progPtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		0,
		uintptr(showCmd),
	)
	// ShellExecute returns a fake HINSTANCE value greater than 32 on success.
	if ret <= 32 {
		return syscall.Errno(ret)
	}
	return nil
}
