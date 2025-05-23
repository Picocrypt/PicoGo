package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type Theme struct {
	Scale float32
}

func (t Theme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff}
	default:
		return theme.DarkTheme().Color(name, variant)
	}
}
func (t Theme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DarkTheme().Font(style)
}
func (t Theme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DarkTheme().Icon(name)
}
func (t Theme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DarkTheme().Size(name) * t.Scale
}

func NewTheme(scale float32) Theme {
	return Theme{Scale: scale}
}
