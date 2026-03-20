package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon sizes for system tray.
// macOS: 22x22 (1x) and 44x44 (2x Retina)
// Linux: 22x22 common, some DEs use 16 or 24
// Windows: 16x16 to 128x128, 32x32 is common
const (
	iconSize   = 22 // Standard tray icon size
	iconSize2x = 44 // Retina/HiDPI size
)

// --- Template Icons (macOS) ---
// Template icons use only black + transparent pixels.
// macOS automatically adapts them to light/dark menu bar themes.

var (
	// TemplateIconConnected is a monochrome Bifrost bridge icon for macOS.
	// Used with systray.SetTemplateIcon() for automatic dark mode support.
	TemplateIconConnected = generateBifrostTemplate(iconSize2x, 1.0)

	// TemplateIconDisconnected is a dimmed version (lower alpha) for disabled state.
	TemplateIconDisconnected = generateBifrostTemplate(iconSize2x, 0.4)
)

// --- Color Icons (Linux/Windows) ---
// Color icons are used on platforms that don't support template images.

var (
	// IconConnected is the Bifrost icon in brand green — active state.
	IconConnected = generateBifrostColor(iconSize2x, color.RGBA{R: 76, G: 175, B: 80, A: 255})

	// IconDisconnected is the Bifrost icon in gray — disabled state.
	IconDisconnected = generateBifrostColor(iconSize2x, color.RGBA{R: 158, G: 158, B: 158, A: 255})

	// IconError is the Bifrost icon in red — error state.
	IconError = generateBifrostColor(iconSize2x, color.RGBA{R: 244, G: 67, B: 54, A: 255})

	// IconWarning is the Bifrost icon in amber — warning state.
	IconWarning = generateBifrostColor(iconSize2x, color.RGBA{R: 255, G: 193, B: 7, A: 255})

	// ConnectingAnimationFrames is a set of template icon frames that pulse
	// in opacity for a "connecting" animation. 6 frames at 200ms each = 1.2s cycle.
	// The opacity follows a sine curve: dim → bright → dim.
	ConnectingAnimationFrames = generateAnimationFrames(iconSize2x, 6)
)

// generateBifrostTemplate creates a monochrome (black + alpha) Bifrost bridge icon.
// This is the macOS template format: only black pixels with varying alpha.
// The alphaScale parameter (0.0-1.0) controls overall opacity for state indication.
//
// The icon depicts a stylized bridge arch — the Bifrost (rainbow bridge from Norse mythology).
func generateBifrostTemplate(size int, alphaScale float64) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	center := s / 2.0

	// Draw a bridge arch with two pillars
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx := float64(x)
			fy := float64(y)

			alpha := 0.0

			// --- Arch (top half): parabolic bridge curve ---
			// Arch spans from 15% to 85% of width, peaks at ~30% from top
			archLeft := s * 0.12
			archRight := s * 0.88
			archPeak := s * 0.22
			archBase := s * 0.58

			if fx >= archLeft && fx <= archRight {
				// Normalized x position along arch (0 to 1)
				t := (fx - archLeft) / (archRight - archLeft)
				// Parabolic curve: y = peak + (base-peak) * (2t-1)^2
				archY := archPeak + (archBase-archPeak)*math.Pow(2*t-1, 2)

				// Stroke thickness proportional to icon size
				strokeWidth := s * 0.09
				dist := math.Abs(fy - archY)
				if dist < strokeWidth {
					alpha = 1.0
				} else if dist < strokeWidth+1.0 {
					alpha = 1.0 - (dist - strokeWidth) // anti-alias
				}
			}

			// --- Left pillar ---
			pillarWidth := s * 0.10
			pillarLeft := s*0.17 - pillarWidth/2
			pillarTop := s * 0.50
			pillarBottom := s * 0.85

			if fx >= pillarLeft && fx <= pillarLeft+pillarWidth &&
				fy >= pillarTop && fy <= pillarBottom {
				alpha = 1.0
			}

			// --- Right pillar ---
			pillarRight := s*0.83 - pillarWidth/2
			if fx >= pillarRight && fx <= pillarRight+pillarWidth &&
				fy >= pillarTop && fy <= pillarBottom {
				alpha = 1.0
			}

			// --- Base line (ground) ---
			baseTop := s * 0.82
			baseBottom := s * 0.88
			baseLeft := s * 0.08
			baseRight := s * 0.92

			if fx >= baseLeft && fx <= baseRight &&
				fy >= baseTop && fy <= baseBottom {
				alpha = 1.0
			}

			// --- Small dot above arch (star / connection indicator) ---
			dotCX := center
			dotCY := s * 0.12
			dotR := s * 0.045
			dotDist := math.Sqrt(math.Pow(fx-dotCX, 2) + math.Pow(fy-dotCY, 2))
			if dotDist <= dotR {
				alpha = 1.0
			} else if dotDist <= dotR+1.0 {
				alpha = math.Max(alpha, 1.0-(dotDist-dotR))
			}

			if alpha > 0 {
				a := uint8(clamp(alpha*alphaScale*255, 0, 255))
				img.Set(x, y, color.RGBA{R: 0, G: 0, B: 0, A: a})
			}
		}
	}

	return encodePNG(img)
}

// generateBifrostColor creates a colored Bifrost bridge icon for Linux/Windows.
// Same shape as the template but filled with the given color.
func generateBifrostColor(size int, c color.RGBA) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	center := s / 2.0

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx := float64(x)
			fy := float64(y)

			alpha := 0.0

			// --- Arch ---
			archLeft := s * 0.12
			archRight := s * 0.88
			archPeak := s * 0.22
			archBase := s * 0.58

			if fx >= archLeft && fx <= archRight {
				t := (fx - archLeft) / (archRight - archLeft)
				archY := archPeak + (archBase-archPeak)*math.Pow(2*t-1, 2)
				strokeWidth := s * 0.09
				dist := math.Abs(fy - archY)
				if dist < strokeWidth {
					alpha = 1.0
				} else if dist < strokeWidth+1.0 {
					alpha = 1.0 - (dist - strokeWidth)
				}
			}

			// --- Left pillar ---
			pillarWidth := s * 0.10
			pillarLeft := s*0.17 - pillarWidth/2
			pillarTop := s * 0.50
			pillarBottom := s * 0.85

			if fx >= pillarLeft && fx <= pillarLeft+pillarWidth &&
				fy >= pillarTop && fy <= pillarBottom {
				alpha = 1.0
			}

			// --- Right pillar ---
			pillarRight := s*0.83 - pillarWidth/2
			if fx >= pillarRight && fx <= pillarRight+pillarWidth &&
				fy >= pillarTop && fy <= pillarBottom {
				alpha = 1.0
			}

			// --- Base ---
			baseTop := s * 0.82
			baseBottom := s * 0.88
			baseLeft := s * 0.08
			baseRight := s * 0.92

			if fx >= baseLeft && fx <= baseRight &&
				fy >= baseTop && fy <= baseBottom {
				alpha = 1.0
			}

			// --- Dot ---
			dotCX := center
			dotCY := s * 0.12
			dotR := s * 0.045
			dotDist := math.Sqrt(math.Pow(fx-dotCX, 2) + math.Pow(fy-dotCY, 2))
			if dotDist <= dotR {
				alpha = 1.0
			} else if dotDist <= dotR+1.0 {
				alpha = math.Max(alpha, 1.0-(dotDist-dotR))
			}

			if alpha > 0 {
				a := uint8(clamp(alpha*255, 0, 255))
				img.Set(x, y, color.RGBA{R: c.R, G: c.G, B: c.B, A: a})
			}
		}
	}

	return encodePNG(img)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func encodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

// generateAnimationFrames creates a series of template icon frames with a
// sinusoidal opacity pulse for the "connecting" animation.
// The alpha follows a sine wave: 0.3 → 1.0 → 0.3 over numFrames steps.
func generateAnimationFrames(size int, numFrames int) [][]byte {
	frames := make([][]byte, numFrames)
	for i := 0; i < numFrames; i++ {
		// Sine wave: maps frame index to 0.3..1.0 range
		t := float64(i) / float64(numFrames)
		alpha := 0.3 + 0.7*math.Pow(math.Sin(t*math.Pi), 2)
		frames[i] = generateBifrostTemplate(size, alpha)
	}
	return frames
}
