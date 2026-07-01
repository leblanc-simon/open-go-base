package mfax

import (
	"encoding/base64"

	"rsc.io/qr"
)

// QRPNG encode un texte (typiquement une URL otpauth://) en QR code PNG, au
// niveau de correction M. Pratique pour servir directement l'image.
func QRPNG(text string) ([]byte, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}

// QRDataURI encode un texte en QR code et renvoie un data URI base64
// (data:image/png;base64,...) prêt à poser dans un attribut src.
//
// Attention : html/template assainit les URL et remplace un data: URI par
// #ZgotmlZ. Côté template, typer le champ en template.URL (sûr ici : la valeur
// est entièrement construite côté serveur, sans donnée utilisateur).
func QRDataURI(text string) (string, error) {
	png, err := QRPNG(text)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
