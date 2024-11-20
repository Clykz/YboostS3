package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

// Déchiffre un fichier et écrase le fichier d'origine
func decryptFileInPlace(filePath string, key []byte) error {
	// Lire le contenu du fichier chiffré
	cipherText, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("erreur lors de la lecture du fichier : %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("erreur lors de la création du bloc AES : %v", err)
	}

	// Vérifier que le fichier est valide
	if len(cipherText) < aes.BlockSize {
		return fmt.Errorf("le texte chiffré est trop court")
	}

	// Extraire l'IV
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// Déchiffrer les données
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	// Écrire le contenu déchiffré dans le même fichier
	if err := ioutil.WriteFile(filePath, cipherText, 0644); err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier déchiffré : %v", err)
	}

	return nil
}

func main() {
	// Chemin du fichier à déchiffrer
	filePath := "/Users/dylan/Documents/mdp.txt"

	// Clé utilisée pour le chiffrement (remplacez par votre clé hexadécimale)
	keyHex := "cda3fc754d18139f34f48e697fb8ee981ce35969dcdf22220b81bedc4e21bf2d" // Exemple : "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Convertir la clé hexadécimale en bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Println("Erreur lors de la conversion de la clé :", err)
		return
	}
	// Déchiffrement
	fmt.Println("Déchiffrement du fichier :", filePath)
	if err := decryptFileInPlace(filePath, key); err != nil {
		fmt.Println("Erreur lors du déchiffrement :", err)
		return
	}
	fmt.Println("Fichier déchiffré avec succès.")
}
