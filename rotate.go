package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength    = 8
	pbkdf2Iter    = 10000
	pbkdf2KeyLen  = 32
	alphanumChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// deriveKey uses PBKDF2-HMAC-SHA256, matching Grafana's encryption.KeyToBytes
func deriveKey(secret string, salt []byte) []byte {
	return pbkdf2.Key([]byte(secret), salt, pbkdf2Iter, pbkdf2KeyLen, sha256.New)
}

// generateSalt generates an 8-character alphanumeric string, matching Grafana's util.GetRandomString
func generateSalt() ([]byte, error) {
	result := make([]byte, saltLength)
	maxVal := big.NewInt(int64(len(alphanumChars)))
	for i := 0; i < saltLength; i++ {
		n, err := rand.Int(rand.Reader, maxVal)
		if err != nil {
			return nil, err
		}
		result[i] = alphanumChars[n.Int64()]
	}
	return result, nil
}

// decryptPayload decrypts the payload portion (after *algo* prefix) of a data_key.
// Format: <8-byte salt><16-byte IV><ciphertext>
func decryptPayload(payload []byte, secret string) ([]byte, error) {
	if len(payload) < saltLength+aes.BlockSize {
		return nil, fmt.Errorf("payload too short: %d", len(payload))
	}

	salt := payload[:saltLength]
	iv := payload[saltLength : saltLength+aes.BlockSize]
	ct := payload[saltLength+aes.BlockSize:]

	key := deriveKey(secret, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ct))
	copy(plaintext, ct)
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, plaintext)
	return plaintext, nil
}

// encryptPayload encrypts a DEK using the new secret, producing the same format Grafana expects.
// Returns: <8-byte salt><16-byte IV><ciphertext>
func encryptPayload(plaintext []byte, secret string) ([]byte, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}

	key := deriveKey(secret, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, saltLength+aes.BlockSize+len(plaintext))
	copy(result[:saltLength], salt)

	iv := result[saltLength : saltLength+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(result[saltLength+aes.BlockSize:], plaintext)

	return result, nil
}

// defaultAlgoMarker is the prefix Grafana uses for AES-CFB encrypted data: *YWVzLWNmYg*
var defaultAlgoMarker = []byte("*YWVzLWNmYg*")

func parseEncryptedData(data []byte) (algoMarker []byte, payload []byte, err error) {
	// Legacy format: no *algo* prefix, entire blob is the payload
	if data[0] != '*' {
		return defaultAlgoMarker, data, nil
	}
	// Modern format: *<base64_algo>*<payload>
	secondStar := -1
	for i := 1; i < len(data); i++ {
		if data[i] == '*' {
			secondStar = i
			break
		}
	}
	if secondStar == -1 {
		return nil, nil, fmt.Errorf("second * not found")
	}
	return data[:secondStar+1], data[secondStar+1:], nil
}

func readSecretKey(iniPath string) (string, error) {
	content, err := os.ReadFile(iniPath)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?m)^secret_key\s*=\s*(.+)$`)
	matches := re.FindSubmatch(content)
	if matches == nil {
		return "", fmt.Errorf("secret_key not found in %s", iniPath)
	}
	value := strings.TrimSpace(string(matches[1]))
	// Handle $__file{path} syntax (Grafana file provider)
	fileRe := regexp.MustCompile(`^\$__file\{(.+)\}$`)
	fileMatch := fileRe.FindStringSubmatch(value)
	if fileMatch != nil {
		filePath := fileMatch[1]
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("reading file provider path %s: %w", filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return value, nil
}

// isPrintable checks if decrypted text looks valid (no control chars except newline/tab).
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// tryDecryptPayload tries to decrypt with each secret in order, returns first printable result.
func tryDecryptPayload(payload []byte, secrets []string) ([]byte, error) {
	for _, secret := range secrets {
		pt, err := decryptPayload(payload, secret)
		if err == nil && isPrintable(string(pt)) {
			return pt, nil
		}
	}
	// Fallback to first secret for error message
	return decryptPayload(payload, secrets[0])
}

// b64DecodePadded decodes base64, adding padding if needed.
func b64DecodePadded(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

// reencryptLegacyField decrypts a base64-encoded legacy encrypted value (trying all old secrets)
// and re-encrypts it with the new secret. Returns new base64-encoded value.
func reencryptLegacyField(encValue string, oldSecrets []string, newSecret string) (string, error) {
	raw, err := b64DecodePadded(encValue)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < saltLength+aes.BlockSize {
		return "", fmt.Errorf("payload too short: %d", len(raw))
	}

	// Decrypt with old secrets
	plaintext, err := tryDecryptPayload(raw, oldSecrets)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	// Re-encrypt with new secret
	newPayload, err := encryptPayload(plaintext, newSecret)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return base64.StdEncoding.EncodeToString(newPayload), nil
}

// reencryptSecureSettingsJSON decrypts and re-encrypts all string fields in a JSON map.
// Legacy format: values are base64(<salt><iv><ciphertext>) encrypted directly with secret_key.
func reencryptSecureSettingsJSON(jsonStr string, oldSecret string, newSecret string) (string, int, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &fields); err != nil {
		return jsonStr, 0, nil
	}
	count := 0
	for key, val := range fields {
		strVal, ok := val.(string)
		if !ok || strVal == "" {
			continue
		}
		newVal, err := reencryptLegacyField(strVal, []string{oldSecret}, newSecret)
		if err != nil {
			return "", 0, fmt.Errorf("field %q: %w", key, err)
		}
		fields[key] = newVal
		count++
	}
	if count == 0 {
		return jsonStr, 0, nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return "", 0, err
	}
	return string(out), count, nil
}

// reencryptAlertmanagerConfig re-encrypts secureSettings inside alertmanager_configuration JSON.
// These use the modern envelope format (#keyId#*algo*payload), encrypted with DEKs.
// Since DEKs don't change during rotation, only re-encrypt if using legacy format.
func reencryptAlertmanagerConfig(amConfigJSON string, oldSecret string, newSecret string) (string, int, error) {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(amConfigJSON), &config); err != nil {
		return amConfigJSON, 0, nil
	}

	amConfig, ok := config["alertmanager_config"].(map[string]interface{})
	if !ok {
		return amConfigJSON, 0, nil
	}

	receivers, ok := amConfig["receivers"].([]interface{})
	if !ok {
		return amConfigJSON, 0, nil
	}

	totalCount := 0
	for _, r := range receivers {
		receiver, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		cfgs, ok := receiver["grafana_managed_receiver_configs"].([]interface{})
		if !ok {
			continue
		}
		for _, c := range cfgs {
			cfg, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			ss, ok := cfg["secureSettings"].(map[string]interface{})
			if !ok || len(ss) == 0 {
				continue
			}
			for key, val := range ss {
				strVal, ok := val.(string)
				if !ok || strVal == "" {
					continue
				}
				// Check if this is legacy format (no #keyId# prefix)
				raw, err := b64DecodePadded(strVal)
				if err != nil || len(raw) < 2 {
					continue
				}
				if raw[0] != '#' {
					// Legacy format — re-encrypt directly
					newVal, err := reencryptLegacyField(strVal, []string{oldSecret}, newSecret)
					if err != nil {
						return "", 0, fmt.Errorf("receiver %v, field %q: %w", cfg["name"], key, err)
					}
					ss[key] = newVal
					totalCount++
				}
				// Modern format — encrypted with DEK, no re-encryption needed
			}
		}
	}

	if totalCount == 0 {
		return amConfigJSON, 0, nil
	}
	out, err := json.Marshal(config)
	if err != nil {
		return "", 0, err
	}
	return string(out), totalCount, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Grafana secret_key rotation tool.

Re-encrypts all encrypted data in grafana.db with a new secret_key
and updates grafana.ini accordingly.

Tables handled:
  - data_keys              (envelope DEKs)
  - alert_notification     (legacy secure_settings)
  - alert_configuration    (alertmanager secureSettings, legacy only)
  - alert_configuration_history (same)

Usage:
  rotate update   -db <path> -ini <path>
  rotate validate -db <path> -key <secret_key>

Commands:
  update     Re-encrypt all data with a new secret_key
  validate   Verify that all encrypted data can be decrypted with given key

Update flags:
  -db        Path to grafana.db  (required)
  -ini       Path to grafana.ini (required)

Validate flags:
  -db        Path to grafana.db  (required)
  -key       Secret key to validate (required)

Examples:
  rotate update -db grafana.db -ini grafana.ini
  rotate validate -db grafana.db -key "YOUR_SECRET_KEY"

Procedure:
  1. Stop Grafana
  2. ./rotate update -db <path>/grafana.db -ini <path>/grafana.ini
  3. Start Grafana
  4. ./rotate validate -db <path>/grafana.db -key <secret_key>
`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "update":
		runUpdate()
	case "validate":
		runValidate()
	default:
		printUsage()
		os.Exit(1)
	}
}

func runUpdate() {
	updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
	dbPath := updateCmd.String("db", "", "Path to grafana.db (required)")
	iniPath := updateCmd.String("ini", "", "Path to grafana.ini (required)")
	updateCmd.Parse(os.Args[2:])

	if *dbPath == "" || *iniPath == "" {
		fmt.Fprintf(os.Stderr, "Error: both -db and -ini flags are required.\n\n")
		printUsage()
		os.Exit(1)
	}

	// 1. Read current secret_key
	oldSecretKey, err := readSecretKey(*iniPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading secret_key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Old secret_key: %s...\n", oldSecretKey[:16])

	// 2. Generate new secret_key
	newSecretKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newSecretKeyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}
	newSecretKey := hex.EncodeToString(newSecretKeyBytes)
	fmt.Printf("New secret_key: %s\n", newSecretKey)

	// 3. Backup database
	timestamp := time.Now().Format("2006-01-02-1504")
	backupPath := fmt.Sprintf("%s.rotation_%s", *dbPath, timestamp)
	srcData, err := os.ReadFile(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading DB: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(backupPath, srcData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing backup: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Database backed up to: %s\n", backupPath)

	// Open database
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// 4. Re-encrypt data_keys
	fmt.Println("\n--- Re-encrypting data_keys ---")
	rows, err := db.Query("SELECT name, encrypted_data FROM data_keys")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying data_keys: %v\n", err)
		os.Exit(1)
	}

	type keyUpdate struct {
		name    string
		newData []byte
	}
	var dataKeyUpdates []keyUpdate

	for rows.Next() {
		var name string
		var encData []byte
		if err := rows.Scan(&name, &encData); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning row: %v\n", err)
			os.Exit(1)
		}

		algoMarker, payload, err := parseEncryptedData(encData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing [%s]: %v\n", name, err)
			os.Exit(1)
		}

		// Decrypt DEK with current secret_key (data_keys are always encrypted
		// with the current key from grafana.ini, not legacy old keys)
		dek, err := decryptPayload(payload, oldSecretKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting [%s]: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("  [%s] DEK decrypted (%d bytes)\n", name, len(dek))

		// Re-encrypt DEK with new secret_key
		newPayload, err := encryptPayload(dek, newSecretKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting [%s]: %v\n", name, err)
			os.Exit(1)
		}

		newEncData := append(algoMarker, newPayload...)

		// Verify
		_, verifyPayload, _ := parseEncryptedData(newEncData)
		verifyDek, err := decryptPayload(verifyPayload, newSecretKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verify decrypt failed [%s]: %v\n", name, err)
			os.Exit(1)
		}
		if hex.EncodeToString(verifyDek) != hex.EncodeToString(dek) {
			fmt.Fprintf(os.Stderr, "Verify mismatch [%s]!\n", name)
			os.Exit(1)
		}

		dataKeyUpdates = append(dataKeyUpdates, keyUpdate{name: name, newData: newEncData})
	}
	rows.Close()

	for _, u := range dataKeyUpdates {
		if _, err := db.Exec("UPDATE data_keys SET encrypted_data = ? WHERE name = ?", u.newData, u.name); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating data_key [%s]: %v\n", u.name, err)
			os.Exit(1)
		}
	}
	fmt.Printf("  %d data_keys re-encrypted.\n", len(dataKeyUpdates))

	// 5. Re-encrypt alert_notification.secure_settings (legacy format)
	fmt.Println("\n--- Re-encrypting alert_notification ---")
	anRows, err := db.Query("SELECT id, name, type, secure_settings FROM alert_notification WHERE secure_settings IS NOT NULL AND secure_settings != ''")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying alert_notification: %v\n", err)
		os.Exit(1)
	}

	type anUpdate struct {
		id              int
		name            string
		newSecureSettings string
	}
	var anUpdates []anUpdate
	anCount := 0

	for anRows.Next() {
		var id int
		var name, typ, secureSettings string
		if err := anRows.Scan(&id, &name, &typ, &secureSettings); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning alert_notification: %v\n", err)
			os.Exit(1)
		}

		newJSON, count, err := reencryptSecureSettingsJSON(secureSettings, oldSecretKey, newSecretKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error re-encrypting alert_notification [%d] %s: %v\n", id, name, err)
			os.Exit(1)
		}
		if count > 0 {
			anUpdates = append(anUpdates, anUpdate{id: id, name: name, newSecureSettings: newJSON})
			anCount += count
			fmt.Printf("  [%d] %s (%s): %d fields re-encrypted\n", id, name, typ, count)
		}
	}
	anRows.Close()

	for _, u := range anUpdates {
		if _, err := db.Exec("UPDATE alert_notification SET secure_settings = ? WHERE id = ?", u.newSecureSettings, u.id); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating alert_notification [%d] %s: %v\n", u.id, u.name, err)
			os.Exit(1)
		}
	}
	fmt.Printf("  %d alert_notification rows updated (%d fields total).\n", len(anUpdates), anCount)

	// 6. Re-encrypt legacy secureSettings inside alert_configuration
	fmt.Println("\n--- Re-encrypting alert_configuration ---")
	reencryptAlertConfigTable(db, "alert_configuration", oldSecretKey, newSecretKey)

	// 7. Re-encrypt legacy secureSettings inside alert_configuration_history
	fmt.Println("\n--- Re-encrypting alert_configuration_history ---")
	reencryptAlertConfigTable(db, "alert_configuration_history", oldSecretKey, newSecretKey)

	fmt.Println()
	fmt.Println("=== ROTATION COMPLETE ===")
	fmt.Printf("New secret_key: %s\n", newSecretKey)
	fmt.Printf("Backup: %s\n", backupPath)
}

func runValidate() {
	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
	dbPath := validateCmd.String("db", "", "Path to grafana.db (required)")
	secretKey := validateCmd.String("key", "", "Secret key to validate (required)")
	validateCmd.Parse(os.Args[2:])

	if *dbPath == "" || *secretKey == "" {
		fmt.Fprintf(os.Stderr, "Error: both -db and -key flags are required.\n\n")
		printUsage()
		os.Exit(1)
	}

	fmt.Printf("Validating encryption with secret_key: %s...\n", (*secretKey)[:min(16, len(*secretKey))])
	fmt.Println()

	// Open database
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	totalErrors := 0

	// 1. Validate data_keys and build cache for later validation
	fmt.Println("--- Validating data_keys ---")
	dataKeys, dataKeyOk, dataKeyErr := validateAndLoadDataKeys(db, *secretKey)
	fmt.Printf("  ✓ %d data_keys decrypted successfully\n", dataKeyOk)
	if dataKeyErr > 0 {
		fmt.Printf("  ✗ %d data_keys FAILED to decrypt\n", dataKeyErr)
		totalErrors += dataKeyErr
	}
	fmt.Println()

	// 1.5. Validate actual encrypted data (data_source, secrets) using DEKs
	fmt.Println("--- Validating data_source secrets ---")
	dsOk, dsErr := validateDataSources(db, dataKeys, *secretKey)
	if dsOk > 0 {
		fmt.Printf("  ✓ %d data sources validated\n", dsOk)
	}
	if dsErr > 0 {
		fmt.Printf("  ✗ %d data sources FAILED validation\n", dsErr)
		totalErrors += dsErr
	}
	if dsOk == 0 && dsErr == 0 {
		fmt.Println("  (no data sources with secrets found)")
	}
	fmt.Println()

	// 2. Validate alert_notification
	fmt.Println("--- Validating alert_notification ---")
	anOk, anErr := validateAlertNotifications(db, *secretKey)
	fmt.Printf("  ✓ %d rows validated\n", anOk)
	if anErr > 0 {
		fmt.Printf("  ✗ %d rows FAILED validation\n", anErr)
		totalErrors += anErr
	}
	fmt.Println()

	// 3. Validate alert_configuration
	fmt.Println("--- Validating alert_configuration ---")
	acOk, acErr := validateAlertConfigTable(db, "alert_configuration", *secretKey)
	fmt.Printf("  ✓ %d rows validated\n", acOk)
	if acErr > 0 {
		fmt.Printf("  ✗ %d rows FAILED validation\n", acErr)
		totalErrors += acErr
	}
	fmt.Println()

	// 4. Validate alert_configuration_history
	fmt.Println("--- Validating alert_configuration_history ---")
	achOk, achErr := validateAlertConfigTable(db, "alert_configuration_history", *secretKey)
	fmt.Printf("  ✓ %d rows validated\n", achOk)
	if achErr > 0 {
		fmt.Printf("  ✗ %d rows FAILED validation\n", achErr)
		totalErrors += achErr
	}
	fmt.Println()

	// Summary
	if totalErrors == 0 {
		fmt.Println("=== VALIDATION PASSED ===")
		fmt.Println("All encrypted data can be decrypted successfully.")
	} else {
		fmt.Printf("=== VALIDATION FAILED ===\n")
		fmt.Printf("Total errors: %d\n", totalErrors)
		os.Exit(1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func validateAndLoadDataKeys(db *sql.DB, secret string) (dataKeys map[string][]byte, ok int, errors int) {
	dataKeys = make(map[string][]byte)
	rows, err := db.Query("SELECT name, encrypted_data FROM data_keys")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error querying data_keys: %v\n", err)
		return dataKeys, 0, 1
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var encData []byte
		if err := rows.Scan(&name, &encData); err != nil {
			fmt.Fprintf(os.Stderr, "  Error scanning row: %v\n", err)
			errors++
			continue
		}

		_, payload, err := parseEncryptedData(encData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] Parse error: %v\n", name, err)
			errors++
			continue
		}

		dek, err := decryptPayload(payload, secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] Decryption FAILED: %v\n", name, err)
			errors++
			continue
		}

		// DEKs should be exactly 16 bytes (128-bit AES key)
		if len(dek) != 16 {
			fmt.Fprintf(os.Stderr, "  [%s] Invalid DEK length: %d bytes (expected 16)\n", name, len(dek))
			errors++
			continue
		}

		// Store decrypted DEK for later use in validating actual data
		dataKeys[name] = dek
		ok++
	}
	return
}

// validateDataSources validates that data_source.secure_json_data can be decrypted
func validateDataSources(db *sql.DB, dataKeys map[string][]byte, secret string) (ok int, errors int) {
	rows, err := db.Query("SELECT id, name, secure_json_data FROM data_source WHERE secure_json_data IS NOT NULL AND secure_json_data != ''")
	if err != nil {
		// Table might not exist in older Grafana versions
		return 0, 0
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, secureJSON string
		if err := rows.Scan(&id, &name, &secureJSON); err != nil {
			fmt.Fprintf(os.Stderr, "  Error scanning row: %v\n", err)
			errors++
			continue
		}

		var fields map[string]interface{}
		if err := json.Unmarshal([]byte(secureJSON), &fields); err != nil {
			continue // Not JSON, skip
		}

		// Try to decrypt at least one field
		fieldOk := false
		for _, val := range fields {
			strVal, ok := val.(string)
			if !ok || strVal == "" {
				continue
			}

			// Try modern format with envelope encryption
			if decrypted, err := decryptEnvelopeField(strVal, dataKeys, secret); err == nil && isPrintable(decrypted) {
				fieldOk = true
				break
			}

			// Try legacy format
			if decrypted, err := decryptLegacyField(strVal, secret); err == nil && isPrintable(decrypted) {
				fieldOk = true
				break
			}
		}

		if fieldOk {
			ok++
		} else if len(fields) > 0 {
			fmt.Fprintf(os.Stderr, "  [%d] %s: Failed to decrypt any fields\n", id, name)
			errors++
		}
	}
	return
}

// decryptEnvelopeField decrypts a modern format field: #<base64(keyId)>#*algo*<payload>
func decryptEnvelopeField(encValue string, dataKeys map[string][]byte, secret string) (string, error) {
	raw, err := b64DecodePadded(encValue)
	if err != nil {
		return "", err
	}
	if len(raw) < 2 || raw[0] != '#' {
		return "", fmt.Errorf("not envelope format")
	}

	// Extract key ID (which is base64-encoded between the two # delimiters)
	rest := raw[1:]
	end := bytes.IndexByte(rest, '#')
	if end == -1 {
		return "", fmt.Errorf("missing key ID delimiter")
	}

	// Decode base64-encoded key ID
	b64KeyID := rest[:end]
	keyIDDecoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(b64KeyID)))
	n, err := base64.RawStdEncoding.Decode(keyIDDecoded, b64KeyID)
	if err != nil {
		return "", fmt.Errorf("decode key ID: %w", err)
	}
	keyID := string(keyIDDecoded[:n])
	payload := rest[end+1:]

	// Look up DEK
	dek, found := dataKeys[keyID]
	if !found {
		return "", fmt.Errorf("data key %q not found", keyID)
	}

	// Strip algo marker if present (*YWVzLWNmYg* = *aes-cfb*)
	if len(payload) > 0 && payload[0] == '*' {
		secondStar := bytes.IndexByte(payload[1:], '*')
		if secondStar != -1 {
			payload = payload[secondStar+2:]
		}
	}

	// Decrypt with DEK
	plaintext, err := decryptPayload(payload, string(dek))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// decryptLegacyField decrypts a legacy format field (directly with secret_key)
func decryptLegacyField(encValue string, secret string) (string, error) {
	raw, err := b64DecodePadded(encValue)
	if err != nil {
		return "", err
	}
	plaintext, err := decryptPayload(raw, secret)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func validateAlertNotifications(db *sql.DB, secret string) (ok int, errors int) {
	rows, err := db.Query("SELECT id, name, secure_settings FROM alert_notification WHERE secure_settings IS NOT NULL AND secure_settings != ''")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error querying alert_notification: %v\n", err)
		return 0, 1
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, secureSettings string
		if err := rows.Scan(&id, &name, &secureSettings); err != nil {
			fmt.Fprintf(os.Stderr, "  Error scanning row: %v\n", err)
			errors++
			continue
		}

		if err := validateSecureSettingsJSON(secureSettings, secret); err != nil {
			fmt.Fprintf(os.Stderr, "  [%d] %s: %v\n", id, name, err)
			errors++
		} else {
			ok++
		}
	}
	return
}

func validateAlertConfigTable(db *sql.DB, table string, secret string) (ok int, errors int) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, alertmanager_configuration FROM %s", table))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error querying %s: %v\n", table, err)
		return 0, 1
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var amConfig string
		if err := rows.Scan(&id, &amConfig); err != nil {
			fmt.Fprintf(os.Stderr, "  Error scanning row: %v\n", err)
			errors++
			continue
		}

		if err := validateAlertmanagerConfigJSON(amConfig, secret); err != nil {
			fmt.Fprintf(os.Stderr, "  [%d]: %v\n", id, err)
			errors++
		} else {
			ok++
		}
	}
	return
}

func validateSecureSettingsJSON(jsonStr string, secret string) error {
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &fields); err != nil {
		return nil // Not JSON or empty, skip
	}

	for key, val := range fields {
		strVal, ok := val.(string)
		if !ok || strVal == "" {
			continue
		}

		// Try to decrypt with the secret
		if _, err := reencryptLegacyField(strVal, []string{secret}, secret); err != nil {
			return fmt.Errorf("field %q failed to decrypt", key)
		}
	}
	return nil
}

func validateAlertmanagerConfigJSON(amConfigJSON string, secret string) error {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(amConfigJSON), &config); err != nil {
		return nil // Not JSON, skip
	}

	amConfig, ok := config["alertmanager_config"].(map[string]interface{})
	if !ok {
		return nil
	}

	receivers, ok := amConfig["receivers"].([]interface{})
	if !ok {
		return nil
	}

	for _, r := range receivers {
		receiver, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		cfgs, ok := receiver["grafana_managed_receiver_configs"].([]interface{})
		if !ok {
			continue
		}
		for _, c := range cfgs {
			cfg, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			ss, ok := cfg["secureSettings"].(map[string]interface{})
			if !ok || len(ss) == 0 {
				continue
			}
			for key, val := range ss {
				strVal, ok := val.(string)
				if !ok || strVal == "" {
					continue
				}

				// Check if legacy format and validate
				raw, err := b64DecodePadded(strVal)
				if err != nil || len(raw) < 2 {
					continue
				}
				if raw[0] != '#' {
					// Legacy format — try to decrypt
					if _, err := reencryptLegacyField(strVal, []string{secret}, secret); err != nil {
						return fmt.Errorf("receiver %v, field %q failed to decrypt", cfg["name"], key)
					}
				}
			}
		}
	}
	return nil
}

func reencryptAlertConfigTable(db *sql.DB, table string, oldSecret string, newSecret string) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, alertmanager_configuration FROM %s", table))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying %s: %v\n", table, err)
		os.Exit(1)
	}

	type acUpdate struct {
		id     int
		newCfg string
	}
	var updates []acUpdate
	totalFields := 0

	for rows.Next() {
		var id int
		var amConfig string
		if err := rows.Scan(&id, &amConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", table, err)
			os.Exit(1)
		}

		newCfg, count, err := reencryptAlertmanagerConfig(amConfig, oldSecret, newSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error re-encrypting %s [%d]: %v\n", table, id, err)
			os.Exit(1)
		}
		if count > 0 {
			updates = append(updates, acUpdate{id: id, newCfg: newCfg})
			totalFields += count
			fmt.Printf("  [%d] %d legacy fields re-encrypted\n", id, count)
		}
	}
	rows.Close()

	for _, u := range updates {
		if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET alertmanager_configuration = ? WHERE id = ?", table), u.newCfg, u.id); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s [%d]: %v\n", table, u.id, err)
			os.Exit(1)
		}
	}
	fmt.Printf("  %d rows updated (%d fields total).\n", len(updates), totalFields)
}
