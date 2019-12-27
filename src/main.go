package main

import (
	"crypto/aes"    //Advanced Encryption Standard is a symmetric block cipher.
	"crypto/cipher" //şifre paketi
	"crypto/md5"    //hash için
	"crypto/rand"
	"encoding/hex" //hex, hexadecimal encoding icin kullanılan bir poket
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

//stringi nasıl encode'luyormusuz bakalım:
// func main() {
// 	word := []byte("Merve")
// 	encodedWord := hex.EncodeToString(word)
// 	fmt.Printf("%s\n", encodedWord) //4d65727665
// }

//hashleyelim:
func createHash(key string) string {
	hasher := md5.New()       //md5 nesnesi üretiyoruz ve bu hasher nesnemiz olacak.
	hasher.Write([]byte(key)) //alacagımız key'i hasher'in write fonksiyonuna yolluyoruz
	return hex.EncodeToString(hasher.Sum(nil))
	//nil inititialize edilmemis value.
}

//encrypt islemi icin aes paketinden faydalanacagız.
func encrypt(data []byte, password string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(password)))
	//buradaki _(underscore), blank identifier olarak geciyor, bu iterator degisken
	// bize lazım degil buna ihtiyacım yok diyoruz derleyiciye
	//password, üstteki hashleme fonksiyonuna gonderilir ve
	//aes paketinin icindeki newCipher ile bir sifreleme blogu(block) olusturulur
	gcm, err := cipher.NewGCM(block)
	//NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode with the standard nonce length.
	if err != nil {
		panic(err.Error()) //stopssss, error fırlattırıyoruz
	}
	//şifrelenmiş bir text olusturmadan önce, bir nonce olusturmaliyiz.
	nonce := make([]byte, gcm.NonceSize())
	//nonce anasifreyi güvenli bir sekilde iletmek icin kullanılan,rastgele secilen bir kod
	//her transactionda nonce value 1 artar.
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	//decryption için kullanacagımız nonce, encryption icin kullanılanla aynı olmalı!
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	//ilk parametre bizim prefix value, encrypted olan dataya bu eklenecek
	//nonce, NonceSize() byte uzunlguunda ve unique olmalı her zaman,verilen key icin.
	//Seal burda encrypt ediyor
	return ciphertext

}

func decrypt(data []byte, password string) []byte {
	key := []byte(createHash(password))
	//encrypted olmus datayı decrypt etmek istiyoruz,bu islem aslında cok benziyor encryption islemine.
	//hashlenmis password  kullanarak yeni bir sifre block u olusturuyoruz.
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	//encrypt fonksiyonunda nonce ile datayı encrpyt ederken prefix olarak kullanmıstık,
	//simdi burda nonce ve encrypt olmus datayı ayırmamız gerek.
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	//nonce ve ciphertext birbirinden ayrıldı, biz simdi decrypt edebiliriz datayı
	// ve onu bir plaintext olarak return edebiliriz.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

//dosya olusturma adımları:

func encryptFile(filename string, data []byte, password string) { //dosyayı sifrelemek icin,dosyaadı,datalar,parolaya ihtiyacımız var.
	file, _ := os.Create(filename) //bir dosya olusturduk.
	defer file.Close()             //use defer to close or deallocate resources.
	file.Write(encrypt(data, password))
}

func decryptFile(filename string, password string) []byte {
	data, _ := ioutil.ReadFile(filename) //dosyayı okuyoruz ve bunu data'ya atıyoruz.
	return decrypt(data, password)       // decrypt fonksiyonuna bu okudugumuz datayı ve sifreyi yolluyoruz.

}

func main() {
	ciphertext := encrypt([]byte("mervvee"), "password") // encrypt fonksiyonunu cagırarak, sifreyi olusturuyoruz.
	fmt.Printf("Encrypted: %x\n", ciphertext)            //  (%x :base 16, with lower-case letters for a-f)
	plaintext := decrypt(ciphertext, "password")         //decrypt edilmis hali, plaintext.
	fmt.Printf("Decrypted: %s\n", plaintext)
	encryptFile("deneme.txt", []byte("mervvee"), "password5")
	fmt.Println(string(decryptFile("deneme.txt", "password5")))

}
