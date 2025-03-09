package main

import (
	"flag"
	"log"
	"errors"
	"strings"
	"io"
	"fmt"
	"os"

	"github.com/jschauma/getpass"
	"github.com/picocrypt/picogo/internal/encryption"
)

type args struct {
	reedSolomon bool
	paranoid bool
	deniability bool
	inFiles []string
	keyfiles []string
	keep bool
	ordered bool
	password string
	comments string
}

func parseArgs() (args, error){
	reedSolomon := flag.Bool("r", false, "(encryption) encode with Reed-Solomon bytes")
	paranoid := flag.Bool("p", false, "(encryption) use paranoid mode")
	deniability := flag.Bool("d", false, "(encryption) use deniability mode")
	keyfilesStr := flag.String("kf", "", "list of keyfiles to use. Separate list with commas (ex: keyfile1,keyfile2,keyfile3)")
	keep := flag.Bool("k", false, "(decryption) keep output even if corrupted")
	ordered := flag.Bool("ordered", false, "(encryption) require keyfiles in given order")
	passfrom := flag.String("passfrom", "tty", "password source")
	comments := flag.String("comments", "", "(encryption) comments to save with the file. THESE ARE NOT ENCRYPTED.")

	flag.Parse()
	if flag.NArg() == 0 {
		return args{}, errors.New("no file specified")
	}

	password, err := getpass.Getpass(*passfrom)
	if err != nil {
		return args{}, err
	}
	keyfiles := []string{}
	if len(*keyfilesStr) > 0 {
		keyfiles = strings.Split(*keyfilesStr, ",")
	}

	return args{
		reedSolomon: *reedSolomon,
		paranoid: *paranoid,
		deniability: *deniability,
		inFiles: flag.Args(),
		keyfiles: keyfiles,
		keep: *keep,
		ordered: *ordered,
		password: password,
		comments: *comments,
	}, nil
}


func encrypt(
	inFile string,
	keyfiles []string,
	settings encryption.Settings,
	password string,
) (string, error){
	inReader, err := os.Open(inFile)
	if err != nil {
		return "", fmt.Errorf("opening  " + inFile + ": %w", err)
	}
	defer inReader.Close()
	keyfileReaders := []io.Reader{}
	for _, keyfile := range keyfiles {
		reader, err := os.Open(keyfile)
		if err != nil {
			return "", fmt.Errorf("opening keyfile " + keyfile + ": %w", err)
		}
		defer reader.Close()
		keyfileReaders = append(keyfileReaders, reader)
	}
	outFile := inFile + ".pcv"
	_, err = os.Stat(outFile)
	if err == nil {
		return "", fmt.Errorf(outFile + " already exists")
	}
	outWriter, err := os.Create(outFile)
	if err != nil {
		return "", fmt.Errorf("creating "+outFile+": %w", err)
	}

	tmp := make([]byte, encryption.HeaderSize(settings))
	_, err = outWriter.Write(tmp)
	if err != nil {
		return "", err
	}

	header, err := encryption.EncryptHeadless(inReader, password, keyfileReaders, settings, outWriter, nil)
	if err != nil {
		return "", err
	}

	_, err = outWriter.Seek(0, 0)
	if err != nil {
		return "", err
	}
	_, err = outWriter.Write(header)
	if err != nil {
		return "", err
	}

	return outFile, nil
}


func decrypt(
	inFile string,
	keyfiles []string,
	password string,
) (string, error){
	inReader, err := os.Open(inFile)
	if err != nil {
		return "", fmt.Errorf("opening  " + inFile + ": %w", err)
	}
	defer inReader.Close()
	keyfileReaders := []io.Reader{}
	for _, keyfile := range keyfiles {
		reader, err := os.Open(keyfile)
		if err != nil {
			return "", fmt.Errorf("opening keyfile " + keyfile + ": %w", err)
		}
		defer reader.Close()
		keyfileReaders = append(keyfileReaders, reader)
	}
	outFile := inFile[:len(inFile)-4]
	_, err = os.Stat(outFile)
	if err == nil {
		return "", fmt.Errorf(outFile + " already exists")
	}
	outWriter, err := os.Create(outFile)
	if err != nil {
		return "", fmt.Errorf("creating "+outFile+": %w", err)
	}

	damaged, err := encryption.Decrypt(
		password,
		keyfileReaders,
		inReader,
		outWriter,
		false,
		nil,
	)

	if err != nil {
		return "", err
	}
	if damaged {
		fmt.Println("Warning: "+inFile+" is damaged, but recovered")
	}
	return outFile, nil

}


func main() {
	a, err := parseArgs()
	log.Println(err)
	log.Println(a)

	for _, inFile := range a.inFiles {
		if strings.HasSuffix(inFile, ".pcv"){
			outFile, err := decrypt(inFile, a.keyfiles, a.password)
			if err != nil {
				fmt.Println("error while decrypting "+inFile+": ", err)
				return
			}
			fmt.Println("decrypted "+inFile+" to "+outFile)
		} else {
			settings := encryption.Settings{
				Comments: a.comments,
				ReedSolomon: a.reedSolomon,
				Paranoid: a.paranoid,
				Deniability: a.deniability,
			}
			outFile, err := encrypt(inFile, a.keyfiles, settings, a.password)
			if err != nil {
				fmt.Println("error while encrypting "+inFile+": ", err)
				return
			}
			fmt.Println("encrypted "+inFile+" to "+outFile)
		}
	}	
}
