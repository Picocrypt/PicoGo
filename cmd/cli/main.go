package main

import (
	"flag"
	"log"
	"errors"
	"strings"

	"github.com/jschauma/getpass"
)

type args struct {
	reedSolomon bool
	paranoid bool
	deniability bool
	inFiles []string
	keyfiles []string
	fix bool
	keep bool
	ordered bool
	password string
}

func parseArgs() (args, error){
	reedSolomon := flag.Bool("r", false, "(encryption) encode with Reed-Solomon bytes")
	paranoid := flag.Bool("p", false, "(encryption) use paranoid mode")
	deniability := flag.Bool("d", false, "(encryption) use deniability mode")
	keyfilesStr := flag.String("kf", "", "list of keyfiles to use. Separate list with commas (ex: keyfile1,keyfile2,keyfile3)")
	fix := flag.Bool("f", false, "(decryption) attempt to fix corruption")
	keep := flag.Bool("k", false, "(decryption) keep output even if corrupted")
	ordered := flag.Bool("ordered", false, "(encryption) require keyfiles in given order")
	passfrom := flag.String("passfrom", "tty", "password source")

	flag.Parse()
	if flag.NArg() == 0 {
		return args{}, errors.New("no file specified")
	}

	password, err := getpass.Getpass(*passfrom)
	if err != nil {
		return args{}, err
	}

	return args{
		reedSolomon: *reedSolomon,
		paranoid: *paranoid,
		deniability: *deniability,
		inFiles: flag.Args(),
		keyfiles: strings.Split(*keyfilesStr, ","),
		fix: *fix,
		keep: *keep,
		ordered: *ordered,
		password: pass,
	}, nil
}


func encrypt(
	inFile string,
	settings encryption.Settings,
) (string, error){
	return "", errors.New("encryption not implemented yet")
}


func decrypt(
	inFile string,
	settings encryption.Settings,
) (string, error){
	return "", errors.New("decryption not implemented yet")
}


func main() {
	a, err := parseArgs()
	log.Println(err)
	log.Println(a)

	for _, inFile := range a.inFiles {
		if strings.HasSuffix(inFile, ".pcv"){
			decrypt(inFile, settings)
		} else {
			encrypt(inFile, settings)
		}
}
