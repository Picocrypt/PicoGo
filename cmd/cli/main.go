package main

import (
	"flag"
	"log"
	"errors"
	"strings"
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
}

func parseArgs() (args, error){
	reedSolomon := flag.Bool("r", false, "(encryption) encode with Reed-Solomon bytes")
	paranoid := flag.Bool("p", false, "(encryption) use paranoid mode")
	deniability := flag.Bool("d", false, "(encryption) use deniability mode")
	keyfilesStr := flag.String("kf", "", "list of keyfiles to use. Separate list with commas (ex: keyfile1,keyfile2,keyfile3)")
	fix := flag.Bool("f", false, "(decryption) attempt to fix corruption")
	keep := flag.Bool("k", false, "(decryption) keep output even if corrupted")
	ordered := flab.Bool("ordered", false, "(encryption) require keyfiles in given order")

	flag.Parse()
	if flag.NArg() == 0 {
		return args{}, errors.New("no file specified")
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
	}, nil
}


func main() {
	a, err := parseArgs()
	log.Println(err)
	log.Println(a)
}
