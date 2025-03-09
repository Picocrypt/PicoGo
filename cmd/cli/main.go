package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jschauma/getpass"
	"github.com/picocrypt/picogo/internal/encryption"
	"github.com/schollz/progressbar/v3"
)

type args struct {
	reedSolomon bool
	paranoid    bool
	deniability bool
	inFiles     []string
	keyfiles    []string
	keep        bool
	ordered     bool
	password    string
	comments    string
}

func parseArgs() (args, error) {
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
		paranoid:    *paranoid,
		deniability: *deniability,
		inFiles:     flag.Args(),
		keyfiles:    keyfiles,
		keep:        *keep,
		ordered:     *ordered,
		password:    password,
		comments:    *comments,
	}, nil
}

func encrypt(
	inFile string,
	keyfiles []string,
	settings encryption.Settings,
	password string,
	outOf [2]int,
) error {
	inReader, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("opening %s: %w", inFile, err)
	}
	defer inReader.Close()
	keyfileReaders := []io.Reader{}
	for _, keyfile := range keyfiles {
		reader, err := os.Open(keyfile)
		if err != nil {
			return fmt.Errorf("opening %s: %w", keyfile, err)
		}
		defer reader.Close()
		keyfileReaders = append(keyfileReaders, reader)
	}
	outFile := inFile + ".pcv"
	_, err = os.Stat(outFile)
	if err == nil {
		return fmt.Errorf("%s already exists", outFile)
	}
	outWriter, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outFile, err)
	}

	tmp := make([]byte, encryption.HeaderSize(settings))
	_, err = outWriter.Write(tmp)
	if err != nil {
		return fmt.Errorf("writing blank header: %w", err)
	}

	bar := progressbar.NewOptions(
		-1,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionUseIECUnits(true),
		progressbar.OptionSetDescription(
			fmt.Sprintf("[%d/%d] Ecrypting: %s", outOf[0]+1, outOf[1], inFile),
		),
	)
	header, err := encryption.EncryptHeadless(inReader, password, keyfileReaders, settings, io.MultiWriter(outWriter, bar), nil)
	bar.Finish() // don't catch the error, fine to ignore
	if err != nil {
		return fmt.Errorf("encrypting %s: %w", inFile, err)
	}

	_, err = outWriter.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("seeking to start of %s: %w", outFile, err)
	}
	_, err = outWriter.Write(header)
	if err != nil {
		return fmt.Errorf("writing header to %s: %w", outFile, err)
	}
	fmt.Printf("[%d/%d] Encrypted %s to %s\n", outOf[0]+1, outOf[1], inFile, outFile)
	return nil
}

func decrypt(
	inFile string,
	keyfiles []string,
	password string,
	outOf [2]int,
	keep bool,
) error {
	inReader, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("opening %s: %w", inFile, err)
	}
	defer inReader.Close()
	keyfileReaders := []io.Reader{}
	for _, keyfile := range keyfiles {
		reader, err := os.Open(keyfile)
		if err != nil {
			return fmt.Errorf("opening %s: %w", keyfile, err)
		}
		defer reader.Close()
		keyfileReaders = append(keyfileReaders, reader)
	}
	outFile := inFile[:len(inFile)-4]
	_, err = os.Stat(outFile)
	if err == nil {
		return fmt.Errorf("%s already exists", outFile)
	}
	outWriter, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outFile, err)
	}

	bar := progressbar.NewOptions(
		-1,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionUseIECUnits(true),
		progressbar.OptionSetDescription(
			fmt.Sprintf("[%d/%d] Decrypting: %s", outOf[0]+1, outOf[1], inFile),
		),
	)
	damaged, err := encryption.Decrypt(
		password,
		keyfileReaders,
		inReader,
		io.MultiWriter(outWriter, bar),
		false,
		nil,
	)
	bar.Finish() // don't catch the error, fine to ignore
	if err != nil {
		if !keep {
			removeErr := os.Remove(outFile)
			if removeErr != nil {
				fmt.Printf("error removing %s: %s\n", outFile, removeErr)
			}
		}
		return err
	}
	if damaged {
		fmt.Printf("Warning: %s is damaged but recovered with reed-solomon bytes. Consider re-encrypting the file.\n", inFile)
	}
	fmt.Printf("[%d/%d] Decrypted %s to %s\n", outOf[0]+1, outOf[1], inFile, outFile)
	return nil
}

func main() {
	a, err := parseArgs()
	if err != nil {
		fmt.Printf("error reading args: %s\n", err)
		os.Exit(1)
	}

	for i, inFile := range a.inFiles {
		if strings.HasSuffix(inFile, ".pcv") {
			err := decrypt(inFile, a.keyfiles, a.password, [2]int{i, len(a.inFiles)}, a.keep)
			if err != nil {
				fmt.Printf("error while decrypting %s: %s\n", inFile, err)
				os.Exit(1)
			}
		} else {
			settings := encryption.Settings{
				Comments:    a.comments,
				ReedSolomon: a.reedSolomon,
				Paranoid:    a.paranoid,
				Deniability: a.deniability,
			}
			err := encrypt(inFile, a.keyfiles, settings, a.password, [2]int{i, len(a.inFiles)})
			if err != nil {
				fmt.Printf("error while encrypting %s: %s\n", inFile, err)
				os.Exit(1)
			}
		}
	}
}
