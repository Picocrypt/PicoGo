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
	overwrite   bool
	encryptOnly bool
	decryptOnly bool
}

func parseArgs() (args, error) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] file1 [file2 ...]\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "\nOptions:\n")
		flag.PrintDefaults()
	}
	reedSolomon := flag.Bool("rs", false, "(encryption) encode with Reed-Solomon bytes")
	paranoid := flag.Bool("paranoid", false, "(encryption) use paranoid mode")
	deniability := flag.Bool("deniability", false, "(encryption) use deniability mode")
	keyfilesStr := flag.String("keyfiles", "", "list of keyfiles to use. Separate list with commas (ex: keyfile1,keyfile2,keyfile3)")
	keep := flag.Bool("keep", false, "(decryption) keep output even if corrupted. If not set, the output file will be deleted.")
	ordered := flag.Bool("ordered", false, "(encryption) require keyfiles in given order")
	passfrom := flag.String("passfrom", "tty", "password source. Options can be found in getpass documentation (github.com/jschauma/getpass)")
	comments := flag.String("comments", "", "(encryption) comments to save with the file. THESE ARE NOT ENCRYPTED. Wrap in quotes.")
	overwrite := flag.Bool("overwrite", false, "overwrite existing files")
	encryptOnly := flag.Bool("encrypt-only", false, "only handle files that require encryption (only processes non-.pcv files)")
	decryptOnly := flag.Bool("decrypt-only", false, "only handle files that require decryption (only processes .pcv files)")

	flag.Parse()
	if flag.NArg() == 0 {
		return args{}, errors.New("no file specified")
	}

	password, err := getpass.Getpass(*passfrom)
	if err != nil {
		return args{}, fmt.Errorf("reading password from %s: %w", *passfrom, err)
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
		overwrite:   *overwrite,
		encryptOnly: *encryptOnly,
		decryptOnly: *decryptOnly,
	}, nil
}

func openFiles(inFile string, keyfiles []string, outFile string, overwrite bool) (*os.File, []*os.File, *os.File, error) {
	inReader, err := os.Open(inFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening %s: %w", inFile, err)
	}
	keyfileReaders := []*os.File{}
	for _, keyfile := range keyfiles {
		reader, err := os.Open(keyfile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("opening %s: %w", keyfile, err)
		}
		keyfileReaders = append(keyfileReaders, reader)
	}
	_, err = os.Stat(outFile)
	if err == nil && !overwrite {
		return nil, nil, nil, fmt.Errorf("%s already exists", outFile)
	}
	outWriter, err := os.Create(outFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating %s: %w", outFile, err)
	}
	return inReader, keyfileReaders, outWriter, nil
}

func asReaders(files []*os.File) []io.Reader {
	readers := make([]io.Reader, len(files))
	for i, file := range files {
		readers[i] = file
	}
	return readers
}

func encrypt(
	inFile string,
	keyfiles []string,
	settings encryption.Settings,
	password string,
	outOf [2]int,
	overwrite bool,
) error {
	outFile := inFile + ".pcv"
	inReader, keyfileReaders, outWriter, err := openFiles(inFile, keyfiles, outFile, overwrite)
	if err != nil {
		return fmt.Errorf("opening files: %w", err)
	}
	defer func() {
		for _, reader := range append(keyfileReaders, inReader, outWriter) {
			reader.Close()
		}
	}()

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
			fmt.Sprintf("[%d/%d] Encrypting: %s", outOf[0]+1, outOf[1], inFile),
		),
	)
	header, err := encryption.EncryptHeadless(inReader, password, asReaders(keyfileReaders), settings, io.MultiWriter(outWriter, bar), nil)
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
	overwrite bool,
) error {
	outFile := strings.TrimSuffix(inFile, ".pcv")
	inReader, keyfileReaders, outWriter, err := openFiles(inFile, keyfiles, outFile, overwrite)
	if err != nil {
		return fmt.Errorf("opening files: %w", err)
	}
	defer func() {
		for _, reader := range append(keyfileReaders, inReader, outWriter) {
			reader.Close()
		}
	}()

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
		asReaders(keyfileReaders),
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
			if a.encryptOnly {
				fmt.Printf("[%d/%d] Skipping %s (encrypt-only is set)\n", i+1, len(a.inFiles), inFile)
				continue
			}
			err := decrypt(inFile, a.keyfiles, a.password, [2]int{i, len(a.inFiles)}, a.keep, a.overwrite)
			if err != nil {
				fmt.Printf("error while decrypting %s: %s\n", inFile, err)
				os.Exit(1)
			}
		} else {
			if a.decryptOnly {
				fmt.Printf("[%d/%d] Skipping %s (decrypt-only is set)\n", i+1, len(a.inFiles), inFile)
				continue
			}
			settings := encryption.Settings{
				Comments:    a.comments,
				ReedSolomon: a.reedSolomon,
				Paranoid:    a.paranoid,
				Deniability: a.deniability,
			}
			err := encrypt(inFile, a.keyfiles, settings, a.password, [2]int{i, len(a.inFiles)}, a.overwrite)
			if err != nil {
				fmt.Printf("error while encrypting %s: %s\n", inFile, err)
				os.Exit(1)
			}
		}
	}
}
