package FileOperations

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// write file
// 按行写入文件
func WriteFile(ans []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	for _, v := range ans {
		if strings.Contains(v, "\n") {
			fmt.Fprint(write, v)
		} else {
			fmt.Fprintln(write, v)
		}
	}

	return write.Flush()
}

func WriteClashFile(ans []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	fmt.Fprintln(write, "#"+"hello")
	fmt.Fprintln(write, "payload:")

	for _, v := range ans {
		if !strings.Contains(v, "USER-AGENT") {
			fmt.Fprint(write, "  - ")
			if strings.Contains(v, "\n") {
				fmt.Fprint(write, v)
			} else {
				fmt.Fprintln(write, v)
			}
		}
	}

	return write.Flush()
}

func WriteAGHomeFile(ans []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	fmt.Fprintln(write, "#"+"hello")
	fmt.Fprintln(write, "payload:")

	for _, v := range ans {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			fmt.Fprint(write, "||")
			fmt.Fprint(write, v)
			// if strings.Contains(v, "\n") {
			// 	fmt.Fprint(write, v)
			// } else {
			// 	fmt.Fprintln(write, v)
			// }
			fmt.Fprintln(write, "^")
		}
	}

	return write.Flush()
}
