package file

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// write file
// 按行写入文件
func WriteFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	for _, v := range data {
		if strings.Contains(v, "\n") {
			fmt.Fprint(write, v)
		} else {
			fmt.Fprintln(write, v)
		}
	}

	return write.Flush()
}

func WriteDomainSetRuleFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)

	for _, v := range data {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)
			fmt.Fprintln(write, v)
		}
	}

	return write.Flush()
}

func WriteClashFile(data []string, filePath string) error {
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

	for _, v := range data {
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

func WriteAGHomeFile(data []string, filePath string) error {
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

	for _, v := range data {
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

func WriteLoonHostFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	fmt.Fprintln(write, "[Host]")

	for _, v := range data {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)
			if strings.HasPrefix(v, ".") {
				fmt.Fprint(write, "*")
			}
			fmt.Fprint(write, v)
			fmt.Fprintln(write, " = 0.0.0.0")
		}
	}

	return write.Flush()
}

func WriteHostFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)

	for _, v := range data {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)
			fmt.Fprint(write, "0.0.0.0 ")
			if strings.HasPrefix(v, ".") {
				fmt.Fprint(write, "*")
			}
			fmt.Fprintln(write, v)
		}
	}

	return write.Flush()
}

func WriteLoonRuleFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)

	for _, v := range data {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)
			if strings.HasPrefix(v, ".") {
				v = strings.TrimPrefix(v, ".")
				fmt.Fprint(write, "DOMAIN-SUFFIX,")
			} else {
				fmt.Fprint(write, "DOMAIN,")
			}
			fmt.Fprintln(write, v)
		}
	}

	return write.Flush()
}

func WriteQuantumultXDNS(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)

	for _, v := range data {
		if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)
			fmt.Fprint(write, "server=/")
			if strings.HasPrefix(v, ".") {
				fmt.Fprint(write, "*")
			}
			fmt.Fprint(write, v)
			fmt.Fprintln(write, "/0.0.0.0")
		}
	}

	return write.Flush()
}
