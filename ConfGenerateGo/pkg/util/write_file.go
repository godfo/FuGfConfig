package util

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func WriteFile(matchType string, data []string, policyName string, filePath string, writeType bool) error {
	var flag int
	if writeType {
		//	如果 为 true 就覆盖写入
		flag = os.O_WRONLY | os.O_TRUNC
	} else {
		flag = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	}
	file, err := os.OpenFile(filePath, flag, 0644)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)

	switch {
	case strings.Contains(matchType, "LoonRule"):
		fmt.Println("LoonRule")
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
	case strings.Contains(matchType, "LoonHost"):
		fmt.Println("LoonHost")
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
	case strings.Contains(matchType, "QuantumultXHost"):
		fmt.Println("QuantumultXHost")
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
	case strings.Contains(matchType, "QuantumultXRules"):
		fmt.Println("QuantumultXRules")
		for _, v := range data {
			if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
				v = strings.Replace(v, "\r", "", -1)
				v = strings.Replace(v, "\n", "", -1)
				if strings.HasPrefix(v, ".") {
					v = strings.TrimPrefix(v, ".")
					fmt.Fprint(write, "HOST-SUFFIX,")
				} else {
					fmt.Fprint(write, "HOST,")
				}
				fmt.Fprint(write, v)
				fmt.Fprint(write, ",")
				fmt.Fprintln(write, policy)
			}
		}
	case strings.Contains(matchType, "Host"):
		fmt.Println("Host")
		for _, v := range data {
			if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
				v = strings.Replace(v, "\r", "", -1)
				v = strings.Replace(v, "\n", "", -1)
				fmt.Fprint(write, "0.0.0.0 ")
				if strings.HasPrefix(v, ".") {
					v = strings.TrimLeft(v, ".")
				}
				fmt.Fprintln(write, v)
			}
		}
	case strings.Contains(matchType, "DomainSetRule"):
		fmt.Println("DomainSetRule")
		for _, v := range data {
			if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
				v = strings.Replace(v, "\r", "", -1)
				v = strings.Replace(v, "\n", "", -1)
				fmt.Fprintln(write, v)
			}
		}
	case strings.Contains(matchType, "AdGuardHome"):
		fmt.Println("AdGuardHome")
		for _, v := range data {
			if !strings.Contains(v, "USER-AGENT") && !strings.Contains(v, "IP-CIDR") && !strings.Contains(v, "IP-CIDR6") && v != "" {
				v = strings.Replace(v, "\r", "", -1)
				v = strings.Replace(v, "\n", "", -1)
				if strings.HasPrefix(v, ".") {
					v = strings.TrimPrefix(v, ".")
				}
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
	case strings.Contains(matchType, "Clash"):
		fmt.Println("Clash")
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
	default:
		fmt.Println("匹配 error")
	}

	return write.Flush()
}
