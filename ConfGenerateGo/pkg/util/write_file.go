package util

import (
	"ConfGenerateGo/pkg/model"
	"bufio"
	"fmt"
	"os"
	"strings"
)

func WriteFile(matchType string, data model.Pairs, policyName string, filePath string, writeType bool) error {
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
			v.Key = strings.Replace(v.Key, "\r", "", -1)
			v.Key = strings.Replace(v.Key, "\n", "", -1)

			fmt.Fprint(write, v.Value)
			fmt.Fprint(write, ",")
			fmt.Fprintln(write, v.Key)

		}
	case strings.Contains(matchType, "LoonHost"):
		fmt.Println("LoonHost")
		fmt.Fprintln(write, "[Host]")
		for _, v := range data {
			if strings.Contains(v.Value, "DOMAIN-SUFFIX") || strings.Contains(v.Value, "DOMAIN") {
				v.Key = strings.Replace(v.Key, "\r", "", -1)
				v.Key = strings.Replace(v.Key, "\n", "", -1)
				if strings.Contains(v.Value, "DOMAIN-SUFFIX") {
					fmt.Fprint(write, "*")
				}
				fmt.Fprint(write, v.Key)
				fmt.Fprintln(write, " = 0.0.0.0")
			}
		}
	case strings.Contains(matchType, "QuantumultXHost"):
		fmt.Println("QuantumultXHost")
		for _, v := range data {
			if strings.Contains(v.Value, "DOMAIN-SUFFIX") || strings.Contains(v.Value, "DOMAIN") {
				v.Key = strings.Replace(v.Key, "\r", "", -1)
				v.Key = strings.Replace(v.Key, "\n", "", -1)
				fmt.Fprint(write, "server=/")
				if strings.Contains(v.Value, "DOMAIN-SUFFIX") {
					fmt.Fprint(write, "*")
				}
				fmt.Fprint(write, v.Key)
				fmt.Fprintln(write, "/0.0.0.0")
			}
		}
	case strings.Contains(matchType, "QuantumultXRules"):
		fmt.Println("QuantumultXRules")
		for _, v := range data {
			// TODO: 什么时候添加 no-resolve
			v.Key = strings.Replace(v.Key, "\n", "", -1)
			v.Key = strings.Replace(v.Key, "\r", "", -1)

			switch {
			case strings.Contains(v.Value, "IP-CIDR6"):
				fmt.Fprint(write, "IP6-CIDR,")
			case strings.Contains(v.Value, "IP-CIDR"):
				fmt.Fprint(write, "IP-CIDR,")
				fmt.Fprintln(write, v.Key+"/32"+","+policyName+",no-resolve")
				continue
			case strings.Contains(v.Value, "DOMAIN-SUFFIX"):
				fmt.Fprint(write, "HOST-SUFFIX,")
			case strings.Contains(v.Value, "DOMAIN"):
				fmt.Fprint(write, "HOST,")
			}

			fmt.Fprintln(write, v.Key+","+policyName)
		}
	case strings.Contains(matchType, "Host"):
		fmt.Println("Host")
		for _, v := range data {
			if strings.Contains(v.Value, "DOMAIN-SUFFIX") || strings.Contains(v.Value, "DOMAIN") {
				v.Key = strings.Replace(v.Key, "\r", "", -1)
				v.Key = strings.Replace(v.Key, "\n", "", -1)
				fmt.Fprint(write, "0.0.0.0 ")
				fmt.Fprintln(write, v.Key)
			}
		}
	case strings.Contains(matchType, "DomainSetRule"):
		fmt.Println("DomainSetRule")
		for _, v := range data {
			if strings.Contains(v.Value, "DOMAIN-SUFFIX") || strings.Contains(v.Value, "DOMAIN") {
				v.Key = strings.Replace(v.Key, "\r", "", -1)
				v.Key = strings.Replace(v.Key, "\n", "", -1)
				if strings.Contains(v.Value, "DOMAIN-SUFFIX") {
					fmt.Fprint(write, ".")
				}
				fmt.Fprintln(write, v.Key)
			}
		}
	case strings.Contains(matchType, "AdGuardHome"):
		fmt.Println("AdGuardHome")
		for _, v := range data {
			if strings.Contains(v.Value, "DOMAIN-SUFFIX") || strings.Contains(v.Value, "DOMAIN") {
				v.Key = strings.Replace(v.Key, "\r", "", -1)
				v.Key = strings.Replace(v.Key, "\n", "", -1)
				fmt.Fprint(write, "||")
				fmt.Fprint(write, v.Key)
				fmt.Fprintln(write, "^")
			}
		}
	case strings.Contains(matchType, "Clash"):
		// todo clash 是否支持 USER-AGENT
		fmt.Fprintln(write, "payload:")
		for _, v := range data {
			if !strings.Contains(v.Value, "USER-AGENT") {
				fmt.Fprint(write, "  - ")
				fmt.Fprint(write, v.Value+",")
				if strings.Contains(v.Key, "\n") {
					fmt.Fprint(write, v.Key)
				} else {
					fmt.Fprintln(write, v.Key)
				}
			}
		}
	case strings.Contains(matchType, "Nomal"):
		for _, v := range data {
			fmt.Fprint(write, "  - ")
			fmt.Fprint(write, v.Value+",")
			if strings.Contains(v.Key, "\n") {
				fmt.Fprint(write, v.Key)
			} else {
				fmt.Fprintln(write, v.Key)
			}
		}
	default:
		fmt.Println("匹配 error")
	}

	return write.Flush()
}

func NomalWriteFile(data []string, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("open file error !")
		fmt.Println(err)
		return err
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	for _, v := range data {
		fmt.Fprintln(write, v)
	}

	return write.Flush()
}
